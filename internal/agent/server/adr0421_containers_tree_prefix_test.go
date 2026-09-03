// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// ADR-0421 D3 items 1-3 — the D1 pins.
//
// D1 admits the containerd CRI *containers* tree as a fourth legitimate --ext-mount-map target
// class. These tests pin three separate properties, because D1's whole risk is that a widening of
// a security control widens more than it means to:
//
//	item 1 — the prefix is EMITTED, once per non-empty discovered root, as a strict subtree;
//	item 2 — the widening is of the PREFIX class only, not of the provenance check;
//	item 3 — nothing adjacent to the containers tree became admissible, including via symlink.

// withDiscoveredRoots pins the three discovered roots for the duration of one test.
func withDiscoveredRoots(t *testing.T, root, runRoot, stateRoot string) {
	t.Helper()
	origRootFn, origRun, origState := resolveContainerdRootDirFn, containerdRunRoot, containerdStateRoot
	resolveContainerdRootDirFn = func(context.Context, string) string { return root }
	containerdRunRoot, containerdStateRoot = runRoot, stateRoot
	t.Cleanup(func() {
		resolveContainerdRootDirFn, containerdRunRoot, containerdStateRoot = origRootFn, origRun, origState
	})
}

// TestADR0421_D3Item1_ContainersTreePrefixShape is D3 item 1.
func TestADR0421_D3Item1_ContainersTreePrefixShape(t *testing.T) {
	cases := []struct {
		name                        string
		root, runRoot, stateRoot    string
		wantContainersPrefixesUnder []string
	}{
		{
			// The kind shape measured live at §P-VERIFY #1.
			name: "all three roots distinct and non-empty",
			root: "/var/lib/containerd", runRoot: "/run/containerd", stateRoot: "/var/lib/containerd-state",
			wantContainersPrefixesUnder: []string{"/var/lib/containerd", "/run/containerd", "/var/lib/containerd-state"},
		},
		{
			// The RKE2 shape measured live at §P-VERIFY #1: containers tree under the `root` dir,
			// state root elsewhere entirely.
			name: "rke2 layout",
			root: "/var/lib/rancher/rke2/agent/containerd", runRoot: "/run/k3s/containerd", stateRoot: "/run/k3s/containerd",
			wantContainersPrefixesUnder: []string{"/var/lib/rancher/rke2/agent/containerd", "/run/k3s/containerd"},
		},
		{
			name: "empty root contributes nothing",
			root: "", runRoot: "/run/containerd", stateRoot: "",
			wantContainersPrefixesUnder: []string{"/run/containerd"},
		},
		{
			name: "all roots empty contributes nothing",
			root: "", runRoot: "", stateRoot: "",
			wantContainersPrefixesUnder: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withDiscoveredRoots(t, tc.root, tc.runRoot, tc.stateRoot)
			got := allowedExtMountHostTargetPrefixes(context.Background())

			// (a) exactly one containers-tree prefix per DISTINCT non-empty root, and it is the
			// documented relative segment joined onto that root.
			for _, root := range tc.wantContainersPrefixesUnder {
				want := filepath.Join(root, criContainersDirRel) + "/"
				if !containsString(got, want) {
					t.Fatalf("missing containers-tree prefix %q for root %q; got %v", want, root, got)
				}
				// (b) it is a STRICT SUBTREE prefix, never the bare root. This is the assertion
				// that fails if a future edit "simplifies" D1 to the containerd root dir.
				if want == root+"/" || !strings.Contains(want, criContainersDirRel) {
					t.Fatalf("containers-tree prefix %q is not a strict subtree of root %q", want, root)
				}
			}

			// (c) the sandbox class is untouched — D1 ADDS a class, it does not replace one.
			for _, root := range tc.wantContainersPrefixesUnder {
				want := filepath.Join(root, criSandboxDirRel) + "/"
				if !containsString(got, want) {
					t.Fatalf("D1 must not disturb the sandbox class: missing %q; got %v", want, got)
				}
			}

			// (d) an empty root contributes NOTHING — not a bare "/", not a rootless
			// "io.containerd.grpc.v1.cri/containers/".
			for _, p := range got {
				if p == "/" || strings.HasPrefix(p, criContainersDirRel) {
					t.Fatalf("empty root leaked a degenerate prefix %q; got %v", p, got)
				}
			}

			// (e) §P-VERIFY #5 mechanically: no emitted CRI prefix is a bare discovered root.
			for _, p := range got {
				for _, root := range []string{tc.root, tc.runRoot, tc.stateRoot} {
					if root == "" {
						continue
					}
					if p == root || p == root+"/" {
						t.Fatalf("§P-VERIFY #5: prefix %q is a BARE discovered root — confinement regressed", p)
					}
				}
			}
		})
	}
}

// TestADR0421_D3Item2_ProvenanceCheckStillGates is D3 item 2: D1 widened the PREFIX class and not
// the resolvedHostTargets provenance check.
func TestADR0421_D3Item2_ProvenanceCheckStillGates(t *testing.T) {
	withDiscoveredRoots(t, "/var/lib/containerd", "/run/containerd", "/run/containerd")
	origRealpath := hostRealpathFn
	hostRealpathFn = func(p string) (string, error) { return p, nil }
	defer func() { hostRealpathFn = origRealpath }()

	target := "/var/lib/containerd/io.containerd.grpc.v1.cri/containers/" +
		"6c09e39d3a1d9e36871605cacf8ed27e889f793f0cd562c9638d982beb55d5b2/volumes/" +
		"13362ae109d6157bc9f5835232ef8f9b675f0ddd20ebb0b61bce2f0851e81a56/data"

	// Provenance populated => ACCEPT. Before D1 this rejected at the prefix check.
	if err := validateExtMountToken("/data", target, map[string]bool{target: true}); err != nil {
		t.Fatalf("D1: a containers-tree target this agent resolved must be admitted, got %v", err)
	}

	// Provenance EMPTY => still REJECT, and specifically on the provenance ground, not the prefix
	// ground. D1 must not have turned the allowlist into the only control.
	err := validateExtMountToken("/data", target, map[string]bool{})
	if err == nil {
		t.Fatal("D1 must not weaken the resolvedHostTargets provenance check")
	}
	if !strings.Contains(err.Error(), "was not resolved by this agent") {
		t.Fatalf("expected the provenance rejection, got %v", err)
	}
}

// TestADR0421_D3Item3_NegativeConfinement is D3 item 3, including rev-3 R17's two added cases.
func TestADR0421_D3Item3_NegativeConfinement(t *testing.T) {
	const root = "/var/lib/containerd"
	withDiscoveredRoots(t, root, "/run/containerd", "/run/containerd")

	t.Run("adjacent trees and bare roots still reject", func(t *testing.T) {
		origRealpath := hostRealpathFn
		hostRealpathFn = func(p string) (string, error) { return p, nil }
		defer func() { hostRealpathFn = origRealpath }()

		for _, target := range []string{
			root + "/io.containerd.grpc.v1.cri",              // bare CRI dir
			root + "/io.containerd.grpc.v1.cri/containers",   // bare containers dir, no trailing sep
			root,                                             // bare containerd root
			root + "/io.containerd.content.v1.content/blobs", // the content store
			root + "/io.containerd.snapshotter.v1.overlayfs/snapshots/42", // the snapshotter tree
			"/etc/shadow",
		} {
			// Provenance is deliberately POPULATED so the only thing that can reject is the
			// prefix/confinement rule — this is the test that fails if a future edit widens to
			// the containerd root dir.
			if err := validateExtMountToken("/data", target, map[string]bool{target: true}); err == nil {
				t.Fatalf("target %q must be rejected by the prefix rule", target)
			}
		}
	})

	// R17 (a) — a containers-tree path containing a `..` segment that resolves OUT of the tree is
	// caught LEXICALLY, before any realpath call. Pinned so a future edit cannot lose the lexical
	// rule and rely on the realpath one (or vice versa — see (b)).
	t.Run("R17a dot-dot escape rejects lexically", func(t *testing.T) {
		origRealpath := hostRealpathFn
		called := false
		hostRealpathFn = func(p string) (string, error) { called = true; return p, nil }
		defer func() { hostRealpathFn = origRealpath }()

		target := root + "/io.containerd.grpc.v1.cri/containers/abc/volumes/../../../../../etc/shadow"
		err := validateExtMountToken("/data", target, map[string]bool{target: true})
		if err == nil {
			t.Fatal("a containers-tree path with a traversal segment must reject")
		}
		if !strings.Contains(err.Error(), "not lexically clean") {
			t.Fatalf("expected the lexical-cleanliness rejection, got %v", err)
		}
		if called {
			t.Fatal("the lexical rule must reject BEFORE the realpath confinement is consulted")
		}
	})

	// R17 (b) — a LEXICALLY CLEAN containers-tree path whose realpath lands outside every prefix
	// still rejects, and an UNRESOLVABLE one still fails closed. This is the case only the
	// ADR-0419 D9 realpath confinement catches, and D1b claims that branch still runs on a
	// containers-tree target. Asserted rather than argued.
	cleanTarget := root + "/io.containerd.grpc.v1.cri/containers/abc/volumes/deadbeef/data"

	t.Run("R17b symlink escaping the tree rejects", func(t *testing.T) {
		origRealpath := hostRealpathFn
		hostRealpathFn = func(string) (string, error) { return "/etc/shadow", nil }
		defer func() { hostRealpathFn = origRealpath }()

		err := validateExtMountToken("/data", cleanTarget, map[string]bool{cleanTarget: true})
		if err == nil {
			t.Fatal("D1 must not route a containers-tree target around the D9 realpath confinement")
		}
		if !strings.Contains(err.Error(), "resolves in the host mount namespace") {
			t.Fatalf("expected the realpath-escape rejection, got %v", err)
		}
	})

	t.Run("R17b unresolvable realpath fails closed", func(t *testing.T) {
		origRealpath := hostRealpathFn
		hostRealpathFn = func(string) (string, error) { return "", errors.New("broker unreachable") }
		defer func() { hostRealpathFn = origRealpath }()

		err := validateExtMountToken("/data", cleanTarget, map[string]bool{cleanTarget: true})
		if err == nil {
			t.Fatal("an unresolvable containers-tree target must fail CLOSED, not be admitted")
		}
		if !errors.Is(err, errExtMountRealpathUnresolved) {
			t.Fatalf("expected errExtMountRealpathUnresolved, got %v", err)
		}
	})
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
