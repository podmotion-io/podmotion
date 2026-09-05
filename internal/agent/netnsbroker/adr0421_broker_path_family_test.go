//go:build linux

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package netnsbroker

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/cripaths"
)

// discoveredContainerdRoots are the containerd `root` dirs the agent's ADR-0370 discovery actually
// resolves on the substrates this project runs on, plus the two run/state roots its allowlist
// enumerates rather than guesses between. The broker never performs that discovery — this test
// stands in for it, so the marker rule is exercised against real absolute shapes.
var discoveredContainerdRoots = []string{
	"/var/lib/containerd",                    // kubeadm / kind
	"/var/lib/rancher/rke2/agent/containerd", // RKE2
	"/var/lib/rancher/k3s/agent/containerd",  // k3s
	"/run/containerd",                        // containerd run root
	"/run/k3s/containerd",                    // k3s/RKE2 run+state root
}

// TestADR0421_BrokerPathFamilyCoversEveryCRIClass is the REGRESSION TEST for the two-allowlist
// desync that ADR-0421 D1 alone did not close.
//
// There are two independent confinement bounds on a runtime-supplied --ext-mount-map target: the
// agent's discovery-derived prefix allowlist (allowedExtMountHostTargetPrefixes, bounds what may be
// USED) and this broker's server-pinned path family (hostRealpathAllowed, bounds what may be ASKED).
// D1 widened the first with the per-container subtree and left the second carrying a hardcoded
// sandbox-only marker, so a legitimate containers-tree target passed the agent's check and was then
// refused here — every such restore failed closed with "outside the server-pinned path family".
//
// The invariant this pins: for EVERY CRI subtree class in the shared list, a path composed the way
// the agent's allowlist composes it (discovered root + class + leaf) must be askable of the broker.
// Adding a class to cripaths without teaching the broker's matcher about it fails here, which is
// exactly what did not happen when the containers class was added.
func TestADR0421_BrokerPathFamilyCoversEveryCRIClass(t *testing.T) {
	rels := cripaths.AllDirRels()
	if len(rels) < 2 {
		t.Fatalf("shared CRI class list has %d entries; the containers class is missing from it, "+
			"so this test cannot observe the desync it exists to catch: %v", len(rels), rels)
	}
	for _, rel := range rels {
		for _, root := range discoveredContainerdRoots {
			// The two live leaf shapes: a sandbox-scoped file and an anonymous volume dir.
			for _, leaf := range []string{"deadbeef/hostname", "deadbeef/volumes/0f1e2d3c"} {
				p := filepath.Join(root, rel, leaf)
				if !hostRealpathAllowed(p) {
					t.Errorf("broker path family REJECTS %q, but the agent's allowlist emits the "+
						"prefix %q — the two bounds have desynced (ADR-0421 D1e)",
						p, filepath.Join(root, rel)+"/")
				}
			}
		}
	}
}

// TestADR0421_ContainersClassSpecifically pins the exact live gate signature that D1 alone did not
// fix, as a named case that survives any future refactor of the loop above.
func TestADR0421_ContainersClassSpecifically(t *testing.T) {
	const p = "/var/lib/containerd/io.containerd.grpc.v1.cri/containers/" +
		"6b1f0a2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8/volumes/9c8b7a6"
	if !hostRealpathAllowed(p) {
		t.Fatalf("the anonymous per-container volume dir must be askable: %q", p)
	}
}

// TestADR0421_ClassAdmissionIsNotRootAdmission holds the D1b property on the BROKER side: widening
// to the containers class must not have widened to the containerd root, which would admit the
// snapshotter tree, the content store and every other subtree and destroy the confinement the op
// exists for. The marker's leading/trailing separators are what enforce this.
func TestADR0421_ClassAdmissionIsNotRootAdmission(t *testing.T) {
	rejected := []string{
		"/var/lib/containerd",
		"/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/abc",
		"/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/42/fs",
		"/var/lib/rancher/rke2/agent/containerd/io.containerd.grpc.v1.cri", // class dir, not traversed
		"/etc/io.containerd.grpc.v1.cri/containers-decoy/x",                // segment must be exact
		"/var/lib/containerd/xio.containerd.grpc.v1.cri/containers/a/b",    // suffix, not a segment
	}
	for _, p := range rejected {
		if hostRealpathAllowed(p) {
			t.Errorf("path family must REJECT %q — class admission is not root admission (ADR-0421 D1b)", p)
		}
	}
	// And the class markers must still be anchored on both sides.
	for _, rel := range cripaths.AllDirRels() {
		m := cripaths.Marker(rel)
		if !strings.HasPrefix(m, "/") || !strings.HasSuffix(m, "/") {
			t.Errorf("marker %q must be separator-anchored on both sides", m)
		}
	}
}

// TestADR0421_SharedClassListIsNotWritableByConsumers pins that a consumer cannot widen the shared
// list for everyone else: AllDirRels hands back a fresh slice, so mutating one caller's copy has no
// effect on the next caller. A package-level exported slice would not have this property, and the
// whole value of a single source of truth is that no importer may edit it.
func TestADR0421_SharedClassListIsNotWritableByConsumers(t *testing.T) {
	got := cripaths.AllDirRels()
	got[0] = "/"
	if again := cripaths.AllDirRels(); again[0] == "/" {
		t.Fatal("AllDirRels returned aliased backing storage — a consumer can widen the shared class list")
	}
}

// TestADR0421_BrokerMarkerListIsExactlyTheSharedClassList holds, on the broker's own derived copy,
// the property the test above holds on the shared source.
//
// D1e demoted criDirMarkers from an immutable `const` block to a package-level `var` initialized by
// a func literal, because the list is now DERIVED from cripaths.AllDirRels() and Go has no
// immutable slice — there is no `const []string`, and an array var is no less writable, so no purely
// syntactic form restores the guarantee `const` gave. The reachable widening is therefore narrower
// than before but not zero: cripaths itself is safe (AllDirRels hands back a fresh slice, pinned
// above), and criDirMarkers is unexported so no importer can touch it, which leaves in-package code
// appending to it — at init, or from any function in this package — as the one remaining path.
//
// This closes that path by pinning the CONTENT rather than the storage class: criDirMarkers must be
// exactly the marker of every shared class, no more and no fewer. Package-level var initialization
// completes before any test runs, so an `init()` or initializer that appends an extra subtree is
// observed here as a surplus entry. An entry added by hand — the exact regression D1e existed to
// prevent, a second hand-maintained copy drifting from the agent's list — fails the same way. The
// guard admits any legitimate change to the shared list automatically, since both sides of the
// comparison move together; only a broker-local widening fails.
func TestADR0421_BrokerMarkerListIsExactlyTheSharedClassList(t *testing.T) {
	want := map[string]bool{}
	for _, rel := range cripaths.AllDirRels() {
		want[cripaths.Marker(rel)] = true
	}

	got := map[string]bool{}
	for _, m := range criDirMarkers {
		got[m] = true
	}

	// Length is compared on the slice, not the set, so a duplicated entry is a failure too.
	if len(criDirMarkers) != len(want) {
		t.Errorf("criDirMarkers has %d entries (%d distinct); the shared class list yields %d — "+
			"the broker's copy has been widened locally instead of derived (ADR-0421 D1e): %v",
			len(criDirMarkers), len(got), len(want), criDirMarkers)
	}
	for m := range got {
		if !want[m] {
			t.Errorf("criDirMarkers admits %q, which no shared CRI class yields — an in-package "+
				"widening of the broker's server-pinned path family. Every marker must come from "+
				"cripaths.AllDirRels(), so the two confinement bounds cannot disagree about which "+
				"subtree classes exist.", m)
		}
	}
	for m := range want {
		if !got[m] {
			t.Errorf("criDirMarkers is MISSING %q, which the shared class list yields — the broker "+
				"will refuse a target the agent's allowlist emits, failing that restore closed "+
				"(the exact D1e desync).", m)
		}
	}
}
