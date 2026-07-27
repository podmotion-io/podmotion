// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

// adr0351_pod_uid_from_cgroups_path_test.go pins podUIDFromCgroupsPath (ADR-0351 D2.5): the
// caller-side extraction that produces the ExpectedPodUID cross-check's expected value. Its
// own doc comment promises it recognizes a pod UID token "in either encoding" — this test
// locks in both the systemd underscore-encoded form (the shape every current platform
// actually emits) AND the standard hyphenated form (the shape resolveCgroupAnchorTarget's
// sibling isSliceToken/expandSliceToken path deliberately keeps a raw-path passthrough for,
// per its own doc comment, on a future cgroupfs-driver substrate) — plus an unextractable
// malformed-input negative case proving the function still fails closed.

import (
	"strings"
	"testing"
)

func TestPodUIDFromCgroupsPath(t *testing.T) {
	const wantUID = "34b0b99f-b322-4cd8-b4e2-6b3003963468"

	t.Run("systemd underscore-encoded slice token", func(t *testing.T) {
		// The live-captured shape (G0.2)
		// every current platform (kind/kubeadm/KVM/k3s/RKE2) actually emits.
		path := "kubepods-besteffort-pod34b0b99f_b322_4cd8_b4e2_6b3003963468.slice:cri-containerd:6aa6e1e43a48"
		got, err := podUIDFromCgroupsPath(path)
		if err != nil {
			t.Fatalf("podUIDFromCgroupsPath(%q): unexpected error: %v", path, err)
		}
		if got != wantUID {
			t.Fatalf("got %q, want %q", got, wantUID)
		}
	})

	t.Run("hyphenated UUID form (future cgroupfs-driver raw-path substrate)", func(t *testing.T) {
		// Not hypothetical: resolveCgroupAnchorTarget's sibling isSliceToken/expandSliceToken
		// path (server.go ~5900-5990) deliberately keeps a raw hyphenated-path passthrough for
		// this substrate. The extraction contract must match what that path actually promises
		// to support.
		path := "/sys/fs/cgroup/kubepods/pod34b0b99f-b322-4cd8-b4e2-6b3003963468.slice/cri-containerd-abc.scope"
		got, err := podUIDFromCgroupsPath(path)
		if err != nil {
			t.Fatalf("podUIDFromCgroupsPath(%q): unexpected error: %v", path, err)
		}
		if got != wantUID {
			t.Fatalf("got %q, want %q", got, wantUID)
		}
	})

	t.Run("hyphenated form embedded in a slice-token-shaped path", func(t *testing.T) {
		// Same hyphenated encoding, but wrapped in the ":"-delimited slice-token shape rather
		// than a raw filesystem path, to prove the token scan (not the outer shape) is what
		// determines the encoding accepted.
		path := "kubepods-besteffort-pod34b0b99f-b322-4cd8-b4e2-6b3003963468.slice:cri-containerd:6aa6e1e43a48"
		got, err := podUIDFromCgroupsPath(path)
		if err != nil {
			t.Fatalf("podUIDFromCgroupsPath(%q): unexpected error: %v", path, err)
		}
		if got != wantUID {
			t.Fatalf("got %q, want %q", got, wantUID)
		}
	})

	t.Run("malformed input with no extractable pod UID fails closed", func(t *testing.T) {
		for _, path := range []string{
			"",
			"kubepods-besteffort-podshort.slice:cri-containerd:abc",
			"kubepods-besteffort.slice:cri-containerd:abc",
			"kubepods-besteffort-pod34b0b99fb3224cd8b4e26b3003963468.slice:cri-containerd:abc", // 32 hex, no separators
		} {
			got, err := podUIDFromCgroupsPath(path)
			if err == nil {
				t.Fatalf("podUIDFromCgroupsPath(%q): expected fail-closed error, got success (%q)", path, got)
			}
			if !strings.Contains(err.Error(), "ADR-0351 D2.5") {
				t.Fatalf("podUIDFromCgroupsPath(%q): error %q should cite ADR-0351 D2.5", path, err.Error())
			}
		}
	})
}
