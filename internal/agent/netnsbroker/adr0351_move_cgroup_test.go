// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package netnsbroker

// adr0351_move_cgroup_test.go covers the move_cgroup op's ExpectedPodUID cross-check
// (ADR-0351 D2.5, sprint53-kind) with real behavioral assertions — Handle(Request{...})
// end to end, mirroring the TestHandleSignalPID pattern (broker_test.go) QA pointed at as
// the precedent: positive success, a mismatch rejection, and an empty-required-field
// rejection, all driven through the same Handle entrypoint the broker actually serves.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// withFixtureCgroupFsRoot points the package-level cgroupFsRoot var at a temp fixture tree
// for the duration of the test, restoring the real value on cleanup. Mirrors the identical
// idiom already established in internal/agent/server's adr0351_cgroup_anchor_test.go.
func withFixtureCgroupFsRoot(t *testing.T) string {
	t.Helper()
	fixture := t.TempDir()
	orig := cgroupFsRoot
	cgroupFsRoot = fixture
	t.Cleanup(func() { cgroupFsRoot = orig })
	return fixture
}

// TestHandleMoveCgroup locks in the SC-1 properties of the move_cgroup op's ADR-0351 D2.5
// ExpectedPodUID cross-check: a correctly-matching UID succeeds and actually performs the
// cgroup.procs write, a mismatched UID is rejected BEFORE any write, and a missing UID is
// rejected outright. Uses a fixture cgroupfs tree (withFixtureCgroupFsRoot) so the write is
// a plain file write in a t.TempDir(), never a real host cgroup.
func TestHandleMoveCgroup(t *testing.T) {
	self := os.Getpid()
	liveStart, err := procStartTime(self)
	if err != nil {
		t.Fatalf("procStartTime(self=%d): %v", self, err)
	}

	const podUID = "34b0b99f-b322-4cd8-b4e2-6b3003963468"
	const podUIDUnderscored = "34b0b99f_b322_4cd8_b4e2_6b3003963468"

	setupFixtureLeaf := func(t *testing.T) (fixtureRelPath string) {
		t.Helper()
		fixture := withFixtureCgroupFsRoot(t)
		leafDir := filepath.Join(fixture, "kubepods", "pod"+podUIDUnderscored+".slice")
		if err := os.MkdirAll(leafDir, 0o755); err != nil {
			t.Fatalf("mkdir fixture cgroup leaf: %v", err)
		}
		return filepath.Join("kubepods", "pod"+podUIDUnderscored+".slice")
	}

	t.Run("correct expectedPodUID + valid cgroup path succeeds and writes cgroup.procs", func(t *testing.T) {
		relPath := setupFixtureLeaf(t)
		resp := Handle(Request{
			Op:                "move_cgroup",
			SignalPID:         self,
			CgroupPath:        relPath,
			ExpectedStartTime: liveStart,
			ExpectedPodUID:    podUID,
		})
		if resp.Error != "" {
			t.Fatalf("expected success, got error %q", resp.Error)
		}
		procsPath := filepath.Join(cgroupFsRoot, relPath, "cgroup.procs")
		got, rerr := os.ReadFile(procsPath)
		if rerr != nil {
			t.Fatalf("expected cgroup.procs to have been written at %s: %v", procsPath, rerr)
		}
		if string(got) != strconv.Itoa(self) {
			t.Fatalf("cgroup.procs content = %q, want %q", got, strconv.Itoa(self))
		}
	})

	t.Run("mismatched expectedPodUID is rejected (pod-confinement) before any write", func(t *testing.T) {
		relPath := setupFixtureLeaf(t)
		const wrongPodUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
		resp := Handle(Request{
			Op:                "move_cgroup",
			SignalPID:         self,
			CgroupPath:        relPath,
			ExpectedStartTime: liveStart,
			ExpectedPodUID:    wrongPodUID,
		})
		if resp.Error == "" {
			t.Fatalf("expected pod-confinement rejection on UID mismatch, got success")
		}
		if !strings.Contains(resp.Error, "pod-confinement") {
			t.Fatalf("error %q should mention pod-confinement", resp.Error)
		}
		procsPath := filepath.Join(cgroupFsRoot, relPath, "cgroup.procs")
		if _, statErr := os.Stat(procsPath); statErr == nil {
			t.Fatalf("cgroup.procs must NOT have been written on a UID mismatch (found %s)", procsPath)
		}
	})

	t.Run("empty expectedPodUID is rejected", func(t *testing.T) {
		relPath := setupFixtureLeaf(t)
		resp := Handle(Request{
			Op:                "move_cgroup",
			SignalPID:         self,
			CgroupPath:        relPath,
			ExpectedStartTime: liveStart,
			ExpectedPodUID:    "",
		})
		if resp.Error == "" {
			t.Fatalf("expected rejection for empty ExpectedPodUID, got success")
		}
		if !strings.Contains(resp.Error, "move_cgroup") {
			t.Fatalf("error %q should mention move_cgroup", resp.Error)
		}
	})

	t.Run("unknown op error names move_cgroup", func(t *testing.T) {
		resp := Handle(Request{Op: "bogus"})
		if resp.Error == "" || !strings.Contains(resp.Error, "move_cgroup") {
			t.Fatalf("unknown-op error should list move_cgroup, got %q", resp.Error)
		}
	})
}

// TestCgroupPathContainsPodUID locks in that the ADR-0351 D2.5 cross-check matches a pod
// UID regardless of which cgroup-path encoding it appears in — systemd's underscore form
// or the standard hyphenated form — since server.go's podUIDFromCgroupsPath can hand this
// function a canonical-hyphenated ExpectedPodUID that must still be found inside a
// systemd-underscored resolved path (the common case), and vice versa.
func TestCgroupPathContainsPodUID(t *testing.T) {
	const podUID = "34b0b99f-b322-4cd8-b4e2-6b3003963468"
	const podUIDUnderscored = "34b0b99f_b322_4cd8_b4e2_6b3003963468"

	t.Run("matches when path contains the underscore-encoded form", func(t *testing.T) {
		path := "/sys/fs/cgroup/kubepods/pod" + podUIDUnderscored + ".slice"
		if !cgroupPathContainsPodUID(path, podUID) {
			t.Fatalf("expected match: path %q contains underscore-encoded UID for %q", path, podUID)
		}
	})

	t.Run("matches when path contains the hyphenated form", func(t *testing.T) {
		path := "/sys/fs/cgroup/kubepods/pod" + podUID + ".slice"
		if !cgroupPathContainsPodUID(path, podUID) {
			t.Fatalf("expected match: path %q contains hyphenated UID for %q", path, podUID)
		}
	})

	t.Run("no match when path contains neither form", func(t *testing.T) {
		path := "/sys/fs/cgroup/kubepods/pod11111111_1111_1111_1111_111111111111.slice"
		if cgroupPathContainsPodUID(path, podUID) {
			t.Fatalf("expected no match: path %q does not contain %q in either encoding", path, podUID)
		}
	})
}
