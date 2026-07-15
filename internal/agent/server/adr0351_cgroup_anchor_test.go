// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 The PodMotion Authors

package server

// adr0351_cgroup_anchor_test.go pins the ADR-0351 cgroup-anchor restore primitive — replacing
// adr0351_pause_pid_wait_test.go and adr0351_parse_pause_pid_test.go (both deleted in the same
// diff, D3.3). Exercises resolveCgroupAnchorTarget (the pure D2 seam) directly, mirroring the
// parsePausePIDFromTaskTable precedent this ADR retires: pull the testable logic out of the I/O
// wrapper so it doesn't require a real host cgroupfs or driving joinNsRestore's untestable body.
//
// Shapes used below are the LIVE G0.1/G0.2-captured values (docs/sprints/sprint46B7/
// g0-probe-adr0351-transcript.md), not invented formats — per D2.2's own requirement.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	g0SliceName             = "kubepods-burstable-podcda2f880_ea57_46f8_a09c_2c33294b204d.slice"
	g0ContainerID           = "6aa6e1e43a48c887069c03dbcdb219617aea90735ab0e89d17f196be3ad35723"
	g0ContainerCgroupsPath  = g0SliceName + ":cri-containerd:" + g0ContainerID
	g0PodCgroupParent       = "/kubepods.slice/kubepods-burstable.slice/" + g0SliceName
	g0ExpandedContainerLeaf = "/kubepods.slice/kubepods-burstable.slice/" + g0SliceName + "/cri-containerd-" + g0ContainerID + ".scope"
)

// withFixtureCgroupFsRoot points the package-level cgroupFsRoot var at a temp fixture tree for
// the duration of the test, restoring the real value on cleanup. Mirrors the existing
// package-var-override idiom used throughout this package (joinNsRestoreFn, sandboxIDForPodUIDFn).
func withFixtureCgroupFsRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	fixture := filepath.Join(root, "cgroupfs")
	if err := os.MkdirAll(fixture, 0o755); err != nil {
		t.Fatalf("mkdir fixture cgroupfs root: %v", err)
	}
	orig := cgroupFsRoot
	cgroupFsRoot = fixture
	t.Cleanup(func() { cgroupFsRoot = orig })
	return fixture
}

// TestCgroupAnchor_TargetIsContainerOwnScope proves resolveCgroupAnchorTarget resolves to the
// migrated CONTAINER's own cgroup leaf (D2.1) — never the pause/sandbox scope — using the
// live-captured slice-token shape (G0.2).
func TestCgroupAnchor_TargetIsContainerOwnScope(t *testing.T) {
	fixture := withFixtureCgroupFsRoot(t)
	leafDir := filepath.Join(fixture, "kubepods.slice", "kubepods-burstable.slice", g0SliceName, "cri-containerd-"+g0ContainerID+".scope")
	if err := os.MkdirAll(leafDir, 0o755); err != nil {
		t.Fatalf("mkdir container leaf fixture: %v", err)
	}
	// A sibling PAUSE container leaf under the SAME parent slice — proves the resolved target is
	// keyed to the CONTAINER's own ID, not merely "some scope under the pod slice."
	pauseLeafDir := filepath.Join(fixture, "kubepods.slice", "kubepods-burstable.slice", g0SliceName, "cri-containerd-5b1eb601de341edb322c996c7055dfbb715dcebfd17ecb096e26acab9eba217c.scope")
	if err := os.MkdirAll(pauseLeafDir, 0o755); err != nil {
		t.Fatalf("mkdir pause leaf fixture: %v", err)
	}

	got, err := resolveCgroupAnchorTarget(g0ContainerCgroupsPath, g0PodCgroupParent)
	if err != nil {
		t.Fatalf("resolveCgroupAnchorTarget returned unexpected error: %v", err)
	}
	want := strings.TrimPrefix(g0ExpandedContainerLeaf, "")
	if got != want {
		t.Fatalf("got anchor target %q, want %q (container's own scope)", got, want)
	}
	if strings.Contains(got, "5b1eb601") {
		t.Fatalf("anchor target %q resolved into the PAUSE container's scope, not the migrated container's own scope (Defect 2 regression)", got)
	}
}

// TestCgroupAnchor_SliceTokenExpansion asserts expandSliceToken/resolveCgroupAnchorTarget expand
// the LIVE-captured systemd slice-token shape (G0.2) to the real filesystem leaf — not an
// invented format. Also proves the raw-path passthrough branch (isSliceToken == false) is a
// no-op, for the substrate where the field ever arrives as a raw path instead.
func TestCgroupAnchor_SliceTokenExpansion(t *testing.T) {
	t.Run("slice token expands to the G0.2 captured shape", func(t *testing.T) {
		got, err := expandSliceToken(g0ContainerCgroupsPath)
		if err != nil {
			t.Fatalf("expandSliceToken: %v", err)
		}
		if got != g0ExpandedContainerLeaf {
			t.Fatalf("got %q, want %q", got, g0ExpandedContainerLeaf)
		}
	})

	t.Run("raw path is a no-op passthrough (isSliceToken false)", func(t *testing.T) {
		fixture := withFixtureCgroupFsRoot(t)
		rawLeaf := "/kubepods.slice/kubepods-burstable.slice/" + g0SliceName + "/cri-containerd-" + g0ContainerID + ".scope"
		if err := os.MkdirAll(filepath.Join(fixture, rawLeaf), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if isSliceToken(rawLeaf) {
			t.Fatalf("isSliceToken(%q) = true, want false (raw /sys/fs/cgroup-relative path, not a slice token)", rawLeaf)
		}
		got, err := resolveCgroupAnchorTarget(rawLeaf, g0PodCgroupParent)
		if err != nil {
			t.Fatalf("resolveCgroupAnchorTarget: %v", err)
		}
		if got != rawLeaf {
			t.Fatalf("got %q, want %q (raw-path passthrough, no expansion)", got, rawLeaf)
		}
	})

	t.Run("isSliceToken true only for the 2-colon slice-token shape", func(t *testing.T) {
		if !isSliceToken(g0ContainerCgroupsPath) {
			t.Fatalf("isSliceToken(%q) = false, want true", g0ContainerCgroupsPath)
		}
		if isSliceToken("/kubepods.slice/foo.scope") {
			t.Fatal("isSliceToken should be false for a leading-slash raw path")
		}
	})
}

// TestCgroupAnchor_RejectParentSliceWrite asserts an anchor target that resolves to exactly the
// pod's PARENT slice (never a write target, D2.3 — cgroup v2 no-internal-process rule) is
// rejected, fail-closed.
func TestCgroupAnchor_RejectParentSliceWrite(t *testing.T) {
	fixture := withFixtureCgroupFsRoot(t)
	parentDir := filepath.Join(fixture, g0PodCgroupParent)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		t.Fatalf("mkdir parent fixture: %v", err)
	}

	// A raw (non-slice-token) containerCgroupsPath that is BYTE-IDENTICAL to podCgroupParent —
	// the anchor would otherwise resolve directly onto the parent slice.
	_, err := resolveCgroupAnchorTarget(g0PodCgroupParent, g0PodCgroupParent)
	if err == nil {
		t.Fatal("resolveCgroupAnchorTarget did not reject an anchor target equal to the pod PARENT slice — D2.3 EBUSY hazard")
	}
	if !strings.Contains(err.Error(), "PARENT slice") {
		t.Fatalf("error %q does not cite the parent-slice rejection reason (D2.3)", err.Error())
	}
}

// TestCgroupAnchor_RejectNonKubepodsPath proves REAL canonicalization (filepath.EvalSymlinks +
// prefix check) defeats both a lexical ".." traversal AND a symlink escape — not lexical
// filepath.Clean alone (D2.4/BD-10, CIA condition: both cases required).
func TestCgroupAnchor_RejectNonKubepodsPath(t *testing.T) {
	t.Run("dot-dot traversal", func(t *testing.T) {
		root := t.TempDir()
		fixture := filepath.Join(root, "cgroupfs")
		if err := os.MkdirAll(fixture, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		// The escape target: a REAL directory OUTSIDE the cgroupfs fixture root, so EvalSymlinks
		// succeeds (proving this is a real-canonicalization rejection, not a bare not-found).
		escapeDir := filepath.Join(root, "etc")
		if err := os.MkdirAll(escapeDir, 0o755); err != nil {
			t.Fatalf("mkdir escape target: %v", err)
		}
		orig := cgroupFsRoot
		cgroupFsRoot = fixture
		defer func() { cgroupFsRoot = orig }()

		_, err := resolveCgroupAnchorTarget("../etc", "")
		if err == nil {
			t.Fatal("resolveCgroupAnchorTarget accepted a '..'-traversal path that resolves OUTSIDE cgroupFsRoot/kubepods — path-confinement bypass (D2.4/BD-10)")
		}
		if !strings.Contains(err.Error(), "path-confinement") {
			t.Fatalf("error %q does not cite path-confinement (BD-10)", err.Error())
		}
	})

	t.Run("symlink escape", func(t *testing.T) {
		root := t.TempDir()
		fixture := filepath.Join(root, "cgroupfs")
		kubepodsDir := filepath.Join(fixture, "kubepods.slice")
		if err := os.MkdirAll(kubepodsDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		escapeDir := filepath.Join(root, "escape-target")
		if err := os.MkdirAll(escapeDir, 0o755); err != nil {
			t.Fatalf("mkdir escape target: %v", err)
		}
		// A symlink INSIDE the kubepods subtree that points OUTSIDE it — lexical Clean/prefix
		// checks on the SYMLINK PATH ITSELF would incorrectly pass; only EvalSymlinks catches this.
		linkPath := filepath.Join(kubepodsDir, "escape-link")
		if err := os.Symlink(escapeDir, linkPath); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		orig := cgroupFsRoot
		cgroupFsRoot = fixture
		defer func() { cgroupFsRoot = orig }()

		_, err := resolveCgroupAnchorTarget("kubepods.slice/escape-link", "")
		if err == nil {
			t.Fatal("resolveCgroupAnchorTarget accepted a symlink that resolves OUTSIDE cgroupFsRoot/kubepods — lexical-only confinement is insufficient (D2.4/BD-10)")
		}
		if !strings.Contains(err.Error(), "path-confinement") {
			t.Fatalf("error %q does not cite path-confinement (BD-10)", err.Error())
		}
	})
}

// TestCgroupAnchor_NoQueryNoPoll is D1.4/BD-2's falsifiable no-poll regression test. It asserts,
// by construction, that resolveCgroupAnchorTarget (the entire D2 anchor-resolution seam) contains
// NO exec/nsenter/containerd query call and NO sleep/retry loop — a future dev re-adding any
// fallback tier changes this source text and fails this test instead of shipping green.
// Complementary timing check: many calls complete fast, consistent with a pure/IO-light function.
func TestCgroupAnchor_NoQueryNoPoll(t *testing.T) {
	src := readAnchorFuncSource(t, "func resolveCgroupAnchorTarget(")
	forbidden := []string{"exec.Command(", "nsenterCmd(", "ctr ", "time.Sleep(", "time.After(", "for {", "context.WithTimeout("}
	for _, tok := range forbidden {
		if strings.Contains(src, tok) {
			t.Fatalf("resolveCgroupAnchorTarget source contains forbidden token %q — the anchor path must stay zero-query/zero-poll/zero-retry (D1.4/BD-2)", tok)
		}
	}

	fixture := withFixtureCgroupFsRoot(t)
	if err := os.MkdirAll(filepath.Join(fixture, "kubepods.slice", "kubepods-burstable.slice", g0SliceName, "cri-containerd-"+g0ContainerID+".scope"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	start := time.Now()
	for i := 0; i < 100; i++ {
		if _, err := resolveCgroupAnchorTarget(g0ContainerCgroupsPath, g0PodCgroupParent); err != nil {
			t.Fatalf("resolveCgroupAnchorTarget: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("100 calls to resolveCgroupAnchorTarget took %s — too slow for a zero-query/zero-poll primitive (D1.4/BD-2)", elapsed)
	}
}

// TestCgroupAnchor_NoSecondOwnershipLock asserts the anchor-resolution path introduces NO
// independent claim/release registry of its own (D2.5/BD-7) — the anchor is a read-only consumer
// of ADR-0353's single-owner claim, reached only from inside joinNsRestore (which ADR-0353 R2
// asserts is claimed on entry). A documentation-grade structural check: neither
// resolveCgroupAnchorTarget nor moveProcessToPodCgroup declares or touches a mutex/claim map.
func TestCgroupAnchor_NoSecondOwnershipLock(t *testing.T) {
	for _, marker := range []string{"func resolveCgroupAnchorTarget(", "func moveProcessToPodCgroup("} {
		src := readAnchorFuncSource(t, marker)
		for _, tok := range []string{"sync.Mutex", "sync.RWMutex", ".Lock()", ".Unlock()", "restoreClaims["} {
			if strings.Contains(src, tok) {
				t.Fatalf("%s contains %q — the anchor must not establish or touch any claim/lock registry of its own; ownership is INHERITED from ADR-0353's one claim (D2.5/BD-7)", marker, tok)
			}
		}
	}
}

// TestCgroupAnchor_WholeTreeContainment documents the D2.6/BD-8 whole-tree-containment scope
// (Open verification #6): moveProcessToPodCgroup's single cgroup.procs write moves only the
// written PID's thread-group, not necessarily every descendant TGID of a multi-process restored
// tree. This is a PRE-EXISTING moveProcessToPodCgroup property this ADR does not change (only the
// anchor TARGET changes) — the live D2.6 proof script (docs/sprints/sprint46B7/validation-tests/
// run-adr0351-cgroup-anchor-live-proof.sh) is what actually MEASURES whole-tree containment
// against a real multi-process workload; this unit test asserts the documented single-write
// property structurally so a future silent change to move multiple PIDs is visible here too.
func TestCgroupAnchor_WholeTreeContainment(t *testing.T) {
	src := readAnchorFuncSource(t, "func moveProcessToPodCgroup(")
	if strings.Count(src, "WriteFile") != 1 {
		t.Fatalf("moveProcessToPodCgroup's cgroup.procs write count changed (found %d os.WriteFile calls) — if this now writes multiple PIDs/walks descendants, update the D2.6/BD-8 Consequences containment claim scope and this test together; do not let scope silently change unnoticed", strings.Count(src, "WriteFile"))
	}
	t.Log("BD-8: whole-tree (multi-process descendant TGID) containment is NOT unit-testable without a real process tree + real cgroupfs — MEASURED by the live D2.6 proof script, not this test. This test only pins the pre-existing single-root-PID-write property so a change to that property is visible.")
}

// TestCgroupAnchor_G5ReapOnTerminalLeg mirrors the retained TestReapRestoredProcessTreeFn_Injectable
// (moved here from the deleted adr0351_pause_pid_wait_test.go): proves the ADR-0351 G5 reap seam
// is a real, overridable function var, independent of driving joinNsRestore itself (joinNsRestore
// has no unit-test seam for its own body — see the deleted file's original scope note, preserved
// here: it performs real ctr image pull/list, checkpoint-image patching, and overlayfs mount calls
// with no injection seam for any of that).
//
// Round 2 (sprint46B7): reapRestoredProcessTreeFn now takes (pid, holderPID) — the caller-known
// CRIU/wrapper holder is passed explicitly rather than re-derived, so this injectability test
// asserts BOTH arguments are threaded through unchanged. See
// TestReapRestoredProcessTree_ScopedToOwnTree_NotBrokerOrSiblings below for the real (non-spy)
// blast-radius proof this spy-only test cannot provide on its own.
func TestCgroupAnchor_G5ReapOnTerminalLeg(t *testing.T) {
	origFn := reapRestoredProcessTreeFn
	var gotPID, gotHolder int
	var called int32
	reapRestoredProcessTreeFn = func(pid, holderPID int) {
		atomic.AddInt32(&called, 1)
		gotPID = pid
		gotHolder = holderPID
	}
	defer func() { reapRestoredProcessTreeFn = origFn }()

	reapRestoredProcessTreeFn(31337, 31336)

	if atomic.LoadInt32(&called) != 1 {
		t.Fatalf("reapRestoredProcessTreeFn was not invoked")
	}
	if gotPID != 31337 {
		t.Fatalf("got pid=%d, want 31337", gotPID)
	}
	if gotHolder != 31336 {
		t.Fatalf("got holderPID=%d, want 31336", gotHolder)
	}
}

// TestReapRestoredProcessTree_ScopedToOwnTree_NotBrokerOrSiblings is the real (non-spy) G5
// blast-radius proof named by the sprint46B7 round-2 defect report: round 1's
// TestCgroupAnchor_G5ReapOnTerminalLeg only ever spied on the overridable Fn var and never
// exercised the REAL reapRestoredProcessTree implementation, so it could not have caught the
// cross-migration cgroup.kill blast radius. This test drives the real production function
// against real OS processes (no cgroupfs/root needed — SIGKILL against processes this test
// owns requires no privilege) and proves two things in one pass:
//  1. every process in the target holder's own tree (holder + restored root + its descendant)
//     is actually killed;
//  2. a "bystander" process standing in for the broker daemon / a sibling migration's restored
//     tree — deliberately NOT a descendant of the reaped holder — survives untouched. Under the
//     retired cgroup.kill design this bystander would have died too if it shared a cgroup with
//     the reaped tree; the kernel-process-hierarchy walk this test exercises has no such shared
//     blast radius by construction.
func TestReapRestoredProcessTree_ScopedToOwnTree_NotBrokerOrSiblings(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires /proc/<pid>/task/<pid>/children (Linux + CONFIG_CHECKPOINT_RESTORE=y)")
	}

	// sleeper spawns a long-lived child that itself spawns one grandchild, mirroring the
	// holder(CRIU) -> restored-root -> descendant shape reapRestoredProcessTree must fully reap.
	spawnTree := func(t *testing.T) (holderPID, rootPID, descendantPID int, cleanup func()) {
		t.Helper()
		// holder: `sh -c` that execs a grandchild sleep, itself standing in for the restored root.
		holderCmd := exec.Command("sh", "-c", "sleep 300 & wait")
		if err := holderCmd.Start(); err != nil {
			t.Fatalf("start holder: %v", err)
		}
		holderPID = holderCmd.Process.Pid
		// Give the shell a moment to fork its "sleep 300" child, then read it from /proc.
		var childPID int
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			kids := collectProcessTree(holderPID)
			if len(kids) >= 2 {
				for _, k := range kids {
					if k != holderPID {
						childPID = k
						break
					}
				}
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if childPID == 0 {
			_ = holderCmd.Process.Kill()
			t.Fatalf("holder never produced a child within deadline")
		}
		cleanup = func() {
			_ = holderCmd.Process.Kill()
			_ = holderCmd.Wait()
		}
		return holderPID, holderPID, childPID, cleanup
	}

	holderPID, rootPID, descendantPID, cleanup := spawnTree(t)
	defer cleanup()

	// Bystander: an entirely separate process tree, standing in for the broker daemon / a
	// sibling migration's restored tree. It shares no ancestry with the reaped holder.
	bystander := exec.Command("sleep", "300")
	if err := bystander.Start(); err != nil {
		t.Fatalf("start bystander: %v", err)
	}
	bystanderPID := bystander.Process.Pid
	defer func() {
		_ = bystander.Process.Kill()
		_ = bystander.Wait()
	}()

	reapRestoredProcessTree(rootPID, holderPID)

	// Give SIGKILL delivery a moment to land. A signal-0 kill() probe is insufficient here: the
	// test process is holderPID's real OS parent (spawned via exec.Command), so a SIGKILLed
	// holder sits as a zombie — still present in the process table, still answering kill(pid,0)
	// — until Wait()ed. Use procStatStateChar (already in this package) and treat zombie ('Z')
	// or "no such /proc entry" as reaped/dead; only a non-zombie, readable state counts as alive.
	alive := func(pid int) bool {
		state, err := procStatStateChar(pid)
		if err != nil {
			return false
		}
		return state != 'Z'
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (alive(holderPID) || alive(descendantPID)) {
		time.Sleep(20 * time.Millisecond)
	}

	if alive(holderPID) {
		t.Errorf("holder PID %d still alive after reapRestoredProcessTree", holderPID)
	}
	if alive(descendantPID) {
		t.Errorf("descendant PID %d still alive after reapRestoredProcessTree", descendantPID)
	}
	if !alive(bystanderPID) {
		t.Fatalf("bystander PID %d (unrelated tree — stands in for the broker daemon / a sibling migration) was killed — cross-migration/broker blast radius regression", bystanderPID)
	}
}

// readAnchorFuncSource returns the body of the function starting at marker in server.go, up to
// (not including) the next top-level `func` declaration. Mirrors readServerSource
// (restore_pid_resolver_symmetry_test.go) but parameterized over the marker so multiple small
// functions (resolveCgroupAnchorTarget, moveProcessToPodCgroup) can each be inspected in
// isolation rather than only joinNsRestore's body.
func readAnchorFuncSource(t *testing.T, marker string) string {
	t.Helper()
	data, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	src := string(data)
	start := strings.Index(src, marker)
	if start < 0 {
		t.Fatalf("could not locate %q in server.go", marker)
	}
	rest := src[start+len(marker):]
	nextFunc := strings.Index(rest, "\nfunc ")
	if nextFunc < 0 {
		t.Fatalf("could not find end of function starting at %q", marker)
	}
	return src[start : start+len(marker)+nextFunc]
}
