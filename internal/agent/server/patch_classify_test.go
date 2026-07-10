/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

// patch_classify_test.go — unit coverage for the single files.img REG-fd classifier
// (classify_reg_fd inside classifyRegFdPy).
//
// Unlike patch_checkpoint_test.go's Go-mirror + string-grep sync guard (the anti-pattern
// that let a Go re-implementation drift from the real Python and miss defects — see
// patch_checkpoint_regfd_test.go's flaw), this test runs the ACTUAL production classifier
// string. It writes classifyRegFdPy to a temp file and invokes `python3 <file>
// --classify-selftest`, feeding plain-dict entries on stdin — no pycriu image dump is
// needed because classification is pure dict logic. What ships is what is tested.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// classifyResult mirrors one element of the --classify-selftest JSON output: the classifier
// action plus (ADR-0311) the entry_type ('DIR'|'REG') the production call site now surfaces.
type classifyResult struct {
	Action    string `json:"action"`
	EntryType string `json:"entry_type"`
}

// runClassifySelftest runs the production classifier in --classify-selftest mode over the
// given ctx + entries and returns one {action, entry_type} result per entry.
func runClassifySelftest(t *testing.T, ctx map[string]any, entries []map[string]any) []classifyResult {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available — skipping real-classifier selftest")
	}
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "pm-classify.py")
	if err := os.WriteFile(scriptPath, []byte(classifyRegFdPy), 0o600); err != nil {
		t.Fatalf("write classifier script: %v", err)
	}
	payload, err := json.Marshal(map[string]any{"ctx": ctx, "entries": entries})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	cmd := exec.Command("python3", scriptPath, "--classify-selftest")
	cmd.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("classifier selftest failed: %v\nstderr: %s", err, stderr.String())
	}
	var results []classifyResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("parse results %q: %v", string(out), err)
	}
	return results
}

// actionsOf extracts just the action strings, for tests that don't care about entry_type.
func actionsOf(results []classifyResult) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r.Action
	}
	return out
}

// reg builds a REG files.img entry with the given id/name/mnt_id/mode/ext.
func reg(id int, name string, mntID int, mode int, ext bool) map[string]any {
	return map[string]any{
		"type": "REG",
		"id":   id,
		"reg": map[string]any{
			"name":   name,
			"mnt_id": mntID,
			"mode":   mode,
			"ext":    ext,
		},
	}
}

const (
	modeDir  = 0o040000 // S_IFDIR
	modeFile = 0o100644 // regular file
)

// TestClassifyRegFd_RealScript exercises every action the production classifier can return,
// by running the shipped Python — one entry per branch.
func TestClassifyRegFd_RealScript(t *testing.T) {
	ctx := map[string]any{
		"remap_ids":        []int{7},
		"inherit_fd_names": []string{"sys/fs/cgroup/cpu.max"},
		"kept_mnt_ids":     []int{1, 100},
		"ext_drop_mnt_ids": []int{500},
		"root_mnt_id":      1, // ADR-0245 D2: sane rebind target (present + kept).
	}
	entries := []map[string]any{
		// 0: non-REG entry → KEEP (out of scope).
		{"type": "PIPE", "id": 1, "reg": map[string]any{}},
		// 1: external fd with an orphan mnt_id → KEEP (exits before open_path).
		reg(10, "/data", 999, modeFile, true),
		// 2: remap fd (id in remap_ids) with orphan mnt_id → KEEP.
		reg(7, "/foo", 999, modeFile, false),
		// 3: inherited fd (slash-stripped name matches) → KEEP.
		reg(11, "/sys/fs/cgroup/cpu.max", 999, modeFile, false),
		// 4: sentinel mnt_id 0 → KEEP.
		reg(12, "/bar", 0, modeFile, false),
		// 5: consistent — mnt_id in kept set → KEEP.
		reg(13, "/baz", 100, modeFile, false),
		// 6: orphan DIRECTORY fd → REBIND_TO_ROOT.
		reg(14, "/data", 500, modeDir, false),
		// 7: orphan NON-directory fd → DECLINE (hard-stop class).
		reg(15, "/data/file", 501, modeFile, false),
	}
	want := []string{"KEEP", "KEEP", "KEEP", "KEEP", "KEEP", "KEEP", "REBIND_TO_ROOT", "DECLINE"}

	got := actionsOf(runClassifySelftest(t, ctx, entries))
	if len(got) != len(want) {
		t.Fatalf("got %d actions, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got action %q, want %q", i, got[i], want[i])
		}
	}
}

// TestClassifyRegFd_RebindThenReCheckKeep proves the key one-classifier property the re-check
// pass relies on: an orphan directory fd classifies REBIND_TO_ROOT, and after its mnt_id is
// rebound to a kept root mnt_id the SAME classifier returns KEEP — so the post-write re-check
// (which calls the identical classify_reg_fd) does not false-positive on a legitimately
// reconciled fd.
func TestClassifyRegFd_RebindThenReCheckKeep(t *testing.T) {
	const rootMntID = 1
	ctx := map[string]any{
		"remap_ids":        []int{},
		"inherit_fd_names": []string{},
		"kept_mnt_ids":     []int{rootMntID},
		"ext_drop_mnt_ids": []int{500},
		"root_mnt_id":      rootMntID,
	}
	orphanDir := reg(20, "/data", 500, modeDir, false)
	if got := runClassifySelftest(t, ctx, []map[string]any{orphanDir}); got[0].Action != "REBIND_TO_ROOT" {
		t.Fatalf("orphan dir: got %q, want REBIND_TO_ROOT", got[0].Action)
	}
	// Simulate the main pass rebinding mnt_id -> rootMntID, then re-run the classifier.
	rebound := reg(20, "/data", rootMntID, modeDir, false)
	if got := runClassifySelftest(t, ctx, []map[string]any{rebound}); got[0].Action != "KEEP" {
		t.Fatalf("rebound dir: got %q, want KEEP (re-check must not false-positive)", got[0].Action)
	}
}

// TestClassifyRegFd_DirRebindTargetValidation covers the ADR-0245 D2 (Storage Architect)
// fail-closed fix: an orphan directory fd is only rebound when the rebind target (root_mnt_id)
// is itself sane — present AND a kept mountpoint. When the target is missing or absent from the
// kept set, rebinding would just move the fd onto another mnt_id that is ALSO not in the restored
// mount set (firing mount.c:3953 anyway), so the classifier fails loud (DECLINE) instead of
// silently redirecting the directory handle to an unusable target.
func TestClassifyRegFd_DirRebindTargetValidation(t *testing.T) {
	orphanDir := reg(30, "/data", 500, modeDir, false)

	cases := []struct {
		name       string
		rootMntID  any   // nil => key present but null; omitted below via missing flag
		omitRoot   bool  // true => root_mnt_id key absent entirely
		keptMntIDs []int
		want       string
	}{
		{
			// Safe scaffolding / ext-drop lockstep rebind: target present + kept => REBIND_TO_ROOT.
			// (The production call site additionally emits a WARNING for this case.)
			name:       "sane target rebinds",
			rootMntID:  1,
			keptMntIDs: []int{1},
			want:       "REBIND_TO_ROOT",
		},
		{
			// Ambiguous / unusable target: root_mnt_id set but NOT in the kept set. Rebinding
			// would land on an absent mnt_id — fail loud instead of silently redirecting.
			name:       "target not in kept set declines",
			rootMntID:  7,
			keptMntIDs: []int{1},
			want:       "DECLINE",
		},
		{
			// root_mnt_id explicitly null (e.g. no '/' entry survived) => no sane target => DECLINE.
			name:       "null target declines",
			rootMntID:  nil,
			keptMntIDs: []int{1},
			want:       "DECLINE",
		},
		{
			// root_mnt_id key absent entirely (defensive: ctx.get returns None) => DECLINE.
			name:       "missing target key declines",
			omitRoot:   true,
			keptMntIDs: []int{1},
			want:       "DECLINE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := map[string]any{
				"remap_ids":        []int{},
				"inherit_fd_names": []string{},
				"kept_mnt_ids":     tc.keptMntIDs,
				"ext_drop_mnt_ids": []int{500},
			}
			if !tc.omitRoot {
				ctx["root_mnt_id"] = tc.rootMntID
			}
			got := runClassifySelftest(t, ctx, []map[string]any{orphanDir})
			if got[0].Action != tc.want {
				t.Errorf("orphan dir with %s: got %q, want %q", tc.name, got[0].Action, tc.want)
			}
		})
	}
}

// TestClassifyRegFd_GenericOrphanDirRebinds proves the "generic orphan" directory case (mnt_id
// in NEITHER the kept set NOR the ext-drop set — a mount that simply vanished from the
// mountpoints image, ADR-0193 §4) still classifies REBIND_TO_ROOT when the target is sane. This
// is the higher-suspicion case the production call site flags with the 'generic-orphan' label;
// the classifier keeps the rebind (visibility, not a hard block, is the fix) so the gate-proven
// ADR-0193 §4 path is preserved rather than escalated to a restore-breaking DECLINE.
func TestClassifyRegFd_GenericOrphanDirRebinds(t *testing.T) {
	ctx := map[string]any{
		"remap_ids":        []int{},
		"inherit_fd_names": []string{},
		"kept_mnt_ids":     []int{1},
		"ext_drop_mnt_ids": []int{}, // empty — mnt_id 777 is a generic orphan, not an ext-drop.
		"root_mnt_id":      1,
	}
	genericOrphanDir := reg(40, "/workload/pv-subdir", 777, modeDir, false)
	if got := runClassifySelftest(t, ctx, []map[string]any{genericOrphanDir}); got[0].Action != "REBIND_TO_ROOT" {
		t.Fatalf("generic orphan dir: got %q, want REBIND_TO_ROOT", got[0].Action)
	}
}

// TestClassifyRegFd_TmpfsShmRegRebind is ADR-0311 fixture (a): a positive shm REBIND. A
// non-directory (REG) orphan fd backed by a dropped tmpfs/shm mount (tmpfs_drop_mnt_ids)
// classifies REBIND_TO_ROOT — fixing the /dev/shm-backed workload (PostgreSQL) restore-abort
// that the old dir-vs-nondir proxy always DECLINEd. Asserts on the new entry_type field too.
func TestClassifyRegFd_TmpfsShmRegRebind(t *testing.T) {
	ctx := map[string]any{
		"remap_ids":          []int{},
		"inherit_fd_names":   []string{},
		"kept_mnt_ids":       []int{1},
		"ext_drop_mnt_ids":   []int{},
		"root_mnt_id":        1,
		"tmpfs_drop_mnt_ids": []int{600}, // e.g. /dev/shm, fstype=='TMPFS' at seed time.
	}
	shmRegFd := reg(50, "/dev/shm/PostgreSQL.123456", 600, modeFile, false)
	got := runClassifySelftest(t, ctx, []map[string]any{shmRegFd})
	if got[0].Action != "REBIND_TO_ROOT" {
		t.Fatalf("shm REG fd: got action %q, want REBIND_TO_ROOT", got[0].Action)
	}
	if got[0].EntryType != "REG" {
		t.Fatalf("shm REG fd: got entry_type %q, want REG", got[0].EntryType)
	}
}

// TestClassifyRegFd_UnaccountedOrphanDeclines is ADR-0311 fixture (b): a negative
// unaccounted-orphan DECLINE. A non-directory orphan fd whose mnt_id is in NEITHER
// kept_mnt_ids NOR tmpfs_drop_mnt_ids still hard-stops (Strict guard unweakened).
func TestClassifyRegFd_UnaccountedOrphanDeclines(t *testing.T) {
	ctx := map[string]any{
		"remap_ids":          []int{},
		"inherit_fd_names":   []string{},
		"kept_mnt_ids":       []int{1},
		"ext_drop_mnt_ids":   []int{},
		"root_mnt_id":        1,
		"tmpfs_drop_mnt_ids": []int{600},
	}
	unaccountedRegFd := reg(51, "/data/file", 999, modeFile, false)
	got := runClassifySelftest(t, ctx, []map[string]any{unaccountedRegFd})
	if got[0].Action != "DECLINE" {
		t.Fatalf("unaccounted orphan REG fd: got %q, want DECLINE", got[0].Action)
	}
}

// TestClassifyRegFd_SysfsOrphanDeclinesNoAliasing is ADR-0311 fixture (c): a negative
// sysfs-orphan DECLINE, with a tmpfs_drop_mnt_ids built by the SAME production seed logic
// (disjoint mnt_id namespace from the sysfs orphan under test), proving no aliasing between
// tmpfs_drop_mnt_ids and DROP_ROOT_FSTYPES(sysfs) — the Security Reviewer's explicit gating
// condition (decision 8c).
func TestClassifyRegFd_SysfsOrphanDeclinesNoAliasing(t *testing.T) {
	ctx := map[string]any{
		"remap_ids":        []int{},
		"inherit_fd_names": []string{},
		"kept_mnt_ids":     []int{1},
		"ext_drop_mnt_ids": []int{},
		"root_mnt_id":      1,
		// tmpfs_drop_mnt_ids seeded (as production does) from a DIFFERENT, disjoint mnt_id
		// (700, a real tmpfs) than the sysfs orphan under test (mnt_id 800) — proving the
		// sysfs orphan is not accidentally swept into the tmpfs set.
		"tmpfs_drop_mnt_ids": []int{700},
	}
	// mnt_id 800 simulates an orphan fd backed by a DROP_ROOT_FSTYPES(sysfs) mount — NOT in
	// kept_mnt_ids and NOT in tmpfs_drop_mnt_ids, so it must still DECLINE.
	sysfsOrphanRegFd := reg(52, "/sys/devices/virtual/dmi/id/product_name", 800, modeFile, false)
	got := runClassifySelftest(t, ctx, []map[string]any{sysfsOrphanRegFd})
	if got[0].Action != "DECLINE" {
		t.Fatalf("sysfs orphan REG fd: got %q, want DECLINE (no aliasing with tmpfs_drop_mnt_ids)", got[0].Action)
	}
}

// TestClassifyRegFd_NonShmTmpfsAliasingRebinds is ADR-0311 fixture (d): a positive non-shm
// tmpfs-aliasing fixture — a synthetic non-/dev/shm DROP_PATHS/DROP_ROOT_FSTYPES entry with
// fstype=='TMPFS' and a REG orphan fd on it still fires REBIND_TO_ROOT. Closes the Network
// Architect's generalization-unproven gap: the fix is keyed on fstype=='TMPFS', not on the
// /dev/shm path specifically. Asserts on entry_type per decision 8.
func TestClassifyRegFd_NonShmTmpfsAliasingRebinds(t *testing.T) {
	ctx := map[string]any{
		"remap_ids":        []int{},
		"inherit_fd_names": []string{},
		"kept_mnt_ids":     []int{1},
		"ext_drop_mnt_ids": []int{},
		"root_mnt_id":      1,
		// mnt_id 601 is a non-/dev/shm tmpfs mount (e.g. a workload-defined tmpfs volume
		// mounted at some other path) that was seeded into tmpfs_drop_mnt_ids purely because
		// its fstype=='TMPFS', proving the fix generalizes beyond /dev/shm specifically.
		"tmpfs_drop_mnt_ids": []int{601},
	}
	nonShmTmpfsRegFd := reg(53, "/var/lib/app/scratch-tmpfs/segment.dat", 601, modeFile, false)
	got := runClassifySelftest(t, ctx, []map[string]any{nonShmTmpfsRegFd})
	if got[0].Action != "REBIND_TO_ROOT" {
		t.Fatalf("non-shm tmpfs-aliasing REG fd: got action %q, want REBIND_TO_ROOT", got[0].Action)
	}
	if got[0].EntryType != "REG" {
		t.Fatalf("non-shm tmpfs-aliasing REG fd: got entry_type %q, want REG", got[0].EntryType)
	}
}

// TestClassifyRegFd_TmpfsShmRegRebindViaFstypeMap is the ADR-0311 follow-up (live-path fix)
// regression: the exact live-failure shape. A /dev/shm PostgreSQL.* REG orphan fd whose
// backing mnt_id (943, the value observed live) is NOT in tmpfs_drop_mnt_ids — because that
// mount was never seeded into the narrow is_drop_root ∧ fstype=='TMPFS' drop set — must still
// REBIND_TO_ROOT because the mnt_id->fstype map resolves it to TMPFS. This is the case the
// prior corpus test missed: it always pre-loaded the mnt_id into tmpfs_drop_mnt_ids, so the
// classifier passed on a shape the real image never produced. Keying on the fstype map (not
// the seed set) is the fix.
func TestClassifyRegFd_TmpfsShmRegRebindViaFstypeMap(t *testing.T) {
	ctx := map[string]any{
		"remap_ids":        []int{},
		"inherit_fd_names": []string{},
		"kept_mnt_ids":     []int{1},
		"ext_drop_mnt_ids": []int{},
		"root_mnt_id":      1,
		// Deliberately EMPTY — the live orphan was never seeded here (that was the bug).
		"tmpfs_drop_mnt_ids": []int{},
		// The mount is present in the mountpoints table as TMPFS. JSON object keys are strings;
		// classify_reg_fd tolerates int-or-str lookup (production keys are native ints).
		"mnt_fstypes": map[string]any{"943": "TMPFS"},
	}
	shmRegFd := reg(54, "/dev/shm/PostgreSQL.987654", 943, modeFile, false)
	got := runClassifySelftest(t, ctx, []map[string]any{shmRegFd})
	if got[0].Action != "REBIND_TO_ROOT" {
		t.Fatalf("live /dev/shm PostgreSQL fd (mnt_id 943, tmpfs via fstype map): got action %q, want REBIND_TO_ROOT", got[0].Action)
	}
	if got[0].EntryType != "REG" {
		t.Fatalf("live /dev/shm PostgreSQL fd: got entry_type %q, want REG", got[0].EntryType)
	}
}

// TestClassifyRegFd_NonTmpfsFstypeMapDeclines is the ADR-0311 follow-up guard: an orphan REG
// fd whose backing mnt_id resolves via the mnt_id->fstype map to a NON-tmpfs fstype (here a
// real persistent-volume-style overlayfs/ext4 mount) must STILL hard-stop (DECLINE). Proves
// the fstype-keyed widening did not weaken the Strict P-0193-1 guard for genuinely
// inconsistent, non-memory-backed fds.
func TestClassifyRegFd_NonTmpfsFstypeMapDeclines(t *testing.T) {
	ctx := map[string]any{
		"remap_ids":          []int{},
		"inherit_fd_names":   []string{},
		"kept_mnt_ids":       []int{1},
		"ext_drop_mnt_ids":   []int{},
		"root_mnt_id":        1,
		"tmpfs_drop_mnt_ids": []int{},
		// mnt_id 950 is a real durable mount (NOT tmpfs) — an fd on it that vanished from the
		// kept set is a genuine inconsistency and must hard-stop, not be silently rebound.
		"mnt_fstypes": map[string]any{"950": "OVERLAYFS"},
	}
	pvRegFd := reg(55, "/var/lib/postgresql/data/base/1/1234", 950, modeFile, false)
	got := runClassifySelftest(t, ctx, []map[string]any{pvRegFd})
	if got[0].Action != "DECLINE" {
		t.Fatalf("non-tmpfs (overlayfs) orphan REG fd: got %q, want DECLINE (Strict guard must not weaken)", got[0].Action)
	}
}
