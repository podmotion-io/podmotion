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

// runClassifySelftest runs the production classifier in --classify-selftest mode over the
// given ctx + entries and returns one action per entry.
func runClassifySelftest(t *testing.T, ctx map[string]any, entries []map[string]any) []string {
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
	var actions []string
	if err := json.Unmarshal(out, &actions); err != nil {
		t.Fatalf("parse actions %q: %v", string(out), err)
	}
	return actions
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

	got := runClassifySelftest(t, ctx, entries)
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
	if got := runClassifySelftest(t, ctx, []map[string]any{orphanDir}); got[0] != "REBIND_TO_ROOT" {
		t.Fatalf("orphan dir: got %q, want REBIND_TO_ROOT", got[0])
	}
	// Simulate the main pass rebinding mnt_id -> rootMntID, then re-run the classifier.
	rebound := reg(20, "/data", rootMntID, modeDir, false)
	if got := runClassifySelftest(t, ctx, []map[string]any{rebound}); got[0] != "KEEP" {
		t.Fatalf("rebound dir: got %q, want KEEP (re-check must not false-positive)", got[0])
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
			if got[0] != tc.want {
				t.Errorf("orphan dir with %s: got %q, want %q", tc.name, got[0], tc.want)
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
	if got := runClassifySelftest(t, ctx, []map[string]any{genericOrphanDir}); got[0] != "REBIND_TO_ROOT" {
		t.Fatalf("generic orphan dir: got %q, want REBIND_TO_ROOT", got[0])
	}
}
