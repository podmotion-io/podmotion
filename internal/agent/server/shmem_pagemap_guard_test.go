/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// shmem_pagemap_guard_test.go — ADR-0246 §P-VERIFY test coverage.
//
// Before this ADR, the string "shmem" appeared in zero Go files in this repo — this failure
// class had no test coverage anywhere. These tests cover:
//   1. Smoke test: the pycriu.images generic reader actually decodes a real mm-<pid>.img
//      produced with pycriu itself and extracts the expected shmid (§P-VERIFY: this decode
//      path must be proven working, not assumed, per Security Review round-1 Finding 1).
//   2. Negative: a referenced-but-missing pagemap-shmem-<shmid>.img fails the guard closed
//      with ErrIncompleteShmemPagemap.
//   3. Positive: a referenced shmid WITH a present, non-empty pagemap-shmem-<shmid>.img passes.
//   4. §P-VERIFY artifact-hygiene: no stray decode artifact (the scan script) survives on a
//      non-tmpfs filesystem after the guard runs, on both the pass and fail paths.
//
// Uses the same synthetic-fixture-built-with-pycriu approach as pycriu_corpus_test.go, and
// reuses its pycriuEnv/resolveRepoPycriuPath helpers (same package) so these tests work both on
// a dev machine (pycriu only in the repo tree) and in an environment with the production
// /usr/lib/python3/dist-packages/pycriu path.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// writeMMImageWithShmid builds a real CRIU mm-<pid>.img (via the vendored pycriu writer, not a
// hand-rolled byte layout) containing one vma entry with the given shmid, plus a second,
// non-shmem vma entry (shmid=0) to make sure the decode correctly ignores non-shmem vmas.
func writeMMImageWithShmid(t *testing.T, pypath string, extraEnv []string, path string, shmid int) {
	t.Helper()
	script := fmt.Sprintf(`
import pycriu
entry = {
    'mm_start_code': 0, 'mm_end_code': 0, 'mm_start_data': 0, 'mm_end_data': 0,
    'mm_start_stack': 0, 'mm_start_brk': 0, 'mm_brk': 0,
    'mm_arg_start': 0, 'mm_arg_end': 0, 'mm_env_start': 0, 'mm_env_end': 0,
    'exe_file_id': 1,
    'vmas': [
        {'start': 0x1000, 'end': 0x2000, 'pgoff': 0, 'shmid': %d, 'prot': 3, 'flags': 0x2801, 'status': 0, 'fd': -1},
        {'start': 0x3000, 'end': 0x4000, 'pgoff': 0, 'shmid': 0, 'prot': 3, 'flags': 0x22, 'status': 0, 'fd': -1},
    ],
}
img = {'magic': 'MM', 'entries': [entry]}
with open(%q, 'wb') as f:
    pycriu.images.dump(img, f)
`, shmid, path)
	cmd := exec.Command("python3", "-c", script)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("writeMMImageWithShmid: %v\n%s", err, out)
	}
}

// withRepoPycriuPath points pycriuPythonPath (the production var) at whatever path pycriuEnv
// resolves as importable in this environment, and restores it afterward. This lets the tests
// exercise the actual production verifyShmemPagemapCompleteness function end-to-end (not a
// reimplementation of it) on a dev machine that lacks the production agent-image path.
func withRepoPycriuPath(t *testing.T) {
	t.Helper()
	pypath, _ := pycriuEnv(t)
	orig := pycriuPythonPath
	pycriuPythonPath = pypath
	t.Cleanup(func() { pycriuPythonPath = orig })
}

// TestVerifyShmemPagemapCompleteness_Smoke is the §P-VERIFY-required smoke test: proves the
// pycriu.images generic reader actually decodes a real mm-<pid>.img and the guard extracts the
// expected shmid — this exact call path had never been exercised end-to-end before this ADR.
//
// RESIDUAL GAP (bug fix, HIGH panel: QA Lead/Arch-A finding — not resolved by this commit):
// this fixture is a synthetic mm-<pid>.img written by pycriu.images.dump() and read back by
// pycriu.images.load() — the SAME library on both ends. That proves internal round-trip
// self-consistency, but it is NOT proof that pycriu correctly parses a real mm-*.img produced
// by an actual CRIU 4.2 dump (CRIU's own image writer, not pycriu's). A real captured fixture
// from the original gate failure (shmid 22685 on gate3 or shmid 11423 on gate2, per
// docs/sprints/SPRINT40C-SHMEM-PREMISE-EVIDENCE.md) is NOT currently available in-repo, and one
// was deliberately NOT fabricated here rather than falsely claiming this gap closed. This is
// flagged as a residual gap to close with a real fixture at live-gate time — see ADR-0246
// §P-VERIFY for the corresponding disclosure.
func TestVerifyShmemPagemapCompleteness_Smoke(t *testing.T) {
	withRepoPycriuPath(t)
	dir := t.TempDir()
	writeMMImageWithShmid(t, pycriuPythonPath, append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"), filepath.Join(dir, "mm-99.img"), 12345)

	err := verifyShmemPagemapCompleteness(dir)
	if err == nil {
		t.Fatal("expected ErrIncompleteShmemPagemap (no pagemap-shmem-12345.img present), got nil")
	}
	if !errors.Is(err, ErrIncompleteShmemPagemap) {
		t.Fatalf("expected errors.Is(err, ErrIncompleteShmemPagemap); got %v", err)
	}
	if !strings.Contains(err.Error(), "12345") {
		t.Errorf("expected shmid 12345 named in error, got: %v", err)
	}
}

// TestVerifyShmemPagemapCompleteness_MissingPagemap_FailsClosed is the required negative test:
// a shmid referenced in mm-*.img with no matching pagemap-shmem-<shmid>.img must fail the guard
// closed with the correctly distinguishable error/reason.
func TestVerifyShmemPagemapCompleteness_MissingPagemap_FailsClosed(t *testing.T) {
	withRepoPycriuPath(t)
	dir := t.TempDir()
	writeMMImageWithShmid(t, pycriuPythonPath, append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"), filepath.Join(dir, "mm-42.img"), 22685)
	// Deliberately do NOT write pagemap-shmem-22685.img (this is the ADR's exact reproduced
	// defect signature — shmid 22685 was one of the two real shmids from the gate diagnosis).

	err := verifyShmemPagemapCompleteness(dir)
	if err == nil {
		t.Fatal("expected guard to fail closed on missing pagemap-shmem-22685.img, got nil")
	}
	if !errors.Is(err, ErrIncompleteShmemPagemap) {
		t.Fatalf("expected errors.Is(err, ErrIncompleteShmemPagemap); got %v", err)
	}
}

// TestVerifyShmemPagemapCompleteness_PagemapPresent_Passes is the required positive test: a
// referenced shmid with a present, non-empty pagemap-shmem-<shmid>.img must pass the guard.
func TestVerifyShmemPagemapCompleteness_PagemapPresent_Passes(t *testing.T) {
	withRepoPycriuPath(t)
	dir := t.TempDir()
	writeMMImageWithShmid(t, pycriuPythonPath, append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"), filepath.Join(dir, "mm-42.img"), 11423)
	pagemapPath := filepath.Join(dir, "pagemap-shmem-11423.img")
	if err := os.WriteFile(pagemapPath, []byte("not-empty-fixture-content"), 0o600); err != nil {
		t.Fatalf("write fixture pagemap: %v", err)
	}

	if err := verifyShmemPagemapCompleteness(dir); err != nil {
		t.Fatalf("expected guard to pass with pagemap-shmem-11423.img present and non-empty, got: %v", err)
	}
}

// TestVerifyShmemPagemapCompleteness_EmptyPagemap_FailsClosed: a zero-byte pagemap file is
// treated the same as a missing one (D1 step 2 requires "non-zero size").
func TestVerifyShmemPagemapCompleteness_EmptyPagemap_FailsClosed(t *testing.T) {
	withRepoPycriuPath(t)
	dir := t.TempDir()
	writeMMImageWithShmid(t, pycriuPythonPath, append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"), filepath.Join(dir, "mm-42.img"), 555)
	if err := os.WriteFile(filepath.Join(dir, "pagemap-shmem-555.img"), nil, 0o600); err != nil {
		t.Fatalf("write empty fixture pagemap: %v", err)
	}

	err := verifyShmemPagemapCompleteness(dir)
	if !errors.Is(err, ErrIncompleteShmemPagemap) {
		t.Fatalf("expected zero-byte pagemap to fail closed with ErrIncompleteShmemPagemap; got %v", err)
	}
}

// TestVerifyShmemPagemapCompleteness_NoShmemVmas_Passes: mm-*.img with no shmem-backed vmas at
// all (shmid always 0) must pass — absence of any anon-shmem reference is not a defect.
func TestVerifyShmemPagemapCompleteness_NoShmemVmas_Passes(t *testing.T) {
	withRepoPycriuPath(t)
	dir := t.TempDir()
	writeMMImageWithShmid(t, pycriuPythonPath, append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"), filepath.Join(dir, "mm-1.img"), 0)

	if err := verifyShmemPagemapCompleteness(dir); err != nil {
		t.Fatalf("expected guard to pass with no shmem-backed vmas, got: %v", err)
	}
}

// TestVerifyShmemPagemapCompleteness_NoStrayArtifact is the required §P-VERIFY artifact-hygiene
// test: the guard's own transient decode artifact (the scan script it writes into imagesDir)
// must not survive after the guard returns, on either the pass or fail path, and — the ADR's
// explicit requirement — must never be written anywhere outside the already-governed tmpfs
// imagesDir in the first place (asserted here by checking a separate, non-tmpfs scratch
// directory picks up nothing at all as a result of calling the guard).
func TestVerifyShmemPagemapCompleteness_NoStrayArtifact(t *testing.T) {
	withRepoPycriuPath(t)

	assertNoStrayFiles := func(t *testing.T, dir string, before map[string]bool) {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("readdir %s: %v", dir, err)
		}
		for _, e := range entries {
			if !before[e.Name()] {
				t.Errorf("stray artifact left behind after guard returned: %s", filepath.Join(dir, e.Name()))
			}
		}
	}

	snapshot := func(t *testing.T, dir string) map[string]bool {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("readdir %s: %v", dir, err)
		}
		m := make(map[string]bool, len(entries))
		for _, e := range entries {
			m[e.Name()] = true
		}
		return m
	}

	t.Run("fail_path", func(t *testing.T) {
		dir := t.TempDir()
		writeMMImageWithShmid(t, pycriuPythonPath, append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"), filepath.Join(dir, "mm-42.img"), 999)
		before := snapshot(t, dir)
		_ = verifyShmemPagemapCompleteness(dir) // expected to fail closed; artifact hygiene must hold regardless
		assertNoStrayFiles(t, dir, before)
	})

	t.Run("pass_path", func(t *testing.T) {
		dir := t.TempDir()
		writeMMImageWithShmid(t, pycriuPythonPath, append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"), filepath.Join(dir, "mm-42.img"), 0)
		before := snapshot(t, dir)
		if err := verifyShmemPagemapCompleteness(dir); err != nil {
			t.Fatalf("unexpected guard failure: %v", err)
		}
		assertNoStrayFiles(t, dir, before)
	})

	// D3/§P-VERIFY: the guard must never place any artifact outside the imagesDir it was given
	// — confirm a sibling, unrelated non-tmpfs-style scratch directory is untouched by a guard
	// call against a different dir entirely.
	t.Run("no_artifact_outside_imagesDir", func(t *testing.T) {
		imagesDir := t.TempDir()
		sibling := t.TempDir()
		writeMMImageWithShmid(t, pycriuPythonPath, append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"), filepath.Join(imagesDir, "mm-42.img"), 0)
		before := snapshot(t, sibling)
		_ = verifyShmemPagemapCompleteness(imagesDir)
		assertNoStrayFiles(t, sibling, before)
	})
}

// TestNewShmemPagemapMissingStatus_TypedContract replaces the retired
// TestErrIncompleteShmemPagemap_ControllerSubstringMatch (ADR-0246 typed-status redesign).
// The old test enforced that the controller's error-string substring
// match stayed in sync with ErrIncompleteShmemPagemap's wording — that whole mechanism is gone
// now, so there is no longer a string for that test to guard. What this test guards instead: the
// gRPC status.Status produced by newShmemPagemapMissingStatus carries the machine-readable
// contract the controller actually reads — codes.FailedPrecondition plus an
// errdetails.ErrorInfo{Reason: ShmemPagemapMissingReason, Domain: ShmemPagemapMissingReasonDomain}
// details entry with the missing-shmid/imagesDir metadata populated.
func TestNewShmemPagemapMissingStatus_TypedContract(t *testing.T) {
	detail := &ShmemPagemapMissingDetail{Missing: []int64{111, 222}, ImagesDir: "/run/podmotion/checkpoints/test/final"}
	err := newShmemPagemapMissingStatus(detail)

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("newShmemPagemapMissingStatus did not return a gRPC status error: %v", err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("expected codes.FailedPrecondition, got %v", st.Code())
	}

	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok {
			info = i
			break
		}
	}
	if info == nil {
		t.Fatalf("expected an errdetails.ErrorInfo status detail, got details=%v", st.Details())
	}
	if info.GetReason() != ShmemPagemapMissingReason {
		t.Fatalf("expected ErrorInfo.Reason=%q, got %q", ShmemPagemapMissingReason, info.GetReason())
	}
	if info.GetDomain() != ShmemPagemapMissingReasonDomain {
		t.Fatalf("expected ErrorInfo.Domain=%q, got %q", ShmemPagemapMissingReasonDomain, info.GetDomain())
	}
	if info.GetMetadata()["imagesDir"] != detail.ImagesDir {
		t.Fatalf("expected ErrorInfo.Metadata[imagesDir]=%q, got %q", detail.ImagesDir, info.GetMetadata()["imagesDir"])
	}

	// The typed status must still satisfy errors.Is(err, ErrIncompleteShmemPagemap) for any
	// in-process (non-wire) caller, since ShmemPagemapMissingDetail.Unwrap preserves it — but
	// this is no longer how the controller classifies the failure over the wire.
	if !errors.Is(detail, ErrIncompleteShmemPagemap) {
		t.Fatalf("expected errors.Is(detail, ErrIncompleteShmemPagemap) to hold via Unwrap")
	}
}

// TestNewShmemPagemapMissingStatus_NonDetailError confirms the fallback path: when the wrapped
// error is not a *ShmemPagemapMissingDetail (e.g. called defensively on some other error), the
// status is still typed codes.FailedPrecondition with the Reason set, just without metadata.
func TestNewShmemPagemapMissingStatus_NonDetailError(t *testing.T) {
	err := newShmemPagemapMissingStatus(errors.New("some other failure"))
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition {
		t.Fatalf("expected codes.FailedPrecondition, got %v", err)
	}
	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok {
			info = i
		}
	}
	if info == nil || info.GetReason() != ShmemPagemapMissingReason {
		t.Fatalf("expected ErrorInfo.Reason=%q even without a ShmemPagemapMissingDetail", ShmemPagemapMissingReason)
	}
}
