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

// VMA status bits, mirrored from pycriu/images/pb2dict.py's mmap_status_map (CRIU's mmap.status
// flags) — same constants the guard's shmemScanScript classifies vmas by.
const (
	vmaFilePrivate = 1 << 6
	vmaAnonShared  = 1 << 8
	vmaAreaMemfd   = 1 << 14
)

// writeMMImageWithShmid builds a real CRIU mm-<pid>.img (via the vendored pycriu writer, not a
// hand-rolled byte layout) containing one vma entry with the given shmid and status, plus a
// second, non-shmem vma entry (shmid=0) to make sure the decode correctly ignores non-shmem
// vmas. status=0 defaults to VMA_ANON_SHARED-equivalent legacy test behavior via the caller.
func writeMMImageWithShmid(t *testing.T, pypath string, extraEnv []string, path string, shmid int) {
	t.Helper()
	writeMMImageWithShmidStatus(t, pypath, extraEnv, path, shmid, vmaAnonShared)
}

// writeMMImageWithShmidStatus is writeMMImageWithShmid but with an explicit vma status bitmask,
// so tests can construct VMA_FILE_PRIVATE / VMA_AREA_MEMFD fixtures alongside VMA_ANON_SHARED.
func writeMMImageWithShmidStatus(t *testing.T, pypath string, extraEnv []string, path string, shmid int, status int) {
	t.Helper()
	script := fmt.Sprintf(`
import pycriu
entry = {
    'mm_start_code': 0, 'mm_end_code': 0, 'mm_start_data': 0, 'mm_end_data': 0,
    'mm_start_stack': 0, 'mm_start_brk': 0, 'mm_brk': 0,
    'mm_arg_start': 0, 'mm_arg_end': 0, 'mm_env_start': 0, 'mm_env_end': 0,
    'exe_file_id': 1,
    'vmas': [
        {'start': 0x1000, 'end': 0x2000, 'pgoff': 0, 'shmid': %d, 'prot': 3, 'flags': 0x2801, 'status': %d, 'fd': -1},
        {'start': 0x3000, 'end': 0x4000, 'pgoff': 0, 'shmid': 0, 'prot': 3, 'flags': 0x22, 'status': 0, 'fd': -1},
    ],
}
img = {'magic': 'MM', 'entries': [entry]}
with open(%q, 'wb') as f:
    pycriu.images.dump(img, f)
`, shmid, status, path)
	cmd := exec.Command("python3", "-c", script)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("writeMMImageWithShmidStatus: %v\n%s", err, out)
	}
}

// writeMemfdImage builds a real CRIU memfd.img (via the vendored pycriu writer) containing one
// memfd_inode_entry mapping the given local inodeID to the given realShmid (the actual
// kernel-assigned identifier that pagemap-shmem-<realShmid>.img is keyed by) — mirroring the
// memfd.img structure decoded in docs/sprints/SPRINT41-NR-BLOCK-2-MECHANISM-INVESTIGATION.md
// (e.g. inode_id=1 -> shmid=13353). Pair with writeFilesImageMemfd to complete the two-hop join
// a VMA_AREA_MEMFD vma's shmid field requires on a real CRIU dump (vma.shmid -> files.img id ->
// this inodeID -> this realShmid).
func writeMemfdImage(t *testing.T, pypath string, extraEnv []string, path string, inodeID, realShmid int) {
	t.Helper()
	script := fmt.Sprintf(`
import pycriu
entry = {
    'name': 'CRIUMFD', 'uid': 0, 'gid': 0, 'size': 4096,
    'shmid': %d, 'seals': 0, 'inode_id': %d,
}
img = {'magic': 'MEMFD_INODE', 'entries': [entry]}
with open(%q, 'wb') as f:
    pycriu.images.dump(img, f)
`, realShmid, inodeID, path)
	cmd := exec.Command("python3", "-c", script)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("writeMemfdImage: %v\n%s", err, out)
	}
}

// writeFilesImageMemfd builds a real CRIU files.img (via the vendored pycriu writer) containing
// one FILES entry of type MEMFD whose id equals a VMA_AREA_MEMFD vma's own shmid field (fileID)
// and whose nested memfd.inode_id equals the corresponding memfd.img memfd_inode_entry's
// inode_id — reproducing the exact real-CRIU-dump indirection discovered during live
// verification against the go-tcp-echo workload (a memfd vma's shmid is a files.img file-object
// id, not memfd.img's inode_id directly).
func writeFilesImageMemfd(t *testing.T, pypath string, extraEnv []string, path string, fileID, inodeID int) {
	t.Helper()
	script := fmt.Sprintf(`
import pycriu
entry = {
    'type': 'MEMFD', 'id': %d,
    'memfd': {'id': %d, 'flags': 0, 'pos': 0,
              'fown': {'uid': 0, 'euid': 0, 'signum': 0, 'pid_type': 0, 'pid': 0},
              'inode_id': %d},
}
img = {'magic': 'FILES', 'entries': [entry]}
with open(%q, 'wb') as f:
    pycriu.images.dump(img, f)
`, fileID, fileID, inodeID, path)
	cmd := exec.Command("python3", "-c", script)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("writeFilesImageMemfd: %v\n%s", err, out)
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

// TestVerifyShmemPagemapCompleteness_AnonSharedMissing_StillCaught is SPRINT41 NR-BLOCK-2 bugfix
// regression case (a): a genuine VMA_ANON_SHARED vma referencing a shmid with no matching
// pagemap-shmem-<shmid>.img must STILL be caught — this is the guard's original, load-bearing
// protection against the real historical ADR-0246 defect (shmid 22685/11423) and must not be
// weakened by the false-positive fix.
func TestVerifyShmemPagemapCompleteness_AnonSharedMissing_StillCaught(t *testing.T) {
	withRepoPycriuPath(t)
	dir := t.TempDir()
	writeMMImageWithShmidStatus(t, pycriuPythonPath, append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"), filepath.Join(dir, "mm-42.img"), 22685, vmaAnonShared)
	// Deliberately do NOT write pagemap-shmem-22685.img.

	err := verifyShmemPagemapCompleteness(dir)
	if err == nil {
		t.Fatal("expected VMA_ANON_SHARED vma with missing pagemap-shmem-22685.img to still be caught, got nil")
	}
	if !errors.Is(err, ErrIncompleteShmemPagemap) {
		t.Fatalf("expected errors.Is(err, ErrIncompleteShmemPagemap); got %v", err)
	}
	if !strings.Contains(err.Error(), "22685") {
		t.Errorf("expected shmid 22685 named in error, got: %v", err)
	}
}

// TestVerifyShmemPagemapCompleteness_FilePrivate_NotFlagged is SPRINT41 NR-BLOCK-2 bugfix case
// (b) — the false-positive fix itself: a VMA_FILE_PRIVATE vma (e.g. an ELF text/data segment)
// carries a generic, overloaded shmid field that is not a pagemap key at all. It must never be
// flagged, even though no pagemap-shmem-<shmid>.img exists for it (none is expected to).
func TestVerifyShmemPagemapCompleteness_FilePrivate_NotFlagged(t *testing.T) {
	withRepoPycriuPath(t)
	dir := t.TempDir()
	// shmid=1 mirrors the real false-positive signature from
	// docs/sprints/SPRINT41-NR-BLOCK-2-MECHANISM-INVESTIGATION.md (the /tcpecho binary's own
	// text segment decoded as {"shmid": 1, "status": "VMA_AREA_REGULAR | VMA_FILE_PRIVATE"}).
	writeMMImageWithShmidStatus(t, pycriuPythonPath, append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python"), filepath.Join(dir, "mm-1.img"), 1, vmaFilePrivate)
	// No pagemap-shmem-1.img written — and none should ever be required for VMA_FILE_PRIVATE.

	if err := verifyShmemPagemapCompleteness(dir); err != nil {
		t.Fatalf("expected VMA_FILE_PRIVATE vma to never be flagged (false-positive fix), got: %v", err)
	}
}

// TestVerifyShmemPagemapCompleteness_MemfdPresentUnderRealKey_Passes is SPRINT41 NR-BLOCK-2
// bugfix case (c): a VMA_AREA_MEMFD vma (e.g. CRIU's own CRIUMFD parasite-injection region)
// whose real pagemap — correctly keyed by memfd.img's memfd_inode_entry.shmid, NOT the vma's
// own small sequential shmid/inode-index field — IS present must pass cleanly.
func TestVerifyShmemPagemapCompleteness_MemfdPresentUnderRealKey_Passes(t *testing.T) {
	withRepoPycriuPath(t)
	dir := t.TempDir()
	env := append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python")
	// vma.shmid=2 is a files.img file-object id; files.img says that id -> inode_id=2;
	// memfd.img says inode_id=2 -> real shmid=13350 (mirroring the investigation doc's exact
	// decoded values and the two-hop join discovered during live verification).
	writeMMImageWithShmidStatus(t, pycriuPythonPath, env, filepath.Join(dir, "mm-1.img"), 2, vmaAreaMemfd)
	writeFilesImageMemfd(t, pycriuPythonPath, env, filepath.Join(dir, "files.img"), 2, 2)
	writeMemfdImage(t, pycriuPythonPath, env, filepath.Join(dir, "memfd.img"), 2, 13350)
	if err := os.WriteFile(filepath.Join(dir, "pagemap-shmem-13350.img"), []byte("real-memfd-pagemap-content"), 0o600); err != nil {
		t.Fatalf("write fixture pagemap: %v", err)
	}
	// No pagemap-shmem-2.img exists (and correctly should not need to) — proves the guard
	// checks the memfd.img-resolved real key, not the vma's own overloaded shmid field.

	if err := verifyShmemPagemapCompleteness(dir); err != nil {
		t.Fatalf("expected VMA_AREA_MEMFD vma with pagemap present under its real memfd.img key to pass, got: %v", err)
	}
}

// TestVerifyShmemPagemapCompleteness_MemfdRealKeyMissing_StillCaught is SPRINT41 NR-BLOCK-2
// bugfix case (d): a VMA_AREA_MEMFD vma whose real, correctly-resolved pagemap (under
// memfd.img's key) is genuinely absent must STILL be caught — proving the fix resolves the
// correct filename to check rather than whitelisting VMA_AREA_MEMFD wholesale.
func TestVerifyShmemPagemapCompleteness_MemfdRealKeyMissing_StillCaught(t *testing.T) {
	withRepoPycriuPath(t)
	dir := t.TempDir()
	env := append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python")
	writeMMImageWithShmidStatus(t, pycriuPythonPath, env, filepath.Join(dir, "mm-1.img"), 3, vmaAreaMemfd)
	writeFilesImageMemfd(t, pycriuPythonPath, env, filepath.Join(dir, "files.img"), 3, 1)
	writeMemfdImage(t, pycriuPythonPath, env, filepath.Join(dir, "memfd.img"), 1, 13353)
	// Deliberately do NOT write pagemap-shmem-13353.img (nor pagemap-shmem-3.img — neither
	// should make this pass; only the real, memfd.img-resolved key matters).

	err := verifyShmemPagemapCompleteness(dir)
	if err == nil {
		t.Fatal("expected VMA_AREA_MEMFD vma with genuinely missing real-keyed pagemap to be caught, got nil")
	}
	if !errors.Is(err, ErrIncompleteShmemPagemap) {
		t.Fatalf("expected errors.Is(err, ErrIncompleteShmemPagemap); got %v", err)
	}
	if !strings.Contains(err.Error(), "13353") {
		t.Errorf("expected real resolved shmid 13353 named in error, got: %v", err)
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
