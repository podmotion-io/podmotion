/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// secure_wipe_test.go — contract regression for B-04 / M-8: zeroizeDir must PROPAGATE a failed
// overwrite instead of swallowing it.
//
// Pre-change bug (server.go zeroizeDir): the per-file WriteAt error was discarded (`_, _ =`) and
// the filepath.Walk error was discarded (`_ =`); zeroizeDir returned only os.RemoveAll's result.
// So a checkpoint image (verbatim process memory on tmpfs) that could NOT be overwritten still
// yielded a nil error while os.RemoveAll unlinked it — a "wiped" claim with recoverable live
// memory left behind (invariant 4 / Standing Rule 7 break). The abort/exit-path callers (the ctr
// fall-through before raw CRIU writes to the same dir; the fail-closed sentinel path) trusted that
// nil and proceeded as if the scrub had happened.
//
// TestZeroizeDir_PropagatesWipeFailure is the "test that would have caught the bug": it constructs
// a dir holding a non-empty file that cannot be opened for writing (mode 0000, non-root), so the
// overwrite cannot happen. Against the pre-change logic zeroizeDir returned nil (bug); against the
// fixed logic it returns non-nil. It is falsifiable: revert the fix and it fails.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestZeroizeDir_PropagatesWipeFailure asserts that when a regular file inside dir cannot be
// overwritten (open-for-write denied because the file is mode 0000 and the test runs unprivileged),
// zeroizeDir returns a non-nil error rather than silently reporting success.
//
// This is the falsifiable M-8 regression: the pre-change zeroizeDir discarded the open/WriteAt
// error and returned os.RemoveAll's (nil) result, so an un-wiped file yielded a nil error.
func TestZeroizeDir_PropagatesWipeFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		// As root, mode 0000 does not prevent O_WRONLY open, so the failure this test relies on
		// cannot be induced. The wipe path is otherwise identical; skip rather than assert-green.
		t.Skip("running as root: cannot induce an open-for-write failure via file mode")
	}

	dir := t.TempDir()
	// A non-empty file standing in for a checkpoint image (recoverable live memory bytes).
	unwipeable := filepath.Join(dir, "pages-1.img")
	if err := os.WriteFile(unwipeable, []byte("live-memory-page-contents"), 0o000); err != nil {
		t.Fatalf("seeding unwipeable file: %v", err)
	}
	// Restore a writable mode at the end so t.TempDir cleanup can remove it if the dir survives.
	defer func() { _ = os.Chmod(unwipeable, 0o600) }()

	// Sanity: confirm the substrate actually denies O_WRONLY on this file, so the test is
	// exercising a real wipe failure and not a vacuous pass.
	if f, err := os.OpenFile(unwipeable, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Skip("substrate allows O_WRONLY on mode-0000 file; cannot induce wipe failure here")
	}

	err := zeroizeDir(dir)
	if err == nil {
		t.Fatal("zeroizeDir returned nil for a directory whose file could NOT be overwritten — " +
			"a failed wipe MUST be propagated, not swallowed (M-8/B-04). A caller would trust a " +
			"non-existent scrub and proceed as if live memory had been zeroized.")
	}
	if !strings.Contains(err.Error(), "secure-wipe") {
		t.Errorf("expected a secure-wipe error, got: %v", err)
	}
}

// TestZeroizeDir_SuccessZeroesAndRemoves asserts the happy path: a directory of ordinary,
// writable files (including one larger than the 1 MiB reusable-buffer chunk, to exercise the
// looped multi-chunk overwrite) is scrubbed and removed, and zeroizeDir returns nil.
func TestZeroizeDir_SuccessZeroesAndRemoves(t *testing.T) {
	dir := t.TempDir()

	small := filepath.Join(dir, "inventory.img")
	if err := os.WriteFile(small, []byte("small-image"), 0o600); err != nil {
		t.Fatalf("seed small: %v", err)
	}
	// Larger than secureWipeChunkBytes (1 MiB) so the write loop runs more than one iteration.
	big := filepath.Join(dir, "pages-1.img")
	payload := make([]byte, secureWipeChunkBytes+4096)
	for i := range payload {
		payload[i] = 0xAB // non-zero so a no-op "wipe" would be observable if the dir survived
	}
	if err := os.WriteFile(big, payload, 0o600); err != nil {
		t.Fatalf("seed big: %v", err)
	}
	// A nested subdirectory with its own image, to confirm the Walk recurses.
	sub := filepath.Join(dir, "round-0")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "pages-1.img"), []byte("nested"), 0o600); err != nil {
		t.Fatalf("seed nested: %v", err)
	}

	if err := zeroizeDir(dir); err != nil {
		t.Fatalf("zeroizeDir on a fully writable dir returned error: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expected dir removed after zeroizeDir, stat err = %v", err)
	}
}

// TestZeroizeDir_AbsentDirIsSuccess asserts an already-absent directory is treated as success
// (idempotent) — callers guard on !os.IsNotExist, and the primitive must not manufacture an
// error for a dir that was never created or was already released.
func TestZeroizeDir_AbsentDirIsSuccess(t *testing.T) {
	parent := t.TempDir()
	missing := filepath.Join(parent, "never-created")
	if err := zeroizeDir(missing); err != nil {
		t.Fatalf("zeroizeDir on an absent dir returned error: %v (expected nil/idempotent)", err)
	}
}
