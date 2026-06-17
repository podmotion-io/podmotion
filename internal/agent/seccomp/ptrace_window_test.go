/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package seccomp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withTempWindowDir redirects ptraceWindowDir at a t.TempDir for the duration of a test and
// restores it afterwards, so tests never touch the privileged /run path.
func withTempWindowDir(t *testing.T) {
	t.Helper()
	orig := ptraceWindowDir
	ptraceWindowDir = filepath.Join(t.TempDir(), "ptrace-window")
	t.Cleanup(func() { ptraceWindowDir = orig })
}

func TestPtraceWindowOpenCloseLifecycle(t *testing.T) {
	withTempWindowDir(t)
	const cid = "container-abc123"

	if IsPtraceWindowOpen(cid) {
		t.Fatal("window should be closed before any open")
	}

	if err := PtraceWindowOpen(cid); err != nil {
		t.Fatalf("PtraceWindowOpen: %v", err)
	}
	if !IsPtraceWindowOpen(cid) {
		t.Fatal("window should report open after PtraceWindowOpen")
	}
	// Marker file must exist on disk and be mode 0600.
	info, err := os.Stat(ptraceWindowPath(cid))
	if err != nil {
		t.Fatalf("stat marker: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("marker perm = %o, want 0600", info.Mode().Perm())
	}

	if err := PtraceWindowClose(cid); err != nil {
		t.Fatalf("PtraceWindowClose: %v", err)
	}
	if IsPtraceWindowOpen(cid) {
		t.Fatal("window should report closed after PtraceWindowClose")
	}
}

func TestPtraceWindowCloseIdempotent(t *testing.T) {
	withTempWindowDir(t)
	const cid = "never-opened"

	// Close on a never-opened window is a no-op success.
	if err := PtraceWindowClose(cid); err != nil {
		t.Fatalf("first close (never opened) should be no-op success, got %v", err)
	}

	// Open then double-close: both succeed, window stays closed.
	if err := PtraceWindowOpen(cid); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := PtraceWindowClose(cid); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := PtraceWindowClose(cid); err != nil {
		t.Fatalf("second close (idempotent) should be no-op success, got %v", err)
	}
	if IsPtraceWindowOpen(cid) {
		t.Fatal("window must be closed after double close")
	}
}

func TestPtraceWindowOpenIdempotentRefreshesMtime(t *testing.T) {
	withTempWindowDir(t)
	const cid = "refresh-me"

	if err := PtraceWindowOpen(cid); err != nil {
		t.Fatalf("first open: %v", err)
	}
	// Backdate the marker to simulate a long-running window.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(ptraceWindowPath(cid), old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Re-open must refresh the mtime (restart the staleness clock) without erroring.
	if err := PtraceWindowOpen(cid); err != nil {
		t.Fatalf("re-open: %v", err)
	}
	info, err := os.Stat(ptraceWindowPath(cid))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if time.Since(info.ModTime()) > time.Minute {
		t.Fatalf("re-open did not refresh mtime; age = %v", time.Since(info.ModTime()))
	}
}

func TestSweepStaleWindowsClosesStaleOnly(t *testing.T) {
	withTempWindowDir(t)
	const stale = "stale-window"
	const fresh = "fresh-window"

	if err := PtraceWindowOpen(stale); err != nil {
		t.Fatalf("open stale: %v", err)
	}
	if err := PtraceWindowOpen(fresh); err != nil {
		t.Fatalf("open fresh: %v", err)
	}

	// Backdate only the stale window well beyond maxAge.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(ptraceWindowPath(stale), old, old); err != nil {
		t.Fatalf("chtimes stale: %v", err)
	}

	swept, err := SweepStaleWindows(10 * time.Second)
	if err != nil {
		t.Fatalf("SweepStaleWindows: %v", err)
	}
	if swept != 1 {
		t.Fatalf("swept = %d, want 1 (only the stale window)", swept)
	}
	if IsPtraceWindowOpen(stale) {
		t.Fatal("stale window should have been closed by the sweeper")
	}
	if !IsPtraceWindowOpen(fresh) {
		t.Fatal("fresh window must NOT be closed by the sweeper")
	}
}

func TestSweepStaleWindowsAbsentDirIsNoop(t *testing.T) {
	withTempWindowDir(t)
	// Directory never created — sweep must be a safe no-op, not an error.
	swept, err := SweepStaleWindows(time.Second)
	if err != nil {
		t.Fatalf("sweep on absent dir should be no-op success, got %v", err)
	}
	if swept != 0 {
		t.Fatalf("swept = %d, want 0 on absent dir", swept)
	}
}

func TestIsPtraceWindowOpenFailClosed(t *testing.T) {
	withTempWindowDir(t)
	// No marker, dir absent → not open (fail-closed: ptrace treated out-of-window).
	if IsPtraceWindowOpen("ghost") {
		t.Fatal("IsPtraceWindowOpen must return false when no marker exists")
	}
}

func TestSanitizeWindowKeyNoEscape(t *testing.T) {
	withTempWindowDir(t)
	// A path-traversal-style ID must collapse to a single safe segment inside ptraceWindowDir.
	const evil = "../../etc/passwd"
	if err := PtraceWindowOpen(evil); err != nil {
		t.Fatalf("open with traversal id: %v", err)
	}
	got := ptraceWindowPath(evil)
	if filepath.Dir(got) != ptraceWindowDir {
		t.Fatalf("marker escaped window dir: %s (dir=%s)", got, ptraceWindowDir)
	}
	if !IsPtraceWindowOpen(evil) {
		t.Fatal("window should be open for the sanitized key")
	}
	if err := PtraceWindowClose(evil); err != nil {
		t.Fatalf("close traversal id: %v", err)
	}
}
