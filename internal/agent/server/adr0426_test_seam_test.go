/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0426_test_seam_test.go — the injectable root-path test seam for ADR-0426's capture leg.
//
// Root cause of the gap this closes: mountHostSourceDir (via runHostDir) hardcoded the "/host-run"
// production root with no way for a test to redirect it. The one existing test that exercised a
// successful capture (TestCaptureContentAbsentMounts_CapturesReachableRawPathSource,
// adr0415_capture_gate_test.go) worked around that by calling os.MkdirAll("/host-run/...") directly
// against the REAL machine filesystem and t.Skipf()-ing when that failed — which it does on any
// non-root machine or CI runner without a live host /run mount, meaning the test silently never
// actually ran in most environments. withHostRunRootForTest is the seam: it points the package-level
// hostRunRoot variable at a t.TempDir() for the duration of one test, so every capture test in this
// package can exercise the real reachability + tar-write path against a throwaway directory instead
// of the host filesystem.

import "testing"

// withHostRunRootForTest overrides the package-level hostRunRoot for the lifetime of the calling
// test and restores the production default ("/host-run") automatically via t.Cleanup. Every test
// that needs mountHostSourceDir/captureContentAbsentMounts to actually resolve and read a source
// directory (rather than merely computing a path string) must call this first.
func withHostRunRootForTest(t *testing.T, root string) {
	t.Helper()
	orig := hostRunRoot
	hostRunRoot = root
	t.Cleanup(func() { hostRunRoot = orig })
}
