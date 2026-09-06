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

// withDumpedFromDeviceCheckAcceptAllForTest overrides the package-level ADR-0427 D6 seam
// (dumpedFromDeviceCheck) for the lifetime of the calling test, restoring the production default
// (dumpedFromDevice) automatically via t.Cleanup. This is the seam ADR-0427 round 4 requires:
// wiring D6 at the capture call site would otherwise make every pre-existing capture-success
// fixture in this package fail closed, because their fixtures pin an arbitrary RootDev that has no
// relationship to the real device their t.TempDir()-backed hostRunRoot lives on — a fact that is
// irrelevant to what those fixtures are actually testing (reachability/demand-blindness/etc., not
// D6's device comparison). Tests that exist SPECIFICALLY to exercise D6's own comparison logic must
// NOT use this override — they call the real dumpedFromDevice (directly or via the unmodified seam)
// so the comparison itself is what is under test.
func withDumpedFromDeviceCheckAcceptAllForTest(t *testing.T) {
	t.Helper()
	orig := dumpedFromDeviceCheck
	dumpedFromDeviceCheck = func(dir string, recordedRootDev int64) (bool, error) { return true, nil }
	t.Cleanup(func() { dumpedFromDeviceCheck = orig })
}
