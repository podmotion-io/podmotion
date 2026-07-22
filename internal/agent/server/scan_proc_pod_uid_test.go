/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// scan_proc_pod_uid_test.go — fail-closed phase-gate remediation (item 4) unit coverage.
//
// scanProcForPodUID must distinguish a genuine negative (clean scan, no cgroup match) from an
// infra/permission failure (os.ReadDir("/proc") itself erroring) — the two used to collapse
// into a single bool, and PrepareSource's caller-side fix (Compatible = found) now depends on
// telling them apart.

import "testing"

// TestScanProcForPodUID_GenuineNegative confirms a clean scan over the real /proc that simply
// never matches the (nonsense) UID returns (false, nil) — a confirmed negative, not an error.
func TestScanProcForPodUID_GenuineNegative(t *testing.T) {
	found, err := scanProcForPodUID("00000000-0000-0000-0000-000000000000-does-not-exist")
	if err != nil {
		t.Fatalf("expected a clean negative scan (no error), got err=%v", err)
	}
	if found {
		t.Fatalf("expected found=false for a UID that matches no real process, got true")
	}
}
