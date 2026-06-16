/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// criu_image_consistency_test.go — ADR-0193 S1 (Security, HARD) test.
//
// The CRIUImageInconsistency Kubernetes Event message MUST:
//   - Contain "data" (the leaf/basename of the offending fd path).
//   - NOT contain "/data" (the full path — leaks host/volume layout in a
//     world-readable cluster Event; SEC-EVENT-1 / S1).
//
// The full path stays only in the 0700-bounded agent log line (P-0193-1b / C-STATE).
// The code MUST NOT pass the raw name through fmt.Sprintf("%+v", entry) near the
// Event recorder — %+v on a RegFileEntry would re-leak the full path.

import (
	"strings"
	"testing"
)

// TestCRIUImageInconsistencyEventMsg_S1 is the mandatory S1 (Security, HARD) test from
// ADR-0193: the emitted CRIUImageInconsistency Event message MUST contain "data" and
// MUST NOT contain "/data". The check applies to the formatting helper that constructs
// the message — the same function used by emitCRIUImageInconsistencyEvent and by
// CRIUImageInconsistencyError.Error().
func TestCRIUImageInconsistencyEventMsg_S1(t *testing.T) {
	// Simulate files.img REG fd id=15, name="/data", mnt_id=2951 (the gc21-cold-be fault).
	// The NameLeaf passed to criuImageInconsistencyEventMsg MUST be filepath.Base("/data") = "data".
	fdID := 15
	nameLeaf := "data" // filepath.Base("/data") — must be computed before this call
	backingMntID := 2951

	msg := criuImageInconsistencyEventMsg(fdID, nameLeaf, backingMntID)

	// S1 requirement 1: message contains "data" (leaf basename present — observer can identify
	// which fd caused the inconsistency).
	if !strings.Contains(msg, "data") {
		t.Errorf("S1 FAIL: CRIUImageInconsistency event message does not contain %q (leaf basename must be present)\nmsg=%q", "data", msg)
	}

	// S1 requirement 2: message does NOT contain "/data" (full path must not be present —
	// Kubernetes Events are world-readable; full volume paths leak host/container layout).
	if strings.Contains(msg, "/data") {
		t.Errorf("S1 FAIL: CRIUImageInconsistency event message contains %q (full path must be redacted to leaf only)\nmsg=%q", "/data", msg)
	}
}

// TestCRIUImageInconsistencyError_S1 verifies that CRIUImageInconsistencyError.Error()
// also satisfies the S1 requirement (same formatter, same constraints).
func TestCRIUImageInconsistencyError_S1(t *testing.T) {
	err := &CRIUImageInconsistencyError{
		FdID:         15,
		NameLeaf:     "data", // filepath.Base("/data")
		BackingMntID: 2951,
	}
	msg := err.Error()

	if !strings.Contains(msg, "data") {
		t.Errorf("S1 FAIL: CRIUImageInconsistencyError.Error() does not contain %q\nmsg=%q", "data", msg)
	}
	if strings.Contains(msg, "/data") {
		t.Errorf("S1 FAIL: CRIUImageInconsistencyError.Error() contains full path %q (must be leaf only)\nmsg=%q", "/data", msg)
	}
}
