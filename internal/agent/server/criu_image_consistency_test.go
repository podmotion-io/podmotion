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

	msg := criuImageInconsistencyEventMsg(fdID, nameLeaf, backingMntID, "")

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

// TestCRIUImageInconsistencyEventMsg_GroundedFstype is the ADR-0193 P-0193-1 grounding test.
// The live postgres failure (2026-07-10) hard-stopped on an orphan REG fd whose backing mount
// was a real emptyDir data volume (fd base/1/1 under /var/lib/postgresql/data), but the message
// reported ONLY the bare backing_mnt_id — giving no way to tell in one run whether the orphan was
// a tmpfs/shm segment that should have rebound (a classifier bug) or a genuine persistent data
// mount that correctly DECLINEd (a mount-preservation gap). This test asserts the decoded
// backing_fstype IS surfaced in the message when known, so the orphan cause is diagnosable.
func TestCRIUImageInconsistencyEventMsg_GroundedFstype(t *testing.T) {
	// Postgres live shape: emptyDir data mount (disk-backed → fstype EXT4/other, NOT tmpfs).
	msg := criuImageInconsistencyEventMsg(47, "000000010000000000000001", 778, "EXT4")

	if !strings.Contains(msg, "backing_fstype=EXT4") {
		t.Errorf("grounding FAIL: message must surface the decoded backing_fstype so a persistent-data orphan is distinguishable from a tmpfs/shm one\nmsg=%q", msg)
	}
	// Empty fstype (decode unavailable / older marker) must degrade gracefully — no bare
	// "backing_fstype=" fragment, and the base P-0193-1 message still emitted.
	msgNoFst := criuImageInconsistencyEventMsg(47, "000000010000000000000001", 778, "")
	if strings.Contains(msgNoFst, "backing_fstype=") {
		t.Errorf("grounding FAIL: empty fstype must be omitted, not rendered as an empty field\nmsg=%q", msgNoFst)
	}
	if !strings.Contains(msgNoFst, "P-0193-1") {
		t.Errorf("grounding FAIL: base P-0193-1 message must still be emitted when fstype is unknown\nmsg=%q", msgNoFst)
	}
}

// TestCRIUImageInconsistencyError_NoMountpointLeak is the SEC-EVENT-1 guard for the new
// grounding fields. BackingMountpoint is a full path and MUST NEVER appear in the
// world-readable Event/error message (it is log-only). BackingFstype (an fs-type enum, not a
// path) IS allowed. This locks the leak surface the grounding change introduced.
func TestCRIUImageInconsistencyError_NoMountpointLeak(t *testing.T) {
	err := &CRIUImageInconsistencyError{
		FdID:              47,
		NameLeaf:          "000000010000000000000001",
		BackingMntID:      778,
		BackingFstype:     "EXT4",
		BackingMountpoint: "/var/lib/postgresql/data", // full path — must NOT leak into the message
	}
	msg := err.Error()

	if strings.Contains(msg, "/var/lib/postgresql/data") {
		t.Errorf("SEC-EVENT-1 FAIL: full backing mountpoint path leaked into the Event/error message\nmsg=%q", msg)
	}
	if !strings.Contains(msg, "EXT4") {
		t.Errorf("grounding FAIL: backing_fstype (safe, non-path) should be present in the message\nmsg=%q", msg)
	}
}
