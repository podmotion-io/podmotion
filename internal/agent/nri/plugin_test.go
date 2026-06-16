/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package nri

import (
	"fmt"
	"strings"
	"testing"
)

// TestVerifyPodMigrationAcceptSet is the P-VERIFY-NRI-PHASE-ORDER contract test (ADR-0185 C2).
//
// It asserts the NRI anti-spoof accept-set equals EXACTLY the set of phases reachable after
// conditionVXLANFDBUpdated=True — an equality/closure check, not a subset check. Under Option B
// (ADR-0185 r1) OverlayHandoff is NOT in the accept-set: the FDB barrier (ADR-0048/0049) is not
// yet confirmed at OverlayHandoff, so CRIU restore must not begin. The bounded retry loop in
// HandleStartContainer waits (treating OverlayHandoff/FinalFreezeStateCapture as transient) until
// the operator advances into an accepted restore phase.
//
// A red result here is a §3d HARD STOP: the gate does not run and the churn counter does not
// increment.
func TestVerifyPodMigrationAcceptSet(t *testing.T) {
	acceptedPhases := []string{
		"Restoring", "RestoreSocketReattach", "DisengageHold",
	}
	rejectedPhases := []string{
		"Pending", "SocketInventory", "PreCopyMemory", "FinalFreezeStateCapture",
		"OverlayHandoff", // C3: must NOT be in accept-set (FDB not yet confirmed)
		"Checkpointed", "CheckpointTransferred", "RollingBack", "Failed", "Succeeded",
	}

	// Each rejected phase must produce a "phase is" error (so the retry loop treats it as
	// transient and waits, rather than accepting it).
	for _, phase := range rejectedPhases {
		err := verifyPhaseInAcceptSet(phase)
		if err == nil || !strings.Contains(err.Error(), "phase is") {
			t.Errorf("phase %q should be rejected but was accepted or gave wrong error: %v", phase, err)
		}
	}

	// Each accepted phase must produce no error.
	for _, phase := range acceptedPhases {
		err := verifyPhaseInAcceptSet(phase)
		if err != nil {
			t.Errorf("phase %q should be accepted but was rejected: %v", phase, err)
		}
	}

	// FinalFreezeStateCapture: retry loop must survive (not fail fast) — C-CNCF-2.
	if !isPhaseTransientErr(fmt.Errorf("PodMigration ns/cr phase is FinalFreezeStateCapture, expected ...")) {
		t.Error("FinalFreezeStateCapture must be treated as transient by isPhaseTransientErr")
	}

	// OverlayHandoff: retry loop must survive (not fail fast) — Option B waits for advance.
	if !isPhaseTransientErr(fmt.Errorf("PodMigration ns/cr phase is OverlayHandoff, expected ...")) {
		t.Error("OverlayHandoff must be treated as transient by isPhaseTransientErr")
	}

	// Forged/missing CR (no "phase is" in error): must NOT be transient — fail fast.
	if isPhaseTransientErr(fmt.Errorf("no PodMigration in ns with checkpointRef \"x\" in Restoring phase")) {
		t.Error("missing CR must NOT be treated as transient")
	}
	if isPhaseTransientErr(fmt.Errorf("PodMigration ns/cr destinationNode a != this node b")) {
		t.Error("node mismatch must NOT be treated as transient")
	}
	if isPhaseTransientErr(fmt.Errorf("list PodMigrations: connection refused")) {
		t.Error("List failure must NOT be treated as transient")
	}
}
