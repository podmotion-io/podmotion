/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestSourceTeardownBlockReason_ZeroWindowDisarmVeto is the package-local falsifiable contract
// test for the fail-closed zero-window disarm predicate (Security Reviewer; ADR-0352 Strict
// teardown re-key). It exercises SourceTeardownBlockReason directly in its own leaf package so
// the guarantee is verifiable independently of the controller package. The predicate closes an
// invariant #1 / ADR-0012 hole the Strict phase-routing defense structurally cannot cover: a
// process exit that persists phase=TCPVerifying bypasses reconcileDisengageHold (the only phase
// that disarms the source zero-window hold), VerifyTCP then measures a still-FROZEN socket,
// seq_delta==0 satisfies the Strict TCP-continuity gate VACUOUSLY, and the source pod would be
// deleted with the hold never disarmed. Reading ConditionZeroWindowArmed / ConditionZeroWindow
// Disarmed directly makes teardown fail CLOSED regardless of which phase route reached it.
func TestSourceTeardownBlockReason_ZeroWindowDisarmVeto(t *testing.T) {
	tests := []struct {
		name       string
		mode       TCPPreservationMode
		conditions []metav1.Condition
		wantBlock  bool // true => teardown must be refused (non-empty block reason)
	}{
		{
			// Base path unchanged: Strict with all positive predicates satisfied and NO zero-window
			// conditions present (antecedent absent) stays ALLOWED — proves the new veto does not
			// perturb the pre-existing happy path.
			name: "Strict_AllPredicates_NoZeroWindowConditions_Allowed",
			mode: TCPPreservationModeStrict,
			conditions: []metav1.Condition{
				{Type: ConditionServiceContinuityVerified, Status: metav1.ConditionTrue},
				{Type: ConditionTCPSequenceContinuityVerified, Status: metav1.ConditionTrue},
				{Type: ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue},
			},
			wantBlock: false,
		},
		{
			// Strict, ALL positive predicates satisfied, hold ARMED but disarm NOT confirmed
			// (ZeroWindowDisarmed absent) — the frozen-source-socket vacuity. Returns "" (permit)
			// against the pre-fix predicate; the fix MUST block until disarm is confirmed.
			name: "Strict_AllPredicates_ArmedNotDisarmed_Blocked",
			mode: TCPPreservationModeStrict,
			conditions: []metav1.Condition{
				{Type: ConditionServiceContinuityVerified, Status: metav1.ConditionTrue},
				{Type: ConditionTCPSequenceContinuityVerified, Status: metav1.ConditionTrue},
				{Type: ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue},
				{Type: ConditionZeroWindowArmed, Status: metav1.ConditionTrue},
			},
			wantBlock: true,
		},
		{
			// Companion: once disarm is CONFIRMED (ZeroWindowDisarmed=True) teardown is permitted —
			// the veto is not over-restrictive.
			name: "Strict_AllPredicates_ArmedAndDisarmed_Allowed",
			mode: TCPPreservationModeStrict,
			conditions: []metav1.Condition{
				{Type: ConditionServiceContinuityVerified, Status: metav1.ConditionTrue},
				{Type: ConditionTCPSequenceContinuityVerified, Status: metav1.ConditionTrue},
				{Type: ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue},
				{Type: ConditionZeroWindowArmed, Status: metav1.ConditionTrue},
				{Type: ConditionZeroWindowDisarmed, Status: metav1.ConditionTrue},
			},
			wantBlock: false,
		},
		{
			// Mode-independence + explicit-False: BestEffort with all its positive predicates
			// satisfied, hold armed, disarm EXPLICITLY False must also block. The veto keys on the
			// arm antecedent, not on Strict.
			name: "BestEffort_Armed_DisarmExplicitlyFalse_Blocked",
			mode: TCPPreservationModeBestEffort,
			conditions: []metav1.Condition{
				{Type: conditionTrafficVerified, Status: metav1.ConditionTrue},
				{Type: ConditionTCPSequenceContinuityVerified, Status: metav1.ConditionTrue},
				{Type: ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue},
				{Type: ConditionZeroWindowArmed, Status: metav1.ConditionTrue},
				{Type: ConditionZeroWindowDisarmed, Status: metav1.ConditionFalse},
			},
			wantBlock: true,
		},
		{
			// Antecedent is ==True, not mere presence: ZeroWindowArmed=False (hold never armed —
			// e.g. a migration that failed before ZeroWindowArm) requires no disarm and stays
			// ALLOWED. Guards against the veto over-firing on an absent/never-armed hold.
			name: "None_ArmedFalse_Allowed",
			mode: TCPPreservationModeNone,
			conditions: []metav1.Condition{
				{Type: conditionTrafficVerified, Status: metav1.ConditionTrue},
				{Type: ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue},
				{Type: ConditionZeroWindowArmed, Status: metav1.ConditionFalse},
			},
			wantBlock: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason := SourceTeardownBlockReason(tc.mode, tc.conditions)
			if gotBlock := reason != ""; gotBlock != tc.wantBlock {
				t.Errorf("SourceTeardownBlockReason(mode=%s) blocked=%v (reason=%q), want blocked=%v",
					tc.mode, gotBlock, reason, tc.wantBlock)
			}
		})
	}
}
