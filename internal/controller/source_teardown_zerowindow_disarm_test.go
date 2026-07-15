/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestSourcePodDeletionBlockReason_ZeroWindowDisarmDelegation is the controller-side companion to
// the package-local api/v1alpha1 test: it asserts the controller's delegating gate
// (sourcePodDeletionBlockReason) reflects the fail-closed zero-window disarm predicate added to
// pmv1.SourceTeardownBlockReason (Security Reviewer; ADR-0352 Strict teardown re-key), so the new
// predicate cannot drift between the two live entry points. The predicate closes an invariant #1 /
// ADR-0012 hole the Strict phase-routing defense structurally cannot cover: a process exit that
// persists phase=TCPVerifying dispatches straight to reconcileTCPVerifying and BYPASSES
// reconcileDisengageHold — the only phase that disarms the source zero-window hold. VerifyTCP then
// measures a still-FROZEN socket, seq_delta==0 satisfies the Strict TCP-continuity gate VACUOUSLY,
// and the source pod would be deleted with the hold never disarmed. Reading the authoritative
// ConditionZeroWindowArmed / ConditionZeroWindowDisarmed write-backs directly makes teardown fail
// CLOSED regardless of which phase route reached it.
func TestSourcePodDeletionBlockReason_ZeroWindowDisarmDelegation(t *testing.T) {
	tests := []struct {
		name       string
		mode       pmv1.TCPPreservationMode
		conditions []metav1.Condition
		wantBlock  bool // true => teardown must be refused (non-empty block reason)
	}{
		{
			// Strict, ALL positive predicates satisfied, hold ARMED but disarm NOT confirmed
			// (ZeroWindowDisarmed absent) — the frozen-source-socket vacuity. Returns "" (permit)
			// against the pre-fix predicate; the fix MUST block until disarm is confirmed.
			name: "Strict_AllPredicates_ArmedNotDisarmed_Blocked",
			mode: pmv1.TCPPreservationModeStrict,
			conditions: []metav1.Condition{
				{Type: string(pmv1.ConditionServiceContinuityVerified), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionTCPSequenceContinuityVerified), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionWorkloadLivenessVerified), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionZeroWindowArmed), Status: metav1.ConditionTrue},
			},
			wantBlock: true,
		},
		{
			// Companion: once disarm is CONFIRMED (ZeroWindowDisarmed=True) teardown is permitted —
			// the veto is not over-restrictive.
			name: "Strict_AllPredicates_ArmedAndDisarmed_Allowed",
			mode: pmv1.TCPPreservationModeStrict,
			conditions: []metav1.Condition{
				{Type: string(pmv1.ConditionServiceContinuityVerified), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionTCPSequenceContinuityVerified), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionWorkloadLivenessVerified), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionZeroWindowArmed), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionZeroWindowDisarmed), Status: metav1.ConditionTrue},
			},
			wantBlock: false,
		},
		{
			// Mode-independence + explicit-False: BestEffort with all its positive predicates
			// satisfied, hold armed, disarm EXPLICITLY False must also block. The veto keys on the
			// arm antecedent, not on Strict.
			name: "BestEffort_Armed_DisarmExplicitlyFalse_Blocked",
			mode: pmv1.TCPPreservationModeBestEffort,
			conditions: []metav1.Condition{
				{Type: conditionTrafficVerified, Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionTCPSequenceContinuityVerified), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionWorkloadLivenessVerified), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionZeroWindowArmed), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionZeroWindowDisarmed), Status: metav1.ConditionFalse},
			},
			wantBlock: true,
		},
		{
			// Antecedent is ==True, not mere presence: ZeroWindowArmed=False (hold never armed —
			// e.g. a migration that failed before ZeroWindowArm) requires no disarm and stays
			// ALLOWED. Guards against the veto over-firing on an absent/never-armed hold.
			name: "None_ArmedFalse_Allowed",
			mode: pmv1.TCPPreservationModeNone,
			conditions: []metav1.Condition{
				{Type: conditionTrafficVerified, Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionWorkloadLivenessVerified), Status: metav1.ConditionTrue},
				{Type: string(pmv1.ConditionZeroWindowArmed), Status: metav1.ConditionFalse},
			},
			wantBlock: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Assert on the function under change directly.
			reason := pmv1.SourceTeardownBlockReason(tc.mode, tc.conditions)
			if gotBlock := reason != ""; gotBlock != tc.wantBlock {
				t.Errorf("SourceTeardownBlockReason(mode=%s) blocked=%v (reason=%q), want blocked=%v",
					tc.mode, gotBlock, reason, tc.wantBlock)
			}
			// Confirm the controller-local delegating gate agrees on the new predicate.
			if got := sourcePodDeletionBlockReason(tc.mode, tc.conditions); (got != "") != tc.wantBlock {
				t.Errorf("sourcePodDeletionBlockReason(mode=%s) blocked=%v, want blocked=%v — delegation drift on the zero-window disarm predicate",
					tc.mode, got != "", tc.wantBlock)
			}
		})
	}
}
