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

func TestPreCopyTCPGatePassed(t *testing.T) {
	tests := []struct {
		name       string
		stats      *pmv1.PreCopyStats
		mode       pmv1.MigrationMode
		wantPassed bool
	}{
		{
			name:       "nil stats: gate not passed (no rounds yet)",
			stats:      nil,
			wantPassed: false,
		},
		{
			name:       "zero rounds: gate not passed",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 0, FinalDirtyPagesMB: 10, DirtyStatsValid: true},
			wantPassed: false,
		},
		{
			name:       "1 round, final=512, valid: 512 >= 64MB budget, gate not passed",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 1, FinalDirtyPagesMB: 512, DirtyStatsValid: true},
			wantPassed: false,
		},
		{
			name:       "4 rounds, final=8, valid: 8 < 64MB budget, headroom=0 < 0.5, gate passed",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 4, FinalDirtyPagesMB: 8, DirtyStatsValid: true},
			wantPassed: true,
		},
		{
			name:       "5 rounds, final=1, valid: 1 < 64MB budget, gate passed",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 5, FinalDirtyPagesMB: 1, DirtyStatsValid: true},
			wantPassed: true,
		},
		{
			name:       "3 rounds, final=50, valid: 50 < 64MB budget, gate passed",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 3, FinalDirtyPagesMB: 50, DirtyStatsValid: true},
			wantPassed: true,
		},
		{
			name:       "final=0, valid: a genuinely idle round is a real converged state, gate passed",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 2, FinalDirtyPagesMB: 0, DirtyStatsValid: true},
			wantPassed: true,
		},
		{
			// Regression case for the exact bug class this redesign closes: a real numeric
			// value under budget must NOT be enough on its own — "could not measure" must
			// block even when the stale/leftover FinalDirtyPagesMB value happens to read low.
			name:       "final=0, DirtyStatsValid=false: could-not-measure must block, not fake-pass",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 2, FinalDirtyPagesMB: 0, DirtyStatsValid: false},
			wantPassed: false,
		},
		{
			name:       "final=8 (well under budget) but DirtyStatsValid=false: must still block",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 4, FinalDirtyPagesMB: 8, DirtyStatsValid: false},
			wantPassed: false,
		},
		{
			name:       "at budget boundary: final=64 is NOT < 64, gate not passed",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 1, FinalDirtyPagesMB: 64, DirtyStatsValid: true},
			wantPassed: false,
		},
		{
			name:       "just under budget: final=63, gate passed",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 1, FinalDirtyPagesMB: 63, DirtyStatsValid: true},
			wantPassed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &pmv1.PodMigration{}
			pm.Status.PreCopyStats = tc.stats
			if tc.mode != "" {
				pm.Spec.Mode = tc.mode
			}
			got := preCopyTCPGatePassed(pm)
			if got != tc.wantPassed {
				t.Errorf("preCopyTCPGatePassed() = %v, want %v", got, tc.wantPassed)
			}
		})
	}
}

// TestPreCopyDirtyConverged_NoFakePassBranches is the direct regression test for the deleted
// preCopyDirtyConvergence fake-pass branches (PreCopyStats == nil, finalMB <= 0, initialMB <= 0
// — each formerly returning a synthetic "converged" signal derived from round count alone, never
// from real memory state). None of these inputs may return true from preCopyDirtyConverged; only
// a real, validated, under-budget measurement may.
func TestPreCopyDirtyConverged_NoFakePassBranches(t *testing.T) {
	tests := []struct {
		name  string
		stats *pmv1.PreCopyStats
		want  bool
	}{
		{"nil PreCopyStats never fake-passes", nil, false},
		{"zero rounds never fake-passes", &pmv1.PreCopyStats{RoundsCompleted: 0, FinalDirtyPagesMB: 0, DirtyStatsValid: true}, false},
		{"DirtyStatsValid=false never passes regardless of FinalDirtyPagesMB value", &pmv1.PreCopyStats{RoundsCompleted: 3, FinalDirtyPagesMB: 0, DirtyStatsValid: false}, false},
		{"real, validated, under-budget measurement passes", &pmv1.PreCopyStats{RoundsCompleted: 3, FinalDirtyPagesMB: 10, DirtyStatsValid: true}, true},
		{"real, validated, over-budget measurement blocks", &pmv1.PreCopyStats{RoundsCompleted: 3, FinalDirtyPagesMB: 200, DirtyStatsValid: true}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &pmv1.PodMigration{}
			pm.Status.PreCopyStats = tc.stats
			got := preCopyDirtyConverged(pm)
			if got != tc.want {
				t.Errorf("preCopyDirtyConverged() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPreCopyTCPGatePassed_MeasurementFailedInterleaving is the direct regression test for the
// following gap: a genuine PreDumpRound
// RPC/decode failure — surfaced via RunPreCopyLoop's MeasurementFailed path
// (internal/agent/replication/replication.go) as MemorySynced=True with a PreCopyStats record
// that has DirtyStatsValid=false — must NOT bypass the freeze-go gate the way the old
// MemorySynced=True && PreCopyStats==nil/RoundsCompleted==0 early-return did. This constructs
// the exact reachable state (Reason=MeasurementFailed, real-shaped-but-invalid PreCopyStats) and
// asserts the gate blocks, distinct from TestPreCopyDirtyConverged_NoFakePassBranches which only
// exercises preCopyDirtyConverged as a pure function without the MemorySynced condition/Reason
// in play at all.
func TestPreCopyTCPGatePassed_MeasurementFailedInterleaving(t *testing.T) {
	tests := []struct {
		name       string
		conditions []metav1.Condition
		stats      *pmv1.PreCopyStats
		wantPassed bool
	}{
		{
			name: "MeasurementFailed reason + nil PreCopyStats: must block, not fake-pass",
			conditions: []metav1.Condition{{
				Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: pmv1.ReasonMemorySyncedMeasurementFailed,
				Message: "pre-dump round 0 failed: no validated measurement",
			}},
			stats:      nil,
			wantPassed: false,
		},
		{
			name: "MeasurementFailed reason + explicit DirtyStatsValid=false stats: must block",
			conditions: []metav1.Condition{{
				Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: pmv1.ReasonMemorySyncedMeasurementFailed,
				Message: "pre-dump round 2 failed: no validated measurement",
			}},
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 2, FinalDirtyPagesMB: 0, DirtyStatsValid: false},
			wantPassed: false,
		},
		{
			name: "MeasurementFailed reason on round 0 (RoundsCompleted=0): must block",
			conditions: []metav1.Condition{{
				Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: pmv1.ReasonMemorySyncedMeasurementFailed,
			}},
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 0, FinalDirtyPagesMB: 0, DirtyStatsValid: false},
			wantPassed: false,
		},
		{
			name: "Converged reason with real validated under-budget stats: gate passes",
			conditions: []metav1.Condition{{
				Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: pmv1.ReasonMemorySyncedConverged,
			}},
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 1, FinalDirtyPagesMB: 10, DirtyStatsValid: true},
			wantPassed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &pmv1.PodMigration{}
			pm.Status.Conditions = tc.conditions
			pm.Status.PreCopyStats = tc.stats
			got := preCopyTCPGatePassed(pm)
			if got != tc.wantPassed {
				t.Errorf("preCopyTCPGatePassed() = %v, want %v", got, tc.wantPassed)
			}
		})
	}
}

// TestPreCopyTCPGatePassed_ForceFreezeExempt is the direct regression test for the
// following behavior: ADR-0011's PreCopyMaxRounds-exhausted escape valve (Reason=ForceFreeze,
// written by RunPreCopyLoop's loop-exit path with a REAL, DirtyStatsValid=true measurement that
// may still be at/above the freeze budget for a sustained-high-dirty-rate workload) must be
// explicitly exempted from the strict FinalDirtyPagesMB < budget recheck — otherwise a busy
// write-heavy pod under TCPPreservationMode=Strict/BestEffort livelocks in PreCopyMemory forever
// (until the ADR-0012 completion-timeout backstop fails it closed). This must NOT regress via the
// MeasurementFailed fix above: ForceFreeze and MeasurementFailed are deliberately kept as two
// distinguishable states.
func TestPreCopyTCPGatePassed_ForceFreezeExempt(t *testing.T) {
	tests := []struct {
		name       string
		conditions []metav1.Condition
		stats      *pmv1.PreCopyStats
		wantPassed bool
	}{
		{
			name: "ForceFreeze reason, real stats still over budget: gate passes (ADR-0011 exemption)",
			conditions: []metav1.Condition{{
				Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: pmv1.ReasonMemorySyncedForceFreeze,
				Message: "max rounds exhausted: 512MB remaining",
			}},
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 5, FinalDirtyPagesMB: 512, DirtyStatsValid: true},
			wantPassed: true,
		},
		{
			name: "ForceFreeze reason, real stats under budget: gate passes",
			conditions: []metav1.Condition{{
				Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: pmv1.ReasonMemorySyncedForceFreeze,
			}},
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 5, FinalDirtyPagesMB: 8, DirtyStatsValid: true},
			wantPassed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &pmv1.PodMigration{}
			pm.Status.Conditions = tc.conditions
			pm.Status.PreCopyStats = tc.stats
			got := preCopyTCPGatePassed(pm)
			if got != tc.wantPassed {
				t.Errorf("preCopyTCPGatePassed() = %v, want %v", got, tc.wantPassed)
			}
		})
	}
}

// TestPreCopyTCPGatePassed_ForceFreezeRequiresRealStats is the direct regression test for the
// following defect: the ForceFreeze exemption previously trusted the Reason=="ForceFreeze" STRING alone as
// proof a real dirty-page measurement backs it. That is not actually enforced by the write path —
// RunPreCopyLoop (internal/agent/replication/replication.go) calls updatePreCopyStats and only
// logs its error (never propagates it) before unconditionally calling patchMemorySynced(...,
// ForceFreeze, ...). A Get failure, a sustained conflict exhausting the retry budget, or any
// other non-conflict error leaves PreCopyStats nil/stale while Reason=ForceFreeze is still
// persisted. This test constructs exactly that reachable interleaving (Reason=ForceFreeze with
// nil, zero-round, or DirtyStatsValid=false PreCopyStats) and asserts the gate must block, not
// fake-pass — the gate must read pm.Status.PreCopyStats.DirtyStatsValid/RoundsCompleted directly,
// never trust the Reason label as a proxy for "a measurement exists."
func TestPreCopyTCPGatePassed_ForceFreezeRequiresRealStats(t *testing.T) {
	tests := []struct {
		name       string
		conditions []metav1.Condition
		stats      *pmv1.PreCopyStats
		wantPassed bool
	}{
		{
			name: "ForceFreeze reason + nil PreCopyStats (swallowed updatePreCopyStats error): must block, not fake-pass",
			conditions: []metav1.Condition{{
				Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: pmv1.ReasonMemorySyncedForceFreeze,
				Message: "max rounds exhausted: 512MB remaining",
			}},
			stats:      nil,
			wantPassed: false,
		},
		{
			name: "ForceFreeze reason + DirtyStatsValid=false stats: must block",
			conditions: []metav1.Condition{{
				Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: pmv1.ReasonMemorySyncedForceFreeze,
			}},
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 5, FinalDirtyPagesMB: 0, DirtyStatsValid: false},
			wantPassed: false,
		},
		{
			name: "ForceFreeze reason + RoundsCompleted=0 (stale zero-value stats): must block",
			conditions: []metav1.Condition{{
				Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: pmv1.ReasonMemorySyncedForceFreeze,
			}},
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 0, FinalDirtyPagesMB: 0, DirtyStatsValid: true},
			wantPassed: false,
		},
		{
			name: "ForceFreeze reason + real validated stats (DirtyStatsValid=true, RoundsCompleted>0): exemption applies, gate passes",
			conditions: []metav1.Condition{{
				Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: pmv1.ReasonMemorySyncedForceFreeze,
			}},
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 5, FinalDirtyPagesMB: 512, DirtyStatsValid: true},
			wantPassed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &pmv1.PodMigration{}
			pm.Status.Conditions = tc.conditions
			pm.Status.PreCopyStats = tc.stats
			got := preCopyTCPGatePassed(pm)
			if got != tc.wantPassed {
				t.Errorf("preCopyTCPGatePassed() = %v, want %v", got, tc.wantPassed)
			}
		})
	}
}

// TestPreCopyDirtyConverged_IdleRoundZeroThenLaterBurst is the direct regression test for the
// "idle round-0 then burst" scenario: the gate must read the
// LATEST round's validated absolute dirty MB, not a stale or synthetic initial-round baseline,
// so a later burst is caught because the latest round's real measurement reflects it. Retained
// InitialDirtyPagesMB is observability-only and must never feed this decision: a legitimately
// idle round 0 (Initial=0) followed by a later round with a large FinalDirtyPagesMB must block.
func TestPreCopyDirtyConverged_IdleRoundZeroThenLaterBurst(t *testing.T) {
	pm := &pmv1.PodMigration{}
	pm.Status.PreCopyStats = &pmv1.PreCopyStats{
		RoundsCompleted:     3,
		InitialDirtyPagesMB: 0,   // round 0 was legitimately idle
		FinalDirtyPagesMB:   500, // but a later round saw a burst
		DirtyStatsValid:     true,
	}
	if preCopyDirtyConverged(pm) {
		t.Error("preCopyDirtyConverged() = true, want false: a later-round burst must not be masked by an idle round-0 baseline")
	}
}
