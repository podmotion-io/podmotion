/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"testing"

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
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 0, FinalDirtyPagesMB: 10},
			wantPassed: false,
		},
		{
			name:       "1 round, final=512: convergence=0.5, below 0.9 threshold",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 1, FinalDirtyPagesMB: 512},
			wantPassed: false,
		},
		{
			name: "4 rounds, final=8: convergence=1 - 8/128 = 0.9375 > 0.9, headroom=0 < 0.5",
			// initial estimate = 8 * 2^4 = 128; convergence = 1 - 8/128 = 0.9375
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 4, FinalDirtyPagesMB: 8},
			wantPassed: true,
		},
		{
			name: "5 rounds, final=1: convergence ~0.969 > 0.9",
			// initial estimate = 1 * 2^5 = 32; convergence = 1 - 1/32 = 0.969
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 5, FinalDirtyPagesMB: 1},
			wantPassed: true,
		},
		{
			name:       "3 rounds, final=50: convergence=1 - 50/400 = 0.875 < 0.9",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 3, FinalDirtyPagesMB: 50},
			wantPassed: false,
		},
		{
			name:       "finalDirtyPagesMB zero: convergence=1.0, gate passes",
			stats:      &pmv1.PreCopyStats{RoundsCompleted: 2, FinalDirtyPagesMB: 0},
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

func TestPreCopyDirtyConvergence(t *testing.T) {
	tests := []struct {
		name  string
		stats *pmv1.PreCopyStats
		want  float64 // approximate
	}{
		{"nil stats", nil, 1.0},
		{"zero rounds", &pmv1.PreCopyStats{RoundsCompleted: 0}, 0.0},
		{"final=0", &pmv1.PreCopyStats{RoundsCompleted: 1, FinalDirtyPagesMB: 0}, 1.0},
		{"4 rounds final=8 → 0.9375", &pmv1.PreCopyStats{RoundsCompleted: 4, FinalDirtyPagesMB: 8}, 0.9375},
		{"1 round final=512 → 0.5", &pmv1.PreCopyStats{RoundsCompleted: 1, FinalDirtyPagesMB: 512}, 0.5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &pmv1.PodMigration{}
			pm.Status.PreCopyStats = tc.stats
			got := preCopyDirtyConvergence(pm)
			const epsilon = 0.001
			if got < tc.want-epsilon || got > tc.want+epsilon {
				t.Errorf("preCopyDirtyConvergence() = %v, want ~%v", got, tc.want)
			}
		})
	}
}
