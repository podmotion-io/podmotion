/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"testing"
	"time"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestMigrationPolicyController_WindowBlocked verifies that blockedCron prevents
// migrations and that allowedCron rejects times outside its window.
func TestMigrationPolicyController_WindowBlocked(t *testing.T) {
	r := &MigrationPolicyReconciler{}

	// Tuesday 14:30 UTC
	fixedTime := time.Date(2026, 6, 9, 14, 30, 0, 0, time.UTC)

	tests := []struct {
		name        string
		blockedCron string
		allowedCron string
		wantBlocked bool
	}{
		{
			name:        "blockedCron matches — blocked",
			blockedCron: "* 14 * * 2",
			wantBlocked: true,
		},
		{
			name:        "blockedCron does not match — allowed",
			blockedCron: "* 3 * * *",
			wantBlocked: false,
		},
		{
			name:        "outside allowedCron — blocked",
			allowedCron: "* 2 * * 1-5",
			wantBlocked: true,
		},
		{
			name:        "inside allowedCron — not blocked",
			allowedCron: "* 14 * * 2",
			wantBlocked: false,
		},
		{
			name:        "blockedCron takes precedence over allowedCron",
			blockedCron: "* 14 * * 2",
			allowedCron: "* 14 * * 2",
			wantBlocked: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := &pmv1.MigrationWindow{
				AllowedCron: tc.allowedCron,
				BlockedCron: tc.blockedCron,
			}
			blocked, _ := r.isWindowBlocked(w, fixedTime)
			if blocked != tc.wantBlocked {
				t.Errorf("isWindowBlocked = %v, want %v", blocked, tc.wantBlocked)
			}
		})
	}
}

// TestCronMatches validates the lightweight cron field matcher.
func TestCronMatches(t *testing.T) {
	// Tuesday 14:30 UTC (weekday=2)
	tuesday14h30 := time.Date(2026, 6, 9, 14, 30, 0, 0, time.UTC)

	cases := []struct {
		expr string
		want bool
	}{
		{"* * * * *", true},
		{"30 14 * * 2", true},
		{"0 14 * * 2", false},   // minute 0, not 30
		{"* 14 * * 1-5", true},  // weekday in range
		{"* 14 * * 6", false},   // Saturday
		{"*/15 * * * *", true},  // 30 % 15 == 0
		{"*/7 * * * *", false},  // 30 % 7 != 0
		{"30,45 14 * * *", true},
		{"0,15 14 * * *", false},
	}
	for _, c := range cases {
		got := cronMatches(c.expr, tuesday14h30)
		if got != c.want {
			t.Errorf("cronMatches(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}
