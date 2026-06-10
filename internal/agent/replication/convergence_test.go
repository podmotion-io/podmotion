/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package replication

import (
	"testing"
)

func TestEvaluateConvergence_Converging(t *testing.T) {
	rounds := []RoundStats{
		{Round: 0, DirtyMB: 256},
		{Round: 1, DirtyMB: 128},
		{Round: 2, DirtyMB: 60},
	}
	result := EvaluateConvergence(rounds, 64, 5)
	if !result.Converged {
		t.Fatalf("expected Converged=true, got reason=%q", result.Reason)
	}
	if result.FinalDirtyMB != 60 {
		t.Errorf("expected FinalDirtyMB=60, got %d", result.FinalDirtyMB)
	}
	if result.Rounds != 3 {
		t.Errorf("expected Rounds=3, got %d", result.Rounds)
	}
}

func TestEvaluateConvergence_ForceFreeze(t *testing.T) {
	rounds := []RoundStats{
		{Round: 0, DirtyMB: 256},
		{Round: 1, DirtyMB: 200},
		{Round: 2, DirtyMB: 180},
		{Round: 3, DirtyMB: 170},
		{Round: 4, DirtyMB: 165},
	}
	result := EvaluateConvergence(rounds, 64, 5)
	if !result.Converged {
		t.Fatalf("expected Converged=true (force-freeze), got reason=%q", result.Reason)
	}
	if result.Reason != "ForceFreeze: max rounds reached" {
		t.Errorf("expected ForceFreeze reason, got %q", result.Reason)
	}
}

func TestEvaluateConvergence_Diverging(t *testing.T) {
	rounds := []RoundStats{
		{Round: 0, DirtyMB: 100},
		{Round: 1, DirtyMB: 150},
		{Round: 2, DirtyMB: 200},
		{Round: 3, DirtyMB: 300},
	}
	result := EvaluateConvergence(rounds, 64, 10)
	if result.Converged {
		t.Fatal("expected Converged=false for diverging series")
	}
	if result.Reason != "DirtyRateIncreasing" {
		t.Errorf("expected DirtyRateIncreasing reason, got %q", result.Reason)
	}
}

func TestEvaluateConvergence_NonConverging_StillLooping(t *testing.T) {
	rounds := []RoundStats{
		{Round: 0, DirtyMB: 256},
		{Round: 1, DirtyMB: 200},
	}
	result := EvaluateConvergence(rounds, 64, 5)
	if result.Converged {
		t.Fatal("expected Converged=false when still above threshold")
	}
	if result.Reason != "continuing" {
		t.Errorf("expected reason=continuing, got %q", result.Reason)
	}
}

func TestEvaluateConvergence_Empty(t *testing.T) {
	result := EvaluateConvergence(nil, 64, 5)
	if result.Converged {
		t.Fatal("empty rounds should not be converged")
	}
}

func TestEvaluateConvergence_TransientSpike(t *testing.T) {
	// Two increasing rounds then one drop — should not abort (window not fully increasing).
	rounds := []RoundStats{
		{Round: 0, DirtyMB: 100},
		{Round: 1, DirtyMB: 150},
		{Round: 2, DirtyMB: 130},
		{Round: 3, DirtyMB: 140},
	}
	result := EvaluateConvergence(rounds, 64, 10)
	if result.Reason == "DirtyRateIncreasing" {
		t.Error("transient spike should not trigger divergence abort")
	}
}
