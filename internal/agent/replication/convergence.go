/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package replication implements the iterative pre-copy dirty-page sync loop (Agent 11, M5).
//
// Architecture:
//   - ReplicationManager drives the Mirror → Iterative → Convergence → Freeze pipeline.
//   - EvaluateConvergence is a pure function for testability.
//   - Divergence abort: 3 consecutive rounds of increasing dirty pages → clean abort
//     (pod is never frozen during this phase so no rollback is required).
//   - See ADR-0024 for the convergence abort policy.
package replication

// RoundStats captures the outcome of one pre-dump round.
type RoundStats struct {
	Round     int
	DirtyMB   int64
	// DirtyRateMBps is the dirty page rate for this round; used for logging only.
	DirtyRateMBps float64
	ElapsedMs     int64
}

// ConvergenceResult summarises the outcome of the full pre-copy loop.
type ConvergenceResult struct {
	// Converged is true when DirtyMB dropped below the threshold before MaxRounds.
	Converged bool
	// FinalDirtyMB is the dirty page count on the round that ended the loop.
	FinalDirtyMB int64
	Rounds       int
	// Reason is a human-readable explanation of why the loop ended.
	Reason string
}

// divergenceWindowSize is the number of consecutive increasing rounds that
// trigger a clean abort. Three rounds gives one transient spike tolerance.
const divergenceWindowSize = 3

// EvaluateConvergence decides whether to continue pre-copy, advance to freeze,
// or abort because dirty pages are increasing.
//
// Rules (in priority order):
//  1. If the last round's DirtyMB is below threshold → Converged=true.
//  2. If rounds >= maxRounds → Converged=true with ForceFreeze note (ADR-0011).
//  3. If the last divergenceWindowSize rounds are all strictly increasing →
//     Converged=false, Reason=DirtyRateIncreasing (ADR-0024 abort path).
//  4. Otherwise → Converged=false, continue looping.
func EvaluateConvergence(rounds []RoundStats, threshold int32, maxRounds int32) ConvergenceResult {
	n := len(rounds)
	if n == 0 {
		return ConvergenceResult{Reason: "no rounds yet"}
	}

	last := rounds[n-1]

	if last.DirtyMB < int64(threshold) {
		return ConvergenceResult{
			Converged:    true,
			FinalDirtyMB: last.DirtyMB,
			Rounds:       n,
			Reason:       "dirty pages below threshold",
		}
	}

	if int32(n) >= maxRounds {
		return ConvergenceResult{
			Converged:    true,
			FinalDirtyMB: last.DirtyMB,
			Rounds:       n,
			Reason:       "ForceFreeze: max rounds reached",
		}
	}

	// Check for diverging dirty rate over the last divergenceWindowSize rounds.
	if n >= divergenceWindowSize {
		window := rounds[n-divergenceWindowSize:]
		diverging := true
		for i := 1; i < len(window); i++ {
			if window[i].DirtyMB <= window[i-1].DirtyMB {
				diverging = false
				break
			}
		}
		if diverging {
			return ConvergenceResult{
				Converged:    false,
				FinalDirtyMB: last.DirtyMB,
				Rounds:       n,
				Reason:       "DirtyRateIncreasing",
			}
		}
	}

	return ConvergenceResult{
		Converged:    false,
		FinalDirtyMB: last.DirtyMB,
		Rounds:       n,
		Reason:       "continuing",
	}
}
