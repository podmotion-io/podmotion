/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package replication

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
)

const (
	conditionMemorySynced = "MemorySynced"
	// basePredumpDir is the root under which per-round image directories are created.
	basePredumpDir = "/var/lib/podmotion/checkpoints"
)

// ReplicationManager owns the iterative pre-copy dirty-page sync loop (Agent 11).
// It runs in a goroutine launched by the PodMigration controller PreMigrating phase
// and patches the MemorySynced condition on the CR when the loop concludes.
type ReplicationManager struct {
	// Client is the k8s client used to patch PodMigration status.
	Client client.Client
}

// RunPreCopyLoop executes the full Mirror → Iterative Sync → Convergence loop.
//
// Loop structure:
//
//	Round 0 (Mirror): initial pre-dump with PrevImagesDir="".
//	Rounds 1..MaxRounds: incremental pre-dumps using the previous round's directory.
//
// Termination conditions (evaluated after each round via EvaluateConvergence):
//   - DirtyMB < threshold → MemorySynced=True (normal convergence)
//   - rounds >= MaxRounds → MemorySynced=True with ForceFreeze note (ADR-0011)
//   - dirty rate increasing for 3 consecutive rounds → MemorySynced=False, reason=DirtyRateIncreasing
//     (ADR-0024: clean abort; pod is never frozen so no rollback needed)
//
// The caller (reconcilePreMigrating goroutine) watches for MemorySynced to appear
// and then gates on StorageReadyForFreeze before advancing to Checkpointing.
func (r *ReplicationManager) RunPreCopyLoop(
	ctx context.Context,
	pm *pmv1.PodMigration,
	checkpointer criu.Checkpointer,
) error {
	log := logf.FromContext(ctx).WithValues("migration", pm.Name)

	maxRounds := pm.Spec.PreCopyMaxRounds
	if maxRounds <= 0 {
		maxRounds = 5
	}
	threshold := pm.Spec.PreCopyDirtyThresholdMB
	if threshold <= 0 {
		threshold = 64
	}

	var (
		rounds      []RoundStats
		prevDir     string
		containerID = pm.Spec.PodName // placeholder — real impl resolves via CRI
		namespace   = "k8s.io"
	)

	for round := 0; int32(round) < maxRounds; round++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		imagesDir := fmt.Sprintf("%s/%s/round-%d", basePredumpDir, pm.Name, round)

		start := time.Now()
		result, err := checkpointer.PreDump(ctx, criu.PreDumpOptions{
			ContainerID:   containerID,
			Namespace:     namespace,
			ImagesDir:     imagesDir,
			PrevImagesDir: prevDir,
			TrackMem:      true,
		})
		if err != nil {
			return fmt.Errorf("pre-dump round %d failed: %w", round, err)
		}

		elapsedMs := time.Since(start).Milliseconds()
		var rateMBps float64
		if elapsedMs > 0 {
			rateMBps = float64(result.DirtyPagesMB) / (float64(elapsedMs) / 1000.0)
		}

		stat := RoundStats{
			Round:         round,
			DirtyMB:       result.DirtyPagesMB,
			DirtyRateMBps: rateMBps,
			ElapsedMs:     elapsedMs,
		}
		rounds = append(rounds, stat)
		prevDir = imagesDir

		log.Info("pre-dump round complete",
			"round", round, "dirtyMB", result.DirtyPagesMB, "elapsedMs", elapsedMs)

		conv := EvaluateConvergence(rounds, threshold, maxRounds)

		if conv.Reason == "DirtyRateIncreasing" {
			// ADR-0024: diverging dirty rate → clean abort without rollback.
			// Pod has never been frozen so source remains fully live.
			log.Info("dirty rate diverging — aborting pre-copy loop", "rounds", conv.Rounds)
			return r.patchMemorySynced(ctx, pm, metav1.ConditionFalse, "DirtyRateIncreasing",
				fmt.Sprintf("dirty pages increasing for %d consecutive rounds: %dMB",
					divergenceWindowSize, conv.FinalDirtyMB))
		}

		if conv.Converged {
			log.Info("pre-copy loop converged", "reason", conv.Reason, "finalDirtyMB", conv.FinalDirtyMB)
			if err := r.updatePreCopyStats(ctx, pm, conv, rounds); err != nil {
				log.Error(err, "failed to update PreCopyStats")
			}
			return r.patchMemorySynced(ctx, pm, metav1.ConditionTrue, "Converged",
				fmt.Sprintf("%s: %dMB remaining after %d rounds", conv.Reason, conv.FinalDirtyMB, conv.Rounds))
		}
	}

	// Should not reach here — EvaluateConvergence handles the maxRounds case,
	// but guard against off-by-one if threshold is never crossed.
	conv := EvaluateConvergence(rounds, threshold, maxRounds)
	if err := r.updatePreCopyStats(ctx, pm, conv, rounds); err != nil {
		log.Error(err, "failed to update PreCopyStats on loop exit")
	}
	return r.patchMemorySynced(ctx, pm, metav1.ConditionTrue, "ForceFreeze",
		fmt.Sprintf("max rounds exhausted: %dMB remaining", conv.FinalDirtyMB))
}

// patchMemorySynced writes the MemorySynced condition to the PodMigration status via SSA patch.
func (r *ReplicationManager) patchMemorySynced(
	ctx context.Context,
	pm *pmv1.PodMigration,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	// Fetch fresh copy to avoid conflict on stale resource version.
	fresh := &pmv1.PodMigration{}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(pm), fresh); err != nil {
		return fmt.Errorf("get PodMigration for patch: %w", err)
	}
	meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
		Type:               conditionMemorySynced,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
	return r.Client.Status().Update(ctx, fresh)
}

// updatePreCopyStats persists pre-copy metrics to pm.Status.PreCopyStats.
// Called before patchMemorySynced so stats are visible alongside the condition.
func (r *ReplicationManager) updatePreCopyStats(
	ctx context.Context,
	pm *pmv1.PodMigration,
	conv ConvergenceResult,
	rounds []RoundStats,
) error {
	fresh := &pmv1.PodMigration{}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(pm), fresh); err != nil {
		return err
	}

	// FreezeDurationMs is not known here (that is the final CRIU Dump timing).
	// Recorded as 0 now; the Checkpointing phase updates it after the real dump.
	fresh.Status.PreCopyStats = &pmv1.PreCopyStats{
		RoundsCompleted:   int32(conv.Rounds),
		FinalDirtyPagesMB: int32(conv.FinalDirtyMB),
		FreezeDurationMs:  0,
	}
	return r.Client.Status().Update(ctx, fresh)
}
