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
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

const conditionMemorySynced = "MemorySynced"

// ReplicationManager owns the iterative pre-copy dirty-page sync loop (Agent 11).
// It runs in a goroutine launched by the PodMigration controller PreMigrating phase
// and patches the MemorySynced condition on the CR when the loop concludes.
//
// Pre-dump rounds are executed via PreDumpRound RPC on the SOURCE agent — CRIU runs
// on the node where the container lives, not on the operator node.
type ReplicationManager struct {
	// Client is the k8s client used to patch PodMigration status.
	Client client.Client
	// AgentPool provides per-node gRPC connections to source agents.
	AgentPool *agentclient.AgentClientPool
}

// RunPreCopyLoop executes the full Mirror → Iterative Sync → Convergence loop.
//
// Loop structure:
//
//	Round 0 (Mirror): initial pre-dump with no previous dir.
//	Rounds 1..MaxRounds: incremental pre-dumps using the previous round as parent.
//
// Termination conditions (evaluated after each round):
//   - DirtyMB < threshold → MemorySynced=True  (normal convergence)
//   - rounds >= MaxRounds → MemorySynced=True with ForceFreeze note (ADR-0011)
//   - dirty rate increasing for 3 consecutive rounds → MemorySynced=False, DirtyRateIncreasing
//     (ADR-0024: clean abort; pod is never frozen so no rollback needed)
func (r *ReplicationManager) RunPreCopyLoop(
	ctx context.Context,
	pm *pmv1.PodMigration,
	_ interface{}, // unused: checkpointer — pre-dump is now via RPC on the source agent
) error {
	log := logf.FromContext(ctx).WithValues("migration", pm.Name)

	if r.AgentPool == nil {
		return fmt.Errorf("ReplicationManager.AgentPool is nil — cannot run pre-copy via RPC")
	}

	sourceNode := pm.Status.SourceNodeName
	if sourceNode == "" {
		sourceNode = pm.Spec.TargetNodeName // fallback for tests
	}
	if sourceNode == "" {
		return fmt.Errorf("source node unknown — cannot issue PreDumpRound RPC")
	}

	srcClient, err := r.AgentPool.ForNode(ctx, sourceNode)
	if err != nil {
		return fmt.Errorf("connect to source agent on %s: %w", sourceNode, err)
	}

	maxRounds := pm.Spec.PreCopyMaxRounds
	if maxRounds <= 0 {
		maxRounds = 5
	}
	threshold := pm.Spec.PreCopyDirtyThresholdMB
	if threshold <= 0 {
		threshold = 64
	}

	var rounds []RoundStats

	for round := int32(0); round < maxRounds; round++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		start := time.Now()
		resp, err := srcClient.PreDumpRound(ctx, &agentpb.PreDumpRoundRequest{
			MigrationName: pm.Name,
			RoundNumber:   round,
			PodUid:        pm.Spec.SourcePodUID,
		})
		if err != nil {
			// Pre-dump RPC failed (e.g. CRIU "Unable to interrupt task" on aarch64 daemon
			// processes). Treat as ForceFreeze — no dirty pages to track, proceed to final
			// checkpoint. This sets MemorySynced=True so the next reconcile does not launch
			// another goroutine (goroutine-launch-leak fix).
			log.Info("PreDumpRound failed — treating as ForceFreeze and proceeding to final checkpoint",
				"round", round, "err", err)
			return r.patchMemorySynced(ctx, pm, metav1.ConditionTrue, "ForceFreeze",
				fmt.Sprintf("pre-dump round %d failed (%v): skipping pre-copy, proceeding to final freeze", round, err))
		}

		elapsedMs := time.Since(start).Milliseconds()
		var rateMBps float64
		if elapsedMs > 0 {
			rateMBps = float64(resp.DirtyPagesMb) / (float64(elapsedMs) / 1000.0)
		}

		stat := RoundStats{
			Round:         int(round),
			DirtyMB:       resp.DirtyPagesMb,
			DirtyRateMBps: rateMBps,
			ElapsedMs:     elapsedMs,
		}
		rounds = append(rounds, stat)

		log.Info("pre-dump round complete",
			"round", round, "dirtyMB", resp.DirtyPagesMb, "elapsedMs", elapsedMs)

		conv := EvaluateConvergence(rounds, threshold, maxRounds)

		if conv.Reason == "DirtyRateIncreasing" {
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

	// Max rounds exhausted without convergence — force freeze (ADR-0011).
	conv := EvaluateConvergence(rounds, threshold, maxRounds)
	if err := r.updatePreCopyStats(ctx, pm, conv, rounds); err != nil {
		log.Error(err, "failed to update PreCopyStats on loop exit")
	}
	return r.patchMemorySynced(ctx, pm, metav1.ConditionTrue, "ForceFreeze",
		fmt.Sprintf("max rounds exhausted: %dMB remaining", conv.FinalDirtyMB))
}

// patchMemorySynced writes the MemorySynced condition to the PodMigration status.
// Retries on optimistic-lock conflict using retry.RetryOnConflict.
func (r *ReplicationManager) patchMemorySynced(
	ctx context.Context,
	pm *pmv1.PodMigration,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	key := client.ObjectKeyFromObject(pm)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := r.Client.Get(ctx, key, fresh); err != nil {
			return fmt.Errorf("get PodMigration for patch: %w", err)
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:   conditionMemorySynced,
			Status: status,
			Reason: reason,
			// ADR-0226: bound the message below the CRD apiserver limit
			// (status.conditions[].message maxLength=32768). The ForceFreeze path
			// embeds the raw CRIU/gRPC error via %v, which can exceed 32768 bytes;
			// an over-limit message is REJECTED by the apiserver, so the condition
			// never persists, memoryCond stays nil, and the controller relaunches
			// the pre-copy goroutine every reconcile (round-0 livelock). The full
			// error remains in the operator log; only the persisted message is
			// capped. Mirrors the controller-side setCondition truncation contract.
			Message:            truncateConditionMsg(message, 1024),
			LastTransitionTime: metav1.Now(),
		})
		return r.Client.Status().Update(ctx, fresh)
	})
}

// truncateConditionMsg bounds a condition message so it never exceeds the CRD
// apiserver limit (status.conditions[].message must be <= 32768 bytes). CRIU dump
// log output and gRPC error strings can be far larger; we cap well under the limit
// at a human-readable length. (ADR-0226 — agent-side dual of the controller's
// setCondition truncation; restores symmetry with the Sprint 31 controller fix.)
func truncateConditionMsg(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// updatePreCopyStats persists pre-copy metrics to pm.Status.PreCopyStats.
func (r *ReplicationManager) updatePreCopyStats(
	ctx context.Context,
	pm *pmv1.PodMigration,
	conv ConvergenceResult,
	rounds []RoundStats,
) error {
	key := client.ObjectKeyFromObject(pm)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := r.Client.Get(ctx, key, fresh); err != nil {
			return err
		}
		fresh.Status.PreCopyStats = &pmv1.PreCopyStats{
			RoundsCompleted:   int32(conv.Rounds),
			FinalDirtyPagesMB: int32(conv.FinalDirtyMB),
			FreezeDurationMs:  0, // updated by Checkpointing phase after the real dump
		}
		return r.Client.Status().Update(ctx, fresh)
	})
}
