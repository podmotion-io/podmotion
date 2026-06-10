/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package estimation implements the dry-run estimation pipeline (M2).
//
// Estimation samples the pod's dirty page write rate without performing a full
// checkpoint. The result surfaces as PodMigrationStatus.DryRunEstimate and answers:
//
//   - Is this pod migratable at all (Tier 4 storage, unsupported mode)?
//   - What storage tier will be used?
//   - What is the predicted freeze duration given the observed dirty rate?
//   - How long will the total migration take?
//
// The estimator talks to the node agent gRPC server (Agent 1) which performs a
// single short pre-dump round (CRIU --track-mem only, no image written to disk)
// and reports dirty_pages_mb and elapsed_ms. From those two numbers the estimator
// predicts convergence behaviour and minimum achievable freeze duration.
//
// In M2 the gRPC call is stubbed — the Estimator interface is live and wired into
// the controller; the real gRPC implementation lands in M4 when the agent gRPC
// server is built (Agent 7).
package estimation

import (
	"context"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// Estimator estimates migration feasibility and duration without touching the pod.
type Estimator interface {
	Estimate(ctx context.Context, pod *corev1.Pod, nmc *pmv1.NodeMigrationCapacity, spec pmv1.PodMigrationSpec) (*pmv1.DryRunEstimate, error)
}

// Probe carries the raw measurement from a single short pre-dump round.
type Probe struct {
	// DirtyPagesMB is the number of dirty pages measured during the sample window.
	DirtyPagesMB float64
	// ElapsedMs is the wall-clock time of the sample window.
	ElapsedMs int64
	// RSSMb is the total resident set size of the pod's containers.
	RSSMb float64
}

// DefaultEstimator is the production estimator.
// In M2 it uses a StaticProber for unit testing; the real gRPC prober lands in M4.
type DefaultEstimator struct {
	Prober Prober
}

// Prober abstracts the single pre-dump round.
// The stub implementation returns a synthetic probe; the real implementation
// calls the node agent gRPC EstimateCheckpoint RPC.
type Prober interface {
	Probe(ctx context.Context, pod *corev1.Pod, nodeAgentAddr string) (Probe, error)
}

// Estimate implements Estimator.
func (e *DefaultEstimator) Estimate(
	ctx context.Context,
	pod *corev1.Pod,
	nmc *pmv1.NodeMigrationCapacity,
	spec pmv1.PodMigrationSpec,
) (*pmv1.DryRunEstimate, error) {
	est := &pmv1.DryRunEstimate{}

	// Determine storage tier.
	tier, tierReason := classifyStorageTier(pod, nmc)
	est.StorageTier = tier

	// Tier 4 = not migratable by default.
	if tier == 4 && spec.StorageStrategy != pmv1.StorageStrategySkip {
		est.Migratable = false
		est.BlockingReason = fmt.Sprintf("Tier 4 storage: %s", tierReason)
		return est, nil
	}

	// PostCopy requires userfaultfd.
	if spec.Mode == pmv1.MigrationModePostCopy && !nmc.Spec.KernelFeatures.Userfaultfd {
		est.Migratable = false
		est.BlockingReason = "PostCopy mode requires CONFIG_USERFAULTFD on source node"
		return est, nil
	}

	// Probe dirty page rate (stub in M2; real gRPC call in M4).
	nodeAgentAddr := fmt.Sprintf("%s:9090", nmc.Spec.NodeName)
	probe, err := e.Prober.Probe(ctx, pod, nodeAgentAddr)
	if err != nil {
		return nil, fmt.Errorf("dirty page probe failed: %w", err)
	}

	// Compute predicted freeze duration.
	// Model: freeze_ms ≈ dirty_pages_mb / bandwidth_mbps * 1000
	// where bandwidth_mbps is capped by spec.BandwidthLimitMbps (0 = estimate from NMC).
	bandwidth := estimateBandwidthMbps(spec, nmc)
	dirtyRateMBps := 0.0
	if probe.ElapsedMs > 0 {
		dirtyRateMBps = probe.DirtyPagesMB / (float64(probe.ElapsedMs) / 1000.0)
	}

	// After N pre-copy rounds converging at typical 50% reduction per round,
	// predict the dirty MB at final freeze.
	rounds := int(spec.PreCopyMaxRounds)
	if rounds <= 0 {
		rounds = 5
	}
	thresholdMB := float64(spec.PreCopyDirtyThresholdMB)
	if thresholdMB <= 0 {
		thresholdMB = 64
	}
	predictedFinalDirtyMB := convergencePredict(probe.DirtyPagesMB, rounds, thresholdMB)
	freezeMs := int64(0)
	if bandwidth > 0 {
		freezeMs = int64((predictedFinalDirtyMB / bandwidth) * 1000)
	}

	est.EstimatedFreezeDurationMs = freezeMs
	est.DirtyPageRateMBps = strconv.FormatFloat(dirtyRateMBps, 'f', 2, 64)
	est.Migratable = true

	// Warn if predicted freeze exceeds 500ms (the practical human-perceivable threshold).
	if freezeMs > 500 {
		est.BlockingReason = fmt.Sprintf(
			"predicted freeze window %dms exceeds 500ms; consider reducing write load or increasing pre-copy rounds",
			freezeMs)
	}

	return est, nil
}

// convergencePredict estimates dirty MB after maxRounds of pre-copy assuming
// a 50% reduction per round (conservative model). Stops when below threshold.
func convergencePredict(initialDirtyMB float64, maxRounds int, thresholdMB float64) float64 {
	dirty := initialDirtyMB
	for i := 0; i < maxRounds; i++ {
		dirty *= 0.5
		if dirty <= thresholdMB {
			return dirty
		}
	}
	return dirty
}

// classifyStorageTier returns the detected storage tier (0-4) and a human-readable reason.
// Tier 0: RWX (NFS, CephFS) — re-attach, no data movement
// Tier 1: Longhorn — dual-engine live migration
// Tier 2: Ceph RBD — rbd live migration
// Tier 3: local/EBS — snapshot+rsync
// Tier 4: hostPath, memory emptyDir — blocked
func classifyStorageTier(pod *corev1.Pod, nmc *pmv1.NodeMigrationCapacity) (int32, string) {
	for _, vol := range pod.Spec.Volumes {
		if vol.HostPath != nil {
			return 4, fmt.Sprintf("hostPath volume %q", vol.Name)
		}
		if vol.EmptyDir != nil && vol.EmptyDir.Medium == corev1.StorageMediumMemory {
			return 4, fmt.Sprintf("memory-backed emptyDir volume %q", vol.Name)
		}
	}
	// No PVCs = stateless pod. Storage tier is moot; use 0.
	if !hasPVC(pod) {
		return 0, "no PVC volumes"
	}
	if nmc.Spec.StorageCapability.LonghornAvailable {
		return 1, "Longhorn dual-engine"
	}
	if nmc.Spec.StorageCapability.CephRBDAvailable {
		return 2, "Ceph RBD live migration"
	}
	if nmc.Spec.StorageCapability.LocalPVMigratable {
		return 3, "snapshot+rsync"
	}
	return 3, "local PV (rsync fallback)"
}

func hasPVC(pod *corev1.Pod) bool {
	for _, vol := range pod.Spec.Volumes {
		if vol.PersistentVolumeClaim != nil {
			return true
		}
	}
	return false
}

func estimateBandwidthMbps(spec pmv1.PodMigrationSpec, _ *pmv1.NodeMigrationCapacity) float64 {
	if spec.BandwidthLimitMbps > 0 {
		return float64(spec.BandwidthLimitMbps)
	}
	// Default assumption: 1Gbps intra-cluster link, estimate effective at 800Mbps = 100MB/s.
	return 800
}

// StubProber returns a synthetic probe for testing and M2 wiring.
// Replace with gRPC prober in M4.
type StubProber struct {
	DirtyMB float64
	ElapseMs int64
}

func (s *StubProber) Probe(_ context.Context, _ *corev1.Pod, _ string) (Probe, error) {
	mb := s.DirtyMB
	if mb == 0 {
		mb = 128 // 128MB default synthetic dirty set
	}
	ms := s.ElapseMs
	if ms == 0 {
		ms = 1000
	}
	return Probe{DirtyPagesMB: mb, ElapsedMs: ms, RSSMb: mb * 4}, nil
}
