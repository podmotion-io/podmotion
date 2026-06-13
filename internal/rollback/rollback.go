/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package rollback implements the migration rollback pipeline (M2).
//
// Rollback order is immutable (ADR-0014): Network → Compute → Storage.
// Each step is idempotent — if the controller restarts mid-rollback, re-running
// from the top is safe.
//
// The source pod is NEVER deleted until TrafficVerified=true (ADR-0012). The
// rollback path is therefore: the source pod is still alive (just frozen if
// Checkpointing phase was reached). Rollback unfreezes it by restoring it in
// place via the CRIU restore primitive on the source node.
//
// In M2 the gRPC calls are stubbed. Real agent calls land in M4/M5.
package rollback

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// Rollbacker executes the rollback pipeline for a failed migration.
type Rollbacker interface {
	Rollback(ctx context.Context, pm *pmv1.PodMigration) error
}

// Step is a single rollback step with an idempotent Execute method.
type Step interface {
	Name() string
	Execute(ctx context.Context, pm *pmv1.PodMigration) error
}

// DefaultRollbacker runs the three-step pipeline in fixed order: Network → Compute → Storage.
type DefaultRollbacker struct {
	NetworkStep Step
	ComputeStep Step
	StorageStep Step
}

// Rollback implements Rollbacker.
// Each step is attempted; failures are collected and returned as a combined error.
// On partial failure the operator surfaces the error so humans can intervene —
// automated retry is handled by the reconcile loop requeueing RollingBack phase.
func (r *DefaultRollbacker) Rollback(ctx context.Context, pm *pmv1.PodMigration) error {
	log := logf.FromContext(ctx).WithValues("migration", fmt.Sprintf("%s/%s", pm.Namespace, pm.Name))

	steps := []Step{r.NetworkStep, r.ComputeStep, r.StorageStep}
	var errs []error

	for _, step := range steps {
		log.Info("rollback step", "step", step.Name())
		if err := step.Execute(ctx, pm); err != nil {
			log.Error(err, "rollback step failed", "step", step.Name())
			errs = append(errs, fmt.Errorf("%s: %w", step.Name(), err))
			// Continue — attempt remaining steps even after partial failure.
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("rollback partial failure (%d/%d steps failed): %v", len(errs), len(steps), errs)
	}
	return nil
}

// ── Stub steps for M2 ──────────────────────────────────────────────────────

// StubNetworkRollback tears down the eBPF bridge and re-establishes source routing.
// Real implementation: Agent 2 gRPC call to disarm bridge, restore source IP routes.
type StubNetworkRollback struct{}

func (s *StubNetworkRollback) Name() string { return "NetworkRollback" }
func (s *StubNetworkRollback) Execute(ctx context.Context, pm *pmv1.PodMigration) error {
	ctrl.LoggerFrom(ctx).Info("stub: network rollback — no-op in M2", "migration", pm.Name)
	return nil
}

// StubComputeRollback unfreezes the source pod via the source agent's Abort RPC.
//
// The source agent's Abort handler calls thawFrozenSource, which sends SIGCONT to
// the PID registered via registerFrozenSource when LeaveStopped=true was used.
// If no frozen source PID is recorded (e.g. failure before the dump, or already thawed),
// the Abort call is idempotent and harmless.
//
// TODO(M24+): Replace with a direct ThawSource gRPC RPC on the source agent to avoid
// coupling rollback semantics to the Abort path. Add the ThawSource proto RPC, implement
// it as a targeted SIGCONT-only call, and wire it here with a real agent client.
type StubComputeRollback struct {
	// SourceAgentClient is the gRPC client for the source node agent.
	// When nil (pre-M4 stubs / unit tests), the rollback logs a warning and returns nil
	// rather than failing — the frozen-source watchdog on the agent will recover after
	// the freeze-deadline fires.
	SourceAgentClient interface {
		Abort(ctx context.Context, migrationName, reason string) error
	}
}

func (s *StubComputeRollback) Name() string { return "ComputeRollback" }
func (s *StubComputeRollback) Execute(ctx context.Context, pm *pmv1.PodMigration) error {
	log := ctrl.LoggerFrom(ctx)
	if s.SourceAgentClient == nil {
		// No agent client wired (M2/M3 stub mode). The source agent's frozen-source
		// watchdog will SIGCONT the source after the freeze deadline. Log clearly so
		// operators know the thaw path depends on the watchdog.
		log.Info("ComputeRollback: source agent client not wired — frozen source will be thawed by agent watchdog",
			"migration", pm.Name)
		return nil
	}
	if err := s.SourceAgentClient.Abort(ctx, pm.Name, "rollback: ComputeRollback"); err != nil {
		return fmt.Errorf("ComputeRollback: Abort RPC to source agent failed: %w", err)
	}
	log.Info("ComputeRollback: Abort RPC sent to source agent — frozen source PID thawed",
		"migration", pm.Name)
	return nil
}

// StubStorageRollback releases the destination volume reservation and tears down
// any pre-staged storage. For Longhorn: cancel dual-engine migration. For Ceph RBD:
// abort the rbd migration. For snapshot+rsync: delete the destination PVC clone.
type StubStorageRollback struct{}

func (s *StubStorageRollback) Name() string { return "StorageRollback" }
func (s *StubStorageRollback) Execute(ctx context.Context, pm *pmv1.PodMigration) error {
	ctrl.LoggerFrom(ctx).Info("stub: storage rollback — no-op in M2", "migration", pm.Name)
	return nil
}

// NewStubRollbacker returns a DefaultRollbacker wired with all stub steps.
// Used in cmd/main.go for M2; swap individual steps for real implementations as agents land.
// sourceAgentClient may be nil in stub/test mode — the frozen-source watchdog on the agent
// handles thawing when no client is wired.
func NewStubRollbacker(sourceAgentClient interface {
	Abort(ctx context.Context, migrationName, reason string) error
}) *DefaultRollbacker {
	return &DefaultRollbacker{
		NetworkStep: &StubNetworkRollback{},
		ComputeStep: &StubComputeRollback{SourceAgentClient: sourceAgentClient},
		StorageStep: &StubStorageRollback{},
	}
}
