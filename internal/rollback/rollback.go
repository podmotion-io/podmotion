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
	"errors"
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
		// ADR-0368 CONDITION 4 (§9 runtime-dependency audit finding): this outer combine used to
		// interpolate errs with %v, which does NOT preserve errors.Is-traversal through the
		// combined error — errors.Join wraps the []error slice with an Unwrap() []error method
		// that errors.Is/As correctly walks, and %w threads that joined error through this
		// message's own wrapping so both the message AND errors.Is(returnedErr,
		// storage.ErrRollbackPointOfNoReturn/ErrRollbackNotImplemented) work. Without this fix the
		// controller-side errors.Is check this whole ADR depends on (reconcileRollingBack) is dead
		// code — it would never match, because the sentinel was wrapped one layer per-step
		// (fmt.Errorf("%s: %w", ...) above) but then flattened to a plain string by %v here.
		return fmt.Errorf("rollback partial failure (%d/%d steps failed): %w", len(errs), len(steps), errors.Join(errs...))
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
	// rather than failing. CORRECTED (ADR-0248): there is NO freeze-deadline watchdog
	// that thaws the source. With a nil client the live (non-restart) rollback path
	// CANNOT thaw the frozen source. The only two real thaw triggers are (1) an Abort
	// RPC reaching thawFrozenSource (internal/agent/server/server.go), and (2) the
	// source agent process restarting and running ReconcileOrphanedFrozenSources
	// (cmd/agent/main.go) at startup. Until a real client is wired here, a mid-checkpoint
	// abort leaves the source frozen until an agent restart happens to occur.
	SourceAgentClient interface {
		Abort(ctx context.Context, migrationName, reason string) error
	}
}

func (s *StubComputeRollback) Name() string { return "ComputeRollback" }
func (s *StubComputeRollback) Execute(ctx context.Context, pm *pmv1.PodMigration) error {
	log := ctrl.LoggerFrom(ctx)
	if s.SourceAgentClient == nil {
		// No agent client wired (M2/M3 stub mode). CORRECTED (ADR-0248): there is no
		// watchdog that will thaw this source. The live rollback path is a no-op here;
		// the frozen source PID stays SIGSTOP'd until either an operator/chaos Abort RPC
		// reaches thawFrozenSource, or the source agent process restarts and
		// ReconcileOrphanedFrozenSources runs at startup. Log clearly so operators do not
		// assume automatic recovery is coming.
		log.Info("ComputeRollback: source agent client not wired — frozen source will NOT be thawed on this path; requires an Abort RPC or a source-agent restart",
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

// StubStorageRollback is the pre-ADR-0368 no-op storage rollback step. RETAINED only for any
// caller that genuinely wants a no-storage-managed rollback pipeline (e.g. a unit test with no
// StorageMgr at all); NewStubRollbacker no longer uses it — see RealStorageRollback below.
// Deliberately NOT the default anymore: this type unconditionally returning nil regardless of
// whether a destination-side reservation actually needs releasing is exactly the "fabricated
// success" failure mode ADR-0368 exists to close (see that ADR's §1 for the live outage this
// caused). Do not wire this into the production rollback pipeline.
type StubStorageRollback struct{}

func (s *StubStorageRollback) Name() string { return "StorageRollback" }
func (s *StubStorageRollback) Execute(ctx context.Context, pm *pmv1.PodMigration) error {
	ctrl.LoggerFrom(ctx).Info("stub: storage rollback — no-op (StubStorageRollback, not wired by NewRollbacker)", "migration", pm.Name)
	return nil
}

// StorageDestinationReleaser is the interface RealStorageRollback dispatches through —
// implemented by *storage.StorageMigrationManager
// (internal/agent/storage/manager.go's ReleaseDestination method). Declared narrowly here,
// rather than depending on the concrete StorageMigrationManager type (and its client.Client/
// Classifier dependencies) directly in this package, so rollback_test.go can inject a minimal
// fake — while cmd/main.go still passes the SAME *storage.StorageMigrationManager instance the
// forward storage-cutover pipeline (the controller's StorageMgr field) already holds
// (ADR-0368 §5.3/CONDITION 5), guaranteeing Cutover's attach and rollback's ReleaseDestination
// dispatch through the identical, already-configured Migrator instances — never a second,
// independently constructed manager that only happens to be configured the same way today.
type StorageDestinationReleaser interface {
	ReleaseDestination(ctx context.Context, pm *pmv1.PodMigration) error
}

// RealStorageRollback replaces StubStorageRollback as the production StorageStep (ADR-0368): it
// dispatches to the SAME StorageMigrationManager/Migrator instances the forward storage-cutover
// pipeline already used for this migration, undoing whatever destination-side reservation
// Cutover created via Migrator.ReleaseDestination. A non-nil error here — including the two
// sentinel errors, storage.ErrRollbackPointOfNoReturn/storage.ErrRollbackNotImplemented —
// propagates through DefaultRollbacker.Rollback's now-%w-wrapped combine (CONDITION 4) to
// reconcileRollingBack, which errors.Is-checks for them and sets a distinct, human-actionable
// condition (ADR-0368 §6 item 3). This step itself does no condition-setting; it only reports
// StorageMgr's verdict, exactly as StubComputeRollback/StubNetworkRollback report theirs.
type RealStorageRollback struct {
	// StorageMgr is the shared StorageMigrationManager instance — see StorageDestinationReleaser's
	// doc comment for why it MUST be the same instance the forward pipeline uses, not a second one.
	StorageMgr StorageDestinationReleaser
}

func (s *RealStorageRollback) Name() string { return "StorageRollback" }
func (s *RealStorageRollback) Execute(ctx context.Context, pm *pmv1.PodMigration) error {
	if s.StorageMgr == nil {
		// Fail loud, never silently no-op: an un-wired StorageMgr is a real configuration gap,
		// not "nothing needed releasing." A fail-open fallback here is exactly the class of bug
		// the zero-tech-debt pillar prohibits and this ADR exists to close.
		ctrl.LoggerFrom(ctx).Error(nil, "RealStorageRollback: no StorageMgr wired — cannot attempt to release destination storage", "migration", pm.Name)
		return fmt.Errorf("storage rollback: no StorageMgr wired for migration %s", pm.Name)
	}
	return s.StorageMgr.ReleaseDestination(ctx, pm)
}

// NewStubRollbacker returns a DefaultRollbacker wired with the NetworkStep/ComputeStep stubs
// unchanged, and StubStorageRollback (the pre-ADR-0368 no-op) for StorageStep. RETAINED for any
// caller that explicitly wants no storage-rollback behavior (e.g. isolating a Network/Compute-only
// test) — production wiring (cmd/main.go) uses NewRollbacker instead. sourceAgentClient may be nil
// in stub/test mode. CORRECTED (ADR-0248): passing nil here means the live rollback path CANNOT
// thaw a frozen source — there is no watchdog. Thaw only happens via an Abort RPC
// (thawFrozenSource) or a source-agent restart (ReconcileOrphanedFrozenSources). Wire a real
// Abort-capable client per ADR-0248 D2.
func NewStubRollbacker(sourceAgentClient interface {
	Abort(ctx context.Context, migrationName, reason string) error
}) *DefaultRollbacker {
	return &DefaultRollbacker{
		NetworkStep: &StubNetworkRollback{},
		ComputeStep: &StubComputeRollback{SourceAgentClient: sourceAgentClient},
		StorageStep: &StubStorageRollback{},
	}
}

// NewRollbacker returns a DefaultRollbacker wired with the real storage-undo step
// (RealStorageRollback) in place of NewStubRollbacker's StubStorageRollback no-op (ADR-0368).
// sourceAgentClient may be nil in stub/test mode (see StubComputeRollback's doc comment —
// ADR-0248 D2 remains open, unaffected by this ADR). storageMgr MUST be the SAME
// *storage.StorageMigrationManager instance the caller's forward storage-cutover pipeline (the
// controller's StorageMgr field) already holds — see StorageDestinationReleaser's doc comment
// for why passing a second, independently constructed manager would defeat the whole point.
func NewRollbacker(sourceAgentClient interface {
	Abort(ctx context.Context, migrationName, reason string) error
}, storageMgr StorageDestinationReleaser) *DefaultRollbacker {
	return &DefaultRollbacker{
		NetworkStep: &StubNetworkRollback{},
		ComputeStep: &StubComputeRollback{SourceAgentClient: sourceAgentClient},
		StorageStep: &RealStorageRollback{StorageMgr: storageMgr},
	}
}
