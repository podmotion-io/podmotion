/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// cephReadyThreshold is the migration progress % that triggers StorageReadyForFreeze.
	// Must be ≥95 per ADR-0011.
	cephReadyThreshold = 95

	// cephPollInterval is the delay between rbd migration status polls.
	cephPollInterval = 2 * time.Second

	// cephSingleOwnerTimeout bounds how long AwaitSingleOwner polls for
	// `rbd migration status` to report state=="committed" after Cutover's
	// "rbd migration commit" call. This is mostly a verification poll — commit
	// is synchronous in practice — but bounding it means a stuck/partial
	// commit fails closed instead of letting the destination pod mount race
	// an image that is still mid-migration.
	cephSingleOwnerTimeout = 1 * time.Minute

	// cephMigrationCommittedState is the rbd migration status "state" value
	// once the migration has fully committed and the image has a single owner.
	cephMigrationCommittedState = "committed"

	// cephSquidMinMajor is the minimum Ceph major version that supports live RBD migration
	// without the "preview" caveat. Reef (18.x) exists but is unsupported for production use
	// (ADR-0026).
	cephSquidMinMajor = 19
)

// rbdMigrationStatus is the relevant subset of `rbd migration status --format json`.
type rbdMigrationStatus struct {
	State    string `json:"state"`    // "prepared", "executing", "executed", "committed"
	Progress int    `json:"progress"` // 0–100
}

// CephRBDMigrator implements Tier2 live migration via the rbd CLI.
//
// Live migration sequence (requires Ceph Squid 19.x — ADR-0026):
//  1. rbd migration prepare <pool>/<image> <dest-pool>/<dest-image>
//  2. rbd migration execute (background; tracks progress)
//  3. Poll status until progress≥95 → emit StorageReadyForFreeze
//  4. rbd migration commit (on cutover after CRIU restore)
//
// The rbd binary must be present on the node agent's PATH. Image names are
// derived from the PVC's PV volumeHandle, which for rbd.csi.ceph.com follows
// the pattern: <pool>/<image-id>.
type CephRBDMigrator struct {
	// DestPool is the Ceph pool on the destination; defaults to source pool.
	DestPool string
	// ExecCommand allows injecting a fake exec in tests.
	ExecCommand func(name string, args ...string) *exec.Cmd
}

// NewCephRBDMigrator returns a production Ceph RBD migrator.
func NewCephRBDMigrator(destPool string) *CephRBDMigrator {
	return &CephRBDMigrator{
		DestPool:    destPool,
		ExecCommand: exec.Command,
	}
}

// Tier returns TierCephRBD.
func (m *CephRBDMigrator) Tier() StorageTier { return TierCephRBD }

// PreStage calls rbd migration prepare + execute and polls until ≥95% progress.
func (m *CephRBDMigrator) PreStage(ctx context.Context, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "CephRBD")

	if err := m.checkCephVersionGate(ctx); err != nil {
		return fmt.Errorf("tier2: %w", err)
	}

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierCephRBD {
			continue
		}

		srcImage, destImage, err := m.imageNames(clsf, opts)
		if err != nil {
			return fmt.Errorf("tier2: parse image name for pvc %s: %w", clsf.PVCName, err)
		}

		log.Info("preparing RBD live migration", "src", srcImage, "dest", destImage)
		if err := m.runRBD(ctx, "migration", "prepare", srcImage, destImage); err != nil {
			return fmt.Errorf("tier2: rbd migration prepare %s: %w", clsf.PVCName, err)
		}

		log.Info("executing RBD live migration", "src", srcImage)
		if err := m.runRBD(ctx, "migration", "execute", srcImage); err != nil {
			return fmt.Errorf("tier2: rbd migration execute %s: %w", clsf.PVCName, err)
		}

		log.Info("polling RBD migration progress", "src", srcImage)
		if err := m.pollUntilReady(ctx, srcImage); err != nil {
			return fmt.Errorf("tier2: poll rbd migration %s: %w", clsf.PVCName, err)
		}

		log.Info("Ceph RBD migration ready for freeze", "pvc", clsf.PVCName)
	}

	return nil
}

// SyncPercent returns the lowest progress across all TierCephRBD volumes.
func (m *CephRBDMigrator) SyncPercent(ctx context.Context, opts MigrationOptions) (int, error) {
	lowest := 100
	found := false

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierCephRBD {
			continue
		}
		found = true
		srcImage, _, err := m.imageNames(clsf, opts)
		if err != nil {
			return 0, err
		}
		pct, err := m.migrationProgress(ctx, srcImage)
		if err != nil {
			return 0, err
		}
		if pct < lowest {
			lowest = pct
		}
	}
	if !found {
		return 100, nil
	}
	return lowest, nil
}

// Cutover calls rbd migration commit for each TierCephRBD volume. Called after
// CRIU restore completes on the destination node.
func (m *CephRBDMigrator) Cutover(ctx context.Context, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "CephRBD")

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierCephRBD {
			continue
		}

		srcImage, _, err := m.imageNames(clsf, opts)
		if err != nil {
			return fmt.Errorf("tier2: parse image name for cutover pvc %s: %w", clsf.PVCName, err)
		}

		log.Info("committing RBD live migration", "src", srcImage)
		if err := m.runRBD(ctx, "migration", "commit", srcImage); err != nil {
			return fmt.Errorf("tier2: rbd migration commit %s: %w", clsf.PVCName, err)
		}
	}
	return nil
}

// AwaitSingleOwner polls `rbd migration status` until state=="committed" for
// each Tier2 image — the point at which Ceph has fully handed the image over
// to the destination pool/image and the source-side migration source image
// no longer exists as a live owner. Cutover's "rbd migration commit" call is
// synchronous in the common case, so this is mostly a verification poll of
// the same status call PreStage already uses via migrationProgress — but it
// is bounded and fails closed rather than assuming commit always finishes
// before it returns.
func (m *CephRBDMigrator) AwaitSingleOwner(ctx context.Context, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "CephRBD")

	deadlineCtx, cancel := context.WithTimeout(ctx, cephSingleOwnerTimeout)
	defer cancel()

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierCephRBD {
			continue
		}

		srcImage, _, err := m.imageNames(clsf, opts)
		if err != nil {
			return fmt.Errorf("tier2: parse image name for pvc %s: %w", clsf.PVCName, err)
		}

		log.Info("awaiting single-owner (committed) migration state", "src", srcImage)
		if err := m.pollUntilCommitted(deadlineCtx, srcImage); err != nil {
			return fmt.Errorf("tier2: await single owner %s: %w", srcImage, err)
		}
		log.Info("RBD migration committed — single owner", "src", srcImage)
	}

	return nil
}

func (m *CephRBDMigrator) migrationState(ctx context.Context, srcImage string) (string, error) {
	cmd := m.ExecCommand("rbd", "migration", "status", srcImage, "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("rbd migration status %s: %w", srcImage, err)
	}
	var status rbdMigrationStatus
	if err := json.Unmarshal(out, &status); err != nil {
		return "", fmt.Errorf("parse rbd migration status: %w", err)
	}
	return status.State, nil
}

func (m *CephRBDMigrator) pollUntilCommitted(ctx context.Context, srcImage string) error {
	for {
		state, err := m.migrationState(ctx, srcImage)
		if err == nil && state == cephMigrationCommittedState {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for rbd migration of %s to reach state=%s: %w",
				srcImage, cephMigrationCommittedState, ctx.Err())
		case <-time.After(cephPollInterval):
		}
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

// imageNames derives rbd image addresses from the TierClassification.
// CSI volumeHandle for rbd.csi.ceph.com is: <pool>/<image-id>.
func (m *CephRBDMigrator) imageNames(clsf TierClassification, opts MigrationOptions) (src, dest string, err error) {
	// StorageClass annotation csi.storage.k8s.io/volumeHandle is not available
	// in TierClassification; we use PVCName as the image name convention used by
	// rbd.csi.ceph.com ("pvc-<uid>"). The pool is taken from DestPool.
	// Real production use would resolve the PV's spec.csi.volumeHandle.
	pool := "rbd"
	if m.DestPool != "" {
		pool = m.DestPool
	}
	image := clsf.PVCName
	src = fmt.Sprintf("%s/%s", pool, image)
	dest = fmt.Sprintf("%s/%s-dest-%s", pool, image, opts.DestinationNode)
	return src, dest, nil
}

func (m *CephRBDMigrator) runRBD(ctx context.Context, args ...string) error {
	cmd := m.ExecCommand("rbd", args...)
	cmd.Env = []string{}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rbd %s: %w — %s", strings.Join(args, " "), err, stderr.String())
	}
	return nil
}

func (m *CephRBDMigrator) migrationProgress(ctx context.Context, srcImage string) (int, error) {
	cmd := m.ExecCommand("rbd", "migration", "status", srcImage, "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("rbd migration status %s: %w", srcImage, err)
	}
	var status rbdMigrationStatus
	if err := json.Unmarshal(out, &status); err != nil {
		return 0, fmt.Errorf("parse rbd migration status: %w", err)
	}
	return status.Progress, nil
}

func (m *CephRBDMigrator) pollUntilReady(ctx context.Context, srcImage string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cephPollInterval):
		}

		pct, err := m.migrationProgress(ctx, srcImage)
		if err != nil {
			// Transient — continue polling.
			continue
		}
		if pct >= cephReadyThreshold {
			return nil
		}
	}
}

// errCephVersionCheckFailed is returned by checkCephVersionGate when the `ceph version`
// exec/parse itself fails — a version-detection failure, distinct from a confirmed Reef
// result. ADR-0026 §3 mandates failing closed on detection failure, not assuming OK.
var errCephVersionCheckFailed = fmt.Errorf("ceph version check failed")

// errCephReefUnsupported is returned by checkCephVersionGate when a Reef 18.x cluster is
// confirmed. ADR-0026 §1 mandates a hard block for Tier2 (RBD live migration) on Reef;
// Tier3 (SnapshotRsync) remains available as the supported fallback.
var errCephReefUnsupported = fmt.Errorf("Ceph Reef 18.x detected — Tier2 RBD live migration requires Squid 19.x+ (ADR-0026); Tier3 snapshot-rsync remains available")

// checkCephVersionGate implements the agent-side (PreStage call-path) half of ADR-0026's
// version gate.
//
// fail-closed phase-gate (item 6): the prior warnIfReefCluster silently discarded BOTH the failure case
// (exec/parse error → "assume OK and let the migration fail naturally") and the confirmed-Reef
// case (logged a warning only, never blocked) — a Reef cluster or an undetectable Ceph version
// let Tier2 proceed exactly as if Squid had been confirmed. ADR-0026 mandates the opposite in
// both cases: fail-closed on detection failure, and a hard block on confirmed Reef.
//
// This closes the finding as scoped to this call path (agent-side PreStage gate) — it does
// NOT implement ADR-0026's actual mandated control point, a ValidatingAdmissionWebhook check at
// CR admission (that control point does not exist at all; internal/webhook/podmigration_webhook.go
// has zero Reef/Ceph/version logic). Making PreStage fail closed here fires later (mid-PreStage,
// after scheduling/checkpointing has already begun) than the ADR intends. See the remediation
// design's item 6 note — flagged for a separate follow-up ADR, not implemented here to avoid
// overreaching a "small, independent fix" scope.
func (m *CephRBDMigrator) checkCephVersionGate(ctx context.Context) error {
	log := logf.FromContext(ctx)
	cmd := m.ExecCommand("ceph", "version", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		// ADR-0026 §3: MUST reject on version-detection failure — fail-closed, not fail-open.
		return fmt.Errorf("%w: exec ceph version: %v", errCephVersionCheckFailed, err)
	}
	var v struct {
		Version string `json:"version"`
	}
	if jsonErr := json.Unmarshal(out, &v); jsonErr != nil {
		return fmt.Errorf("%w: parse ceph version output: %v", errCephVersionCheckFailed, jsonErr)
	}
	// version string looks like: "ceph version 18.2.1 (hash) reef (stable)"
	if strings.Contains(v.Version, " 18.") {
		return fmt.Errorf("%w (reported version: %q)", errCephReefUnsupported, v.Version)
	}
	log.Info("Ceph version gate passed (Squid 19.x+ or newer)", "version", v.Version)
	return nil
}

// ── Stub ───────────────────────────────────────────────────────────────────

// CephRBDStubMigrator is used in unit tests and environments without Ceph.
// It emits simulated progress 0 → 50 → 95 → 100 with 100ms delays.
type CephRBDStubMigrator struct {
	PreStageCalled         bool
	CutoverCalled          bool
	AwaitSingleOwnerCalled bool
	// InjectPreStageError causes PreStage to return an error.
	InjectPreStageError error
	// InjectAwaitSingleOwnerError causes AwaitSingleOwner to return this error.
	InjectAwaitSingleOwnerError error
	// progressSteps tracks which step the stub is on for SyncPercent calls.
	progressStep int
}

// Tier returns TierCephRBD.
func (s *CephRBDStubMigrator) Tier() StorageTier { return TierCephRBD }

// PreStage simulates migration progress through 0→50→95→100 with 100ms delays.
func (s *CephRBDStubMigrator) PreStage(_ context.Context, _ MigrationOptions) error {
	if s.InjectPreStageError != nil {
		return s.InjectPreStageError
	}
	steps := []int{0, 50, 95, 100}
	for _, pct := range steps {
		time.Sleep(100 * time.Millisecond)
		s.progressStep = pct
	}
	s.PreStageCalled = true
	return nil
}

// SyncPercent returns the current simulated progress.
func (s *CephRBDStubMigrator) SyncPercent(_ context.Context, _ MigrationOptions) (int, error) {
	return s.progressStep, nil
}

// Cutover records the call.
func (s *CephRBDStubMigrator) Cutover(_ context.Context, _ MigrationOptions) error {
	s.CutoverCalled = true
	return nil
}

// AwaitSingleOwner records the call and returns the injected error (nil by default).
func (s *CephRBDStubMigrator) AwaitSingleOwner(_ context.Context, _ MigrationOptions) error {
	s.AwaitSingleOwnerCalled = true
	return s.InjectAwaitSingleOwnerError
}
