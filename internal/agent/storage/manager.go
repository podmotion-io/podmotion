/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

const conditionStorageReadyForFreeze = "StorageReadyForFreeze"

const (
	// preStageMaxAttempts bounds the retry on a transient PreStage failure
	// (e.g. the Longhorn Manager DNS name not yet resolvable right after a
	// fresh agent pod restart). Bounded and small on purpose — this must not
	// become an unbounded/exponential retry that eats the whole migration's
	// completion budget.
	preStageMaxAttempts = 3
	// preStageRetryBackoff is a fixed short delay between PreStage retry
	// attempts (not exponential-to-infinity).
	preStageRetryBackoff = 3 * time.Second
)

// isTransientPreStageError reports whether err is a network/timeout-class
// error worth a bounded retry — DNS not yet converged, connection refused
// right after a fresh pod restart, dial/read timeouts — as opposed to a
// permanent error (e.g. a real "volume not found" 404 from the Longhorn
// Manager API). Retrying a permanent error only wastes the migration's
// completion budget, so those must fail fast instead.
func isTransientPreStageError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// MigrationOptions carries context required by tier migrators.
type MigrationOptions struct {
	// MigrationName is the name of the PodMigration CR (for logging/patching).
	MigrationName string
	// PodNamespace is the namespace of the source pod.
	PodNamespace string
	// SourceNode is the node the pod is migrating from.
	SourceNode string
	// DestinationNode is the node the pod is migrating to.
	DestinationNode string
	// Classifications is the list of per-PVC tier decisions from StorageClassifier.
	Classifications []TierClassification
}

// Migrator is the interface implemented by each storage tier handler.
type Migrator interface {
	// Tier returns the storage tier this migrator handles.
	Tier() StorageTier
	// PreStage prepares storage on the destination before the compute freeze.
	// For Tier0 this is a no-op verification; for Tier1 it starts replica sync.
	PreStage(ctx context.Context, opts MigrationOptions) error
	// SyncPercent returns the current synchronisation progress (0–100).
	// Returns 100 for tiers with no sync phase (Tier0).
	SyncPercent(ctx context.Context, opts MigrationOptions) (int, error)
	// Cutover detaches from the source and attaches to the destination.
	// Called after CRIU restore completes on the destination node.
	Cutover(ctx context.Context, opts MigrationOptions) error
	// AwaitSingleOwner blocks until every classified volume for this tier is
	// in a single-owner, mountable state on the destination node. Called by
	// the controller after Cutover succeeds and before the destination pod's
	// volume mounts are allowed to proceed.
	//
	// Must return promptly (bounded internal poll) rather than blocking
	// forever; a timeout is a real error, not a wait condition. Each tier
	// implements this using its own backend-specific readiness signal (e.g.
	// Longhorn's replica list collapsing to a single RW replica on the
	// destination node) — never a generic string match on a driver error.
	// Tiers with no shared-attachment/dual-owner concept (RWX, snapshot-rsync)
	// return nil immediately.
	AwaitSingleOwner(ctx context.Context, opts MigrationOptions) error
}

// StorageMigrationManager selects the appropriate Migrator based on the tier
// classification, runs PreStage concurrently with the pre-copy loop, and patches
// StorageReadyForFreeze on the PodMigration CR once the 95% sync threshold is met.
//
// The manager is called from the PodMigration controller PreMigrating phase alongside
// the ReplicationManager; both goroutines run concurrently (ADR-0011).
type StorageMigrationManager struct {
	Client     client.Client
	Classifier *StorageClassifier
	// Migrators maps StorageTier → Migrator. Populated by wire code in cmd/operator.
	// Tests inject stubs here.
	Migrators map[StorageTier]Migrator
}

// NewStorageMigrationManager returns a manager wired with the default migrators.
// Tier2 (CephRBD) and Tier3 (SnapshotRsync) are registered as stubs by default
// so that the state machine is unblocked in environments without Ceph or a snapshot
// provisioner. Wire production migrators via RegisterMigrator in cmd/operator.
// Pass overrides via RegisterMigrator in tests to inject fakes.
func NewStorageMigrationManager(c client.Client) *StorageMigrationManager {
	m := &StorageMigrationManager{
		Client:     c,
		Classifier: NewStorageClassifier(c),
		Migrators:  map[StorageTier]Migrator{},
	}
	// Default registrations — all production implementations are registered by
	// the operator wire code; explicit stubs are used here so the manager is
	// usable out of the box without external dependencies, and so that no tier
	// falls through to the missing-migrator branch (which now blocks the freeze
	// for any tier > TierRWX rather than silently declaring it ready).
	m.Migrators[TierRWX] = NewRWXReattachMigrator(c)
	m.Migrators[TierLonghorn] = &LonghornStubMigrator{}
	m.Migrators[TierCephRBD] = &CephRBDStubMigrator{}
	m.Migrators[TierSnapshotRsync] = &SnapshotRsyncStubMigrator{}
	return m
}

// NewStorageMigrationManagerWithProduction returns a manager wired with real migrators
// for all tiers. cephDestPool is the Ceph pool for RBD live migration destination images.
// longhornManagerURL is the base URL of the Longhorn Manager HTTP API; if empty, the
// explicit Longhorn stub registered by NewStorageMigrationManager is retained (a real
// Longhorn tier volume then blocks on the stub's ready path rather than falling through
// to the missing-migrator freeze block).
func NewStorageMigrationManagerWithProduction(c client.Client, cephDestPool, longhornManagerURL string) *StorageMigrationManager {
	m := NewStorageMigrationManager(c)
	if longhornManagerURL != "" {
		m.Migrators[TierLonghorn] = NewLonghornMigrator(longhornManagerURL, c)
	}
	m.Migrators[TierCephRBD] = NewCephRBDMigrator(cephDestPool)
	m.Migrators[TierSnapshotRsync] = NewSnapshotRsyncMigrator(c)
	return m
}

// RegisterMigrator adds or replaces the migrator for a given tier.
func (m *StorageMigrationManager) RegisterMigrator(tier StorageTier, mg Migrator) {
	m.Migrators[tier] = mg
}

// RunPreStage classifies the pod's PVCs, selects the appropriate Migrator, runs
// PreStage, and patches StorageReadyForFreeze=True on the PodMigration CR when
// the sync threshold is reached.
//
// Intended to run in a goroutine — patches the CR directly via the k8s client.
// The PodMigration controller re-evaluates the condition on the next reconcile.
func (m *StorageMigrationManager) RunPreStage(ctx context.Context, pm *pmv1.PodMigration) error {
	log := logf.FromContext(ctx).WithValues("migration", pm.Name)

	highest, migrator, opts, err := m.buildMigrationOptions(ctx, pm)
	if err != nil {
		return m.patchStorageReady(ctx, pm, metav1.ConditionFalse, "ClassifyFailed", err.Error())
	}

	// Persist the highest tier to status.storageTier.
	tier := int32(highest.Tier)
	if err := m.patchStorageTier(ctx, pm, tier); err != nil {
		log.Error(err, "failed to patch storageTier — continuing")
	}

	if highest.Tier == TierBlocked {
		return m.patchStorageReady(ctx, pm, metav1.ConditionFalse, "BlockedVolume",
			fmt.Sprintf("pod has un-migratable volume: %s", highest.Reason))
	}

	if migrator == nil {
		// No migrator registered for the selected tier.
		//
		// The immediate-ready path is valid ONLY for TierRWX, where no data
		// movement is required (the volume is simply re-attached on the
		// destination). For any tier > TierRWX a missing migrator means the
		// destination replica/image does NOT exist yet, so declaring the freeze
		// ready would let the pod freeze and restore before its storage is
		// staged — silent data loss (H-14/C-08). Patch StorageReadyForFreeze=False
		// with a recoverable, human-actionable reason so the freeze does not
		// proceed and an operator can register the missing tier migrator.
		if highest.Tier > TierRWX {
			log.Info("no migrator registered for tier > TierRWX — blocking freeze",
				"tier", highest.Tier)
			return m.patchStorageReady(ctx, pm, metav1.ConditionFalse, "NoMigratorForTier",
				fmt.Sprintf("tier%d: no storage migrator registered — cannot stage "+
					"destination storage; register a migrator for this tier before "+
					"migrating (%s)", highest.Tier, highest.Reason))
		}
		log.Info("no migrator registered for TierRWX — emitting StorageReadyForFreeze immediately",
			"tier", highest.Tier)
		return m.patchStorageReady(ctx, pm, metav1.ConditionTrue, "NoOpTier",
			fmt.Sprintf("tier%d: re-attach only — no data movement required", highest.Tier))
	}

	log.Info("starting storage pre-stage", "tier", highest.Tier, "reason", highest.Reason)
	var preStageErr error
retryLoop:
	for attempt := 1; attempt <= preStageMaxAttempts; attempt++ {
		preStageErr = migrator.PreStage(ctx, opts)
		if preStageErr == nil {
			break
		}
		if attempt == preStageMaxAttempts || !isTransientPreStageError(preStageErr) {
			break
		}
		log.Info("pre-stage failed with a transient error — retrying",
			"tier", highest.Tier, "attempt", attempt, "maxAttempts", preStageMaxAttempts, "err", preStageErr)
		select {
		case <-ctx.Done():
			preStageErr = ctx.Err()
			break retryLoop
		case <-time.After(preStageRetryBackoff):
		}
	}
	if preStageErr != nil {
		return m.patchStorageReady(ctx, pm, metav1.ConditionFalse, "PreStageFailed",
			fmt.Sprintf("tier%d pre-stage: %v", highest.Tier, preStageErr))
	}

	// PreStage succeeded — for Tier0 (RWX) this is sufficient.
	// For tiers with a sync phase, PreStage blocks until ≥95% is reached internally.
	return m.patchStorageReady(ctx, pm, metav1.ConditionTrue, "StorageReady",
		fmt.Sprintf("tier%d pre-stage complete: %s", highest.Tier, highest.Reason))
}

// buildMigrationOptions classifies the source pod's PVCs, selects the
// highest-tier classification, resolves the Migrator registered for it, and
// assembles the MigrationOptions the migrator's methods need. This is the
// shared classify-and-select boilerplate used by RunPreStage, Cutover, and
// AwaitSingleOwner so it is written once instead of triplicated.
//
// migrator is nil when no Migrator is registered for the selected tier —
// callers decide how to handle that (RunPreStage has a TierRWX-only no-op
// fallback; Cutover/AwaitSingleOwner treat it as an error since a missing
// migrator at that point means the cutover cannot be verified).
func (m *StorageMigrationManager) buildMigrationOptions(ctx context.Context, pm *pmv1.PodMigration) (TierClassification, Migrator, MigrationOptions, error) {
	sourcePod, err := m.getSourcePod(ctx, pm)
	if err != nil {
		return TierClassification{}, nil, MigrationOptions{}, fmt.Errorf("get source pod: %w", err)
	}

	classifications, err := m.Classifier.ClassifyPod(ctx, sourcePod)
	if err != nil {
		return TierClassification{}, nil, MigrationOptions{}, fmt.Errorf("classify pod pvcs: %w", err)
	}

	highest := HighestTier(classifications)
	opts := MigrationOptions{
		MigrationName:   pm.Name,
		PodNamespace:    pm.Spec.PodNamespace,
		SourceNode:      pm.Status.SourceNodeName,
		DestinationNode: pm.Status.DestinationNodeName,
		Classifications: classifications,
	}

	return highest, m.Migrators[highest.Tier], opts, nil
}

// Cutover looks up the classified tier's migrator and delegates to its
// Cutover method (detach from source, attach to destination), patching
// ConditionStorageCutoverComplete=False with a recoverable reason on
// failure. Called by the controller after CRIU restore completes, before
// AwaitSingleOwner and before the DisengageHold phase is allowed to proceed.
func (m *StorageMigrationManager) Cutover(ctx context.Context, pm *pmv1.PodMigration) error {
	highest, migrator, opts, err := m.buildMigrationOptions(ctx, pm)
	if err != nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "CutoverFailed",
			fmt.Sprintf("classify pod pvcs for cutover: %v", err))
	}
	if highest.Tier == TierBlocked {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "CutoverFailed",
			fmt.Sprintf("pod has un-migratable volume: %s", highest.Reason))
	}
	if migrator == nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "CutoverFailed",
			fmt.Sprintf("tier%d: no storage migrator registered for cutover", highest.Tier))
	}
	if err := migrator.Cutover(ctx, opts); err != nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "CutoverFailed",
			fmt.Sprintf("tier%d cutover: %v", highest.Tier, err))
	}
	return nil
}

// AwaitSingleOwner looks up the classified tier's migrator and delegates to
// its AwaitSingleOwner method, blocking until the migrated volume(s) are in
// a single-owner, mountable state on the destination node. Patches
// ConditionStorageCutoverComplete=False with reason AwaitSingleOwnerTimeout
// on failure (a timeout is a real, recoverable error — not silently retried
// forever). The controller calls this after Cutover succeeds and before
// permitting the destination pod's volume mounts to proceed.
func (m *StorageMigrationManager) AwaitSingleOwner(ctx context.Context, pm *pmv1.PodMigration) error {
	highest, migrator, opts, err := m.buildMigrationOptions(ctx, pm)
	if err != nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "AwaitSingleOwnerTimeout",
			fmt.Sprintf("classify pod pvcs for await-single-owner: %v", err))
	}
	if highest.Tier == TierBlocked {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "AwaitSingleOwnerTimeout",
			fmt.Sprintf("pod has un-migratable volume: %s", highest.Reason))
	}
	if migrator == nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "AwaitSingleOwnerTimeout",
			fmt.Sprintf("tier%d: no storage migrator registered for await-single-owner", highest.Tier))
	}
	if err := migrator.AwaitSingleOwner(ctx, opts); err != nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "AwaitSingleOwnerTimeout",
			fmt.Sprintf("tier%d await-single-owner: %v", highest.Tier, err))
	}
	return m.patchStorageCutover(ctx, pm, metav1.ConditionTrue, "CutoverComplete",
		fmt.Sprintf("tier%d: volume collapsed to single-owner mountable state", highest.Tier))
}

// patchStorageCutover updates the StorageCutoverComplete condition on the
// PodMigration CR. Retries on optimistic-lock conflict, mirroring
// patchStorageReady.
func (m *StorageMigrationManager) patchStorageCutover(
	ctx context.Context,
	pm *pmv1.PodMigration,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	key := client.ObjectKeyFromObject(pm)
	patchErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := m.Client.Get(ctx, key, fresh); err != nil {
			return fmt.Errorf("get PodMigration for storage cutover patch: %w", err)
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               pmv1.ConditionStorageCutoverComplete,
			Status:             status,
			Reason:             reason,
			Message:            message,
			LastTransitionTime: metav1.Now(),
		})
		return m.Client.Status().Update(ctx, fresh)
	})
	if patchErr != nil {
		return patchErr
	}
	if status != metav1.ConditionTrue {
		return fmt.Errorf("%s: %s", reason, message)
	}
	return nil
}

// patchStorageReady updates the StorageReadyForFreeze condition on the PodMigration CR.
// Retries on optimistic-lock conflict (resource version mismatch) using retry.RetryOnConflict.
func (m *StorageMigrationManager) patchStorageReady(
	ctx context.Context,
	pm *pmv1.PodMigration,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	key := client.ObjectKeyFromObject(pm)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := m.Client.Get(ctx, key, fresh); err != nil {
			return fmt.Errorf("get PodMigration for storage patch: %w", err)
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               conditionStorageReadyForFreeze,
			Status:             status,
			Reason:             reason,
			Message:            message,
			LastTransitionTime: metav1.Now(),
		})
		return m.Client.Status().Update(ctx, fresh)
	})
}

// patchStorageTier writes pm.Status.StorageTier via a fresh fetch.
// Retries on optimistic-lock conflict (resource version mismatch).
func (m *StorageMigrationManager) patchStorageTier(ctx context.Context, pm *pmv1.PodMigration, tier int32) error {
	key := client.ObjectKeyFromObject(pm)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := m.Client.Get(ctx, key, fresh); err != nil {
			return err
		}
		fresh.Status.StorageTier = &tier
		return m.Client.Status().Update(ctx, fresh)
	})
}

func (m *StorageMigrationManager) getSourcePod(ctx context.Context, pm *pmv1.PodMigration) (*corev1.Pod, error) {
	p := &corev1.Pod{}
	err := m.Client.Get(ctx, client.ObjectKey{
		Namespace: pm.Spec.PodNamespace,
		Name:      pm.Spec.PodName,
	}, p)
	return p, err
}
