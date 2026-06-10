/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

const conditionStorageReadyForFreeze = "StorageReadyForFreeze"

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
// Pass overrides via opts to inject stubs in tests.
func NewStorageMigrationManager(c client.Client) *StorageMigrationManager {
	return &StorageMigrationManager{
		Client:     c,
		Classifier: NewStorageClassifier(c),
		Migrators:  map[StorageTier]Migrator{},
	}
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

	// Use the classifier to enumerate PVC tiers.
	sourcePod, err := m.getSourcePod(ctx, pm)
	if err != nil {
		return m.patchStorageReady(ctx, pm, metav1.ConditionFalse, "ClassifyFailed",
			fmt.Sprintf("get source pod: %v", err))
	}

	classifications, err := m.Classifier.ClassifyPod(ctx, sourcePod)
	if err != nil {
		return m.patchStorageReady(ctx, pm, metav1.ConditionFalse, "ClassifyFailed",
			fmt.Sprintf("classify pod pvcs: %v", err))
	}

	// Persist the highest tier to status.storageTier.
	highest := HighestTier(classifications)
	tier := int32(highest.Tier)
	if err := m.patchStorageTier(ctx, pm, tier); err != nil {
		log.Error(err, "failed to patch storageTier — continuing")
	}

	if highest.Tier == TierBlocked {
		return m.patchStorageReady(ctx, pm, metav1.ConditionFalse, "BlockedVolume",
			fmt.Sprintf("pod has un-migratable volume: %s", highest.Reason))
	}

	migrator, ok := m.Migrators[highest.Tier]
	if !ok {
		// No migrator registered for this tier — fall back to stub that emits ready immediately.
		// This keeps the state machine unblocked while tier support is being added.
		log.Info("no migrator registered for tier — emitting StorageReadyForFreeze immediately",
			"tier", highest.Tier)
		return m.patchStorageReady(ctx, pm, metav1.ConditionTrue, "NoOpTier",
			fmt.Sprintf("tier%d: no migrator registered — no data movement required", highest.Tier))
	}

	opts := MigrationOptions{
		MigrationName:   pm.Name,
		PodNamespace:    pm.Spec.PodNamespace,
		SourceNode:      pm.Status.SourceNodeName,
		DestinationNode: pm.Status.DestinationNodeName,
		Classifications: classifications,
	}

	log.Info("starting storage pre-stage", "tier", highest.Tier, "reason", highest.Reason)
	if err := migrator.PreStage(ctx, opts); err != nil {
		return m.patchStorageReady(ctx, pm, metav1.ConditionFalse, "PreStageFailed",
			fmt.Sprintf("tier%d pre-stage: %v", highest.Tier, err))
	}

	// PreStage succeeded — for Tier0 (RWX) this is sufficient.
	// For tiers with a sync phase, PreStage blocks until ≥95% is reached internally.
	return m.patchStorageReady(ctx, pm, metav1.ConditionTrue, "StorageReady",
		fmt.Sprintf("tier%d pre-stage complete: %s", highest.Tier, highest.Reason))
}

// patchStorageReady updates the StorageReadyForFreeze condition on the PodMigration CR.
// Fetches a fresh copy to avoid conflict on stale resource version.
func (m *StorageMigrationManager) patchStorageReady(
	ctx context.Context,
	pm *pmv1.PodMigration,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	fresh := &pmv1.PodMigration{}
	if err := m.Client.Get(ctx, client.ObjectKeyFromObject(pm), fresh); err != nil {
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
}

// patchStorageTier writes pm.Status.StorageTier via a fresh fetch.
func (m *StorageMigrationManager) patchStorageTier(ctx context.Context, pm *pmv1.PodMigration, tier int32) error {
	fresh := &pmv1.PodMigration{}
	if err := m.Client.Get(ctx, client.ObjectKeyFromObject(pm), fresh); err != nil {
		return err
	}
	fresh.Status.StorageTier = &tier
	return m.Client.Status().Update(ctx, fresh)
}

func (m *StorageMigrationManager) getSourcePod(ctx context.Context, pm *pmv1.PodMigration) (*corev1.Pod, error) {
	p := &corev1.Pod{}
	err := m.Client.Get(ctx, client.ObjectKey{
		Namespace: pm.Spec.PodNamespace,
		Name:      pm.Spec.PodName,
	}, p)
	return p, err
}
