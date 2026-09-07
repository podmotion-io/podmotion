/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

// adr0368_manager_release_destination_test.go covers StorageMigrationManager.ReleaseDestination
// (ADR-0368 §5.3) and the opts.CutoverComplete population it drives (CONDITION 2's grounding in
// the existing meta.FindStatusCondition/meta.IsStatusConditionTrue pattern — see
// podmigration_controller.go:1640's use of the same ConditionStorageCutoverComplete condition).

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

// TestStorageMigrationManager_ReleaseDestination_NoCachedClassification_ReturnsNil covers the
// "rollback fired before RunPreStage ever ran" case (e.g. a Validating-phase failure) — nothing
// storage-side was ever staged, so ReleaseDestination must return nil, not the generic
// "no cached PVC classification yet" error Cutover/AwaitSingleOwner correctly treat as a failure.
func TestStorageMigrationManager_ReleaseDestination_NoCachedClassification_ReturnsNil(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-nostage", "default", "src-pod")
	// Deliberately no PVC/StorageTier — RunPreStage never ran.

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()
	mgr := storage.NewStorageMigrationManager(c)

	if err := mgr.ReleaseDestination(context.Background(), pm); err != nil {
		t.Errorf("expected nil when no classification was ever cached (nothing to release), got: %v", err)
	}
}

// TestStorageMigrationManager_ReleaseDestination_TierBlocked_ReturnsNil covers a classification
// that resolved to TierBlocked — RunPreStage always halts before Cutover can run for a blocked
// volume, so nothing was ever staged for it either.
func TestStorageMigrationManager_ReleaseDestination_TierBlocked_ReturnsNil(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-blocked", "default", "src-pod")
	blockedTier := int32(storage.TierBlocked)
	pm.Status.StorageTier = &blockedTier
	pm.Status.ClassifiedVolumes = []pmv1.PVCTierClassification{
		{Tier: int32(storage.TierBlocked), PVCName: "hostpath-vol", Reason: "hostPath is not migratable"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()
	mgr := storage.NewStorageMigrationManager(c)

	if err := mgr.ReleaseDestination(context.Background(), pm); err != nil {
		t.Errorf("expected nil for a TierBlocked classification (Cutover can never have run), got: %v", err)
	}
}

// TestStorageMigrationManager_ReleaseDestination_NilMigrator_ReturnsError proves the ambiguous
// "we don't know if there's anything to release" case (a registered-but-missing migrator for a
// real classified tier) stays a real, fail-loud error — never silently nil.
func TestStorageMigrationManager_ReleaseDestination_NilMigrator_ReturnsError(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-nomigrator", "default", "src-pod")
	tier := int32(storage.TierLonghorn)
	pm.Status.StorageTier = &tier
	pm.Status.ClassifiedVolumes = []pmv1.PVCTierClassification{
		{Tier: int32(storage.TierLonghorn), PVCName: "pgdata", Reason: "test"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()
	mgr := storage.NewStorageMigrationManager(c)
	mgr.Migrators = map[storage.StorageTier]storage.Migrator{} // no migrator registered at all

	err := mgr.ReleaseDestination(context.Background(), pm)
	if err == nil {
		t.Fatalf("expected a real error when no migrator is registered for a classified tier — an ambiguous case must never be treated as nothing-to-release")
	}
}

// recordingReleaseMigrator is a storage.Migrator fake that records the MigrationOptions it was
// called with, so tests can assert what opts.CutoverComplete the manager computed.
type recordingReleaseMigrator struct {
	tier     storage.StorageTier
	called   bool
	lastOpts storage.MigrationOptions
}

func (r *recordingReleaseMigrator) Tier() storage.StorageTier { return r.tier }
func (r *recordingReleaseMigrator) PreStage(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}
func (r *recordingReleaseMigrator) SyncPercent(_ context.Context, _ storage.MigrationOptions) (int, error) {
	return 100, nil
}
func (r *recordingReleaseMigrator) Cutover(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}
func (r *recordingReleaseMigrator) AwaitSingleOwner(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}
func (r *recordingReleaseMigrator) ReleaseDestination(_ context.Context, opts storage.MigrationOptions) error {
	r.called = true
	r.lastOpts = opts
	return nil
}

func withCachedLonghornClassification(pm *pmv1.PodMigration) {
	tier := int32(storage.TierLonghorn)
	pm.Status.StorageTier = &tier
	pm.Status.ClassifiedVolumes = []pmv1.PVCTierClassification{
		{Tier: int32(storage.TierLonghorn), PVCName: "pgdata", Reason: "test"},
	}
}

// TestStorageMigrationManager_ReleaseDestination_CutoverCompleteGrounding table-drives
// CutoverSideEffectOccurred's three input shapes against the real
// ConditionStorageCutoverComplete condition (CONDITION 2's grounding requirement) — proving
// opts.CutoverComplete reflects the codebase's existing condition-reading pattern, not tier
// identity.
func TestStorageMigrationManager_ReleaseDestination_CutoverCompleteGrounding(t *testing.T) {
	cases := []struct {
		name       string
		conditions []metav1.Condition
		want       bool
	}{
		{
			name:       "condition absent (rollback before Cutover ever ran)",
			conditions: nil,
			want:       false,
		},
		{
			name: "condition True (AwaitSingleOwner confirmed collapse)",
			conditions: []metav1.Condition{
				{Type: pmv1.ConditionStorageCutoverComplete, Status: metav1.ConditionTrue,
					Reason: "CutoverComplete", LastTransitionTime: metav1.Now()},
			},
			want: true,
		},
		{
			name: "condition False, reason AwaitSingleOwnerTimeout (Cutover succeeded, poll timed out)",
			conditions: []metav1.Condition{
				{Type: pmv1.ConditionStorageCutoverComplete, Status: metav1.ConditionFalse,
					Reason: "AwaitSingleOwnerTimeout", LastTransitionTime: metav1.Now()},
			},
			want: true,
		},
		{
			name: "condition False, reason CutoverFailed (Cutover itself never succeeded)",
			conditions: []metav1.Condition{
				{Type: pmv1.ConditionStorageCutoverComplete, Status: metav1.ConditionFalse,
					Reason: "CutoverFailed", LastTransitionTime: metav1.Now()},
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newManagerScheme(t)
			pm := makeMigration("mig-grounding-"+tc.name, "default", "src-pod")
			withCachedLonghornClassification(pm)
			pm.Status.Conditions = tc.conditions

			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()
			mgr := storage.NewStorageMigrationManager(c)
			spy := &recordingReleaseMigrator{tier: storage.TierLonghorn}
			mgr.RegisterMigrator(storage.TierLonghorn, spy)

			if err := mgr.ReleaseDestination(context.Background(), pm); err != nil {
				t.Fatalf("ReleaseDestination: %v", err)
			}
			if !spy.called {
				t.Fatalf("migrator.ReleaseDestination was never called")
			}
			if spy.lastOpts.CutoverComplete != tc.want {
				t.Errorf("opts.CutoverComplete = %v, want %v", spy.lastOpts.CutoverComplete, tc.want)
			}
		})
	}
}

// TestStorageMigrationManager_ReleaseDestination_PropagatesMigratorSentinelError proves a
// tier's sentinel error returned by Migrator.ReleaseDestination survives the manager's own %w
// wrap un-mangled (errors.Is must still resolve after passing through this layer — mirrors the
// verification assertion for StorageMigrationManager.ReleaseDestination).
func TestStorageMigrationManager_ReleaseDestination_PropagatesMigratorSentinelError(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-propagate", "default", "src-pod")
	withCachedLonghornClassification(pm)
	pm.Status.Conditions = []metav1.Condition{
		{Type: pmv1.ConditionStorageCutoverComplete, Status: metav1.ConditionTrue,
			Reason: "CutoverComplete", LastTransitionTime: metav1.Now()},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()
	mgr := storage.NewStorageMigrationManager(c)
	stub := &storage.LonghornStubMigrator{}
	mgr.RegisterMigrator(storage.TierLonghorn, stub)

	err := mgr.ReleaseDestination(context.Background(), pm)
	if !errors.Is(err, storage.ErrRollbackNotImplemented) {
		t.Fatalf("expected errors.Is(err, storage.ErrRollbackNotImplemented) to resolve through StorageMigrationManager.ReleaseDestination's wrap, got: %v", err)
	}
}
