/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package rollback_test

// rollback_test.go covers ADR-0368:
//   - CONDITION 4: DefaultRollbacker.Rollback's outer combine must preserve errors.Is-traversal
//     down to the per-step sentinel errors (fixed by switching %v → errors.Join+%w).
//   - CONDITION 5: RealStorageRollback/NewRollbacker must dispatch through the SAME
//     StorageMigrationManager/Migrator instance the forward storage-cutover pipeline already
//     used for a migration — never a second, independently constructed manager.
//   - RealStorageRollback's own fail-loud contract (a nil StorageMgr is a real error, never a
//     silent no-op).

import (
	"context"
	"errors"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
	"github.com/podmotion-io/podmotion/internal/rollback"
)

// alwaysOKStep is a rollback.Step that always succeeds.
type alwaysOKStep struct{ name string }

func (s *alwaysOKStep) Name() string                                          { return s.name }
func (s *alwaysOKStep) Execute(_ context.Context, _ *pmv1.PodMigration) error { return nil }

// failingStep is a rollback.Step whose Execute returns a configured error.
type failingStep struct {
	name string
	err  error
}

func (s *failingStep) Name() string { return s.name }
func (s *failingStep) Execute(_ context.Context, _ *pmv1.PodMigration) error {
	return s.err
}

func testPM(name string) *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "src", PodNamespace: "default"},
	}
}

// TestDefaultRollbacker_Rollback_ErrorsIsTraversesPointOfNoReturn is the regression test for
// CONDITION 4 / the §9 runtime-dependency-audit finding: the outer combine used to interpolate
// the per-step errors with %v, which does not implement Unwrap and so breaks errors.Is
// traversal — this is the exact failure mode that would make the controller-side errors.Is
// check (reconcileRollingBack) silently never match, defeating the whole ADR.
func TestDefaultRollbacker_Rollback_ErrorsIsTraversesPointOfNoReturn(t *testing.T) {
	stepErr := fmt.Errorf("tier2: %w: rbd migration commit already completed for rbd/pvc-x — source image deleted",
		storage.ErrRollbackPointOfNoReturn)

	rb := &rollback.DefaultRollbacker{
		NetworkStep: &alwaysOKStep{name: "NetworkRollback"},
		ComputeStep: &alwaysOKStep{name: "ComputeRollback"},
		StorageStep: &failingStep{name: "StorageRollback", err: stepErr},
	}

	err := rb.Rollback(context.Background(), testPM("mig-ponr"))
	if err == nil {
		t.Fatalf("expected a non-nil combined error")
	}
	if !errors.Is(err, storage.ErrRollbackPointOfNoReturn) {
		t.Fatalf("errors.Is(combinedErr, storage.ErrRollbackPointOfNoReturn) = false; combined error traversal is broken: %v", err)
	}
	if errors.Is(err, storage.ErrRollbackNotImplemented) {
		t.Errorf("errors.Is unexpectedly matched ErrRollbackNotImplemented for a PointOfNoReturn-only failure")
	}
}

// TestDefaultRollbacker_Rollback_ErrorsIsTraversesNotImplemented mirrors the PointOfNoReturn
// case for the ErrRollbackNotImplemented sentinel, and additionally proves the traversal still
// works when MULTIPLE steps fail simultaneously (the verification assertion's "not just through an
// individual step's error" requirement) — a real scenario if e.g. NetworkRollback also failed on
// the same reconcile.
func TestDefaultRollbacker_Rollback_ErrorsIsTraversesNotImplemented_MultiStepFailure(t *testing.T) {
	networkErr := errors.New("network rollback: disarm bridge RPC failed")
	storageErr := fmt.Errorf("tier3: %w", storage.ErrRollbackNotImplemented)

	rb := &rollback.DefaultRollbacker{
		NetworkStep: &failingStep{name: "NetworkRollback", err: networkErr},
		ComputeStep: &alwaysOKStep{name: "ComputeRollback"},
		StorageStep: &failingStep{name: "StorageRollback", err: storageErr},
	}

	err := rb.Rollback(context.Background(), testPM("mig-multi"))
	if err == nil {
		t.Fatalf("expected a non-nil combined error")
	}
	if !errors.Is(err, storage.ErrRollbackNotImplemented) {
		t.Fatalf("errors.Is(combinedErr, storage.ErrRollbackNotImplemented) = false through a 2/3-step combined failure: %v", err)
	}
	if errors.Is(err, storage.ErrRollbackPointOfNoReturn) {
		t.Errorf("errors.Is unexpectedly matched ErrRollbackPointOfNoReturn for a NotImplemented-only storage failure")
	}
}

// TestRealStorageRollback_Execute_NilStorageMgr_FailsLoudNeverNil proves the zero-tech-debt
// fail-loud contract: an un-wired StorageMgr must return a real, distinct error — never silently
// report success as StubStorageRollback used to (regardless of reason).
func TestRealStorageRollback_Execute_NilStorageMgr_FailsLoudNeverNil(t *testing.T) {
	step := &rollback.RealStorageRollback{}
	err := step.Execute(context.Background(), testPM("mig-nilmgr"))
	if err == nil {
		t.Fatalf("expected a non-nil error when StorageMgr is nil — a fail-open nil here reopens the exact bug ADR-0368 closes")
	}
}

// spyReleaser is a minimal storage.StorageDestinationReleaser fake — records the PodMigration it
// was called with.
type spyReleaser struct {
	called bool
	gotPM  *pmv1.PodMigration
	err    error
}

func (s *spyReleaser) ReleaseDestination(_ context.Context, pm *pmv1.PodMigration) error {
	s.called = true
	s.gotPM = pm
	return s.err
}

func TestRealStorageRollback_Execute_DelegatesToStorageMgr(t *testing.T) {
	spy := &spyReleaser{}
	step := &rollback.RealStorageRollback{StorageMgr: spy}
	pm := testPM("mig-delegate")

	if err := step.Execute(context.Background(), pm); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !spy.called {
		t.Fatalf("RealStorageRollback.Execute did not call StorageMgr.ReleaseDestination")
	}
	if spy.gotPM != pm {
		t.Errorf("RealStorageRollback.Execute did not pass through the same *PodMigration pointer")
	}
}

func TestRealStorageRollback_Execute_PropagatesStorageMgrError(t *testing.T) {
	wantErr := fmt.Errorf("tier2: %w", storage.ErrRollbackPointOfNoReturn)
	step := &rollback.RealStorageRollback{StorageMgr: &spyReleaser{err: wantErr}}

	err := step.Execute(context.Background(), testPM("mig-propagate"))
	if !errors.Is(err, storage.ErrRollbackPointOfNoReturn) {
		t.Fatalf("expected StorageMgr's error to propagate un-mangled, got: %v", err)
	}
}

// spySharedMigrator is a storage.Migrator fake that records whether Cutover and
// ReleaseDestination were each called — used to prove CONDITION 5's shared-instance wiring: the
// SAME registered Migrator instance must see both the forward Cutover call and the rollback
// ReleaseDestination call.
type spySharedMigrator struct {
	tier                     storage.StorageTier
	cutoverCalled            bool
	releaseDestinationCalled bool
}

func (s *spySharedMigrator) Tier() storage.StorageTier { return s.tier }
func (s *spySharedMigrator) PreStage(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}
func (s *spySharedMigrator) SyncPercent(_ context.Context, _ storage.MigrationOptions) (int, error) {
	return 100, nil
}
func (s *spySharedMigrator) Cutover(_ context.Context, _ storage.MigrationOptions) error {
	s.cutoverCalled = true
	return nil
}
func (s *spySharedMigrator) AwaitSingleOwner(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}
func (s *spySharedMigrator) ReleaseDestination(_ context.Context, _ storage.MigrationOptions) error {
	s.releaseDestinationCalled = true
	return nil
}

// TestNewRollbacker_StorageStepSharesForwardStorageMigrationManagerInstance is the regression
// test for ADR-0368 CONDITION 5 / §5.3 / §9's "no shared StorageMigrationManager" finding:
// cmd/main.go used to construct storageMgr (wired into the controller's forward StorageMgr
// field) and the rollback pipeline (via NewStubRollbacker, which has no storageMgr parameter at
// all) as two completely independent objects — so a Cutover call and a subsequent
// ReleaseDestination rollback call could never be guaranteed to reach the same, already-
// configured Migrator instance. This test builds ONE StorageMigrationManager, registers ONE spy
// Migrator on it, drives a forward Cutover through it (simulating the controller's StorageMgr
// field), then builds a rollback.NewRollbacker around the SAME manager and drives a Rollback
// through it — and asserts the SAME spy instance observed both calls.
func TestNewRollbacker_StorageStepSharesForwardStorageMigrationManagerInstance(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}

	tier := int32(storage.TierLonghorn)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-instance-mig", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "src", PodNamespace: "default"},
		Status: pmv1.PodMigrationStatus{
			SourceNodeName:      "src-node",
			DestinationNodeName: "dst-node",
			StorageTier:         &tier,
			ClassifiedVolumes: []pmv1.PVCTierClassification{
				{Tier: int32(storage.TierLonghorn), PVCName: "pgdata", Reason: "test fixture"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()

	storageMgr := storage.NewStorageMigrationManager(fakeClient)
	spy := &spySharedMigrator{tier: storage.TierLonghorn}
	storageMgr.RegisterMigrator(storage.TierLonghorn, spy)

	ctx := context.Background()

	// Forward path: exactly what the controller's gateStorageCutoverBeforeRestore does via
	// r.StorageMgr.Cutover.
	if err := storageMgr.Cutover(ctx, pm); err != nil {
		t.Fatalf("Cutover: %v", err)
	}
	if !spy.cutoverCalled {
		t.Fatalf("setup failure: the registered spy migrator's Cutover was not called")
	}

	// Rollback path: ADR-0368 §5.3 requires this to be built around the SAME storageMgr — not a
	// second, independently constructed one — exactly as cmd/main.go now does.
	rb := rollback.NewRollbacker(nil, storageMgr)
	if err := rb.Rollback(ctx, pm); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if !spy.releaseDestinationCalled {
		t.Fatalf("rollback's StorageStep did not dispatch through the SAME Migrator instance the " +
			"forward Cutover call used — CONDITION 5 shared-instance wiring is broken")
	}
}
