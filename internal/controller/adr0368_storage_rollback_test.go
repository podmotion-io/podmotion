/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0368_storage_rollback_test.go covers ADR-0368 §6 item 3: reconcileRollingBack must
// errors.Is-check the combined rollback error for storage.ErrRollbackPointOfNoReturn/
// storage.ErrRollbackNotImplemented and set a distinct, human-actionable condition + Warning
// event, on top of (not instead of) the existing generic ConditionFailed terminal outcome — and
// must NOT do so for an ordinary transient rollback error.
//
// These tests drive the real reconcileRollingBack logic via r.Reconcile (mirroring
// adr0351_pause_pid_rollback_test.go's shape) with a real rollback.DefaultRollbacker whose
// StorageStep is a fake returning a specific error — isolating the controller-side errors.Is
// branching from the storage package's own ReleaseDestination implementations (covered
// separately in internal/agent/storage).

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
	"github.com/podmotion-io/podmotion/internal/rollback"
)

// noopRollbackStep is a rollback.Step that always succeeds — isolates the StorageStep under test
// from NetworkRollback/ComputeRollback (mirrors StubNetworkRollback/StubComputeRollback's shape
// without needing a real SourceAgentClient wired).
type noopRollbackStep struct{ name string }

func (s *noopRollbackStep) Name() string                                          { return s.name }
func (s *noopRollbackStep) Execute(_ context.Context, _ *pmv1.PodMigration) error { return nil }

// fakeStorageStep is a rollback.Step whose Execute returns a configured error — stands in for
// rollback.RealStorageRollback so these tests can drive reconcileRollingBack's errors.Is
// branching directly, without a live StorageMigrationManager/Migrator/Longhorn Manager.
type fakeStorageStep struct{ err error }

func (s *fakeStorageStep) Name() string                                          { return "StorageRollback" }
func (s *fakeStorageStep) Execute(_ context.Context, _ *pmv1.PodMigration) error { return s.err }

// adr0368RollingBackPM builds a minimal PodMigration already in RollingBack with a live source
// pod — StorageTier deliberately left nil (Tier0/no-tier) so restoreSourceStorageIfNeeded
// short-circuits without needing an AgentPool, matching
// TestRestore_CgroupAnchorFailedClosed_SourcePodSurvivesRollback's established pattern.
func adr0368RollingBackPM(name string) (*pmv1.PodMigration, *corev1.Pod) {
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod-" + name, Namespace: "default", UID: types.UID("uid-" + name)},
		Spec:       corev1.PodSpec{NodeName: "src-node"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.99"},
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Finalizers: []string{finalizerName}},
		Spec: pmv1.PodMigrationSpec{
			PodName:             srcPod.Name,
			PodNamespace:        "default",
			Mode:                pmv1.MigrationModeCold,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
			RollbackOnFailure:   true,
			TargetNodeName:      "dst-node",
			SourcePodIP:         "10.0.0.99",
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseRollingBack,
			SourceNodeName:      "src-node",
			DestinationNodeName: "dst-node",
		},
	}
	return pm, srcPod
}

func TestReconcileRollingBack_StorageRollbackImpossible_SetsDistinctConditionAndEvent(t *testing.T) {
	scheme := adr0210Scheme(t)
	pm, srcPod := adr0368RollingBackPM("adr0368-pointofnoreturn")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod).
		WithStatusSubresource(pm).
		Build()

	wantErr := fmt.Errorf("tier2: %w: rbd migration commit already completed for rbd/pvc-x — source image deleted",
		storage.ErrRollbackPointOfNoReturn)
	rb := &rollback.DefaultRollbacker{
		NetworkStep: &noopRollbackStep{name: "NetworkRollback"},
		ComputeStep: &noopRollbackStep{name: "ComputeRollback"},
		StorageStep: &fakeStorageStep{err: wantErr},
	}
	rec := record.NewFakeRecorder(8)
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: rb, Recorder: rec}

	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile(RollingBack) returned error: %v", err)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("get PodMigration: %v", err)
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionStorageRollbackImpossible) {
		t.Errorf("expected ConditionStorageRollbackImpossible=True for a wrapped ErrRollbackPointOfNoReturn, got conditions=%+v", fresh.Status.Conditions)
	}
	if meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionStorageRollbackNotSupported) {
		t.Errorf("ConditionStorageRollbackNotSupported must NOT be set for a point-of-no-return error")
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionFailed) {
		t.Errorf("expected the existing generic ConditionFailed=True terminal outcome to still be set, got conditions=%+v", fresh.Status.Conditions)
	}

	select {
	case ev := <-rec.Events:
		if !strings.Contains(ev, "StorageRollbackImpossible") {
			t.Errorf("expected a StorageRollbackImpossible Warning event, got %q", ev)
		}
	default:
		t.Errorf("expected a Warning event to be recorded, got none")
	}
}

func TestReconcileRollingBack_StorageRollbackNotSupported_SetsDistinctConditionAndEvent(t *testing.T) {
	scheme := adr0210Scheme(t)
	pm, srcPod := adr0368RollingBackPM("adr0368-notimplemented")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod).
		WithStatusSubresource(pm).
		Build()

	wantErr := fmt.Errorf("tier3: %w", storage.ErrRollbackNotImplemented)
	rb := &rollback.DefaultRollbacker{
		NetworkStep: &noopRollbackStep{name: "NetworkRollback"},
		ComputeStep: &noopRollbackStep{name: "ComputeRollback"},
		StorageStep: &fakeStorageStep{err: wantErr},
	}
	rec := record.NewFakeRecorder(8)
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: rb, Recorder: rec}

	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile(RollingBack) returned error: %v", err)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("get PodMigration: %v", err)
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionStorageRollbackNotSupported) {
		t.Errorf("expected ConditionStorageRollbackNotSupported=True for a wrapped ErrRollbackNotImplemented, got conditions=%+v", fresh.Status.Conditions)
	}
	if meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionStorageRollbackImpossible) {
		t.Errorf("ConditionStorageRollbackImpossible must NOT be set for a not-implemented error")
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionFailed) {
		t.Errorf("expected the existing generic ConditionFailed=True terminal outcome to still be set, got conditions=%+v", fresh.Status.Conditions)
	}

	select {
	case ev := <-rec.Events:
		if !strings.Contains(ev, "StorageRollbackNotSupported") {
			t.Errorf("expected a StorageRollbackNotSupported Warning event, got %q", ev)
		}
	default:
		t.Errorf("expected a Warning event to be recorded, got none")
	}
}

func TestReconcileRollingBack_TransientStorageError_NeitherADR0368ConditionSet(t *testing.T) {
	scheme := adr0210Scheme(t)
	pm, srcPod := adr0368RollingBackPM("adr0368-transient")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod).
		WithStatusSubresource(pm).
		Build()

	// An ordinary operational failure (e.g. an HTTP timeout talking to the Longhorn Manager) —
	// NOT one of the two ADR-0368 sentinels. Must fall through to the pre-existing generic
	// ConditionFailed path only; retriable in principle, not a structural impossibility/gap.
	wantErr := fmt.Errorf("tier1: rollback detach volX from dst-node: dial tcp: connection refused")
	rb := &rollback.DefaultRollbacker{
		NetworkStep: &noopRollbackStep{name: "NetworkRollback"},
		ComputeStep: &noopRollbackStep{name: "ComputeRollback"},
		StorageStep: &fakeStorageStep{err: wantErr},
	}
	rec := record.NewFakeRecorder(8)
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: rb, Recorder: rec}

	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile(RollingBack) returned error: %v", err)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("get PodMigration: %v", err)
	}
	if meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionStorageRollbackImpossible) {
		t.Errorf("ConditionStorageRollbackImpossible must NOT be set for a plain transient error")
	}
	if meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionStorageRollbackNotSupported) {
		t.Errorf("ConditionStorageRollbackNotSupported must NOT be set for a plain transient error")
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionFailed) {
		t.Errorf("expected the existing generic ConditionFailed=True terminal outcome to still be set, got conditions=%+v", fresh.Status.Conditions)
	}
}
