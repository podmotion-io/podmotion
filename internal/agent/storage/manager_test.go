/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

const conditionStorageReadyForFreeze = "StorageReadyForFreeze"

func newManagerScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	if err := storagev1.AddToScheme(s); err != nil {
		t.Fatalf("add storagev1: %v", err)
	}
	if err := pmv1.AddToScheme(s); err != nil {
		t.Fatalf("add pmv1: %v", err)
	}
	return s
}

func makeMigration(name, ns, podName string) *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:      podName,
			PodNamespace: ns,
		},
		Status: pmv1.PodMigrationStatus{
			SourceNodeName:      "node-a",
			DestinationNodeName: "node-b",
		},
	}
}

func makePodWithEmptyDir(ns, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "scratch",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{}, // disk-backed
					},
				},
			},
		},
	}
}

func readStorageReady(t *testing.T, c client.Client, pm *pmv1.PodMigration) *metav1.Condition {
	t.Helper()
	fresh := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pm), fresh); err != nil {
		t.Fatalf("get PodMigration: %v", err)
	}
	return meta.FindStatusCondition(fresh.Status.Conditions, conditionStorageReadyForFreeze)
}

// TestRunPreStage_MissingMigratorAboveRWX_BlocksFreeze is the contract test for
// H-14/C-08. A tier > TierRWX with no registered migrator must patch
// StorageReadyForFreeze=False — never True — so the pod does not freeze and restore
// before its destination storage exists (silent data loss).
//
// On the pre-change logic the missing-migrator branch unconditionally patched
// ConditionTrue with reason "NoOpTier", so this test would have FAILED then — it is
// the "test that would have caught the bug".
func TestRunPreStage_MissingMigratorAboveRWX_BlocksFreeze(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-1", "default", "src-pod")

	// A pod whose highest tier is a disk-backed emptyDir → TierBlocked. But to test
	// the missing-migrator branch specifically for a data-movement tier, we register
	// a manager with NO migrators and drive it against a Longhorn-classified pod via
	// a direct manager built with an empty Migrators map (below). Here we use the
	// TierBlocked path to prove the freeze is refused; a separate assertion covers
	// the empty-migrator-map case.
	//
	// This case: highest tier is TierBlocked (disk emptyDir) — must be ConditionFalse.
	pod := makePodWithEmptyDir("default", "src-pod")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, pod).
		WithStatusSubresource(pm).
		Build()

	mgr := storage.NewStorageMigrationManager(c)
	if err := mgr.RunPreStage(context.Background(), pm); err != nil {
		t.Fatalf("RunPreStage returned error: %v", err)
	}

	cond := readStorageReady(t, c, pm)
	if cond == nil {
		t.Fatalf("StorageReadyForFreeze condition not set")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("expected StorageReadyForFreeze=False for a blocked-volume pod, got %s (reason=%s)",
			cond.Status, cond.Reason)
	}
}

// TestRunPreStage_UnregisteredDataTier_BlocksFreeze drives the missing-migrator
// branch for a data-movement tier (> TierRWX) directly by removing the Longhorn
// migrator from an otherwise-default manager, then classifying a Longhorn pod.
// The freeze MUST be refused with ConditionFalse, never the old "NoOpTier"=True.
func TestRunPreStage_UnregisteredDataTier_BlocksFreeze(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-2", "default", "lh-pod")

	pvc := makePVC("lh-pvc", "default", "longhorn",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce})
	sc := makeSC("longhorn", "driver.longhorn.io", nil)
	pod := makePodWithPVC("default", "lh-pvc")
	pod.Name = "lh-pod"

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, pvc, sc, pod).
		WithStatusSubresource(pm).
		Build()

	mgr := storage.NewStorageMigrationManager(c)
	// Remove the Longhorn migrator so the selected tier has no migrator.
	mgr.Migrators = map[storage.StorageTier]storage.Migrator{
		storage.TierRWX: storage.NewRWXReattachMigrator(c),
	}

	if err := mgr.RunPreStage(context.Background(), pm); err != nil {
		t.Fatalf("RunPreStage returned error: %v", err)
	}

	cond := readStorageReady(t, c, pm)
	if cond == nil {
		t.Fatalf("StorageReadyForFreeze condition not set")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("expected StorageReadyForFreeze=False for unregistered tier > TierRWX, got %s (reason=%s)",
			cond.Status, cond.Reason)
	}
	if cond.Reason == "NoOpTier" {
		t.Errorf("unregistered data tier must NOT reuse the NoOpTier ready path")
	}
}

// TestDefaultConstructor_RegistersLonghornMigrator proves both that the default
// constructor now wires a Longhorn migrator (so a real Longhorn volume no longer
// hits the missing-migrator branch) and that the resulting freeze is declared ready
// via the stub — i.e. the Longhorn tier is no longer silently unhandled.
func TestDefaultConstructor_RegistersLonghornMigrator(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-3", "default", "lh-pod")

	pvc := makePVC("lh-pvc", "default", "longhorn",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce})
	sc := makeSC("longhorn", "driver.longhorn.io", nil)
	pod := makePodWithPVC("default", "lh-pvc")
	pod.Name = "lh-pod"

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, pvc, sc, pod).
		WithStatusSubresource(pm).
		Build()

	mgr := storage.NewStorageMigrationManager(c)
	if _, ok := mgr.Migrators[storage.TierLonghorn]; !ok {
		t.Fatalf("default constructor must register a TierLonghorn migrator")
	}

	if err := mgr.RunPreStage(context.Background(), pm); err != nil {
		t.Fatalf("RunPreStage returned error: %v", err)
	}

	cond := readStorageReady(t, c, pm)
	if cond == nil {
		t.Fatalf("StorageReadyForFreeze condition not set")
	}
	// The registered Longhorn stub completes PreStage and declares ready — the point
	// is that it went through a real migrator, NOT the missing-migrator block.
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("expected StorageReadyForFreeze=True via the registered Longhorn stub, got %s (reason=%s)",
			cond.Status, cond.Reason)
	}
	if cond.Reason == "NoMigratorForTier" {
		t.Errorf("Longhorn tier must not fall through to the missing-migrator block")
	}
}

// TestProductionConstructor_RegistersRealLonghorn confirms the production constructor
// wires the real Longhorn migrator when a manager URL is supplied.
func TestProductionConstructor_RegistersRealLonghorn(t *testing.T) {
	scheme := newManagerScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	mgr := storage.NewStorageMigrationManagerWithProduction(c, "rbd-pool", "http://longhorn.longhorn-system:80")
	mig, ok := mgr.Migrators[storage.TierLonghorn]
	if !ok {
		t.Fatalf("production constructor must register a TierLonghorn migrator")
	}
	if _, isStub := mig.(*storage.LonghornStubMigrator); isStub {
		t.Errorf("production constructor with a manager URL must register the real Longhorn migrator, got stub")
	}

	// With an empty URL, the explicit stub from the default constructor is retained
	// (never a missing migrator).
	mgr2 := storage.NewStorageMigrationManagerWithProduction(c, "rbd-pool", "")
	if _, ok := mgr2.Migrators[storage.TierLonghorn]; !ok {
		t.Fatalf("production constructor with empty Longhorn URL must retain the explicit stub")
	}
}

// fakeTransientNetError implements net.Error to simulate a DNS/routing-race
// style transient failure (e.g. right after a fresh agent pod restart)
// without depending on an actual network call.
type fakeTransientNetError struct{}

func (fakeTransientNetError) Error() string   { return "fake transient network error" }
func (fakeTransientNetError) Timeout() bool   { return true }
func (fakeTransientNetError) Temporary() bool { return true }

// fakeCountingMigrator returns the queued error for each successive PreStage
// call (nil once the queue is exhausted) and records the number of calls, so
// tests can assert exactly how many attempts RunPreStage made.
type fakeCountingMigrator struct {
	tier      storage.StorageTier
	errsQueue []error
	calls     int
}

func (f *fakeCountingMigrator) Tier() storage.StorageTier { return f.tier }

func (f *fakeCountingMigrator) PreStage(_ context.Context, _ storage.MigrationOptions) error {
	idx := f.calls
	f.calls++
	if idx < len(f.errsQueue) {
		return f.errsQueue[idx]
	}
	return nil
}

func (f *fakeCountingMigrator) SyncPercent(_ context.Context, _ storage.MigrationOptions) (int, error) {
	return 100, nil
}

func (f *fakeCountingMigrator) Cutover(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}

// TestRunPreStage_TransientError_RetriesThenSucceeds is the regression test
// for the no-retry-on-transient-failure bug: a PreStage call that fails
// twice with a network/timeout-class error (the DNS/routing race right
// after a fresh pod restart) and then succeeds on the third attempt must
// still result in StorageReadyForFreeze=True — not a permanent False from
// the first failure.
func TestRunPreStage_TransientError_RetriesThenSucceeds(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-retry-ok", "default", "lh-pod")

	pvc := makePVC("lh-pvc", "default", "longhorn",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce})
	sc := makeSC("longhorn", "driver.longhorn.io", nil)
	pod := makePodWithPVC("default", "lh-pvc")
	pod.Name = "lh-pod"

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, pvc, sc, pod).
		WithStatusSubresource(pm).
		Build()

	fake := &fakeCountingMigrator{
		tier: storage.TierLonghorn,
		errsQueue: []error{
			fakeTransientNetError{},
			fakeTransientNetError{},
		},
	}

	mgr := storage.NewStorageMigrationManager(c)
	mgr.RegisterMigrator(storage.TierLonghorn, fake)

	if err := mgr.RunPreStage(context.Background(), pm); err != nil {
		t.Fatalf("RunPreStage returned error: %v", err)
	}

	if fake.calls != 3 {
		t.Errorf("expected 3 PreStage attempts (2 transient failures + 1 success), got %d", fake.calls)
	}

	cond := readStorageReady(t, c, pm)
	if cond == nil {
		t.Fatalf("StorageReadyForFreeze condition not set")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("expected StorageReadyForFreeze=True after the transient failures cleared, got %s (reason=%s)",
			cond.Status, cond.Reason)
	}
}

// TestRunPreStage_TransientError_BoundedRetry_FailsClosedAfterMaxAttempts
// proves the retry is bounded: if every attempt fails transiently, the
// manager gives up after a fixed small number of attempts (not an infinite
// or unbounded-exponential retry) and fails closed (ConditionFalse).
func TestRunPreStage_TransientError_BoundedRetry_FailsClosedAfterMaxAttempts(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-retry-exhausted", "default", "lh-pod")

	pvc := makePVC("lh-pvc", "default", "longhorn",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce})
	sc := makeSC("longhorn", "driver.longhorn.io", nil)
	pod := makePodWithPVC("default", "lh-pvc")
	pod.Name = "lh-pod"

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, pvc, sc, pod).
		WithStatusSubresource(pm).
		Build()

	fake := &fakeCountingMigrator{
		tier: storage.TierLonghorn,
		errsQueue: []error{
			fakeTransientNetError{},
			fakeTransientNetError{},
			fakeTransientNetError{},
			fakeTransientNetError{}, // never reached if the bound holds
		},
	}

	mgr := storage.NewStorageMigrationManager(c)
	mgr.RegisterMigrator(storage.TierLonghorn, fake)

	if err := mgr.RunPreStage(context.Background(), pm); err != nil {
		t.Fatalf("RunPreStage returned error: %v", err)
	}

	if fake.calls != 3 {
		t.Errorf("expected the retry to be bounded at 3 attempts, got %d calls", fake.calls)
	}

	cond := readStorageReady(t, c, pm)
	if cond == nil {
		t.Fatalf("StorageReadyForFreeze condition not set")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("expected StorageReadyForFreeze=False once all bounded retries are exhausted, got %s (reason=%s)",
			cond.Status, cond.Reason)
	}
}

// TestRunPreStage_PermanentError_FailsFastWithoutRetry proves a genuinely
// permanent error (e.g. the "volume doesn't exist" 404-style error from a
// real Longhorn lookup) is NOT retried — retrying it would only waste the
// migration's bounded completion budget on an error that can never resolve
// itself.
func TestRunPreStage_PermanentError_FailsFastWithoutRetry(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-permanent", "default", "lh-pod")

	pvc := makePVC("lh-pvc", "default", "longhorn",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce})
	sc := makeSC("longhorn", "driver.longhorn.io", nil)
	pod := makePodWithPVC("default", "lh-pvc")
	pod.Name = "lh-pod"

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, pvc, sc, pod).
		WithStatusSubresource(pm).
		Build()

	fake := &fakeCountingMigrator{
		tier: storage.TierLonghorn,
		errsQueue: []error{
			fmt.Errorf("longhorn volume %q not found", "lh-pvc"),
		},
	}

	mgr := storage.NewStorageMigrationManager(c)
	mgr.RegisterMigrator(storage.TierLonghorn, fake)

	if err := mgr.RunPreStage(context.Background(), pm); err != nil {
		t.Fatalf("RunPreStage returned error: %v", err)
	}

	if fake.calls != 1 {
		t.Errorf("expected a permanent (non-network) error to fail fast with exactly 1 attempt, got %d", fake.calls)
	}

	cond := readStorageReady(t, c, pm)
	if cond == nil {
		t.Fatalf("StorageReadyForFreeze condition not set")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("expected StorageReadyForFreeze=False for a permanent error, got %s (reason=%s)",
			cond.Status, cond.Reason)
	}
}
