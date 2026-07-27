/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

// adr0365_fail_closed_test.go covers ADR-0365 Decision §2's fail-closed hardenings at the
// internal/agent/storage layer:
//
//   - item 2 (bounded RunPreStage dispatch): the outer context passed to RunPreStage now
//     actually bounds a hung migrator call, surfacing StorageReadyForFreeze=False with a
//     PreStageTimeout reason instead of hanging forever.
//   - item 3 (empty-DestinationNode guard): LonghornMigrator.PreStage rejects an empty
//     opts.DestinationNode immediately, before issuing any HTTP call to the Longhorn Manager.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

// hangingMigrator's PreStage blocks until ctx is cancelled/expires, then returns ctx.Err() —
// simulating a genuinely-stuck Longhorn call (or any tier migrator) that never resolves on its
// own, the exact scenario ADR-0365 Decision §2.2's bounded dispatch context exists to catch.
type hangingMigrator struct {
	tier storage.StorageTier
}

func (h *hangingMigrator) Tier() storage.StorageTier { return h.tier }

func (h *hangingMigrator) PreStage(ctx context.Context, _ storage.MigrationOptions) error {
	<-ctx.Done()
	return ctx.Err()
}

func (h *hangingMigrator) SyncPercent(_ context.Context, _ storage.MigrationOptions) (int, error) {
	return 0, nil
}

func (h *hangingMigrator) Cutover(_ context.Context, _ storage.MigrationOptions) error { return nil }

func (h *hangingMigrator) AwaitSingleOwner(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}

func (h *hangingMigrator) ReleaseDestination(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}

// TestRunPreStage_HungPreStage_TimeoutSurfacesAsPreStageTimeout is the regression test for
// ADR-0365 Decision §2.2: a genuinely-stuck tier-migrator PreStage call must be bounded by the
// context the caller (the controller's reconcilePreCopyMemory/reconcilePreMigrating dispatch,
// per ADR-0365) passes in — NOT allowed to spin until the 600s top-level completion budget fires
// — and the resulting failure must be phase-attributable (reason "PreStageTimeout"), not a
// generic "PreStageFailed" indistinguishable from any other tier-migrator error.
func TestRunPreStage_HungPreStage_TimeoutSurfacesAsPreStageTimeout(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-hung", "default", "lh-pod")

	pvc := makePVC("lh-pvc", "default", "longhorn-migratable",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany})
	sc := makeSC("longhorn-migratable", "driver.longhorn.io", nil)
	pod := makeOwnedPodWithPVC("default", "lh-pvc")
	pod.Name = "lh-pod"

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, pvc, sc, pod).
		WithStatusSubresource(pm).
		Build()

	mgr := storage.NewStorageMigrationManager(c)
	mgr.RegisterMigrator(storage.TierLonghorn, &hangingMigrator{tier: storage.TierLonghorn})

	// Mirrors what the controller's bounded dispatch does (ADR-0365 Decision §2.2): a real,
	// short deadline on the context passed into RunPreStage — not context.Background().
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := mgr.RunPreStage(ctx, pm, false, ""); err != nil {
		t.Fatalf("RunPreStage returned a transport error (expected it to swallow the timeout into a status patch): %v", err)
	}
	elapsed := time.Since(start)

	// Must return promptly once the bounded context expires — nowhere near the 600s completion
	// budget invariant #8 would otherwise wait out.
	if elapsed > 5*time.Second {
		t.Fatalf("RunPreStage took %s to return after a 200ms context timeout — the hung migrator call was not actually bounded", elapsed)
	}

	cond := readStorageReady(t, c, pm)
	if cond == nil {
		t.Fatalf("StorageReadyForFreeze condition not set")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("expected StorageReadyForFreeze=False after the bounded context expired, got %s", cond.Status)
	}
	if cond.Reason != "PreStageTimeout" {
		t.Errorf("expected reason %q (phase-attributable, distinguishable from a generic tier-migrator "+
			"failure or the outer completion-budget wedge) — got %q (message=%q)",
			"PreStageTimeout", cond.Reason, cond.Message)
	}
}

// TestLonghornMigrator_PreStage_EmptyDestinationNode_FailsClosedNoHTTPCall is the regression test
// for ADR-0365 Decision §2 item 3: an empty opts.DestinationNode must be rejected at the top of
// PreStage, before any HTTP call reaches the Longhorn Manager API (which — pre-fix — silently
// accepted nodeSelector:[""] and depended on Longhorn's own unverified handling of it).
func TestLonghornMigrator_PreStage_EmptyDestinationNode_FailsClosedNoHTTPCall(t *testing.T) {
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dialed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	mig := storage.NewLonghornMigrator(srv.URL, c)

	opts := storage.MigrationOptions{
		MigrationName:   "mig-empty-dest",
		PodNamespace:    "default",
		DestinationNode: "", // the guard under test
		Classifications: []storage.TierClassification{
			{Tier: storage.TierLonghorn, PVCName: "irrelevant-pvc"},
		},
	}

	err := mig.PreStage(context.Background(), opts)
	if err == nil {
		t.Fatalf("expected PreStage to reject an empty DestinationNode, got nil error")
	}
	if dialed {
		t.Errorf("PreStage dialed the Longhorn Manager API with an empty DestinationNode — must fail closed before issuing any HTTP call")
	}
}

// TestRunPreStage_EmptyDestinationNode_SurfacesAsEmptyDestinationNodeCondition proves the guard's
// error is surfaced through RunPreStage's existing error-handling path with the distinct
// "EmptyDestinationNode" reason the ADR names, not a generic "PreStageFailed".
func TestRunPreStage_EmptyDestinationNode_SurfacesAsEmptyDestinationNodeCondition(t *testing.T) {
	scheme := newManagerScheme(t)
	pm := makeMigration("mig-empty-dest-e2e", "default", "lh-pod")
	pm.Status.DestinationNodeName = "" // the empty-destination case under test

	pvc := makePVC("lh-pvc", "default", "longhorn-migratable",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany})
	sc := makeSC("longhorn-migratable", "driver.longhorn.io", nil)
	pod := makeOwnedPodWithPVC("default", "lh-pvc")
	pod.Name = "lh-pod"

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, pvc, sc, pod).
		WithStatusSubresource(pm).
		Build()

	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dialed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mgr := storage.NewStorageMigrationManager(c)
	mgr.RegisterMigrator(storage.TierLonghorn, storage.NewLonghornMigrator(srv.URL, c))

	if err := mgr.RunPreStage(context.Background(), pm, false, ""); err != nil {
		t.Fatalf("RunPreStage returned a transport error (expected it to swallow the guard error into a status patch): %v", err)
	}
	if dialed {
		t.Errorf("RunPreStage reached the Longhorn Manager API despite an empty DestinationNode")
	}

	cond := readStorageReady(t, c, pm)
	if cond == nil {
		t.Fatalf("StorageReadyForFreeze condition not set")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("expected StorageReadyForFreeze=False, got %s", cond.Status)
	}
	if cond.Reason != "EmptyDestinationNode" {
		t.Errorf("expected reason %q, got %q (message=%q)", "EmptyDestinationNode", cond.Reason, cond.Message)
	}
}
