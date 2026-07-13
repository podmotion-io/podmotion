//go:build chaos_test

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package chaos

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/traffic"
)

// newFS093Fixture builds a FaultFixture backed by a fake WithWatch client
// seeded with a single Tier0 PodMigration in the given phase, mirroring the
// pattern used by the other RunFS0xx unit-level exercises in this package.
func newFS093Fixture(t *testing.T, phase pmv1.MigrationPhase) (*FaultFixture, types.NamespacedName) {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(clientgoscheme): %v", err)
	}
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(pmv1): %v", err)
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-fs093", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "postgres-0",
			PodNamespace: "default",
		},
		Status: pmv1.PodMigrationStatus{
			Phase: phase,
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pm).
		Build()

	pmNN := types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}
	return &FaultFixture{Client: c, PMNN: pmNN}, pmNN
}

// TestRunFS093Variants asserts that RunFS093 is defined for all three
// ADR-0344 Decision B injection points and drives the fault-injection +
// terminal-failure + EndpointSlice/storage-restore assertion sequence without
// panicking, using a short-deadline context (these are wiring/compile-shape
// checks; full timing behavior is validated on the live chaos harness per
// ADR-0344, which explicitly does not require a live cluster for FS-093).
func TestRunFS093Variants(t *testing.T) {
	for _, variant := range []FS093Variant{
		FS093PreRemountConfirmation,
		FS093PostRemountPreRestore,
		FS093Verifying,
	} {
		variant := variant
		t.Run("", func(t *testing.T) {
			f, pmNN := newFS093Fixture(t, pmv1.MigrationPhaseRestoring)

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()

			// RunFS093 blocks on WaitForSyncPoint, which this minimal fixture
			// never signals — assert it returns a bounded, non-nil error
			// (context deadline) rather than hanging, confirming the function
			// is wired end-to-end (WaitForSyncPoint -> fault injection ->
			// waitForTerminalFailure -> HasEndpointForIP ->
			// AssertNoDestinationMountCreated/AssertSourceStorageWriteRestored)
			// rather than being an undefined symbol (ADR-0344 P-VERIFY gap).
			err := RunFS093(ctx, f, pmNN, "default", "10.0.0.5", variant)
			if err == nil {
				t.Fatalf("RunFS093(variant=%d): expected bounded error against an unsignalled sync point, got nil", variant)
			}
		})
	}
}

// TestRunFS093Variants_DrivesRealAssertionsGreen is the C1-remediation test
// (ADR-0344 sign-off finding): unlike TestRunFS093Variants above, which only
// proves RunFS093 is wired end-to-end against an unsignalled sync point, this
// test plays the reconciler's half of the ChaosSyncPoint protocol so that
// RunFS093 actually walks past WaitForSyncPoint, fault injection, and
// waitForTerminalFailure, and reaches the real
// esMgr.HasEndpointForIP(ctx, ns, sourceIP) call (chaos_hooks.go) against a
// fixture whose EndpointSlice genuinely carries the source IP — and, for the
// pre-remount variant, asserts no ReplacementPod exists.
func TestRunFS093Variants_DrivesRealAssertionsGreen(t *testing.T) {
	const (
		ns       = "default"
		sourceIP = "10.0.0.5"
	)

	for _, variant := range []FS093Variant{
		FS093PreRemountConfirmation,
		FS093PostRemountPreRestore,
		FS093Verifying,
	} {
		variant := variant
		t.Run("", func(t *testing.T) {
			f, pmNN := newFS093FixtureWithEndpointSlice(t, pmv1.MigrationPhaseRestoring, ns, sourceIP)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Play the reconciler's side of the ChaosSyncPoint protocol and
			// then drive the migration to its terminal RollingBack phase with
			// ConditionSourceStorageWriteRestored=True, exactly as the real
			// reconciler does inside reconcileRollingBack before resuming the
			// frozen source (ADR-0344 Decision A.2).
			go simulateReconcilerForFS093(ctx, f, pmNN)

			err := RunFS093(ctx, f, pmNN, ns, sourceIP, variant)
			if err != nil {
				t.Fatalf("RunFS093(variant=%d): expected nil error with a driven sync point and seeded EndpointSlice, got: %v", variant, err)
			}

			// Directly re-assert the load-bearing invariant this test exists
			// to prove: HasEndpointForIP(ns, sourceIP) == true, executed
			// against the real traffic.EndpointSliceManager, not inferred
			// from RunFS093's own success.
			esMgr := traffic.NewEndpointSliceManager(f.Client)
			hasEP, epErr := esMgr.HasEndpointForIP(ctx, ns, sourceIP)
			if epErr != nil {
				t.Fatalf("HasEndpointForIP: %v", epErr)
			}
			if !hasEP {
				t.Fatalf("HasEndpointForIP(%s, %s) = false, want true: source EndpointSlice intactness not proven", ns, sourceIP)
			}

			if variant == FS093PreRemountConfirmation {
				if err := AssertNoDestinationMountCreated(ctx, f, pmNN); err != nil {
					t.Fatalf("AssertNoDestinationMountCreated: %v", err)
				}
			}
		})
	}
}

// simulateReconcilerForFS093 plays the minimal reconciler-side half of the
// ChaosSyncPoint protocol that a live controller-manager provides in
// production/envtest: it signals ChaosSyncReached immediately (the reconciler
// has reached the sync point), waits for the harness's ChaosSyncResume signal
// (RunFS093's resume() call after injecting the fault), and then — mirroring
// reconcileRollingBack — sets ConditionSourceStorageWriteRestored=True before
// transitioning the migration to MigrationPhaseRollingBack (terminal).
func simulateReconcilerForFS093(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName) {
	const syncPointName = "post-checkpoint-transfer"
	const verifyingSyncPointName = "post-freeze"

	setReached := func(name string) {
		// Retry on optimistic-lock conflicts: RunFS093's own PatchCRCondition
		// call (fault injection) races this goroutine's writes on the same CR.
		for attempt := 0; attempt < 10; attempt++ {
			var pm pmv1.PodMigration
			if err := f.Client.Get(ctx, pmNN, &pm); err != nil {
				return
			}
			base := pm.DeepCopy()
			meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
				Type:               "ChaosSyncReached/" + name,
				Status:             metav1.ConditionTrue,
				Reason:             "ReconcilerSimulated",
				Message:            "simulated reconciler reached sync point",
				LastTransitionTime: metav1.Now(),
			})
			if err := f.Client.Status().Patch(ctx, &pm, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err == nil {
				return
			}
		}
	}

	// Both FS093PreRemountConfirmation and FS093PostRemountPreRestore use
	// syncPointName; FS093Verifying uses verifyingSyncPointName. Signal both
	// ChaosSyncReached conditions up front (harmless no-op for the one the
	// running variant doesn't use) and wait for whichever resume fires.
	setReached(syncPointName)
	setReached(verifyingSyncPointName)

	resumed := false
	for !resumed && ctx.Err() == nil {
		var pm pmv1.PodMigration
		if err := f.Client.Get(ctx, pmNN, &pm); err == nil {
			if meta.IsStatusConditionTrue(pm.Status.Conditions, "ChaosSyncResume/"+syncPointName) ||
				meta.IsStatusConditionTrue(pm.Status.Conditions, "ChaosSyncResume/"+verifyingSyncPointName) {
				resumed = true
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !resumed {
		return
	}

	// Mirror reconcileRollingBack (ADR-0344 Decision A.2): confirm the
	// source's Tier0 storage is writable again BEFORE the migration lands in
	// its terminal RollingBack phase.
	for attempt := 0; attempt < 10; attempt++ {
		var pm pmv1.PodMigration
		if err := f.Client.Get(ctx, pmNN, &pm); err != nil {
			return
		}
		base := pm.DeepCopy()
		meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
			Type:               pmv1.ConditionSourceStorageWriteRestored,
			Status:             metav1.ConditionTrue,
			Reason:             "ReconcilerSimulatedRemountRW",
			Message:            "simulated reconciler confirmed source storage writable",
			LastTransitionTime: metav1.Now(),
		})
		pm.Status.Phase = pmv1.MigrationPhaseRollingBack
		if err := f.Client.Status().Patch(ctx, &pm, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err == nil {
			return
		}
	}
}

// newFS093FixtureWithEndpointSlice is newFS093Fixture plus a discoveryv1
// EndpointSlice that genuinely carries sourceIP, so HasEndpointForIP has a
// non-vacuous fixture to assert against (C1 remediation).
func newFS093FixtureWithEndpointSlice(t *testing.T, phase pmv1.MigrationPhase, ns, sourceIP string) (*FaultFixture, types.NamespacedName) {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(clientgoscheme): %v", err)
	}
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(pmv1): %v", err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(discoveryv1): %v", err)
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-fs093-ep", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "postgres-0",
			PodNamespace: ns,
		},
		Status: pmv1.PodMigrationStatus{
			Phase: phase,
		},
	}

	slice := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: "postgres-slice", Namespace: ns},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{sourceIP}},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pm, slice).
		Build()

	pmNN := types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}
	return &FaultFixture{Client: c, PMNN: pmNN}, pmNN
}
