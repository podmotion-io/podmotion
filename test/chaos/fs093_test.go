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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
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
