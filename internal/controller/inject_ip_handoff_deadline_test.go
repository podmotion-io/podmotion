/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"testing"
	"time"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestInjectIPHandoff_DeadlineExceeded verifies that injectIPHandoff transitions the
// PodMigration to RollingBack when replVethMAC has not been written within the
// macWritebackDeadlineSec window (ADR-0133 D3 / ADR-0157 D3).
func TestInjectIPHandoff_DeadlineExceeded(t *testing.T) {
	// Arrange: a migration in OverlayHandoff phase with SourcePodIP set but ReplVethMAC empty.
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-migration-deadline",
			Namespace: "default",
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "redis-0",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
			SourcePodIP:         "10.244.1.50",
		},
		Status: pmv1.PodMigrationStatus{
			Phase:       pmv1.MigrationPhaseOverlayHandoff,
			ReplVethMAC: "", // MAC not yet written — simulates NRI plugin lag
		},
	}

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pm).
		Build()

	r := &PodMigrationReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	// Seed the firstSeen timestamp to 35 seconds ago — past the 30s deadline.
	migrationKey := pm.Name
	macWritebackFirstSeen.Store(migrationKey, time.Now().Add(-35*time.Second))

	// Override nowFn so the deadline calculation uses the same wall clock as the seed above.
	origNow := nowFn
	nowFn = time.Now
	defer func() {
		nowFn = origNow
		macWritebackFirstSeen.Delete(migrationKey)
	}()

	// Act
	result, err, handled := r.injectIPHandoff(context.Background(), pm)
	_ = result

	// Assert: deadline branch must have triggered — no requeue error, not handled (forwarded
	// to RollingBack), and the condition RestoreTimedOut must be set on the in-memory pm.
	if err != nil {
		t.Fatalf("expected nil error from deadline transition; got: %v", err)
	}
	if handled {
		t.Error("expected handled=false (deadline path transitions to RollingBack, not done)")
	}

	// The condition must be set on the in-memory pm object before the status update.
	timedOut := false
	for _, cond := range pm.Status.Conditions {
		if cond.Type == conditionRestoreTimedOut && cond.Status == metav1.ConditionTrue {
			timedOut = true
			break
		}
	}
	if !timedOut {
		t.Errorf("expected conditionRestoreTimedOut=True on pm.Status.Conditions after deadline; got: %v", pm.Status.Conditions)
	}
}
