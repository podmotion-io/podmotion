/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package controller

// inject_ip_handoff_deadline_test.go — E1 Condition 4 regression test:
//
//   - TestInjectIPHandoff_DeadlineExceeded: when CRIURestoreConfirmed=true and replVethMAC
//     is still empty after macWritebackDeadlineSec, injectIPHandoff must transition the
//     migration to RollingBack with reason "MACWritebackDeadlineExceeded".

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestInjectIPHandoff_DeadlineExceeded asserts that injectIPHandoff transitions to
// RollingBack when replVethMAC remains empty for longer than macWritebackDeadlineSec
// (E1 Condition 4). It manipulates macWritebackFirstSeen directly to simulate elapsed
// time, then verifies that the phase transitioned to RollingBack.
func TestInjectIPHandoff_DeadlineExceeded(t *testing.T) {
	// Shorten the deadline so the test runs without sleeping.
	origDeadline := macWritebackDeadlineSec
	macWritebackDeadlineSec = 1 * time.Millisecond
	defer func() {
		macWritebackDeadlineSec = origDeadline
		macWritebackFirstSeen.Delete("test-mac-deadline")
	}()

	confirmed := true
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mac-deadline",
			Namespace: "default",
		},
		Spec: pmv1.PodMigrationSpec{
			SourcePodIP: "10.0.0.1",
		},
		Status: pmv1.PodMigrationStatus{
			CRIURestoreConfirmed: &confirmed,
			ReplVethMAC:          "", // empty — triggering the deadline path
			Phase:                pmv1.MigrationPhaseRestoring,
		},
	}

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	ctx := context.Background()

	// Pre-seed macWritebackFirstSeen with a timestamp well in the past so the deadline
	// triggers immediately.
	macWritebackFirstSeen.Store("test-mac-deadline", time.Now().Add(-10*time.Second))

	// First call to injectIPHandoff: MAC is empty and deadline has elapsed.
	_, _, done := r.injectIPHandoff(ctx, pm)

	// done=true is returned on both deadline-exceeded (transition to RollingBack) and
	// successful injection. The transition path sets the phase to RollingBack.
	if !done {
		t.Fatal("expected done=true after deadline exceeded, got false")
	}

	// transitionTo patches the CR via the k8s client — re-fetch from fake client to verify.
	updated := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(pm), updated); err != nil {
		t.Fatalf("re-fetch after transition: %v", err)
	}
	if updated.Status.Phase != pmv1.MigrationPhaseRollingBack {
		t.Errorf("expected phase=RollingBack after deadline exceeded, got %q", updated.Status.Phase)
	}

	// The condition is set on pm (in-memory) before the statusUpdate/transitionTo calls.
	var found bool
	for _, c := range pm.Status.Conditions {
		if c.Type == conditionIPHandoffInjected && c.Reason == "MACWritebackDeadlineExceeded" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected condition %s with reason MACWritebackDeadlineExceeded; conditions: %+v",
			conditionIPHandoffInjected, pm.Status.Conditions)
	}

	// Verify the deadline entry was cleared.
	if _, ok := macWritebackFirstSeen.Load("test-mac-deadline"); ok {
		t.Error("expected macWritebackFirstSeen entry to be deleted after deadline exceeded")
	}
}
