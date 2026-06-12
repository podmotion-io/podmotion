/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"bytes"
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestTwelvePhaseTransitions drives a PodMigration through all 12 phases of the ADR-0047
// pipeline and asserts each phase name appears in either the log output or the phase
// sequence observed on the PodMigration status, satisfying the M19 acceptance criterion:
// "mock reconcile shows 12 distinct phase transitions in logs".
//
// All agent-dependent paths (AgentPool, ReplicationMgr, StorageMgr, TrafficVerifier) are
// left nil so fast-path and skip branches are exercised. TCPPreservationMode=None exercises
// the stateless degenerate case (ADR-0047: stateless as degenerate TCPPreservationMode=None).
// Conditions that require a live agent are pre-seeded so each phase advances without
// blocking on external RPCs.
func TestTwelvePhaseTransitions(t *testing.T) {
	var logBuf bytes.Buffer
	logf.SetLogger(zap.New(zap.WriteTo(&logBuf), zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "src-pod",
			Namespace: "default",
			UID:       "test-uid-1",
		},
		Spec: corev1.PodSpec{NodeName: "src-node"},
		Status: corev1.PodStatus{PodIP: "10.0.0.1"},
	}

	nmc := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "src-node"},
		Status:     pmv1.NodeMigrationCapacityStatus{Ready: true},
	}

	now := metav1.Now()
	trueCondition := func(condType string) metav1.Condition {
		return metav1.Condition{
			Type:               condType,
			Status:             metav1.ConditionTrue,
			Reason:             "PreSeeded",
			Message:            "pre-seeded for 12-phase mock test",
			LastTransitionTime: now,
		}
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-12phase",
			Namespace: "default",
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			Mode:                pmv1.MigrationModeCold,
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
			RollbackOnFailure:   true,
			TargetNodeName:      "dst-node",
		},
		Status: pmv1.PodMigrationStatus{
			// Pre-seed all agent-dependent conditions so phases advance without a live agent.
			Conditions: []metav1.Condition{
				trueCondition(conditionCheckpointed),
				trueCondition(conditionRestored),
				trueCondition(conditionTrafficVerified),
				trueCondition(conditionDestinationVolumeReady),
			},
			CheckpointTransferred: true,
			SourceNodeName:        "src-node",
			DestinationNodeName:   "dst-node",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod, nmc).
		WithStatusSubresource(pm, nmc).
		Build()

	r := &PodMigrationReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-12phase", Namespace: "default"}}

	// Track all phases observed on the PodMigration status across reconcile iterations.
	visitedPhases := make(map[pmv1.MigrationPhase]bool)

	const maxIterations = 60
	for i := 0; i < maxIterations; i++ {
		fresh := &pmv1.PodMigration{}
		if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
			t.Fatalf("iteration %d: Get before reconcile: %v", i, err)
		}
		visitedPhases[fresh.Status.Phase] = true

		_, err := r.Reconcile(ctx, req)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}

		if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
			t.Fatalf("iteration %d: Get after reconcile: %v", i, err)
		}
		visitedPhases[fresh.Status.Phase] = true

		phase := fresh.Status.Phase
		if phase == pmv1.MigrationPhaseComplete ||
			phase == pmv1.MigrationPhaseFailed ||
			phase == pmv1.MigrationPhaseDryRunComplete {
			break
		}
	}

	logs := logBuf.String()

	// Each of the 12 phase names must appear either in the phase visit record or in logs.
	expectedPhases := []pmv1.MigrationPhase{
		pmv1.MigrationPhaseSocketInventory,
		pmv1.MigrationPhaseValidating,
		pmv1.MigrationPhaseDestinationPrewarm,
		pmv1.MigrationPhasePreCopyMemory,
		pmv1.MigrationPhaseZeroWindowArm,
		pmv1.MigrationPhaseFinalFreezeStateCapture,
		pmv1.MigrationPhaseOverlayHandoff,
		pmv1.MigrationPhaseRestoreSocketReattach,
		pmv1.MigrationPhaseDisengageHold,
		pmv1.MigrationPhaseTCPVerifying,
		pmv1.MigrationPhaseServiceVerifying,
		pmv1.MigrationPhaseCutoverComplete,
	}

	var missing []string
	for _, phase := range expectedPhases {
		inPhaseMap := visitedPhases[phase]
		inLogs := strings.Contains(logs, string(phase))
		if !inPhaseMap && !inLogs {
			missing = append(missing, string(phase))
		}
	}
	if len(missing) > 0 {
		t.Errorf("12-phase transitions not observed (missing from both phase map and logs): %v\n\nvisited phases: %v\n\nlog output:\n%s",
			missing, visitedPhases, logs)
	}
}
