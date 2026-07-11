/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// cond builds a True/False status condition for the delete-gate tests.
func cond(condType string, status metav1.ConditionStatus) metav1.Condition {
	return metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             "TestSeeded",
		Message:            "seeded for source-pod-delete gate test",
		LastTransitionTime: metav1.Now(),
	}
}

// TestSourcePodDeletionBlockReason is the FALSIFIABLE contract test the panel demanded for
// item B-06 (invariant-1 / ADR-0012): the single deleteSourcePodIfSafe primitive must carry
// the STRICTER union of the two drifted gates. In particular, the source pod must NOT be
// deletable under Strict OR BestEffort until TCPSequenceContinuityVerified=True.
//
// This is the "test that would have caught the bug": the WEAK Verifying gate (formerly
// controller:3853-3862) evaluated ONLY DataplaneReachabilityVerified (Strict) or TrafficVerified
// (non-Strict) and NEVER re-checked TCPSequenceContinuityVerified. Against that weak logic the
// BestEffort-without-TCP-continuity and Strict-without-TCP-continuity cases below would have been
// (wrongly) ALLOWED — this test asserts they are BLOCKED. It fails against the pre-change logic.
func TestSourcePodDeletionBlockReason(t *testing.T) {
	tests := []struct {
		name       string
		mode       pmv1.TCPPreservationMode
		conditions []metav1.Condition
		wantBlock  bool // true => deletion must be refused (non-empty block reason)
	}{
		{
			// Strict, all predicates satisfied → allowed.
			name: "Strict_AllPredicates_Allowed",
			mode: pmv1.TCPPreservationModeStrict,
			conditions: []metav1.Condition{
				cond(conditionDataplaneReachabilityVerified, metav1.ConditionTrue),
				cond(pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionTrue),
				cond(pmv1.ConditionWorkloadLivenessVerified, metav1.ConditionTrue),
			},
			wantBlock: false,
		},
		{
			// Strict, dataplane gate passed but TCP-continuity NOT verified → MUST block.
			// The pre-change weak Verifying gate would have ALLOWED this (bug).
			name: "Strict_DataplaneOK_NoTCPContinuity_Blocked",
			mode: pmv1.TCPPreservationModeStrict,
			conditions: []metav1.Condition{
				cond(conditionDataplaneReachabilityVerified, metav1.ConditionTrue),
			},
			wantBlock: true,
		},
		{
			// Strict, no dataplane reachability → MUST block.
			name: "Strict_NoDataplane_Blocked",
			mode: pmv1.TCPPreservationModeStrict,
			conditions: []metav1.Condition{
				cond(pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionTrue),
			},
			wantBlock: true,
		},
		{
			// BestEffort, traffic + TCP-continuity verified → allowed.
			name: "BestEffort_TrafficAndTCP_Allowed",
			mode: pmv1.TCPPreservationModeBestEffort,
			conditions: []metav1.Condition{
				cond(conditionTrafficVerified, metav1.ConditionTrue),
				cond(pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionTrue),
				cond(pmv1.ConditionWorkloadLivenessVerified, metav1.ConditionTrue),
			},
			wantBlock: false,
		},
		{
			// BestEffort, traffic verified but TCP-continuity NOT verified → MUST block.
			// THIS is the exact drift the weak Verifying gate allowed: it deleted the source
			// pod on TrafficVerified alone. This case MUST be blocked now.
			name: "BestEffort_TrafficOK_NoTCPContinuity_Blocked",
			mode: pmv1.TCPPreservationModeBestEffort,
			conditions: []metav1.Condition{
				cond(conditionTrafficVerified, metav1.ConditionTrue),
			},
			wantBlock: true,
		},
		{
			// None (cold/stateless): TrafficVerified is the only predicate; no TCP-continuity
			// requirement. Verified → allowed.
			name: "None_TrafficVerified_Allowed",
			mode: pmv1.TCPPreservationModeNone,
			conditions: []metav1.Condition{
				cond(conditionTrafficVerified, metav1.ConditionTrue),
				cond(pmv1.ConditionWorkloadLivenessVerified, metav1.ConditionTrue),
			},
			wantBlock: false,
		},
		{
			// None, TrafficVerified not set → block.
			name:       "None_NoTraffic_Blocked",
			mode:       pmv1.TCPPreservationModeNone,
			conditions: []metav1.Condition{},
			wantBlock:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason := sourcePodDeletionBlockReason(tc.mode, tc.conditions)
			gotBlock := reason != ""
			if gotBlock != tc.wantBlock {
				t.Errorf("mode=%s: sourcePodDeletionBlockReason blocked=%v (reason=%q), want blocked=%v",
					tc.mode, gotBlock, reason, tc.wantBlock)
			}
		})
	}
}

// TestDeleteSourcePodIfSafe_BestEffortWithoutTCPContinuity is the reconciler-level contract test:
// driving deleteSourcePodIfSafe under BestEffort with TrafficVerified=True but
// TCPSequenceContinuityVerified NOT set MUST refuse to delete the source pod (blocked=true, pod
// survives). Under the pre-change weak Verifying gate this deletion would have proceeded — this
// asserts invariant-1: the source pod is NOT deleted until TCPSequenceContinuityVerified=True.
func TestDeleteSourcePodIfSafe_BestEffortWithoutTCPContinuity(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "default", UID: "uid-b06"},
		Spec:       corev1.PodSpec{NodeName: "src-node"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.1"},
	}

	// BestEffort: TrafficVerified=True (the weak gate's only predicate) but
	// TCPSequenceContinuityVerified is absent → the STRICTER union must block.
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-b06", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeBestEffort,
			TargetNodeName:      "dst-node",
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseVerifying,
			SourceNodeName:      "src-node",
			DestinationNodeName: "dst-node",
			Conditions: []metav1.Condition{
				cond(conditionTrafficVerified, metav1.ConditionTrue),
				// TCPSequenceContinuityVerified deliberately NOT set.
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	blocked, _ := r.deleteSourcePodIfSafe(ctx, pm)
	if !blocked {
		t.Fatalf("BestEffort without TCPSequenceContinuityVerified: deleteSourcePodIfSafe returned blocked=false — source pod would be deleted without TCP-continuity proof (invariant-1/ADR-0012 break)")
	}

	// The source pod MUST still exist.
	got := &corev1.Pod{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "src-pod", Namespace: "default"}, got); err != nil {
		t.Fatalf("source pod was deleted despite TCPSequenceContinuityVerified not being True: %v", err)
	}

	// Now set TCPSequenceContinuityVerified=True and confirm the gate opens and the pod is deleted.
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "test-b06", Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}
	fresh.Status.Conditions = append(fresh.Status.Conditions,
		cond(pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionTrue),
		cond(pmv1.ConditionWorkloadLivenessVerified, metav1.ConditionTrue))
	if err := fakeClient.Status().Update(ctx, fresh); err != nil {
		t.Fatalf("Status().Update seeding TCPSequenceContinuityVerified: %v", err)
	}

	blocked2, _ := r.deleteSourcePodIfSafe(ctx, fresh)
	if blocked2 {
		t.Fatalf("BestEffort WITH TCPSequenceContinuityVerified=True: deleteSourcePodIfSafe still blocked — gate over-restrictive")
	}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "src-pod", Namespace: "default"}, got); err == nil {
		t.Fatalf("source pod still present after gate opened — deleteSourcePodIfSafe did not delete it")
	}
}
