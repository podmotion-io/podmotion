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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestReconcileServiceVerifying_WorkloadLivenessFailure_RequeuesNotRollback_NonStrict is the
// scope-mandated regression test for ADR-0325 (real workload-liveness gate). It asserts the
// specific safety invariant every reviewer flagged as unproven: when the workload-liveness probe
// cannot be completed/passes as failed in NON-STRICT (BestEffort/None) mode, reconcileServiceVerifying
// MUST requeue and MUST NOT trigger rollback (initiateRollback/MigrationPhaseRollingBack) or delete
// the source pod. Converting a transient probe failure into a destructive rollback would violate
// ADR-0012 (source pod never deleted until verified) by causing needless churn/destructive action
// on a merely-retryable condition, and would regress the "requeue, don't rollback" contract that
// Strict-mode failures alone are permitted to trigger (see the TrafficVerifier-error branch above,
// which explicitly reserves initiateRollback for Strict mode only).
//
// This drives the real reconcileServiceVerifying path (not a hand-rolled reimplementation): the
// AgentPool is deliberately left nil, which is the exact "cannot complete the liveness probe" case
// documented at podmigration_controller.go (ServiceVerifying: AgentPool not wired — requeuing).
// Because the destination pod resolves a known protocol (an explicit spec.applicationProbe), the
// idempotency guard's !alreadyVerified branch is entered and the AgentPool-nil guard fires before
// any RPC — the same code path a real probe failure/timeout would also hit on retry starvation.
func TestReconcileServiceVerifying_WorkloadLivenessFailure_RequeuesNotRollback_NonStrict(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "default", UID: "uid-liveness-1"},
		Spec:       corev1.PodSpec{NodeName: "src-node"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.1"},
	}
	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "dst-pod", Namespace: "default", UID: "uid-liveness-1-dst"},
		Spec:       corev1.PodSpec{NodeName: "dst-node"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.2"},
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-liveness-1", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeBestEffort, // non-Strict
			TargetNodeName:      "dst-node",
			ApplicationProbe: &pmv1.ApplicationProbeSpec{
				Protocol: pmv1.ApplicationProbeProtocolSQL,
				Port:     5432,
			},
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseVerifying,
			SourceNodeName:      "src-node",
			DestinationNodeName: "dst-node",
			ReplacementPodName:  "dst-pod",
			Conditions: []metav1.Condition{
				cond(conditionDataplaneReachabilityVerified, metav1.ConditionTrue),
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod, destPod).
		WithStatusSubresource(pm).
		Build()

	// AgentPool deliberately nil: this is the "cannot complete the workload-liveness probe" case.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, AgentPool: nil}
	ctx := context.Background()

	res, err := r.reconcileServiceVerifying(ctx, pm)
	if err != nil {
		t.Fatalf("reconcileServiceVerifying returned unexpected error: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("workload-liveness probe unavailable in non-Strict mode: expected a positive RequeueAfter, got %v (must requeue, not silently proceed or terminate)", res)
	}

	// The source pod MUST NOT have been deleted as a side effect of the probe being unresolved.
	gotSrc := &corev1.Pod{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "src-pod", Namespace: "default"}, gotSrc); err != nil {
		t.Fatalf("source pod was deleted/unreachable after an unresolved workload-liveness probe (requeue-not-rollback invariant broken): %v", err)
	}

	// The PodMigration MUST NOT have been driven into RollingBack/Failed as a result of a
	// retryable, non-Strict liveness-probe gap — that is reserved for Strict-mode hard failures.
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "test-liveness-1", Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}
	if fresh.Status.Phase == pmv1.MigrationPhaseRollingBack || fresh.Status.Phase == pmv1.MigrationPhaseFailed {
		t.Fatalf("non-Strict workload-liveness probe gap incorrectly triggered rollback/failure: phase=%s, want requeue-in-place (still Verifying)", fresh.Status.Phase)
	}

	// WorkloadLivenessVerified must not have been forced True by an unresolved probe attempt.
	if meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionWorkloadLivenessVerified) {
		t.Fatalf("WorkloadLivenessVerified was set True despite the probe never completing (AgentPool nil) — gate would falsely permit source-pod deletion")
	}
}
