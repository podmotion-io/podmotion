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

func newSchemeForADR0325(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	return scheme
}

// TestReconcileServiceVerifying_NoneMode_AdvancesOnWorkloadLivenessAlone_WithoutDataplaneReachability
// is the regression test for the ADR-0325 None-mode CutoverComplete gating change in
// reconcileServiceVerifying. Mode=None never sets DataplaneReachabilityVerified (injectIPHandoff
// is skipped for None — the old-IP cross-node nonce probe is structurally inapplicable), so
// requiring it, as the pre-ADR-0325 code did, permanently deadlocked every None migration in
// ServiceVerifying. This test asserts that with NO known application-probe protocol resolved
// (zero container ports declared, no spec.applicationProbe) — the "NoKnownProtocol" transport-only
// path — a None-mode migration advances to CutoverComplete WITHOUT DataplaneReachabilityVerified
// ever being set True.
func TestReconcileServiceVerifying_NoneMode_AdvancesOnWorkloadLivenessAlone_WithoutDataplaneReachability(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := newSchemeForADR0325(t)

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "dst-pod", Namespace: "default", UID: "uid-none-1-dst"},
		Spec:       corev1.PodSpec{NodeName: "dst-node"}, // no container ports -> zeroMatch, no ApplicationProbe -> NoKnownProtocol
		Status:     corev1.PodStatus{PodIP: "10.0.1.2"},
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-none-cutover-1", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
			TargetNodeName:      "dst-node",
			// ApplicationProbe deliberately nil -> zeroMatch && ApplicationProbe==nil -> NoKnownProtocol
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseServiceVerifying,
			SourceNodeName:      "src-node",
			DestinationNodeName: "dst-node",
			ReplacementPodName:  "dst-pod",
			// No conditions at all — DataplaneReachabilityVerified is deliberately ABSENT/never True,
			// which is exactly the real-world state for every None-mode migration.
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, destPod).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	res, err := r.reconcileServiceVerifying(ctx, pm)
	if err != nil {
		t.Fatalf("reconcileServiceVerifying returned unexpected error: %v", err)
	}
	_ = res

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "test-none-cutover-1", Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}

	if meta.IsStatusConditionTrue(fresh.Status.Conditions, conditionDataplaneReachabilityVerified) {
		t.Fatalf("test setup invariant violated: DataplaneReachabilityVerified became True; this test requires it to remain unset for None mode")
	}

	if fresh.Status.Phase != pmv1.MigrationPhaseCutoverComplete {
		t.Fatalf("None-mode migration with NoKnownProtocol liveness did not advance to CutoverComplete: got phase=%s, want %s (ADR-0325 None-mode gate must not require DataplaneReachabilityVerified)",
			fresh.Status.Phase, pmv1.MigrationPhaseCutoverComplete)
	}
}

// TestReconcileServiceVerifying_StrictMode_BlocksOnMissingDataplaneReachability_NoVerifier is the
// paired negative test proving the ADR-0325 None-mode shortcut (the early return keyed on
// `noneMode`) is NOT taken for Strict mode. Strict mode with no TrafficVerifier wired is a hard
// controller misconfiguration and MUST requeue rather than reach CutoverComplete — regardless of
// WorkloadLivenessVerified/DataplaneReachabilityVerified state. This pins the mode-scoping of the
// `if noneMode { ... } else if ... ` branch added by ADR-0325: it must not silently broaden to
// Strict.
func TestReconcileServiceVerifying_StrictMode_BlocksOnMissingDataplaneReachability_NoVerifier(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := newSchemeForADR0325(t)

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "dst-pod-strict", Namespace: "default", UID: "uid-strict-1-dst"},
		Spec:       corev1.PodSpec{NodeName: "dst-node"},
		Status:     corev1.PodStatus{PodIP: "10.0.1.3"},
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-strict-cutover-1", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod-strict",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
			TargetNodeName:      "dst-node",
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseServiceVerifying,
			SourceNodeName:      "src-node",
			DestinationNodeName: "dst-node",
			ReplacementPodName:  "dst-pod-strict",
			// DataplaneReachabilityVerified deliberately absent.
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, destPod).
		WithStatusSubresource(pm).
		Build()

	// No TrafficVerifier wired: Strict mode must treat this as a hard block, never silently proceed.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	res, err := r.reconcileServiceVerifying(ctx, pm)
	if err != nil {
		t.Fatalf("reconcileServiceVerifying returned unexpected error: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("Strict mode with no TrafficVerifier wired and no DataplaneReachabilityVerified must requeue rather than proceed, got RequeueAfter=%v", res.RequeueAfter)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "test-strict-cutover-1", Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}

	if fresh.Status.Phase == pmv1.MigrationPhaseCutoverComplete {
		t.Fatalf("Strict-mode migration advanced to CutoverComplete without a wired TrafficVerifier / DataplaneReachabilityVerified — the ADR-0325 None-mode shortcut must not leak into Strict mode")
	}
}

// TestEnsureWorkloadLivenessVerified_AlreadyVerified_ShortCircuitsWithoutFetch asserts the
// idempotency guard at the top of ensureWorkloadLivenessVerified: when
// ConditionWorkloadLivenessVerified is already True, the function returns verified=true
// immediately without requiring a destination pod to exist (proves the short-circuit runs
// before any Get call).
func TestEnsureWorkloadLivenessVerified_AlreadyVerified_ShortCircuitsWithoutFetch(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := newSchemeForADR0325(t)

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-already-verified", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod-av",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
		},
		Status: pmv1.PodMigrationStatus{
			ReplacementPodName: "dst-pod-does-not-exist",
			Conditions: []metav1.Condition{
				cond(string(pmv1.ConditionWorkloadLivenessVerified), metav1.ConditionTrue),
			},
		},
	}

	// Deliberately do NOT create the destination pod — if the short-circuit did not fire first,
	// the subsequent r.Get would fail and the function would return verified=false.
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	verified, res := r.ensureWorkloadLivenessVerified(ctx, pm)
	if !verified {
		t.Fatalf("ensureWorkloadLivenessVerified: expected verified=true via already-True short-circuit, got false (res=%v)", res)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("ensureWorkloadLivenessVerified: already-verified short-circuit should not request a requeue, got RequeueAfter=%v", res.RequeueAfter)
	}
}

// TestEnsureWorkloadLivenessVerified_DestPodFetchError_RequeuesFalse asserts that when the
// destination pod cannot be fetched, the function fails closed: verified=false and a positive
// RequeueAfter, never a silent true.
func TestEnsureWorkloadLivenessVerified_DestPodFetchError_RequeuesFalse(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := newSchemeForADR0325(t)

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-fetch-error", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod-fe",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
		},
		Status: pmv1.PodMigrationStatus{
			ReplacementPodName: "dst-pod-missing",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm). // destination pod NOT created
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	verified, res := r.ensureWorkloadLivenessVerified(ctx, pm)
	if verified {
		t.Fatalf("ensureWorkloadLivenessVerified: expected verified=false when destination pod fetch fails, got true")
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("ensureWorkloadLivenessVerified: expected a positive RequeueAfter on destination pod fetch failure, got %v", res.RequeueAfter)
	}
}

// TestEnsureWorkloadLivenessVerified_NoKnownProtocol_SetsTrueWithoutAgentPool asserts the
// transport-only (NoKnownProtocol) path sets WorkloadLivenessVerified=True and does not require
// AgentPool to be wired (no RPC needed).
func TestEnsureWorkloadLivenessVerified_NoKnownProtocol_SetsTrueWithoutAgentPool(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := newSchemeForADR0325(t)

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "dst-pod-nk", Namespace: "default", UID: "uid-nk-dst"},
		Spec:       corev1.PodSpec{NodeName: "dst-node"},
		Status:     corev1.PodStatus{PodIP: "10.0.1.9"},
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-no-known-protocol", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod-nk",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
		},
		Status: pmv1.PodMigrationStatus{
			ReplacementPodName: "dst-pod-nk",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, destPod).
		WithStatusSubresource(pm).
		Build()

	// AgentPool deliberately nil — if the NoKnownProtocol branch incorrectly tried to reach an
	// agent, this would panic/fail rather than short-circuit to verified=true.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, AgentPool: nil}
	ctx := context.Background()

	verified, _ := r.ensureWorkloadLivenessVerified(ctx, pm)
	if !verified {
		t.Fatalf("ensureWorkloadLivenessVerified: expected verified=true for NoKnownProtocol transport-only path, got false")
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "test-no-known-protocol", Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionWorkloadLivenessVerified) {
		t.Fatalf("ensureWorkloadLivenessVerified: ConditionWorkloadLivenessVerified was not persisted True for the NoKnownProtocol path")
	}
}
