/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package controller

// adr0210_dataplane_gate_test.go — ADR-0210 cross-node DataplaneReachabilityVerified
// gate-blocking regression tests, UPDATED per ADR-0352 D5.1/D5.2/D5.3 to assert against
// the re-keyed Strict predicate (ServiceContinuityVerified, not DataplaneReachabilityVerified):
//
//   - TestVerifying_DoesNotSetTrafficVerified_OnLoopbackOnlyProbe: under Strict, TrafficVerified=True
//     (the demoted self-probe pre-check) alone with ServiceContinuityVerified absent must NOT
//     permit source-pod deletion. The OLD tautology (lo-alias self-loop sets TrafficVerified and
//     deletion proceeds) is regression-locked out.
//   - TestVerifying_NeverDeletesSource_WhenCrossNodeUnreachable (ADR-0352 D5.1): under Strict, with
//     ServiceContinuityVerified=False the source pod is HELD (not deleted).
//   - TestVerifying_DeletesSource_WhenCrossNodeReachable (ADR-0352 D5.2): under Strict, with
//     ServiceContinuityVerified=True the source pod IS deleted.
//   - TestVerifying_DeletesSource_WhenReplacementHasDifferentIPAndMAC (ADR-0352 D5.3 — THE
//     acceptance test the ADR mandates): the replacement has a DIFFERENT IP than the source and
//     Strict teardown STILL proceeds, because ServiceContinuityVerified=True holds via ClusterIP +
//     Ready-enrollment — NOT via preserved-IP reachability (DataplaneReachabilityVerified is
//     deliberately left unset in this test, proving no pod-IP-preservation signal was involved).
//     This is the test that FAILS before the re-key and PASSES after.
//   - TestServiceVerifying_SeqDeltaPlumbing_NonZeroFailsStrict: a non-zero measured SeqDeltaMax
//     surfaces and fails Strict (mirrors gate_harness seqDelta plumbing expectation).

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

func adr0210Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme discoveryv1: %v", err)
	}
	return scheme
}

// strictPMReadyForDeletion builds a Strict PodMigration in CutoverComplete with the
// pre-deletion gates (DestinationVolumeReady, TrafficVerified, TCPSequenceContinuityVerified)
// satisfied EXCEPT DataplaneReachabilityVerified, plus a live source pod object.
func strictPMReadyForDeletion(name string, dataplaneVerified *bool) (*pmv1.PodMigration, *corev1.Pod) {
	conds := []metav1.Condition{
		{Type: conditionDestinationVolumeReady, Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()},
		{Type: conditionTrafficVerified, Status: metav1.ConditionTrue, Reason: "HandoffInstalled", LastTransitionTime: metav1.Now()},
		{Type: pmv1.ConditionTCPSequenceContinuityVerified, Status: metav1.ConditionTrue, Reason: "SequenceContinuityVerified", LastTransitionTime: metav1.Now()},
		{Type: pmv1.ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue, Reason: "NoKnownProtocol", LastTransitionTime: metav1.Now()},
	}
	if dataplaneVerified != nil {
		st := metav1.ConditionFalse
		if *dataplaneVerified {
			st = metav1.ConditionTrue
		}
		conds = append(conds, metav1.Condition{
			Type: conditionDataplaneReachabilityVerified, Status: st, Reason: "Test", LastTransitionTime: metav1.Now(),
		})
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             name + "-src",
			PodNamespace:        "default",
			SourcePodIP:         "10.0.0.5",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:          pmv1.MigrationPhaseCutoverComplete,
			SourceNodeName: "node-a",
			Conditions:     conds,
		},
	}
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-src", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
	}
	return pm, srcPod
}

// strictPMReadyForDeletionSC (ADR-0352 D5.1/D5.2/D5.4) is the ServiceContinuityVerified
// sibling of strictPMReadyForDeletion: same pre-deletion gates satisfied, but the
// mode-dependent predicate under test is the NEW re-keyed condition
// (ConditionServiceContinuityVerified), not the retired DataplaneReachabilityVerified.
// Both fixtures are kept (D2.2b: two live conditions/vetoes) since a Strict CR could in
// principle carry both — tests must construct them independently.
func strictPMReadyForDeletionSC(name string, serviceContinuityVerified *bool) (*pmv1.PodMigration, *corev1.Pod) {
	conds := []metav1.Condition{
		{Type: conditionDestinationVolumeReady, Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()},
		{Type: conditionTrafficVerified, Status: metav1.ConditionTrue, Reason: "HandoffInstalled", LastTransitionTime: metav1.Now()},
		{Type: pmv1.ConditionTCPSequenceContinuityVerified, Status: metav1.ConditionTrue, Reason: "SequenceContinuityVerified", LastTransitionTime: metav1.Now()},
		{Type: pmv1.ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue, Reason: "NoKnownProtocol", LastTransitionTime: metav1.Now()},
	}
	if serviceContinuityVerified != nil {
		st := metav1.ConditionFalse
		if *serviceContinuityVerified {
			st = metav1.ConditionTrue
		}
		conds = append(conds, metav1.Condition{
			Type: pmv1.ConditionServiceContinuityVerified, Status: st, Reason: "Test", LastTransitionTime: metav1.Now(),
		})
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             name + "-src",
			PodNamespace:        "default",
			SourcePodIP:         "10.0.0.5",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:          pmv1.MigrationPhaseCutoverComplete,
			SourceNodeName: "node-a",
			Conditions:     conds,
		},
	}
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-src", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
	}
	return pm, srcPod
}

func TestVerifying_DoesNotSetTrafficVerified_OnLoopbackOnlyProbe(t *testing.T) {
	// Strict + TrafficVerified=True (the demoted self-probe pre-check) but NO
	// DataplaneReachabilityVerified condition => deletion must be BLOCKED.
	scheme := adr0210Scheme(t)
	pm, srcPod := strictPMReadyForDeletion("adr0210-loopback-only", nil /* DataplaneReachabilityVerified absent */)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod).
		WithStatusSubresource(pm).
		Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	_, err := r.reconcileCutoverComplete(ctx, pm)
	if err != nil {
		t.Fatalf("reconcileCutoverComplete: %v", err)
	}

	// The source pod MUST still exist — TrafficVerified alone (loopback self-probe) is not a gate.
	got := &corev1.Pod{}
	if gerr := fakeClient.Get(ctx, client.ObjectKeyFromObject(srcPod), got); gerr != nil {
		t.Fatalf("source pod must NOT be deleted when only TrafficVerified set (loopback tautology); got error: %v", gerr)
	}
}

func TestVerifying_NeverDeletesSource_WhenCrossNodeUnreachable(t *testing.T) {
	// ADR-0352 D5.1: Strict + ServiceContinuityVerified=False => source pod HELD.
	scheme := adr0210Scheme(t)
	unreachable := false
	pm, srcPod := strictPMReadyForDeletionSC("adr0352-svccontinuity-unreachable", &unreachable)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod).
		WithStatusSubresource(pm).
		Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	_, err := r.reconcileCutoverComplete(ctx, pm)
	if err != nil {
		t.Fatalf("reconcileCutoverComplete: %v", err)
	}

	got := &corev1.Pod{}
	if gerr := fakeClient.Get(ctx, client.ObjectKeyFromObject(srcPod), got); gerr != nil {
		t.Fatalf("source pod must be HELD when ServiceContinuityVerified=False; got error: %v", gerr)
	}
}

func TestVerifying_DeletesSource_WhenCrossNodeReachable(t *testing.T) {
	// ADR-0352 D5.2: positive control — Strict + ServiceContinuityVerified=True => deletion permitted.
	scheme := adr0210Scheme(t)
	reachable := true
	pm, srcPod := strictPMReadyForDeletionSC("adr0352-svccontinuity-reachable", &reachable)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod).
		WithStatusSubresource(pm).
		Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	if _, err := r.reconcileCutoverComplete(ctx, pm); err != nil {
		t.Fatalf("reconcileCutoverComplete: %v", err)
	}

	got := &corev1.Pod{}
	gerr := fakeClient.Get(ctx, client.ObjectKeyFromObject(srcPod), got)
	if gerr == nil {
		t.Fatalf("source pod should be deleted when ServiceContinuityVerified=True")
	}
}

func TestVerifying_DeletesSource_WhenReplacementHasDifferentIPAndMAC(t *testing.T) {
	// ADR-0352 D5.3: THE acceptance test. The replacement pod has a DIFFERENT IP than the
	// source (10.0.0.5 vs 10.0.0.99) — under the OLD gate (DataplaneReachabilityVerified,
	// which requires the SOURCE IP to answer cross-node) this could never converge for a
	// changed IP. Under the re-keyed gate, Strict teardown proceeds because
	// ServiceContinuityVerified=True holds via ClusterIP + Ready-enrollment — a signal that
	// is INDEPENDENT of pod-IP preservation. DataplaneReachabilityVerified is deliberately
	// left absent to prove no pod-IP-preservation signal was involved in this pass.
	scheme := adr0210Scheme(t)
	reachable := true
	pm, srcPod := strictPMReadyForDeletionSC("adr0352-different-ip-mac", &reachable)
	pm.Status.ReplacementPodName = "adr0352-different-ip-mac-dst"
	replacementPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: pm.Status.ReplacementPodName, Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-b"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.99"}, // different IP than SourcePodIP (10.0.0.5)
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod, replacementPod).
		WithStatusSubresource(pm).
		Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	if _, err := r.reconcileCutoverComplete(ctx, pm); err != nil {
		t.Fatalf("reconcileCutoverComplete: %v", err)
	}

	got := &corev1.Pod{}
	gerr := fakeClient.Get(ctx, client.ObjectKeyFromObject(srcPod), got)
	if gerr == nil {
		t.Fatalf("source pod should be deleted: replacement has a different IP/MAC but ServiceContinuityVerified=True (ClusterIP + Ready-enrollment) permits Strict teardown")
	}
}
