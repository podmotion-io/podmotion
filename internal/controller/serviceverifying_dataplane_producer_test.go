/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// serviceverifying_dataplane_producer_test.go — regression tests originally authored for the
// sprint46B2 surgical fix (cross-node DataplaneReachabilityVerified gate reachability), UPDATED
// per ADR-0352 (DR-6: no collateral regression) to assert against the re-keyed Strict predicate.
//
// ADR-0352 D3 retires the pod-IP-preservation producers (tryEstablishCiliumDataplaneReachability,
// verifyDataplaneReachability) from the Strict completion path in reconcileServiceVerifying,
// replacing them with establishServiceContinuity (D1: EndpointSlice-Ready enrollment + ClusterIP
// round-trip) and re-keying the gate onto ServiceContinuityVerified (D2.1). The four tests below
// now pin the SAME structural properties (hold-without-proof, fall-through-guard,
// advance-on-True, bounded-rollback-on-timeout) against the new condition instead of the retired
// one — the underlying invariant-#1/#8 properties these tests protect are unchanged by the re-key;
// only the authoritative signal identity is.

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/traffic"
)

// TestServiceVerifying_Strict_TrafficVerifierSuccess_HoldsWithoutDataplaneReachability mirrors the
// live-proof-cycle2 CR (redis Strict, SourcePodIP=10.244.1.178, src=pm-w1, dest=pm-w2). The
// service-path TrafficVerifier SUCCEEDS (as it did live — TrafficVerified=True), but the ADR-0210
// cross-node producer cannot establish DataplaneReachabilityVerified (AgentPool nil). The migration
// MUST hold in ServiceVerifying, never advance to CutoverComplete on TrafficVerified alone.
func TestServiceVerifying_Strict_TrafficVerifierSuccess_HoldsWithoutDataplaneReachability(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := adr0210Scheme(t)

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-src-m-1", Namespace: "default", UID: "uid-repl-1"},
		Spec:       corev1.PodSpec{NodeName: "pm-w2"},
		Status:     corev1.PodStatus{PodIP: "10.244.2.50"},
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "svcverify-strict-hold", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "redis-src",
			PodNamespace:        "default",
			SourcePodIP:         "10.244.1.178",
			TargetNodeName:      "pm-w2",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseServiceVerifying,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  "redis-src-m-1",
			ReplVethMAC:         "aa:bb:cc:dd:ee:ff",
			Conditions: []metav1.Condition{
				cond(string(pmv1.ConditionWorkloadLivenessVerified), metav1.ConditionTrue),
				cond(string(pmv1.ConditionTCPSequenceContinuityVerified), metav1.ConditionTrue),
				// DataplaneReachabilityVerified deliberately ABSENT — the exact live state.
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, destPod).
		WithStatusSubresource(pm).
		Build()

	// TrafficVerifier wired and SUCCEEDING (the EndpointSlice/service-path verifier the live run
	// passed). AgentPool deliberately nil: the ADR-0210 producer cannot obtain cross-node proof, so
	// Strict MUST hold here rather than bypass to CutoverComplete on TrafficVerified alone.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, TrafficVerifier: &traffic.StubVerifier{}}
	ctx := context.Background()

	res, err := r.reconcileServiceVerifying(ctx, pm)
	if err != nil {
		t.Fatalf("reconcileServiceVerifying returned unexpected error: %v", err)
	}
	if res.RequeueAfter <= 0 && !res.Requeue {
		t.Fatalf("Strict migration with DataplaneReachabilityVerified absent must requeue (hold), got %+v", res)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "svcverify-strict-hold", Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}
	if fresh.Status.Phase == pmv1.MigrationPhaseCutoverComplete {
		t.Fatalf("BUG (bypass): Strict advanced to CutoverComplete with ServiceContinuityVerified absent — the service-path verifier (TrafficVerified) is NOT a Strict cutover gate")
	}
	if meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionServiceContinuityVerified) {
		t.Fatalf("test invariant: ServiceContinuityVerified must remain unset (no Service/EndpointSlice fixture wired — D1 cannot converge)")
	}
}

// TestServiceVerifying_Strict_FallthroughGuard_HoldsWhenProducerYieldsNoCrossNodeProof exercises
// the residual fall-through guard directly. With SourcePodIP empty, injectIPHandoff short-circuits
// done=true WITHOUT producing DataplaneReachabilityVerified, so the reconcile reaches the
// service-path fall-through with the TrafficVerifier succeeding — the exact 1687 bypass. The Strict
// guard MUST hold (requeue) rather than transition to CutoverComplete.
func TestServiceVerifying_Strict_FallthroughGuard_HoldsWhenProducerYieldsNoCrossNodeProof(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := adr0210Scheme(t)

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "repl-2", Namespace: "default", UID: "uid-repl-2"},
		Spec:       corev1.PodSpec{NodeName: "pm-w2"},
		Status:     corev1.PodStatus{PodIP: "10.244.2.51"},
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "svcverify-strict-guard", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "redis-src",
			PodNamespace:        "default",
			SourcePodIP:         "", // empty -> injectIPHandoff yields no cross-node proof
			TargetNodeName:      "pm-w2",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseServiceVerifying,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  "repl-2",
			Conditions: []metav1.Condition{
				cond(string(pmv1.ConditionWorkloadLivenessVerified), metav1.ConditionTrue),
				cond(string(pmv1.ConditionTCPSequenceContinuityVerified), metav1.ConditionTrue),
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, destPod).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, TrafficVerifier: &traffic.StubVerifier{}}
	ctx := context.Background()

	res, err := r.reconcileServiceVerifying(ctx, pm)
	if err != nil {
		t.Fatalf("reconcileServiceVerifying returned unexpected error: %v", err)
	}
	if res.RequeueAfter <= 0 && !res.Requeue {
		t.Fatalf("Strict fall-through with no cross-node proof must requeue (hold), got %+v", res)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "svcverify-strict-guard", Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}
	if fresh.Status.Phase == pmv1.MigrationPhaseCutoverComplete {
		t.Fatalf("BUG (bypass): Strict reached CutoverComplete via the service-path verifier with DataplaneReachabilityVerified absent")
	}
}

// TestServiceVerifying_Strict_AdvancesToCutover_WhenDataplaneReachabilityVerified is the positive
// control: once the authoritative ServiceContinuityVerified gate is True, Strict MUST advance to
// CutoverComplete (the fix does not over-block). AgentPool is nil to prove establishServiceContinuity
// is SKIPPED when ServiceContinuityVerified is already True (no redundant probe re-run).
func TestServiceVerifying_Strict_AdvancesToCutover_WhenDataplaneReachabilityVerified(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := adr0210Scheme(t)

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "repl-3", Namespace: "default", UID: "uid-repl-3"},
		Spec:       corev1.PodSpec{NodeName: "pm-w2"},
		Status:     corev1.PodStatus{PodIP: "10.244.2.52"},
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "svcverify-strict-advance", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "redis-src",
			PodNamespace:        "default",
			SourcePodIP:         "10.244.1.178",
			TargetNodeName:      "pm-w2",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseServiceVerifying,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  "repl-3",
			Conditions: []metav1.Condition{
				cond(string(pmv1.ConditionWorkloadLivenessVerified), metav1.ConditionTrue),
				cond(string(pmv1.ConditionTCPSequenceContinuityVerified), metav1.ConditionTrue),
				cond(string(pmv1.ConditionServiceContinuityVerified), metav1.ConditionTrue),
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, destPod).
		WithStatusSubresource(pm).
		Build()

	// AgentPool nil: with ServiceContinuityVerified already True, establishServiceContinuity MUST
	// be skipped, so a nil AgentPool proves the advance path does not re-run the ClusterIP probe.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, TrafficVerifier: &traffic.StubVerifier{}}
	ctx := context.Background()

	if _, err := r.reconcileServiceVerifying(ctx, pm); err != nil {
		t.Fatalf("reconcileServiceVerifying returned unexpected error: %v", err)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "svcverify-strict-advance", Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseCutoverComplete {
		t.Fatalf("Strict migration with ServiceContinuityVerified=True must advance to CutoverComplete; got phase=%s", fresh.Status.Phase)
	}
}

// TestServiceVerifying_Strict_BoundedRollback_WhenDataplaneReachabilityNeverConverges is the
// invariant-#8 terminal-bound regression. It closes the gap the three tests above leave open:
// they only prove the migration HOLDS (requeues) when ServiceContinuityVerified cannot be
// established — which, unbounded, IS the >120s forever-wedge invariant #8 forbids. This test
// proves the wait is now TERMINALLY bounded (ADR-0352 D4, structure preserved verbatim from the
// retired ADR-0210 backstop): a Strict migration whose D1 gate has not converged by 2/3 of its
// own declared completionTimeoutSeconds (read from creationTimestamp, the source of truth on the
// CR) fails closed to RollingBack rather than requeuing forever. The source is never deleted
// (ADR-0012) — this bounds the wedge, it does not fabricate continuity.
//
// AgentPool is nil to prove the deadline fires BEFORE establishServiceContinuity is invoked — no
// ClusterIP probe is needed to reach the terminal decision once the budget is spent.
func TestServiceVerifying_Strict_BoundedRollback_WhenDataplaneReachabilityNeverConverges(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := adr0210Scheme(t)

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "repl-4", Namespace: "default", UID: "uid-repl-4"},
		Spec:       corev1.PodSpec{NodeName: "pm-w2"},
		Status:     corev1.PodStatus{PodIP: "10.244.2.53"},
	}

	// creationTimestamp set 200s in the past against a 120s budget: 2/3 * 120s = 80s < 200s, so the
	// terminal deadline is already exceeded on this reconcile.
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "svcverify-strict-bounded",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-200 * time.Second)),
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  "redis-src",
			PodNamespace:             "default",
			SourcePodIP:              "10.244.1.178",
			TargetNodeName:           "pm-w2",
			TCPPreservationMode:      pmv1.TCPPreservationModeStrict,
			CompletionTimeoutSeconds: 120,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseServiceVerifying,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  "repl-4",
			ReplVethMAC:         "aa:bb:cc:dd:ee:ff",
			Conditions: []metav1.Condition{
				cond(string(pmv1.ConditionWorkloadLivenessVerified), metav1.ConditionTrue),
				cond(string(pmv1.ConditionTCPSequenceContinuityVerified), metav1.ConditionTrue),
				// DataplaneReachabilityVerified deliberately ABSENT and never converging.
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, destPod).
		WithStatusSubresource(pm).
		Build()

	// AgentPool nil: the deadline branch must be reached BEFORE injectIPHandoff, so a nil pool must
	// not be dereferenced. TrafficVerifier wired and succeeding (as it did live).
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, TrafficVerifier: &traffic.StubVerifier{}}
	ctx := context.Background()

	if _, err := r.reconcileServiceVerifying(ctx, pm); err != nil {
		t.Fatalf("reconcileServiceVerifying returned unexpected error: %v", err)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "svcverify-strict-bounded", Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseRollingBack {
		t.Fatalf("BUG (forever-wedge): Strict migration past its completion budget with ServiceContinuityVerified unconverged must fail closed to RollingBack (invariant #8); got phase=%s", fresh.Status.Phase)
	}
	if fresh.Status.Phase == pmv1.MigrationPhaseCutoverComplete {
		t.Fatalf("BUG (bypass): Strict advanced to CutoverComplete without ServiceContinuityVerified")
	}
	scv := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionServiceContinuityVerified)
	if scv == nil || scv.Status != metav1.ConditionFalse || scv.Reason != "ServiceContinuityDeadlineExceeded" {
		t.Fatalf("expected ServiceContinuityVerified=False/ServiceContinuityDeadlineExceeded on the bounded-rollback path; got %+v", scv)
	}
}
