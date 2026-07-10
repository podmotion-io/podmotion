/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"bytes"
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/rollback"
)

// spyRollbacker records whether Rollback was invoked. It stands in for the real
// three-step (Network→Compute→Storage) rollback pipeline so the contract test can
// prove the source-thaw step is driven on the abort-at-freeze-window path without a
// live agent. The real ComputeRollback step is what SIGCONTs the frozen source
// (via the source agent's Abort RPC → thawFrozenSource → broker SignalPID, C-06);
// observing that Rollback ran here is the controller-side proof that the source
// resume is actually driven and not skipped.
type spyRollbacker struct {
	called bool
	pm     *pmv1.PodMigration
}

func (s *spyRollbacker) Rollback(_ context.Context, pm *pmv1.PodMigration) error {
	s.called = true
	s.pm = pm
	return nil
}

var _ rollback.Rollbacker = (*spyRollbacker)(nil)

// TestAbortAtFreezeWindowResumesSourceAndNeverDeletesIt is the platform_sre-C1 (A-02
// abort/rollback at freeze window) contract test. It asserts the invariant-1 / ADR-0012
// guarantee for the exact hazard the panel named: a restore that fails AFTER the
// zero-window hold engages (ZeroWindowArmed=True) but BEFORE TrafficVerified=True must
// degrade to "source still serving", never "both gone".
//
// Concretely, when the migration enters RollingBack from that mid-freeze state, the
// reconciler MUST:
//  1. drive the source resume (Rollbacker.Rollback → ComputeRollback → source thaw),
//  2. never delete the source pod (the only surviving copy of process state), and
//  3. leave TrafficVerified NOT True (never fabricate a "verified" cutover on the abort
//     path — the re-drive of TrafficVerified happens only from a live destination, never
//     as a side effect of failing).
//
// Falsifiability: this test FAILS on the pre-A-02 logic if reconcileRollingBack ever
// (a) skips the source-resume step, (b) deletes the source pod on the failure path, or
// (c) sets TrafficVerified=True while rolling back. The source pod is present in the
// fake client with the source node set; a deletion would be observable as a NotFound.
func TestAbortAtFreezeWindowResumesSourceAndNeverDeletesIt(t *testing.T) {
	var logBuf bytes.Buffer
	logf.SetLogger(zap.New(zap.WriteTo(&logBuf), zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	// The source pod is alive and pinned to the source node — the only surviving copy.
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "default", UID: "uid-abort"},
		Spec:       corev1.PodSpec{NodeName: "src-node"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.20"},
	}

	now := metav1.Now()
	// Mid-freeze-window state: the zero-window hold is ARMED and NOT yet disarmed, and
	// TrafficVerified has NOT been established. This is precisely the "restore failed
	// after the hold engaged, before traffic was verified" hazard.
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-abort-freeze",
			Namespace:  "default",
			Finalizers: []string{finalizerName},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			Mode:                pmv1.MigrationModeCold,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
			RollbackOnFailure:   true,
			TargetNodeName:      "dst-node",
			SourcePodIP:         "10.0.0.20",
		},
		Status: pmv1.PodMigrationStatus{
			Phase: pmv1.MigrationPhaseRollingBack,
			Conditions: []metav1.Condition{
				{
					Type: string(pmv1.ConditionZeroWindowArmed), Status: metav1.ConditionTrue,
					Reason: "Armed", Message: "hold armed on source veth", LastTransitionTime: now,
				},
			},
			SourceNodeName:      "src-node",
			DestinationNodeName: "dst-node",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod).
		WithStatusSubresource(pm).
		Build()

	spy := &spyRollbacker{}
	// AgentPool is left nil: disarmZeroWindowOnFailurePath and the GC-9/GC-10 dest
	// cleanup are best-effort and nil-guarded, so the rollback still runs to completion.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: spy}

	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-abort-freeze", Namespace: "default"}}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile(RollingBack) returned error: %v", err)
	}

	// (1) The source resume path MUST have been driven.
	if !spy.called {
		t.Errorf("abort at freeze window did NOT drive Rollbacker.Rollback — the frozen source is never SIGCONTed; invariant-1/ADR-0012 break")
	}

	// (2) The source pod MUST still exist — never deleted on the abort path.
	survivor := &corev1.Pod{}
	getErr := fakeClient.Get(ctx, types.NamespacedName{Name: "src-pod", Namespace: "default"}, survivor)
	if apierrors.IsNotFound(getErr) {
		t.Errorf("SOURCE POD DELETED on the abort/rollback path — both copies gone; invariant-1/ADR-0012 break")
	} else if getErr != nil {
		t.Fatalf("unexpected error re-fetching source pod: %v", getErr)
	}

	// (3) The migration must land Failed with RolledBack=True, and TrafficVerified must
	//     NOT have been fabricated True on the abort path.
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
		t.Fatalf("Get PodMigration after reconcile: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseFailed {
		t.Errorf("abort at freeze window did not land Failed; got phase=%q", fresh.Status.Phase)
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, "RolledBack") {
		t.Errorf("RolledBack condition not set True after rollback — source-restored-to-live-state not recorded")
	}
	if meta.IsStatusConditionTrue(fresh.Status.Conditions, conditionTrafficVerified) {
		t.Errorf("TrafficVerified=True was set on the abort path — a failing migration must never fabricate a verified cutover (both-gone risk)")
	}
	// The source pod must not be recorded as deleted either.
	if meta.IsStatusConditionTrue(fresh.Status.Conditions, conditionSourcePodDeleted) {
		t.Errorf("SourcePodDeleted=True on the abort path — source must remain serving")
	}
}
