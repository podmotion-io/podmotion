/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0351_pause_pid_rollback_test.go is the controller-level discharge for the ADR-0351
// cgroup-anchor primitive's fail-closed terminal leg (sprint46B7 revision — REWRITTEN from the
// retired pause-PID-wait budget-spent leg this file originally covered onto the new
// resolveCgroupAnchorTarget fail-closed leg at the joinNsRestore anchor gate, D3.3). The binding
// companion to internal/agent/server's TestCgroupAnchor_RejectNonKubepodsPath (that package's
// fixtures construct no source Pod object and no controller reconcile loop, so an in-package
// assertion could never go red if ADR-0012 were violated).
//
// This test drives a Restore RPC failure carrying the new cgroup-anchor fail-closed terminal
// message through the reconciler's RollingBack phase (mirroring
// TestAbortAtFreezeWindowResumesSourceAndNeverDeletesIt, abort_freeze_window_test.go) and asserts
// the source pod is resumed and never deleted (ADR-0012 invariant #1) for this stop-here failure
// leg — unchanged in shape from the retired pause-PID leg, only the error text and its cause
// (D2.4 path-confinement rejection instead of a pause-PID wait timeout) are different.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestRestore_CgroupAnchorFailedClosed_SourcePodSurvivesRollback is ADR-0351's D2/D3.3
// (sprint46B7 rewrite of the retired D6.7): a Restore RPC failure whose error text is the new
// cgroup-anchor fail-closed terminal (the stop-here failure leg at the joinNsRestore cgroup-anchor
// gate) must still resume the source and never delete it, exactly like every other
// pre-TrafficVerified failure mode.
func TestRestore_CgroupAnchorFailedClosed_SourcePodSurvivesRollback(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	// The source pod is alive and pinned to the source node — the only surviving copy.
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod-pausepid", Namespace: "default", UID: "uid-pausepid"},
		Spec:       corev1.PodSpec{NodeName: "src-node"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.21"},
	}

	// The new cgroup-anchor fail-closed terminal message (verbatim shape resolveCgroupAnchorTarget/
	// the D2 anchor call site produce) is what a real Restore RPC failure would carry through
	// initiateRollback's msg parameter on this path.
	const cgroupAnchorFailedClosedMsg = "ADR-0351: resolve cgroup anchor for sandbox sandbox-pausepid-test: ADR-0351: cgroup leaf \"/sys/fs/cgroup/evil.slice\" resolves to \"/sys/fs/cgroup/evil.slice\", outside /sys/fs/cgroup/kubepods — refusing (path-confinement, BD-10)"

	now := metav1.Now()
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-pausepid-budget-spent",
			Namespace:  "default",
			Finalizers: []string{finalizerName},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod-pausepid",
			PodNamespace:        "default",
			Mode:                pmv1.MigrationModeCold,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
			RollbackOnFailure:   true,
			TargetNodeName:      "dst-node",
			SourcePodIP:         "10.0.0.21",
		},
		Status: pmv1.PodMigrationStatus{
			Phase: pmv1.MigrationPhaseRollingBack,
			Conditions: []metav1.Condition{
				{
					Type: string(pmv1.ConditionZeroWindowArmed), Status: metav1.ConditionTrue,
					Reason: "Armed", Message: "hold armed on source veth", LastTransitionTime: now,
				},
				{
					// ADR-0351 D2: the joinNsRestore cgroup-anchor gate failed closed — the
					// resolveCgroupAnchorTarget path-confinement check rejected the NRI-carried cgroup
					// path — a stop-here failure leg occurring after CRIU restore produced a live
					// process but before the restore was confirmed/traffic verified.
					Type: string(conditionRestored), Status: metav1.ConditionFalse,
					Reason: "RestoreFailed", Message: cgroupAnchorFailedClosedMsg, LastTransitionTime: now,
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
	// AgentPool is left nil: disarmZeroWindowOnFailurePath and the GC-9/GC-10 dest cleanup are
	// best-effort and nil-guarded, so the rollback still runs to completion — this test exercises
	// the controller-side rollback logic (source resume + no deletion), not a live agent RPC,
	// which is sufficient for this test's claim (mirrors abort_freeze_window_test.go's own scope).
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: spy}

	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-pausepid-budget-spent", Namespace: "default"}}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile(RollingBack) returned error: %v", err)
	}

	// (1) The source resume path MUST have been driven.
	if !spy.called {
		t.Errorf("ADR-0351 cgroup-anchor fail-closed rollback did NOT drive Rollbacker.Rollback — the frozen source is never SIGCONTed; invariant-1/ADR-0012 break")
	}

	// (2) The source pod MUST still exist — never deleted on this failure leg.
	survivor := &corev1.Pod{}
	getErr := fakeClient.Get(ctx, types.NamespacedName{Name: "src-pod-pausepid", Namespace: "default"}, survivor)
	if apierrors.IsNotFound(getErr) {
		t.Errorf("SOURCE POD DELETED after an ADR-0351 cgroup-anchor fail-closed failure — both copies gone; invariant-1/ADR-0012 break")
	} else if getErr != nil {
		t.Fatalf("unexpected error re-fetching source pod: %v", getErr)
	}

	// (3) The migration must land Failed with RolledBack=True, and TrafficVerified must NOT have
	//     been fabricated True on this failure leg.
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
		t.Fatalf("Get PodMigration after reconcile: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseFailed {
		t.Errorf("ADR-0351 cgroup-anchor fail-closed rollback did not land Failed; got phase=%q", fresh.Status.Phase)
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionRolledBack) {
		t.Errorf("RolledBack condition not set True after rollback — source-restored-to-live-state not recorded")
	}
	if meta.IsStatusConditionTrue(fresh.Status.Conditions, conditionTrafficVerified) {
		t.Errorf("TrafficVerified=True was set after an ADR-0351 cgroup-anchor fail-closed failure — a failing migration must never fabricate a verified cutover (both-gone risk)")
	}
	if meta.IsStatusConditionTrue(fresh.Status.Conditions, conditionSourcePodDeleted) {
		t.Errorf("SourcePodDeleted=True after an ADR-0351 cgroup-anchor fail-closed failure — source must remain serving")
	}
}
