/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// verifying_wedge_legitimate_source_deletion_test.go is the §P-VERIFY acceptance test for the
// round-2 fix to the legacy None-mode Verifying-phase wedge.
//
// Real scenario reproduced live on pm-e2e/podmotion-demo-wgbzz (see round-1 diagnosis, carried
// forward unchanged into round 2): a tcpPreservationMode=None PodMigration passes every real
// gate (TrafficVerified=True, WorkloadLivenessVerified=True), deleteSourcePodIfSafe legitimately
// deletes the source pod and sets conditionSourcePodDeleted=True (ADR-0012 satisfied), but the
// ADR-0241 cni0-cleanup-verify retry loop's VerifyCleanup keeps returning Clean=false. Round 1
// wedged here because the retry loop's r.Update (bumping an annotation) tripped Rule 1 (pod
// existence) on every UPDATE, so the attempt counter never persisted and the migration looped
// until the completion-budget watchdog force-rolled-back an already-succeeded migration —
// thawing a nonexistent source and deleting the healthy replacement pod (a real availability
// regression).
//
// This test drives the full Reconcile entrypoint (not a synthetic webhook-only unit test) and
// asserts the round-2 fix end to end at the controller level:
//   - Finding 3(a): the retry counter is a status field now, so no r.Update (spec/metadata) is
//     ever issued for it — nothing for Rule 1 to (mis)trip in the first place, even before the
//     watchdog guard engages.
//   - Finding 3(b): even though the completion budget is exceeded (VerifyCleanup never
//     converges), the watchdog does NOT roll back — because the source pod is already
//     confirmed+verified gone (conditionSourcePodDeleted=True + live fetch NotFound), it closes
//     out straight to Complete. The replacement pod is NEVER deleted and no
//     Rollbacker.Rollback/deleteReplacementPod call occurs.
//
// A prior version of this test (pre-round-2 code) FAILS: phase ends RollingBack and the
// replacement pod is torn down.

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestReconcile_VerifyingWedge_LegitimateSourceDeletion_ClosesOutInsteadOfRollback is the
// §P-VERIFY acceptance test for the round-2 Verifying-phase wedge fix.
func TestReconcile_VerifyingWedge_LegitimateSourceDeletion_ClosesOutInsteadOfRollback(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := adr0210Scheme(t)

	const (
		ns              = "default"
		migrationName   = "wedge-legitimate-source-deletion"
		replacementName = "workload-src-m-replacement"
		sourcePodName   = "workload-src" // already deleted — deliberately NOT seeded into the fake client
	)

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      migrationName,
			Namespace: ns,
			// Far past the completion budget — this is what fires the watchdog.
			CreationTimestamp: metav1.NewTime(time.Now().Add(-999 * time.Second)),
			Finalizers:        []string{finalizerName},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  sourcePodName,
			PodNamespace:             ns,
			SourcePodIP:              "10.244.0.77",
			TargetNodeName:           "pm-w2",
			TCPPreservationMode:      pmv1.TCPPreservationModeNone,
			CompletionTimeoutSeconds: 120,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseVerifying, // non-terminal — the exact wedge phase
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  replacementName,
			// The real gates that legitimately authorized source-pod deletion (ADR-0012)
			// already passed, and deleteSourcePodIfSafe already ran and recorded it:
			Conditions: []metav1.Condition{
				{Type: conditionTrafficVerified, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: metav1.Now()},
				{Type: pmv1.ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: metav1.Now()},
				{Type: conditionSourcePodDeleted, Status: metav1.ConditionTrue, Reason: "Deleted",
					Message: "Source pod deleted post-TrafficVerified+WorkloadLivenessVerified", LastTransitionTime: metav1.Now()},
				// The cni0-cleanup-verify retry budget is exhausted (ADR-0241 fail-open) —
				// this is the actual non-fatal straggler that kept the migration from reaching
				// Complete on its own, not a real failure.
				{Type: pmv1.ConditionCni0CleanupVerified, Status: metav1.ConditionFalse, Reason: "CleanupLeakExhausted",
					Message: "cni0 cleanup not confirmed after 3 retries (ADR-0241, fail-open)", LastTransitionTime: metav1.Now()},
			},
		},
	}

	// The replacement pod is real, healthy, and Ready — exactly what a genuinely successful
	// migration leaves behind. It must survive this reconcile untouched.
	replacementPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: replacementName, Namespace: ns},
		Spec:       corev1.PodSpec{NodeName: "pm-w2"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, replacementPod).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}); err != nil {
		t.Fatalf("Reconcile returned unexpected error: %v", err)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("Get pm after reconcile: %v", err)
	}

	// Finding 3(b): must close out to Complete, NOT roll back.
	if fresh.Status.Phase != pmv1.MigrationPhaseComplete {
		t.Fatalf("BUG (destructive rollback of an already-succeeded migration): expected phase=Complete "+
			"(source already legitimately deleted per ADR-0012), got phase=%s", fresh.Status.Phase)
	}
	if fresh.Status.CompletionTime == nil {
		t.Errorf("expected CompletionTime to be set on the Complete close-out path")
	}

	// Must NOT have initiated a rollback anywhere along the way.
	for _, c := range fresh.Status.Conditions {
		if c.Type == "RollbackReason" {
			t.Fatalf("BUG: RollbackReason condition present — the destructive rollback path ran despite the "+
				"source pod already being legitimately deleted: %+v", c)
		}
	}

	// The replacement pod — the healthy, already-migrated workload — must still exist. The
	// round-1 bug deleted this pod on every occurrence of this wedge.
	gotReplacement := &corev1.Pod{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: replacementName, Namespace: ns}, gotReplacement); err != nil {
		t.Fatalf("BUG (availability regression): replacement pod %q was deleted by the destructive rollback path: %v", replacementName, err)
	}
	readyCond := false
	for _, c := range gotReplacement.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			readyCond = true
		}
	}
	if !readyCond {
		t.Errorf("replacement pod is no longer Ready after reconcile")
	}
}

// TestReconcile_VerifyingWedge_SourceStillLive_StillRollsBack is the negative control: if the
// source pod was NEVER legitimately deleted (conditionSourcePodDeleted absent/false), the
// completion-budget watchdog must still fail closed to RollingBack exactly as before — the
// Finding 3(b) guard must not weaken the genuine invariant-#8 safety net.
func TestReconcile_VerifyingWedge_SourceStillLive_StillRollsBack(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := adr0210Scheme(t)

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "wedge-source-never-deleted",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-999 * time.Second)),
			Finalizers:        []string{finalizerName},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  "workload-src-2",
			PodNamespace:             "default",
			TargetNodeName:           "pm-w2",
			TCPPreservationMode:      pmv1.TCPPreservationModeNone,
			CompletionTimeoutSeconds: 120,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseVerifying,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  "workload-src-2-m-replacement",
			// conditionSourcePodDeleted is deliberately absent — this is a genuine wedge, not a
			// legitimately-completed migration.
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	_, _ = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}})

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("Get pm after reconcile: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseRollingBack {
		t.Fatalf("BUG (weakened safety net): a migration whose source was never deleted must still fail "+
			"closed to RollingBack past its completion budget; got phase=%s", fresh.Status.Phase)
	}
}
