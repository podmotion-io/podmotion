/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"testing"
	"time"

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

func newSchemeForRestoreRouting(t *testing.T) *runtime.Scheme {
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

// TestReconcileRestoring_RoutesToNRIByLabel_WhenStatusReplacementPodNameLostToClobberRace is the
// regression pin for the sprint46B2 live-proof-cycle1 failure. The controller MUST decide
// "wait for the NRI-driven restore" vs "call the direct Restore RPC" on the AUTHORITATIVE
// podmotion.io/migration-name label the controller stamps at replacement-pod creation, NOT on
// the pm.Status.ReplacementPodName status mirror.
//
// Live root cause (pm-w2 agent log, 2026-07-13): the status mirror read back EMPTY at the
// Restoring reconcile (status-subresource clobber race), so the old gate
// (`if pm.Status.ReplacementPodName != ""`) fell through to the direct Restore RPC, whose
// agent-side resolvePodNetnsSandbox -> sandboxIDForPodUID raced containerd sandbox creation,
// returned "no sandbox container found for pod uid <uid>", tripped the ADR-0325 fail-closed
// gate, and marked the migration Failed in 9s — which then blocked the NRI hook (it only
// restores while the CR is still in the Restoring phase). Routing on the label (which exists
// long before restore and does not race the status write) makes the controller wait for the
// authoritative NRI restore instead of racing it (invariant #10 — primitive over brittle chain).
func TestReconcileRestoring_RoutesToNRIByLabel_WhenStatusReplacementPodNameLostToClobberRace(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := newSchemeForRestoreRouting(t)

	const migName = "test-restore-race"
	const replName = "test-restore-race-m-abc123"

	// The replacement pod exists and carries the authoritative migration-name label (stamped at
	// createReplacementPod), but is NOT yet Running (NRI restore in progress). This is exactly
	// the live state when the direct RPC misfired.
	replPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      replName,
			Namespace: "default",
			UID:       "uid-repl-race",
			Labels:    map[string]string{replacementPodMigrationNameLabel: migName},
		},
		Spec:   corev1.PodSpec{NodeName: "pm-w2"},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "redis-src",
			PodNamespace:        "default",
			TargetNodeName:      "pm-w2",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
			RollbackOnFailure:   true,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseRestoring,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			// ReplacementPodName deliberately EMPTY — the clobber-race state the fix targets.
			ReplacementPodName: "",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, replPod).
		WithStatusSubresource(pm).
		Build()

	// AgentPool deliberately nil: if the routing regressed and fell through to the direct
	// Restore RPC path, it would hit the `r.AgentPool == nil` early-return (RequeueAfter 3s)
	// WITHOUT healing the status mirror — a distinct, observable signature from the NRI path.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, AgentPool: nil}
	ctx := context.Background()

	res, err := r.reconcileRestoring(ctx, pm)
	if err != nil {
		t.Fatalf("reconcileRestoring returned unexpected error: %v", err)
	}

	// NRI path requeues at 2s waiting for the replacement pod to reach Running; the direct
	// nil-AgentPool fallthrough would requeue at 3s. The 2s value proves the NRI route was taken.
	if res.RequeueAfter != 2*time.Second {
		t.Fatalf("expected NRI-path RequeueAfter=2s (routed by label), got %v — routing likely fell through to the sandbox-racing direct Restore path", res.RequeueAfter)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: migName, Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}

	// The status mirror MUST be healed to the label-resolved replacement pod name so downstream
	// by-name reads resolve. The old gate never healed it (it never resolved by label at all).
	if fresh.Status.ReplacementPodName != replName {
		t.Fatalf("Status.ReplacementPodName not healed from the authoritative label: got %q, want %q", fresh.Status.ReplacementPodName, replName)
	}

	// The migration MUST NOT have been failed closed — the whole point is that the direct
	// sandbox-racing RPC (which produced RestoreFailed live) is not taken.
	if cond := meta.FindStatusCondition(fresh.Status.Conditions, conditionRestored); cond != nil &&
		cond.Status == metav1.ConditionFalse && cond.Reason == "RestoreFailed" {
		t.Fatalf("migration was failed closed (Restored=False/RestoreFailed: %q) — the direct sandbox-racing restore path must not be taken when a replacement pod exists", cond.Message)
	}
}

// TestReconcileRestoring_FallsThroughToDirectPath_WhenNoReplacementPodExists pins the negative
// side of the routing primitive: when NO replacement pod is resolvable by label AND the status
// mirror is empty (a genuine no-replacement-pod flow, e.g. dev/raw-CRIU without an operator-
// created replacement), the label routing must NOT divert to the NRI path and must preserve the
// prior fall-through to the direct Restore RPC path. With a nil AgentPool that path early-returns
// RequeueAfter 3s and does not heal the (correctly still-empty) status mirror.
func TestReconcileRestoring_FallsThroughToDirectPath_WhenNoReplacementPodExists(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := newSchemeForRestoreRouting(t)

	const migName = "test-no-replacement"

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "redis-src",
			PodNamespace:        "default",
			TargetNodeName:      "pm-w2",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseRestoring,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  "",
		},
	}

	// No replacement pod object at all.
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, AgentPool: nil}
	ctx := context.Background()

	res, err := r.reconcileRestoring(ctx, pm)
	if err != nil {
		t.Fatalf("reconcileRestoring returned unexpected error: %v", err)
	}

	// Direct-path nil-AgentPool early return requeues at 3s (NOT the NRI path's 2s).
	if res.RequeueAfter != 3*time.Second {
		t.Fatalf("expected direct-path RequeueAfter=3s when no replacement pod exists, got %v — label routing must not divert a genuine no-replacement-pod flow to the NRI path", res.RequeueAfter)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: migName, Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get pm: %v", err)
	}
	if fresh.Status.ReplacementPodName != "" {
		t.Fatalf("Status.ReplacementPodName must stay empty when no replacement pod exists, got %q", fresh.Status.ReplacementPodName)
	}
}
