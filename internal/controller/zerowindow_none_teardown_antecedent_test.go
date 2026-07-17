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

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestZeroWindowArmNoneModeSetsArmedFalse is the falsifiable regression for the None-mode
// source-teardown wedge (sprint46B9 postgres CLOSE-GATE round-3 live-proof failure): a
// None/PreCopy migration reached phase=Verifying with the restore, traffic, and liveness all
// verified, yet deleteSourcePodIfSafe blocked forever with "ZeroWindowArmed=True but
// ZeroWindowDisarmed is not True — source zero-window hold not confirmed disarmed", wedging
// past the 240s completion budget into a fail-closed rollback.
//
// Root cause: reconcileZeroWindowArm recorded ConditionZeroWindowArmed=True (reason=Skipped)
// for None mode. That condition is NOT a mere phase-completion marker like the other None-mode
// "Skipped" conditions — it is the fail-closed antecedent of the single source-teardown gate
// (SourceTeardownBlockReason). In None mode NO TC-BPF hold is ever armed, and the only producer
// of ZeroWindowDisarmed=True (reconcileDisengageHold) is never traversed on the None-mode legacy
// completion tail (reconcileRestoringNRI -> MigrationPhaseVerifying -> reconcileVerifying, which
// routes only Strict onward to DisengageHold), so a True antecedent could never be satisfied.
//
// The pre-existing gate unit tests (source_teardown_test.go / source_teardown_zerowindow_disarm_
// test.go "None_ArmedFalse_Allowed") already ASSUMED the runtime records ZeroWindowArmed=FALSE
// for None — but they exercised the gate function in isolation with a hand-built condition, so
// they never caught that the real PRODUCER wrote True. This test closes that producer-vs-gate
// gap: it asserts the condition the real reconcile writes, then feeds exactly that condition set
// through the real teardown gate, reproducing the live wedge scenario end to end.
func TestZeroWindowArmNoneModeSetsArmedFalse(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "zw-none", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
			TargetNodeName:      "dst-node",
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseZeroWindowArm,
			SourceNodeName:      "src-node",
			DestinationNodeName: "dst-node",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()

	// AgentPool is intentionally nil: the None branch must return before any agent RPC. If the
	// fix ever regresses such that None falls through to the live-arm path, ForNode(nil) would
	// surface here rather than silently.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	if _, err := r.reconcileZeroWindowArm(ctx, pm); err != nil {
		t.Fatalf("reconcileZeroWindowArm(None): unexpected error: %v", err)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "zw-none", Namespace: "default"}, fresh); err != nil {
		t.Fatalf("Get after reconcile: %v", err)
	}

	// (1) The condition the real producer writes must be present and FALSE — not True — so the
	// source-teardown gate antecedent stays honest for a mode that never arms a hold.
	c := meta.FindStatusCondition(fresh.Status.Conditions, string(pmv1.ConditionZeroWindowArmed))
	if c == nil {
		t.Fatalf("ConditionZeroWindowArmed not set by reconcileZeroWindowArm in None mode")
	}
	if c.Status == metav1.ConditionTrue {
		t.Fatalf("ConditionZeroWindowArmed=True in None mode — this is the false safety antecedent that wedged deleteSourcePodIfSafe on the None completion path (want False)")
	}
	if c.Status != metav1.ConditionFalse {
		t.Fatalf("ConditionZeroWindowArmed=%s in None mode, want False", c.Status)
	}

	// (2) End-to-end antecedent proof: feed the EXACT conditions the reconcile produced (plus the
	// Traffic + Liveness the None legacy tail sets before teardown, and deliberately NO
	// ZeroWindowDisarmed — reproducing the wedge scenario where DisengageHold was never traversed)
	// through the real teardown gate. It must NOT block. Before the fix (Armed=True) this returned
	// the frozen-source-socket block that wedged the migration.
	conds := append([]metav1.Condition{}, fresh.Status.Conditions...)
	conds = append(conds,
		metav1.Condition{Type: conditionTrafficVerified, Status: metav1.ConditionTrue, Reason: "TrafficVerified"},
		metav1.Condition{Type: string(pmv1.ConditionWorkloadLivenessVerified), Status: metav1.ConditionTrue, Reason: "Verified"},
	)
	if reason := pmv1.SourceTeardownBlockReason(pmv1.TCPPreservationModeNone, conds); reason != "" {
		t.Fatalf("None-mode source teardown still blocked after honest arm condition: %q — the wedge is not fixed", reason)
	}

	// (3) The phase must still advance — the honesty fix must not stall the None spine.
	if fresh.Status.Phase != pmv1.MigrationPhaseFinalFreezeStateCapture {
		t.Fatalf("phase after reconcileZeroWindowArm(None) = %s, want FinalFreezeStateCapture", fresh.Status.Phase)
	}
}

// TestZeroWindowArmNoneModeIdempotentReentry guards the reconcileZeroWindowArm fast-path
// (line ~720: "if ZeroWindowArmed is True, skip to FinalFreezeStateCapture"). Because the None
// branch now records ZeroWindowArmed=FALSE, that IsStatusConditionTrue fast-path no longer
// short-circuits on re-entry — so the None branch itself must be idempotent. A second reconcile
// from phase=ZeroWindowArm must again land ZeroWindowArmed=False and advance, never flip it True
// or error.
func TestZeroWindowArmNoneModeIdempotentReentry(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "zw-none-reentry", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
			TargetNodeName:      "dst-node",
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseZeroWindowArm,
			SourceNodeName:      "src-node",
			DestinationNodeName: "dst-node",
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()
	key := types.NamespacedName{Name: "zw-none-reentry", Namespace: "default"}

	for i := 0; i < 2; i++ {
		// Re-drive from phase=ZeroWindowArm to simulate a re-entry (e.g. requeue before the
		// FinalFreezeStateCapture write is observed by the caller).
		cur := &pmv1.PodMigration{}
		if err := fakeClient.Get(ctx, key, cur); err != nil {
			t.Fatalf("iter %d: Get: %v", i, err)
		}
		cur.Status.Phase = pmv1.MigrationPhaseZeroWindowArm
		if err := fakeClient.Status().Update(ctx, cur); err != nil {
			t.Fatalf("iter %d: reset phase: %v", i, err)
		}
		if _, err := r.reconcileZeroWindowArm(ctx, cur); err != nil {
			t.Fatalf("iter %d: reconcileZeroWindowArm(None): %v", i, err)
		}
		fresh := &pmv1.PodMigration{}
		if err := fakeClient.Get(ctx, key, fresh); err != nil {
			t.Fatalf("iter %d: Get after: %v", i, err)
		}
		if meta.IsStatusConditionTrue(fresh.Status.Conditions, string(pmv1.ConditionZeroWindowArmed)) {
			t.Fatalf("iter %d: ConditionZeroWindowArmed flipped True on re-entry — antecedent must stay False for None", i)
		}
		if fresh.Status.Phase != pmv1.MigrationPhaseFinalFreezeStateCapture {
			t.Fatalf("iter %d: phase = %s, want FinalFreezeStateCapture", i, fresh.Status.Phase)
		}
	}
}
