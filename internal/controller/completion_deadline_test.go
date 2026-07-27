/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// completion_deadline_test.go — regression for the sprint46B3 surgical fix: the top-level
// AUTHORITATIVE completion-deadline primitive in Reconcile (invariant #8 / ADR-0012).
//
// Live evidence: a redis Strict pm-w1→pm-w2
// migration ran …→RestoreSocketReattach→DisengageHold→Verifying and WEDGED in phase=Verifying for
// the whole watch window — the outer watch bound fired rc=124 at 125s, MIG1_FINAL_PHASE=Verifying,
// finalizer intact, namespace stuck Terminating. Root cause: no phase on the DisengageHold→Verifying
// path enforced a wall-clock terminal bound. The pre-existing bound lived only in
// reconcileServiceVerifying — a phase this migration never enters — so it never ran. The per-reconcile
// context.WithTimeout (Reconcile) only bounds downstream RPCs; every requeue derives a fresh timer,
// so the CR could requeue forever, never Complete, never Failed.
//
// The fix is ONE deadline gate at the dispatch (not a copy per phase — invariant #10), keyed on the
// CR's own creationTimestamp + spec.completionTimeoutSeconds. These tests pin, via the full Reconcile
// entrypoint, that:
//   (1) a non-terminal migration (phase=Verifying — the exact wedge phase) that has burned its whole
//       declared completionTimeoutSeconds fails closed to RollingBack (source never deleted); and
//   (2) the gate is inert for a migration still within its budget; and
//   (3) the gate does NOT re-fire on a terminal/rolling-back phase (no rollback loop, no fight with
//       the terminal-outcome handlers).
//
// Test (1) FAILS on the pre-fix baseline (Reconcile dispatches to reconcileVerifying and requeues
// indefinitely, phase stays Verifying) and PASSES after.

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// reconcileOnce drives the full Reconcile entrypoint for pm against a fake client seeded with the CR.
func reconcileOnceForDeadline(t *testing.T, pm *pmv1.PodMigration) *pmv1.PodMigration {
	t.Helper()
	logf.SetLogger(zap.New(zap.UseDevMode(true)))
	scheme := adr0210Scheme(t)

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
	return fresh
}

// TestReconcile_CompletionDeadline_WedgedVerifying_FailsClosedToRollingBack is the load-bearing
// regression: the exact live-proof-cycle2 shape — phase=Verifying, Strict, past its 120s budget —
// must fail closed to RollingBack rather than wedge forever.
func TestReconcile_CompletionDeadline_WedgedVerifying_FailsClosedToRollingBack(t *testing.T) {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deadline-wedged-verifying",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-200 * time.Second)), // > 120s budget
			Finalizers:        []string{finalizerName},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  "redis-src",
			PodNamespace:             "default",
			SourcePodIP:              "10.244.0.165",
			TargetNodeName:           "pm-w2",
			TCPPreservationMode:      pmv1.TCPPreservationModeStrict,
			CompletionTimeoutSeconds: 120,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseVerifying,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  "redis-src-m-f4510a17",
		},
	}

	fresh := reconcileOnceForDeadline(t, pm)
	if fresh.Status.Phase != pmv1.MigrationPhaseRollingBack {
		t.Fatalf("BUG (forever-wedge): a non-terminal migration past its completionTimeoutSeconds must fail closed to RollingBack (invariant #8); got phase=%s", fresh.Status.Phase)
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, "RollbackReason") {
		t.Fatalf("expected RollbackReason=True to be set on the deadline fail-closed path; conditions=%+v", fresh.Status.Conditions)
	}
}

// TestReconcile_CompletionDeadline_WithinBudget_DoesNotRollBack is the no-over-block control: a
// non-terminal migration still inside its declared budget must NOT be rolled back by the gate.
func TestReconcile_CompletionDeadline_WithinBudget_DoesNotRollBack(t *testing.T) {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deadline-within-budget",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-5 * time.Second)), // well inside 120s
			Finalizers:        []string{finalizerName},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  "redis-src",
			PodNamespace:             "default",
			TargetNodeName:           "pm-w2",
			TCPPreservationMode:      pmv1.TCPPreservationModeStrict,
			CompletionTimeoutSeconds: 120,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseVerifying,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  "redis-src-m-1",
		},
	}

	fresh := reconcileOnceForDeadline(t, pm)
	if fresh.Status.Phase == pmv1.MigrationPhaseRollingBack {
		t.Fatalf("BUG (over-block): the completion-deadline gate rolled back a migration still within its budget")
	}
}

// TestReconcile_CompletionDeadline_TerminalPhaseNotReFired proves the gate excludes terminal/
// rolling-back phases even when past the budget — no rollback loop, no fight with terminal handlers.
// DryRunComplete is used because its dispatch is a pure no-op (returns immediately, no deps).
func TestReconcile_CompletionDeadline_TerminalPhaseNotReFired(t *testing.T) {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deadline-terminal-excluded",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-999 * time.Second)), // far past any budget
			Finalizers:        []string{finalizerName},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  "redis-src",
			PodNamespace:             "default",
			TargetNodeName:           "pm-w2",
			CompletionTimeoutSeconds: 120,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseDryRunComplete,
			DestinationNodeName: "pm-w2",
		},
	}

	fresh := reconcileOnceForDeadline(t, pm)
	if fresh.Status.Phase != pmv1.MigrationPhaseDryRunComplete {
		t.Fatalf("BUG: the completion-deadline gate fired on a terminal phase; phase should stay DryRunComplete, got %s", fresh.Status.Phase)
	}
}
