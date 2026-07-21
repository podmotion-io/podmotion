/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// samenode_placement_guard_test.go — regression coverage for resolveAndValidateReplacementPlacement,
// the single source of truth for "is the replacement-pod placement valid, and if not, what
// corrective action fires."
//
// WHY THIS FILE WAS REWRITTEN (round-3 finding #1): the previous version proved "self-recovery" by
// directly mutating a bound pod's Spec.NodeName in the fake client
// (`freshPod.Spec.NodeName = "node-b"; r.Update(...)`). The real Kubernetes API server REJECTS that
// mutation — a pod's node binding is immutable once set — so the previous test passed against a
// scenario that can never occur in production, and no code path actually corrected a mis-placed pod.
//
// The real, apiserver-legal correction is to DELETE the replacement pod so the scheduler can place a
// fresh one; a delete is always legal, and binding a FRESHLY-CREATED (still unbound) pod to a node is
// the normal scheduler operation — neither is the forbidden in-place rebind. These tests exercise
// exactly that: delete → recreate (unbound) → bind the fresh pod to a distinct node → validate. Every
// pod write below is one the real apiserver accepts.

import (
	"context"
	"crypto/tls"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
)

// readyNode builds a Node object reporting NodeReady=True, so nodeIsPresentAndReady returns
// (present, ready) for it — the "present, Ready" half of placement validity.
func placementReadyNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}
}

// newPlacementFixture builds a reconciler for a migration in the Transferring phase with the source
// pod live on node-a (never deleted — ADR-0012), Nodes node-a and node-b both Ready, and — when
// replNode != "" or replGated — a replacement pod carrying the migration label. AGENT_IMAGE is set so
// the recovery recreate path (createReplacementPod) can build a fresh pod. CheckpointTransferred is
// pre-set so a reconcile that reaches a VALID placement can advance past the agent-only transfer RPCs
// (mirroring the crash-recovery tail the prior test used). AgentPool is non-nil but resolves no live
// agents, so any ForNode call fails fast without dialing.
func newPlacementFixture(t *testing.T, replNode string, replGated bool) (*PodMigrationReconciler, *pmv1.PodMigration) {
	t.Helper()
	t.Setenv("AGENT_IMAGE", "podmotion-agent:test")
	scheme := adr0331Scheme(t)

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-placement", Namespace: "default", UID: "plcuid012345"},
		Spec:       pmv1.PodMigrationSpec{PodName: "app", PodNamespace: "default"},
		Status: pmv1.PodMigrationStatus{
			Phase:                 pmv1.MigrationPhaseTransferring,
			SourceNodeName:        "node-a",
			CheckpointTransferred: true,
		},
	}
	sourcePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: corev1.PodSpec{
			NodeName:   "node-a",
			Containers: []corev1.Container{{Name: "app", Image: "redis:7-alpine"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	objs := []client.Object{pm, sourcePod, placementReadyNode("node-a"), placementReadyNode("node-b")}
	if replNode != "" || replGated {
		replPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "app-repl",
				Namespace: "default",
				Labels:    map[string]string{replacementPodMigrationNameLabel: pm.Name},
			},
			Spec: corev1.PodSpec{
				NodeName:   replNode,
				Containers: []corev1.Container{{Name: "app", Image: "redis:7-alpine"}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		if replGated {
			replPod.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: schedulingGateAwaitingCheckpoint}}
		}
		pm.Status.ReplacementPodName = "app-repl"
		objs = append(objs, replPod)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(objs...).Build()
	pool := agentclient.NewAgentClientPool(fakeClient, "9090", &tls.Config{InsecureSkipVerify: true})
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, AgentPool: pool}
	return r, pm
}

// listReplacementPods returns every pod carrying the migration label — the source-of-truth resolution
// resolveReplacementPodByLabel uses.
func listReplacementPods(t *testing.T, r *PodMigrationReconciler, pm *pmv1.PodMigration) []corev1.Pod {
	t.Helper()
	list := &corev1.PodList{}
	if err := r.List(context.Background(), list,
		client.InNamespace(pm.Spec.PodNamespace),
		client.MatchingLabels{replacementPodMigrationNameLabel: pm.Name}); err != nil {
		t.Fatalf("list replacement pods: %v", err)
	}
	return list.Items
}

func getPM(t *testing.T, r *PodMigrationReconciler, pm *pmv1.PodMigration) *pmv1.PodMigration {
	t.Helper()
	got := &pmv1.PodMigration{}
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name}, got); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	return got
}

// TestReplacementPlacement_SameNodeBound_DeletesForReschedule is the core round-3 fix: a replacement
// pod the default scheduler bound onto the SOURCE node is DELETED (the only apiserver-legal
// correction) so a fresh pod can be scheduled. The prior implementation only set a condition and
// requeued; it never deleted anything, so nothing ever rescheduled.
func TestReplacementPlacement_SameNodeBound_DeletesForReschedule(t *testing.T) {
	ctx := context.Background()
	r, pm := newPlacementFixture(t, "node-a", false) // replacement pod bound to the SOURCE node

	if got := len(listReplacementPods(t, r, pm)); got != 1 {
		t.Fatalf("precondition: expected 1 replacement pod, got %d", got)
	}

	dec, err := r.resolveAndValidateReplacementPlacement(ctx, pm, "node-a", true)
	if err != nil {
		t.Fatalf("resolveAndValidateReplacementPlacement: %v", err)
	}
	if dec.Action != replacementPlacementRequeue {
		t.Fatalf("same-node bound: expected requeue action, got %v", dec.Action)
	}

	// The corrective action actually happened: the same-node pod is GONE (a real, apiserver-legal
	// delete — not an in-place spec.nodeName mutation).
	if got := len(listReplacementPods(t, r, pm)); got != 0 {
		t.Fatalf("same-node replacement pod was not deleted for reschedule; still %d present", got)
	}
	fresh := getPM(t, r, pm)
	if n := readSameNodeRecoveryAttempts(fresh); n != 1 {
		t.Fatalf("expected recovery attempt counter == 1 after first delete, got %d", n)
	}
	if fresh.Status.DestinationNodeName != "" {
		t.Fatalf("a same-node placement must never be cached into Status.DestinationNodeName; got %q", fresh.Status.DestinationNodeName)
	}
	c := meta.FindStatusCondition(fresh.Status.Conditions, conditionDestinationPlacementValid)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "SameNodePlacement" {
		t.Fatalf("expected DestinationPlacementValid=False/SameNodePlacement, got %+v", c)
	}
}

// TestReplacementPlacement_RecreatesAfterDelete_Unbound proves the second half of real recovery:
// once the same-node pod is gone and a recovery is in progress, the primitive recreates a fresh
// replacement pod, and — per ADR-0359 — that pod is created UNBOUND (no spec.nodeName), so a real
// scheduler is free to place it on a different node.
func TestReplacementPlacement_RecreatesAfterDelete_Unbound(t *testing.T) {
	ctx := context.Background()
	r, pm := newPlacementFixture(t, "", false) // no replacement pod (post-delete state)

	// Stamp "recovery in progress" (one delete already happened) so the primitive recreates.
	pm.Annotations = map[string]string{sameNodeRecoveryAttemptsAnnotation: "1"}
	if err := r.Update(ctx, pm); err != nil {
		t.Fatalf("seed recovery annotation: %v", err)
	}

	dec, err := r.resolveAndValidateReplacementPlacement(ctx, pm, "node-a", true)
	if err != nil {
		t.Fatalf("resolveAndValidateReplacementPlacement: %v", err)
	}
	if dec.Action != replacementPlacementRequeue {
		t.Fatalf("recreate pass: expected requeue action, got %v", dec.Action)
	}
	pods := listReplacementPods(t, r, pm)
	if len(pods) != 1 {
		t.Fatalf("expected exactly 1 recreated replacement pod, got %d", len(pods))
	}
	if pods[0].Spec.NodeName != "" {
		t.Fatalf("recreated replacement pod must be UNBOUND so the scheduler can place it on a "+
			"distinct node (ADR-0359); got spec.nodeName=%q", pods[0].Spec.NodeName)
	}
}

// TestReplacementPlacement_RecoversWhenRescheduledToDistinctNode is the headline end-to-end recovery
// test and the direct, apiserver-LEGAL replacement for the old illegal-mutation test: reconcile #1
// deletes the same-node pod, reconcile #2 recreates it unbound, the test binds that FRESH (unbound)
// pod to node-b — the normal scheduler operation, which the real apiserver accepts — and reconcile #3
// observes the distinct, Ready placement, clears the veto, and lets the migration proceed. Every pod
// write here is one a real API server permits.
func TestReplacementPlacement_RecoversWhenRescheduledToDistinctNode(t *testing.T) {
	ctx := context.Background()
	r, pm := newPlacementFixture(t, "node-a", false) // start degenerate: replacement pod on the source

	// Reconcile #1 — same-node observed → real delete, requeue, nothing latched.
	res1, err := r.reconcileTransferring(ctx, pm)
	if err != nil {
		t.Fatalf("reconcile #1: %v", err)
	}
	if res1.RequeueAfter == 0 {
		t.Fatalf("reconcile #1: expected a requeue after the corrective delete, got %+v", res1)
	}
	if got := len(listReplacementPods(t, r, pm)); got != 0 {
		t.Fatalf("reconcile #1: same-node pod not deleted, %d still present", got)
	}
	if dn := getPM(t, r, pm).Status.DestinationNodeName; dn != "" {
		t.Fatalf("reconcile #1 latched a same-node destination (%q); recovery would be impossible once latched", dn)
	}

	// Reconcile #2 — pod gone, recovery in progress → recreate a fresh UNBOUND pod.
	pm = getPM(t, r, pm)
	if _, err := r.reconcileTransferring(ctx, pm); err != nil {
		t.Fatalf("reconcile #2: %v", err)
	}
	pods := listReplacementPods(t, r, pm)
	if len(pods) != 1 {
		t.Fatalf("reconcile #2: expected 1 recreated pod, got %d", len(pods))
	}
	if pods[0].Spec.NodeName != "" {
		t.Fatalf("reconcile #2: recreated pod should be unbound, got node %q", pods[0].Spec.NodeName)
	}

	// Simulate the scheduler binding the FRESH, still-unbound pod to a distinct node. Binding an
	// unbound pod is the normal, apiserver-legal scheduler operation — NOT the forbidden in-place
	// rebind of an already-bound pod that the old test relied on.
	fresh := &pods[0]
	fresh.Spec.NodeName = "node-b"
	if err := r.Update(ctx, fresh); err != nil {
		t.Fatalf("bind recreated pod to node-b: %v", err)
	}

	// Reconcile #3 — distinct, Ready placement → veto cleared, cache refreshed, migration proceeds.
	pm = getPM(t, r, pm)
	if _, err := r.reconcileTransferring(ctx, pm); err != nil {
		t.Fatalf("reconcile #3: %v", err)
	}
	recovered := getPM(t, r, pm)
	if recovered.Status.DestinationNodeName != "node-b" {
		t.Fatalf("recovery: expected DestinationNodeName=node-b (cached off the live rebind), got %q", recovered.Status.DestinationNodeName)
	}
	if !meta.IsStatusConditionTrue(recovered.Status.Conditions, conditionDestinationPlacementValid) {
		t.Fatalf("recovery: expected DestinationPlacementValid=True, got %+v",
			meta.FindStatusCondition(recovered.Status.Conditions, conditionDestinationPlacementValid))
	}
	if n := readSameNodeRecoveryAttempts(recovered); n != 0 {
		t.Fatalf("recovery: expected the recovery attempt counter cleared, got %d", n)
	}
	if recovered.Status.Phase == pmv1.MigrationPhaseTransferring {
		t.Fatalf("recovery: migration did not proceed past Transferring — phase still %q", recovered.Status.Phase)
	}
}

// TestReplacementPlacement_TerminalAfterBudgetExhausted proves bounded recovery is the honest
// promise: once maxSameNodeRecoveryDeletes deletes have all still landed on the source node, the
// primitive returns a terminal decision (not an infinite retry) with a human-visible reason.
func TestReplacementPlacement_TerminalAfterBudgetExhausted(t *testing.T) {
	ctx := context.Background()
	r, pm := newPlacementFixture(t, "node-a", false) // replacement pod bound to the SOURCE node

	// Pre-set the counter at the budget so this pass is the terminal one.
	pm.Annotations = map[string]string{sameNodeRecoveryAttemptsAnnotation: strconv.Itoa(maxSameNodeRecoveryDeletes)}
	if err := r.Update(ctx, pm); err != nil {
		t.Fatalf("seed exhausted counter: %v", err)
	}

	dec, err := r.resolveAndValidateReplacementPlacement(ctx, pm, "node-a", true)
	if err != nil {
		t.Fatalf("resolveAndValidateReplacementPlacement: %v", err)
	}
	if dec.Action != replacementPlacementTerminal {
		t.Fatalf("budget exhausted: expected terminal action, got %v", dec.Action)
	}
	if dec.TerminalReason == "" {
		t.Fatalf("budget exhausted: expected a non-empty human-visible terminal reason")
	}
	c := meta.FindStatusCondition(getPM(t, r, pm).Status.Conditions, conditionDestinationPlacementValid)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "SameNodePlacementUnrecoverable" {
		t.Fatalf("expected DestinationPlacementValid=False/SameNodePlacementUnrecoverable, got %+v", c)
	}
}

// TestReconcileTransferring_SameNodeUnrecoverable_RollsBack proves the wiring of the terminal
// decision: reconcileTransferring fails the migration closed to RollingBack (source pod never
// deleted — ADR-0012) rather than wedging when the placement cannot be corrected.
func TestReconcileTransferring_SameNodeUnrecoverable_RollsBack(t *testing.T) {
	ctx := context.Background()
	r, pm := newPlacementFixture(t, "node-a", false)
	pm.Annotations = map[string]string{sameNodeRecoveryAttemptsAnnotation: strconv.Itoa(maxSameNodeRecoveryDeletes)}
	if err := r.Update(ctx, pm); err != nil {
		t.Fatalf("seed exhausted counter: %v", err)
	}

	if _, err := r.reconcileTransferring(ctx, pm); err != nil {
		t.Fatalf("reconcileTransferring: %v", err)
	}
	got := getPM(t, r, pm)
	if got.Status.Phase != pmv1.MigrationPhaseRollingBack {
		t.Fatalf("expected phase RollingBack after unrecoverable same-node placement, got %q", got.Status.Phase)
	}
	// The SOURCE pod must still exist — the replacement pod is what recovery/rollback tears down, never
	// the source (ADR-0012).
	src := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: "default", Name: "app"}, src); err != nil {
		t.Fatalf("source pod must never be deleted by placement recovery (ADR-0012), but Get failed: %v", err)
	}
}

// TestReplacementPlacement_DistinctReadyNode_Valid is the happy path: a pod bound to a distinct,
// Ready node is valid, is cached into Status.DestinationNodeName for observability, and the caller is
// told to proceed.
func TestReplacementPlacement_DistinctReadyNode_Valid(t *testing.T) {
	ctx := context.Background()
	r, pm := newPlacementFixture(t, "node-b", false) // bound to a distinct, Ready node

	dec, err := r.resolveAndValidateReplacementPlacement(ctx, pm, "node-a", true)
	if err != nil {
		t.Fatalf("resolveAndValidateReplacementPlacement: %v", err)
	}
	if dec.Action != replacementPlacementProceed || !dec.Valid {
		t.Fatalf("distinct Ready node: expected proceed/valid, got action=%v valid=%v", dec.Action, dec.Valid)
	}
	if dec.DestNode != "node-b" {
		t.Fatalf("expected DestNode=node-b, got %q", dec.DestNode)
	}
	fresh := getPM(t, r, pm)
	if fresh.Status.DestinationNodeName != "node-b" {
		t.Fatalf("expected Status.DestinationNodeName cached to node-b, got %q", fresh.Status.DestinationNodeName)
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, conditionDestinationPlacementValid) {
		t.Fatalf("expected DestinationPlacementValid=True, got %+v",
			meta.FindStatusCondition(fresh.Status.Conditions, conditionDestinationPlacementValid))
	}
}

// TestNormalizeSeed_DoesNotLatchSameNodeTarget is the round-3 finding #2 regression: an operator who
// pins the migration at the pod's own current node must NOT get that same-node value latched into
// Status.DestinationNodeName by the top-level normalize/seed producer. Seed mode (correctInvalid
// false) refuses to cache it — an empty cache cannot latch the wedge — while writing nothing else, so
// it never perturbs the finalizer/phase writes in the same reconcile. The authoritative same-node
// veto and recovery happen later, in reconcileTransferring's correct-mode call.
func TestNormalizeSeed_DoesNotLatchSameNodeTarget(t *testing.T) {
	ctx := context.Background()
	r, pm := newPlacementFixture(t, "", false) // no replacement pod yet
	// Operator pins the source node as the target.
	pm.Spec.TargetNodeName = "node-a"
	if err := r.Update(ctx, pm); err != nil {
		t.Fatalf("set target: %v", err)
	}

	dec, err := r.resolveAndValidateReplacementPlacement(ctx, pm, "node-a", false)
	if err != nil {
		t.Fatalf("seed-mode resolve: %v", err)
	}
	if dec.Action == replacementPlacementTerminal {
		t.Fatalf("seed mode must never fail the migration closed; got terminal action")
	}
	if fresh := getPM(t, r, pm); fresh.Status.DestinationNodeName == "node-a" {
		t.Fatalf("normalize/seed latched the same-node target into Status.DestinationNodeName — finding #2 not fixed")
	}
}

// TestNormalizeSeed_CachesDistinctTarget is the companion happy path: a distinct declared target is
// seeded into the cache by the same seed-mode producer.
func TestNormalizeSeed_CachesDistinctTarget(t *testing.T) {
	ctx := context.Background()
	r, pm := newPlacementFixture(t, "", false)
	pm.Spec.TargetNodeName = "node-b" // distinct from source node-a
	if err := r.Update(ctx, pm); err != nil {
		t.Fatalf("set target: %v", err)
	}

	if _, err := r.resolveAndValidateReplacementPlacement(ctx, pm, "node-a", false); err != nil {
		t.Fatalf("seed-mode resolve: %v", err)
	}
	if dn := getPM(t, r, pm).Status.DestinationNodeName; dn != "node-b" {
		t.Fatalf("seed mode should cache the distinct target node-b, got %q", dn)
	}
}

// TestReplacementPlacement_GatedPinnedToSource_Terminal covers the real-substrate mis-specification:
// a still-gated replacement pod whose declared destination is the source node cannot be corrected by
// rescheduling (a gated pod is held out of the scheduling queue), so the primitive fails closed
// rather than deleting/recreating a pod that would only inherit the same bad target.
func TestReplacementPlacement_GatedPinnedToSource_Terminal(t *testing.T) {
	ctx := context.Background()
	r, pm := newPlacementFixture(t, "", true) // replacement pod present, gated, UNBOUND
	pm.Spec.TargetNodeName = "node-a"         // declared destination == source
	if err := r.Update(ctx, pm); err != nil {
		t.Fatalf("set target: %v", err)
	}

	dec, err := r.resolveAndValidateReplacementPlacement(ctx, pm, "node-a", true)
	if err != nil {
		t.Fatalf("resolveAndValidateReplacementPlacement: %v", err)
	}
	if dec.Action != replacementPlacementTerminal {
		t.Fatalf("gated + source-pinned: expected terminal action, got %v", dec.Action)
	}
	// No delete-and-recreate churn: a gated pod cannot be rescheduled, so the pod is left in place for
	// the rollback path to reap.
	if got := len(listReplacementPods(t, r, pm)); got != 1 {
		t.Fatalf("gated terminal path must not delete/recreate the pod; got %d pods", got)
	}
}
