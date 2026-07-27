/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0365_early_destination_decision_test.go — ADR-0365 regression/unit coverage:
//
//   - Decision §1 (resolveEarlyDestinationNode): correctly picks among healthy/NotReady/
//     at-capacity candidate nodes, and fails closed (no candidate) when none pass.
//   - Decision §2.1 (hoisted destNode-required gate): a TCPPreservationMode=None migration
//     with no resolved destination now requeues instead of proceeding straight to
//     PreCopyMemory.
//   - Decision §2.2 (bounded pre-stage dispatch): preStageDispatchTimeout's pure budget math.
//   - Condition 1 (revalidateDestinationBeforeReplacementPod): detects a destination that went
//     bad (NotReady NMC, drain-labeled, over capacity) between the early decision and actual
//     replacement-pod creation, and fails closed — redeciding for an unpinned migration,
//     rolling back for a pinned one — never force-binding to the stale node.

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

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/placement"
)

func adr0365Scheme(t *testing.T) *runtime.Scheme {
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

func adr0365NMC(name string, ready bool, active, max int32) *pmv1.NodeMigrationCapacity {
	return &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: pmv1.NodeMigrationCapacitySpec{
			CRIUVersion:                        "4.2",
			MaxConcurrentMigrationsDestination: max,
		},
		Status: pmv1.NodeMigrationCapacityStatus{
			Ready:                       ready,
			ActiveDestinationMigrations: active,
		},
	}
}

func adr0365Node(name string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// adr0365ControlPlaneNode is adr0365Node plus the standard kubeadm control-plane role
// taint, so placement.IsControlPlaneNode recognises it.
func adr0365ControlPlaneNode(name string) *corev1.Node {
	node := adr0365Node(name)
	node.Spec.Taints = []corev1.Taint{{
		Key:    placement.TaintKeyControlPlane,
		Effect: corev1.TaintEffectNoSchedule,
	}}
	return node
}

// TestResolveEarlyDestinationNode_PicksHealthyAmongHealthyUnhealthyAtCapacity is the primary
// Decision §1 test: three candidate nodes (a NotReady one, an at-capacity one, and a genuinely
// eligible one) — only the eligible one may win, and it must be written to
// Status.DestinationNodeName.
func TestResolveEarlyDestinationNode_PicksHealthyAmongHealthyUnhealthyAtCapacity(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-early", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "app", PodNamespace: "default"},
		Status:     pmv1.PodMigrationStatus{SourceNodeName: "node-src"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		pm,
		adr0365Node("node-src"),
		adr0365Node("node-notready"), adr0365NMC("node-notready", false, 0, 5),
		adr0365Node("node-atcapacity"), adr0365NMC("node-atcapacity", true, 5, 5),
		adr0365Node("node-healthy"), adr0365NMC("node-healthy", true, 0, 5),
	).WithStatusSubresource(pm).Build()

	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	winner, err := r.resolveEarlyDestinationNode(context.Background(), pm)
	if err != nil {
		t.Fatalf("resolveEarlyDestinationNode returned an error: %v", err)
	}
	if winner != "node-healthy" {
		t.Fatalf("expected winner %q, got %q", "node-healthy", winner)
	}
	if pm.Status.DestinationNodeName != "node-healthy" {
		t.Fatalf("expected Status.DestinationNodeName = %q, got %q", "node-healthy", pm.Status.DestinationNodeName)
	}
}

// TestResolveEarlyDestinationNode_NoEligibleNode_FailsClosed proves the "no candidate passes
// Filter" path returns a non-nil error and leaves Status.DestinationNodeName empty — never a
// guessed destination.
func TestResolveEarlyDestinationNode_NoEligibleNode_FailsClosed(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-noeligible", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "app", PodNamespace: "default"},
		Status:     pmv1.PodMigrationStatus{SourceNodeName: "node-src"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		pm,
		adr0365Node("node-src"),
		adr0365Node("node-a"), adr0365NMC("node-a", false, 0, 5), // NotReady
		adr0365Node("node-b"), adr0365NMC("node-b", true, 5, 5), // at capacity
	).WithStatusSubresource(pm).Build()

	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	winner, err := r.resolveEarlyDestinationNode(context.Background(), pm)
	if err == nil {
		t.Fatalf("expected an error when no candidate node is eligible, got winner=%q, nil error", winner)
	}
	if winner != "" {
		t.Fatalf("expected empty winner on failure, got %q", winner)
	}
	if pm.Status.DestinationNodeName != "" {
		t.Fatalf("expected Status.DestinationNodeName to remain empty on failure, got %q", pm.Status.DestinationNodeName)
	}
}

// TestResolveEarlyDestinationNode_PrefersWorkerOverControlPlane is the regression test for the
// wrong-destination symptom: an unpinned migration with two equally-eligible destinations, one a
// worker ("cp-worker") and one a control-plane node ("cp-master"). Both pass Filter and score
// identically, and the deterministic lexicographic tie-break ("cp-master" < "cp-worker") would
// otherwise send the workload to the control plane. The worker must win regardless — the early
// decision (ADR-0365) must not place migration workloads on the control plane when any worker is
// eligible.
func TestResolveEarlyDestinationNode_PrefersWorkerOverControlPlane(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-cp-avoid", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "app", PodNamespace: "default"},
		Status:     pmv1.PodMigrationStatus{SourceNodeName: "node-src"},
	}
	// "cp-master" sorts lexicographically before "cp-worker": pre-fix the tie-break would pick it.
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		pm,
		adr0365Node("node-src"),
		adr0365ControlPlaneNode("cp-master"), adr0365NMC("cp-master", true, 0, 5),
		adr0365Node("cp-worker"), adr0365NMC("cp-worker", true, 0, 5),
	).WithStatusSubresource(pm).Build()

	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	winner, err := r.resolveEarlyDestinationNode(context.Background(), pm)
	if err != nil {
		t.Fatalf("resolveEarlyDestinationNode returned an error: %v", err)
	}
	if winner != "cp-worker" {
		t.Fatalf("expected the worker %q to win over the control-plane node, got %q", "cp-worker", winner)
	}
	if pm.Status.DestinationNodeName != "cp-worker" {
		t.Fatalf("expected Status.DestinationNodeName = %q, got %q", "cp-worker", pm.Status.DestinationNodeName)
	}
}

// TestResolveEarlyDestinationNode_ControlPlaneAsLastResort is the companion positive case:
// deprioritising the control plane must not fail closed. When the ONLY eligible destination is a
// control-plane node (no worker qualifies), it is still selected — matching createReplacementPod's
// force-toleration of the control-plane taint, which exists precisely to support this fallback.
func TestResolveEarlyDestinationNode_ControlPlaneAsLastResort(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-cp-lastresort", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "app", PodNamespace: "default"},
		Status:     pmv1.PodMigrationStatus{SourceNodeName: "node-src"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		pm,
		adr0365Node("node-src"),
		adr0365Node("node-worker-notready"), adr0365NMC("node-worker-notready", false, 0, 5), // only worker is NotReady
		adr0365ControlPlaneNode("cp-master"), adr0365NMC("cp-master", true, 0, 5),
	).WithStatusSubresource(pm).Build()

	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	winner, err := r.resolveEarlyDestinationNode(context.Background(), pm)
	if err != nil {
		t.Fatalf("resolveEarlyDestinationNode returned an error: %v", err)
	}
	if winner != "cp-master" {
		t.Fatalf("expected the control-plane node %q as the last-resort destination, got %q", "cp-master", winner)
	}
	if pm.Status.DestinationNodeName != "cp-master" {
		t.Fatalf("expected Status.DestinationNodeName = %q, got %q", "cp-master", pm.Status.DestinationNodeName)
	}
}

// TestReconcileValidating_UnpinnedMigration_ResolvesEarlyDestination is an end-to-end (through
// reconcileValidating) check that the early decision fires for an unpinned migration and the
// migration proceeds to DestinationPrewarm with a non-empty destination.
func TestReconcileValidating_UnpinnedMigration_ResolvesEarlyDestination(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-e2e-unpinned", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "app", PodNamespace: "default"},
		Status:     pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhaseValidating},
	}
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-src"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.5"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		pm, srcPod,
		adr0365Node("node-src"), adr0365NMC("node-src", true, 0, 5),
		adr0365Node("node-dst"), adr0365NMC("node-dst", true, 0, 5),
	).WithStatusSubresource(pm).Build()

	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	if _, err := r.reconcileValidating(context.Background(), pm); err != nil {
		t.Fatalf("reconcileValidating: %v", err)
	}

	if pm.Status.DestinationNodeName != "node-dst" {
		t.Fatalf("expected the early decision to resolve Status.DestinationNodeName to %q, got %q",
			"node-dst", pm.Status.DestinationNodeName)
	}
	cond := meta.FindStatusCondition(pm.Status.Conditions, conditionDestinationResolvable)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected DestinationResolvable=True, got %+v", cond)
	}
}

// TestReconcileDestinationPrewarm_NoneMode_EmptyDestNode_RequeuesInsteadOfProceeding is the
// regression test for Decision §2.1: pre-fix, a TCPPreservationMode=None migration with no
// resolved destination transitioned straight to PreCopyMemory (skipping the destNode-required
// gate entirely). Post-fix, the same input must requeue with a diagnosable reason instead.
func TestReconcileDestinationPrewarm_NoneMode_EmptyDestNode_RequeuesInsteadOfProceeding(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-none-nodst", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "app",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
			// Deliberately no TargetNodeName/DestinationNode.
		},
		Status: pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhaseDestinationPrewarm},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	res, err := r.reconcileDestinationPrewarm(context.Background(), pm)
	if err != nil {
		t.Fatalf("reconcileDestinationPrewarm: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected a RequeueAfter (fail-closed) when TCPPreservationMode=None has no resolved "+
			"destination, got %+v (this would have been the C-2-style gap: None mode reaching "+
			"PreCopyMemory with an empty destination)", res)
	}
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionDestinationNetnsReady) {
		t.Fatalf("ConditionDestinationNetnsReady must not be set True — the None fast path must not run before the gate")
	}
}

// TestReconcileDestinationPrewarm_NoneMode_WithDestNode_StillProceeds is the companion positive
// case: once a destination IS resolved, None mode must still take its fast path unchanged.
func TestReconcileDestinationPrewarm_NoneMode_WithDestNode_StillProceeds(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-none-withdst", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "app",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseDestinationPrewarm,
			DestinationNodeName: "node-dst",
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	if _, err := r.reconcileDestinationPrewarm(context.Background(), pm); err != nil {
		t.Fatalf("reconcileDestinationPrewarm: %v", err)
	}
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionDestinationNetnsReady) {
		t.Fatalf("expected the None fast path to still set ConditionDestinationNetnsReady=True once a destination is resolved")
	}
}

// TestPreStageDispatchTimeout_DerivesFromCompletionBudgetAndFloors pins preStageDispatchTimeout's
// pure budget math (Decision §2.2): half the completion budget, defaulting to 600s when unset,
// floored at preStageMinDispatchTimeout so a tiny/zero budget can't collapse it further.
func TestPreStageDispatchTimeout_DerivesFromCompletionBudgetAndFloors(t *testing.T) {
	cases := []struct {
		name    string
		budget  int32
		wantMin time.Duration
		wantMax time.Duration
	}{
		{"default budget (unset)", 0, 299 * time.Second, 301 * time.Second}, // 600/2
		{"explicit 200s budget", 200, 99 * time.Second, 101 * time.Second},  // 200/2
		{"tiny budget floors", 10, preStageMinDispatchTimeout, preStageMinDispatchTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pm := &pmv1.PodMigration{Spec: pmv1.PodMigrationSpec{CompletionTimeoutSeconds: tc.budget}}
			got := preStageDispatchTimeout(pm)
			if got < tc.wantMin || got > tc.wantMax {
				t.Fatalf("preStageDispatchTimeout(budget=%d) = %s, want in [%s, %s]",
					tc.budget, got, tc.wantMin, tc.wantMax)
			}
		})
	}
}

// TestRevalidateDestination_UnpinnedStaleNode_RedecidesToHealthyNode is the Condition 1
// regression test for the unpinned case: the previously-resolved destination went NotReady
// between the early decision and replacement-pod creation. The revalidation must fail closed —
// never force-bind to the stale node — and, being unpinned, re-run the early decision to land on
// the one healthy alternative.
func TestRevalidateDestination_UnpinnedStaleNode_RedecidesToHealthyNode(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-reval-unpinned", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "app", PodNamespace: "default"},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseCheckpointing,
			SourceNodeName:      "node-src",
			DestinationNodeName: "node-bad",
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(
		pm,
		adr0365Node("node-src"),
		adr0365Node("node-bad"), adr0365NMC("node-bad", false, 0, 5), // went NotReady
		adr0365Node("node-good"), adr0365NMC("node-good", true, 0, 5),
	).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	res, proceed, err := r.revalidateDestinationBeforeReplacementPod(context.Background(), pm)
	if err != nil {
		t.Fatalf("revalidateDestinationBeforeReplacementPod: %v", err)
	}
	if proceed {
		t.Fatalf("expected proceed=false on the first (staleness-detected) call")
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected a requeue after redeciding, got %+v", res)
	}
	if pm.Status.DestinationNodeName != "node-good" {
		t.Fatalf("expected the stale destination to be replaced with the healthy alternative %q, got %q",
			"node-good", pm.Status.DestinationNodeName)
	}
	cond := meta.FindStatusCondition(pm.Status.Conditions, conditionDestinationResolvable)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "RedecidedAfterStaleness" {
		t.Fatalf("expected DestinationResolvable=True/RedecidedAfterStaleness, got %+v", cond)
	}

	// Never force-bound to the stale node.
	if pm.Status.DestinationNodeName == "node-bad" {
		t.Fatalf("must never force-bind to the now-invalid node")
	}
}

// TestRevalidateDestination_PinnedStaleNode_FailsClosedToRollingBack is the Condition 1
// regression test for the pinned case: the controller must not silently pick a different node
// than the operator pinned, so a stale pinned destination fails the phase and rolls back
// (invariant #8/ADR-0012 pattern), rather than force-binding or guessing an alternative.
func TestRevalidateDestination_PinnedStaleNode_FailsClosedToRollingBack(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-reval-pinned", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:        "app",
			PodNamespace:   "default",
			TargetNodeName: "node-bad",
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseCheckpointing,
			SourceNodeName:      "node-src",
			DestinationNodeName: "node-bad",
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(
		pm,
		adr0365Node("node-src"),
		adr0365Node("node-bad"), adr0365NMC("node-bad", false, 0, 5), // went NotReady
	).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	_, proceed, err := r.revalidateDestinationBeforeReplacementPod(context.Background(), pm)
	if err != nil {
		t.Fatalf("revalidateDestinationBeforeReplacementPod: %v", err)
	}
	if proceed {
		t.Fatalf("expected proceed=false for a pinned migration whose destination went stale")
	}

	fresh := &pmv1.PodMigration{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("Get fresh: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseRollingBack {
		t.Fatalf("expected the pinned migration to fail closed to RollingBack, got phase %q", fresh.Status.Phase)
	}
	if fresh.Status.DestinationNodeName != "node-bad" {
		t.Fatalf("must never force-bind/silently redecide a pinned migration's destination; expected it to remain %q, got %q",
			"node-bad", fresh.Status.DestinationNodeName)
	}
	rbCond := meta.FindStatusCondition(fresh.Status.Conditions, "RollbackReason")
	if rbCond == nil || rbCond.Status != metav1.ConditionTrue {
		t.Fatalf("expected a RollbackReason=True condition explaining the failure, got %+v", rbCond)
	}
}

// TestRevalidateDestination_DrainLabeled_FailsClosed proves the "newly drain-labeled" staleness
// signal the ADR names explicitly, independent of NMC readiness.
func TestRevalidateDestination_DrainLabeled_FailsClosed(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-reval-drain", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "app", PodNamespace: "default"},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseCheckpointing,
			SourceNodeName:      "node-src",
			DestinationNodeName: "node-bad",
		},
	}
	drainedNode := adr0365Node("node-bad")
	drainedNode.Labels = map[string]string{placement.LabelDraining: "true"}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(
		pm,
		adr0365Node("node-src"),
		drainedNode, adr0365NMC("node-bad", true, 0, 5), // NMC itself still reports Ready — only the label changed
		adr0365Node("node-good"), adr0365NMC("node-good", true, 0, 5),
	).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	_, proceed, err := r.revalidateDestinationBeforeReplacementPod(context.Background(), pm)
	if err != nil {
		t.Fatalf("revalidateDestinationBeforeReplacementPod: %v", err)
	}
	if proceed {
		t.Fatalf("expected proceed=false once the destination node is drain-labeled")
	}
	if pm.Status.DestinationNodeName != "node-good" {
		t.Fatalf("expected redecision away from the drain-labeled node to %q, got %q", "node-good", pm.Status.DestinationNodeName)
	}
}

// TestRevalidateDestination_HealthyNode_Proceeds is the negative control: an unchanged, still-
// healthy destination must be a no-op that lets the caller proceed to pod creation.
func TestRevalidateDestination_HealthyNode_Proceeds(t *testing.T) {
	scheme := adr0365Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-reval-healthy", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "app", PodNamespace: "default"},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseCheckpointing,
			SourceNodeName:      "node-src",
			DestinationNodeName: "node-good",
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(
		pm,
		adr0365Node("node-src"),
		adr0365Node("node-good"), adr0365NMC("node-good", true, 0, 5),
	).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	res, proceed, err := r.revalidateDestinationBeforeReplacementPod(context.Background(), pm)
	if err != nil {
		t.Fatalf("revalidateDestinationBeforeReplacementPod: %v", err)
	}
	if !proceed {
		t.Fatalf("expected proceed=true for a still-healthy destination")
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected a zero-value Result on the proceed path, got %+v", res)
	}
	if pm.Status.DestinationNodeName != "node-good" {
		t.Fatalf("healthy destination must be left unchanged, got %q", pm.Status.DestinationNodeName)
	}
}
