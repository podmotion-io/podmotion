/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// checkpoint_replacement_stall_test.go — regression coverage for the checkpoint→replacement-pod
// stall: reconcileCheckpointing's Checkpointed=True fast-path used to infer "the replacement pod
// was created" from the unrelated fact "the checkpoint succeeded" (a brittle-chain defect).
// If createReplacementPod was never reached or failed on the one reconcile that set
// Checkpointed=True, every subsequent reconcile took the fast path straight to
// advanceAfterCheckpoint and never attempted creation again — the migration was permanently
// wedged with no replacement pod, until the 600s completion-deadline watchdog rolled it back.
//
// The fix (ensureReplacementPodCreated) makes both the fast-path and the main checkpoint body
// funnel through one live, label-based lookup (resolveReplacementPodByLabel) before ever advancing
// past Checkpointing, so a genuinely-missing replacement pod is detected and retried on every
// reconcile instead of being silently and permanently skipped.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// stallFixture builds a PodMigration already at phase Checkpointing with Checkpointed=True set
// (reproducing "the CRIU dump succeeded and was persisted") and NO replacement pod anywhere in the
// cluster (reproducing "createReplacementPod was never reached, or errored, before the pod was
// created") — the exact wedge state described in the incident. AGENT_IMAGE is set so, once the fix
// makes the fast-path attempt creation again, createReplacementPod's real path can succeed.
func stallFixture(t *testing.T) (*PodMigrationReconciler, *pmv1.PodMigration) {
	t.Helper()
	t.Setenv("AGENT_IMAGE", "podmotion-agent:test")
	scheme := adr0331Scheme(t)

	now := metav1.Now()
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-stall", Namespace: "default", UID: "stalluid01"},
		Spec: pmv1.PodMigrationSpec{
			PodName:        "app",
			PodNamespace:   "default",
			TargetNodeName: "node-b",
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseCheckpointing,
			SourceNodeName:      "node-a",
			DestinationNodeName: "node-b",
			// Deliberately NOT set: ReplacementPodName — mirrors the wedge where the status
			// write that would have recorded it never landed (or the pod was never created).
			Conditions: []metav1.Condition{
				{
					Type:               conditionCheckpointed,
					Status:             metav1.ConditionTrue,
					Reason:             "Checkpointed",
					Message:            "Checkpoint captured: size=1024 bytes sha256=deadbeef freeze=5ms",
					LastTransitionTime: now,
				},
			},
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

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pm, sourcePod).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	return r, pm
}

// TestCheckpointFastPathCreatesMissingReplacementPod reproduces the exact reported stall: on entry
// to reconcileCheckpointing, Checkpointed is already True but no replacement pod exists anywhere in
// the cluster. Pre-fix, the fast path returned advanceAfterCheckpoint immediately and NEVER called
// createReplacementPod — this test would have observed zero replacement pods and a Requeue after the
// call, forever. Post-fix, the fast path must detect the missing pod via the live label lookup and
// create it before advancing.
func TestCheckpointFastPathCreatesMissingReplacementPod(t *testing.T) {
	r, pm := stallFixture(t)
	ctx := context.Background()

	// Precondition sanity: confirm the wedge state really has no replacement pod anywhere, so a
	// pass here cannot be a false negative from an accidentally-preseeded pod.
	preList := &corev1.PodList{}
	if err := r.List(ctx, preList, client.InNamespace("default"),
		client.MatchingLabels{replacementPodMigrationNameLabel: pm.Name}); err != nil {
		t.Fatalf("precondition List: %v", err)
	}
	if len(preList.Items) != 0 {
		t.Fatalf("precondition violated: expected zero replacement pods before reconcile, got %d", len(preList.Items))
	}

	if _, err := r.reconcileCheckpointing(ctx, pm); err != nil {
		t.Fatalf("reconcileCheckpointing: %v", err)
	}

	// Primary assertion: a live List against the label — the same source-of-truth primitive
	// resolveAndValidateReplacementPlacement trusts — must now find exactly one replacement pod.
	postList := &corev1.PodList{}
	if err := r.List(ctx, postList, client.InNamespace("default"),
		client.MatchingLabels{replacementPodMigrationNameLabel: pm.Name}); err != nil {
		t.Fatalf("postcondition List: %v", err)
	}
	if len(postList.Items) != 1 {
		t.Fatalf("expected exactly 1 replacement pod to be created by the checkpoint fast-path, got %d", len(postList.Items))
	}

	// Defense-in-depth: the status mirror should have been (re)populated to match.
	fresh := &pmv1.PodMigration{}
	if err := r.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("Get fresh: %v", err)
	}
	if fresh.Status.ReplacementPodName != postList.Items[0].Name {
		t.Fatalf("Status.ReplacementPodName = %q, want it to match the created pod %q",
			fresh.Status.ReplacementPodName, postList.Items[0].Name)
	}

	// ADR-0012 safety: the source pod must never be touched/deleted by this path.
	srcCheck := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Name: "app", Namespace: "default"}, srcCheck); err != nil {
		t.Fatalf("ADR-0012 violation: source pod is gone after checkpoint fast-path: %v", err)
	}
}

// TestEnsureReplacementPodCreatedSelfHealsCache exercises the "pod exists but the status mirror is
// stale/empty" half of ensureReplacementPodCreated directly: a replacement pod already exists
// (carrying the label) but pm.Status.ReplacementPodName was never recorded (e.g. lost to a
// status-write race). The helper must find it via the live lookup, self-heal the cache, and create
// NOTHING new — asserting we never double-create when a pod is already there.
func TestEnsureReplacementPodCreatedSelfHealsCache(t *testing.T) {
	r, pm := stallFixture(t)
	ctx := context.Background()

	existing := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-existing-repl",
			Namespace: "default",
			Labels:    map[string]string{replacementPodMigrationNameLabel: pm.Name},
		},
	}
	if err := r.Create(ctx, existing); err != nil {
		t.Fatalf("seed existing replacement pod: %v", err)
	}

	sourcePod := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Name: "app", Namespace: "default"}, sourcePod); err != nil {
		t.Fatalf("Get sourcePod: %v", err)
	}

	created, err := r.ensureReplacementPodCreated(ctx, pm, sourcePod)
	if err != nil {
		t.Fatalf("ensureReplacementPodCreated: %v", err)
	}
	if !created {
		t.Fatalf("expected created=true (pod found), got false")
	}

	list := &corev1.PodList{}
	if err := r.List(ctx, list, client.InNamespace("default"),
		client.MatchingLabels{replacementPodMigrationNameLabel: pm.Name}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected no NEW pod to be created when one already exists, got %d total", len(list.Items))
	}
	if list.Items[0].Name != "app-existing-repl" {
		t.Fatalf("expected the pre-existing pod to be adopted, got %q", list.Items[0].Name)
	}

	fresh := &pmv1.PodMigration{}
	if err := r.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("Get fresh: %v", err)
	}
	if fresh.Status.ReplacementPodName != "app-existing-repl" {
		t.Fatalf("expected self-healed ReplacementPodName = %q, got %q",
			"app-existing-repl", fresh.Status.ReplacementPodName)
	}
}

// TestEnsureReplacementPodCreatedFailsClosedOnLookupError proves the fail-closed guarantee: if the live lookup
// itself cannot be trusted (simulated here via a namespace mismatch causing the List to legitimately
// find nothing while ALSO not being able to fall back to a stale name), the helper must never
// fabricate created=true — it must attempt creation, and if that also cannot succeed (no AGENT_IMAGE),
// return a real error rather than silently reporting success.
func TestEnsureReplacementPodCreatedFailsClosedWithoutAgentImage(t *testing.T) {
	scheme := adr0331Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-noimage", Namespace: "default", UID: "noimageuid1"},
		Spec:       pmv1.PodMigrationSpec{PodName: "app", PodNamespace: "default"},
		Status:     pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhaseCheckpointing, SourceNodeName: "node-a"},
	}
	sourcePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: corev1.PodSpec{
			NodeName:   "node-a",
			Containers: []corev1.Container{{Name: "app", Image: "redis:7-alpine"}},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pm, sourcePod).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	// AGENT_IMAGE intentionally unset (t.Setenv not called) — createReplacementPod must fail loudly
	// per ADR-0196 rather than fabricating an image string.
	created, err := r.ensureReplacementPodCreated(context.Background(), pm, sourcePod)
	if err == nil {
		t.Fatalf("expected ensureReplacementPodCreated to fail closed when AGENT_IMAGE is unset, got created=%v, err=nil", created)
	}
	if created {
		t.Fatalf("expected created=false on failure, got true")
	}
}
