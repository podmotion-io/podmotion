/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package controller

// adr0360_ensure_replacement_pod_bound_test.go — ADR-0360 regression/unit coverage for
// ensureReplacementPodBound.
//
// Prior behavior (the bug): removeSchedulingGate returned nil (treated by the call site as
// "gate removed, proceed") on THREE separate paths that verified nothing against the live pod:
// an empty pm.Status.ReplacementPodName mirror, a NotFound Get, and "gate not present in
// whatever we happened to read." Combined with a one-shot latch at the call site, a single
// false nil permanently stranded a pod behind a scheduling gate that was never actually
// verified absent.
//
// The fix (ADR-0360): ensureReplacementPodBound resolves via the label-keyed
// resolveReplacementPodByLabel (never the raw status mirror), patches the gate off if present,
// and then re-Gets the pod fresh — bound/success is derived ONLY from that freshly observed
// object, never from a patch call's error return or from the absence of a resolvable pod.
//
// This file pins the five load-bearing behaviors: (1) an empty/stale status mirror with no
// resolvable pod must not read as success; (2) a NotFound on the only resolution the status
// mirror offers must not read as success; (3) a genuinely-gated pod has its gate removed and the
// result is verified via a fresh re-read, not trusted from the patch call; (4) re-entry once
// already bound is a safe, spurious-patch-free no-op; (5) resolving with an errored label List
// propagates the error rather than silently reporting success.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

func newADR0360TestPM() *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "adr0360-pm", Namespace: "pm-ns", UID: "adr0360-uid"},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "src-pod",
			PodNamespace: "pm-ns",
		},
	}
}

func newADR0360FakeClient(t *testing.T, pm *pmv1.PodMigration, objs ...client.Object) client.Client {
	t.Helper()
	scheme := adr0331Scheme(t)
	allObjs := append([]client.Object{pm}, objs...)
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(allObjs...).
		WithStatusSubresource(pm).
		Build()
}

func newGatedReplacementPod(name string, pm *pmv1.PodMigration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: pm.Spec.PodNamespace,
			Labels:    map[string]string{replacementPodMigrationNameLabel: pm.Name},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "redis:7-alpine"}},
			SchedulingGates: []corev1.PodSchedulingGate{
				{Name: schedulingGateAwaitingCheckpoint},
			},
		},
	}
}

// TestEnsureReplacementPodBound_EmptyStaleMirror_NotSuccess covers: an empty status mirror
// with no label-matched pod anywhere in the namespace must NOT be treated as gate-removal
// success. This is the "pm.Status.ReplacementPodName == "" { return nil }" bug in the old
// removeSchedulingGate, reproduced against the new primitive.
func TestEnsureReplacementPodBound_EmptyStaleMirror_NotSuccess(t *testing.T) {
	pm := newADR0360TestPM() // Status.ReplacementPodName left empty; no pod exists at all
	fakeClient := newADR0360FakeClient(t, pm)
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: fakeClient.Scheme()}

	pod, bound, err := r.ensureReplacementPodBound(context.Background(), pm)
	if err != nil {
		t.Fatalf("ensureReplacementPodBound returned unexpected error: %v", err)
	}
	if bound {
		t.Fatalf("bound = true, want false: an empty status mirror with no resolvable pod must never be treated as gate-removal success")
	}
	if pod != nil {
		t.Fatalf("pod = %+v, want nil", pod)
	}
}

// TestEnsureReplacementPodBound_NotFoundOnResolvedPod_NotSuccess covers: the status mirror
// names a pod that no longer exists (or never existed) and the label lookup finds nothing
// either — the NotFound path that IgnoreNotFound used to silently swallow as "nil == success"
// in the old removeSchedulingGate.
func TestEnsureReplacementPodBound_NotFoundOnResolvedPod_NotSuccess(t *testing.T) {
	pm := newADR0360TestPM()
	pm.Status.ReplacementPodName = "ghost-replacement-pod" // stale mirror, no such pod, no label match
	fakeClient := newADR0360FakeClient(t, pm)
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: fakeClient.Scheme()}

	pod, bound, err := r.ensureReplacementPodBound(context.Background(), pm)
	if err != nil {
		t.Fatalf("ensureReplacementPodBound returned unexpected error: %v", err)
	}
	if bound {
		t.Fatalf("bound = true, want false: a NotFound resolution must never be treated as gate-removal success")
	}
	if pod != nil {
		t.Fatalf("pod = %+v, want nil", pod)
	}
}

// TestEnsureReplacementPodBound_GateGenuinelyRemoved_VerifiedViaReRead covers the success path:
// a real pod with the gate present resolves via the label, the gate is patched off, and the
// primitive's own re-Get (not the Patch call's nil return) is what proves it — asserted here by
// independently re-fetching the pod from the fake client afterward and checking the gate is
// actually gone on the stored object, not just in ensureReplacementPodBound's in-memory copy.
func TestEnsureReplacementPodBound_GateGenuinelyRemoved_VerifiedViaReRead(t *testing.T) {
	pm := newADR0360TestPM()
	replacementPod := newGatedReplacementPod("adr0360-repl-pod", pm)
	fakeClient := newADR0360FakeClient(t, pm, replacementPod)
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: fakeClient.Scheme()}

	pod, bound, err := r.ensureReplacementPodBound(context.Background(), pm)
	if err != nil {
		t.Fatalf("ensureReplacementPodBound returned unexpected error: %v", err)
	}
	if !bound {
		t.Fatalf("bound = false, want true: a genuinely gate-free pod (post-patch, re-read) must report bound")
	}
	if pod == nil || pod.Name != replacementPod.Name {
		t.Fatalf("pod = %+v, want %q", pod, replacementPod.Name)
	}

	// Independently verify against the fake client's stored state — not the returned in-memory
	// object — that the gate is actually gone, and that the status mirror got healed.
	stored := &corev1.Pod{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(replacementPod), stored); err != nil {
		t.Fatalf("re-fetching stored pod: %v", err)
	}
	for _, g := range stored.Spec.SchedulingGates {
		if g.Name == schedulingGateAwaitingCheckpoint {
			t.Fatalf("stored pod still carries the %s gate after ensureReplacementPodBound reported bound=true",
				schedulingGateAwaitingCheckpoint)
		}
	}
	if pm.Status.ReplacementPodName != replacementPod.Name {
		t.Errorf("pm.Status.ReplacementPodName = %q, want healed to %q",
			pm.Status.ReplacementPodName, replacementPod.Name)
	}
}

// TestEnsureReplacementPodBound_IdempotentReentry_NoSpuriousPatch covers re-entrancy: once a
// pod is already bound (gate absent), calling ensureReplacementPodBound again must be a safe
// no-op — no spurious patch attempt, and the result stays bound=true. Asserted via
// ResourceVersion staying identical across the second call (a Patch against the fake client
// always bumps ResourceVersion, so an unchanged ResourceVersion is proof no patch was issued).
func TestEnsureReplacementPodBound_IdempotentReentry_NoSpuriousPatch(t *testing.T) {
	pm := newADR0360TestPM()
	replacementPod := newGatedReplacementPod("adr0360-repl-pod-idempotent", pm)
	fakeClient := newADR0360FakeClient(t, pm, replacementPod)
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: fakeClient.Scheme()}
	ctx := context.Background()

	// First call: gate present, gets patched off, verified via re-read.
	_, bound1, err := r.ensureReplacementPodBound(ctx, pm)
	if err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}
	if !bound1 {
		t.Fatalf("first call: bound = false, want true")
	}

	afterFirst := &corev1.Pod{}
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(replacementPod), afterFirst); err != nil {
		t.Fatalf("re-fetching pod after first call: %v", err)
	}
	rvAfterFirst := afterFirst.ResourceVersion

	// Second call: primitive must re-enter cleanly — no gate to remove, no patch issued,
	// still bound=true.
	pod2, bound2, err := r.ensureReplacementPodBound(ctx, pm)
	if err != nil {
		t.Fatalf("second (idempotent) call: unexpected error: %v", err)
	}
	if !bound2 {
		t.Fatalf("second call: bound = false, want true (idempotent re-entry must stay bound)")
	}
	if pod2 == nil || pod2.ResourceVersion != rvAfterFirst {
		t.Fatalf("second call mutated the pod (ResourceVersion %v -> %v): a call with no gate present must not issue a spurious patch",
			rvAfterFirst, pod2.ResourceVersion)
	}
}

// TestEnsureReplacementPodBound_LabelListError_PropagatesError covers: an error while listing
// by label (the primitive's resolution source of truth) must propagate as a real error, not be
// silently swallowed into a false "not yet created" (bound=false, err=nil) state — otherwise a
// transient list failure would look identical to "no replacement pod yet," undermining the
// caller's ability to distinguish a genuine requeue-and-wait from an infrastructure problem.
func TestEnsureReplacementPodBound_LabelListError_PropagatesError(t *testing.T) {
	pm := newADR0360TestPM()
	fakeClient := &erroringListClient{Client: newADR0360FakeClient(t, pm)}
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: fakeClient.Scheme()}

	_, bound, err := r.ensureReplacementPodBound(context.Background(), pm)
	if err == nil {
		t.Fatalf("expected a propagated error from a failing label List, got nil")
	}
	if bound {
		t.Fatalf("bound = true, want false alongside a propagated error")
	}
}

// erroringListClient wraps a client.Client and fails every List call, to exercise
// resolveReplacementPodByLabel's error path from ensureReplacementPodBound.
type erroringListClient struct {
	client.Client
}

func (e *erroringListClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return errListFailed
}

var errListFailed = &listFailedError{}

type listFailedError struct{}

func (*listFailedError) Error() string { return "simulated List failure" }
