/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestDeleteReplacementPod_ReapsByLabelWhenStatusMirrorEmpty is the regression guard for the
// live-proof-cycle2 §6 split-brain. On the rollback path the replacement pod (redis-src-m-*)
// was left Running AND enrolled in the source Service's Endpoints alongside the resumed source,
// so the client round-robined between two diverging Redis instances and logged sequence-
// regression WRITE_ERRORs for minutes after RolledBack=True.
//
// Root cause: deleteReplacementPod resolved its target only through pm.Status.ReplacementPodName,
// a status-subresource mirror the codebase documents (reconcileTCPVerifying, ~L1180) as losable
// to a clobber race. When that mirror reads "" the old name-only path early-returned and never
// deleted the pod. The fix keys the teardown on the source-of-truth podmotion.io/migration-name
// LABEL the pod is stamped with at creation, so an empty mirror can no longer strand a live,
// unsynchronized replacement in the dataplane.
//
// This test sets Status.ReplacementPodName to "" (the clobber-race window) while the replacement
// pod carries the label, and asserts the teardown still deletes it.
func TestDeleteReplacementPod_ReapsByLabelWhenStatusMirrorEmpty(t *testing.T) {
	scheme := adr0210Scheme(t)

	const ns = "pm-redis-test"
	const replName = "redis-src-m-24b3bf9b"

	repl := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      replName,
			Namespace: ns,
			Labels:    map[string]string{replacementPodMigrationNameLabel: "redis-live-strict"},
		},
		Spec:   corev1.PodSpec{NodeName: "pm-w2", Containers: []corev1.Container{{Name: "redis", Image: "redis:7-alpine"}}},
		Status: corev1.PodStatus{PodIP: "10.244.1.128"},
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-live-strict", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "redis-src",
			PodNamespace:        ns,
			TargetNodeName:      "pm-w2",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:          pmv1.MigrationPhaseRollingBack,
			SourceNodeName: "pm-w1",
			// Deliberately EMPTY — reproduces the clobber-race window in which the prior
			// name-only teardown early-returned and left the replacement pod alive (§6).
			ReplacementPodName: "",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, repl).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	r.deleteReplacementPod(context.Background(), pm)

	got := &corev1.Pod{}
	err := fakeClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: replName}, got)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("replacement pod must be reaped by label even when Status.ReplacementPodName is empty "+
			"(live-proof-cycle2 §6 split-brain regression); got err=%v", err)
	}
}

// TestDeleteReplacementPod_ReapsStalePriorAttempt asserts the teardown reaps EVERY pod carrying
// this migration's label, not just the one named in the status mirror — a stale prior-attempt
// replacement pod is an equally live split-brain endpoint and must not be left behind.
func TestDeleteReplacementPod_ReapsStalePriorAttempt(t *testing.T) {
	scheme := adr0210Scheme(t)

	const ns = "pm-redis-test"
	stale := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "redis-src-m-stale00",
			Namespace: ns,
			Labels:    map[string]string{replacementPodMigrationNameLabel: "redis-live-strict"},
		},
		Status: corev1.PodStatus{PodIP: "10.244.1.100"},
	}
	current := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "redis-src-m-current0",
			Namespace: ns,
			Labels:    map[string]string{replacementPodMigrationNameLabel: "redis-live-strict"},
		},
		Status: corev1.PodStatus{PodIP: "10.244.1.128"},
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-live-strict", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "redis-src",
			PodNamespace:        ns,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:              pmv1.MigrationPhaseRollingBack,
			ReplacementPodName: "redis-src-m-current0", // mirror knows only the current attempt
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, stale, current).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	r.deleteReplacementPod(context.Background(), pm)

	for _, name := range []string{"redis-src-m-stale00", "redis-src-m-current0"} {
		got := &corev1.Pod{}
		if err := fakeClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, got); !apierrors.IsNotFound(err) {
			t.Fatalf("pod %s must be reaped by label (stale prior-attempt replacements are split-brain endpoints too); got err=%v", name, err)
		}
	}
}

// ── ADR-0350 D4: replacement-endpoint-removal happens-before RolledBack=True ───────────────

// replacementEndpointSlice builds an EndpointSlice whose endpoints reference replPod (and,
// if non-nil, sourcePod) by TargetRef.UID — the ADR-0350 D1 match key.
func replacementEndpointSlice(ns, sliceName string, replPod, sourcePod *corev1.Pod) *discoveryv1.EndpointSlice {
	eps := []discoveryv1.Endpoint{}
	if sourcePod != nil {
		eps = append(eps, discoveryv1.Endpoint{
			Addresses: []string{sourcePod.Status.PodIP},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: sourcePod.Name, UID: sourcePod.UID},
		})
	}
	eps = append(eps, discoveryv1.Endpoint{
		Addresses: []string{replPod.Status.PodIP},
		TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: replPod.Name, UID: replPod.UID},
	})
	return &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: sliceName, Namespace: ns},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   eps,
	}
}

// TestDeleteReplacementPod_RemovesEndpointSliceMembership is D4's membership-removal test:
// after teardown, the replacement's EndpointSlice entry must be gone and only the resumed
// source's entry must remain.
func TestDeleteReplacementPod_RemovesEndpointSliceMembership(t *testing.T) {
	scheme := adr0210Scheme(t)
	const ns = "pm-redis-test"

	repl := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-src-m-abc123", Namespace: ns, UID: "repl-uid-1",
			Labels: map[string]string{replacementPodMigrationNameLabel: "redis-live-strict"}},
		Status: corev1.PodStatus{PodIP: "10.244.1.50"},
	}
	source := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-src", Namespace: ns, UID: "source-uid-1"},
		Status:     corev1.PodStatus{PodIP: "10.244.0.10"},
	}
	slice := replacementEndpointSlice(ns, "redis-src-slice", repl, source)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-live-strict", Namespace: ns},
		Spec:       pmv1.PodMigrationSpec{PodName: "redis-src", PodNamespace: ns, TCPPreservationMode: pmv1.TCPPreservationModeStrict},
		Status:     pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhaseRollingBack},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, repl, source, slice).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	reaped := r.deleteReplacementPod(context.Background(), pm)
	ok, mode, err := r.ensureReplacementEndpointsRemoved(context.Background(), pm, reaped)
	if err != nil || !ok {
		t.Fatalf("ensureReplacementEndpointsRemoved: ok=%v mode=%q err=%v", ok, mode, err)
	}

	got := &discoveryv1.EndpointSlice{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "redis-src-slice"}, got); err != nil {
		t.Fatalf("get slice: %v", err)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].TargetRef.UID != "source-uid-1" {
		t.Fatalf("expected only the source endpoint to remain, got %+v", got.Endpoints)
	}
}

// TestDeleteReplacementPod_RemovalHappensBeforeRolledBack drives the full reconciler and
// asserts the ordering invariant: RolledBack=True is only ever observed alongside a confirmed
// absence of the replacement's EndpointSlice entry.
func TestDeleteReplacementPod_RemovalHappensBeforeRolledBack(t *testing.T) {
	var logBuf bytes.Buffer
	logf.SetLogger(zap.New(zap.WriteTo(&logBuf), zap.UseDevMode(true)))

	scheme := adr0210Scheme(t)
	const ns = "pm-redis-test"

	repl := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-src-m-abc123", Namespace: ns, UID: "repl-uid-2",
			Labels: map[string]string{replacementPodMigrationNameLabel: "redis-live-strict"}},
		Spec:   corev1.PodSpec{NodeName: "pm-w2"},
		Status: corev1.PodStatus{PodIP: "10.244.1.51"},
	}
	source := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-src", Namespace: ns, UID: "source-uid-2"},
		Spec:       corev1.PodSpec{NodeName: "pm-w1"},
		Status:     corev1.PodStatus{PodIP: "10.244.0.11"},
	}
	slice := replacementEndpointSlice(ns, "redis-src-slice2", repl, source)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-live-strict", Namespace: ns, Finalizers: []string{finalizerName}},
		Spec: pmv1.PodMigrationSpec{
			PodName: "redis-src", PodNamespace: ns, TargetNodeName: "pm-w2",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseRollingBack,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, repl, source, slice).WithStatusSubresource(pm).Build()
	spy := &spyRollbacker{}
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: spy}

	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "redis-live-strict", Namespace: ns}}

	t.Run("clean_removal_gates_rolledback_true", func(t *testing.T) {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}

		fresh := &pmv1.PodMigration{}
		if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
			t.Fatalf("get pm: %v", err)
		}
		if !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionRolledBack) {
			t.Fatalf("expected RolledBack=True after a clean removal+confirm, got conditions=%+v", fresh.Status.Conditions)
		}
		if !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionReplacementEndpointsRemoved) {
			t.Fatalf("expected ConditionReplacementEndpointsRemoved=True as the audit record of the gate, got conditions=%+v", fresh.Status.Conditions)
		}

		got := &discoveryv1.EndpointSlice{}
		if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "redis-src-slice2"}, got); err != nil {
			t.Fatalf("get slice: %v", err)
		}
		for _, ep := range got.Endpoints {
			if ep.TargetRef != nil && ep.TargetRef.UID == "repl-uid-2" {
				t.Fatalf("replacement endpoint still present alongside RolledBack=True — split-brain window observed: %+v", got.Endpoints)
			}
		}
	})

	// "Simulated mid-rollback abort leaves RolledBack unset" — exercised precisely by
	// TestDeleteReplacementPod_SustainedContentionExhaustsRetryWithholdsRolledBack and
	// TestDeleteReplacementPod_UndeletableReplacementWithholdsRolledBackAndSignals below,
	// which drive the non-confirming branch directly rather than duplicating it here.
}

// TestDeleteReplacementPod_RemovesEndpointSliceMembership_MultiPod is D4's 2+ replacement
// membership case: current + a stale prior attempt, mirroring the existing
// TestDeleteReplacementPod_ReapsStalePriorAttempt pod-level test.
func TestDeleteReplacementPod_RemovesEndpointSliceMembership_MultiPod(t *testing.T) {
	scheme := adr0210Scheme(t)
	const ns = "pm-redis-test"

	stale := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-src-m-stale00", Namespace: ns, UID: "repl-uid-stale",
			Labels: map[string]string{replacementPodMigrationNameLabel: "redis-live-strict"}},
		Status: corev1.PodStatus{PodIP: "10.244.1.100"},
	}
	current := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-src-m-current0", Namespace: ns, UID: "repl-uid-current",
			Labels: map[string]string{replacementPodMigrationNameLabel: "redis-live-strict"}},
		Status: corev1.PodStatus{PodIP: "10.244.1.128"},
	}
	source := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-src", Namespace: ns, UID: "source-uid-3"},
		Status:     corev1.PodStatus{PodIP: "10.244.0.12"},
	}
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: "redis-src-slice3", Namespace: ns},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{source.Status.PodIP}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: source.Name, UID: source.UID}},
			{Addresses: []string{stale.Status.PodIP}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: stale.Name, UID: stale.UID}},
			{Addresses: []string{current.Status.PodIP}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: current.Name, UID: current.UID}},
		},
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-live-strict", Namespace: ns},
		Spec:       pmv1.PodMigrationSpec{PodName: "redis-src", PodNamespace: ns, TCPPreservationMode: pmv1.TCPPreservationModeStrict},
		Status:     pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhaseRollingBack, ReplacementPodName: "redis-src-m-current0"},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, stale, current, source, slice).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	reaped := r.deleteReplacementPod(context.Background(), pm)
	if len(reaped) != 2 {
		t.Fatalf("expected 2 reaped replacement pods (stale + current), got %d: %+v", len(reaped), reaped)
	}
	ok, mode, err := r.ensureReplacementEndpointsRemoved(context.Background(), pm, reaped)
	if err != nil || !ok {
		t.Fatalf("ensureReplacementEndpointsRemoved: ok=%v mode=%q err=%v", ok, mode, err)
	}

	got := &discoveryv1.EndpointSlice{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "redis-src-slice3"}, got); err != nil {
		t.Fatalf("get slice: %v", err)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].TargetRef.UID != "source-uid-3" {
		t.Fatalf("expected only the source endpoint to remain after reaping both replacement UIDs, got %+v", got.Endpoints)
	}
}

// TestDeleteReplacementPod_SustainedContentionExhaustsRetryWithholdsRolledBack is QA's added
// D4 test: force every EndpointSlice Update to 409 Conflict, modelling sustained contention
// from kube's own EndpointSlice controller, and assert the CAS retry is bounded, RolledBack is
// withheld, the reconcile requeues, and the D6 signal fires with the contended reason.
func TestDeleteReplacementPod_SustainedContentionExhaustsRetryWithholdsRolledBack(t *testing.T) {
	const ns = "pm-redis-test"

	newFixture := func() (base client.WithWatch, contended client.WithWatch, updateAttempts *int) {
		scheme := adr0210Scheme(t)
		repl := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "redis-src-m-cont01", Namespace: ns, UID: "repl-uid-3",
				Labels: map[string]string{replacementPodMigrationNameLabel: "redis-live-strict"}},
			Status: corev1.PodStatus{PodIP: "10.244.1.52"},
		}
		slice := replacementEndpointSlice(ns, "redis-src-slice4", repl, nil)
		pm := &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{Name: "redis-live-strict", Namespace: ns, Finalizers: []string{finalizerName}},
			Spec:       pmv1.PodMigrationSpec{PodName: "redis-src", PodNamespace: ns, TCPPreservationMode: pmv1.TCPPreservationModeStrict},
			Status:     pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhaseRollingBack},
		}
		b := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, repl, slice).WithStatusSubresource(pm).Build()
		attempts := 0
		c := interceptor.NewClient(b, interceptor.Funcs{
			Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if _, isSlice := obj.(*discoveryv1.EndpointSlice); isSlice {
					attempts++
					return apierrors.NewConflict(discoveryv1.Resource("endpointslices"), obj.GetName(), fmt.Errorf("simulated sustained contention"))
				}
				return cl.Update(ctx, obj, opts...)
			},
		})
		return b, c, &attempts
	}

	t.Run("unit_bound_and_mode", func(t *testing.T) {
		_, contended, updateAttempts := newFixture()
		scheme := adr0210Scheme(t)
		pm := &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{Name: "redis-live-strict", Namespace: ns},
			Spec:       pmv1.PodMigrationSpec{PodName: "redis-src", PodNamespace: ns, TCPPreservationMode: pmv1.TCPPreservationModeStrict},
			Status:     pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhaseRollingBack},
		}
		r := &PodMigrationReconciler{Client: contended, Scheme: scheme}
		reaped := r.deleteReplacementPod(context.Background(), pm) // repl.deleteConfirmed=true (pod delete itself is not intercepted)
		if len(reaped) != 1 || !reaped[0].deleteConfirmed {
			t.Fatalf("expected exactly one confirmed-deleted reaped pod, got %+v", reaped)
		}
		ok, mode, err := r.ensureReplacementEndpointsRemoved(context.Background(), pm, reaped)
		if ok {
			t.Fatalf("expected exhaustion under sustained 409s, got ok=true")
		}
		if mode != "contended" {
			t.Fatalf("expected mode=contended (all deletes confirmed, only the CAS is contended), got %q (err=%v)", mode, err)
		}
		// Boundedness: retry.DefaultRetry is a fixed 5-step budget — the interceptor forcing
		// every attempt to 409 must still yield a finite, small attempt count, not an
		// unbounded spin.
		if *updateAttempts == 0 || *updateAttempts > 10 {
			t.Fatalf("expected a small, bounded number of Update attempts (retry.DefaultRetry), got %d", *updateAttempts)
		}
	})

	t.Run("full_reconcile_withholds_and_signals", func(t *testing.T) {
		base, contended, _ := newFixture()
		rec := record.NewFakeRecorder(8)
		r := &PodMigrationReconciler{Client: contended, Scheme: adr0210Scheme(t), Rollbacker: &spyRollbacker{}, Recorder: rec}
		ctx := context.Background()
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "redis-live-strict", Namespace: ns}}

		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}

		got := &pmv1.PodMigration{}
		if err := base.Get(ctx, req.NamespacedName, got); err != nil {
			t.Fatalf("get pm after reconcile: %v", err)
		}
		if meta.IsStatusConditionTrue(got.Status.Conditions, pmv1.ConditionRolledBack) {
			t.Fatalf("RolledBack must NOT be True while the EndpointSlice CAS is exhausted under sustained contention; conditions=%+v", got.Status.Conditions)
		}
		cond := meta.FindStatusCondition(got.Status.Conditions, pmv1.ConditionReplacementEndpointsRemoved)
		if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "ReplacementEndpointRemovalContended" {
			t.Fatalf("expected ConditionReplacementEndpointsRemoved=False reason=ReplacementEndpointRemovalContended, got %+v", cond)
		}

		select {
		case msg := <-rec.Events:
			if !containsAll(msg, "Warning", "ReplacementEndpointRemovalExhausted") {
				t.Fatalf("unexpected event content: %s", msg)
			}
		default:
			t.Fatalf("expected a Warning event to be recorded on retry exhaustion, got none")
		}

		// A follow-up reconcile against the non-intercepted base client (contention lifted)
		// confirms absence on a fresh read and only then writes RolledBack=True.
		r2 := &PodMigrationReconciler{Client: base, Scheme: adr0210Scheme(t), Rollbacker: &spyRollbacker{}}
		if _, err := r2.Reconcile(ctx, req); err != nil {
			t.Fatalf("follow-up Reconcile: %v", err)
		}
		final := &pmv1.PodMigration{}
		if err := base.Get(ctx, req.NamespacedName, final); err != nil {
			t.Fatalf("get pm after follow-up reconcile: %v", err)
		}
		if !meta.IsStatusConditionTrue(final.Status.Conditions, pmv1.ConditionRolledBack) {
			t.Fatalf("expected RolledBack=True once contention clears, got conditions=%+v", final.Status.Conditions)
		}
	})
}

// TestDeleteReplacementPod_UndeletableReplacementWithholdsRolledBackAndSignals is D4's
// round-1-qaLead failure mode: a replacement pod whose Delete persistently fails (non-NotFound)
// stays Running and selector-matched, so the CAS can never confirm absence. RolledBack must be
// withheld indefinitely and the D6 signal must distinguish this from transient contention.
func TestDeleteReplacementPod_UndeletableReplacementWithholdsRolledBackAndSignals(t *testing.T) {
	scheme := adr0210Scheme(t)
	const ns = "pm-redis-test"

	repl := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-src-m-stuck01", Namespace: ns, UID: "repl-uid-4",
			Labels: map[string]string{replacementPodMigrationNameLabel: "redis-live-strict"}},
		Status: corev1.PodStatus{PodIP: "10.244.1.53"},
	}
	slice := replacementEndpointSlice(ns, "redis-src-slice5", repl, nil)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-live-strict", Namespace: ns, Finalizers: []string{finalizerName}},
		Spec:       pmv1.PodMigrationSpec{PodName: "redis-src", PodNamespace: ns, TCPPreservationMode: pmv1.TCPPreservationModeStrict},
		Status:     pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhaseRollingBack},
	}

	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, repl, slice).WithStatusSubresource(pm).Build()
	undeletable := interceptor.NewClient(base, interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, isPod := obj.(*corev1.Pod); isPod {
				return apierrors.NewForbidden(corev1.Resource("pods"), obj.GetName(), fmt.Errorf("simulated stuck finalizer / rejecting webhook"))
			}
			return c.Delete(ctx, obj, opts...)
		},
	})

	t.Run("unit_delete_unconfirmed_and_mode", func(t *testing.T) {
		r := &PodMigrationReconciler{Client: undeletable, Scheme: scheme}
		reaped := r.deleteReplacementPod(context.Background(), pm)
		if len(reaped) != 1 || reaped[0].deleteConfirmed {
			t.Fatalf("expected exactly one reaped pod with deleteConfirmed=false, got %+v", reaped)
		}
		ok, mode, err := r.ensureReplacementEndpointsRemoved(context.Background(), pm, reaped)
		if ok {
			t.Fatalf("expected ok=false for an undeletable replacement, got ok=true")
		}
		if mode != "undeletable" {
			t.Fatalf("expected mode=undeletable (delete unconfirmed), got %q (err=%v)", mode, err)
		}
	})

	t.Run("full_reconcile_withholds_and_signals_distinctly", func(t *testing.T) {
		rec := record.NewFakeRecorder(8)
		r := &PodMigrationReconciler{Client: undeletable, Scheme: scheme, Rollbacker: &spyRollbacker{}, Recorder: rec}
		ctx := context.Background()
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "redis-live-strict", Namespace: ns}}

		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}

		got := &pmv1.PodMigration{}
		if err := base.Get(ctx, req.NamespacedName, got); err != nil {
			t.Fatalf("get pm after reconcile: %v", err)
		}
		if meta.IsStatusConditionTrue(got.Status.Conditions, pmv1.ConditionRolledBack) {
			t.Fatalf("RolledBack must NOT be True over a live, undeletable replacement; conditions=%+v", got.Status.Conditions)
		}
		cond := meta.FindStatusCondition(got.Status.Conditions, pmv1.ConditionReplacementEndpointsRemoved)
		if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "ReplacementPodUndeletable" {
			t.Fatalf("expected ConditionReplacementEndpointsRemoved=False reason=ReplacementPodUndeletable (distinct from contention), got %+v", cond)
		}

		select {
		case msg := <-rec.Events:
			if !containsAll(msg, "Warning", "ReplacementEndpointRemovalExhausted") {
				t.Fatalf("unexpected event content: %s", msg)
			}
		default:
			t.Fatalf("expected a Warning event to be recorded on retry exhaustion, got none")
		}

		// Undeletable is NOT self-clearing: re-running against the SAME intercepted client
		// (the pod is still stuck) must still withhold RolledBack — no de-label/force-orphan
		// escape hatch exists in ensureReplacementEndpointsRemoved to make the CAS "win."
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("second Reconcile: %v", err)
		}
		still := &pmv1.PodMigration{}
		if err := base.Get(ctx, req.NamespacedName, still); err != nil {
			t.Fatalf("get pm after second reconcile: %v", err)
		}
		if meta.IsStatusConditionTrue(still.Status.Conditions, pmv1.ConditionRolledBack) {
			t.Fatalf("RolledBack became True on a second reconcile despite the replacement pod remaining undeletable — an escape hatch was reintroduced")
		}
	})
}

// containsAll reports whether s contains every one of subs.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
