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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
