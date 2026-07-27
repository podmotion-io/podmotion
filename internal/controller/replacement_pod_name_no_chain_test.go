/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// replacement_pod_name_no_chain_test.go pins the invariant that a pod name STOPS growing across
// repeated migration/recreate cycles. Before the fix, createReplacementPod and buildColdRecreatePod
// appended a per-migration suffix to the CURRENT source pod name, so migrating an already-migrated
// pod chained a second suffix ("redis-m-aaaa" -> "redis-m-aaaa-m-bbbb" -> ...), growing without
// bound. Both sites now derive the name from the STABLE ROOT (podlineage), and lineage lives in
// labels. These tests migrate a pod, then migrate ITS replacement, and assert the second name is a
// same-length function of the root — not a chain — with lineage recorded in labels.

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/podlineage"
)

func noChainScheme(t *testing.T) *runtime.Scheme {
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

// migrateOnce runs createReplacementPod for one migration and returns the created replacement pod.
func migrateOnce(t *testing.T, scheme *runtime.Scheme, pmUID string, source *corev1.Pod) *corev1.Pod {
	t.Helper()
	ns := source.Namespace
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-" + pmUID[:8], Namespace: ns, UID: types.UID(pmUID)},
		Spec:       pmv1.PodMigrationSpec{PodName: source.Name, PodNamespace: ns},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(pm, source).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	if err := r.createReplacementPod(context.Background(), pm, source); err != nil {
		t.Fatalf("createReplacementPod: %v", err)
	}
	list := &corev1.PodList{}
	if err := c.List(context.Background(), list, client.InNamespace(ns),
		client.MatchingLabels{replacementPodMigrationNameLabel: pm.Name}); err != nil {
		t.Fatalf("list replacement pod: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected exactly 1 replacement pod, got %d", len(list.Items))
	}
	return &list.Items[0]
}

func TestReplacementPodName_DoesNotChainAcrossMigrations(t *testing.T) {
	t.Setenv("AGENT_IMAGE", "podmotion-agent:test")
	scheme := noChainScheme(t)
	const ns = "default"
	const root = "migration-demo-redis"

	original := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: root, Namespace: ns, UID: "pod-uid-original"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "redis", Image: "redis:7-alpine"}}},
	}

	// Migration 1: original -> gen1 replacement.
	gen1 := migrateOnce(t, scheme, "aaaaaaaa-1111-2222-3333-444444444444", original)
	wantGen1 := root + "-m-aaaaaaaa"
	if gen1.Name != wantGen1 {
		t.Fatalf("gen1 name = %q, want %q", gen1.Name, wantGen1)
	}
	if gen1.Labels[podlineage.OriginalPodNameLabel] != root {
		t.Fatalf("gen1 original label = %q, want %q", gen1.Labels[podlineage.OriginalPodNameLabel], root)
	}
	if gen1.Labels[podlineage.GenerationLabel] != "1" {
		t.Fatalf("gen1 generation = %q, want 1", gen1.Labels[podlineage.GenerationLabel])
	}
	if gen1.Labels[podlineage.PredecessorPodNameLabel] != root {
		t.Fatalf("gen1 predecessor = %q, want %q", gen1.Labels[podlineage.PredecessorPodNameLabel], root)
	}

	// Migration 2: migrate gen1 ITSELF (this is the case that used to chain the name). Give the
	// replacement pod a UID so the predecessor-uid label is populated.
	gen1.UID = "pod-uid-gen1"
	gen2 := migrateOnce(t, scheme, "bbbbbbbb-1111-2222-3333-444444444444", gen1)
	wantGen2 := root + "-m-bbbbbbbb"
	if gen2.Name != wantGen2 {
		t.Fatalf("gen2 name = %q, want %q (must derive from ROOT, not chain onto gen1)", gen2.Name, wantGen2)
	}

	// The load-bearing anti-chaining assertions:
	if strings.Count(gen2.Name, "-m-") != 1 {
		t.Fatalf("gen2 name %q chained a second -m- suffix — names must not grow", gen2.Name)
	}
	if len(gen2.Name) != len(gen1.Name) {
		t.Fatalf("names must be fixed width across cycles: len(gen1)=%d len(gen2)=%d", len(gen1.Name), len(gen2.Name))
	}
	if podlineage.CanonicalBaseName(gen2.Name) != root {
		t.Fatalf("gen2 name %q does not canonicalize to root %q", gen2.Name, root)
	}

	// Lineage moved to labels, and it advances correctly:
	if gen2.Labels[podlineage.OriginalPodNameLabel] != root {
		t.Fatalf("gen2 original label = %q, want stable root %q", gen2.Labels[podlineage.OriginalPodNameLabel], root)
	}
	if gen2.Labels[podlineage.GenerationLabel] != "2" {
		t.Fatalf("gen2 generation = %q, want 2 (predecessor 1 + 1)", gen2.Labels[podlineage.GenerationLabel])
	}
	if gen2.Labels[podlineage.PredecessorPodNameLabel] != gen1.Name {
		t.Fatalf("gen2 predecessor name = %q, want gen1 %q", gen2.Labels[podlineage.PredecessorPodNameLabel], gen1.Name)
	}
	if gen2.Labels[podlineage.PredecessorUIDLabel] != "pod-uid-gen1" {
		t.Fatalf("gen2 predecessor uid = %q, want pod-uid-gen1", gen2.Labels[podlineage.PredecessorUIDLabel])
	}

	// Third cycle for good measure: still bounded, generation 3, root intact.
	gen2.UID = "pod-uid-gen2"
	gen3 := migrateOnce(t, scheme, "cccccccc-1111-2222-3333-444444444444", gen2)
	if gen3.Name != root+"-m-cccccccc" {
		t.Fatalf("gen3 name = %q, want %q", gen3.Name, root+"-m-cccccccc")
	}
	if gen3.Labels[podlineage.GenerationLabel] != "3" {
		t.Fatalf("gen3 generation = %q, want 3", gen3.Labels[podlineage.GenerationLabel])
	}
}
