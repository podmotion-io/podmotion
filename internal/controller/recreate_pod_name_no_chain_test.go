/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// recreate_pod_name_no_chain_test.go pins Site 2 (buildColdRecreatePod): the cold-recreate pod name
// derives from the STABLE ROOT recovered from the captured snapshot's lineage labels, not from
// s.BaseName (which, on an already-migrated source, is itself a suffixed name). It also asserts the
// recreate pod carries the lineage labels and deliberately takes NO PodMigration ownerReference.

import (
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/podlineage"
)

func TestColdRecreatePodName_DoesNotChain(t *testing.T) {
	const root = "migration-demo-redis"
	specJSON, err := json.Marshal(&corev1.PodSpec{
		Containers: []corev1.Container{{Name: "redis", Image: "redis:7-alpine"}},
	})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}

	pm := &pmv1.PodMigration{}
	pm.UID = types.UID("bbbbbbbb-1111-2222-3333-444444444444")

	// The captured source pod is itself a prior migration's replacement: its name is already
	// suffixed AND it carries the root/generation lineage labels (captured into s.Labels).
	pm.Status.SourcePodSpecSnapshot = &pmv1.SourcePodSpecSnapshot{
		PodSpecJSON:  specJSON,
		BaseName:     root + "-m-aaaaaaaa",
		Namespace:    "default",
		SourcePodUID: "src-uid-gen1",
		Labels: map[string]string{
			podlineage.OriginalPodNameLabel: root,
			podlineage.GenerationLabel:      "1",
			"app":                           "redis",
		},
	}

	pod, err := buildColdRecreatePod(pm)
	if err != nil {
		t.Fatalf("buildColdRecreatePod: %v", err)
	}

	// Name derives from ROOT, not from the suffixed BaseName — no chaining.
	want := root + "-r-bbbbbbbb"
	if pod.Name != want {
		t.Fatalf("recreate name = %q, want %q (root-derived, not chained onto BaseName)", pod.Name, want)
	}
	if strings.Count(pod.Name, "-m-") != 0 || strings.Count(pod.Name, "-r-") != 1 {
		t.Fatalf("recreate name %q must not chain the source's -m- suffix", pod.Name)
	}
	if podlineage.CanonicalBaseName(pod.Name) != root {
		t.Fatalf("recreate name %q does not canonicalize to root %q", pod.Name, root)
	}

	// Lineage recorded in labels; generation advances from the captured predecessor's 1 -> 2.
	if pod.Labels[podlineage.OriginalPodNameLabel] != root {
		t.Fatalf("original label = %q, want %q", pod.Labels[podlineage.OriginalPodNameLabel], root)
	}
	if pod.Labels[podlineage.GenerationLabel] != "2" {
		t.Fatalf("generation label = %q, want 2", pod.Labels[podlineage.GenerationLabel])
	}
	if pod.Labels[podlineage.PredecessorPodNameLabel] != root+"-m-aaaaaaaa" {
		t.Fatalf("predecessor name label = %q, want %q", pod.Labels[podlineage.PredecessorPodNameLabel], root+"-m-aaaaaaaa")
	}
	if pod.Labels[podlineage.PredecessorUIDLabel] != "src-uid-gen1" {
		t.Fatalf("predecessor uid label = %q, want src-uid-gen1", pod.Labels[podlineage.PredecessorUIDLabel])
	}
	// The distinct recreate marker is still present (idempotency/discovery contract, ADR-0393).
	if pod.Labels[rollbackRecreateMigrationUIDLabel] != string(pm.UID) {
		t.Fatalf("recreate marker label = %q, want %q", pod.Labels[rollbackRecreateMigrationUIDLabel], string(pm.UID))
	}
	// Standalone recovered pod: no PodMigration ownerReference (would cascade-delete the recovery).
	if len(pod.OwnerReferences) != 0 {
		t.Fatalf("recreate pod must carry no ownerReferences, got %d", len(pod.OwnerReferences))
	}
}

// TestColdRecreatePodName_FirstGenerationSeed: a never-migrated source (no lineage labels) seeds the
// root from the canonicalized BaseName and lands at generation 1 — the existing "<base>-r-<uid>"
// shape (ADR-0393) is preserved for the common case.
func TestColdRecreatePodName_FirstGenerationSeed(t *testing.T) {
	specJSON, _ := json.Marshal(&corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "postgres:16"}}})
	pm := &pmv1.PodMigration{}
	pm.UID = types.UID("cccccccc-1111-2222-3333-444444444444")
	pm.Status.SourcePodSpecSnapshot = &pmv1.SourcePodSpecSnapshot{
		PodSpecJSON:  specJSON,
		BaseName:     "src-pod",
		Namespace:    "default",
		SourcePodUID: "src-uid-0",
	}
	pod, err := buildColdRecreatePod(pm)
	if err != nil {
		t.Fatalf("buildColdRecreatePod: %v", err)
	}
	if pod.Name != "src-pod-r-cccccccc" {
		t.Fatalf("recreate name = %q, want src-pod-r-cccccccc", pod.Name)
	}
	if pod.Labels[podlineage.OriginalPodNameLabel] != "src-pod" {
		t.Fatalf("original label = %q, want src-pod", pod.Labels[podlineage.OriginalPodNameLabel])
	}
	if pod.Labels[podlineage.GenerationLabel] != "1" {
		t.Fatalf("generation label = %q, want 1", pod.Labels[podlineage.GenerationLabel])
	}
}
