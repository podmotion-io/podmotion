/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package controller

// adr0331_selector_label_preservation_test.go — ADR-0331 regression test: proves
// createReplacementPod preserves a Service's spec.selector label(s) on the bare-Pod /
// single-selector-key fixture (postgres-src.yaml pattern), and that the existing
// pod-template-hash / ReplicaSet-selector strip path is unaffected (negative control).
//
// Per ADR-0331 Decision item 4 / Context item 3: no controller code fix is made or
// needed here — createReplacementPod's label-copy path (controller.go:5161-5167)
// already preserves any Service-selector key that is not pod-template-hash or an
// owning ReplicaSet's selector key. This test pins that property so a future
// selectorKeysToStrip change cannot silently regress it.
//
// expectServiceSelectorPreserved is the SHARED, reusable SUPERSET-assertion helper
// this ADR owns building (per the integration architecture's shared-abstractions
// list) — future selector-label ADRs should reuse it rather than re-inline the
// assertion.

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

func adr0331Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme appsv1: %v", err)
	}
	return scheme
}

// expectServiceSelectorPreserved runs createReplacementPod against a source pod carrying
// sourceLabels/sourceOwnerRefs and asserts the replacement pod carries a SUPERSET of:
//   - the Service-selector key/value under test (wantSelectorKey/wantVal) — asserts
//     PRESENCE, not map equality, because the replacement pod also legitimately carries
//     the migration-name marker label (see below) and, in the negative-control case,
//     legitimately does NOT carry the stripped selector key.
//   - podmotion.io/migration-name == pm.Name (stamped unconditionally at controller.go:5167,
//     constant replacementPodMigrationNameLabel, controller.go:5430) — this is the SAME
//     object's dual-label contract with the agent's resolveSandboxIDForMigration
//     (server.go:715), so any assertion here must not regress to label-map equality,
//     which would incorrectly fail on this correct code.
//
// When wantPresent is false (the negative-control / stripped-key case), the helper instead
// asserts the key is ABSENT from the replacement pod's labels.
func expectServiceSelectorPreserved(
	t *testing.T,
	sourceLabels map[string]string,
	sourceOwnerRefs []metav1.OwnerReference,
	wantSelectorKey, wantVal string,
	wantPresent bool,
	extraObjs ...client.Object,
) {
	t.Helper()

	t.Setenv("AGENT_IMAGE", "podmotion-agent:test")

	scheme := adr0331Scheme(t)

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "adr0331-pm", Namespace: "pm-db-test", UID: "abcd1234-uid"},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "postgres-src",
			PodNamespace: "pm-db-test",
		},
	}
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "postgres-src",
			Namespace:       "pm-db-test",
			Labels:          sourceLabels,
			OwnerReferences: sourceOwnerRefs,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "postgres", Image: "postgres:16-alpine"}},
		},
	}

	objs := []client.Object{pm, srcPod}
	objs = append(objs, extraObjs...)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	if err := r.createReplacementPod(ctx, pm, srcPod); err != nil {
		t.Fatalf("createReplacementPod: %v", err)
	}

	// Fetch the created replacement pod back out via the migration-name label index
	// (mirrors resolveSandboxIDForMigration's own lookup path, server.go:715).
	list := &corev1.PodList{}
	if err := fakeClient.List(ctx, list, client.InNamespace("pm-db-test"),
		client.MatchingLabels{replacementPodMigrationNameLabel: pm.Name}); err != nil {
		t.Fatalf("list replacement pod: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected exactly 1 replacement pod, got %d", len(list.Items))
	}
	got := list.Items[0]

	// Superset assertion 1: migration-name marker label always present.
	if gotVal := got.Labels[replacementPodMigrationNameLabel]; gotVal != pm.Name {
		t.Errorf("replacementPodMigrationNameLabel = %q, want %q", gotVal, pm.Name)
	}

	// Superset assertion 2: the Service-selector key, present or absent per wantPresent.
	gotVal, ok := got.Labels[wantSelectorKey]
	if wantPresent {
		if !ok || gotVal != wantVal {
			t.Errorf("selector key %q = (%q, present=%v), want (%q, present=true)", wantSelectorKey, gotVal, ok, wantVal)
		}
	} else if ok {
		t.Errorf("selector key %q unexpectedly present with value %q; want stripped (absent)", wantSelectorKey, gotVal)
	}
}

// TestCreateReplacementPod_PreservesServiceSelectorLabels is the ADR-0331 regression test.
func TestCreateReplacementPod_PreservesServiceSelectorLabels(t *testing.T) {
	t.Run("bare pod, single-key Service selector survives (postgres-src.yaml fixture shape)", func(t *testing.T) {
		expectServiceSelectorPreserved(
			t,
			map[string]string{"app": "postgres-live"},
			nil, // no OwnerReferences — mirrors postgres-src.yaml exactly
			"app", "postgres-live",
			true,
		)
	})

	t.Run("ReplicaSet-owned source: pod-template-hash is stripped (regression pin, existing behavior)", func(t *testing.T) {
		rs := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: "some-rs", Namespace: "pm-db-test"},
			Spec: appsv1.ReplicaSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"pod-template-hash": "abc123"},
				},
			},
		}
		expectServiceSelectorPreserved(
			t,
			map[string]string{"app": "postgres-live", "pod-template-hash": "abc123"},
			[]metav1.OwnerReference{{Kind: "ReplicaSet", Name: "some-rs", APIVersion: "apps/v1", UID: "rs-uid"}},
			"pod-template-hash", "abc123",
			false, // must be stripped
			rs,
		)
	})
}
