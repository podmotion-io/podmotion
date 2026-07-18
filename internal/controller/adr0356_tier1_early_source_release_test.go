/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0356_tier1_early_source_release_test.go — regression tests for the narrow,
// Tier1-Longhorn-only exception to ADR-0012 documented in ADR-0356: source pod release
// ahead of TrafficVerified is permitted ONLY when (a) the migration is classified
// StorageTier==TierLonghorn, (b) CheckpointTransferred=True (durable, cryptographically
// verified checkpoint on the destination node), and (c) the destination node's
// NodeMigrationCapacity is freshly Ready. Every other tier (or a not-yet-classified
// migration) must be a complete no-op — ADR-0012's normal ordering is unaffected.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

func adr0356Scheme(t *testing.T) *runtime.Scheme {
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

func tier1PM(name string, tier int32, checkpointTransferred bool) *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "src-pod",
			PodNamespace: "default",
		},
		Status: pmv1.PodMigrationStatus{
			SourceNodeName:        "node-src",
			DestinationNodeName:   "node-dst",
			StorageTier:           &tier,
			CheckpointTransferred: checkpointTransferred,
		},
	}
}

func readyNMC(name string) *pmv1.NodeMigrationCapacity {
	return &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     pmv1.NodeMigrationCapacityStatus{Ready: true},
	}
}

func notReadyNMC(name string) *pmv1.NodeMigrationCapacity {
	return &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     pmv1.NodeMigrationCapacityStatus{Ready: false},
	}
}

func srcPodOnNode(node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: node},
	}
}

// TestEarlyReleaseSourceForTier1Longhorn_NonLonghornTier_NoOp asserts every non-Longhorn
// tier (including "not yet classified", nil StorageTier) is completely untouched: the
// source pod must still exist and no condition is set. ADR-0012's normal ordering must be
// the only path for these tiers.
func TestEarlyReleaseSourceForTier1Longhorn_NonLonghornTier_NoOp(t *testing.T) {
	scheme := adr0356Scheme(t)
	for _, tc := range []struct {
		name string
		tier *int32
	}{
		{"RWX", int32Ptr(int32(storage.TierRWX))},
		{"CephRBD", int32Ptr(int32(storage.TierCephRBD))},
		{"NotYetClassified", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := srcPodOnNode("node-src")
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{Name: "pm-" + tc.name, Namespace: "default"},
				Spec:       pmv1.PodMigrationSpec{PodName: "src-pod", PodNamespace: "default"},
				Status: pmv1.PodMigrationStatus{
					SourceNodeName:        "node-src",
					DestinationNodeName:   "node-dst",
					StorageTier:           tc.tier,
					CheckpointTransferred: true,
				},
			}
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&pmv1.PodMigration{}).
				WithObjects(pod, pm, readyNMC("node-dst")).Build()
			r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

			if err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm); err != nil {
				t.Fatalf("expected no-op (nil error) for tier %v, got: %v", tc.tier, err)
			}
			got := &corev1.Pod{}
			if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, got); err != nil {
				t.Fatalf("source pod should NOT have been deleted for tier %v: %v", tc.tier, err)
			}
			if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
				t.Fatalf("ConditionTier1EarlySourceRelease must not be set for tier %v", tc.tier)
			}
		})
	}
}

// TestEarlyReleaseSourceForTier1Longhorn_RefusesBeforeCheckpointTransferred is the
// falsifiable guard on guarantee #1: without a durably-verified checkpoint on the
// destination, early release must be refused (source pod untouched, error returned).
func TestEarlyReleaseSourceForTier1Longhorn_RefusesBeforeCheckpointTransferred(t *testing.T) {
	scheme := adr0356Scheme(t)
	pod := srcPodOnNode("node-src")
	pm := tier1PM("pm1", int32(storage.TierLonghorn), false /* CheckpointTransferred */)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pod, pm, readyNMC("node-dst")).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm)
	if err == nil {
		t.Fatal("expected an error refusing early release before CheckpointTransferred=True")
	}
	got := &corev1.Pod{}
	if getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, got); getErr != nil {
		t.Fatalf("source pod should NOT have been deleted: %v", getErr)
	}
}

// TestEarlyReleaseSourceForTier1Longhorn_RefusesWhenDestNMCNotReady is the falsifiable
// guard on guarantee #2: a stale/not-Ready destination NMC must block deletion.
func TestEarlyReleaseSourceForTier1Longhorn_RefusesWhenDestNMCNotReady(t *testing.T) {
	scheme := adr0356Scheme(t)
	pod := srcPodOnNode("node-src")
	pm := tier1PM("pm1", int32(storage.TierLonghorn), true)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pod, pm, notReadyNMC("node-dst")).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm)
	if err == nil {
		t.Fatal("expected an error refusing early release when destination NMC is not Ready")
	}
	got := &corev1.Pod{}
	if getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, got); getErr != nil {
		t.Fatalf("source pod should NOT have been deleted: %v", getErr)
	}
}

// TestEarlyReleaseSourceForTier1Longhorn_DeletesWhenBothGuaranteesSatisfied is the
// positive acceptance test: with CheckpointTransferred=True and a fresh-Ready destination
// NMC, the source pod IS deleted and both conditions are set True.
func TestEarlyReleaseSourceForTier1Longhorn_DeletesWhenBothGuaranteesSatisfied(t *testing.T) {
	scheme := adr0356Scheme(t)
	pod := srcPodOnNode("node-src")
	pm := tier1PM("pm1", int32(storage.TierLonghorn), true)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pod, pm, readyNMC("node-dst")).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	if err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, &corev1.Pod{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected source pod to be deleted (NotFound), got err=%v", err)
	}
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
		t.Fatal("expected ConditionTier1EarlySourceRelease=True")
	}
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionSourcePodDeleted) {
		t.Fatal("expected conditionSourcePodDeleted=True")
	}

	// Idempotency: calling again must be a safe no-op (no error re-attempting a delete on
	// an already-absent pod).
	if err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm); err != nil {
		t.Fatalf("expected idempotent no-op on second call, got: %v", err)
	}
}

func int32Ptr(v int32) *int32 { return &v }
