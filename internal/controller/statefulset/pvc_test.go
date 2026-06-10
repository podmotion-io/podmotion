/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package statefulset

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func makePVC(name, namespace, podName string, phase corev1.PersistentVolumeClaimPhase) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				LabelStatefulSetPodName: podName,
			},
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase: phase,
		},
	}
}

// TestStatefulSetPVCFollowAlong_FindsByLabel verifies that FindPVCsForPod correctly
// filters PVCs by the statefulset.kubernetes.io/pod-name label.
func TestStatefulSetPVCFollowAlong_FindsByLabel(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	pvc1 := makePVC("data-myapp-2", "default", "myapp-2", corev1.ClaimBound)
	pvc2 := makePVC("logs-myapp-2", "default", "myapp-2", corev1.ClaimBound)
	pvcOther := makePVC("data-myapp-1", "default", "myapp-1", corev1.ClaimBound)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pvc1, pvc2, pvcOther).
		Build()

	f := &PVCFollowAlong{Client: fakeClient}
	names, err := f.FindPVCsForPod(context.Background(), "default", "myapp-2")
	if err != nil {
		t.Fatalf("FindPVCsForPod: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("expected 2 PVCs for myapp-2, got %d: %v", len(names), names)
	}
	// Ensure the other pod's PVC is not included.
	for _, n := range names {
		if n == "data-myapp-1" {
			t.Errorf("found PVC for myapp-1 in results for myapp-2")
		}
	}
}

// TestStatefulSetPVCFollowAlong_VerifyBound verifies that VerifyPVCBound returns
// an error when a PVC is in a non-Bound phase.
func TestStatefulSetPVCFollowAlong_VerifyBound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	pvcBound := makePVC("data-myapp-0", "default", "myapp-0", corev1.ClaimBound)
	pvcPending := makePVC("logs-myapp-0", "default", "myapp-0", corev1.ClaimPending)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pvcBound, pvcPending).
		Build()

	f := &PVCFollowAlong{Client: fakeClient}

	// Verifying only the bound PVC should succeed.
	if err := f.VerifyPVCBound(context.Background(), "default", []string{"data-myapp-0"}); err != nil {
		t.Errorf("expected no error for Bound PVC, got: %v", err)
	}

	// Verifying the pending PVC should fail.
	if err := f.VerifyPVCBound(context.Background(), "default", []string{"logs-myapp-0"}); err == nil {
		t.Error("expected error for Pending PVC, got nil")
	}
}
