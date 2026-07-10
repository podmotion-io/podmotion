/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = storagev1.AddToScheme(s)
	return s
}

// makePVC builds a minimal PVC for tests.
func makePVC(name, namespace, scName string, modes []corev1.PersistentVolumeAccessMode) *corev1.PersistentVolumeClaim {
	sc := scName
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      modes,
			StorageClassName: &sc,
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase: corev1.ClaimBound,
		},
	}
}

func makeSC(name, provisioner string, annotations map[string]string) *storagev1.StorageClass {
	return &storagev1.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Provisioner: provisioner,
	}
}

func makePodWithPVC(namespace, pvcName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: namespace},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: pvcName,
						},
					},
				},
			},
		},
	}
}

func TestStorageClassifier_Tier0_RWX(t *testing.T) {
	pvc := makePVC("my-pvc", "default", "nfs-sc",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany})
	sc := makeSC("nfs-sc", "nfs.csi.k8s.io", nil)
	pod := makePodWithPVC("default", "my-pvc")

	fakeClient := fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(pvc, sc).
		Build()

	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierRWX {
		t.Errorf("expected TierRWX (0), got %d", clsfs[0].Tier)
	}
}

func TestStorageClassifier_Tier1_Longhorn(t *testing.T) {
	pvc := makePVC("lh-pvc", "default", "longhorn",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce})
	sc := makeSC("longhorn", "driver.longhorn.io", nil)
	pod := makePodWithPVC("default", "lh-pvc")

	fakeClient := fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(pvc, sc).
		Build()

	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierLonghorn {
		t.Errorf("expected TierLonghorn (1), got %d", clsfs[0].Tier)
	}
}

func TestStorageClassifier_Tier3_GenericRWO(t *testing.T) {
	pvc := makePVC("rwo-pvc", "default", "ebs-csi",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce})
	sc := makeSC("ebs-csi", "ebs.csi.aws.com", nil)
	pod := makePodWithPVC("default", "rwo-pvc")

	fakeClient := fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(pvc, sc).
		Build()

	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierSnapshotRsync {
		t.Errorf("expected TierSnapshotRsync (3), got %d", clsfs[0].Tier)
	}
}

func TestStorageClassifier_Tier4_HostPath(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "hostpath-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "host-vol",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{Path: "/tmp"},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(newScheme()).Build()
	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierBlocked {
		t.Errorf("expected TierBlocked (4), got %d", clsfs[0].Tier)
	}
}

func TestStorageClassifier_Tier4_MemoryEmptyDir(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "mem-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "mem-vol",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumMemory,
						},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(newScheme()).Build()
	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierBlocked {
		t.Errorf("expected TierBlocked (4), got %d", clsfs[0].Tier)
	}
}

// TestStorageClassifier_DiskEmptyDir_IsBlocked is the contract test for C-4/A-04.
// A disk-backed emptyDir holds pod-local writable state that no migrator moves, so
// it MUST be classified TierBlocked rather than silently dropped. On the pre-change
// logic this pod produced ZERO classifications (the disk-emptyDir fell through the
// `PersistentVolumeClaim == nil` continue), so this test would have failed then —
// making it a genuine regression guard against the silent-data-loss path.
func TestStorageClassifier_DiskEmptyDir_IsBlocked(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "disk-emptydir-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "scratch",
					VolumeSource: corev1.VolumeSource{
						// Disk-backed emptyDir: Medium is the default (StorageMediumDefault),
						// NOT memory.
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(newScheme()).Build()
	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification (disk emptyDir must not be silently dropped), got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierBlocked {
		t.Errorf("expected TierBlocked (4) for disk-backed emptyDir, got %d", clsfs[0].Tier)
	}
	if clsfs[0].Reason == "" {
		t.Errorf("expected a human-actionable Reason on the blocked classification, got empty")
	}
}

// TestStorageClassifier_TransparentVolumes_NotClassified confirms that genuinely
// transparent non-PVC volumes (configMap/secret) are still skipped — the emptyDir
// fix must not over-block volumes that carry no writable pod-local state.
func TestStorageClassifier_TransparentVolumes_NotClassified(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "cm-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "cfg",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-cm"},
						},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(newScheme()).Build()
	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 0 {
		t.Fatalf("expected 0 classifications for a configMap-only pod, got %d", len(clsfs))
	}
}

func TestLonghornStubMigrator_EmitsReadyImmediately(t *testing.T) {
	stub := &storage.LonghornStubMigrator{}

	opts := storage.MigrationOptions{
		MigrationName:   "test-migration",
		PodNamespace:    "default",
		SourceNode:      "node-a",
		DestinationNode: "node-b",
		Classifications: []storage.TierClassification{
			{Tier: storage.TierLonghorn, PVCName: "lh-pvc", Reason: "Longhorn"},
		},
	}

	if err := stub.PreStage(context.Background(), opts); err != nil {
		t.Fatalf("PreStage returned error: %v", err)
	}

	pct, err := stub.SyncPercent(context.Background(), opts)
	if err != nil {
		t.Fatalf("SyncPercent returned error: %v", err)
	}
	if pct != 100 {
		t.Errorf("expected 100%% sync, got %d", pct)
	}
	if stub.PreStageCalled != 1 {
		t.Errorf("expected PreStageCalled=1, got %d", stub.PreStageCalled)
	}
}

func TestHighestTier_SelectsCorrectly(t *testing.T) {
	cases := []struct {
		name     string
		input    []storage.TierClassification
		expected storage.StorageTier
	}{
		{
			name:     "single Tier0",
			input:    []storage.TierClassification{{Tier: storage.TierRWX}},
			expected: storage.TierRWX,
		},
		{
			name: "Tier0 and Tier1 — Tier1 wins",
			input: []storage.TierClassification{
				{Tier: storage.TierRWX},
				{Tier: storage.TierLonghorn},
			},
			expected: storage.TierLonghorn,
		},
		{
			name: "Tier1 and Tier4 — Tier4 wins",
			input: []storage.TierClassification{
				{Tier: storage.TierLonghorn},
				{Tier: storage.TierBlocked},
			},
			expected: storage.TierBlocked,
		},
		{
			name:     "empty — treated as Tier0",
			input:    []storage.TierClassification{},
			expected: storage.TierRWX,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := storage.HighestTier(tc.input)
			if got.Tier != tc.expected {
				t.Errorf("expected tier %d, got %d", tc.expected, got.Tier)
			}
		})
	}
}
