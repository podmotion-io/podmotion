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

// trueBoolPtr mirrors internal/controller/adr0387_tier1_owner_kind_test.go's helper of the
// same shape — OwnerReference.Controller is *bool, and there is no addressable literal.
func trueBoolPtr() *bool { b := true; return &b }

// makeOwnedPodWithPVC is identical to makePodWithPVC except the pod carries a
// Controller=true OwnerReference (e.g. a ReplicaSet), for ADR-0391 test fixtures that need
// to distinguish "has an owning controller" from the bare-pod case makePodWithPVC produces.
func makeOwnedPodWithPVC(namespace, pvcName string) *corev1.Pod {
	pod := makePodWithPVC(namespace, pvcName)
	pod.OwnerReferences = []metav1.OwnerReference{
		{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "test-rs", UID: "test-rs-uid", Controller: trueBoolPtr()},
	}
	return pod
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
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
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

// TestStorageClassifier_Tier1Longhorn_RWO_IsBlocked is the regression test for ADR-0387: a
// Longhorn-backed PVC that is NOT ReadWriteMany (the cluster's default single-attach
// `longhorn` StorageClass) must be classified TierBlocked, never TierLonghorn. Longhorn's
// dual-engine live migration does not exist for a ReadWriteOnce volume regardless of
// StorageClass name — before this fix, this exact fixture was classified TierLonghorn and
// routed through ADR-0356's early-source-release path, whose recovery guarantee is
// structurally unmet for a standalone pod (see docs/adr/0387-longhorn-tier-requires-rwx.md).
func TestStorageClassifier_Tier1Longhorn_RWO_IsBlocked(t *testing.T) {
	pvc := makePVC("lh-pvc", "default", "longhorn",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce})
	sc := makeSC("longhorn", "driver.longhorn.io", nil)
	pod := makePodWithPVC("default", "lh-pvc")

	fakeClient := fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(pvc, sc).
		Build()

	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierBlocked {
		t.Errorf("expected TierBlocked (4) for a ReadWriteOnce Longhorn PVC, got %d (reason=%q)",
			clsfs[0].Tier, clsfs[0].Reason)
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
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
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
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
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
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
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
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
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

// TestStorageClassifier_PodmotionHolderVolume_NotBlocked is the regression guard
// for a real bug confirmed live 2026-07-18: a bare nginx pod's SECOND migration
// (after a first, successful one) permanently stalled at PreCopyMemory with
// StorageReadyForFreeze=False/BlockedVolume. Root cause: PodMotion's own
// mutating webhook injects a disk-backed emptyDir ("podmotion-holder-bin") into
// every replacement pod to stage the holder binary, and the classifier's
// disk-emptyDir-must-block rule couldn't distinguish that from real user data —
// meaning ANY pod that had already been migrated once could never migrate
// again, on any tier or CNI, since the webhook re-injects this same volume
// every time. This volume holds no pod data (recreated fresh on every
// migration), so it must always be transparent, unlike a genuine user emptyDir.
func TestStorageClassifier_PodmotionHolderVolume_NotBlocked(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "twice-migrated-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "podmotion-holder-bin",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(newScheme()).Build()
	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 0 {
		t.Fatalf("expected 0 classifications for PodMotion's own injected holder volume (must be transparent), got %d: %+v", len(clsfs), clsfs)
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
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 0 {
		t.Fatalf("expected 0 classifications for a configMap-only pod, got %d", len(clsfs))
	}
}

// TestStorageClassifier_BareNFSVolume_EarnsTier0 is the sprint53-kind EC2 regression: a pod-spec
// volume that is a BARE `nfs:` source with no PersistentVolumeClaim wrapper — the shape used on a
// cluster with no StorageClass/CSI — must be
// classified TierRWX by real inspection of vol.NFS, not merely read as Tier0 by accident through
// HighestTier's empty-classification-list default. Before this fix, ClassifyPod fell through the
// "remaining non-PVC volumes are transparent" branch for an NFS volume exactly like it does for a
// configMap, returning ZERO classifications; HighestTier then defaulted the empty list to TierRWX,
// which coincidentally matched but did not derive from actually inspecting the volume — the same
// vacuous default a genuinely unmigratable non-PVC volume type would also hit. This test asserts
// ClassifyPod itself returns a real, non-empty TierRWX entry for the NFS volume.
func TestStorageClassifier_BareNFSVolume_EarnsTier0(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "postgres-src", Namespace: "default"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "pgdata",
					VolumeSource: corev1.VolumeSource{
						NFS: &corev1.NFSVolumeSource{Server: "10.60.1.225", Path: "/export/pgdata"},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(newScheme()).Build()
	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 real classification for the bare NFS volume, got %d: %+v", len(clsfs), clsfs)
	}
	if clsfs[0].Tier != storage.TierRWX {
		t.Errorf("expected TierRWX (0) for a bare NFS volume, got %d", clsfs[0].Tier)
	}
	if got := storage.HighestTier(clsfs); got.Tier != storage.TierRWX {
		t.Errorf("HighestTier: expected TierRWX (0), got %d (reason: %s)", got.Tier, got.Reason)
	}
}

// TestStorageClassifier_PostgresPGDataOnRWX_ReachesTier0 is the PINNED regression
// guard for the postgres checkpoint-stage failure (2026-07-10 live gate).
//
// Ground truth from the live KVM run: postgres never reached Checkpointing. With
// PGDATA on a disk-backed emptyDir the classifier (correctly) returns TierBlocked,
// so StorageReadyForFreeze stays False (reason=BlockedVolume) and the migration
// hangs in PreCopyMemory — silent-data-loss protection, but the pod can never
// migrate. The fix backs PGDATA with an RWX PV (nfs-shared) so both source and
// destination nodes see the SAME live data directory: it maps to Tier0 (re-attach,
// zero data movement) and the freeze is allowed to proceed past Checkpointing.
//
// This test pins the exact postgres pod shape — an RWX PVC-backed PGDATA mount
// alongside a transparent configMap init volume — and asserts the highest tier is
// Tier0, NOT TierBlocked. If a future change reverts PGDATA to a raw emptyDir, or
// mis-classifies an RWX PVC, the migration would silently regress back to the
// PreCopyMemory hang; this test fails loudly instead.
func TestStorageClassifier_PostgresPGDataOnRWX_ReachesTier0(t *testing.T) {
	// RWX PVC on the shared-NFS StorageClass, exactly as the postgres-src fixture
	// declares it after the fix.
	pvc := makePVC("postgres-pgdata", "pm-db-test", "nfs-shared",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "postgres-src", Namespace: "pm-db-test"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					// PGDATA — the writable DB state, now on an RWX PV.
					Name: "data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: "postgres-pgdata",
						},
					},
				},
				{
					// init.sql — transparent, reconstructed from the pod spec.
					Name: "init",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "postgres-init"},
						},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(pvc).
		Build()

	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the PVC volume is classified; the configMap is transparent (skipped).
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification (PGDATA PVC; configMap transparent), got %d", len(clsfs))
	}
	highest := storage.HighestTier(clsfs)
	if highest.Tier != storage.TierRWX {
		t.Fatalf("postgres PGDATA on an RWX PV must map to Tier0 re-attach (not Blocked) so the "+
			"migration reaches past Checkpointing; got tier=%d reason=%q", highest.Tier, highest.Reason)
	}
	if highest.Tier == storage.TierBlocked {
		t.Fatalf("regression: postgres migration blocked at the storage freeze gate (would hang in PreCopyMemory)")
	}
}

// TestStorageClassifier_Tier1_LonghornRWX is the regression guard for the
// live-gate stall (2026-07-17): a Longhorn-backed StorageClass ("longhorn-migratable",
// provisioner driver.longhorn.io) genuinely supports live migration via its own
// dual-engine mechanism even when the PVC's accessMode is ReadWriteMany. Before this
// fix, the classifier checked accessModes for RWX FIRST and short-circuited to
// TierRWX (generic Tier0 re-attach) before ever inspecting the StorageClass, so this
// PVC was misrouted into the Longhorn-incompatible generic path and hit a Longhorn
// CSI "invalid controller count 2" error during a live test. A Longhorn-backed
// StorageClass must route to TierLonghorn regardless of accessMode.
//
// Uses an owned pod (ADR-0391): TierLonghorn additionally requires an owning
// controller (see TestStorageClassifier_Tier1Longhorn_NoOwningController_IsBlocked for
// the bare-pod case), so this fixture needs one to keep testing what it says it tests —
// RWX-vs-accessMode routing — rather than incidentally tripping the ADR-0391 gate.
func TestStorageClassifier_Tier1_LonghornRWX(t *testing.T) {
	pvc := makePVC("lh-rwx-pvc", "default", "longhorn-migratable",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany})
	sc := makeSC("longhorn-migratable", "driver.longhorn.io", nil)
	pod := makeOwnedPodWithPVC("default", "lh-rwx-pvc")

	fakeClient := fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(pvc, sc).
		Build()

	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierLonghorn {
		t.Errorf("expected TierLonghorn (1) for a Longhorn-backed RWX PVC, got %d (reason=%q)",
			clsfs[0].Tier, clsfs[0].Reason)
	}
}

// TestStorageClassifier_Tier1_LonghornRWX_AnnotationOnly covers a Longhorn
// StorageClass identified only via a longhorn.io/* annotation (not the provisioner
// string) still routes RWX to TierLonghorn ahead of the generic RWX check.
//
// Uses an owned pod for the same ADR-0391 reason as TestStorageClassifier_Tier1_LonghornRWX.
func TestStorageClassifier_Tier1_LonghornRWX_AnnotationOnly(t *testing.T) {
	pvc := makePVC("lh-rwx-annot-pvc", "default", "lh-annot-sc",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany})
	sc := makeSC("lh-annot-sc", "some.other.provisioner", map[string]string{
		"longhorn.io/last-applied-configmap": "unused",
	})
	pod := makeOwnedPodWithPVC("default", "lh-rwx-annot-pvc")

	fakeClient := fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(pvc, sc).
		Build()

	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierLonghorn {
		t.Errorf("expected TierLonghorn (1) for a Longhorn-annotated RWX StorageClass, got %d", clsfs[0].Tier)
	}
}

// TestStorageClassifier_Tier1Longhorn_NoOwningController_IsBlocked is the regression test
// for ADR-0391: a genuinely ReadWriteMany/migratable Longhorn PVC — the case ADR-0387 left
// routing to TierLonghorn — must be classified TierBlocked instead when the pod has no
// owning controller (ReplicaSet/Deployment), because ADR-0356's early-source-release
// recovery story (ADR-0387: "an owning controller recreates the pod") is structurally unmet
// for a bare pod. Before this fix, this exact fixture (RWX Longhorn + bare pod) was
// classified TierLonghorn and reached earlyReleaseSourceForTier1Longhorn, deleting the
// source pod with no path back if restore then failed — the live mechanism behind migration
// attempt podmotion-demo-4prxx (migration-demo-postgres).
func TestStorageClassifier_Tier1Longhorn_NoOwningController_IsBlocked(t *testing.T) {
	pvc := makePVC("lh-rwx-bare-pvc", "default", "longhorn-migratable",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany})
	sc := makeSC("longhorn-migratable", "driver.longhorn.io", nil)
	pod := makePodWithPVC("default", "lh-rwx-bare-pvc") // bare pod — no OwnerReferences

	fakeClient := fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(pvc, sc).
		Build()

	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierBlocked {
		t.Errorf("expected TierBlocked (4) for RWX Longhorn on a pod with no owning controller, got %d (reason=%q)",
			clsfs[0].Tier, clsfs[0].Reason)
	}
}

// ADR-0396 D3: the SAME bare-pod + RWX-Longhorn fixture as
// TestStorageClassifier_Tier1Longhorn_NoOwningController_IsBlocked, but classified with
// coldRecreateArmed=true, keeps TierLonghorn — the downgrade is skipped because the operator has
// (by construction of the armed boolean) captured and re-verified ADR-0393's operator-keyed-HMAC
// cold-recreate snapshot for this migration, so a failed restore has a real recovery path. This is
// the single behavioral flip ADR-0396 introduces; the unarmed regression is asserted directly above.
func TestStorageClassifier_Tier1Longhorn_BarePod_ArmedKeepsLonghorn(t *testing.T) {
	pvc := makePVC("lh-rwx-bare-pvc", "default", "longhorn-migratable",
		[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany})
	sc := makeSC("longhorn-migratable", "driver.longhorn.io", nil)
	pod := makePodWithPVC("default", "lh-rwx-bare-pvc") // bare pod — no OwnerReferences

	fakeClient := fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(pvc, sc).
		Build()

	classifier := storage.NewStorageClassifier(fakeClient)
	clsfs, err := classifier.ClassifyPod(context.Background(), pod, true) // ADR-0396: armed
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clsfs) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(clsfs))
	}
	if clsfs[0].Tier != storage.TierLonghorn {
		t.Errorf("ADR-0396: expected TierLonghorn (1) for an ARMED bare-pod RWX Longhorn PVC, got %d (reason=%q)",
			clsfs[0].Tier, clsfs[0].Reason)
	}
}

// ADR-0396: an OWNED pod is unaffected by coldRecreateArmed in BOTH directions — ownership
// short-circuits the gate, exactly as ADR-0391. An owned RWX Longhorn pod stays TierLonghorn whether
// armed or not; arming is a no-op for it (owned pods recover via their controller and are never
// eligible for arming in the first place).
func TestStorageClassifier_Tier1Longhorn_OwnedPod_UnaffectedByArming(t *testing.T) {
	for _, armed := range []bool{false, true} {
		pvc := makePVC("lh-rwx-owned-pvc", "default", "longhorn-migratable",
			[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany})
		sc := makeSC("longhorn-migratable", "driver.longhorn.io", nil)
		pod := makeOwnedPodWithPVC("default", "lh-rwx-owned-pvc")

		fakeClient := fake.NewClientBuilder().
			WithScheme(newScheme()).
			WithObjects(pvc, sc).
			Build()

		classifier := storage.NewStorageClassifier(fakeClient)
		clsfs, err := classifier.ClassifyPod(context.Background(), pod, armed)
		if err != nil {
			t.Fatalf("armed=%v: unexpected error: %v", armed, err)
		}
		if len(clsfs) != 1 {
			t.Fatalf("armed=%v: expected 1 classification, got %d", armed, len(clsfs))
		}
		if clsfs[0].Tier != storage.TierLonghorn {
			t.Errorf("armed=%v: expected TierLonghorn (1) for an OWNED RWX Longhorn pod (unaffected by arming), got %d (reason=%q)",
				armed, clsfs[0].Tier, clsfs[0].Reason)
		}
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
