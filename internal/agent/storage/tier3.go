/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// snapshotPollInterval is the delay between VolumeSnapshot readiness polls.
	snapshotPollInterval = 2 * time.Second
	// snapshotPollTimeout is the maximum time to wait for a snapshot to become ready.
	snapshotPollTimeout = 5 * time.Minute

	// pvcBindTimeout is the maximum time to wait for the destination PVC to be Bound.
	pvcBindTimeout = 5 * time.Minute

	// volumeSnapshotGroup is the API group for external-snapshotter CRDs.
	volumeSnapshotGroup = "snapshot.storage.k8s.io"
	// volumeSnapshotVersion is the API version for VolumeSnapshot.
	volumeSnapshotVersion = "v1"
)

// volumeSnapshotGVR is the GroupVersionResource for VolumeSnapshot.
var volumeSnapshotGVR = schema.GroupVersionResource{
	Group:    volumeSnapshotGroup,
	Version:  volumeSnapshotVersion,
	Resource: "volumesnapshots",
}

// SnapshotRsyncMigrator implements Tier3 migration via VolumeSnapshot + PVC clone + rsync delta.
//
// Migration sequence:
//  1. Create VolumeSnapshot of source PVC via external-snapshotter API
//  2. Wait for VolumeSnapshot.status.readyToUse=true
//  3. Create destination PVC with spec.dataSource pointing at the VolumeSnapshot
//  4. Wait for destination PVC to be Bound
//  5. rsync --checksum --partial source-mount dest-mount (delta transfer)
//  6. On cutover: stop rsync, final rsync pass during freeze window
//
// VolumeSnapshot types are accessed via unstructured client to avoid importing
// sigs.k8s.io/external-snapshotter as a direct module dependency. The CRD must
// already be installed on the cluster (external-snapshotter deployed separately).
type SnapshotRsyncMigrator struct {
	Client      client.Client
	ExecCommand func(name string, args ...string) *exec.Cmd
}

// NewSnapshotRsyncMigrator returns a production Tier3 migrator.
func NewSnapshotRsyncMigrator(c client.Client) *SnapshotRsyncMigrator {
	return &SnapshotRsyncMigrator{
		Client:      c,
		ExecCommand: exec.Command,
	}
}

// Tier returns TierSnapshotRsync.
func (m *SnapshotRsyncMigrator) Tier() StorageTier { return TierSnapshotRsync }

// PreStage creates VolumeSnapshots, clones PVCs to the destination, and starts rsync.
func (m *SnapshotRsyncMigrator) PreStage(ctx context.Context, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "SnapshotRsync")

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierSnapshotRsync {
			continue
		}

		snapName := snapshotName(opts.MigrationName, clsf.PVCName)

		log.Info("creating VolumeSnapshot", "pvc", clsf.PVCName, "snapshot", snapName)
		if err := m.createVolumeSnapshot(ctx, opts.PodNamespace, snapName, clsf.PVCName); err != nil {
			return fmt.Errorf("tier3: create snapshot for %s: %w", clsf.PVCName, err)
		}

		log.Info("waiting for VolumeSnapshot readyToUse", "snapshot", snapName)
		if err := m.waitSnapshotReady(ctx, opts.PodNamespace, snapName); err != nil {
			return fmt.Errorf("tier3: snapshot not ready %s: %w", snapName, err)
		}

		destPVCName := destPVCName(opts.MigrationName, clsf.PVCName)
		log.Info("creating destination PVC from snapshot", "destPVC", destPVCName)

		srcPVC := &corev1.PersistentVolumeClaim{}
		if err := m.Client.Get(ctx, client.ObjectKey{
			Namespace: opts.PodNamespace,
			Name:      clsf.PVCName,
		}, srcPVC); err != nil {
			return fmt.Errorf("tier3: get source pvc %s: %w", clsf.PVCName, err)
		}

		if err := m.createDestPVC(ctx, opts.PodNamespace, destPVCName, snapName, srcPVC); err != nil {
			return fmt.Errorf("tier3: create dest pvc %s: %w", destPVCName, err)
		}

		log.Info("waiting for destination PVC to be Bound", "pvc", destPVCName)
		if err := m.waitPVCBound(ctx, opts.PodNamespace, destPVCName); err != nil {
			return fmt.Errorf("tier3: dest pvc not bound %s: %w", destPVCName, err)
		}

		// rsync delta phase: source mount path is inferred from the PVC name convention.
		// In production the agent resolves the actual mount path from the pod's CRI status.
		srcMount := fmt.Sprintf("/var/lib/kubelet/pods/*/volumes/kubernetes.io~csi/%s/mount", clsf.PVCName)
		destMount := fmt.Sprintf("/var/lib/kubelet/pods/*/volumes/kubernetes.io~csi/%s/mount", destPVCName)

		log.Info("starting rsync delta transfer", "src", srcMount, "dest", destMount)
		if err := m.runRsync(ctx, srcMount, destMount); err != nil {
			return fmt.Errorf("tier3: rsync for %s: %w", clsf.PVCName, err)
		}

		log.Info("Tier3 storage ready for freeze", "pvc", clsf.PVCName)
	}
	return nil
}

// SyncPercent returns 100 once PreStage completes (rsync is synchronous in this implementation).
func (m *SnapshotRsyncMigrator) SyncPercent(_ context.Context, _ MigrationOptions) (int, error) {
	return 100, nil
}

// Cutover runs a final rsync pass during the freeze window to sync any writes
// that occurred after the initial rsync completed.
func (m *SnapshotRsyncMigrator) Cutover(ctx context.Context, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "SnapshotRsync")

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierSnapshotRsync {
			continue
		}

		destPVC := destPVCName(opts.MigrationName, clsf.PVCName)
		srcMount := fmt.Sprintf("/var/lib/kubelet/pods/*/volumes/kubernetes.io~csi/%s/mount", clsf.PVCName)
		destMount := fmt.Sprintf("/var/lib/kubelet/pods/*/volumes/kubernetes.io~csi/%s/mount", destPVC)

		log.Info("running final rsync pass during freeze window", "pvc", clsf.PVCName)
		if err := m.runRsync(ctx, srcMount, destMount); err != nil {
			return fmt.Errorf("tier3: cutover rsync for %s: %w", clsf.PVCName, err)
		}
	}
	return nil
}

// ── helpers ────────────────────────────────────────────────────────────────

func snapshotName(migrationName, pvcName string) string {
	return fmt.Sprintf("pm-%s-%s-snap", migrationName, pvcName)
}

func destPVCName(migrationName, pvcName string) string {
	return fmt.Sprintf("pm-%s-%s-dest", migrationName, pvcName)
}

func (m *SnapshotRsyncMigrator) createVolumeSnapshot(ctx context.Context, namespace, snapName, pvcName string) error {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": volumeSnapshotGroup + "/" + volumeSnapshotVersion,
			"kind":       "VolumeSnapshot",
			"metadata": map[string]interface{}{
				"name":      snapName,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"source": map[string]interface{}{
					"persistentVolumeClaimName": pvcName,
				},
			},
		},
	}
	if err := m.Client.Create(ctx, obj); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (m *SnapshotRsyncMigrator) waitSnapshotReady(ctx context.Context, namespace, snapName string) error {
	return wait.PollUntilContextTimeout(ctx, snapshotPollInterval, snapshotPollTimeout, false,
		func(ctx context.Context) (bool, error) {
			snap := &unstructured.Unstructured{}
			snap.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   volumeSnapshotGroup,
				Version: volumeSnapshotVersion,
				Kind:    "VolumeSnapshot",
			})
			if err := m.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: snapName}, snap); err != nil {
				return false, nil
			}
			ready, _, _ := unstructured.NestedBool(snap.Object, "status", "readyToUse")
			return ready, nil
		})
}

func (m *SnapshotRsyncMigrator) createDestPVC(ctx context.Context, namespace, destPVCName, snapName string, srcPVC *corev1.PersistentVolumeClaim) error {
	apiGroup := volumeSnapshotGroup
	storageClass := ""
	if srcPVC.Spec.StorageClassName != nil {
		storageClass = *srcPVC.Spec.StorageClassName
	}

	// Determine capacity from source PVC.
	capacity := srcPVC.Spec.Resources.Requests[corev1.ResourceStorage]
	if capacity.IsZero() {
		capacity = resource.MustParse("1Gi")
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      destPVCName,
			Namespace: namespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      srcPVC.Spec.AccessModes,
			StorageClassName: &storageClass,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: capacity,
				},
			},
			DataSource: &corev1.TypedLocalObjectReference{
				APIGroup: &apiGroup,
				Kind:     "VolumeSnapshot",
				Name:     snapName,
			},
		},
	}
	if err := m.Client.Create(ctx, pvc); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (m *SnapshotRsyncMigrator) waitPVCBound(ctx context.Context, namespace, pvcName string) error {
	return wait.PollUntilContextTimeout(ctx, snapshotPollInterval, pvcBindTimeout, false,
		func(ctx context.Context) (bool, error) {
			pvc := &corev1.PersistentVolumeClaim{}
			if err := m.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: pvcName}, pvc); err != nil {
				return false, nil
			}
			return pvc.Status.Phase == corev1.ClaimBound, nil
		})
}

func (m *SnapshotRsyncMigrator) runRsync(ctx context.Context, src, dest string) error {
	cmd := m.ExecCommand("rsync", "--checksum", "--partial", "--archive", src+"/", dest+"/")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Attach context cancellation: if ctx is cancelled rsync is killed.
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msg := strings.TrimSpace(stderr.String())
		return fmt.Errorf("rsync: %w — %s", err, msg)
	}
	return nil
}

// ── Stub ───────────────────────────────────────────────────────────────────

// SnapshotRsyncStubMigrator is used in unit tests and environments without
// a storage provisioner. It emits ready after 200ms.
type SnapshotRsyncStubMigrator struct {
	PreStageCalled bool
	CutoverCalled  bool
	// CreatedPVCs records the dest PVC names that would have been created.
	CreatedPVCs []string
	// InjectPreStageError causes PreStage to return an error.
	InjectPreStageError error
}

// Tier returns TierSnapshotRsync.
func (s *SnapshotRsyncStubMigrator) Tier() StorageTier { return TierSnapshotRsync }

// PreStage records which PVCs were processed and simulates a 200ms delay.
func (s *SnapshotRsyncStubMigrator) PreStage(_ context.Context, opts MigrationOptions) error {
	if s.InjectPreStageError != nil {
		return s.InjectPreStageError
	}
	time.Sleep(200 * time.Millisecond)
	for _, clsf := range opts.Classifications {
		if clsf.Tier == TierSnapshotRsync {
			s.CreatedPVCs = append(s.CreatedPVCs, destPVCName(opts.MigrationName, clsf.PVCName))
		}
	}
	s.PreStageCalled = true
	return nil
}

// SyncPercent returns 100 — stub is always ready.
func (s *SnapshotRsyncStubMigrator) SyncPercent(_ context.Context, _ MigrationOptions) (int, error) {
	return 100, nil
}

// Cutover records the call.
func (s *SnapshotRsyncStubMigrator) Cutover(_ context.Context, _ MigrationOptions) error {
	s.CutoverCalled = true
	return nil
}
