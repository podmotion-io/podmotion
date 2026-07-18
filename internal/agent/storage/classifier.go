/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package storage implements M6 storage tier classification and migration
// strategies for PodMotion live pod migration.
//
// Tier hierarchy (ADR-0007):
//
//	Tier0: ReadWriteMany (NFS, CephFS) — re-attach only, zero data movement
//	Tier1: Longhorn dual-engine live migration
//	Tier2: Ceph RBD (rbd.csi.ceph.com) — live migration via CSI
//	Tier3: RWO generic — snapshot + rsync
//	Tier4: hostPath / memory emptyDir — blocked by webhook before we get here
package storage

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// StorageTier identifies which migration strategy to use for a PVC.
type StorageTier int32

const (
	// TierRWX is a ReadWriteMany volume — re-attach only, StorageReadyForFreeze is immediate.
	TierRWX StorageTier = 0
	// TierLonghorn uses Longhorn dual-engine live migration.
	TierLonghorn StorageTier = 1
	// TierCephRBD uses Ceph RBD live migration via CSI.
	TierCephRBD StorageTier = 2
	// TierSnapshotRsync snapshots the PVC and rsyncs to destination.
	TierSnapshotRsync StorageTier = 3
	// TierBlocked is a volume type (hostPath, memory emptyDir) that cannot be migrated.
	// The webhook rejects pods with Tier4 volumes before migration begins.
	TierBlocked StorageTier = 4
)

// TierClassification holds the result of classifying a single PVC.
type TierClassification struct {
	Tier         StorageTier
	Reason       string
	PVCName      string
	StorageClass string
}

// StorageClassifier inspects a pod's PVCs and determines the appropriate
// migration tier for each volume.
type StorageClassifier struct {
	client client.Client
}

// podmotionHolderVolumeName is the emptyDir PodMotion's own mutating webhook
// injects into every replacement pod to stage the holder binary (see
// holderVolumeName in internal/controller/podmigration_controller.go — kept
// as a separate literal here rather than a shared import to avoid a
// storage->controller package dependency; the two names must stay in sync).
// It is disk-backed, so without this exclusion it was indistinguishable from
// real user pod-local state and got classified TierBlocked — meaning ANY
// pod that had already been migrated once could never be migrated again, on
// any storage tier or CNI, since the webhook re-injects this same volume
// into every replacement pod. Confirmed live 2026-07-18: a bare nginx pod's
// second migration (after a first, successful one) permanently stalled at
// PreCopyMemory with StorageReadyForFreeze=False/BlockedVolume. This volume
// holds no pod data — it's recreated fresh by the webhook on every
// migration — so it is always transparent to migration, never blocked.
const podmotionHolderVolumeName = "podmotion-holder-bin"

// NewStorageClassifier returns a classifier backed by the given k8s client.
func NewStorageClassifier(c client.Client) *StorageClassifier {
	return &StorageClassifier{client: c}
}

// ClassifyPod returns a TierClassification for each PVC mounted by the pod.
// If the pod has no PVCs it returns an empty slice — Tier0 re-attach logic applies.
// The highest-cost tier across all PVCs determines the overall migration strategy.
func (sc *StorageClassifier) ClassifyPod(ctx context.Context, pod *corev1.Pod) ([]TierClassification, error) {
	var results []TierClassification

	for _, vol := range pod.Spec.Volumes {
		// hostPath and memory emptyDir are caught by the webhook, but guard defensively.
		if vol.HostPath != nil {
			results = append(results, TierClassification{
				Tier:    TierBlocked,
				Reason:  "hostPath volumes cannot be migrated",
				PVCName: vol.Name,
			})
			continue
		}
		if vol.EmptyDir != nil && vol.EmptyDir.Medium == corev1.StorageMediumMemory {
			results = append(results, TierClassification{
				Tier:    TierBlocked,
				Reason:  "memory-backed emptyDir cannot be migrated",
				PVCName: vol.Name,
			})
			continue
		}
		// PodMotion's own injected holder-binary volume: never real pod data,
		// always recreated fresh by the mutating webhook on every migration —
		// transparent to migration, same as configMap/secret/projected below.
		if vol.EmptyDir != nil && vol.Name == podmotionHolderVolumeName {
			continue
		}
		// Disk-backed emptyDir holds real pod-local writable state on the source
		// kubelet directory, on no PV. No tier migrator moves it today (the full
		// data-staging migrator is deferred), so it MUST be classified TierBlocked
		// rather than silently dropped — otherwise the pod freezes and restores
		// with an empty volume (silent data loss, C-4/A-04). Classifying it Blocked
		// makes admission hard-refuse with a recoverable, human-actionable reason.
		if vol.EmptyDir != nil {
			results = append(results, TierClassification{
				Tier: TierBlocked,
				Reason: "disk-backed emptyDir holds pod-local state that no migrator " +
					"currently moves; migration would silently lose it — remove the " +
					"emptyDir or use a supported PVC-backed volume",
				PVCName: vol.Name,
			})
			continue
		}

		if vol.PersistentVolumeClaim == nil {
			// Remaining non-PVC volumes (configMap, secret, downwardAPI, projected)
			// are reconstructed on the destination from the pod spec — no data
			// movement is required, so they are transparent to migration.
			continue
		}

		clsf, err := sc.classifyPVC(ctx, pod.Namespace, vol.PersistentVolumeClaim.ClaimName)
		if err != nil {
			return nil, fmt.Errorf("classify pvc %s: %w", vol.PersistentVolumeClaim.ClaimName, err)
		}
		results = append(results, clsf)
	}

	return results, nil
}

// HighestTier returns the most expensive tier from a slice of classifications.
// Tier4 (blocked) always wins; Tier0 only wins if nothing else is present.
func HighestTier(classifications []TierClassification) TierClassification {
	if len(classifications) == 0 {
		return TierClassification{
			Tier:   TierRWX,
			Reason: "no PVCs — treat as RWX re-attach",
		}
	}
	highest := classifications[0]
	for _, c := range classifications[1:] {
		if c.Tier > highest.Tier {
			highest = c
		}
	}
	return highest
}

func (sc *StorageClassifier) classifyPVC(ctx context.Context, namespace, name string) (TierClassification, error) {
	pvc := &corev1.PersistentVolumeClaim{}
	if err := sc.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pvc); err != nil {
		return TierClassification{}, fmt.Errorf("get pvc: %w", err)
	}

	// Note whether the PVC requests ReadWriteMany, but do NOT short-circuit on
	// it yet: a Longhorn-backed StorageClass must be checked FIRST, because
	// Longhorn's own dual-engine live migration is required even for an RWX
	// Longhorn volume — routing it into the generic Tier0 re-attach path
	// instead causes a Longhorn CSI failure ("invalid controller count 2").
	isRWX := false
	for _, am := range pvc.Spec.AccessModes {
		if am == corev1.ReadWriteMany {
			isRWX = true
			break
		}
	}

	// Resolve StorageClass to inspect provisioner annotations.
	scName := ""
	if pvc.Spec.StorageClassName != nil {
		scName = *pvc.Spec.StorageClassName
	}

	if scName != "" {
		sc2 := &storagev1.StorageClass{}
		if err := sc.client.Get(ctx, client.ObjectKey{Name: scName}, sc2); err == nil {
			// Longhorn-backed StorageClass takes priority over the generic RWX
			// check regardless of accessMode — Longhorn supports live migration
			// via its own dual-engine mechanism, so a Longhorn RWX PVC must
			// still go to TierLonghorn, not the generic RWX/Tier0 path.
			if isLonghornStorageClass(sc2) {
				return TierClassification{
					Tier:         TierLonghorn,
					Reason:       reasonForTier(TierLonghorn, sc2.Provisioner),
					PVCName:      name,
					StorageClass: scName,
				}, nil
			}

			if isRWX {
				return TierClassification{
					Tier:         TierRWX,
					Reason:       "ReadWriteMany access mode — re-attach only",
					PVCName:      name,
					StorageClass: scName,
				}, nil
			}

			tier := classifyByStorageClass(sc2)
			return TierClassification{
				Tier:         tier,
				Reason:       reasonForTier(tier, sc2.Provisioner),
				PVCName:      name,
				StorageClass: scName,
			}, nil
		}
		// If StorageClass not found, fall through to the RWX check and then
		// Tier3 (generic RWO snapshot+rsync) below.
	}

	// Non-Longhorn (or unresolved-StorageClass) RWX volume — e.g. NFS/CephFS
	// shared storage — maps to Tier0 generic re-attach.
	if isRWX {
		return TierClassification{
			Tier:         TierRWX,
			Reason:       "ReadWriteMany access mode — re-attach only",
			PVCName:      name,
			StorageClass: scName,
		}, nil
	}

	return TierClassification{
		Tier:         TierSnapshotRsync,
		Reason:       "no StorageClass resolved — falling back to snapshot+rsync",
		PVCName:      name,
		StorageClass: scName,
	}, nil
}

// classifyByStorageClass maps a StorageClass provisioner to a StorageTier.
// Longhorn takes priority over Ceph because Longhorn's dual-engine migration
// is less disruptive than RBD mirroring for single-replica volumes.
func classifyByStorageClass(sc *storagev1.StorageClass) StorageTier {
	p := sc.Provisioner

	if isLonghornStorageClass(sc) {
		return TierLonghorn
	}

	// Ceph RBD via CSI
	if strings.Contains(p, "rbd.csi.ceph.com") {
		return TierCephRBD
	}

	// CephFS via CSI — still RWX capable but single-access RWO mode treated as Tier3
	// unless the PVC actually has RWX (handled above).
	if strings.Contains(p, "cephfs.csi.ceph.com") {
		return TierSnapshotRsync
	}

	return TierSnapshotRsync
}

// isLonghornStorageClass reports whether the given StorageClass is backed by
// Longhorn: driver.longhorn.io (or any longhorn.io/* provisioner) or any
// longhorn.io/* annotation. This is read from the StorageClass object's own
// Provisioner/Annotations fields rather than any hardcoded class name — a
// class named e.g. "longhorn-migratable" is this repo's own naming choice,
// not a universal identifier.
// IsLonghornStorageClass is the exported form of isLonghornStorageClass, for callers outside this
// package (e.g. internal/agent/server's re-attach mount tier classification) that need the same
// Longhorn-detection rule this classifier uses — so a Longhorn-backed PVC is never independently
// re-derived (and potentially drifted) by a second, narrower check elsewhere in the codebase.
func IsLonghornStorageClass(sc *storagev1.StorageClass) bool {
	return isLonghornStorageClass(sc)
}

func isLonghornStorageClass(sc *storagev1.StorageClass) bool {
	if strings.Contains(sc.Provisioner, "longhorn.io") {
		return true
	}
	for k := range sc.Annotations {
		if strings.HasPrefix(k, "longhorn.io/") {
			return true
		}
	}
	return false
}

func reasonForTier(tier StorageTier, provisioner string) string {
	switch tier {
	case TierLonghorn:
		return fmt.Sprintf("Longhorn provisioner (%s) — dual-engine live migration", provisioner)
	case TierCephRBD:
		return fmt.Sprintf("Ceph RBD provisioner (%s) — live migration via CSI", provisioner)
	default:
		return fmt.Sprintf("provisioner %s — snapshot+rsync fallback", provisioner)
	}
}
