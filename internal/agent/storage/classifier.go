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
//	Tier1: Longhorn dual-engine live migration — ReadWriteMany/migratable Longhorn
//	       PVCs ONLY (ADR-0387); a Longhorn PVC that is ReadWriteOnce (the cluster's
//	       default single-attach StorageClass) cannot use Longhorn's dual-engine
//	       mechanism and is classified TierBlocked instead, never TierLonghorn.
//	       Even when RWX, TierLonghorn additionally requires the pod to have an
//	       owning controller (ReplicaSet/Deployment) — ADR-0356's early-source-release
//	       recovery story is structurally unmet for a standalone pod, so a bare pod's
//	       RWX Longhorn PVC is also classified TierBlocked instead (ADR-0391).
//	Tier2: Ceph RBD (rbd.csi.ceph.com) — live migration via CSI
//	Tier3: RWO generic — snapshot + rsync
//	Tier4: hostPath / memory emptyDir / disk-backed emptyDir — blocked by webhook
//	       before we get here (ADR-0383; see detectTier4Volume in
//	       internal/webhook/podmigration_webhook.go) — also emitted directly by
//	       classifyPVC for a ReadWriteOnce Longhorn PVC (ADR-0387), and by ClassifyPod
//	       for an owning-controller-less pod's otherwise-valid RWX Longhorn PVC (ADR-0391).
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
//
// coldRecreateArmed (ADR-0396) narrows ADR-0391's unconditional bare-pod
// TierLonghorn→TierBlocked downgrade. It is an in-process boolean the OPERATOR computes,
// immediately before dispatching pre-stage, by actually capturing and read-back-verifying
// ADR-0393's operator-keyed-HMAC cold-recreate snapshot for THIS migration
// (armTier1ColdRecreateIfEligible, internal/controller). It is threaded here as a plain
// function argument — never a status field, so there is nothing on the wire for a lower-trust
// co-writer to forge. When true, the bare-pod downgrade below is skipped (a verified recovery
// parachute exists for this pod); when false — the default and the value on every non-arming
// path (owned pod, bare non-Longhorn pod, failed/failed-verify capture, missing key) — the
// downgrade fires exactly as ADR-0391 does today. The fail-closed default is preserved verbatim.
func (sc *StorageClassifier) ClassifyPod(ctx context.Context, pod *corev1.Pod, coldRecreateArmed bool) ([]TierClassification, error) {
	var results []TierClassification

	for _, vol := range pod.Spec.Volumes {
		// hostPath, memory emptyDir, and disk-backed emptyDir (ADR-0383) are all caught by
		// the webhook's detectTier4Volume before a PodMigration is even admitted — the checks
		// below are a defensive second layer (e.g. a pod whose spec changed after admission),
		// not the primary enforcement point.
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

		// Bare in-tree NFS volume (no PVC wrapper): per ADR-0007, NFS is Tier0
		// ReadWriteMany re-attach storage regardless of whether it arrives via a
		// PVC/PV or a raw pod-spec volume. Classify it explicitly here rather than
		// letting it fall through the no-PVC branch below — falling through means
		// ClassifyPod returns zero entries for this volume and the ONLY reason it
		// ever reads as Tier0 is HighestTier's empty-list default ("no PVCs — treat
		// as RWX re-attach"), which is a coincidence, not a real classification: a
		// pod with a genuinely unmigratable non-PVC volume type would hit that same
		// vacuous default and be silently waved through. Earning the label here
		// also makes it reachable by resolveReattachMountsImpl's mirrored tier
		// logic in internal/agent/server (classifyReattachTier's NFS counterpart),
		// which needs a real Tier0 signal to admit the volume into the re-attach
		// set instead of PVC-only gating it out.
		if vol.NFS != nil {
			results = append(results, TierClassification{
				Tier:    TierRWX,
				Reason:  "ReadWriteMany NFS volume (no PVC) — re-attach only",
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

	// ADR-0391: TierLonghorn is only safe to hand a migration to when ADR-0356's
	// early-source-release path (earlyReleaseSourceForTier1Longhorn,
	// internal/controller/podmigration_controller.go) is itself recoverable. That
	// function's own doc comment states the recovery story plainly: once the source pod
	// is deleted ahead of TrafficVerified, recovery from a failed restore is "recreate
	// from the durably-verified checkpoint" — and per ADR-0387, that recreate is only
	// ever actually performed by an owning controller (ReplicaSet/Deployment) noticing
	// the shortfall. ADR-0387 already closed this gap for the ReadWriteOnce-Longhorn
	// case (classified TierBlocked above, never reaching TierLonghorn at all), but a
	// genuinely ReadWriteMany/migratable Longhorn PVC still routes to TierLonghorn
	// regardless of the pod's ownership — and a pod with NO owning controller (a bare
	// pod, currently the ONLY pod shape this project supports per CLAUDE.md's standing
	// scope note, 2026-07-23) can reach earlyReleaseSourceForTier1Longhorn, have its
	// source deleted, and then have nothing anywhere recreate it if restore fails: a
	// guaranteed, not merely possible, unrecovered outage on that one failure path. This
	// is the live mechanism behind migration attempt podmotion-demo-4prxx
	// (migration-demo-postgres): RolledBack=True/RollbackCompleteNoOwningController with
	// no replacement ever created. Block it here, at classification time — before
	// checkpoint/freeze ever starts — exactly as ADR-0387 already does for the RWO case,
	// rather than let the migration proceed to a point where failure is unrecoverable by
	// design. This does not touch TierLonghorn for a pod that DOES have an owning
	// controller (ReplicaSet/Deployment) — that combination's recovery story remains
	// real and this block is a no-op for it.
	//
	// ADR-0396: the downgrade is now CONDITIONAL. It is skipped when coldRecreateArmed==true —
	// i.e. when the operator has itself captured and read-back-verified ADR-0393's operator-keyed
	// -HMAC cold-recreate snapshot for this specific migration, so a failed restore has a real,
	// verified recovery path (a cold-recreated pod from the durable snapshot) rather than an
	// unrecoverable outage. When coldRecreateArmed==false (the default and every non-arming path)
	// the block fires exactly as ADR-0391 authored it. true can ONLY have been produced by an
	// operator-side keyed-HMAC verification the agent cannot forge (no signing key), so relaxing on
	// it authorizes the early-release datapath on a re-verified fact, never on field presence.
	if !podHasControllerOwner(pod) && !coldRecreateArmed {
		for i := range results {
			if results[i].Tier != TierLonghorn {
				continue
			}
			results[i] = TierClassification{
				Tier: TierBlocked,
				Reason: fmt.Sprintf("Longhorn-backed StorageClass %q is ReadWriteMany/migratable, "+
					"but this pod has no owning controller (ReplicaSet/Deployment) — "+
					"ADR-0356's early-source-release path for Tier1-Longhorn deletes the source "+
					"pod ahead of TrafficVerified, and per ADR-0387 the only recovery from a "+
					"subsequently failed restore is an owning controller recreating the pod; a "+
					"standalone pod has no such recovery path, making any restore failure an "+
					"unrecoverable outage by design rather than a narrowed-but-real guarantee "+
					"(ADR-0391)", results[i].StorageClass),
				PVCName:      results[i].PVCName,
				StorageClass: results[i].StorageClass,
			}
		}
	}

	return results, nil
}

// podHasControllerOwner reports whether pod has any OwnerReference with Controller=true
// (a ReplicaSet, Deployment-via-ReplicaSet, StatefulSet, DaemonSet, Job, etc. actually
// managing this pod's lifecycle) — mirroring the exact same check
// earlyReleaseSourceForTier1Longhorn uses to capture
// pm.Status.Tier1EarlyReleaseSourceOwnerKind (internal/controller/podmigration_controller.go),
// so classification time and early-release time agree on what "has an owning controller"
// means.
func podHasControllerOwner(pod *corev1.Pod) bool {
	for i := range pod.OwnerReferences {
		ref := pod.OwnerReferences[i]
		if ref.Controller != nil && *ref.Controller {
			return true
		}
	}
	return false
}

// PodHasControllerOwner is the exported form of podHasControllerOwner, for callers outside this
// package (ADR-0396's operator-side arming eligibility, internal/controller) that must decide
// "is this pod bare?" using the EXACT same predicate the classifier's gate uses — so arming-time
// and classification-time can never disagree on which pods are "bare" (ADR-0396 D5, no-drift). It
// mirrors the IsLonghornStorageClass/isLonghornStorageClass exported-wrapper idiom already in this
// file, rather than re-deriving the ownership rule in a second place.
func PodHasControllerOwner(pod *corev1.Pod) bool {
	return podHasControllerOwner(pod)
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
			//
			// ADR-0387: TierLonghorn is ONLY valid for a PVC that actually declares
			// ReadWriteMany. Longhorn's real dual-engine live-migration mode requires
			// RWX — it does not exist for a ReadWriteOnce (single-attach) volume, no
			// matter which StorageClass name is used. Before this fix, ANY
			// Longhorn-provisioned PVC was classified TierLonghorn regardless of
			// access mode, so an RWO PVC on the cluster's default single-attach
			// `longhorn` StorageClass was silently promised the same live-migration
			// path as a genuinely-migratable RWX volume. That promise cannot be kept:
			// Longhorn's own CSI attacher only frees the source node's
			// VolumeAttachment once no pod on that node references the PVC, so the
			// only way to unblock the destination mount was ADR-0356's early source
			// release (deleting/killing the source pod BEFORE TrafficVerified,
			// ahead of the normal ADR-0012 ordering) — a narrow, risky exception
			// whose own stated recovery guarantee ("recreate from the durably
			// verified checkpoint via the source pod's owning controller") is
			// structurally unmet for a standalone pod with no owning controller,
			// which is the ONLY pod shape this project currently supports (see
			// CLAUDE.md standing scope note, 2026-07-23). Requiring RWX here means an
			// RWO Longhorn PVC is refused up front (TierBlocked, below) instead of
			// being routed through a live-migration path it cannot safely deliver.
			if isLonghornStorageClass(sc2) {
				if !isRWX {
					return TierClassification{
						Tier: TierBlocked,
						Reason: fmt.Sprintf("Longhorn-backed StorageClass %q (provisioner %s) is not "+
							"ReadWriteMany — PodMotion only supports live migration of Longhorn volumes "+
							"on an RWX/migratable StorageClass (e.g. \"longhorn-migratable\"); the default "+
							"single-attach ReadWriteOnce Longhorn class cannot support Longhorn's dual-engine "+
							"live migration and is not eligible for the Tier1-Longhorn early-source-release "+
							"path (ADR-0356/ADR-0387)", scName, sc2.Provisioner),
						PVCName:      name,
						StorageClass: scName,
					}, nil
				}
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
