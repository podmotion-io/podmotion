/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/podlineage"
)

// rollbackRecreateMigrationUIDLabel is the DISTINCT marker the ADR-0393 cold-recreate stamps on the
// recreated pod. It is deliberately NOT replacementPodMigrationNameLabel (which is keyed on pm.Name
// and is used by deleteReplacementPod's fire-and-forget label reaper). Keying the recreate marker on
// pm.UID and giving the recreated pod a distinct deterministic name (`-r-` suffix, vs the
// replacement pod's `-m-` suffix) means the recreate's idempotency lookup can never (a) false-positive
// on a still-terminating reaped replacement pod and skip the recreate, nor (b) collide names and race
// a second pod onto the same volume (KVM/Live-Migration Systems Expert finding, ADR-0393 D3).
const rollbackRecreateMigrationUIDLabel = "podmotion.io/rollback-recreate-migration-uid"

// coldRecreateOutcome is the result of one reconcileTier1ColdRecreateFromSnapshot pass.
type coldRecreateOutcome int

const (
	// coldRecreatePending: the recreate is in progress (persisted RollbackRecreatePending=True) and
	// the caller must requeue without setting a terminal RolledBack condition; a re-entrant reconcile
	// resumes from persisted state (ADR-0393 D-ACCEPT).
	coldRecreatePending coldRecreateOutcome = iota
	// coldRecreateSucceeded: the recreated pod is confirmed present; the caller sets
	// RollbackCompleteColdRecreatedFromSnapshot and proceeds to the terminal Failed phase.
	coldRecreateSucceeded
	// coldRecreateBlockedInvalid: the snapshot is absent/tampered/stale; the caller falls through to
	// today's honest RollbackCompleteNoOwningController outage report (nothing was fabricated).
	coldRecreateBlockedInvalid
)

// captureSourcePodSpecSnapshot implements ADR-0393 D2: the fail-closed durable snapshot capture.
// For a bare (no owning controller) source pod on the Tier1-Longhorn early-release path, it captures
// the live source pod's PodSpec + recreate identity, signs it with the operator-only-held HMAC key,
// persists it to pm.Status BEFORE any irreversible source action, and CONFIRMS the persisted snapshot
// reads back and verifies. Any failure returns an error so the caller aborts before KillFrozenSource /
// source-pod delete — no confirmed snapshot, no source kill.
//
// It is a structural no-op (returns nil, captures nothing) for a pod that HAS an owning controller —
// such a pod recovers via its controller and needs no snapshot — so it does not change the kill/delete
// ordering for owned pods at all. It is idempotent: once pm.Status.SourcePodSpecSnapshot is set, a
// repeat call returns nil.
func (r *PodMigrationReconciler) captureSourcePodSpecSnapshot(ctx context.Context, pm *pmv1.PodMigration, sourcePod *corev1.Pod) error {
	// Owned pod ⇒ its controller recreates it; capture nothing, change no ordering.
	for i := range sourcePod.OwnerReferences {
		if c := sourcePod.OwnerReferences[i].Controller; c != nil && *c {
			return nil
		}
	}
	// ADR-0396 D-KILL-FIX: do NOT trust snapshot PRESENCE. The agent SA is a co-writer of the
	// podmigrations/status subresource and subresource RBAC has no field granularity, so a compromised
	// agent can PLANT a SourcePodSpecSnapshot. The pre-ADR-0396 short-circuit ("present ⇒ return nil")
	// would then report the capture gate satisfied on a forged snapshot and authorize the source kill
	// (podmigration_controller.go:2619) on bytes the operator never signed — and would make ADR-0396's
	// armed := (capture == nil) forgeable. Re-verify the operator's own keyed HMAC instead: return nil
	// (genuinely idempotent) ONLY for our own valid, operator-signed snapshot; otherwise discard the
	// present-but-unverifiable snapshot and fall through to re-capture + re-sign from the live source
	// pod (which itself fail-closes if it cannot produce a verified snapshot). A forged/tampered/stale
	// snapshot can therefore never authorize a delete on trust, on any pod class, gate flip or not.
	if pm.Status.SourcePodSpecSnapshot != nil {
		if ok, _ := r.verifySnapshotIntegrity(ctx, pm); ok {
			return nil // our own valid, operator-signed snapshot — genuinely idempotent under requeue
		}
		pm.Status.SourcePodSpecSnapshot = nil // present but not operator-signed for this migration — discard, re-capture below
	}

	spec := sourcePod.Spec.DeepCopy()
	// Clear scheduler-assigned/mutable fields exactly as createReplacementPod does, so the mutating
	// webhook re-injects scheduler name/gates on recreate and the pod schedules fresh.
	spec.SchedulerName = ""
	spec.SchedulingGates = nil
	spec.NodeName = ""

	specJSON, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("ADR-0393: serialize source pod spec: %w", err)
	}
	scDigest, err := podSecurityContextDigest(spec)
	if err != nil {
		return err
	}

	labels := make(map[string]string, len(sourcePod.Labels))
	for k, v := range sourcePod.Labels {
		labels[k] = v
	}
	annotations := make(map[string]string, len(sourcePod.Annotations))
	for k, v := range sourcePod.Annotations {
		annotations[k] = v
	}
	delete(annotations, "kubectl.kubernetes.io/last-applied-configuration")

	snap := &pmv1.SourcePodSpecSnapshot{
		PodSpecJSON:           specJSON,
		BaseName:              sourcePod.Name,
		Namespace:             sourcePod.Namespace,
		Labels:                labels,
		Annotations:           annotations,
		SourcePodUID:          string(sourcePod.UID),
		ServiceAccountName:    spec.ServiceAccountName,
		SecurityContextDigest: scDigest,
		CapturedAtGeneration:  pm.Generation,
	}
	key, err := r.snapshotHMACKey(ctx)
	if err != nil {
		return err
	}
	snap.IntegrityHMAC = computeSnapshotHMAC(key, snap, string(pm.UID))

	// ADR-0408: persist the durable snapshot via a FIELD-SCOPED optimistic-lock patch — NOT the
	// whole-.status blob writer statusUpdate. The blob writer carries forward only the ADR-0398 marker,
	// so a concurrent reconcile's blob overwrite (fresh.Status = *want, want DeepCopy'd before this
	// write) would drop SourcePodSpecSnapshot between the write and the read-back below, making a
	// perfectly-armable pod report un-capturable (deterministic on idle/instantly-converging pods).
	if err := r.patchSourcePodSpecSnapshot(ctx, pm, snap); err != nil {
		pm.Status.SourcePodSpecSnapshot = nil // do not leave a phantom in-memory snapshot
		return fmt.Errorf("ADR-0393: persist source pod spec snapshot: %w", err)
	}

	// Read-back confirmation: re-Get the object and re-verify integrity from the persisted bytes.
	// A write that did not round-trip (or does not verify) must NOT unblock the source kill.
	//
	// ADR-0410: read through the UNCACHED APIReader, not the cached client. The Status().Patch above
	// is a direct write to the API server; the informer cache is NOT read-after-write consistent with
	// it, so a cached Get can still hold the pre-patch object (SourcePodSpecSnapshot == nil) until the
	// watch delivers the write — a read-your-own-write blip, worst at operator cold-start. The uncached
	// read observes authoritative server truth immediately, honoring this gate's "from the persisted
	// bytes" intent (matching the ADR-0400/0401 uncached-fail-closed-read precedent).
	fresh := &pmv1.PodMigration{}
	if err := r.readBackReader().Get(ctx, types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name}, fresh); err != nil {
		return fmt.Errorf("ADR-0393: read-back source pod spec snapshot: %w", err)
	}
	if fresh.Status.SourcePodSpecSnapshot == nil {
		return fmt.Errorf("ADR-0393: source pod spec snapshot did not persist (read-back nil) — refusing source kill")
	}
	if ok, reason := r.verifySnapshotIntegrity(ctx, fresh); !ok {
		return fmt.Errorf("ADR-0393: source pod spec snapshot read-back failed verification (%s) — refusing source kill", reason)
	}
	return nil
}

// readBackReader returns the UNCACHED APIReader for the ADR-0393/0410 capture read-back gate, falling
// back to the cached client only when APIReader is unset (unit tests, where the fake client is
// read-after-write consistent and no cache-lag exists to defend against). Production ALWAYS wires
// APIReader (cmd/main.go), so the authoritative read-back never depends on watch-delivery latency.
func (r *PodMigrationReconciler) readBackReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// buildColdRecreatePod deserializes the snapshot into a fresh Pod object for cold-recreate. This is a
// plain pod from the captured spec — NOT a checkpoint restore (the CRIU restore is the thing that
// failed) — so it carries no holder init-container and no checkpoint-ref annotation. Scheduler fields
// are re-cleared defensively. The name is deterministic and bound to pm.UID, and a distinct recreate
// marker label is stamped (see rollbackRecreateMigrationUIDLabel).
func buildColdRecreatePod(pm *pmv1.PodMigration) (*corev1.Pod, error) {
	s := pm.Status.SourcePodSpecSnapshot
	if s == nil {
		return nil, fmt.Errorf("ADR-0393: no snapshot to build recreate pod from")
	}
	var spec corev1.PodSpec
	if err := json.Unmarshal(s.PodSpecJSON, &spec); err != nil {
		return nil, fmt.Errorf("ADR-0393: deserialize snapshot pod spec: %w", err)
	}
	spec.SchedulerName = ""
	spec.SchedulingGates = nil
	spec.NodeName = ""

	// Derive the recreate pod name from the STABLE ORIGINAL (root) workload name,
	// never from s.BaseName directly. s.BaseName is the source pod's name AT THIS
	// migration's capture time — on a pod that is already an "-m-"/"-r-" successor
	// it already carries that suffix, so appending "-r-<uid>" to it chained the name
	// without bound (the same defect as createReplacementPod, one indirection removed
	// via the snapshot). OriginalNameFromLabels reads the root the source pod carried
	// forward in a label (or canonicalizes s.BaseName for a never-migrated pod), so
	// the "-r-" recreate name is a fixed-width function of (root, pm.UID) and never
	// grows across repeated cycles. The tag stays "-r-" (distinct from the "-m-"
	// replacement pod) so the two pod classes never collide on a name.
	base := podlineage.OriginalNameFromLabels(s.Labels, s.BaseName)
	name := podlineage.DeterministicIncarnationName(base, podlineage.RecreateNameTag, string(pm.UID))

	labels := make(map[string]string, len(s.Labels)+1)
	for k, v := range s.Labels {
		labels[k] = v
	}
	labels[rollbackRecreateMigrationUIDLabel] = string(pm.UID)
	// Record migration lineage in LABELS rather than in the pod name (parity with
	// createReplacementPod): stable root, generation depth, and the immediate
	// predecessor (the captured source pod). Fail closed — an unrooted recreate is a
	// real error, not a silently unlabeled pod. NOTE: the recreate pod is a STANDALONE
	// recovered workload standing in for the deleted bare source, so — unlike the
	// migration-transient "-m-" replacement pod — it deliberately takes NO PodMigration
	// ownerReference (that would cascade-delete the recovered pod when the PM CR is
	// reaped). It is discoverable by these labels + rollbackRecreateMigrationUIDLabel.
	if err := podlineage.StampLabels(labels, base, s.BaseName, s.SourcePodUID,
		podlineage.GenerationFromLabels(s.Labels)+1); err != nil {
		return nil, fmt.Errorf("ADR-0393: stamp lineage labels on cold-recreate pod: %w", err)
	}

	annotations := make(map[string]string, len(s.Annotations))
	for k, v := range s.Annotations {
		annotations[k] = v
	}
	delete(annotations, "kubectl.kubernetes.io/last-applied-configuration")

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   s.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: spec,
	}, nil
}

// reconcileTier1ColdRecreateFromSnapshot implements ADR-0393 D3/D4/D5: the fail-closed cold-recreate
// state machine for a bare pod whose source was early-deleted (ADR-0356) and whose restore then
// failed. It is re-entrant and crash-safe (D-ACCEPT): the recreate pod name is deterministic, so a
// reconcile that re-enters after an operator crash — whether the crash landed before r.Create or after
// r.Create succeeded but before anything was recorded — recomputes the same name, finds (or re-creates)
// exactly one pod, and completes the transition. It never introduces a second pod.
func (r *PodMigrationReconciler) reconcileTier1ColdRecreateFromSnapshot(ctx context.Context, pm *pmv1.PodMigration) (coldRecreateOutcome, ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// D5: validate before doing anything irreversible on the API.
	if ok, reason := r.verifySnapshotIntegrity(ctx, pm); !ok {
		setCondition(pm, pmv1.ConditionRollbackRecreatePending, metav1.ConditionFalse,
			"RollbackRecreateBlockedInvalidSnapshot", "ADR-0393: "+reason)
		log.Info("ADR-0393: cold-recreate blocked — snapshot invalid; degrading to honest unrecovered-outage report",
			"migration", pm.Name, "reason", reason)
		return coldRecreateBlockedInvalid, ctrl.Result{}, nil
	}

	pod, err := buildColdRecreatePod(pm)
	if err != nil {
		setCondition(pm, pmv1.ConditionRollbackRecreatePending, metav1.ConditionFalse,
			"RollbackRecreateBlockedInvalidSnapshot", err.Error())
		log.Info("ADR-0393: cold-recreate blocked — could not build pod from snapshot; degrading to honest outage report",
			"migration", pm.Name, "err", err.Error())
		return coldRecreateBlockedInvalid, ctrl.Result{}, nil
	}

	// Idempotency + crash recovery: look up the deterministic recreate pod by name.
	existing := &corev1.Pod{}
	getErr := r.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, existing)
	switch {
	case getErr == nil:
		// A pod already occupies the deterministic recreate name. Confirm it is OURS (carries the
		// pm.UID-bound recreate marker) before declaring success — never adopt a foreign pod.
		if existing.Labels[rollbackRecreateMigrationUIDLabel] != string(pm.UID) {
			setCondition(pm, pmv1.ConditionRollbackRecreatePending, metav1.ConditionFalse,
				"RollbackRecreateBlockedInvalidSnapshot",
				"ADR-0393: deterministic recreate name is occupied by a pod that is not this migration's recreate")
			log.Info("ADR-0393: cold-recreate name occupied by a non-recreate pod — failing closed to honest outage report",
				"migration", pm.Name, "pod", pod.Name)
			return coldRecreateBlockedInvalid, ctrl.Result{}, nil
		}
		return r.completeColdRecreate(ctx, pm), ctrl.Result{}, nil
	case !apierrors.IsNotFound(getErr):
		return coldRecreatePending, ctrl.Result{RequeueAfter: 3 * time.Second}, getErr
	}

	// Not found yet. Persist RollbackRecreatePending=True BEFORE r.Create so a crash between here and
	// the Create re-enters this path (the deterministic name makes the re-create idempotent).
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionRollbackRecreatePending) {
		setCondition(pm, pmv1.ConditionRollbackRecreatePending, metav1.ConditionTrue,
			"RollbackRecreateInProgress", "ADR-0393: cold-recreating source pod from durable snapshot")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return coldRecreatePending, ctrl.Result{RequeueAfter: 3 * time.Second}, err
		}
	}

	// D4: create through the SAME admission chain a normal pod create traverses (no privileged
	// bypass). A rejected create leaves RollbackRecreatePending=True and requeues — it never
	// downgrades to a widened pod.
	if err := r.Create(ctx, pod); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Created concurrently (e.g. crash-after-create re-entry) — treat as success.
			return r.completeColdRecreate(ctx, pm), ctrl.Result{}, nil
		}
		log.Error(err, "ADR-0393: cold-recreate create rejected/failed — withholding terminal RolledBack, requeuing",
			"migration", pm.Name, "pod", pod.Name)
		return coldRecreatePending, ctrl.Result{RequeueAfter: 3 * time.Second}, err
	}
	log.Info("ADR-0393: cold-recreated source pod from durable snapshot (ReplicaSet parity — NOT a zero-downtime rollback)",
		"migration", pm.Name, "pod", pod.Name)
	return r.completeColdRecreate(ctx, pm), ctrl.Result{}, nil
}

// patchSourcePodSpecSnapshot writes ONLY .status.sourcePodSpecSnapshot as a field-scoped, optimistic-lock
// JSON merge patch (ADR-0408) — the same primitive ADR-0398 uses for StoragePreStageDispatch. Unlike the
// whole-.status blob overwrite in statusUpdate, this patch names a single field, so the API server applies
// it on top of live state and a disjoint concurrent status write cannot clobber it (nor it them). A 409
// (an unrelated writer bumped resourceVersion) is retried in place: re-Get, re-set the field, re-Patch.
// The retry uses the ADR-0407 storm-sized storagePreStageFinalizeBackoff (NOT retry.DefaultRetry): the
// capture patch races the same creation-instant status-write storm the mechanism map measured, so its
// retry must outlast that storm exactly as ADR-0407's finalize patch does.
func (r *PodMigrationReconciler) patchSourcePodSpecSnapshot(ctx context.Context, pm *pmv1.PodMigration, snap *pmv1.SourcePodSpecSnapshot) error {
	key := client.ObjectKeyFromObject(pm)
	return retry.RetryOnConflict(storagePreStageFinalizeBackoff, func() error {
		fresh := &pmv1.PodMigration{}
		if err := r.Get(ctx, key, fresh); err != nil {
			return err
		}
		base := fresh.DeepCopy()
		fresh.Status.SourcePodSpecSnapshot = snap
		if err := r.Status().Patch(ctx, fresh, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			return err
		}
		pm.Status.SourcePodSpecSnapshot = fresh.Status.SourcePodSpecSnapshot // keep the in-memory pm coherent
		return nil
	})
}

// clearSourcePodSpecSnapshot is the same field-scoped optimistic-lock patch with snap == nil (used by
// completeColdRecreate and the discard of a present-but-unverifiable snapshot). Passing nil clears the
// field. Because the clear now lands as a field-scoped patch that D2's preserveOperatorOwnedDurableStatus
// honors from the server, a consumed snapshot stays cleared rather than being resurrected by a
// server-authoritative carry-forward on the next blob overwrite.
func (r *PodMigrationReconciler) clearSourcePodSpecSnapshot(ctx context.Context, pm *pmv1.PodMigration) error {
	return r.patchSourcePodSpecSnapshot(ctx, pm, nil)
}

// completeColdRecreate finalizes a successful recreate: clears the pending condition, drops the now
// -consumed snapshot from status. The terminal RolledBack condition is set by the caller.
//
// ADR-0408: the snapshot clear is a field-scoped clearSourcePodSpecSnapshot patch (so D2's server-
// authoritative carry-forward cannot resurrect the just-consumed snapshot). The clear is fail-SAFE, not
// fail-propagating: on error it is logged and swallowed and the function STILL returns
// coldRecreateSucceeded. The recreate has already succeeded; the snapshot only ever authorized the
// already-past source-kill (never a future one); a lingering HMAC-signed snapshot is inert (every
// consumer verifies HMAC on use) and is re-cleared on the next reconcile. Failing a completed recreate
// on a best-effort cleanup would be strictly worse.
func (r *PodMigrationReconciler) completeColdRecreate(ctx context.Context, pm *pmv1.PodMigration) coldRecreateOutcome {
	setCondition(pm, pmv1.ConditionRollbackRecreatePending, metav1.ConditionFalse,
		"RollbackRecreateComplete", "ADR-0393: source pod cold-recreated from durable snapshot")
	if err := r.clearSourcePodSpecSnapshot(ctx, pm); err != nil {
		logf.FromContext(ctx).Error(err, "ADR-0408: best-effort snapshot clear after cold-recreate failed (inert, re-cleared next reconcile) — recreate still succeeds",
			"migration", pm.Name)
	}
	pm.Status.SourcePodSpecSnapshot = nil // keep in-memory pm coherent regardless of clear outcome
	return coldRecreateSucceeded
}
