/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0423_terminal_integrity.go implements ADR-0423 (accepted, round 8): the completion-budget
// watchdog's escape hatch must verify genuine success, not merely "source pod is gone" (D1); the
// sole-writer terminal-cleanup primitive for Phase=Failed (D2); the rollback wall-clock bound and
// its sole-writer primitive for Phase=RollingBack (D4/D4a/D4b). See docs/adr/0423-*.md for the
// full decision record — this file implements it exactly as decided; it does not re-derive it.

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	pmmetrics "github.com/podmotion-io/podmotion/internal/metrics"
	"github.com/podmotion-io/podmotion/internal/podlineage"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// rollbackBudget (D4) is the wall-clock bound applied to a migration once Phase==RollingBack,
// keyed on the durable pm.Status.RollbackStartTime. 180s ~= 60 requeues of the existing 3s
// requeue loops — a design choice recorded by the ADR, not a correctness mechanism in itself: no
// value changes WHETHER a migration reaches a terminal outcome, only how long a genuinely-
// converging rollback is given before this bound declares it non-converging.
const rollbackBudget = 180 * time.Second

// ── D1 — migrationGenuinelyVerifiedComplete ─────────────────────────────────────────────────

// migrationGenuinelyVerifiedComplete implements ADR-0423 D1: the corrected predicate the
// completion-budget watchdog's escape hatch must use before closing a migration out to Complete
// on a stale antecedent. It is strictly stronger than the bare sourceAlreadyDeletedLegitimately
// check it replaces — dropping the round-2 OR-disjunction — and is mode-correct by construction
// because every mode-dependent conjunct lives inside the single canonical
// pmv1.SourceTeardownBlockReason primitive, never re-derived here.
//
//	migrationGenuinelyVerifiedComplete(pm) :=
//	    sourceAlreadyDeletedLegitimately(pm)
//	    AND SourceTeardownBlockReason(pm.Spec.TCPPreservationMode, pm.Status.Conditions) == ""
//	    AND Restored == True
func (r *PodMigrationReconciler) migrationGenuinelyVerifiedComplete(ctx context.Context, pm *pmv1.PodMigration) bool {
	if !r.sourceAlreadyDeletedLegitimately(ctx, pm) {
		return false
	}
	if pmv1.SourceTeardownBlockReason(pm.Spec.TCPPreservationMode, pm.Status.Conditions) != "" {
		return false
	}
	return meta.IsStatusConditionTrue(pm.Status.Conditions, conditionRestored)
}

// ── D2 — ensureMigrationTerminalCleanup / finalizeFailed ────────────────────────────────────

// ensureMigrationTerminalCleanup performs, unconditionally and in this order, 7 of the 8
// cleanup/reporting items a migration reaching Phase=Failed must have attempted — the union of
// what every current Failed-producing exit does between them, MINUS step 6
// (ensureReplacementEndpointsRemoved), which is deliberately excluded (ADR-0423 Gap 3/D2): its
// `reaped` UID input exists only in the memory of the single reconcile invocation that computed
// it, so calling it from a later, non-contiguous invocation would silently vacuously report
// confirmed absence. Step 6 stays exactly where it runs safely today, inline inside
// reconcileRollingBack's own gate, in the same invocation that freshly computed `reaped`.
//
// Exit-path-agnostic and idempotent: every step below is already individually idempotent, and
// none of them require knowing which caller invoked this function. This is what makes "a
// PodMigration cannot reach Phase=Failed without its destination residue being cleaned and its
// outcome honestly reported" a property enforced AT THE ACT (this function, called from the sole
// place Phase may become Failed) rather than inferred from THE ROUTE a caller happened to take.
func (r *PodMigrationReconciler) ensureMigrationTerminalCleanup(ctx context.Context, pm *pmv1.PodMigration) {
	log := logf.FromContext(ctx)

	// Step 1: disarm the zero-window hold if armed and not yet disarmed (ADR-0157 D2). No-op if
	// never armed or already disarmed — safe to call again even when reconcileRollingBack's own
	// early disarm call (for prompt peer release) already ran this same reconcile.
	r.disarmZeroWindowOnFailurePath(ctx, pm)

	// Step 2: reap any replacement pod. Label-driven and idempotent — a no-op if nothing was ever
	// created for this migration, or it is already reaped.
	r.deleteReplacementPod(ctx, pm)

	// Steps 3/4 (D7 fix): GC-9 dest checkpoint release and GC-10 dest-netns Abort, gated
	// INDEPENDENTLY per ADR-0182 CHURN-15 Issue 3 — there is no shared "destStaged" outer guard
	// coupling them (today's defect this ADR fixes: a migration with CheckpointTransferred=true
	// and ConditionDestinationNetnsReady absent/False never zeroized its destination checkpoint on
	// any path). Both RPCs are warn-only (ADR-0012: the source pod is already safe, so cleanup RPC
	// failure never blocks the terminal write) and this function runs to completion regardless of
	// either step's outcome.
	if r.AgentPool != nil && pm.Status.DestinationNodeName != "" {
		destNode := pm.Status.DestinationNodeName
		destAgent, agErr := r.AgentPool.ForNode(ctx, destNode)
		if agErr != nil {
			log.Error(agErr, "ensureMigrationTerminalCleanup: cannot connect to dest agent for GC-9/GC-10 cleanup (warn-only)",
				"migration", pm.Name, "node", destNode)
		} else {
			if pm.Status.CheckpointTransferred {
				_, relErr := destAgent.ReleaseCheckpoint(ctx, &agentpb.ReleaseCheckpointRequest{
					MigrationName:      pm.Name,
					MigrationNamespace: pm.Namespace,
				})
				if relErr != nil {
					log.Error(relErr, "ensureMigrationTerminalCleanup: dest ReleaseCheckpoint failed (GC-9, warn-only — images remain on dest tmpfs until reboot)",
						"migration", pm.Name, "node", destNode)
				} else {
					log.Info("ensureMigrationTerminalCleanup: dest checkpoint released (GC-9)", "migration", pm.Name, "node", destNode)
				}
			}
			if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionDestinationNetnsReady) {
				_, abErr := destAgent.Abort(ctx, &agentpb.AbortRequest{
					MigrationName: pm.Name,
					Reason:        "ADR-0423 terminal cleanup: tear down dest migration netns (phase-independent)",
				})
				if abErr != nil {
					log.Error(abErr, "ensureMigrationTerminalCleanup: dest Abort/teardown failed (GC-10, warn-only — dest netns may remain until reboot)",
						"migration", pm.Name, "node", destNode)
				} else {
					log.Info("ensureMigrationTerminalCleanup: dest migration netns teardown signalled (GC-10)", "migration", pm.Name, "node", destNode)
				}
			}
		}
	}

	// Step 5: GC-9 half B — MigrationCheckpoint CR Status.Phase = "Failed". Guarded on the MCP's
	// OWN observed phase (not pm.Status.Phase, which this function runs BEFORE the caller sets) so
	// this is safe and idempotent regardless of which invocation runs it.
	if pm.Status.CheckpointRef != nil && pm.Status.CheckpointRef.Name != "" {
		mcp := &pmv1.MigrationCheckpoint{}
		mcpKey := types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}
		if getErr := r.Get(ctx, mcpKey, mcp); getErr == nil {
			if mcp.Status.Phase != "Failed" {
				mcp.Status.Phase = "Failed"
				if updErr := r.Status().Update(ctx, mcp); updErr != nil {
					log.Error(updErr, "ensureMigrationTerminalCleanup: GC-9 failed to set MCP Status.Phase=Failed (warn-only, ADR-0012)", "migration", pm.Name)
				} else {
					log.Info("ensureMigrationTerminalCleanup: GC-9 MCP Status.Phase set to Failed", "migration", pm.Name)
				}
			}
		} else {
			log.Error(getErr, "ensureMigrationTerminalCleanup: GC-9 failed to fetch MCP for phase update (warn-only)", "migration", pm.Name)
		}
	}

	// Step 6 (ensureReplacementEndpointsRemoved) is DELIBERATELY EXCLUDED here — ADR-0423 Gap 3.
	// It stays inline in reconcileRollingBack's own gate, in the same invocation that freshly
	// computed step 2's `reaped` UID list.

	// Step 7: release destination NMC capacity slot. Invocation-agnostic (decrements only if
	// DestinationNodeName is set and the NMC counter is still above zero).
	r.releaseDestinationCapacity(ctx, pm)

	// Step 8: flow-loss metric, incremented exactly once per migration. Idempotency key: skip only
	// if a FRESH, SERVER-SIDE READ shows ConditionFailed or ConditionRolledBack already True — i.e.
	// a PRIOR reconcile invocation already persisted the terminal condition and already ran this
	// step for it.
	//
	// Checking pm.Status.Conditions (the caller's own in-memory object, as this used to do) is
	// WRONG: reconcileRollingBack's tail sets ConditionRolledBack=True on this SAME in-memory pm, in
	// this SAME reconcile call, moments before calling finalizeFailed — so by the time this step
	// runs, pm.Status.Conditions already shows the very condition this call is about to persist, and
	// the guard skipped the increment on EVERY invocation of that path. Three independent reviewers
	// reproduced this in the ADR-0423/0424 implementation review: MigrationFlowLossTotal fired zero
	// times on the reconcileRollingBack -> finalizeFailed exit (the single most common Failed/
	// RolledBack path), where it fired unconditionally before this refactor.
	//
	// A fresh, uncached Get of the object reflects what was durably persisted BEFORE this reconcile
	// call's own in-memory mutations — the correct "was this already counted by a prior invocation"
	// signal — mirroring the same fresh-Get idempotency pattern this file already uses elsewhere
	// (e.g. patchRollbackProgress's read-back Get, step 5's MCP Get above).
	alreadyCounted := false
	freshPM := &pmv1.PodMigration{}
	if getErr := r.Get(ctx, client.ObjectKeyFromObject(pm), freshPM); getErr != nil {
		// Cannot confirm the prior persisted state. Bias AWAY from silently dropping the metric
		// again (the exact defect this fix closes) and toward proceeding as not-yet-counted: a rare
		// spurious double-count on a Get failure is far preferable to reintroducing the
		// always-skipped zero-count regression this step exists to fix.
		log.Error(getErr, "ensureMigrationTerminalCleanup: fresh Get for flow-loss idempotency check failed — proceeding as not-yet-counted",
			"migration", pm.Name)
	} else {
		alreadyCounted = meta.IsStatusConditionTrue(freshPM.Status.Conditions, pmv1.ConditionFailed) ||
			meta.IsStatusConditionTrue(freshPM.Status.Conditions, pmv1.ConditionRolledBack)
	}
	if !alreadyCounted {
		pmmetrics.MigrationFlowLossTotal.WithLabelValues(pm.Name, pm.Namespace).Add(
			float64(len(pm.Status.TCPSeqSnapshots)),
		)
	}
}

// coldRecreatePodExists reports whether this migration's ADR-0393 cold-recreate pod exists and
// carries this migration's distinct recreate marker — checked by a FRESH Get on its deterministic
// name, never from the in-memory `coldRecreated` bool a single reconcile call computed (ADR-0423
// D2 finding (a) / V8). The deterministic name is recomputable purely from pm.Spec.PodName +
// pm.UID, independent of pm.Status.SourcePodSpecSnapshot — which may already have been durably
// cleared (via clearSourcePodSpecSnapshot) by the time a re-entrant reconcile runs this check.
// This is safe specifically because D6b restricts cold-recreate to FIRST-GENERATION sources only:
// a first-generation source carries no OriginalPodNameLabel to diverge from
// podlineage.CanonicalBaseName(pm.Spec.PodName), so this recomputation is byte-identical to the
// `base` buildColdRecreatePod itself used from the (now possibly-cleared) snapshot.
func (r *PodMigrationReconciler) coldRecreatePodExists(ctx context.Context, pm *pmv1.PodMigration) bool {
	base := podlineage.CanonicalBaseName(pm.Spec.PodName)
	name := podlineage.DeterministicIncarnationName(base, podlineage.RecreateNameTag, string(pm.UID))
	existing := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: name}, existing); err != nil {
		return false
	}
	return existing.Labels[rollbackRecreateMigrationUIDLabel] == string(pm.UID)
}

// finalizeFailed is the SOLE writer of Phase=Failed in the controller (ADR-0423 D2). It performs
// the unconditional terminal cleanup FIRST, then persists Phase=Failed + CompletionTime +
// ConditionFailed via the existing retry-on-conflict status write. Every present and future
// caller inherits the cleanup guarantee automatically, with zero textual change at the call site.
func (r *PodMigrationReconciler) finalizeFailed(ctx context.Context, pm *pmv1.PodMigration, reason string) (ctrl.Result, error) {
	r.ensureMigrationTerminalCleanup(ctx, pm)

	key := client.ObjectKeyFromObject(pm)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if fetchErr := r.Get(ctx, key, fresh); fetchErr != nil {
			return fetchErr
		}
		server := fresh.DeepCopy()
		fresh.Status = pm.Status
		preserveOperatorOwnedDurableStatus(server, &fresh.Status) // ADR-0398/0408: never blob-overwrite marker or snapshot
		fresh.Status.Phase = pmv1.MigrationPhaseFailed
		now := metav1.Now()
		fresh.Status.CompletionTime = &now
		setCondition(fresh, pmv1.ConditionFailed, metav1.ConditionTrue, "MigrationFailed", reason)
		return r.Status().Update(ctx, fresh)
	})
	return ctrl.Result{}, err
}

// ── D4/D4a/D4b/decision(a)/decision(b)/decision(c) — the rollback wall-clock bound ──────────

// enterRollingBack is the SOLE writer of Phase=RollingBack in the controller (ADR-0423 D4
// decision (b)/(d)). It unconditionally stamps a rollback-start marker, DURABLY, via the
// field-scoped patchRollbackProgress (never via the blob-write path), then transitions —
// regardless of the stamp's own outcome.
//
// Round 8 (Security Reviewer, the round-7 hard-block finding): this call is fail-safe, NOT
// fail-propagating. r.Rollbacker.Rollback has exactly one call site, reconcileRollingBack,
// dispatched only when Phase==RollingBack — so a `return` here on any patchRollbackProgress error
// would block the only in-band mechanism that thaws a SIGSTOPped source, on every reconcile until
// the transient error clears: the identical shape of defect this ADR exists to close, one call
// site earlier than round 7 fixed it. Log the error (and/or `!stamped`) and fall through
// unconditionally to setCondition/transitionTo regardless of the patch's outcome — nothing is
// lost, because D4(c)'s adopt-and-stamp branch (enforceRollbackBudget, below) re-stamps on the
// very next RollingBack reconcile via the same CAS, with unconditional fall-through.
func (r *PodMigrationReconciler) enterRollingBack(ctx context.Context, pm *pmv1.PodMigration, reason string) (ctrl.Result, error) {
	now := metav1.Now()
	if stamped, err := r.patchRollbackProgress(ctx, pm, &now, nil); err != nil || !stamped {
		logf.FromContext(ctx).Error(err, "enterRollingBack: patchRollbackProgress did not confirm RollbackStartTime stamp — proceeding to RollingBack anyway (D4(c) re-stamps on the next reconcile)",
			"migration", pm.Name, "stamped", stamped)
	}
	setCondition(pm, "RollbackReason", metav1.ConditionTrue, "Initiating", reason)
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseRollingBack)
}

// EnterRollingBack is the exported, one-line wrapper around enterRollingBack that satisfies
// storage.RollbackEnterer (ADR-0423 D4 decision (b)) — the seam internal/agent/storage's
// NodeFencingEmitter depends on so its own initiateRollback never writes Status.Phase directly,
// without creating an import cycle (internal/agent/storage cannot import internal/controller).
// There remains exactly one place Phase=RollingBack is actually set: enterRollingBack itself.
func (r *PodMigrationReconciler) EnterRollingBack(ctx context.Context, pm *pmv1.PodMigration, reason string) error {
	_, err := r.enterRollingBack(ctx, pm, reason)
	return err
}

// patchRollbackProgress writes ONLY .status.rollbackStartTime and/or .status.rollbackAttempted as
// a field-scoped, optimistic-lock JSON merge patch (ADR-0423 decision (a)) — the same primitive
// ADR-0398's completeStoragePreStageDispatch and ADR-0408's patchSourcePodSpecSnapshot use, never
// a whole-.status blob write, and never routed through transitionTo/statusUpdate/failMigration.
//
// Each parameter is a compare-and-swap request, never an overwrite: a non-nil startTime stamps
// RollbackStartTime ONLY if the freshly-fetched server value is still nil; a non-nil attempted
// (pointing at true) sets RollbackAttempted ONLY if the freshly-fetched server value is still
// false. A nil parameter means "this call does not touch that field." "The first reconcile to
// observe the field unset wins; every later one, including a concurrent racer, is a no-op" is the
// whole guard — it is what prevents two concurrent reconciles from both successfully stamping the
// field with two different timestamps.
//
// Returns (stamped bool, err error), mirroring completeStoragePreStageDispatch's shape — a nil err
// does NOT by itself mean the field durably landed (an unapplied CRD schema silently prunes it; a
// concurrent overwrite can race the read-back), so the function re-reads through the uncached
// r.readBackReader() after a Patch, the same read-back discipline captureSourcePodSpecSnapshot
// already uses, and reports stamped=true only if the target field(s) are actually observed set on
// that read-back. Every caller (enterRollingBack, D4(c) via enforceRollbackBudget, D4a) treats
// stamped=false the same way: log it, do not block, proceed — a bookkeeping write may never gate a
// safety action, applied here to durability-confirmation as well as to the write itself.
//
// The read-back Get is gated to the branch where this call actually performed a Patch: the no-op
// `!changed` path already observed the target field(s) set on the fresh Get taken moments earlier
// inside the retry loop, so a second, uncached read confirms nothing new and no caller acts
// differently on the returned `stamped` value regardless.
func (r *PodMigrationReconciler) patchRollbackProgress(ctx context.Context, pm *pmv1.PodMigration, startTime *metav1.Time, attempted *bool) (bool, error) {
	key := client.ObjectKeyFromObject(pm)
	patched := false
	if err := retry.RetryOnConflict(storagePreStageFinalizeBackoff, func() error {
		fresh := &pmv1.PodMigration{}
		if err := r.Get(ctx, key, fresh); err != nil {
			return err
		}
		base := fresh.DeepCopy()
		changed := false
		if startTime != nil && fresh.Status.RollbackStartTime == nil {
			fresh.Status.RollbackStartTime = startTime
			changed = true
		}
		if attempted != nil && *attempted && !fresh.Status.RollbackAttempted {
			fresh.Status.RollbackAttempted = true
			changed = true
		}
		if !changed {
			// Already set by a concurrent winner (or this call is redundant): genuine
			// supersession, not a conflict — no Patch, keep pm coherent with server state.
			pm.Status.RollbackStartTime = fresh.Status.RollbackStartTime
			pm.Status.RollbackAttempted = fresh.Status.RollbackAttempted
			return nil
		}
		if err := r.Status().Patch(ctx, fresh, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			return err
		}
		patched = true
		pm.Status.RollbackStartTime = fresh.Status.RollbackStartTime
		pm.Status.RollbackAttempted = fresh.Status.RollbackAttempted
		return nil
	}); err != nil {
		return false, err
	}
	if !patched {
		// No Patch occurred on the winning attempt — the no-op branch's own fresh Get already
		// confirmed the target field(s) set. Nothing to read back.
		return true, nil
	}
	// Read-back verification: a nil Patch error is not proof of durability — the field may have
	// been silently pruned by an unapplied CRD schema, or clobbered by a concurrent overwrite that
	// raced this call. Re-read through the uncached APIReader, mirroring
	// captureSourcePodSpecSnapshot's own read-back discipline.
	fresh := &pmv1.PodMigration{}
	if err := r.readBackReader().Get(ctx, key, fresh); err != nil {
		// Cannot confirm durability either way. Do not fail the call on this account — pm was
		// already updated above from the Patch attempt's own fresh Get, and every caller's
		// disposition on an unconfirmed stamp is "log it, do not block, proceed."
		return false, nil
	}
	stamped := true
	if startTime != nil && fresh.Status.RollbackStartTime == nil {
		stamped = false
	}
	if attempted != nil && *attempted && !fresh.Status.RollbackAttempted {
		stamped = false
	}
	return stamped, nil
}

// correctImplausibleRollbackStartTime is D4b's bounds-triggered correction: unlike
// patchRollbackProgress's nil-only CAS, this OVERWRITES an already-non-nil but objectively
// untrustworthy RollbackStartTime (in the future, or strictly before pm.CreationTimestamp — both
// physically impossible for a real rollback entry) with a fresh timestamp. It is a distinct,
// explicit code path from the ordinary CAS in patchRollbackProgress — safe precisely because it
// fires only when the existing value is already known-bad by an objective, cheap check, never on
// a merely-inconvenient one.
func (r *PodMigrationReconciler) correctImplausibleRollbackStartTime(ctx context.Context, pm *pmv1.PodMigration, now *metav1.Time) (bool, error) {
	key := client.ObjectKeyFromObject(pm)
	patched := false
	if err := retry.RetryOnConflict(storagePreStageFinalizeBackoff, func() error {
		fresh := &pmv1.PodMigration{}
		if err := r.Get(ctx, key, fresh); err != nil {
			return err
		}
		base := fresh.DeepCopy()
		fresh.Status.RollbackStartTime = now
		if err := r.Status().Patch(ctx, fresh, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			return err
		}
		patched = true
		pm.Status.RollbackStartTime = fresh.Status.RollbackStartTime
		return nil
	}); err != nil {
		return false, err
	}
	return patched, nil
}

// enforceRollbackBudget implements D4/D4(c)/D4a/D4b: the wall-clock bound applied once
// Phase==RollingBack, where the top-level completion-budget watchdog (guarded on
// !isTerminalOrRollingBackPhase) is otherwise inert. Returns terminal=true only when it has itself
// forced a terminal decision (via finalizeFailed) this pass — every other outcome (nil-stamp,
// implausible-value correction, or attempt-not-yet-made) returns terminal=false so the caller
// falls through UNCONDITIONALLY to the normal phase-switch dispatch (reconcileRollingBack) on this
// same pass, exactly as D4(c) requires: the budget cannot legitimately have expired on the very
// pass where the stamp was just (attempted to be) taken, so skipping only its evaluation costs
// nothing, and the thaw attempt (r.Rollbacker.Rollback, reached via reconcileRollingBack) never
// depends on the stamp's fate.
func (r *PodMigrationReconciler) enforceRollbackBudget(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error, bool) {
	log := logf.FromContext(ctx)

	if pm.Status.RollbackStartTime == nil {
		// D4(c) adopt-and-stamp, nil branch. Regardless of *why* it is nil (pre-upgrade CR,
		// adversarial/co-writer status PATCH, or a self-healing transient blob-clobber regression)
		// — the mechanism does not need to distinguish the cause.
		now := metav1.Now()
		stamped, err := r.patchRollbackProgress(ctx, pm, &now, nil)
		if err != nil || !stamped {
			log.Error(err, "enforceRollbackBudget: patchRollbackProgress did not confirm RollbackStartTime stamp — proceeding unconditionally; re-stamped on the next RollingBack reconcile (ADR-0423 D4(c))",
				"migration", pm.Name, "stamped", stamped)
		}
		return ctrl.Result{}, nil, false
	}

	// D4b bounds check: an already-non-nil RollbackStartTime that is in the future, or strictly
	// before pm.CreationTimestamp (the migration object itself did not exist before that instant,
	// so ANY earlier value is physically impossible), is untrustworthy — e.g. the unadmitted
	// node-agent co-writer D4(c) vector 2 already names. Correct it via a direct overwrite (never
	// the nil-only CAS, which cannot repair an already-non-nil value by design) rather than
	// adopting it.
	if pm.Status.RollbackStartTime.After(time.Now()) || pm.Status.RollbackStartTime.Before(&pm.CreationTimestamp) {
		bad := pm.Status.RollbackStartTime.DeepCopy()
		now := metav1.Now()
		if _, err := r.correctImplausibleRollbackStartTime(ctx, pm, &now); err != nil {
			log.Error(err, "enforceRollbackBudget: corrective patch for implausible RollbackStartTime failed — proceeding unconditionally (ADR-0423 D4b)",
				"migration", pm.Name)
		}
		if r.Recorder != nil {
			r.Recorder.Eventf(pm, corev1.EventTypeWarning, "RollbackStartTimeImplausible",
				"migration %s: RollbackStartTime %s is untrustworthy (future, or before CreationTimestamp %s) — corrected to now (ADR-0423 D4b)",
				pm.Name, bad.Format(time.RFC3339), pm.CreationTimestamp.Format(time.RFC3339))
		}
		return ctrl.Result{}, nil, false
	}

	if !pm.Status.RollbackAttempted {
		// D4a: the bound must not fire before Rollbacker.Rollback has been attempted at least
		// once. reconcileRollingBack sets RollbackAttempted immediately after
		// disarmZeroWindowOnFailurePath, before Rollbacker.Rollback — leave this pass to the
		// ordinary requeue loop rather than force-terminating sight-unseen.
		return ctrl.Result{}, nil, false
	}

	if time.Now().After(pm.Status.RollbackStartTime.Add(rollbackBudget)) {
		log.Error(nil, "rollback did not converge within its budget — failing closed to Failed (ADR-0423 D4)",
			"migration", pm.Name, "rollbackStartTime", pm.Status.RollbackStartTime, "rollbackBudget", rollbackBudget)
		res, err := r.finalizeFailed(ctx, pm, fmt.Sprintf("rollback did not converge within its budget (%s, ADR-0423 D4)", rollbackBudget))
		return res, err, true
	}
	return ctrl.Result{}, nil, false
}
