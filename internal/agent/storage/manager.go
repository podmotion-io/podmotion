/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

const conditionStorageReadyForFreeze = "StorageReadyForFreeze"

const (
	// preStageMaxAttempts bounds the retry on a transient PreStage failure
	// (e.g. the Longhorn Manager DNS name not yet resolvable right after a
	// fresh agent pod restart). Bounded and small on purpose — this must not
	// become an unbounded/exponential retry that eats the whole migration's
	// completion budget.
	preStageMaxAttempts = 3
	// preStageRetryBackoff is a fixed short delay between PreStage retry
	// attempts (not exponential-to-infinity).
	preStageRetryBackoff = 3 * time.Second
)

// isTransientPreStageError reports whether err is a network/timeout-class
// error worth a bounded retry — DNS not yet converged, connection refused
// right after a fresh pod restart, dial/read timeouts — as opposed to a
// permanent error (e.g. a real "volume not found" 404 from the Longhorn
// Manager API). Retrying a permanent error only wastes the migration's
// completion budget, so those must fail fast instead.
func isTransientPreStageError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// MigrationOptions carries context required by tier migrators.
type MigrationOptions struct {
	// MigrationName is the name of the PodMigration CR (for logging/patching).
	MigrationName string
	// PodNamespace is the namespace of the source pod.
	PodNamespace string
	// SourceNode is the node the pod is migrating from.
	SourceNode string
	// DestinationNode is the node the pod is migrating to.
	DestinationNode string
	// Classifications is the list of per-PVC tier decisions from StorageClassifier.
	Classifications []TierClassification
	// CutoverComplete is true when ConditionStorageCutoverComplete is (or, per
	// cutoverSideEffectOccurred, was) True on the PodMigration at the moment this
	// MigrationOptions was built — i.e. Cutover's tier-specific destination-side action
	// (Longhorn attach, Ceph `rbd migration commit`, …) is known to have actually executed.
	// Populated ONLY by buildMigrationOptionsFromCache (the read path ReleaseDestination uses),
	// via the same meta.FindStatusCondition/meta.IsStatusConditionTrue pattern already used
	// elsewhere in this controller (podmigration_controller.go:1050) — never inferred from tier
	// identity alone (ADR-0368 CONDITION 2 / KVM Expert FINDING 1). Tier2/Tier3's
	// ReleaseDestination implementations gate their point-of-no-return/not-implemented sentinel
	// on this field: if cutover never actually ran, there is nothing destination-side to
	// release, and returning the sentinel anyway would incorrectly terminate a recoverable
	// failure that happened before Cutover ever fired (the common case: a Checkpointing- or
	// Transferring-phase failure). Ignored by Tier0 (never creates a reservation) and Tier1
	// (detachFromNode is idempotent against a volume that was never attached to the destination,
	// so no gate is needed there — see LonghornMigrator.ReleaseDestination).
	CutoverComplete bool
}

// Migrator is the interface implemented by each storage tier handler.
type Migrator interface {
	// Tier returns the storage tier this migrator handles.
	Tier() StorageTier
	// PreStage prepares storage on the destination before the compute freeze.
	// For Tier0 this is a no-op verification; for Tier1 it starts replica sync.
	PreStage(ctx context.Context, opts MigrationOptions) error
	// SyncPercent returns the current synchronisation progress (0–100).
	// Returns 100 for tiers with no sync phase (Tier0).
	SyncPercent(ctx context.Context, opts MigrationOptions) (int, error)
	// Cutover detaches from the source and attaches to the destination.
	// Called by the controller from reconcileOverlayHandoff
	// (gateStorageCutoverBeforeRestore), at the very end of that phase,
	// immediately before the phase transition into RestoreSocketReattach —
	// the first phase in the NRI StartContainer hook's restore accept-set
	// (nri/plugin.go verifyPhaseInAcceptSet). That is deliberately AFTER the
	// scheduling gate has already been removed (end of reconcileTransferring):
	// for tiers like Longhorn whose dual-engine collapse only begins once the
	// destination pod is actually scheduled and kubelet mounts the volume,
	// gating any earlier would deadlock forever waiting for a collapse that
	// can never start (sprint49 finding). Restore must never be allowed to
	// race ahead of storage actually being attached/collapsing on the
	// destination node — gating at the last moment before the phase write
	// that unblocks restore is what actually prevents that race.
	Cutover(ctx context.Context, opts MigrationOptions) error
	// AwaitSingleOwner blocks until every classified volume for this tier is
	// in a single-owner, mountable state on the destination node. Called by
	// the controller immediately after Cutover succeeds, in the same
	// gateStorageCutoverBeforeRestore call — still strictly BEFORE the phase
	// transition into RestoreSocketReattach, so CRIU restore (NRI-triggered
	// or the direct/legacy RPC path) cannot begin until this returns. This is
	// the actual gate that prevents restore from racing ahead of the
	// destination storage engine being present/ready (e.g. Longhorn's
	// dual-engine collapsing to a single RW replica on the destination node).
	//
	// Must return promptly (bounded internal poll) rather than blocking
	// forever; a timeout is a real error, not a wait condition. Each tier
	// implements this using its own backend-specific readiness signal (e.g.
	// Longhorn's replica list collapsing to a single RW replica on the
	// destination node) — never a generic string match on a driver error.
	// Tiers with no shared-attachment/dual-owner concept (RWX, snapshot-rsync)
	// return nil immediately.
	AwaitSingleOwner(ctx context.Context, opts MigrationOptions) error
	// ReleaseDestination undoes whatever destination-side reservation Cutover created, as part
	// of the rollback path (internal/rollback/rollback.go's StorageStep, called from
	// reconcileRollingBack after ComputeRollback but governed by the same Network→Compute→Storage
	// order as the forward pipeline — ADR-0014, unaffected by this ADR).
	//
	// Every tier MUST return one of exactly three outcomes, never anything else (ADR-0368 §5.1):
	//   - nil: the destination-side reservation (if any) has been confirmed released, or the
	//     tier never created one in the first place. This is the ONLY value that may cause the
	//     rollback pipeline to treat storage as cleanly rolled back.
	//   - a wrapped ErrRollbackPointOfNoReturn: undo is structurally impossible (the forward
	//     Cutover already made an irrevocable choice). The caller MUST NOT retry.
	//   - a wrapped ErrRollbackNotImplemented: undo has not been built for this tier yet. Must
	//     be surfaced exactly as loudly as ErrRollbackPointOfNoReturn.
	//   - any other non-nil error: a real, transient/operational failure attempting the undo.
	//     Retriable via the normal reconcile requeue.
	//
	// ReleaseDestination MUST NEVER return nil for a tier/case where the destination-side
	// reservation was NOT actually confirmed released. A fabricated nil here is exactly the
	// failure mode this method exists to prevent — the live outage ADR-0368 documents.
	ReleaseDestination(ctx context.Context, opts MigrationOptions) error
}

// StorageMigrationManager selects the appropriate Migrator based on the tier
// classification, runs PreStage concurrently with the pre-copy loop, and patches
// StorageReadyForFreeze on the PodMigration CR once the 95% sync threshold is met.
//
// The manager is called from the PodMigration controller PreMigrating phase alongside
// the ReplicationManager; both goroutines run concurrently (ADR-0011).
type StorageMigrationManager struct {
	Client     client.Client
	Classifier *StorageClassifier
	// Migrators maps StorageTier → Migrator. Populated by wire code in cmd/operator.
	// Tests inject stubs here.
	Migrators map[StorageTier]Migrator
}

// NewStorageMigrationManager returns a manager wired with the default migrators.
// Tier2 (CephRBD) and Tier3 (SnapshotRsync) are registered as stubs by default
// so that the state machine is unblocked in environments without Ceph or a snapshot
// provisioner. Wire production migrators via RegisterMigrator in cmd/operator.
// Pass overrides via RegisterMigrator in tests to inject fakes.
func NewStorageMigrationManager(c client.Client) *StorageMigrationManager {
	m := &StorageMigrationManager{
		Client:     c,
		Classifier: NewStorageClassifier(c),
		Migrators:  map[StorageTier]Migrator{},
	}
	// Default registrations — all production implementations are registered by
	// the operator wire code; explicit stubs are used here so the manager is
	// usable out of the box without external dependencies, and so that no tier
	// falls through to the missing-migrator branch (which now blocks the freeze
	// for any tier > TierRWX rather than silently declaring it ready).
	m.Migrators[TierRWX] = NewRWXReattachMigrator(c)
	m.Migrators[TierLonghorn] = &LonghornStubMigrator{}
	m.Migrators[TierCephRBD] = &CephRBDStubMigrator{}
	m.Migrators[TierSnapshotRsync] = &SnapshotRsyncStubMigrator{}
	return m
}

// NewStorageMigrationManagerWithProduction returns a manager wired with real migrators
// for all tiers. cephDestPool is the Ceph pool for RBD live migration destination images.
// longhornManagerURL is the base URL of the Longhorn Manager HTTP API; if empty, the
// explicit Longhorn stub registered by NewStorageMigrationManager is retained (a real
// Longhorn tier volume then blocks on the stub's ready path rather than falling through
// to the missing-migrator freeze block).
func NewStorageMigrationManagerWithProduction(c client.Client, cephDestPool, longhornManagerURL string) *StorageMigrationManager {
	m := NewStorageMigrationManager(c)
	if longhornManagerURL != "" {
		m.Migrators[TierLonghorn] = NewLonghornMigrator(longhornManagerURL, c)
	}
	m.Migrators[TierCephRBD] = NewCephRBDMigrator(cephDestPool)
	m.Migrators[TierSnapshotRsync] = NewSnapshotRsyncMigrator(c)
	return m
}

// RegisterMigrator adds or replaces the migrator for a given tier.
func (m *StorageMigrationManager) RegisterMigrator(tier StorageTier, mg Migrator) {
	m.Migrators[tier] = mg
}

// RunPreStage classifies the pod's PVCs, selects the appropriate Migrator, runs
// PreStage, and patches StorageReadyForFreeze=True on the PodMigration CR when
// the sync threshold is reached.
//
// Intended to run in a goroutine — patches the CR directly via the k8s client.
// The PodMigration controller re-evaluates the condition on the next reconcile.
//
// coldRecreateArmed (ADR-0396) is the operator-computed, in-process arming boolean threaded to
// ClassifyPod (via classifyFromLiveSourcePod). It is never re-derived here and never read from
// status — the operator computes it before dispatch and passes it as this argument.
//
// claimToken (ADR-0398 D1) is the fencing token of the single-dispatch claim under which this
// RunPreStage was launched. It is threaded into every terminal StorageReadyForFreeze write so that a
// SUPERSEDED holder (whose claim a later reconcile re-claimed with a fresh token after a lease expiry)
// cannot write a terminal verdict. This is defense-in-depth: the operator already guarantees
// exactly-once launch by gating the goroutine on a fenced Complete-mark, so under normal operation the
// token always still matches. An empty claimToken disables fencing (used by unit tests that call
// RunPreStage directly, outside the operator's claim machinery).
func (m *StorageMigrationManager) RunPreStage(ctx context.Context, pm *pmv1.PodMigration, coldRecreateArmed bool, claimToken string) error {
	log := logf.FromContext(ctx).WithValues("migration", pm.Name)

	highest, classifications, migrator, opts, err := m.classifyFromLiveSourcePod(ctx, pm, coldRecreateArmed)
	if err != nil {
		return m.patchStorageReady(ctx, pm, claimToken, metav1.ConditionFalse, "ClassifyFailed", err.Error())
	}

	// Persist the highest tier and the full per-PVC classification to status.
	// ClassifiedVolumes is what Cutover/AwaitSingleOwner read later — RunPreStage runs during
	// PreMigrating, while the source pod is still guaranteed to exist, so this is the last
	// point in the phase graph where a live re-classification is possible for every tier
	// (Tier1-Longhorn's ADR-0356 early source-pod release means the pod may already be gone
	// by the time Cutover runs — see ClassifiedVolumes' doc comment in podmigration_types.go).
	tier := int32(highest.Tier)
	if err := m.patchStorageTier(ctx, pm, tier); err != nil {
		log.Error(err, "failed to patch storageTier — continuing")
	}
	if err := m.patchClassifiedVolumes(ctx, pm, classifications); err != nil {
		log.Error(err, "failed to patch classifiedVolumes — continuing")
	}

	if highest.Tier == TierBlocked {
		return m.patchStorageReady(ctx, pm, claimToken, metav1.ConditionFalse, "BlockedVolume",
			fmt.Sprintf("pod has un-migratable volume: %s", highest.Reason))
	}

	if migrator == nil {
		// No migrator registered for the selected tier.
		//
		// The immediate-ready path is valid ONLY for TierRWX, where no data
		// movement is required (the volume is simply re-attached on the
		// destination). For any tier > TierRWX a missing migrator means the
		// destination replica/image does NOT exist yet, so declaring the freeze
		// ready would let the pod freeze and restore before its storage is
		// staged — silent data loss (H-14/C-08). Patch StorageReadyForFreeze=False
		// with a recoverable, human-actionable reason so the freeze does not
		// proceed and an operator can register the missing tier migrator.
		if highest.Tier > TierRWX {
			log.Info("no migrator registered for tier > TierRWX — blocking freeze",
				"tier", highest.Tier)
			return m.patchStorageReady(ctx, pm, claimToken, metav1.ConditionFalse, "NoMigratorForTier",
				fmt.Sprintf("tier%d: no storage migrator registered — cannot stage "+
					"destination storage; register a migrator for this tier before "+
					"migrating (%s)", highest.Tier, highest.Reason))
		}
		log.Info("no migrator registered for TierRWX — emitting StorageReadyForFreeze immediately",
			"tier", highest.Tier)
		return m.patchStorageReady(ctx, pm, claimToken, metav1.ConditionTrue, "NoOpTier",
			fmt.Sprintf("tier%d: re-attach only — no data movement required", highest.Tier))
	}

	log.Info("starting storage pre-stage", "tier", highest.Tier, "reason", highest.Reason)
	var preStageErr error
retryLoop:
	for attempt := 1; attempt <= preStageMaxAttempts; attempt++ {
		preStageErr = migrator.PreStage(ctx, opts)
		if preStageErr == nil {
			break
		}
		if attempt == preStageMaxAttempts || !isTransientPreStageError(preStageErr) {
			break
		}
		log.Info("pre-stage failed with a transient error — retrying",
			"tier", highest.Tier, "attempt", attempt, "maxAttempts", preStageMaxAttempts, "err", preStageErr)
		select {
		case <-ctx.Done():
			preStageErr = ctx.Err()
			break retryLoop
		case <-time.After(preStageRetryBackoff):
		}
	}
	if preStageErr != nil {
		// ADR-0365 Decision §2.2/§2 item 3: distinguish the two fail-closed hardenings' errors
		// from a generic PreStageFailed so Status.Conditions names WHY, not just that pre-stage
		// failed — PreStageTimeout for the new bounded-dispatch-context expiring (§2.2), and
		// EmptyDestinationNode for the migrator-level empty-DestinationNode guard (§2 item 3)
		// firing, both distinct from an ordinary tier-migrator error.
		reason := "PreStageFailed"
		switch {
		case errors.Is(preStageErr, context.DeadlineExceeded):
			reason = "PreStageTimeout"
		case errors.Is(preStageErr, errEmptyDestinationNode):
			reason = "EmptyDestinationNode"
		}
		return m.patchStorageReady(ctx, pm, claimToken, metav1.ConditionFalse, reason,
			fmt.Sprintf("tier%d pre-stage: %v", highest.Tier, preStageErr))
	}

	// PreStage succeeded — for Tier0 (RWX) this is sufficient.
	// For tiers with a sync phase, PreStage blocks until ≥95% is reached internally.
	return m.patchStorageReady(ctx, pm, claimToken, metav1.ConditionTrue, "StorageReady",
		fmt.Sprintf("tier%d pre-stage complete: %s", highest.Tier, highest.Reason))
}

// classifyFromLiveSourcePod fetches the live source pod, classifies its PVCs, selects the
// highest-tier classification, resolves the Migrator registered for it, and assembles the
// MigrationOptions the migrator's methods need.
//
// This performs a live GET of the source pod and MUST ONLY be called from RunPreStage, which
// runs during PreMigrating — before ADR-0356's Tier1-Longhorn early source-pod release can
// possibly have fired (that release requires CheckpointTransferred=True, several phases later).
// Cutover and AwaitSingleOwner run much later (reconcileOverlayHandoff) and must NOT call this:
// they use buildMigrationOptionsFromCache instead, which reads the classification RunPreStage
// persisted to pm.Status.ClassifiedVolumes, since a live re-fetch of the source pod 404s once
// ADR-0356 has released it (sprint49 live-proof finding).
//
// migrator is nil when no Migrator is registered for the selected tier — RunPreStage has a
// TierRWX-only no-op fallback for that case.
func (m *StorageMigrationManager) classifyFromLiveSourcePod(ctx context.Context, pm *pmv1.PodMigration, coldRecreateArmed bool) (TierClassification, []TierClassification, Migrator, MigrationOptions, error) {
	sourcePod, err := m.getSourcePod(ctx, pm)
	if err != nil {
		return TierClassification{}, nil, nil, MigrationOptions{}, fmt.Errorf("get source pod: %w", err)
	}

	classifications, err := m.Classifier.ClassifyPod(ctx, sourcePod, coldRecreateArmed)
	if err != nil {
		return TierClassification{}, nil, nil, MigrationOptions{}, fmt.Errorf("classify pod pvcs: %w", err)
	}

	highest := HighestTier(classifications)
	opts := MigrationOptions{
		MigrationName:   pm.Name,
		PodNamespace:    pm.Spec.PodNamespace,
		SourceNode:      pm.Status.SourceNodeName,
		DestinationNode: pm.Status.DestinationNodeName,
		Classifications: classifications,
	}

	return highest, classifications, m.Migrators[highest.Tier], opts, nil
}

// buildMigrationOptionsFromCache assembles MigrationOptions from the per-PVC classification
// RunPreStage persisted to pm.Status.ClassifiedVolumes, WITHOUT re-fetching the live source
// pod. This is the classify path Cutover and AwaitSingleOwner must use: by the time they run
// (reconcileOverlayHandoff, well after CheckpointTransferred=True), ADR-0356's Tier1-Longhorn
// early source-pod release may have already deleted the source pod, so a live re-fetch/
// re-classify 404s every time (sprint49 live-proof finding — migration permanently stuck in
// OverlayHandoff, reason CutoverFailed / "get source pod: ... not found"). The PVC objects are
// never deleted by ADR-0356 (only the pod is), so the classification computed once while the
// pod still existed remains valid for the rest of the migration.
//
// Re-fetches pm fresh so it observes RunPreStage's patch even if the caller's in-memory copy
// predates it. Returns an error satisfying errors.Is(err, errNoCachedClassification) if no
// classification has been cached yet (RunPreStage has not completed) — this is a recoverable,
// retryable condition, not a permanent failure.
func (m *StorageMigrationManager) buildMigrationOptionsFromCache(ctx context.Context, pm *pmv1.PodMigration) (TierClassification, Migrator, MigrationOptions, error) {
	fresh := &pmv1.PodMigration{}
	if err := m.Client.Get(ctx, client.ObjectKeyFromObject(pm), fresh); err != nil {
		return TierClassification{}, nil, MigrationOptions{}, fmt.Errorf("re-fetch PodMigration for cached classification: %w", err)
	}
	if fresh.Status.StorageTier == nil {
		return TierClassification{}, nil, MigrationOptions{}, errNoCachedClassification
	}

	classifications := make([]TierClassification, 0, len(fresh.Status.ClassifiedVolumes))
	for _, c := range fresh.Status.ClassifiedVolumes {
		classifications = append(classifications, TierClassification{
			Tier:         StorageTier(c.Tier),
			Reason:       c.Reason,
			PVCName:      c.PVCName,
			StorageClass: c.StorageClass,
		})
	}

	highest := HighestTier(classifications)
	opts := MigrationOptions{
		MigrationName:   pm.Name,
		PodNamespace:    pm.Spec.PodNamespace,
		SourceNode:      pm.Status.SourceNodeName,
		DestinationNode: pm.Status.DestinationNodeName,
		Classifications: classifications,
		CutoverComplete: cutoverSideEffectOccurred(fresh.Status.Conditions),
	}

	return highest, m.Migrators[highest.Tier], opts, nil
}

// errNoCachedClassification is returned by buildMigrationOptionsFromCache when
// pm.Status.StorageTier is nil — RunPreStage has not completed yet (or never ran, e.g. a
// migration that failed before/during PreMigrating). Cutover/AwaitSingleOwner treat this as a
// real, retryable failure (they should not be called before classification exists). Rollback's
// ReleaseDestination treats it differently (see StorageMigrationManager.ReleaseDestination):
// no classification means storage was never staged for this migration, so — exactly like Tier0's
// "no reservation ever created" case — there is structurally nothing destination-side to release.
var errNoCachedClassification = errors.New(
	"no cached PVC classification yet (RunPreStage has not completed) — cannot cutover before storage pre-stage classifies volumes")

// cutoverSideEffectOccurred reports whether Cutover's tier-specific destination-side action
// (Longhorn attach, Ceph `rbd migration commit`, …) is known to have actually executed for this
// PodMigration, read from the SAME ConditionStorageCutoverComplete condition/pattern already used
// elsewhere in this controller (podmigration_controller.go:1050's
// meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionStorageCutoverComplete) check) —
// ADR-0368 CONDITION 2: ground this in the codebase's existing condition-reading pattern, never
// infer it from tier identity alone.
//
// True in two cases:
//   - the condition is already True: AwaitSingleOwner (manager.go's AwaitSingleOwner method,
//     patchStorageCutover) confirmed the whole storage-cutover step, including the tier's
//     Cutover call, completed successfully.
//   - the condition is False with reason "AwaitSingleOwnerTimeout": this reason is set ONLY
//     after migrator.Cutover(ctx, opts) already returned nil (manager.go's AwaitSingleOwner
//     calls migrator.AwaitSingleOwner only once Cutover succeeded — see the Cutover/
//     AwaitSingleOwner call sequence in reconcileOverlayHandoff) — the destination-side action
//     itself already executed; only the post-Cutover collapse poll timed out. Treating this as
//     "cutover happened" is the deliberately conservative direction: the alternative (treating
//     it as "cutover did not happen") risks silently returning nil from ReleaseDestination for a
//     tier whose irrevocable destination-side action already ran — the exact fabricated-success
//     failure mode this whole ADR exists to close.
//
// Any other case (condition absent — the common case for a rollback that fired before
// PreMigrating's Cutover phase ever ran, e.g. a Checkpointing/Transferring-phase failure; or
// reason "CutoverFailed"/"ClassifyFailed"/etc — migrator.Cutover itself never returned nil)
// reports false: Cutover's destination-side action never executed.
func cutoverSideEffectOccurred(conditions []metav1.Condition) bool {
	cond := meta.FindStatusCondition(conditions, pmv1.ConditionStorageCutoverComplete)
	if cond == nil {
		return false
	}
	if cond.Status == metav1.ConditionTrue {
		return true
	}
	return cond.Reason == "AwaitSingleOwnerTimeout"
}

// Cutover looks up the classified tier's migrator and delegates to its
// Cutover method (detach from source, attach to destination), patching
// ConditionStorageCutoverComplete=False with a recoverable reason on
// failure. Called by the controller from reconcileOverlayHandoff
// (gateStorageCutoverBeforeRestore), after scheduling-gate removal but
// strictly before the phase transition into RestoreSocketReattach —
// immediately before AwaitSingleOwner, never after restore, since restore
// racing ahead of a ready destination storage engine is the failure this
// gate exists to prevent.
func (m *StorageMigrationManager) Cutover(ctx context.Context, pm *pmv1.PodMigration) error {
	highest, migrator, opts, err := m.buildMigrationOptionsFromCache(ctx, pm)
	if err != nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "CutoverFailed",
			fmt.Sprintf("classify pod pvcs for cutover: %v", err))
	}
	if highest.Tier == TierBlocked {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "CutoverFailed",
			fmt.Sprintf("pod has un-migratable volume: %s", highest.Reason))
	}
	if migrator == nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "CutoverFailed",
			fmt.Sprintf("tier%d: no storage migrator registered for cutover", highest.Tier))
	}
	if err := migrator.Cutover(ctx, opts); err != nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "CutoverFailed",
			fmt.Sprintf("tier%d cutover: %v", highest.Tier, err))
	}
	return nil
}

// AwaitSingleOwner looks up the classified tier's migrator and delegates to
// its AwaitSingleOwner method, blocking until the migrated volume(s) are in
// a single-owner, mountable state on the destination node. Patches
// ConditionStorageCutoverComplete=False with reason AwaitSingleOwnerTimeout
// on failure (a timeout is a real, recoverable error — not silently retried
// forever). The controller calls this after Cutover succeeds, from
// reconcileOverlayHandoff's gateStorageCutoverBeforeRestore, and before
// permitting the phase transition that makes CRIU restore eligible to run
// (RestoreSocketReattach — see nri/plugin.go verifyPhaseInAcceptSet).
func (m *StorageMigrationManager) AwaitSingleOwner(ctx context.Context, pm *pmv1.PodMigration) error {
	highest, migrator, opts, err := m.buildMigrationOptionsFromCache(ctx, pm)
	if err != nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "AwaitSingleOwnerTimeout",
			fmt.Sprintf("classify pod pvcs for await-single-owner: %v", err))
	}
	if highest.Tier == TierBlocked {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "AwaitSingleOwnerTimeout",
			fmt.Sprintf("pod has un-migratable volume: %s", highest.Reason))
	}
	if migrator == nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "AwaitSingleOwnerTimeout",
			fmt.Sprintf("tier%d: no storage migrator registered for await-single-owner", highest.Tier))
	}
	if err := migrator.AwaitSingleOwner(ctx, opts); err != nil {
		return m.patchStorageCutover(ctx, pm, metav1.ConditionFalse, "AwaitSingleOwnerTimeout",
			fmt.Sprintf("tier%d await-single-owner: %v", highest.Tier, err))
	}
	return m.patchStorageCutover(ctx, pm, metav1.ConditionTrue, "CutoverComplete",
		fmt.Sprintf("tier%d: volume collapsed to single-owner mountable state", highest.Tier))
}

// ReleaseDestination looks up the classified tier's migrator and delegates to its
// ReleaseDestination method, undoing whatever destination-side reservation Cutover created.
// Called by rollback.RealStorageRollback (internal/rollback/rollback.go's StorageStep) from
// reconcileRollingBack, after ComputeRollback but governed by the same Network→Compute→Storage
// order as the forward pipeline (ADR-0014). Mirrors Cutover/AwaitSingleOwner's classify+dispatch
// shape exactly (buildMigrationOptionsFromCache, same Migrators map) so ReleaseDestination is
// dispatched through the SAME migrator instances Cutover/AwaitSingleOwner already used for this
// migration (ADR-0368 §5.3/CONDITION 5) — never a second, independently constructed manager.
//
// Unlike Cutover/AwaitSingleOwner, a missing cached classification (errNoCachedClassification)
// is NOT treated as an error here: it means RunPreStage never ran (or never completed) for this
// migration — e.g. the migration failed and rolled back before/during PreMigrating — so, exactly
// like Tier0's "no reservation ever created" case, there is structurally nothing destination-side
// to release. Returning the real error in that case would fail every very-early rollback loudly
// for no reason; returning nil here is honest, not a fabricated success, because no tier's
// Cutover could possibly have run yet. TierBlocked is treated the same way: a blocked
// classification always halts RunPreStage before Cutover can ever be reached, so nothing was
// ever staged for that PVC either.
//
// A registered-but-nil migrator, in contrast, stays a real error: it is a configuration gap
// this code cannot reason past, and per the fail-loud contract, an ambiguous case must never be
// treated as "clearly nothing to release."
func (m *StorageMigrationManager) ReleaseDestination(ctx context.Context, pm *pmv1.PodMigration) error {
	highest, migrator, opts, err := m.buildMigrationOptionsFromCache(ctx, pm)
	if err != nil {
		if errors.Is(err, errNoCachedClassification) {
			return nil
		}
		return fmt.Errorf("release destination: classify pod pvcs: %w", err)
	}
	if highest.Tier == TierBlocked {
		return nil
	}
	if migrator == nil {
		return fmt.Errorf("release destination: tier%d: no storage migrator registered", highest.Tier)
	}
	if err := migrator.ReleaseDestination(ctx, opts); err != nil {
		return fmt.Errorf("tier%d release destination: %w", highest.Tier, err)
	}
	return nil
}

// patchStorageCutover updates the StorageCutoverComplete condition on the
// PodMigration CR. Retries on optimistic-lock conflict, mirroring
// patchStorageReady.
func (m *StorageMigrationManager) patchStorageCutover(
	ctx context.Context,
	pm *pmv1.PodMigration,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	key := client.ObjectKeyFromObject(pm)
	patchErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := m.Client.Get(ctx, key, fresh); err != nil {
			return fmt.Errorf("get PodMigration for storage cutover patch: %w", err)
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               pmv1.ConditionStorageCutoverComplete,
			Status:             status,
			Reason:             reason,
			Message:            message,
			LastTransitionTime: metav1.Now(),
		})
		return m.Client.Status().Update(ctx, fresh)
	})
	if patchErr != nil {
		return patchErr
	}
	if status != metav1.ConditionTrue {
		return fmt.Errorf("%s: %s", reason, message)
	}
	return nil
}

// patchStorageReady updates the StorageReadyForFreeze condition on the PodMigration CR.
// Retries on optimistic-lock conflict (resource version mismatch) using retry.RetryOnConflict.
//
// ADR-0398 D1 fencing: claimToken is the single-dispatch claim token this RunPreStage was launched
// under. If it is non-empty and the live StoragePreStageDispatch marker records a DIFFERENT token, this
// RunPreStage is a superseded holder (its claim was re-claimed by a later reconcile after a lease
// expiry) and MUST NOT write a terminal verdict — the write is skipped. This is defense-in-depth atop
// the operator's exactly-once launch gate (the fenced Complete-mark), so under normal operation the
// token always matches. An empty claimToken disables fencing (direct unit-test callers).
func (m *StorageMigrationManager) patchStorageReady(
	ctx context.Context,
	pm *pmv1.PodMigration,
	claimToken string,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	key := client.ObjectKeyFromObject(pm)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := m.Client.Get(ctx, key, fresh); err != nil {
			return fmt.Errorf("get PodMigration for storage patch: %w", err)
		}
		if claimToken != "" {
			if d := fresh.Status.StoragePreStageDispatch; d != nil && d.ClaimToken != claimToken {
				logf.FromContext(ctx).Info("ADR-0398: storage pre-stage claim superseded — skipping terminal StorageReadyForFreeze write from a stale dispatch",
					"migration", pm.Name, "reason", reason)
				return nil
			}
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               conditionStorageReadyForFreeze,
			Status:             status,
			Reason:             reason,
			Message:            message,
			LastTransitionTime: metav1.Now(),
		})
		return m.Client.Status().Update(ctx, fresh)
	})
}

// patchStorageTier writes pm.Status.StorageTier via a fresh fetch.
// Retries on optimistic-lock conflict (resource version mismatch).
func (m *StorageMigrationManager) patchStorageTier(ctx context.Context, pm *pmv1.PodMigration, tier int32) error {
	key := client.ObjectKeyFromObject(pm)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := m.Client.Get(ctx, key, fresh); err != nil {
			return err
		}
		fresh.Status.StorageTier = &tier
		return m.Client.Status().Update(ctx, fresh)
	})
}

// patchClassifiedVolumes writes pm.Status.ClassifiedVolumes via a fresh fetch, converting from
// the internal TierClassification slice to the CRD-status PVCTierClassification mirror. This is
// the cache Cutover/AwaitSingleOwner read from later (buildMigrationOptionsFromCache) instead of
// re-fetching and re-classifying the live source pod, which may already be deleted by the time
// they run (ADR-0356 Tier1-Longhorn early source-pod release). Retries on optimistic-lock
// conflict, mirroring patchStorageTier.
func (m *StorageMigrationManager) patchClassifiedVolumes(ctx context.Context, pm *pmv1.PodMigration, classifications []TierClassification) error {
	cached := make([]pmv1.PVCTierClassification, 0, len(classifications))
	for _, c := range classifications {
		cached = append(cached, pmv1.PVCTierClassification{
			Tier:         int32(c.Tier),
			Reason:       c.Reason,
			PVCName:      c.PVCName,
			StorageClass: c.StorageClass,
		})
	}
	key := client.ObjectKeyFromObject(pm)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := m.Client.Get(ctx, key, fresh); err != nil {
			return err
		}
		fresh.Status.ClassifiedVolumes = cached
		return m.Client.Status().Update(ctx, fresh)
	})
}

func (m *StorageMigrationManager) getSourcePod(ctx context.Context, pm *pmv1.PodMigration) (*corev1.Pod, error) {
	p := &corev1.Pod{}
	err := m.Client.Get(ctx, client.ObjectKey{
		Namespace: pm.Spec.PodNamespace,
		Name:      pm.Spec.PodName,
	}, p)
	return p, err
}
