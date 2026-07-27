/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0398_single_dispatch_test.go — ADR-0398 regression coverage: the durable, fenced
// single-dispatch marker (StoragePreStageDispatch), the transient-vs-terminal arming taxonomy, the
// verdict-gated ADR-0380 fail-fast, and the marker's immunity to whole-status blob overwrites.
//
// Proves, against the real reconcile helpers (no mocks of the code under test):
//   - D1: the Complete-mark and claim-release are fenced by ClaimToken — a superseded holder (whose
//     claim a later reconcile re-claimed with a fresh token) cannot finalize or release.
//   - D1: dispatchStoragePreStageOnce is idempotent under a Complete marker and honors an in-flight
//     claim within its lease.
//   - D2: arming classifies a momentarily-unreadable source pod as transient (release + requeue,
//     no disarmed dispatch, no BlockedVolume) and an owned pod as a no-op.
//   - D3: the ADR-0380 fail-fast fires ONLY on Complete && !ColdRecreateArmed; it requeues (never
//     fails) on a nil marker, an in-flight marker, and a Complete && armed marker.
//   - The marker survives statusUpdate/transitionTo whole-status blob overwrites (never regressed
//     to nil by a stale in-memory Status).

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

func adr0398Client(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := adr0356Scheme(t)
	return fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(objs...).Build()
}

func adr0398GetMarker(t *testing.T, c client.Client, pm *pmv1.PodMigration) *pmv1.StoragePreStageDispatch {
	t.Helper()
	fresh := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pm), fresh); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	return fresh.Status.StoragePreStageDispatch
}

// --- D1: fenced Complete-mark -------------------------------------------------------------------

func TestADR0398_CompleteDispatch_FencedByToken(t *testing.T) {
	pm := tier1PM("pm-complete", int32(storage.TierLonghorn), true)
	pm.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
		Phase:      pmv1.StoragePreStageInFlight,
		ClaimToken: "token-A",
		ClaimedAt:  metav1.Now(),
	}
	c := adr0398Client(t, pm)
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t)}

	// Matching token finalizes with the recorded verdict.
	completed, err := r.completeStoragePreStageDispatch(context.Background(), pm, "token-A", true, true)
	if err != nil || !completed {
		t.Fatalf("expected Complete to succeed with matching token, got completed=%v err=%v", completed, err)
	}
	m := adr0398GetMarker(t, c, pm)
	if m == nil || m.Phase != pmv1.StoragePreStageComplete || !m.ColdRecreateArmed || !m.ArmAttempted {
		t.Fatalf("marker not finalized as Complete/armed: %+v", m)
	}

	// Now simulate a re-claim by a fresh holder (token-B), then a superseded holder's late Complete
	// with the stale token-A must be REFUSED.
	reclaim := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pm), reclaim); err != nil {
		t.Fatalf("get: %v", err)
	}
	reclaim.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
		Phase:      pmv1.StoragePreStageInFlight,
		ClaimToken: "token-B",
		ClaimedAt:  metav1.Now(),
	}
	if err := c.Status().Update(context.Background(), reclaim); err != nil {
		t.Fatalf("reclaim update: %v", err)
	}
	completed, err = r.completeStoragePreStageDispatch(context.Background(), pm, "token-A", true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if completed {
		t.Fatal("superseded holder (stale token-A) must NOT finalize the dispatch")
	}
	m = adr0398GetMarker(t, c, pm)
	if m == nil || m.ClaimToken != "token-B" || m.Phase != pmv1.StoragePreStageInFlight {
		t.Fatalf("re-claim marker must be untouched by the superseded holder: %+v", m)
	}
}

// --- D1: fenced release -------------------------------------------------------------------------

func TestADR0398_ReleaseClaim_FencedByToken(t *testing.T) {
	pm := tier1PM("pm-release", int32(storage.TierLonghorn), true)
	pm.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
		Phase:      pmv1.StoragePreStageInFlight,
		ClaimToken: "token-B",
		ClaimedAt:  metav1.Now(),
	}
	c := adr0398Client(t, pm)
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t)}

	// A stale token must NOT release a claim owned by a different token.
	r.releaseStoragePreStageClaim(context.Background(), pm, "token-A")
	if m := adr0398GetMarker(t, c, pm); m == nil || m.ClaimToken != "token-B" {
		t.Fatalf("stale-token release must be a no-op, got: %+v", m)
	}

	// The owning token releases (marker → nil), freeing a prompt re-claim.
	r.releaseStoragePreStageClaim(context.Background(), pm, "token-B")
	if m := adr0398GetMarker(t, c, pm); m != nil {
		t.Fatalf("owning-token release must clear the marker, got: %+v", m)
	}
}

// --- D1: dispatchStoragePreStageOnce decision branches ------------------------------------------

func TestADR0398_DispatchOnce_IdempotentUnderCompleteAndInFlight(t *testing.T) {
	// Complete marker ⇒ no dispatch, no requeue-for-dispatch (idempotent).
	pmDone := tier1PM("pm-done", int32(storage.TierLonghorn), true)
	pmDone.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
		Phase: pmv1.StoragePreStageComplete, ClaimToken: "t", ClaimedAt: metav1.Now(),
	}
	cDone := adr0398Client(t, pmDone)
	rDone := &PodMigrationReconciler{Client: cDone, Scheme: adr0356Scheme(t), StorageMgr: storage.NewStorageMigrationManager(cDone)}
	if requeue, err := rDone.dispatchStoragePreStageOnce(context.Background(), pmDone); err != nil || requeue {
		t.Fatalf("Complete marker: expected (false,nil), got (%v,%v)", requeue, err)
	}

	// InFlight within lease ⇒ requeue, do not re-dispatch, marker unchanged.
	pmFlight := tier1PM("pm-flight", int32(storage.TierLonghorn), true)
	pmFlight.Spec.CompletionTimeoutSeconds = 600
	pmFlight.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
		Phase: pmv1.StoragePreStageInFlight, ClaimToken: "held", ClaimedAt: metav1.Now(),
	}
	cFlight := adr0398Client(t, pmFlight)
	rFlight := &PodMigrationReconciler{Client: cFlight, Scheme: adr0356Scheme(t), StorageMgr: storage.NewStorageMigrationManager(cFlight)}
	if requeue, err := rFlight.dispatchStoragePreStageOnce(context.Background(), pmFlight); err != nil || !requeue {
		t.Fatalf("InFlight-in-lease: expected (true,nil), got (%v,%v)", requeue, err)
	}
	if m := adr0398GetMarker(t, cFlight, pmFlight); m == nil || m.ClaimToken != "held" {
		t.Fatalf("in-flight claim must be left untouched: %+v", m)
	}
}

// --- liveness lease: abandoned pre-launch InFlight claim frees on the short arming lease ---------

// TestADR0398_DispatchLease_DecoupledFromCompletionBudget pins that the InFlight abandonment lease is
// the fixed pre-launch arming lease, NOT the RunPreStage completion budget. A large budget must not
// stretch it: the lease guards only claim→arm→Complete, and RunPreStage (the budget-sized work) launches
// only after Complete permanently stops re-claims.
func TestADR0398_DispatchLease_DecoupledFromCompletionBudget(t *testing.T) {
	pm := tier1PM("pm-lease", int32(storage.TierLonghorn), true)
	pm.Spec.CompletionTimeoutSeconds = 3600 // budget/2 = 1800s
	if got := storagePreStageDispatchLease(pm); got != storagePreStageInFlightLease {
		t.Fatalf("lease must be the fixed in-flight lease %s regardless of a %ds budget, got %s",
			storagePreStageInFlightLease, pm.Spec.CompletionTimeoutSeconds, got)
	}
	if lease, budget := storagePreStageDispatchLease(pm), preStageDispatchTimeout(pm); lease >= budget {
		t.Fatalf("in-flight lease %s must be far shorter than the completion budget %s it used to be bound to",
			lease, budget)
	}
}

// TestADR0398_AbandonedInFlightClaim_ReclaimedAfterInFlightLease is the regression for the PreCopyMemory
// stall (known issue #2): a pre-launch InFlight claim whose holder abandoned it (never stamped Complete,
// never released) must free after the short arming lease, NOT after the ~completion-budget lease. With a
// 600s budget the OLD lease was 300s, so a 60s-old claim stayed wedged with StorageReadyForFreeze never
// set; the fixed in-flight lease (30s) frees it now.
func TestADR0398_AbandonedInFlightClaim_ReclaimedAfterInFlightLease(t *testing.T) {
	pm := tier1PM("pm-abandoned", int32(storage.TierLonghorn), true)
	pm.Spec.CompletionTimeoutSeconds = 600 // old budget-scaled lease would be 300s
	pm.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
		Phase:      pmv1.StoragePreStageInFlight,
		ClaimToken: "abandoned-holder",
		ClaimedAt:  metav1.NewTime(time.Now().Add(-60 * time.Second)),
	}
	c := adr0398Client(t, pm)
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t), StorageMgr: storage.NewStorageMigrationManager(c)}

	// No source pod exists, so the re-claim's arming classifies transient and releases the fresh claim.
	// The observable proof that a RE-CLAIM happened (rather than a wedged in-lease hold) is that the
	// abandoned "abandoned-holder" marker is gone — an in-lease hold would have left it untouched.
	requeue, err := r.dispatchStoragePreStageOnce(context.Background(), pm)
	if err != nil || !requeue {
		t.Fatalf("expected re-claim then transient-release requeue (true,nil), got (%v,%v)", requeue, err)
	}
	if m := adr0398GetMarker(t, c, pm); m != nil && m.ClaimToken == "abandoned-holder" {
		t.Fatalf("abandoned InFlight claim was NOT re-claimed — still wedged under the old holder: %+v", m)
	}
}

// --- D2: transient arming on a momentarily-unreadable source pod --------------------------------

func TestADR0398_DispatchOnce_TransientArming_ReleasesAndRequeues_NoBlockedVolume(t *testing.T) {
	// No source pod object exists ⇒ arming is transient ⇒ claim is released, requeue, NO dispatch,
	// NO BlockedVolume written.
	pm := tier1PM("pm-transient", int32(storage.TierLonghorn), true)
	c := adr0398Client(t, pm)
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t), StorageMgr: storage.NewStorageMigrationManager(c)}

	requeue, err := r.dispatchStoragePreStageOnce(context.Background(), pm)
	if err != nil || !requeue {
		t.Fatalf("transient arming: expected (true,nil), got (%v,%v)", requeue, err)
	}
	// Claim must be released (freed for a prompt re-arm), not left InFlight and not Complete.
	if m := adr0398GetMarker(t, c, pm); m != nil {
		t.Fatalf("transient arming must release the claim (marker nil), got: %+v", m)
	}
	// No terminal BlockedVolume may be written from a transient fact.
	fresh := &pmv1.PodMigration{}
	_ = c.Get(context.Background(), client.ObjectKeyFromObject(pm), fresh)
	if cond := meta.FindStatusCondition(fresh.Status.Conditions, conditionStorageReady); cond != nil {
		t.Fatalf("no StorageReadyForFreeze condition may be written on a transient arming failure, got: %+v", cond)
	}
}

func TestADR0398_Arm_OwnedPodIsNoOp(t *testing.T) {
	pm := tier1PM("pm-owned", int32(storage.TierLonghorn), true)
	owned := srcPodOnNode("node-src")
	tru := true
	owned.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: types.UID("rs-uid"), Controller: &tru,
	}}
	c := adr0398Client(t, pm, owned)
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t)}
	if got := r.armStoragePreStage(context.Background(), pm); got != armOutcomeNoOp {
		t.Fatalf("owned pod must arm as no-op, got %v", got)
	}
}

// --- D3: verdict-gated fail-fast ----------------------------------------------------------------

func adr0398BlockedPM(name string, marker *pmv1.StoragePreStageDispatch) *pmv1.PodMigration {
	pm := tier1PM(name, int32(storage.TierLonghorn), false)
	pm.Status.Phase = pmv1.MigrationPhasePreCopyMemory
	meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
		Type:    conditionStorageReady,
		Status:  metav1.ConditionFalse,
		Reason:  "BlockedVolume",
		Message: "pod has un-migratable volume: x",
	})
	pm.Status.StoragePreStageDispatch = marker
	return pm
}

func TestADR0398_D3_FailFastGatedOnRecordedVerdict(t *testing.T) {
	now := metav1.Now()
	cases := []struct {
		name       string
		marker     *pmv1.StoragePreStageDispatch
		wantFailed bool
	}{
		{"nil-marker-requeues", nil, false},
		{"in-flight-requeues", &pmv1.StoragePreStageDispatch{Phase: pmv1.StoragePreStageInFlight, ClaimToken: "t", ClaimedAt: now}, false},
		{"complete-armed-requeues", &pmv1.StoragePreStageDispatch{Phase: pmv1.StoragePreStageComplete, ClaimToken: "t", ClaimedAt: now, ArmAttempted: true, ColdRecreateArmed: true}, false},
		{"complete-unarmed-fails-fast", &pmv1.StoragePreStageDispatch{Phase: pmv1.StoragePreStageComplete, ClaimToken: "t", ClaimedAt: now, ArmAttempted: false, ColdRecreateArmed: false}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pm := adr0398BlockedPM("pm-"+tc.name, tc.marker)
			c := adr0398Client(t, pm)
			r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t)}
			res, err := r.reconcilePreCopyMemory(context.Background(), pm)
			if err != nil {
				t.Fatalf("reconcile err: %v", err)
			}
			fresh := &pmv1.PodMigration{}
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(pm), fresh); err != nil {
				t.Fatalf("get: %v", err)
			}
			failed := fresh.Status.Phase == pmv1.MigrationPhaseFailed
			if failed != tc.wantFailed {
				t.Fatalf("want failed=%v, got phase=%q (result=%+v)", tc.wantFailed, fresh.Status.Phase, res)
			}
			if !tc.wantFailed && res.RequeueAfter <= 0 {
				t.Fatalf("non-terminal BlockedVolume must requeue, got result=%+v", res)
			}
		})
	}
}

// --- marker immunity to whole-status blob overwrites --------------------------------------------

func TestADR0398_MarkerSurvivesBlobOverwrite(t *testing.T) {
	// The server object carries a live marker; a stale in-memory Status (marker nil) must NOT wipe
	// it via statusUpdate or transitionTo.
	server := tier1PM("pm-preserve", int32(storage.TierLonghorn), true)
	server.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
		Phase: pmv1.StoragePreStageComplete, ClaimToken: "live", ClaimedAt: metav1.Now(), ColdRecreateArmed: true,
	}
	c := adr0398Client(t, server)
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t)}

	// statusUpdate with a stale copy whose marker is nil.
	stale := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(server), stale); err != nil {
		t.Fatalf("get: %v", err)
	}
	stale.Status.StoragePreStageDispatch = nil
	meta.SetStatusCondition(&stale.Status.Conditions, metav1.Condition{
		Type: conditionMemorySynced, Status: metav1.ConditionTrue, Reason: "X", Message: "y",
	})
	if err := r.statusUpdate(context.Background(), stale); err != nil {
		t.Fatalf("statusUpdate: %v", err)
	}
	if m := adr0398GetMarker(t, c, server); m == nil || m.ClaimToken != "live" {
		t.Fatalf("statusUpdate blob-overwrite wiped the marker: %+v", m)
	}

	// transitionTo with a stale copy whose marker is nil.
	stale2 := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(server), stale2); err != nil {
		t.Fatalf("get: %v", err)
	}
	stale2.Status.StoragePreStageDispatch = nil
	if _, err := r.transitionTo(context.Background(), stale2, pmv1.MigrationPhaseCheckpointing); err != nil {
		t.Fatalf("transitionTo: %v", err)
	}
	if m := adr0398GetMarker(t, c, server); m == nil || m.ClaimToken != "live" {
		t.Fatalf("transitionTo blob-overwrite wiped the marker: %+v", m)
	}
}
