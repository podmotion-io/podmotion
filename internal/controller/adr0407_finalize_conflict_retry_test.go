/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0407_finalize_conflict_retry_test.go — ADR-0407 regression coverage: a 409 on the token-fenced
// storage-pre-stage finalize Patch is a TRANSIENT optimistic-concurrency conflict from an unrelated
// concurrent status writer, not a claim supersession.
//
// The defect being closed (proved live on the deployed sprint54-adr0405 binary, mechanism map
// CHECKPOINT-HANG-IDLE-WORKLOAD-MECHANISM-MAP.md): completeStoragePreStageDispatch treated any 409 on the
// finalize Patch as supersession and returned completed=false, leaving the marker permanently InFlight so
// RunPreStage never launched — a deterministic idle-pod livelock. These tests prove the fix at the
// finalize-function boundary. They are NECESSARY BUT NOT SUFFICIENT (verification assertion 1): the load-bearing
// acceptance fact is the live idle-pod reconcile-storm completion proof (verification assertion 2), which is OWED.
//
// Proves, against the real completeStoragePreStageDispatch (no mock of the code under test):
//   - a transient (one-shot) 409 on the finalize Patch is retried in place — the holder re-Gets,
//     re-verifies the token, re-Patches, and finalizes to Complete EXACTLY ONCE (defect closed);
//   - genuine supersession (a re-fetched object bearing a DIFFERENT token) still short-circuits with
//     completed=false and NO Patch — ADR-0398's exactly-once launch guarantee is preserved;
//   - a PERSISTENT conflict exhausts the storm-sized backoff and returns a CONFLICT error (marker left
//     InFlight) so the caller's ADR-0407 IsConflict branch soft-requeues rather than wedging;
//   - a genuine NON-conflict Patch error is surfaced as-is (NOT swallowed and NOT misread as a
//     supersession) — the reviewer error-conflation finding: the caller can distinguish it from an
//     exhausted conflict and keep surfacing real API faults on the datapath.

import (
	"context"
	"fmt"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

var adr0407PMGR = schema.GroupResource{Group: "podmotion.io", Resource: "podmigrations"}

// adr0407InFlightPM builds a Tier1 PM whose marker is already claimed InFlight by the given token —
// the exact state at the moment completeStoragePreStageDispatch is called to finalize.
func adr0407InFlightPM(name, token string) *pmv1.PodMigration {
	pm := tier1PM(name, int32(storage.TierLonghorn), true)
	pm.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
		Phase:      pmv1.StoragePreStageInFlight,
		ClaimToken: token,
		ClaimedAt:  metav1.Now(),
	}
	return pm
}

// TestADR0407_FinalizeRetriesTransientConflict — a single transient 409 on the finalize Patch must be
// retried in place (re-Get, re-verify token, re-Patch) and finalize to Complete exactly once. Pre-fix
// this returned completed=false and wedged the marker InFlight forever (the idle-pod livelock).
func TestADR0407_FinalizeRetriesTransientConflict(t *testing.T) {
	pm := adr0407InFlightPM("pm-transient-409", "token-A")
	base := fake.NewClientBuilder().WithScheme(adr0356Scheme(t)).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()

	patchAttempts := 0
	c := interceptor.NewClient(base, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, cl client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			patchAttempts++
			if patchAttempts == 1 {
				// One-shot benign 409 from an unrelated concurrent status writer.
				return apierrors.NewConflict(adr0407PMGR, obj.GetName(), fmt.Errorf("simulated creation-instant reconcile-storm conflict"))
			}
			return cl.Status().Patch(ctx, obj, patch, opts...)
		},
	})
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t)}

	completed, err := r.completeStoragePreStageDispatch(context.Background(), pm, "token-A", true, true)
	if err != nil {
		t.Fatalf("a transient 409 must be retried, not surfaced: err=%v", err)
	}
	if !completed {
		t.Fatal("DEFECT NOT CLOSED: a transient finalize 409 was misclassified as supersession (completed=false) — the idle-pod wedge")
	}
	if patchAttempts < 2 {
		t.Fatalf("expected the finalize to be re-attempted after the 409 (>=2 Patch attempts), got %d", patchAttempts)
	}
	m := adr0398GetMarker(t, c, pm)
	if m == nil || m.Phase != pmv1.StoragePreStageComplete || !m.ColdRecreateArmed || !m.ArmAttempted {
		t.Fatalf("marker must be finalized to Complete/armed after the retry, got: %+v", m)
	}
}

// TestADR0407_FinalizeStopsOnTokenSupersession — a GENUINE supersession (the live object carries a
// DIFFERENT valid token) must still short-circuit with completed=false and issue NO finalize Patch. The
// retry loop consults the authoritative token every pass, so exactly-once is preserved.
func TestADR0407_FinalizeStopsOnTokenSupersession(t *testing.T) {
	// Server marker is owned by token-B; the stale holder calls in with token-A.
	pm := adr0407InFlightPM("pm-superseded", "token-B")
	base := fake.NewClientBuilder().WithScheme(adr0356Scheme(t)).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()

	patchAttempts := 0
	c := interceptor.NewClient(base, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, cl client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			patchAttempts++
			return cl.Status().Patch(ctx, obj, patch, opts...)
		},
	})
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t)}

	completed, err := r.completeStoragePreStageDispatch(context.Background(), pm, "token-A", true, false)
	if err != nil {
		t.Fatalf("genuine supersession is not an error: err=%v", err)
	}
	if completed {
		t.Fatal("a superseded holder (stale token-A) must NOT finalize the dispatch — exactly-once violated")
	}
	if patchAttempts != 0 {
		t.Fatalf("a superseded holder must issue NO finalize Patch, got %d", patchAttempts)
	}
	if m := adr0398GetMarker(t, c, pm); m == nil || m.ClaimToken != "token-B" || m.Phase != pmv1.StoragePreStageInFlight {
		t.Fatalf("the live claim (token-B) must be untouched by the superseded holder: %+v", m)
	}
}

// TestADR0407_FinalizePersistentConflictReturnsConflictErr — if a conflict storm outlasts the storm-sized
// backoff, the finalize returns a CONFLICT error (bounded attempts, marker left InFlight). The caller's
// ADR-0407 IsConflict branch then soft-requeues; this is §RESIDUAL, strictly no worse than pre-fix.
func TestADR0407_FinalizePersistentConflictReturnsConflictErr(t *testing.T) {
	pm := adr0407InFlightPM("pm-persistent-409", "token-A")
	base := fake.NewClientBuilder().WithScheme(adr0356Scheme(t)).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()

	patchAttempts := 0
	c := interceptor.NewClient(base, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, cl client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			patchAttempts++
			return apierrors.NewConflict(adr0407PMGR, obj.GetName(), fmt.Errorf("sustained reconcile-storm conflict"))
		},
	})
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t)}

	completed, err := r.completeStoragePreStageDispatch(context.Background(), pm, "token-A", true, true)
	if err == nil {
		t.Fatal("a persistent conflict must surface an error after exhausting the backoff")
	}
	if !apierrors.IsConflict(err) {
		t.Fatalf("an exhausted-conflict error must remain a CONFLICT so the caller soft-requeues, got: %v", err)
	}
	if completed {
		t.Fatal("a conflict-exhausted finalize must not report completed=true")
	}
	// Storm-sized backoff is 8 steps: bounded, not an unbounded spin.
	if patchAttempts == 0 || patchAttempts > 12 {
		t.Fatalf("expected a small, bounded number of finalize Patch attempts, got %d", patchAttempts)
	}
	if m := adr0398GetMarker(t, c, pm); m == nil || m.Phase != pmv1.StoragePreStageInFlight {
		t.Fatalf("marker must be left InFlight for a later reconcile to re-finalize, got: %+v", m)
	}
}

// TestADR0407_FinalizeSurfacesNonConflictError — the reviewer error-conflation finding: a genuine
// NON-conflict Patch error (API fault / CR mid-deletion) must be surfaced as-is, NOT swallowed and NOT
// misread as a supersession. This is what lets the caller branch on IsConflict and keep real datapath
// faults visible instead of downgrading them to an Info line.
func TestADR0407_FinalizeSurfacesNonConflictError(t *testing.T) {
	pm := adr0407InFlightPM("pm-api-fault", "token-A")
	base := fake.NewClientBuilder().WithScheme(adr0356Scheme(t)).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()

	c := interceptor.NewClient(base, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, cl client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			return apierrors.NewInternalError(fmt.Errorf("simulated apiserver fault"))
		},
	})
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t)}

	completed, err := r.completeStoragePreStageDispatch(context.Background(), pm, "token-A", true, true)
	if err == nil {
		t.Fatal("a genuine non-conflict Patch error must be surfaced, not swallowed")
	}
	if apierrors.IsConflict(err) {
		t.Fatalf("a non-conflict error must NOT be reported as a conflict (that would misroute the caller), got: %v", err)
	}
	if completed {
		t.Fatal("a non-conflict Patch error must not report completed=true")
	}
}
