/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0407_release_conflict_retry_test.go — ADR-0407 regression coverage extended to the SIBLING release
// path (releaseStoragePreStageClaim).
//
// The defect being closed: releaseStoragePreStageClaim cleared the InFlight marker with a single
// Get+Patch and NO conflict retry, while its sibling completeStoragePreStageDispatch was storm-hardened
// (adr0407_finalize_conflict_retry_test.go). During the creation-instant status-write storm (unrelated
// concurrent writers — the pre-copy goroutine's MemorySynced write, condition updates), a transient-arm
// release would 409 on the first attempt and give up, leaving the marker InFlight. Because the liveness
// lease is budget-scaled (~300s), NO reconcile may re-claim until the lease expires — the migration wedges
// in PreCopyMemory for minutes (StorageReadyForFreeze never set) even though memory pre-copy has already
// converged. This is the mirror image of the idle-pod finalize livelock, on the path ADR-0407 never
// hardened. Observed live as the "PreCopyMemory STALL, storagePreStageDispatch InFlight never advances"
// failure.
//
// Proves, against the real releaseStoragePreStageClaim (no mock of the code under test):
//   - a transient (one-shot) 409 on the release Patch is retried in place — the holder re-Gets,
//     re-verifies the token, re-Patches, and clears the marker to nil EXACTLY as intended (defect closed);
//   - a PERSISTENT conflict exhausts the storm-sized backoff and leaves the marker InFlight (the liveness
//     lease is the slower backstop) — strictly no worse than the pre-fix single-shot behavior;
//   - a GENUINE supersession (the live object carries a DIFFERENT token) is left untouched and no Patch is
//     issued — a re-claim by a later reconcile is never clobbered by a stale holder's release.

import (
	"context"
	"fmt"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestADR0407_ReleaseRetriesTransientConflict — a single transient 409 on the release Patch must be
// retried in place (re-Get, re-verify token, re-Patch) and clear the marker to nil. Pre-fix this abandoned
// the clear on the first 409, leaving the marker InFlight so no reconcile could re-claim until the ~300s
// liveness lease expired — the PreCopyMemory stall.
func TestADR0407_ReleaseRetriesTransientConflict(t *testing.T) {
	pm := adr0407InFlightPM("pm-release-transient-409", "token-A")
	base := fake.NewClientBuilder().WithScheme(adr0356Scheme(t)).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()

	patchAttempts := 0
	c := interceptor.NewClient(base, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, cl client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			patchAttempts++
			if patchAttempts == 1 {
				// One-shot benign 409 from an unrelated concurrent status writer (e.g. MemorySynced).
				return apierrors.NewConflict(adr0407PMGR, obj.GetName(), fmt.Errorf("simulated creation-instant reconcile-storm conflict"))
			}
			return cl.Status().Patch(ctx, obj, patch, opts...)
		},
	})
	r := &PodMigrationReconciler{Client: c, Scheme: adr0356Scheme(t)}

	r.releaseStoragePreStageClaim(context.Background(), pm, "token-A")

	if patchAttempts < 2 {
		t.Fatalf("expected the release to be re-attempted after the 409 (>=2 Patch attempts), got %d", patchAttempts)
	}
	if m := adr0398GetMarker(t, c, pm); m != nil {
		t.Fatalf("DEFECT NOT CLOSED: a transient release 409 left the marker InFlight instead of clearing it — the PreCopyMemory wedge; got: %+v", m)
	}
	if pm.Status.StoragePreStageDispatch != nil {
		t.Fatalf("the in-memory pm marker must also be cleared on a successful release, got: %+v", pm.Status.StoragePreStageDispatch)
	}
}

// TestADR0407_ReleasePersistentConflictLeavesInFlight — if a conflict storm outlasts the storm-sized
// backoff, the release leaves the marker InFlight (bounded attempts) and the liveness lease is the slower
// backstop. Strictly no worse than the pre-fix single-shot give-up.
func TestADR0407_ReleasePersistentConflictLeavesInFlight(t *testing.T) {
	pm := adr0407InFlightPM("pm-release-persistent-409", "token-A")
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

	r.releaseStoragePreStageClaim(context.Background(), pm, "token-A")

	// Storm-sized backoff is 8 steps: bounded, not an unbounded spin.
	if patchAttempts == 0 || patchAttempts > 12 {
		t.Fatalf("expected a small, bounded number of release Patch attempts, got %d", patchAttempts)
	}
	if m := adr0398GetMarker(t, c, pm); m == nil || m.Phase != pmv1.StoragePreStageInFlight || m.ClaimToken != "token-A" {
		t.Fatalf("marker must be left InFlight (lease is the backstop) after an exhausted release, got: %+v", m)
	}
}

// TestADR0407_ReleaseStopsOnTokenSupersession — a GENUINE supersession (the live object carries a
// DIFFERENT valid token) must issue NO release Patch and leave the live claim untouched, so a later
// reconcile's re-claim is never clobbered by a stale holder.
func TestADR0407_ReleaseStopsOnTokenSupersession(t *testing.T) {
	// Server marker is owned by token-B; the stale holder calls in with token-A.
	pm := adr0407InFlightPM("pm-release-superseded", "token-B")
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

	r.releaseStoragePreStageClaim(context.Background(), pm, "token-A")

	if patchAttempts != 0 {
		t.Fatalf("a superseded holder (stale token-A) must issue NO release Patch, got %d", patchAttempts)
	}
	if m := adr0398GetMarker(t, c, pm); m == nil || m.ClaimToken != "token-B" || m.Phase != pmv1.StoragePreStageInFlight {
		t.Fatalf("the live claim (token-B) must be untouched by the superseded holder: %+v", m)
	}
}
