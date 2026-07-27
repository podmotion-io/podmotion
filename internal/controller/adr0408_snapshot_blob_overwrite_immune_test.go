/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0408_snapshot_blob_overwrite_immune_test.go — ADR-0408 regression coverage: the ADR-0393
// SourcePodSpecSnapshot must be persisted/cleared via a field-scoped optimistic-lock patch and be
// immune to the whole-.status blob overwrite in statusUpdate, exactly as ADR-0398's dispatch marker
// already is.
//
// These unit tests are NECESSARY BUT NOT SUFFICIENT (ADR-0408 §6.1 / verification assertion 1): they prove field
// immunity in isolation; the load-bearing acceptance is the live idle-pod/bare-Longhorn
// PreCopyMemory-advances-to-Complete proof under a reproduced reconcile storm (verification assertion 2, OWED).
//
// Proves:
//   - a snapshot captured via patchSourcePodSpecSnapshot SURVIVES a subsequent concurrent blob
//     statusUpdate whose in-memory `want` predates the snapshot write (pre-fix: the blob overwrite
//     dropped it, and captureSourcePodSpecSnapshot's read-back saw nil → armOutcomeTransient livelock);
//   - completeColdRecreate DURABLY clears the snapshot even when a concurrent blob statusUpdate carries
//     a stale non-nil snapshot forward (D1 field-scoped clear + D2 server-authoritative preserve);
//   - preserveOperatorOwnedDurableStatus carries the StoragePreStageDispatch marker forward
//     byte-identically (no ADR-0398/0407 regression);
//   - patchSourcePodSpecSnapshot retries a transient 409 in place and still persists.

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

var adr0408PMGR = schema.GroupResource{Group: "podmotion.io", Resource: "podmigrations"}

func adr0408Key(t *testing.T) types.NamespacedName {
	t.Helper()
	return types.NamespacedName{Namespace: "default", Name: "pm-0408"}
}

// TestADR0408_SnapshotSurvivesConcurrentBlobOverwrite — the core fix. Capture a snapshot via the
// field-scoped patch, then interleave a concurrent blob statusUpdate whose `want` was DeepCopy'd BEFORE
// the snapshot write (the exact map §3.3 lost-update interleaving). Post-fix, D2's
// preserveOperatorOwnedDurableStatus carries the snapshot forward from the server, so it survives.
func TestADR0408_SnapshotSurvivesConcurrentBlobOverwrite(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-0408")
	pm.Namespace = "default"
	pod := srcPodOnNode("node-src")
	pod.UID = types.UID("src-uid-1") // must match adr0393BarePM's pm.Spec.SourcePodUID for read-back verify
	pod.Spec.Containers = []corev1.Container{{Name: "app", Image: "redis:7"}}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, testOnlySnapshotHMACKey: adr0393TestKey()}
	ctx := context.Background()

	// A concurrent reconcile's in-memory view, captured BEFORE the snapshot is written. Its Status has
	// no snapshot; when it later runs statusUpdate it must NOT regress the field written meanwhile.
	stale := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, adr0408Key(t), stale); err != nil {
		t.Fatalf("get stale view: %v", err)
	}
	if stale.Status.SourcePodSpecSnapshot != nil {
		t.Fatal("precondition: stale view should have no snapshot")
	}

	// Capture succeeds (field-scoped patch + read-back).
	if err := r.captureSourcePodSpecSnapshot(ctx, pm, pod); err != nil {
		t.Fatalf("capture failed post-fix (pre-fix this is the read-back-nil livelock): %v", err)
	}

	// The concurrent reconcile now issues its whole-.status blob write with the pre-snapshot `want`.
	stale.Status.ReplacementPodName = "concurrent-reconcile-unrelated-write" // some unrelated field the concurrent reconcile was updating
	if err := r.statusUpdate(ctx, stale); err != nil {
		t.Fatalf("concurrent blob statusUpdate failed: %v", err)
	}

	// The snapshot must still be on the server — carried forward by D2.
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, adr0408Key(t), fresh); err != nil {
		t.Fatalf("re-get: %v", err)
	}
	if fresh.Status.SourcePodSpecSnapshot == nil {
		t.Fatal("ADR-0408 REGRESSION: snapshot was dropped by the concurrent blob overwrite (the livelock)")
	}
	if ok, reason := r.verifySnapshotIntegrity(ctx, fresh); !ok {
		t.Fatalf("surviving snapshot failed verification: %s", reason)
	}
	// The unrelated concurrent field also landed — the blob write was not lost, only the snapshot preserved.
	if fresh.Status.ReplacementPodName != "concurrent-reconcile-unrelated-write" {
		t.Fatal("concurrent reconcile's own field update should have landed")
	}
}

// TestADR0408_CompleteColdRecreateDurablyClearsSnapshot — a consumed snapshot cleared by
// completeColdRecreate must STAY cleared even when a concurrent blob statusUpdate carries a stale
// non-nil snapshot. D1's field-scoped clear + D2's server-authoritative preserve must win.
func TestADR0408_CompleteColdRecreateDurablyClearsSnapshot(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-0408")
	pm.Namespace = "default"
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "redis:7"}}}
	snap := adr0393MakeSnapshot(t, adr0393TestKey(), pm, spec, "redis", "default")
	pm.Status.SourcePodSpecSnapshot = snap

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	// Seed the snapshot onto the server via the field-scoped patch (the real persist path).
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, testOnlySnapshotHMACKey: adr0393TestKey()}
	ctx := context.Background()
	if err := r.patchSourcePodSpecSnapshot(ctx, pm, snap); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	// A concurrent reconcile's stale view, captured while the snapshot is still present.
	stale := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, adr0408Key(t), stale); err != nil {
		t.Fatalf("get stale: %v", err)
	}
	if stale.Status.SourcePodSpecSnapshot == nil {
		t.Fatal("precondition: stale view should carry the (soon-consumed) snapshot")
	}

	// Consume it.
	if out := r.completeColdRecreate(ctx, pm); out != coldRecreateSucceeded {
		t.Fatalf("completeColdRecreate outcome = %v, want succeeded", out)
	}

	// The stale reconcile now writes its blob with the non-nil snapshot still in `want`.
	if err := r.statusUpdate(ctx, stale); err != nil {
		t.Fatalf("concurrent blob statusUpdate: %v", err)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, adr0408Key(t), fresh); err != nil {
		t.Fatalf("re-get: %v", err)
	}
	if fresh.Status.SourcePodSpecSnapshot != nil {
		t.Fatal("ADR-0408 REGRESSION: consumed snapshot was resurrected by a stale concurrent blob overwrite")
	}
}

// TestADR0408_MarkerImmunityUnchanged — preserveOperatorOwnedDurableStatus must carry the ADR-0398
// StoragePreStageDispatch marker forward byte-identically (the renamed helper's first line is unchanged).
func TestADR0408_MarkerImmunityUnchanged(t *testing.T) {
	server := &pmv1.PodMigration{}
	server.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
		Phase:      pmv1.StoragePreStageInFlight,
		ClaimToken: "tok-abc",
		ClaimedAt:  metav1.Now(),
	}
	// install (a stale blob about to be written) has NO marker — it must be repopulated from server.
	install := &pmv1.PodMigrationStatus{}

	preserveOperatorOwnedDurableStatus(server, install)

	if install.StoragePreStageDispatch == nil {
		t.Fatal("marker was not carried forward — ADR-0398/0407 regression")
	}
	if install.StoragePreStageDispatch.ClaimToken != "tok-abc" ||
		install.StoragePreStageDispatch.Phase != pmv1.StoragePreStageInFlight {
		t.Fatalf("marker not carried forward byte-identically: got %+v", install.StoragePreStageDispatch)
	}
}

// TestADR0408_PatchRetriesTransientConflict — a one-shot 409 on the snapshot Patch must be retried in
// place (re-Get, re-set, re-Patch) using the storm-sized backoff, and still persist.
func TestADR0408_PatchRetriesTransientConflict(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-0408")
	pm.Namespace = "default"
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "redis:7"}}}
	snap := adr0393MakeSnapshot(t, adr0393TestKey(), pm, spec, "redis", "default")

	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	var patchCalls int
	c := interceptor.NewClient(base, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			patchCalls++
			if patchCalls == 1 {
				return apierrors.NewConflict(adr0408PMGR, obj.GetName(), fmt.Errorf("simulated creation-instant reconcile-storm conflict"))
			}
			return cl.Status().Patch(ctx, obj, patch, opts...)
		},
	})
	r := &PodMigrationReconciler{Client: c, Scheme: scheme, testOnlySnapshotHMACKey: adr0393TestKey()}
	ctx := context.Background()

	if err := r.patchSourcePodSpecSnapshot(ctx, pm, snap); err != nil {
		t.Fatalf("patch should have retried the transient 409 and succeeded: %v", err)
	}
	if patchCalls < 2 {
		t.Fatalf("expected a retry after the injected 409, got %d patch call(s)", patchCalls)
	}
	fresh := &pmv1.PodMigration{}
	if err := base.Get(ctx, adr0408Key(t), fresh); err != nil {
		t.Fatalf("re-get: %v", err)
	}
	if fresh.Status.SourcePodSpecSnapshot == nil {
		t.Fatal("snapshot did not persist after the retried conflict")
	}
}
