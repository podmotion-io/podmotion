/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0393_durable_snapshot_recreate_test.go — ADR-0393 regression coverage: the durable,
// operator-captured SourcePodSpecSnapshot and the fail-closed owner-independent cold-recreate.
//
// Proves, against the real reconcile helpers (no mocks of the code under test):
//   - D2 capture round-trips and is operator-keyed-HMAC verifiable; owned pods capture nothing.
//   - D2 capture gate is fail-closed: no signing key ⇒ earlyReleaseSourceForTier1Longhorn errors
//     and the source pod is NOT deleted (KillFrozenSource is never reached).
//   - D5 fails closed on a tampered spec, a forged/tampered HMAC, a stale/mis-bound UID, a
//     security-context digest mismatch, and a service-account mismatch — the keyed HMAC means a
//     co-writer who rewrites the spec bytes cannot produce a valid MAC (integrity is not theater).
//   - D3 cold-recreate creates exactly one pod carrying a DISTINCT pm.UID-bound marker label (not
//     the replacement-pod label) and a "-r-" deterministic name, and is idempotent / crash-safe:
//     the create-succeeded-but-unrecorded interleaving recovers without a second pod (D-ACCEPT).
//   - D5 blocked-invalid snapshot creates NO pod (degrades to the honest outage report upstream).

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

func adr0393TestKey() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

// adr0393MakeSnapshot builds a valid, HMAC-signed snapshot for a spec, so verify/recreate tests
// do not have to route through capture. Individual fields can then be tampered by the caller.
func adr0393MakeSnapshot(t *testing.T, key []byte, pm *pmv1.PodMigration, spec *corev1.PodSpec, baseName, ns string) *pmv1.SourcePodSpecSnapshot {
	t.Helper()
	specJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	dig, err := podSecurityContextDigest(spec)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	s := &pmv1.SourcePodSpecSnapshot{
		PodSpecJSON:           specJSON,
		BaseName:              baseName,
		Namespace:             ns,
		SourcePodUID:          pm.Spec.SourcePodUID,
		ServiceAccountName:    spec.ServiceAccountName,
		SecurityContextDigest: dig,
		CapturedAtGeneration:  pm.Generation,
	}
	s.IntegrityHMAC = computeSnapshotHMAC(key, s, string(pm.UID))
	return s
}

func adr0393BarePM(name string) *pmv1.PodMigration {
	pm := tier1PM(name, int32(storage.TierLonghorn), true)
	pm.UID = types.UID("uid1234567890abcdef")
	pm.Spec.SourcePodUID = "src-uid-1"
	return pm
}

func adr0393SimpleSpec() *corev1.PodSpec {
	return &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "app", Image: "postgres:16"}},
	}
}

// countRecreatePods returns pods carrying this migration's DISTINCT recreate marker.
func countRecreatePods(t *testing.T, c client.Client, pm *pmv1.PodMigration) int {
	t.Helper()
	list := &corev1.PodList{}
	if err := c.List(context.Background(), list,
		client.MatchingLabels{rollbackRecreateMigrationUIDLabel: string(pm.UID)}); err != nil {
		t.Fatalf("list recreate pods: %v", err)
	}
	return len(list.Items)
}

// --- D2 capture ---------------------------------------------------------------------------------

func TestADR0393_Capture_BarePod_RoundTripsAndVerifies(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-cap")
	pod := srcPodOnNode("node-src")
	pod.UID = types.UID("src-uid-1")
	pod.Labels = map[string]string{"app": "pg"}
	pod.Spec.Containers = []corev1.Container{{Name: "app", Image: "postgres:16"}}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, testOnlySnapshotHMACKey: adr0393TestKey()}

	if err := r.captureSourcePodSpecSnapshot(context.Background(), pm, pod); err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	if pm.Status.SourcePodSpecSnapshot == nil {
		t.Fatal("expected snapshot captured on pm.Status")
	}
	// Persisted (read-back).
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name}, fresh); err != nil {
		t.Fatalf("re-get pm: %v", err)
	}
	if fresh.Status.SourcePodSpecSnapshot == nil {
		t.Fatal("snapshot did not persist to the API")
	}
	if ok, reason := r.verifySnapshotIntegrity(context.Background(), fresh); !ok {
		t.Fatalf("persisted snapshot failed verification: %s", reason)
	}
}

func TestADR0393_Capture_OwnedPod_IsNoOp(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-owned")
	pod := srcPodOnNode("node-src")
	pod.OwnerReferences = []metav1.OwnerReference{
		{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-uid", Controller: trueBoolPtr()},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, testOnlySnapshotHMACKey: adr0393TestKey()}

	if err := r.captureSourcePodSpecSnapshot(context.Background(), pm, pod); err != nil {
		t.Fatalf("capture returned error for owned pod: %v", err)
	}
	if pm.Status.SourcePodSpecSnapshot != nil {
		t.Fatal("expected NO snapshot for an owned pod (its controller recreates it)")
	}
}

// --- ADR-0396 D-KILL-FIX: capture idempotency re-verifies the HMAC, never trusts presence --------

// TestADR0396_KillFix_PresentValidSnapshot_IsIdempotent: a present snapshot that carries the
// operator's own valid keyed HMAC is genuinely idempotent — a repeat capture short-circuits and
// leaves it untouched (the legitimate requeue case ADR-0393 relied on).
func TestADR0396_KillFix_PresentValidSnapshot_IsIdempotent(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-killfix-valid")
	pod := srcPodOnNode("node-src")
	pod.UID = types.UID("src-uid-1")
	pod.Spec.Containers = []corev1.Container{{Name: "app", Image: "postgres:16"}}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, testOnlySnapshotHMACKey: adr0393TestKey()}

	if err := r.captureSourcePodSpecSnapshot(context.Background(), pm, pod); err != nil {
		t.Fatalf("initial capture failed: %v", err)
	}
	first := pm.Status.SourcePodSpecSnapshot
	if first == nil {
		t.Fatal("expected a snapshot after the first capture")
	}
	if err := r.captureSourcePodSpecSnapshot(context.Background(), pm, pod); err != nil {
		t.Fatalf("idempotent re-capture over a valid snapshot failed: %v", err)
	}
	if pm.Status.SourcePodSpecSnapshot != first {
		t.Fatal("ADR-0396 D-KILL-FIX: a present, operator-valid snapshot must be left intact (idempotent), not re-captured")
	}
}

// TestADR0396_KillFix_PresentForgedSnapshot_DiscardedAndReSigned: the S1(b) fix. A present snapshot
// whose HMAC does NOT verify under the operator key (a stand-in for a co-writer's forged bytes on the
// writable podmigrations/status subresource) must NOT be trusted on presence. Capture discards it and
// re-captures + re-signs from the live source pod, so a forged snapshot can never make the capture gate
// (and thus ADR-0396's armed := (capture == nil)) succeed on unverified bytes.
func TestADR0396_KillFix_PresentForgedSnapshot_DiscardedAndReSigned(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-killfix-forged")
	pod := srcPodOnNode("node-src")
	pod.UID = types.UID("src-uid-1")
	pod.Spec.Containers = []corev1.Container{{Name: "app", Image: "postgres:16"}}

	// Plant a snapshot signed with the WRONG key: present, structurally valid, but its HMAC does not
	// verify under the operator's key — exactly a forged co-writer plant.
	wrongKey := bytes.Repeat([]byte{0x11}, 32)
	forged := adr0393MakeSnapshot(t, wrongKey, pm, pod.Spec.DeepCopy(), pod.Name, pod.Namespace)
	pm.Status.SourcePodSpecSnapshot = forged

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, testOnlySnapshotHMACKey: adr0393TestKey()}

	// Setup sanity: the plant must not verify under the operator key.
	if ok, _ := r.verifySnapshotIntegrity(context.Background(), pm); ok {
		t.Fatal("test setup: forged snapshot unexpectedly verifies under the operator key")
	}

	if err := r.captureSourcePodSpecSnapshot(context.Background(), pm, pod); err != nil {
		t.Fatalf("capture over a forged snapshot failed (expected discard + re-sign, not error): %v", err)
	}
	if pm.Status.SourcePodSpecSnapshot == nil {
		t.Fatal("ADR-0396 D-KILL-FIX: expected a re-captured snapshot, got nil")
	}
	if pm.Status.SourcePodSpecSnapshot.IntegrityHMAC == forged.IntegrityHMAC {
		t.Fatal("ADR-0396 D-KILL-FIX: forged snapshot was trusted on presence (HMAC unchanged) — the kill-site bug is not fixed")
	}
	if ok, reason := r.verifySnapshotIntegrity(context.Background(), pm); !ok {
		t.Fatalf("ADR-0396 D-KILL-FIX: the re-captured snapshot must verify under the operator key: %s", reason)
	}
}

// TestADR0393_CaptureGate_FailClosed_NoKey proves the fail-closed capture gate: with no signing
// key available (no KubeClient, no test key), earlyReleaseSourceForTier1Longhorn errors out for a
// bare pod and the source pod is NOT deleted — KillFrozenSource is downstream of the capture and
// is therefore never reached.
func TestADR0393_CaptureGate_FailClosed_NoKey(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-failclosed")
	pod := srcPodOnNode("node-src") // bare pod

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithIndex(&corev1.Pod{}, "spec.nodeName", adr0351PodNodeNameIndexer).
		WithObjects(pod, pm, readyNMC("node-dst")).Build()
	// No KubeClient, no testOnlySnapshotHMACKey ⇒ snapshotHMACKey() fails ⇒ capture gate fails closed.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm)
	if err == nil {
		t.Fatal("expected fail-closed error when the snapshot cannot be captured")
	}
	got := &corev1.Pod{}
	if gErr := fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "src-pod"}, got); gErr != nil {
		t.Fatalf("source pod must NOT be deleted when the capture gate fails closed: %v", gErr)
	}
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
		t.Fatal("early-release must not be marked complete when the capture gate failed closed")
	}
}

// --- D5 fail-closed verification ---------------------------------------------------------------

func TestADR0393_Verify_FailsClosed(t *testing.T) {
	key := adr0393TestKey()
	newPMWithSnap := func() (*pmv1.PodMigration, *pmv1.SourcePodSpecSnapshot) {
		pm := adr0393BarePM("pm-v")
		s := adr0393MakeSnapshot(t, key, pm, adr0393SimpleSpec(), "src-pod", "default")
		pm.Status.SourcePodSpecSnapshot = s
		return pm, s
	}
	r := &PodMigrationReconciler{testOnlySnapshotHMACKey: key}
	ctx := context.Background()

	// Positive control.
	if pm, _ := newPMWithSnap(); func() bool { ok, _ := r.verifySnapshotIntegrity(ctx, pm); return !ok }() {
		t.Fatal("valid snapshot should verify")
	}

	cases := []struct {
		name   string
		mutate func(pm *pmv1.PodMigration, s *pmv1.SourcePodSpecSnapshot)
	}{
		{"tampered-podspec", func(_ *pmv1.PodMigration, s *pmv1.SourcePodSpecSnapshot) {
			// Rewrite the spec bytes (widen the image) WITHOUT the key — the co-writer attack.
			var spec corev1.PodSpec
			_ = json.Unmarshal(s.PodSpecJSON, &spec)
			spec.Containers[0].Image = "attacker/evil:latest"
			s.PodSpecJSON, _ = json.Marshal(&spec)
		}},
		{"tampered-hmac", func(_ *pmv1.PodMigration, s *pmv1.SourcePodSpecSnapshot) {
			s.IntegrityHMAC = "deadbeef" + s.IntegrityHMAC[8:]
		}},
		{"stale-misbound-uid", func(pm *pmv1.PodMigration, _ *pmv1.SourcePodSpecSnapshot) {
			pm.Spec.SourcePodUID = "a-different-uid"
		}},
		{"securitycontext-digest-mismatch", func(_ *pmv1.PodMigration, s *pmv1.SourcePodSpecSnapshot) {
			// Widen the security context inside the (HMAC'd) bytes AND fix the HMAC so only the
			// digest cross-check catches it — proves the digest is an independent backstop.
			var spec corev1.PodSpec
			_ = json.Unmarshal(s.PodSpecJSON, &spec)
			priv := true
			var rootUID int64
			spec.SecurityContext = &corev1.PodSecurityContext{RunAsUser: &rootUID}
			spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &priv}
			s.PodSpecJSON, _ = json.Marshal(&spec)
			// leave SecurityContextDigest as the OLD value; recompute the HMAC over the new bytes.
			s.IntegrityHMAC = computeSnapshotHMAC(key, s, "uid1234567890abcdef")
		}},
		{"serviceaccount-mismatch", func(_ *pmv1.PodMigration, s *pmv1.SourcePodSpecSnapshot) {
			var spec corev1.PodSpec
			_ = json.Unmarshal(s.PodSpecJSON, &spec)
			spec.ServiceAccountName = "privileged-sa"
			s.PodSpecJSON, _ = json.Marshal(&spec)
			// keep s.ServiceAccountName as "" and recompute HMAC so only the SA cross-check trips.
			s.IntegrityHMAC = computeSnapshotHMAC(key, s, "uid1234567890abcdef")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pm, s := newPMWithSnap()
			tc.mutate(pm, s)
			if ok, _ := r.verifySnapshotIntegrity(ctx, pm); ok {
				t.Fatalf("%s: expected verification to FAIL CLOSED, but it passed", tc.name)
			}
		})
	}
}

// --- D3 / D-ACCEPT cold-recreate ---------------------------------------------------------------

func adr0393RecreateReconciler(t *testing.T, pm *pmv1.PodMigration) (*PodMigrationReconciler, client.Client) {
	t.Helper()
	scheme := adr0356Scheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	return &PodMigrationReconciler{Client: c, Scheme: scheme, testOnlySnapshotHMACKey: adr0393TestKey()}, c
}

func TestADR0393_ColdRecreate_CreatesOnePod_DistinctMarker(t *testing.T) {
	key := adr0393TestKey()
	pm := adr0393BarePM("pm-recreate")
	pm.Status.SourcePodSpecSnapshot = adr0393MakeSnapshot(t, key, pm, adr0393SimpleSpec(), "src-pod", "default")
	r, c := adr0393RecreateReconciler(t, pm)

	outcome, _, err := r.reconcileTier1ColdRecreateFromSnapshot(context.Background(), pm)
	if err != nil {
		t.Fatalf("recreate errored: %v", err)
	}
	if outcome != coldRecreateSucceeded {
		t.Fatalf("expected coldRecreateSucceeded, got %v", outcome)
	}
	if n := countRecreatePods(t, c, pm); n != 1 {
		t.Fatalf("expected exactly 1 recreate pod, got %d", n)
	}
	// Distinct marker + deterministic "-r-" name; NOT the replacement-pod label.
	want := "src-pod-r-" + string(pm.UID)[:8]
	got := &corev1.Pod{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: want}, got); err != nil {
		t.Fatalf("recreate pod %q not found: %v", want, err)
	}
	if got.Labels[rollbackRecreateMigrationUIDLabel] != string(pm.UID) {
		t.Fatalf("recreate pod missing distinct pm.UID marker label")
	}
	if _, bad := got.Labels[replacementPodMigrationNameLabel]; bad {
		t.Fatal("recreate pod must NOT carry the replacement-pod label (would collide with the reaper)")
	}
	// Snapshot consumed.
	if pm.Status.SourcePodSpecSnapshot != nil {
		t.Fatal("expected snapshot cleared after successful recreate")
	}
}

// TestADR0393_ColdRecreate_DAccept_CreateSucceededButUnrecorded proves the dangerous interleaving:
// r.Create already landed on the apiserver, then the operator died before recording anything. On
// re-entry the deterministic name resolves the existing pod and the transition completes WITHOUT a
// second pod racing the same volume.
func TestADR0393_ColdRecreate_DAccept_CreateSucceededButUnrecorded(t *testing.T) {
	key := adr0393TestKey()
	pm := adr0393BarePM("pm-daccept")
	pm.Status.SourcePodSpecSnapshot = adr0393MakeSnapshot(t, key, pm, adr0393SimpleSpec(), "src-pod", "default")
	// Snapshot still present AND RollbackRecreatePending still True (nothing was cleared before the crash).
	setCondition(pm, pmv1.ConditionRollbackRecreatePending, metav1.ConditionTrue, "RollbackRecreateInProgress", "")

	scheme := adr0356Scheme(t)
	// Pre-seed the already-created recreate pod (the create that landed before the crash).
	preExisting := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "src-pod-r-" + string(pm.UID)[:8],
			Namespace: "default",
			Labels:    map[string]string{rollbackRecreateMigrationUIDLabel: string(pm.UID)},
		},
		Spec: *adr0393SimpleSpec(),
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm, preExisting).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme, testOnlySnapshotHMACKey: key}

	outcome, _, err := r.reconcileTier1ColdRecreateFromSnapshot(context.Background(), pm)
	if err != nil {
		t.Fatalf("re-entrant recreate errored: %v", err)
	}
	if outcome != coldRecreateSucceeded {
		t.Fatalf("expected coldRecreateSucceeded on re-entry, got %v", outcome)
	}
	if n := countRecreatePods(t, c, pm); n != 1 {
		t.Fatalf("re-entry must not create a second pod; got %d recreate pods", n)
	}
}

// TestADR0393_ColdRecreate_InvalidSnapshot_CreatesNoPod proves a tampered snapshot yields
// coldRecreateBlockedInvalid and creates nothing (upstream then reports the honest outage).
func TestADR0393_ColdRecreate_InvalidSnapshot_CreatesNoPod(t *testing.T) {
	key := adr0393TestKey()
	pm := adr0393BarePM("pm-invalid")
	s := adr0393MakeSnapshot(t, key, pm, adr0393SimpleSpec(), "src-pod", "default")
	s.IntegrityHMAC = "0000000000000000" + s.IntegrityHMAC[16:] // forge
	pm.Status.SourcePodSpecSnapshot = s
	r, c := adr0393RecreateReconciler(t, pm)

	outcome, _, err := r.reconcileTier1ColdRecreateFromSnapshot(context.Background(), pm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != coldRecreateBlockedInvalid {
		t.Fatalf("expected coldRecreateBlockedInvalid, got %v", outcome)
	}
	if n := countRecreatePods(t, c, pm); n != 0 {
		t.Fatalf("blocked-invalid snapshot must create NO pod; got %d", n)
	}
}
