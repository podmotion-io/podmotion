/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0387_tier1_owner_kind_test.go covers ADR-0387: reconcileRollingBack must report the TRUE
// recovery story for a Tier1-Longhorn early-released migration — "a controller recreates a
// fresh replacement" only when the source pod actually had one, "unrecovered outage requiring
// manual intervention" when it did not (a bare/standalone pod, this project's only currently-
// supported pod shape). This file proves both halves: (1) earlyReleaseSourceForTier1Longhorn
// correctly captures pm.Status.Tier1EarlyReleaseSourceOwnerKind from the source pod's
// OwnerReferences before deleting it, for both a bare pod and a ReplicaSet-owned pod; and (2)
// setRolledBackConditionForTier1EarlyRelease picks the correct Reason/message/event from that
// captured field.

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

func trueBoolPtr() *bool { b := true; return &b }

// TestEarlyReleaseSourceForTier1Longhorn_CapturesOwnerKind_BarePod proves a bare (no
// OwnerReferences) source pod leaves Tier1EarlyReleaseSourceOwnerKind empty.
func TestEarlyReleaseSourceForTier1Longhorn_CapturesOwnerKind_BarePod(t *testing.T) {
	scheme := adr0356Scheme(t)
	pod := srcPodOnNode("node-src") // no OwnerReferences — bare pod
	pm := tier1PM("pm1", int32(storage.TierLonghorn), true)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()
	serverCert := adr0351SelfSignedServerCert(t)
	spy := &spyKillFrozenSourceAgentServer{resp: &agentpb.KillFrozenSourceResponse{Success: true, Killed: true}}
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{serverCert}})))
	agentpb.RegisterMigrationAgentServiceServer(grpcSrv, spy)
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()
	port := lis.Addr().(*net.TCPAddr).Port

	srcAgentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "podmotion-agent-src", Namespace: "podmotion-system", Labels: map[string]string{"app": "podmotion-agent"}},
		Spec:       corev1.PodSpec{NodeName: "node-src"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithIndex(&corev1.Pod{}, "spec.nodeName", adr0351PodNodeNameIndexer).
		WithObjects(pod, srcAgentPod, pm, readyNMC("node-dst")).Build()
	clientTLSCfg := &tls.Config{InsecureSkipVerify: true}
	pool := agentclient.NewAgentClientPool(fakeClient, strconv.Itoa(port), clientTLSCfg)
	// ADR-0393: the bare-pod early-release path now captures a durable spec snapshot before the
	// source kill, which requires the operator-only HMAC signing key. Production wires KubeClient
	// (which loads-or-creates it); this unit test injects a fixed key directly.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, AgentPool: pool, testOnlySnapshotHMACKey: adr0393TestKey()}

	if err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
		t.Fatal("expected ConditionTier1EarlySourceRelease=True")
	}
	if pm.Status.Tier1EarlyReleaseSourceOwnerKind != "" {
		t.Fatalf("expected Tier1EarlyReleaseSourceOwnerKind empty for a bare pod, got %q",
			pm.Status.Tier1EarlyReleaseSourceOwnerKind)
	}
}

// TestEarlyReleaseSourceForTier1Longhorn_CapturesOwnerKind_ReplicaSetOwned proves a
// ReplicaSet-owned source pod's controller Kind is captured BEFORE the source pod is deleted
// — even along a path where the subsequent ADR-0371 re-adopt step itself fails (no
// ReplacementPodName recorded on pm.Status), because the capture is unconditional and runs
// first. This isolates the ADR-0387 capture from ADR-0371's re-adopt machinery, which is
// covered by its own dedicated test file.
func TestEarlyReleaseSourceForTier1Longhorn_CapturesOwnerKind_ReplicaSetOwned(t *testing.T) {
	scheme := adr0356Scheme(t)
	pod := srcPodOnNode("node-src")
	pod.OwnerReferences = []metav1.OwnerReference{
		{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "my-rs", UID: "rs-uid", Controller: trueBoolPtr()},
	}
	pm := tier1PM("pm1", int32(storage.TierLonghorn), true)
	// Deliberately no pm.Status.ReplacementPodName — forces readoptReplacementPodIntoOwningReplicaSet
	// to error out ("no replacement pod recorded"), so this test can prove the capture already
	// happened before that failure, without needing to stand up a full ReplicaSet + replacement pod.

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithIndex(&corev1.Pod{}, "spec.nodeName", adr0351PodNodeNameIndexer).
		WithObjects(pod, pm, readyNMC("node-dst")).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm)
	if err == nil {
		t.Fatal("expected re-adopt to fail (no ReplacementPodName recorded) — this test only needs the capture to have already run")
	}
	if pm.Status.Tier1EarlyReleaseSourceOwnerKind != "ReplicaSet" {
		t.Fatalf("expected Tier1EarlyReleaseSourceOwnerKind=%q captured before the re-adopt step, got %q",
			"ReplicaSet", pm.Status.Tier1EarlyReleaseSourceOwnerKind)
	}
	// The source pod must NOT have been deleted — the re-adopt failure is fail-closed.
	got := &corev1.Pod{}
	if getErr := fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "src-pod"}, got); getErr != nil {
		t.Fatalf("source pod should NOT have been deleted when re-adopt failed: %v", getErr)
	}
}

// TestSetRolledBackConditionForTier1EarlyRelease_NoOwner proves a bare-pod early release
// reports an unrecovered outage (distinct Reason + Warning event), never the generic
// "recreate via owning controller" story ADR-0356 uses when a controller actually exists.
func TestSetRolledBackConditionForTier1EarlyRelease_NoOwner(t *testing.T) {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-no-owner", Namespace: "default"},
		Status:     pmv1.PodMigrationStatus{Tier1EarlyReleaseSourceOwnerKind: ""},
	}
	rec := record.NewFakeRecorder(10)
	r := &PodMigrationReconciler{Recorder: rec}

	r.setRolledBackConditionForTier1EarlyRelease(pm)

	cond := meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionRolledBack)
	if cond == nil {
		t.Fatal("expected ConditionRolledBack to be set")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected ConditionRolledBack=True, got %s", cond.Status)
	}
	if cond.Reason != "RollbackCompleteNoOwningController" {
		t.Fatalf("expected reason RollbackCompleteNoOwningController, got %s", cond.Reason)
	}
	select {
	case ev := <-rec.Events:
		if !strings.Contains(ev, "Warning") || !strings.Contains(ev, "Tier1EarlyReleaseUnrecoveredOutage") {
			t.Fatalf("expected a Warning Tier1EarlyReleaseUnrecoveredOutage event, got %q", ev)
		}
	default:
		t.Fatal("expected a Warning event to be recorded for the no-owner case")
	}
}

// TestSetRolledBackConditionForTier1EarlyRelease_WithOwner proves a ReplicaSet-owned early
// release keeps ADR-0356's original bounded-downtime message, naming the actual owner Kind,
// and emits no event (the normal, expected-recovery case).
func TestSetRolledBackConditionForTier1EarlyRelease_WithOwner(t *testing.T) {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-with-owner", Namespace: "default"},
		Status:     pmv1.PodMigrationStatus{Tier1EarlyReleaseSourceOwnerKind: "ReplicaSet"},
	}
	rec := record.NewFakeRecorder(10)
	r := &PodMigrationReconciler{Recorder: rec}

	r.setRolledBackConditionForTier1EarlyRelease(pm)

	cond := meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionRolledBack)
	if cond == nil {
		t.Fatal("expected ConditionRolledBack to be set")
	}
	if cond.Reason != "RollbackCompleteBoundedDowntime" {
		t.Fatalf("expected reason RollbackCompleteBoundedDowntime, got %s", cond.Reason)
	}
	if !strings.Contains(cond.Message, "ReplicaSet") {
		t.Fatalf("expected message to name the owning ReplicaSet, got %q", cond.Message)
	}
	select {
	case ev := <-rec.Events:
		t.Fatalf("expected NO event for the has-owner case, got %q", ev)
	default:
	}
}
