/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0356_tier1_early_source_release_test.go — regression tests for the narrow,
// Tier1-Longhorn-only exception to ADR-0012 documented in ADR-0356: source pod release
// ahead of TrafficVerified is permitted ONLY when (a) the migration is classified
// StorageTier==TierLonghorn, (b) CheckpointTransferred=True (durable, cryptographically
// verified checkpoint on the destination node), and (c) the destination node's
// NodeMigrationCapacity is freshly Ready. Every other tier (or a not-yet-classified
// migration) must be a complete no-op — ADR-0012's normal ordering is unaffected.

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// spyKillFrozenSourceAgentServer is a minimal MigrationAgentService stub used to prove
// earlyReleaseSourceForTier1Longhorn routes source termination through KillFrozenSource
// (ADR-0356 round 2 fix) before ever deleting the source pod. It records whether/how many
// times it was called so the test can assert call ORDER (kill before delete) and count.
type spyKillFrozenSourceAgentServer struct {
	agentpb.UnimplementedMigrationAgentServiceServer
	calls int
	resp  *agentpb.KillFrozenSourceResponse
}

func (s *spyKillFrozenSourceAgentServer) KillFrozenSource(_ context.Context, _ *agentpb.KillFrozenSourceRequest) (*agentpb.KillFrozenSourceResponse, error) {
	s.calls++
	return s.resp, nil
}

func adr0356Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	return scheme
}

func tier1PM(name string, tier int32, checkpointTransferred bool) *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "src-pod",
			PodNamespace: "default",
		},
		Status: pmv1.PodMigrationStatus{
			SourceNodeName:        "node-src",
			DestinationNodeName:   "node-dst",
			StorageTier:           &tier,
			CheckpointTransferred: checkpointTransferred,
		},
	}
}

func readyNMC(name string) *pmv1.NodeMigrationCapacity {
	return &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     pmv1.NodeMigrationCapacityStatus{Ready: true},
	}
}

func notReadyNMC(name string) *pmv1.NodeMigrationCapacity {
	return &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     pmv1.NodeMigrationCapacityStatus{Ready: false},
	}
}

func srcPodOnNode(node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: node},
	}
}

// TestEarlyReleaseSourceForTier1Longhorn_NonLonghornTier_NoOp asserts every non-Longhorn
// tier (including "not yet classified", nil StorageTier) is completely untouched: the
// source pod must still exist and no condition is set. ADR-0012's normal ordering must be
// the only path for these tiers.
func TestEarlyReleaseSourceForTier1Longhorn_NonLonghornTier_NoOp(t *testing.T) {
	scheme := adr0356Scheme(t)
	for _, tc := range []struct {
		name string
		tier *int32
	}{
		{"RWX", int32Ptr(int32(storage.TierRWX))},
		{"CephRBD", int32Ptr(int32(storage.TierCephRBD))},
		{"NotYetClassified", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := srcPodOnNode("node-src")
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{Name: "pm-" + tc.name, Namespace: "default"},
				Spec:       pmv1.PodMigrationSpec{PodName: "src-pod", PodNamespace: "default"},
				Status: pmv1.PodMigrationStatus{
					SourceNodeName:        "node-src",
					DestinationNodeName:   "node-dst",
					StorageTier:           tc.tier,
					CheckpointTransferred: true,
				},
			}
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&pmv1.PodMigration{}).
				WithObjects(pod, pm, readyNMC("node-dst")).Build()
			r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

			if err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm); err != nil {
				t.Fatalf("expected no-op (nil error) for tier %v, got: %v", tc.tier, err)
			}
			got := &corev1.Pod{}
			if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, got); err != nil {
				t.Fatalf("source pod should NOT have been deleted for tier %v: %v", tc.tier, err)
			}
			if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
				t.Fatalf("ConditionTier1EarlySourceRelease must not be set for tier %v", tc.tier)
			}
		})
	}
}

// TestEarlyReleaseSourceForTier1Longhorn_RefusesBeforeCheckpointTransferred is the
// falsifiable guard on guarantee #1: without a durably-verified checkpoint on the
// destination, early release must be refused (source pod untouched, error returned).
func TestEarlyReleaseSourceForTier1Longhorn_RefusesBeforeCheckpointTransferred(t *testing.T) {
	scheme := adr0356Scheme(t)
	pod := srcPodOnNode("node-src")
	pm := tier1PM("pm1", int32(storage.TierLonghorn), false /* CheckpointTransferred */)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pod, pm, readyNMC("node-dst")).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm)
	if err == nil {
		t.Fatal("expected an error refusing early release before CheckpointTransferred=True")
	}
	got := &corev1.Pod{}
	if getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, got); getErr != nil {
		t.Fatalf("source pod should NOT have been deleted: %v", getErr)
	}
}

// TestEarlyReleaseSourceForTier1Longhorn_RefusesWhenDestNMCNotReady is the falsifiable
// guard on guarantee #2: a stale/not-Ready destination NMC must block deletion.
func TestEarlyReleaseSourceForTier1Longhorn_RefusesWhenDestNMCNotReady(t *testing.T) {
	scheme := adr0356Scheme(t)
	pod := srcPodOnNode("node-src")
	pm := tier1PM("pm1", int32(storage.TierLonghorn), true)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithObjects(pod, pm, notReadyNMC("node-dst")).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm)
	if err == nil {
		t.Fatal("expected an error refusing early release when destination NMC is not Ready")
	}
	got := &corev1.Pod{}
	if getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, got); getErr != nil {
		t.Fatalf("source pod should NOT have been deleted: %v", getErr)
	}
}

// TestEarlyReleaseSourceForTier1Longhorn_DeletesWhenBothGuaranteesSatisfied is the
// positive acceptance test: with CheckpointTransferred=True and a fresh-Ready destination
// NMC, the source pod IS deleted and both conditions are set True.
func TestEarlyReleaseSourceForTier1Longhorn_DeletesWhenBothGuaranteesSatisfied(t *testing.T) {
	scheme := adr0356Scheme(t)
	pod := srcPodOnNode("node-src")
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

	// Running agent pod on node-src (the SOURCE node) at 127.0.0.1 so AgentClientPool.ForNode
	// resolves KillFrozenSource's target to the spy — this test proves the source-side kill
	// happens, not the destination side.
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
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, AgentPool: pool}

	if err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if spy.calls != 1 {
		t.Fatalf("expected KillFrozenSource to be called exactly once before pod deletion, got %d calls", spy.calls)
	}
	getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, &corev1.Pod{})
	if !apierrors.IsNotFound(getErr) {
		t.Fatalf("expected source pod to be deleted (NotFound), got err=%v", getErr)
	}
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
		t.Fatal("expected ConditionTier1EarlySourceRelease=True")
	}
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionSourcePodDeleted) {
		t.Fatal("expected conditionSourcePodDeleted=True")
	}

	// Idempotency: calling again must be a safe no-op (no error re-attempting a delete on
	// an already-absent pod). ConditionTier1EarlySourceRelease is already True, so
	// earlyReleaseSourceForTier1Longhorn returns before ever reaching KillFrozenSource again.
	if err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm); err != nil {
		t.Fatalf("expected idempotent no-op on second call, got: %v", err)
	}
	if spy.calls != 1 {
		t.Fatalf("expected KillFrozenSource still called exactly once after idempotent replay, got %d calls", spy.calls)
	}
}

// TestEarlyReleaseSourceForTier1Longhorn_KillFrozenSourceFailureBlocksDelete is the
// falsifiable regression proof for the actual bug found live in sprint49: a plain
// Kubernetes pod delete resumes (SIGCONT) a SIGSTOPped source container before signalling
// it, giving its application-level shutdown code a real window to mutate the SAME shared
// Longhorn volume the CRIU-restored destination depends on (observed: PostgreSQL's own
// postmaster.pid safety check then self-terminates the destination). The fix routes source
// termination through KillFrozenSource (a direct SIGKILL to the still-stopped PID, which
// never resumes it to userspace) BEFORE deleting the pod. This test proves the source pod
// is NOT deleted, and the unsafe fallback path is never taken, if KillFrozenSource fails.
func TestEarlyReleaseSourceForTier1Longhorn_KillFrozenSourceFailureBlocksDelete(t *testing.T) {
	scheme := adr0356Scheme(t)
	pod := srcPodOnNode("node-src")
	pm := tier1PM("pm1", int32(storage.TierLonghorn), true)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()
	serverCert := adr0351SelfSignedServerCert(t)
	spy := &spyKillFrozenSourceAgentServer{resp: &agentpb.KillFrozenSourceResponse{Success: false, Error: "broker SIGKILL failed"}}
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
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, AgentPool: pool}

	if err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm); err == nil {
		t.Fatal("expected an error when KillFrozenSource fails — must not fall through to an unsafe pod delete")
	}
	getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, &corev1.Pod{})
	if getErr != nil {
		t.Fatalf("source pod should NOT have been deleted when KillFrozenSource failed: %v", getErr)
	}
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
		t.Fatal("ConditionTier1EarlySourceRelease must not be set when KillFrozenSource failed")
	}
}

func int32Ptr(v int32) *int32 { return &v }
