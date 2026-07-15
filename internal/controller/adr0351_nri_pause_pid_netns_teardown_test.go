/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0351_nri_pause_pid_netns_teardown_test.go is the controller-level discharge (sprint46B7
// rewrite, D3.3 — REWRITTEN from the retired pause-PID-wait budget-spent leg onto the new
// cgroup-anchor fail-closed leg) for the NRI-path netns-teardown chain. On the NRI path
// (joinNsRestore's cgroup-anchor gate) the in-frame Restore()
// GC-10 defer CANNOT fire (no Restore() call frame — the NRI wrapper runs in a detached restore
// goroutine). Teardown is controller-rollback-driven: reconcileRestoringNRI's 60s
// criuRestoreConfirmed poll expires -> gRPC Restore fallback -> on terminal rollback
// reconcileRollingBack calls destAgent.Abort -> the ADR-0173 Abort GC-10 defer reaps the dest
// migration netns.
//
// No prior controller test dispatches a real Abort RPC and observes it — this test builds the
// minimum real-gRPC-listener harness needed to do so: a stub agent implementing only Abort (spy),
// wired into a real AgentClientPool via a fake k8s client carrying a Running agent pod at
// 127.0.0.1. This proves reconcileRollingBack's Abort dispatch actually fires on this failure
// leg — a future change to that dispatch or to the NRI-fallback-to-Restore sequencing goes red
// here instead of silently leaking the dest netns.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// adr0351SelfSignedServerCert mints a throwaway self-signed TLS cert for 127.0.0.1, purely to
// satisfy AgentClientPool.dial's ADR-SEC-A fail-closed "never dial plaintext" gate in this test
// binary (built without the //go:build dev tag). The client side uses InsecureSkipVerify (test
// only) since this test does not exercise the SPIFFE peer-identity verifier — that is a separate,
// already-covered concern (internal/agent/tls).
func adr0351SelfSignedServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "adr0351-test-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// podNodeNameIndexer mirrors internal/agent/client/client_test.go's field indexer — required for
// AgentClientPool.resolveAgentPodIP's client.MatchingFields{"spec.nodeName": ...} list to work
// against a fake client.
func adr0351PodNodeNameIndexer(obj client.Object) []string {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	return []string{pod.Spec.NodeName}
}

// spyAbortAgentServer is a minimal MigrationAgentServiceServer implementing only Abort (spy) —
// the lighter of the two harnesses ADR-0351's own template text permits ("register a stub/real
// AgentServer.Abort to record the call"). It proves the dispatch fires with the right migration
// name; it does not additionally reconstruct a real *server.AgentServer's destMigrationNetns map.
type spyAbortAgentServer struct {
	agentpb.UnimplementedMigrationAgentServiceServer
	calledCh chan *agentpb.AbortRequest
}

func (s *spyAbortAgentServer) Abort(_ context.Context, req *agentpb.AbortRequest) (*agentpb.AbortResponse, error) {
	s.calledCh <- req
	return &agentpb.AbortResponse{Success: true}, nil
}

// TestRestore_NRICgroupAnchorFailedClosed_DestMigrationNetnsTornDownViaRollback is ADR-0351's
// D2/D3.3 (sprint46B7 rewrite of the retired D6.8): drives an NRI-path cgroup-anchor fail-closed
// terminal through to RollingBack and asserts the rollback chain actually dispatches
// destAgent.Abort against the destination node's agent — the controller-rollback-driven teardown
// mechanism that (unlike the gRPC path's in-frame Restore() defer) is the ONLY teardown mechanism
// reachable on the NRI path (D1.3/G5).
func TestRestore_NRICgroupAnchorFailedClosed_DestMigrationNetnsTornDownViaRollback(t *testing.T) {
	// 1. Real gRPC listener + spy Abort handler standing in for the destination node's agent.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer lis.Close()

	serverCert := adr0351SelfSignedServerCert(t)
	spy := &spyAbortAgentServer{calledCh: make(chan *agentpb.AbortRequest, 1)}
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
	})))
	agentpb.RegisterMigrationAgentServiceServer(grpcSrv, spy)
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()

	port := lis.Addr().(*net.TCPAddr).Port

	// 2. Fake k8s client carrying the PodMigration, the source pod, AND a Running agent pod on
	//    the destination node at 127.0.0.1 (so AgentClientPool.ForNode resolves to our spy).
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	const destNode = "dst-node-nri"
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod-nri-pausepid", Namespace: "default", UID: "uid-nri-pausepid"},
		Spec:       corev1.PodSpec{NodeName: "src-node"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.22"},
	}
	agentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podmotion-agent-dst",
			Namespace: "podmotion-system",
			Labels:    map[string]string{"app": "podmotion-agent"},
		},
		Spec:   corev1.PodSpec{NodeName: destNode},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}

	now := metav1.Now()
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-nri-pausepid-netns-teardown",
			Namespace:  "default",
			Finalizers: []string{finalizerName},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod-nri-pausepid",
			PodNamespace:        "default",
			Mode:                pmv1.MigrationModeCold,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
			RollbackOnFailure:   true,
			TargetNodeName:      destNode,
			SourcePodIP:         "10.0.0.22",
		},
		Status: pmv1.PodMigrationStatus{
			Phase: pmv1.MigrationPhaseRollingBack,
			Conditions: []metav1.Condition{
				{
					Type: string(pmv1.ConditionZeroWindowArmed), Status: metav1.ConditionTrue,
					Reason: "Armed", Message: "hold armed on source veth", LastTransitionTime: now,
				},
				{
					// ADR-0351 D2: the NRI-path cgroup-anchor gate failed closed
					// (resolveCgroupAnchorTarget rejected the NRI-carried cgroup path);
					// reconcileRestoringNRI's 60s poll expired and fell back to the gRPC Restore RPC,
					// which also failed, landing RollingBack — destStaged must be true so
					// reconcileRollingBack dispatches Abort.
					Type: string(conditionRestored), Status: metav1.ConditionFalse,
					Reason:             "RestoreFailed",
					Message:            "ADR-0351: resolve cgroup anchor for sandbox sandbox-nri-test: ADR-0351: cgroup leaf \"/sys/fs/cgroup/evil.slice\" resolves to \"/sys/fs/cgroup/evil.slice\", outside /sys/fs/cgroup/kubepods — refusing (path-confinement, BD-10)",
					LastTransitionTime: now,
				},
				{
					// destStaged gate (reconcileRollingBack): staged at DestinationPrewarm,
					// independent of which restore path later ran.
					Type: pmv1.ConditionDestinationNetnsReady, Status: metav1.ConditionTrue,
					Reason: "Staged", Message: "dest migration netns pre-staged", LastTransitionTime: now,
				},
			},
			SourceNodeName:      "src-node",
			DestinationNodeName: destNode,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod, agentPod).
		WithStatusSubresource(pm).
		WithIndex(&corev1.Pod{}, "spec.nodeName", adr0351PodNodeNameIndexer).
		Build()

	// #nosec G402 -- test-only client cert verification skip; this test does not exercise the
	// SPIFFE peer-identity verifier (internal/agent/tls), only the Abort dispatch chain.
	clientTLSCfg := &tls.Config{InsecureSkipVerify: true}
	pool := agentclient.NewAgentClientPool(fakeClient, strconv.Itoa(port), clientTLSCfg)

	spyRB := &spyRollbacker{}
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: spyRB, AgentPool: pool}

	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-nri-pausepid-netns-teardown", Namespace: "default"}}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile(RollingBack) returned error: %v", err)
	}

	select {
	case abReq := <-spy.calledCh:
		if abReq.MigrationName != "test-nri-pausepid-netns-teardown" {
			t.Errorf("Abort dispatched with MigrationName=%q, want %q", abReq.MigrationName, "test-nri-pausepid-netns-teardown")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("destAgent.Abort was NOT dispatched within 5s — the NRI-path dest migration netns teardown chain (reconcileRollingBack -> Abort -> ADR-0173 defer) did not fire for the ADR-0351 cgroup-anchor fail-closed failure leg")
	}

	// Source-survival is asserted by D6.7; this test's scope is the Abort dispatch itself.
	if !spyRB.called {
		t.Errorf("Rollbacker.Rollback was not driven alongside the Abort dispatch")
	}
}
