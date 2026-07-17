/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// verifytcp_source_seqsnapshots_test.go is the falsifiable regression proof that
// reconcileTCPVerifying threads the source-freeze TCP sequence snapshots
// (pm.Status.TCPSeqSnapshots) into the VerifyTCP RPC's SourceSeqSnapshots field.
//
// The defect this closes (live redis Strict held-connection proof): VerifyTCP resolves the
// source snapshots from the destination agent's per-migration migrationSeqSnapshots map, which
// is written ONLY on the gRPC join-ns Restore path. The live North Star restore runs through the
// NRI JoinNsRestore hook and any follow-up gRPC Restore takes the ADR-0228 idempotent-confirm
// early return, so on the live path that map is NEVER populated. With the controller ALSO not
// sending the snapshots it already holds in pm.Status.TCPSeqSnapshots, VerifyTCP had no source
// snapshots to compare against and failed closed with "source SeqSnapshots absent but destination
// has N ESTABLISHED connection(s)" (ADR-0049 fail-closed) even though a real connection was held.
//
// The fix passes pm.Status.TCPSeqSnapshots via VerifyTCPRequest.SourceSeqSnapshots, which VerifyTCP
// consults as a fallback when its stored map is empty — making verification restore-path-agnostic.
// A refactor that drops the plumbing goes red here instead of shipping a byte-identical green.

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// capturingVerifyTCPAgentServer records the last VerifyTCPRequest it received so the test can
// assert what the controller actually put on the wire.
type capturingVerifyTCPAgentServer struct {
	agentpb.UnimplementedMigrationAgentServiceServer
	mu   sync.Mutex
	last *agentpb.VerifyTCPRequest
	resp *agentpb.VerifyTCPResponse
}

func (s *capturingVerifyTCPAgentServer) VerifyTCP(_ context.Context, req *agentpb.VerifyTCPRequest) (*agentpb.VerifyTCPResponse, error) {
	s.mu.Lock()
	s.last = req
	s.mu.Unlock()
	return s.resp, nil
}

func (s *capturingVerifyTCPAgentServer) lastReq() *agentpb.VerifyTCPRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func TestReconcileTCPVerifying_ThreadsSourceSeqSnapshots(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	serverCert := adr0351SelfSignedServerCert(t)
	// Respond with a genuine 2/2 held-connection pass so reconcileTCPVerifying runs to completion
	// (the point under test is the REQUEST the controller builds, not the response handling).
	spy := &capturingVerifyTCPAgentServer{
		resp: &agentpb.VerifyTCPResponse{Verified: true, ConnectionsVerified: 1, ConnectionsExpected: 1},
	}
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
	})))
	agentpb.RegisterMigrationAgentServiceServer(grpcSrv, spy)
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()
	port := lis.Addr().(*net.TCPAddr).Port

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	const destNode = "dst-node-seqthread"
	const ns = "default"
	const migName = "pm-seqthread"

	agentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podmotion-agent-dst",
			Namespace: "podmotion-system",
			Labels:    map[string]string{"app": "podmotion-agent"},
		},
		Spec:   corev1.PodSpec{NodeName: destNode},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}
	replacementPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "repl-pod-seqthread",
			Namespace: ns,
			UID:       "uid-repl-seqthread",
			Labels:    map[string]string{replacementPodMigrationNameLabel: migName},
		},
		Spec:   corev1.PodSpec{NodeName: destNode},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.77"},
	}

	// The source-freeze snapshot the controller persisted from CheckpointResponse. This is the
	// exact data that must reach VerifyTCP; on the live NRI restore path nothing else carries it.
	srcSnaps := []pmv1.TCPSeqSnapshot{
		{SrcIP: "10.244.2.71", SrcPort: 6379, DstIP: "10.244.2.210", DstPort: 41946, SndNxt: 0x11223344, RcvNxt: 0x55667788, TsRecent: 99},
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod-seqthread",
			PodNamespace:        ns,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
			TargetNodeName:      destNode,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseTCPVerifying,
			DestinationNodeName: destNode,
			ReplacementPodName:  "repl-pod-seqthread",
			TCPSeqSnapshots:     srcSnaps,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, agentPod, replacementPod).
		WithStatusSubresource(pm).
		WithIndex(&corev1.Pod{}, "spec.nodeName", adr0351PodNodeNameIndexer).
		Build()

	// #nosec G402 -- test-only: does not exercise the SPIFFE peer-identity verifier.
	clientTLSCfg := &tls.Config{InsecureSkipVerify: true}
	pool := agentclient.NewAgentClientPool(fakeClient, strconv.Itoa(port), clientTLSCfg)
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, AgentPool: pool}

	if _, err := r.reconcileTCPVerifying(context.Background(), pm); err != nil {
		t.Fatalf("reconcileTCPVerifying returned error: %v", err)
	}

	req := spy.lastReq()
	if req == nil {
		t.Fatal("VerifyTCP was never called")
	}
	if len(req.SourceSeqSnapshots) != len(srcSnaps) {
		t.Fatalf("VerifyTCPRequest.SourceSeqSnapshots len = %d, want %d — the controller must thread "+
			"pm.Status.TCPSeqSnapshots so the destination agent's VerifyTCP does not fail closed with "+
			"\"source SeqSnapshots absent\" on the live NRI restore path", len(req.SourceSeqSnapshots), len(srcSnaps))
	}
	got := req.SourceSeqSnapshots[0]
	want := srcSnaps[0]
	if got.SrcIp != want.SrcIP || got.SrcPort != want.SrcPort ||
		got.DstIp != want.DstIP || got.DstPort != want.DstPort ||
		got.SndNxt != want.SndNxt || got.RcvNxt != want.RcvNxt || got.TsRecent != want.TsRecent {
		t.Fatalf("threaded snapshot = %+v, want fields from %+v (4-tuple + snd_nxt/rcv_nxt/ts_recent must "+
			"survive the status->request conversion intact for the ±MSS continuity comparison)", got, want)
	}
}
