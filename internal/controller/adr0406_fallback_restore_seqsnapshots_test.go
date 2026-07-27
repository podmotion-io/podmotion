/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0406_fallback_restore_seqsnapshots_test.go is the falsifiable regression proof for ADR-0406:
// the controller's NRI-fallback Restore RPC call site (reconcileRestoringNRI) MUST carry
// SeqSnapshots (plus SourceNodeAddr / SourceFreezeTimestampNs) exactly as the primary restore
// call site (reconcileRestoring) does, so the destination agent seeds PM_SEQ_XLAT on the fallback
// path identically to the primary path.
//
// The defect (live redis / migration-demo-web Strict held-connection proof, investigation
// RELAY-SEEDING-REGRESSION-INVESTIGATION.md): when the NRI holder-quiescent barrier times out the
// controller falls back to the gRPC Restore RPC, but that request omitted SeqSnapshots. On the
// agent, the gRPC seeding block guard `if len(req.SeqSnapshots) > 0` was then false, so
// SeedRelayFromSnapshots never ran and reconcileDisengageHold later (correctly) failed closed with
// SeqXlatNotSeeded. The fix populates the fallback request from pm.Status.TCPSeqSnapshots via the
// single-authority buildRestoreSeqSnapshots helper. A refactor that drops the plumbing — or a
// future proto field added to only one call site — goes red here instead of shipping green.
//
// These are the wiring assertions (ADR-0406 verification notes 1 and 4). They are NECESSARY but NOT
// SUFFICIENT to close the ADR: closing it additionally requires the REAL live fallback-path
// seeding proof (verification assertion 2, SeqXlatSeeded=True on a held connection), which no unit
// test can substitute for.

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

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

// capturingRestoreAgentServer records the last RestoreRequest it received so the test can assert
// what the controller actually put on the wire on the NRI-fallback path.
type capturingRestoreAgentServer struct {
	agentpb.UnimplementedMigrationAgentServiceServer
	mu   sync.Mutex
	last *agentpb.RestoreRequest
}

func (s *capturingRestoreAgentServer) Restore(_ context.Context, req *agentpb.RestoreRequest) (*agentpb.RestoreResponse, error) {
	s.mu.Lock()
	s.last = req
	s.mu.Unlock()
	// Report success so reconcileRestoringNRI runs the fallback branch to completion; the point
	// under test is the REQUEST the controller builds, not the response handling.
	return &agentpb.RestoreResponse{Success: true, RestoreDurationMs: 1}, nil
}

func (s *capturingRestoreAgentServer) lastReq() *agentpb.RestoreRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// adr0406DriveFallback stands up a capturing agent, builds a Running+Ready replacement pod and a
// PodMigration whose criu-confirm wait-start annotation is already past the 60s timeout so
// reconcileRestoringNRI takes the :5037 NRI-fallback branch, then returns the captured request.
func adr0406DriveFallback(t *testing.T, seqSnaps []pmv1.TCPSeqSnapshot) *agentpb.RestoreRequest {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	serverCert := adr0351SelfSignedServerCert(t)
	spy := &capturingRestoreAgentServer{}
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

	const destNode = "dst-node-adr0406"
	const ns = "default"
	const migName = "pm-adr0406-fallback"
	const replName = "repl-pod-adr0406"

	agentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podmotion-agent-dst",
			Namespace: "podmotion-system",
			Labels:    map[string]string{"app": "podmotion-agent"},
		},
		Spec:   corev1.PodSpec{NodeName: destNode},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}
	// Replacement pod: Running with a Ready container so reconcileRestoringNRI passes the
	// readiness precondition and reaches the criuRestoreConfirmed poll / fallback branch.
	replacementPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      replName,
			Namespace: ns,
			UID:       "uid-repl-adr0406",
			Labels:    map[string]string{replacementPodMigrationNameLabel: migName},
		},
		Spec: corev1.PodSpec{NodeName: destNode},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			PodIP:             "10.0.0.88",
			ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Ready: true}},
		},
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      migName,
			Namespace: ns,
			// Pre-stamp the wait-start annotation well past the 60s criuConfirmTimeout so the
			// NRI-confirm poll elapses immediately and the fallback Restore RPC branch fires.
			Annotations: map[string]string{
				"podmotion.io/restore-confirm-wait-start": time.Now().Add(-10 * time.Minute).Format(time.RFC3339),
			},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod-adr0406",
			PodNamespace:        ns,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
			TargetNodeName:      destNode,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:                   pmv1.MigrationPhaseRestoring,
			DestinationNodeName:     destNode,
			ReplacementPodName:      replName,
			SourceNodeName:          "src-node-adr0406",
			SourceFreezeTimestampNs: 0x0BADC0DE,
			DestNetnsPath:           "/proc/4242/ns/net",
			TCPSeqSnapshots:         seqSnaps,
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

	if _, err := r.reconcileRestoringNRI(context.Background(), pm); err != nil {
		t.Fatalf("reconcileRestoringNRI returned error: %v", err)
	}

	req := spy.lastReq()
	if req == nil {
		t.Fatal("NRI-fallback Restore RPC was never called — the test did not reach the :5037 " +
			"fallback branch (check the wait-start annotation / replacement-pod readiness preconditions)")
	}
	return req
}

// TestADR0406_FallbackRestoreRequestCarriesSeqSnapshots is the load-bearing wiring proof: on the
// NRI-fallback path the controller must send the same seeding fields the primary sends.
func TestADR0406_FallbackRestoreRequestCarriesSeqSnapshots(t *testing.T) {
	srcSnaps := []pmv1.TCPSeqSnapshot{
		{SrcIP: "10.244.2.71", SrcPort: 6379, DstIP: "10.244.2.210", DstPort: 41946, SndNxt: 0x11223344, RcvNxt: 0x55667788, TsRecent: 99},
		{SrcIP: "10.244.2.71", SrcPort: 6379, DstIP: "10.244.2.211", DstPort: 51000, SndNxt: 0xAABBCCDD, RcvNxt: 0x01020304, TsRecent: 4242},
	}

	req := adr0406DriveFallback(t, srcSnaps)

	if len(req.SeqSnapshots) != len(srcSnaps) {
		t.Fatalf("NRI-fallback RestoreRequest.SeqSnapshots len = %d, want %d — the fallback call site "+
			"MUST carry the snapshots so the agent's `len(req.SeqSnapshots) > 0` seed guard is true and "+
			"SeedRelayFromSnapshots runs; before ADR-0406 this field was empty and the migration failed "+
			"closed with SeqXlatNotSeeded", len(req.SeqSnapshots), len(srcSnaps))
	}
	for i, want := range srcSnaps {
		got := req.SeqSnapshots[i]
		if got.SrcIp != want.SrcIP || got.SrcPort != want.SrcPort ||
			got.DstIp != want.DstIP || got.DstPort != want.DstPort ||
			got.SndNxt != want.SndNxt || got.RcvNxt != want.RcvNxt || got.TsRecent != want.TsRecent {
			t.Fatalf("SeqSnapshots[%d] = %+v, want fields from %+v (4-tuple + snd_nxt/rcv_nxt/ts_recent "+
				"must survive the status->request conversion intact)", i, got, want)
		}
	}

	// Mirror the primary exactly: SourceNodeAddr and SourceFreezeTimestampNs must also be threaded.
	if req.SourceNodeAddr != "src-node-adr0406" {
		t.Errorf("SourceNodeAddr = %q, want %q (fallback must mirror the primary's field set)",
			req.SourceNodeAddr, "src-node-adr0406")
	}
	if req.SourceFreezeTimestampNs != 0x0BADC0DE {
		t.Errorf("SourceFreezeTimestampNs = %#x, want %#x (fallback must mirror the primary's field set)",
			req.SourceFreezeTimestampNs, 0x0BADC0DE)
	}

	// The four fields that were already correct on the fallback path.
	if req.MigrationName == "" || req.CheckpointRef == "" || req.DestNetnsFd == "" ||
		req.TcpPreservationMode != string(pmv1.TCPPreservationModeStrict) {
		t.Errorf("baseline fields regressed: MigrationName=%q CheckpointRef=%q DestNetnsFd=%q TcpPreservationMode=%q",
			req.MigrationName, req.CheckpointRef, req.DestNetnsFd, req.TcpPreservationMode)
	}

	// ADR-0406 D1: RelayIfname must stay UNSET — the agent self-resolves it via
	// discoverHostInterface (ADR-0357 D1.5). Forcing a literal here would reintroduce that defect.
	if req.RelayIfname != "" {
		t.Errorf("RelayIfname = %q, want empty — the fallback must leave it agent-discovered exactly "+
			"as the primary does; a literal (e.g. flannel.1) reintroduces the ADR-0357 D1.5 defect",
			req.RelayIfname)
	}
}

// TestADR0406_FallbackNoSnapshotsNoSeed proves the change is inert on a stateless migration:
// with no source snapshots the fallback carries an empty SeqSnapshots slice, so the agent's seed
// guard stays correctly false and no seed is forced on a None-mode / zero-connection migration.
func TestADR0406_FallbackNoSnapshotsNoSeed(t *testing.T) {
	req := adr0406DriveFallback(t, nil)

	if len(req.SeqSnapshots) != 0 {
		t.Fatalf("NRI-fallback RestoreRequest.SeqSnapshots len = %d, want 0 — with no source snapshots "+
			"the change must add nothing; seeding is only introduced when there is something to seed",
			len(req.SeqSnapshots))
	}
}

// TestADR0406_BuildRestoreSeqSnapshots_ConversionFidelity locks the single-authority conversion
// helper both restore call sites (and the VerifyTCP source-snapshot thread) now route through
// (ADR-0406 §D1 shared-helper requirement, resolving the Arch-B CONDITIONAL). Because both the
// primary (reconcileRestoring) and the fallback (reconcileRestoringNRI) call this exact function,
// the two call sites produce identical requests for the same input by construction, not by
// test-enforced coincidence — a future SeqSnapshot proto field added here reaches both sites.
func TestADR0406_BuildRestoreSeqSnapshots_ConversionFidelity(t *testing.T) {
	// Empty status → nil (leaves the agent seed guard false).
	if out := buildRestoreSeqSnapshots(&pmv1.PodMigration{}); out != nil {
		t.Fatalf("buildRestoreSeqSnapshots(empty) = %v, want nil", out)
	}

	snaps := []pmv1.TCPSeqSnapshot{
		{SrcIP: "1.2.3.4", SrcPort: 111, DstIP: "5.6.7.8", DstPort: 222, SndNxt: 0xDEADBEEF, RcvNxt: 0xFEEDFACE, TsRecent: 7},
	}
	pm := &pmv1.PodMigration{Status: pmv1.PodMigrationStatus{TCPSeqSnapshots: snaps}}
	out := buildRestoreSeqSnapshots(pm)
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	g, w := out[0], snaps[0]
	if g.SrcIp != w.SrcIP || g.SrcPort != w.SrcPort || g.DstIp != w.DstIP || g.DstPort != w.DstPort ||
		g.SndNxt != w.SndNxt || g.RcvNxt != w.RcvNxt || g.TsRecent != w.TsRecent {
		t.Fatalf("conversion = %+v, want all 7 fields from %+v (incl. TsRecent)", g, w)
	}
}
