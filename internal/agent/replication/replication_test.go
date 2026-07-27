/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package replication

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// erroringPreDumpAgent is a fake source-agent gRPC server whose PreDumpRound RPC always fails —
// simulating a transient network blip, agent-unreachable condition, or a decodeCRIUStats failure
// surfaced as a gRPC error, exactly the class of failure the MeasurementFailed path exists for.
type erroringPreDumpAgent struct {
	agentpb.UnimplementedMigrationAgentServiceServer
}

func (erroringPreDumpAgent) PreDumpRound(ctx context.Context, req *agentpb.PreDumpRoundRequest) (*agentpb.PreDumpRoundResponse, error) {
	return nil, fmt.Errorf("simulated PreDumpRound RPC failure (round %d)", req.RoundNumber)
}

func podNodeNameIndexer(obj client.Object) []string {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	return []string{pod.Spec.NodeName}
}

// startFakeSourceAgent brings up an in-process gRPC server (bufconn — no real network) backed by
// erroringPreDumpAgent, and returns a *grpc.ClientConn dialed against it plus a cleanup func.
func startFakeSourceAgent(t *testing.T) *grpc.ClientConn {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	agentpb.RegisterMigrationAgentServiceServer(srv, erroringPreDumpAgent{})
	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(srv.Stop)

	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	//nolint:staticcheck // grpc.DialContext deprecated but consistent with the production dial path
	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithInsecure(), //nolint:staticcheck // test-only, no TLS needed for bufconn
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestRunPreCopyLoop_PreDumpRoundError_PersistsMeasurementFailed is the QA-required end-to-end
// regression test: it drives RunPreCopyLoop against a REAL (bufconn, in-process) gRPC server whose
// PreDumpRound RPC always errors, through a REAL AgentClientPool resolving the agent address via a
// fake k8s client's pod lookup — not a hand-constructed metav1.Condition/PreCopyStats fixture —
// and asserts the resulting PodMigration.Status, read back from the fake controller-runtime
// client, actually has Reason=MeasurementFailed (pmv1.ReasonMemorySyncedMeasurementFailed) and
// PreCopyStats.DirtyStatsValid=false persisted. This closes a coverage gap:
// prior tests only verified the GATE's reading logic against independently re-typed literals, never
// that RunPreCopyLoop's actual RPC-failure branch really produces that state end-to-end.
func TestRunPreCopyLoop_PreDumpRoundError_PersistsMeasurementFailed(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("pmv1.AddToScheme: %v", err)
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-migration",
			Namespace: "default",
			UID:       types.UID("test-uid-1"),
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                 "test-pod",
			PodNamespace:            "default",
			TargetNodeName:          "worker-node-1",
			PreCopyMaxRounds:        5,
			PreCopyDirtyThresholdMB: 64,
		},
		Status: pmv1.PodMigrationStatus{
			SourceNodeName: "worker-node-1",
		},
	}

	// A running agent pod for worker-node-1 so AgentClientPool.ForNode resolves an address —
	// the actual dial target is swapped for the bufconn server via a custom AgentClientPool
	// constructed to reuse the already-established bufconn connection (see below); the pod's
	// PodIP/labels only need to satisfy resolveAgentPodIP's lookup so ForNode doesn't fall back
	// to the (absent) NMC lookup path.
	agentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podmotion-agent-worker1",
			Namespace: "podmotion-system",
			Labels:    map[string]string{"app": "podmotion-agent"},
		},
		Spec: corev1.PodSpec{NodeName: "worker-node-1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "127.0.0.1",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, agentPod).
		WithStatusSubresource(pm, agentPod).
		WithIndex(&corev1.Pod{}, "spec.nodeName", podNodeNameIndexer).
		Build()

	// Real bufconn gRPC server+conn backing the erroring PreDumpRound implementation.
	conn := startFakeSourceAgent(t)

	pool := agentclient.NewAgentClientPool(fakeClient, "9090", nil)
	// Pre-seed the pool's connection cache for "worker-node-1" with the bufconn connection so
	// RunPreCopyLoop's real srcClient.PreDumpRound call is served by erroringPreDumpAgent — this
	// exercises the exact production call path (AgentPool.ForNode -> MigrationAgentServiceClient
	// -> PreDumpRound) without needing a routable network address for the fake pod IP.
	agentclient.SeedConnForTest(pool, "worker-node-1", conn)

	rm := &ReplicationManager{
		Client:    fakeClient,
		AgentPool: pool,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := rm.RunPreCopyLoop(ctx, pm, nil); err != nil {
		t.Fatalf("RunPreCopyLoop returned unexpected error: %v", err)
	}

	// Read back status via the fake client — not the in-memory pm passed in — so this asserts
	// against what was actually persisted, mirroring how the controller reads it in production.
	got := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(pm), got); err != nil {
		t.Fatalf("get PodMigration after RunPreCopyLoop: %v", err)
	}

	cond := meta.FindStatusCondition(got.Status.Conditions, "MemorySynced")
	if cond == nil {
		t.Fatal("MemorySynced condition not persisted")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("MemorySynced.Status = %v, want True", cond.Status)
	}
	if cond.Reason != pmv1.ReasonMemorySyncedMeasurementFailed {
		t.Errorf("MemorySynced.Reason = %q, want %q", cond.Reason, pmv1.ReasonMemorySyncedMeasurementFailed)
	}

	if got.Status.PreCopyStats == nil {
		t.Fatal("PreCopyStats not persisted (nil) — expected explicit DirtyStatsValid=false record")
	}
	if got.Status.PreCopyStats.DirtyStatsValid {
		t.Error("PreCopyStats.DirtyStatsValid = true, want false: no real measurement backs a PreDumpRound RPC failure")
	}

	// End-to-end tie-in with the controller-side gate: this exact persisted state
	// (Reason=MeasurementFailed, DirtyStatsValid=false) must never be exempted by
	// preCopyTCPGatePassed's ForceFreeze branch — confirmed independently by
	// TestPreCopyTCPGatePassed_MeasurementFailedInterleaving in
	// internal/controller/precopy_tcp_gate_test.go, which this test's persisted-state shape now
	// has direct production-path provenance for.
}
