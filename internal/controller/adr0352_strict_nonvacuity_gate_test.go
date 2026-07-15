/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0352_strict_nonvacuity_gate_test.go is the falsifiable regression proof for the ADR-0352
// B8-DR-2 / D6(i) / DR-23 Strict NON-VACUITY guard added to reconcileTCPVerifying.
//
// The defect this closes (Validation cycle 1, live-migration-race lens): under Strict,
// VerifyTCP's stateless fast path returns Verified=true with ConnectionsExpected=0 when there
// were no source SeqSnapshots and no destination ESTABLISHED sockets. The controller gate
// previously inferred TCP continuity from a trivially-true measuredSeqDelta==0 and never read
// the authoritative connection count, so a Strict migration that preserved ZERO connections
// reached Complete — a vacuous proof that authorises source-pod deletion without ever exercising
// the preservation datapath (the exact "0/0 connections" completion the panel declared a FAIL).
//
// The guard reads vtcpResp.ConnectionsExpected / ConnectionsVerified directly and fails closed.
// This test drives reconcileTCPVerifying through a real AgentClientPool + gRPC spy so the fix is
// falsifiable in BOTH directions: a 0/0 response must roll back; a real held-connection response
// must pass. A future refactor that reintroduces the vacuity goes red here instead of shipping a
// byte-identical green.

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// spyVerifyTCPAgentServer is a minimal MigrationAgentService stub that returns a canned
// VerifyTCPResponse, so the test can drive reconcileTCPVerifying through the real AgentClientPool
// dial path and assert the controller's Strict non-vacuity POLICY (mode-specific, controller-side)
// directly — VerifyTCP itself is mode-agnostic and correctly reports 0/0 as an honest fact.
type spyVerifyTCPAgentServer struct {
	agentpb.UnimplementedMigrationAgentServiceServer
	resp *agentpb.VerifyTCPResponse
}

func (s *spyVerifyTCPAgentServer) VerifyTCP(context.Context, *agentpb.VerifyTCPRequest) (*agentpb.VerifyTCPResponse, error) {
	return s.resp, nil
}

func TestReconcileTCPVerifying_StrictNonVacuityGate(t *testing.T) {
	cases := []struct {
		name          string
		resp          *agentpb.VerifyTCPResponse
		wantPhase     pmv1.MigrationPhase
		wantCondFalse bool
		wantReason    string
	}{
		{
			// The stateless VerifyTCP fast path: Verified=true but ConnectionsExpected=0.
			// Under Strict this is a vacuous proof and MUST fail closed to rollback.
			name:          "vacuous_0_of_0_fails_closed_to_rollback",
			resp:          &agentpb.VerifyTCPResponse{Verified: true, ConnectionsVerified: 0, ConnectionsExpected: 0},
			wantPhase:     pmv1.MigrationPhaseRollingBack,
			wantCondFalse: true,
			wantReason:    "VacuousTCPProof",
		},
		{
			// A genuine held connection: ConnectionsExpected>0, all verified, seq_delta==0.
			// The guard must NOT over-fire — this proceeds to ServiceVerifying.
			name:          "real_held_connection_passes_to_serviceverifying",
			resp:          &agentpb.VerifyTCPResponse{Verified: true, ConnectionsVerified: 2, ConnectionsExpected: 2, SndSeqDeltaMax: 0, RcvSeqDeltaMax: 0},
			wantPhase:     pmv1.MigrationPhaseServiceVerifying,
			wantCondFalse: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer lis.Close()

			serverCert := adr0351SelfSignedServerCert(t)
			spy := &spyVerifyTCPAgentServer{resp: tc.resp}
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

			const destNode = "dst-node-nonvacuity"
			const ns = "default"
			const migName = "pm-strict-nonvacuity"

			// Running agent pod on destNode at 127.0.0.1 so AgentClientPool.ForNode resolves to the spy.
			agentPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podmotion-agent-dst",
					Namespace: "podmotion-system",
					Labels:    map[string]string{"app": "podmotion-agent"},
				},
				Spec:   corev1.PodSpec{NodeName: destNode},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
			}
			// Replacement pod carrying the migration-name label so resolveReplacementPodByLabel
			// returns a pod with a non-empty UID (the dest PID-resolution source of truth).
			replacementPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "repl-pod-nonvacuity",
					Namespace: ns,
					UID:       "uid-repl-nonvacuity",
					Labels:    map[string]string{replacementPodMigrationNameLabel: migName},
				},
				Spec:   corev1.PodSpec{NodeName: destNode},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.55"},
			}
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: ns},
				Spec: pmv1.PodMigrationSpec{
					PodName:             "src-pod-nonvacuity",
					PodNamespace:        ns,
					TCPPreservationMode: pmv1.TCPPreservationModeStrict,
					TargetNodeName:      destNode,
				},
				Status: pmv1.PodMigrationStatus{
					Phase:               pmv1.MigrationPhaseTCPVerifying,
					DestinationNodeName: destNode,
					ReplacementPodName:  "repl-pod-nonvacuity",
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

			ctx := context.Background()
			if _, err := r.reconcileTCPVerifying(ctx, pm); err != nil {
				t.Fatalf("reconcileTCPVerifying returned error: %v", err)
			}

			got := &pmv1.PodMigration{}
			if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: migName}, got); err != nil {
				t.Fatalf("get pm: %v", err)
			}
			if got.Status.Phase != tc.wantPhase {
				t.Errorf("phase = %q, want %q", got.Status.Phase, tc.wantPhase)
			}
			cond := meta.FindStatusCondition(got.Status.Conditions, pmv1.ConditionTCPSequenceContinuityVerified)
			if tc.wantCondFalse {
				if cond == nil || cond.Status != metav1.ConditionFalse {
					t.Fatalf("TCPSequenceContinuityVerified = %+v, want status False — a Strict 0/0 (vacuous) proof MUST fail closed", cond)
				}
				if cond.Reason != tc.wantReason {
					t.Errorf("condition reason = %q, want %q", cond.Reason, tc.wantReason)
				}
			} else {
				if cond == nil || cond.Status != metav1.ConditionTrue {
					t.Fatalf("TCPSequenceContinuityVerified = %+v, want status True — a real held connection must pass the guard", cond)
				}
			}
		})
	}
}
