/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0210_probe_test.go — ADR-0210 cross-node ProbeDataplaneReachability unit tests:
//
//   - TestProbeDataplaneReachability_NoListener_NotReachable: dialing a closed port returns
//     reachable=false (negative control — no datapath / no nonce echo).
//   - TestProbeDataplaneReachability_NonceMismatch_NotReachable (QA-C6 self-loop regression):
//     a listener that does NOT echo the controller-issued nonce must NOT set reachable — the
//     source agent cannot synthesize success; a self-loop alone proves nothing.
//   - TestProbeDataplaneReachability_NonceRoundTrip_Reachable: only a correct nonce round-trip
//     yields reachable=true.
//   - TestVerifyTCPResponse_SeqDeltaFieldsPresent: compile-time plumbing proof that the measured
//     per-direction seq-delta fields exist on the proto response (controller reads these, not 0).

import (
	"context"
	"net"
	"testing"
	"time"

	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

func startEchoListener(t *testing.T, reply string) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			if reply != "" {
				_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write([]byte(reply))
			}
			_ = conn.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestProbeDataplaneReachability_NoListener_NotReachable(t *testing.T) {
	s := &AgentServer{}
	// Port 1 is reserved/closed — dial fails fast.
	resp, err := s.ProbeDataplaneReachability(context.Background(), &agentpb.ProbeDataplaneReachabilityRequest{
		MigrationName: "t", TargetIp: "127.0.0.1", TargetPort: 1, ExpectedNonce: "abc", TimeoutS: 1,
	})
	if err != nil {
		t.Fatalf("rpc err: %v", err)
	}
	if resp.Reachable {
		t.Fatal("expected reachable=false when no listener/datapath")
	}
}

func TestProbeDataplaneReachability_NonceMismatch_NotReachable(t *testing.T) {
	// QA-C6: a listener that answers but does NOT echo the controller nonce must NOT pass.
	ip, port := startEchoListener(t, "WRONG-NONCE")
	s := &AgentServer{}
	resp, err := s.ProbeDataplaneReachability(context.Background(), &agentpb.ProbeDataplaneReachabilityRequest{
		MigrationName: "t", TargetIp: ip, TargetPort: int32(port), ExpectedNonce: "expected-nonce", TimeoutS: 2,
	})
	if err != nil {
		t.Fatalf("rpc err: %v", err)
	}
	if resp.Reachable {
		t.Fatal("expected reachable=false on nonce mismatch (self-loop cannot synthesize success)")
	}
}

func TestProbeDataplaneReachability_NonceRoundTrip_Reachable(t *testing.T) {
	const nonce = "adr0210-correct-nonce"
	ip, port := startEchoListener(t, nonce)
	s := &AgentServer{}
	resp, err := s.ProbeDataplaneReachability(context.Background(), &agentpb.ProbeDataplaneReachabilityRequest{
		MigrationName: "t", TargetIp: ip, TargetPort: int32(port), ExpectedNonce: nonce, TimeoutS: 2,
	})
	if err != nil {
		t.Fatalf("rpc err: %v", err)
	}
	if !resp.Reachable {
		t.Fatalf("expected reachable=true on correct nonce round-trip; detail=%s", resp.Detail)
	}
}

func TestVerifyTCPResponse_SeqDeltaFieldsPresent(t *testing.T) {
	// Compile-time plumbing proof: the measured per-direction seq-delta fields exist and are
	// settable (controller populates the gauge/North Star from these, never a literal 0).
	resp := &agentpb.VerifyTCPResponse{SndSeqDeltaMax: 1448, RcvSeqDeltaMax: 0}
	if resp.SndSeqDeltaMax != 1448 || resp.RcvSeqDeltaMax != 0 {
		t.Fatal("VerifyTCPResponse measured seq-delta fields not plumbed")
	}
}
