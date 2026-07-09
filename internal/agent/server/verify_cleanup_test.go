/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// verify_cleanup_test.go — ADR-0284 GC-6 coverage for AgentServer.VerifyCleanup.
//
// These tests assert the RPC-level contract that does not require CAP_NET_ADMIN or a real overlay
// device: (1) input validation (old_pod_ip required + IPv4-only), (2) scope routing (unspecified/
// unknown scope => InvalidArgument), and (3) that a probe run against a sandbox with no flannel.1
// device produces a clean=true verdict for the netlink/route-absent probes and does not error the
// whole RPC (each probe's device-absent branch is treated as "object absent", not a fail-closed
// present). Probes whose external command is missing from the sandbox are fail-closed to present;
// the tests therefore assert only the non-present-forcing invariants that hold regardless of which
// of iptables/ip/tc/bridge happen to be installed in the test environment.

import (
	"context"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestVerifyCleanup_RequiresOldPodIP(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	_, err := s.VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-1",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for missing old_pod_ip, got %v (%v)", status.Code(err), err)
	}
}

func TestVerifyCleanup_RejectsIPv6(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	_, err := s.VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-1",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "fe80::1",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for IPv6 old_pod_ip, got %v (%v)", status.Code(err), err)
	}
}

func TestVerifyCleanup_UnspecifiedScopeRejected(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	_, err := s.VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-1",
		OldPodIp:      "10.244.1.7",
		// Scope left at CLEANUP_SCOPE_UNSPECIFIED.
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for unspecified scope, got %v (%v)", status.Code(err), err)
	}
}

// TestVerifyCleanup_IPReclaimUnknownDeviceIsClean asserts that the netlink/route/neigh probes,
// pointed at a device that does not exist in the sandbox, return a device-absent => object-absent
// verdict rather than erroring the RPC. It restricts the requested objects to the ones whose
// probe's device-absent branch is deterministic regardless of whether iptables happens to be
// installed (flannel1_route/neigh/fdb), so the assertion holds in any CI sandbox.
func TestVerifyCleanup_IPReclaimUnknownDeviceIsClean(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	resp, err := s.VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-1",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		FdbIfname:     "flannel.1-absent-in-sandbox",
		Objects:       []string{"flannel1_neigh", "flannel1_fdb"},
		ReplVethMac:   "", // empty MAC => fdb probe reports absent (best-effort)
	})
	if err != nil {
		t.Fatalf("VerifyCleanup returned unexpected RPC error: %v", err)
	}
	if !resp.Clean {
		t.Fatalf("expected clean=true against absent device with no MAC, got present=%v reason=%q",
			resp.PresentObjects, resp.BlockingReason)
	}
}

// TestVerifyCleanup_UnknownObjectFailsClosed asserts an unrecognized object identifier is counted
// as present (fail-closed), never silently dropped from the clean calculation.
func TestVerifyCleanup_UnknownObjectFailsClosed(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	resp, err := s.VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-1",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		Objects:       []string{"not_a_real_object"},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.Clean {
		t.Fatal("expected clean=false for an unknown object identifier (fail-closed)")
	}
	if len(resp.PresentObjects) != 1 || resp.PresentObjects[0] != "not_a_real_object" {
		t.Fatalf("expected the unknown object echoed in present_objects, got %v", resp.PresentObjects)
	}
}
