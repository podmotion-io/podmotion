/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// repl_veth_mac_test.go — E1 regression tests for the path-independent MAC population
// contract (Conditions 1–3):
//
//   - TestJoinNsRestore_PopulatesMAC: stub ReadReplVethMAC returns a non-empty MAC;
//     assert finalizeRestore populates restoreResult.mac and that the MAC would be
//     passed to ReportRestoreConfirmed on the gRPC path.
//   - TestJoinNsRestore_EmptyMACStrictFails: stub returns "", mode=Strict;
//     assert finalizeRestore returns a non-nil error (fail-closed, Condition 3).
//   - TestJoinNsRestore_EmptyMACBestEffortDegrades: stub returns "", mode=BestEffort;
//     assert finalizeRestore returns nil error and continues (Condition 3).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
)

// TestJoinNsRestore_PopulatesMAC asserts that finalizeRestore populates restoreResult.mac
// when readReplVethMACFn returns a non-empty MAC (E1 Condition 1).
// Verifies: the shared finalization primitive correctly captures the MAC so that all
// callers (gRPC + NRI) receive a non-empty MAC to pass to ReportRestoreConfirmed.
func TestJoinNsRestore_PopulatesMAC(t *testing.T) {
	const wantMAC = "aa:bb:cc:dd:ee:ff"

	// Inject stub: always returns the expected MAC.
	orig := readReplVethMACFn
	readReplVethMACFn = func(_ context.Context, pid int, netnsPath, ifname string) (string, error) {
		return wantMAC, nil
	}
	defer func() { readReplVethMACFn = orig }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	// k8sClient is nil — finalizeRestore skips k8s operations but must still populate mac.
	result, err := s.finalizeRestore(context.Background(), 12345, "/var/run/netns/test", "eth0", "test-migration", "", "None", "", "")
	if err != nil {
		t.Fatalf("finalizeRestore returned unexpected error: %v", err)
	}
	if result.mac != wantMAC {
		t.Errorf("expected result.mac=%q, got %q", wantMAC, result.mac)
	}
}

// TestJoinNsRestore_EmptyMACStrictFails asserts that finalizeRestore returns a non-nil
// error when ReadReplVethMAC returns "" and mode=Strict (E1 Condition 3 fail-closed path).
// ADR-0012: the error propagation causes the controller to roll back; the source pod is
// preserved because source deletion is gated on TrafficVerified=True.
func TestJoinNsRestore_EmptyMACStrictFails(t *testing.T) {
	orig := readReplVethMACFn
	readReplVethMACFn = func(_ context.Context, pid int, netnsPath, ifname string) (string, error) {
		return "", errors.New("stub: nsenter failed")
	}
	defer func() { readReplVethMACFn = orig }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	_, err := s.finalizeRestore(context.Background(), 12345, "/var/run/netns/test", "eth0", "test-migration", "", "Strict", "", "")
	if err == nil {
		t.Fatal("expected non-nil error for Strict mode with empty MAC, got nil")
	}
	if !strings.Contains(err.Error(), "path-independent contract violation") {
		t.Errorf("expected error to mention 'path-independent contract violation'; got: %v", err)
	}
}

// TestJoinNsRestore_EmptyMACBestEffortDegrades asserts that finalizeRestore returns nil
// when ReadReplVethMAC returns "" and mode=BestEffort — degrade-and-continue (Condition 3).
// The restoreResult.mac is empty but no error is surfaced; the controller observes the
// queryable CR-status condition set by finalizeRestore (when k8s client is available).
func TestJoinNsRestore_EmptyMACBestEffortDegrades(t *testing.T) {
	orig := readReplVethMACFn
	readReplVethMACFn = func(_ context.Context, pid int, netnsPath, ifname string) (string, error) {
		return "", errors.New("stub: nsenter failed")
	}
	defer func() { readReplVethMACFn = orig }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	result, err := s.finalizeRestore(context.Background(), 12345, "/var/run/netns/test", "eth0", "test-migration", "", "BestEffort", "", "")
	if err != nil {
		t.Fatalf("BestEffort mode: expected nil error on empty MAC, got: %v", err)
	}
	// MAC should be empty (no stub returned one), but no error.
	if result.mac != "" {
		t.Errorf("expected empty mac for BestEffort degraded path, got %q", result.mac)
	}
}
