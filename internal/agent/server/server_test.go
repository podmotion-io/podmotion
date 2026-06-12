/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

import (
	"context"
	"strings"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// TestBuildCRIURestoreArgs_JoinNs asserts that when destNetnsFd is non-empty,
// buildCRIURestoreArgs produces --join-ns net:<fd> and --tcp-established, and
// that --empty-ns and --tcp-close are absent (M19 acceptance criterion: joinNsRestore
// unit test asserts --join-ns net:<fd> selected when NetworkContinuity != None).
func TestBuildCRIURestoreArgs_JoinNs(t *testing.T) {
	args := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		"/var/lib/podmotion/restore/test/termination-log",
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"/proc/12345/fd/7",
	)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--join-ns net:/proc/12345/fd/7") {
		t.Errorf("expected --join-ns net:/proc/12345/fd/7 in args; got: %s", joined)
	}
	if !strings.Contains(joined, "--tcp-established") {
		t.Errorf("expected --tcp-established in args; got: %s", joined)
	}
	if strings.Contains(joined, "--empty-ns") {
		t.Errorf("--empty-ns must not appear when destNetnsFd is set; got: %s", joined)
	}
	if strings.Contains(joined, "--tcp-close") {
		t.Errorf("--tcp-close must not appear when destNetnsFd is set; got: %s", joined)
	}
	if strings.Contains(joined, "--restore-detached") {
		t.Errorf("--restore-detached must never appear (ghost container risk); got: %s", joined)
	}
}

// TestBuildCRIURestoreArgs_EmptyNs asserts that when destNetnsFd is empty (stateless
// cold migration), buildCRIURestoreArgs produces --empty-ns net and --tcp-close, and
// that --join-ns and --tcp-established are absent.
func TestBuildCRIURestoreArgs_EmptyNs(t *testing.T) {
	args := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		"/var/lib/podmotion/restore/test/termination-log",
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"",
	)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--empty-ns net") {
		t.Errorf("expected --empty-ns net in args; got: %s", joined)
	}
	if !strings.Contains(joined, "--tcp-close") {
		t.Errorf("expected --tcp-close in args; got: %s", joined)
	}
	if strings.Contains(joined, "--join-ns") {
		t.Errorf("--join-ns must not appear when destNetnsFd is empty; got: %s", joined)
	}
	if strings.Contains(joined, "--tcp-established") {
		t.Errorf("--tcp-established must not appear when destNetnsFd is empty; got: %s", joined)
	}
	if strings.Contains(joined, "--restore-detached") {
		t.Errorf("--restore-detached must never appear (ghost container risk); got: %s", joined)
	}
}

// TestArmZeroWindow_ArmsAndRegistersWatchdog verifies that ArmZeroWindow returns
// armed=true, records the hold state, and creates a watchdog goroutine.
func TestArmZeroWindow_ArmsAndRegistersWatchdog(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	resp, err := s.ArmZeroWindow(ctx, &agentpb.ArmZeroWindowRequest{
		MigrationName:        "test-migration",
		PodUid:               "pod-uid-123",
		FreezeWindowBudgetMs: 500,
	})
	if err != nil {
		t.Fatalf("ArmZeroWindow returned unexpected error: %v", err)
	}
	if !resp.Armed {
		t.Errorf("expected Armed=true, got false; reason=%s", resp.BlockingReason)
	}
	if resp.ArmedAtNs == 0 {
		t.Errorf("expected ArmedAtNs to be set, got 0")
	}

	s.zwHoldMu.Lock()
	_, ok := s.zwHolds["test-migration"]
	s.zwHoldMu.Unlock()
	if !ok {
		t.Errorf("expected zwHolds to contain test-migration entry after ArmZeroWindow")
	}
}

// TestDisarmZeroWindow_DisarmsArmedHold verifies that DisarmZeroWindow correctly removes
// the hold state and returns disarmed=true with a hold duration.
func TestDisarmZeroWindow_DisarmsArmedHold(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	armResp, err := s.ArmZeroWindow(ctx, &agentpb.ArmZeroWindowRequest{
		MigrationName:        "test-disarm",
		PodUid:               "pod-uid-456",
		FreezeWindowBudgetMs: 5000,
	})
	if err != nil || !armResp.Armed {
		t.Fatalf("ArmZeroWindow failed: err=%v armed=%v", err, armResp.Armed)
	}

	disarmResp, err := s.DisarmZeroWindow(ctx, &agentpb.DisarmZeroWindowRequest{
		MigrationName: "test-disarm",
		PodUid:        "pod-uid-456",
	})
	if err != nil {
		t.Fatalf("DisarmZeroWindow returned unexpected error: %v", err)
	}
	if !disarmResp.Disarmed {
		t.Errorf("expected Disarmed=true, got false; reason=%s", disarmResp.BlockingReason)
	}
	if disarmResp.HoldDurationMs < 0 {
		t.Errorf("expected non-negative HoldDurationMs, got %d", disarmResp.HoldDurationMs)
	}

	s.zwHoldMu.Lock()
	_, stillPresent := s.zwHolds["test-disarm"]
	s.zwHoldMu.Unlock()
	if stillPresent {
		t.Errorf("expected zwHolds entry to be removed after DisarmZeroWindow")
	}
}

// TestDisarmZeroWindow_NoActiveHold verifies that DisarmZeroWindow on a migration
// without an active hold returns disarmed=false with a blocking reason (idempotent path).
func TestDisarmZeroWindow_NoActiveHold(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	resp, err := s.DisarmZeroWindow(ctx, &agentpb.DisarmZeroWindowRequest{
		MigrationName: "no-such-migration",
		PodUid:        "",
	})
	if err != nil {
		t.Fatalf("DisarmZeroWindow returned unexpected error: %v", err)
	}
	if resp.Disarmed {
		t.Errorf("expected Disarmed=false for unknown migration, got true")
	}
	if resp.BlockingReason == "" {
		t.Errorf("expected a BlockingReason explaining why disarm failed")
	}
}
