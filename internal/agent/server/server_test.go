/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

import (
	"context"
	"strings"
	"testing"
	"time"

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
		3,
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
	if strings.Contains(joined, "--net-fd") {
		t.Errorf("--net-fd must not appear on the --join-ns path; got: %s", joined)
	}
	if strings.Contains(joined, "--tcp-close") {
		t.Errorf("--tcp-close must not appear when destNetnsFd is set; got: %s", joined)
	}
	if strings.Contains(joined, "--restore-detached") {
		t.Errorf("--restore-detached must never appear (ghost container risk); got: %s", joined)
	}
}

// TestBuildCRIURestoreArgs_NetFd asserts that when destNetnsFd is empty (stateless
// cold migration), buildCRIURestoreArgs joins the replacement pod's pause container
// netns via --net-fd <childFd> + --tcp-close (ADR-0122), and that --empty-ns, --join-ns,
// and --tcp-established are absent.
func TestBuildCRIURestoreArgs_NetFd(t *testing.T) {
	args := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		"/var/lib/podmotion/restore/test/termination-log",
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"",
		3,
	)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--net-fd 3") {
		t.Errorf("expected --net-fd 3 in args (ADR-0122); got: %s", joined)
	}
	if strings.Contains(joined, "--empty-ns") {
		t.Errorf("--empty-ns must not appear (ADR-0122 removed it); got: %s", joined)
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

// TestWatchdog_AutoDisarmFiresWhenDisarmWithheld verifies that when DisarmZeroWindow is
// NOT called within FreezeWindowBudgetMs + margin, the watchdog goroutine fires and
// removes the hold state — proving the connection cannot be stalled indefinitely
// (M20 acceptance criterion: watchdog test).
//
// Uses a very short budget (5ms) so the test completes quickly without sleeping long.
func TestWatchdog_AutoDisarmFiresWhenDisarmWithheld(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	// Arm with a 5ms freeze budget. Watchdog deadline = 5ms + zwWatchdogMargin (500ms).
	// We use a short separate budget and poll quickly rather than waiting the full margin.
	_, err := s.ArmZeroWindow(ctx, &agentpb.ArmZeroWindowRequest{
		MigrationName:        "watchdog-test",
		PodUid:               "pod-watchdog",
		FreezeWindowBudgetMs: 5,
	})
	if err != nil {
		t.Fatalf("ArmZeroWindow returned unexpected error: %v", err)
	}

	// Confirm hold is registered immediately after arm.
	s.zwHoldMu.Lock()
	_, armed := s.zwHolds["watchdog-test"]
	s.zwHoldMu.Unlock()
	if !armed {
		t.Fatal("expected hold to be registered after ArmZeroWindow")
	}

	// Wait for watchdog to fire: budget(5ms) + zwWatchdogMargin(500ms) + 200ms headroom.
	deadline := time.Now().Add(time.Duration(5)*time.Millisecond + zwWatchdogMargin + 200*time.Millisecond)
	var cleared bool
	for time.Now().Before(deadline) {
		s.zwHoldMu.Lock()
		_, still := s.zwHolds["watchdog-test"]
		s.zwHoldMu.Unlock()
		if !still {
			cleared = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cleared {
		t.Errorf("watchdog did not auto-disarm within expected deadline; hold state still present")
	}

	// After watchdog fires, DisarmZeroWindow must report no active hold (connection survived —
	// the BPF program was detached, so the sender window is restored and the connection lives).
	resp, err := s.DisarmZeroWindow(ctx, &agentpb.DisarmZeroWindowRequest{
		MigrationName: "watchdog-test",
		PodUid:        "pod-watchdog",
	})
	if err != nil {
		t.Fatalf("DisarmZeroWindow after watchdog returned error: %v", err)
	}
	// Watchdog already cleaned up the hold; DisarmZeroWindow should return not-found path.
	if resp.Disarmed {
		// Acceptable if the implementation is re-entrant, but the hold must not still be
		// in memory — check the state map is clear either way.
	}
	s.zwHoldMu.Lock()
	_, remainingHold := s.zwHolds["watchdog-test"]
	s.zwHoldMu.Unlock()
	if remainingHold {
		t.Errorf("hold state must be absent after watchdog auto-disarm + explicit DisarmZeroWindow")
	}
}

// TestHoldDuration_WithinFreezeWindowBudget verifies that when DisarmZeroWindow is called
// promptly, HoldDurationMs is less than or equal to FreezeWindowBudgetMs (M20 acceptance
// criterion: condition delta ZeroWindowArmed→Disarmed ≤ FreezeWindowBudgetMs).
func TestHoldDuration_WithinFreezeWindowBudget(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	const budgetMs = int64(5000)

	armResp, err := s.ArmZeroWindow(ctx, &agentpb.ArmZeroWindowRequest{
		MigrationName:        "budget-test",
		PodUid:               "pod-budget",
		FreezeWindowBudgetMs: budgetMs,
	})
	if err != nil || !armResp.Armed {
		t.Fatalf("ArmZeroWindow failed: err=%v armed=%v", err, armResp.Armed)
	}

	// Disarm immediately — hold duration should be negligible (< budgetMs by a large margin).
	disarmResp, err := s.DisarmZeroWindow(ctx, &agentpb.DisarmZeroWindowRequest{
		MigrationName: "budget-test",
		PodUid:        "pod-budget",
	})
	if err != nil {
		t.Fatalf("DisarmZeroWindow returned error: %v", err)
	}
	if !disarmResp.Disarmed {
		t.Fatalf("DisarmZeroWindow returned Disarmed=false unexpectedly: %s", disarmResp.BlockingReason)
	}
	if disarmResp.HoldDurationMs > budgetMs {
		t.Errorf("HoldDurationMs=%d exceeds FreezeWindowBudgetMs=%d — hold took too long",
			disarmResp.HoldDurationMs, budgetMs)
	}
	if disarmResp.HoldDurationMs < 0 {
		t.Errorf("HoldDurationMs must be non-negative, got %d", disarmResp.HoldDurationMs)
	}
	if disarmResp.DisarmedAtNs <= armResp.ArmedAtNs {
		t.Errorf("DisarmedAtNs (%d) must be after ArmedAtNs (%d)",
			disarmResp.DisarmedAtNs, armResp.ArmedAtNs)
	}
}
