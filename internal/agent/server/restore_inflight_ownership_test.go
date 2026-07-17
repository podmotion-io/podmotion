/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

// restore_inflight_ownership_test.go — regression guard for ADR-0353 (single-owner in-flight
// restore claim). Drives the real AgentServer claim/CRIU-chokepoint code with joinNsRestoreFn
// stubbed only to block/unblock the not-yet-alive window — not a synthetic re-implementation of
// claimRestore/releaseRestore.

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// TestRestoreInFlightSingleOwner_NotYetAliveRace is the core race test (T1). An NRI-path restore
// acquires the claim and blocks mid-CRIU; a concurrent gRPC Restore for the SAME migration MUST
// NOT drive a second CRIU exec and MUST return the transient ErrRestoreInFlight decline
// (codes.Aborted). Fails before the fix (no lock -> two CRIU execs / double-drive), passes after.
func TestRestoreInFlightSingleOwner_NotYetAliveRace(t *testing.T) {
	const migName = "test-inflight-race"

	criuCallCount := int32(0)
	unblock := make(chan struct{})
	entered := make(chan struct{})

	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, _, _, _, _, _, _, _ string, _ bool, _ []reattachMount, _, _, _ string) (int, []ExternalMountDroppedInfo, error) {
		atomic.AddInt32(&criuCallCount, 1)
		close(entered) // signal the NRI call has entered CRIU (claim is held, not-yet-alive)
		<-unblock      // hold the not-yet-alive window open until the test unblocks it
		return 4242, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	origMAC := readReplVethMACFn
	readReplVethMACFn = func(context.Context, int, string, string) (string, error) { return "aa:bb:cc:dd:ee:ff", nil }
	defer func() { readReplVethMACFn = origMAC }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)

	// ADR-0215/ADR-0217 fail-close: JoinNsRestore requires a resolvable workload image before it
	// will call joinNsRestoreFn. Seed the PrepareDestinationNetns cache the same way production
	// does so image resolution succeeds and the real claim/chokepoint code actually runs.
	s.destWorkloadImageMu.Lock()
	s.destWorkloadImage[migName] = "docker.io/library/redis:7-alpine"
	s.destWorkloadImageMu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// NRI path — k8sClient is nil so ReportRestoreConfirmed inside JoinNsRestore is a
		// non-fatal no-op path per its own nil-guard; the test only asserts CRIU-call symmetry.
		_, _, _ = s.JoinNsRestore(migName, "default", "/tmp/does-not-matter", "", "container-1", "sandbox-1", "", "", "None")
	}()

	<-entered // wait until the NRI restore is genuinely mid-CRIU (claim held, not confirmed)

	resp, err := s.Restore(context.Background(), &agentpb.RestoreRequest{
		MigrationName: migName,
		CheckpointRef: t.TempDir(), // no inventory.img — irrelevant, the claim decline returns first
	})
	if resp != nil {
		t.Fatalf("expected nil response on ErrRestoreInFlight decline, got %+v", resp)
	}
	if err == nil {
		t.Fatal("expected ErrRestoreInFlight (codes.Aborted), got nil error")
	}
	if got := status.Code(err); got != codes.Aborted {
		t.Fatalf("expected codes.Aborted (ADR-0353 R5), got %v (err=%v)", got, err)
	}

	close(unblock)
	wg.Wait()

	if got := atomic.LoadInt32(&criuCallCount); got != 1 {
		t.Fatalf("expected exactly ONE CRIU-restore exec against the destination, got %d", got)
	}
}

// TestJoinNsRestore_PanicsWithoutClaim is the direct R2/D2 discharge test: joinNsRestore (the
// package-level CRIU-drive chokepoint) MUST fail loud if entered with no claim held for the
// migration — this is the self-checking invariant that catches any future call site that
// bypasses claimRestore, per ADR-0353 R2.
func TestJoinNsRestore_PanicsWithoutClaim(t *testing.T) {
	const migName = "test-inflight-no-claim-panic"

	// Sanity: no claim is held for this migration name.
	if isRestoreClaimed(migName) {
		t.Fatal("setup invariant violated: claim unexpectedly already held")
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected joinNsRestore to panic when entered with no restore claim held (ADR-0353 R2)")
		}
	}()

	// Call the real chokepoint function directly (bypassing claimRestore) to prove the entry
	// assertion fires. Arguments beyond migrationName are irrelevant — the assertion is the
	// very first statement in the function body.
	_, _, _ = joinNsRestore(context.Background(), migName, "/tmp/does-not-matter", "", "", "", "", "", false, nil, "", "", "")
}

// TestRestoreInFlight_ReleasedOnCompletionAndFailure is T2 (R4/R6): the claim is absent after a
// simulated success AND after a simulated failure, and a fresh claimRestore for the same key
// succeeds afterward (the retry is not wedged).
func TestRestoreInFlight_ReleasedOnCompletionAndFailure(t *testing.T) {
	const migName = "test-inflight-release"

	if !claimRestore(migName, "gRPC") {
		t.Fatal("claimRestore on empty registry must succeed")
	}
	releaseRestore(migName)
	if isRestoreClaimed(migName) {
		t.Fatal("claim must be absent after releaseRestore (simulated success leg)")
	}
	if !claimRestore(migName, "gRPC") {
		t.Fatal("re-claim after release must succeed — retry must not be wedged (R6)")
	}
	releaseRestore(migName)

	// Simulated failure leg: acquire, then release via the same unconditional path a defer would
	// use (no distinction between success/failure release — R4 always releases).
	if !claimRestore(migName, "NRI") {
		t.Fatal("claimRestore must succeed on empty registry (failure-leg simulation)")
	}
	releaseRestore(migName)
	if isRestoreClaimed(migName) {
		t.Fatal("claim must be absent after releaseRestore (simulated failure leg)")
	}

	// releaseRestore must also be safe (idempotent) to call on an already-absent claim — every
	// defer path calls it unconditionally regardless of whether the acquire upstream succeeded.
	releaseRestore(migName)
	if isRestoreClaimed(migName) {
		t.Fatal("releaseRestore on an already-absent claim must remain a no-op")
	}
}

// TestRestoreInFlight_gRPCDeclineDoesNotZeroizeImages is T3 (R5, safety-critical): with an NRI
// restore claimed and mid-flight, a concurrent gRPC Restore returning ErrRestoreInFlight MUST
// leave the checkpoint tmpfs images dir intact.
func TestRestoreInFlight_gRPCDeclineDoesNotZeroizeImages(t *testing.T) {
	const migName = "test-inflight-nozeroize"

	if !claimRestore(migName, "NRI") {
		t.Fatal("setup: claimRestore must succeed")
	}
	defer releaseRestore(migName)

	imagesDir := t.TempDir()
	markerPath := filepath.Join(imagesDir, "inventory.img")
	if err := os.WriteFile(markerPath, []byte("CRIU\x00\x01"), 0o600); err != nil {
		t.Fatalf("write inventory.img marker: %v", err)
	}

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	resp, err := s.Restore(context.Background(), &agentpb.RestoreRequest{
		MigrationName: migName,
		CheckpointRef: imagesDir,
	})
	if resp != nil || err == nil {
		t.Fatalf("expected (nil, ErrRestoreInFlight), got (%+v, %v)", resp, err)
	}
	if status.Code(err) != codes.Aborted {
		t.Fatalf("expected codes.Aborted (ADR-0353 R5), got %v", status.Code(err))
	}
	if _, statErr := os.Stat(markerPath); statErr != nil {
		t.Fatalf("checkpoint images were zeroized/removed on an ErrRestoreInFlight decline — R5 violated: %v", statErr)
	}
}
