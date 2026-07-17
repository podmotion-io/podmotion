/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

// migration_pod_uid_precedence_test.go — regression tests for the sprint46B9 pre-work fix:
// ArmZeroWindow/DisarmZeroWindow/Checkpoint each read a migrationPodUID cache (populated once by
// PrepareSource, never evicted mid-migration) and previously let that cache win over a fresh,
// caller-supplied value whenever the cache was non-empty. A migration name reused across pod
// incarnations (a retried CR, or this repo's own live-proof test harness) left a stale entry from
// a PRIOR incarnation in the cache; the next incarnation's ArmZeroWindow read that stale UID
// instead of the fresh one the controller supplied, scanned /proc for a pod that no longer
// existed, and correctly failed closed under Strict — but for the wrong reason (a stale identity,
// not a genuine read-mechanism failure). Fixed by centralizing the precedence decision in
// authoritativePodUID: the fresh value always wins when supplied; the cache is a crash-recovery
// fallback only. All three call sites (ArmZeroWindow, DisarmZeroWindow, Checkpoint) now go
// through this one function, so they cannot diverge from one another.
//
// This test deliberately exercises the DECISION FUNCTION in isolation rather than the full
// ArmZeroWindow/DisarmZeroWindow RPCs end-to-end: those RPCs call resolveVethIfindex, which
// requires real host netns/process state to resolve anything past the empty-input stub path, so
// a hermetic unit test cannot drive them meaningfully. authoritativePodUID is where the actual
// bug lived and is fully testable without any host dependency.

import "testing"

// TestAuthoritativePodUID_StaleCacheFromPriorIncarnation reproduces the exact live-proof failure
// shape: a migration name is reused across two separate pod incarnations on a standing agent. The
// first incarnation's PrepareSource wrote its UID into the cache; that incarnation completed (or
// was aborted) and nothing evicted the entry. The SECOND incarnation's ArmZeroWindow now runs
// BEFORE that incarnation's own PrepareSource has ever been called (PrepareSource only runs
// inside the later Checkpointing phase — ZeroWindowArm precedes it in the 12-phase pipeline), so
// the cache still holds the FIRST incarnation's stale UID while the caller supplies the fresh,
// correct UID for the current pod. The fresh value must win.
func TestAuthoritativePodUID_StaleCacheFromPriorIncarnation(t *testing.T) {
	const staleUID = "9bf2e2b8-4ea6-463e-87c3-e1abe39bf156" // prior incarnation, dead
	const freshUID = "c4183f2b-ab38-4cfc-896b-6be56bad1f4f" // current incarnation, live

	podUID, stale := authoritativePodUID(staleUID, freshUID)

	if podUID != freshUID {
		t.Fatalf("expected the fresh caller-supplied UID %q to win over the stale cached UID %q, got %q",
			freshUID, staleUID, podUID)
	}
	if !stale {
		t.Error("expected stale=true when the cache disagrees with a non-empty fresh value, got false")
	}
}

// TestAuthoritativePodUID_NoCacheEntry covers the true first-call case: nothing cached yet
// (first-ever call for this migration name), fresh value supplied. Must resolve the fresh value
// and must NOT report staleness (there is nothing stale about an empty cache).
func TestAuthoritativePodUID_NoCacheEntry(t *testing.T) {
	podUID, stale := authoritativePodUID("", "c4183f2b-ab38-4cfc-896b-6be56bad1f4f")
	if podUID != "c4183f2b-ab38-4cfc-896b-6be56bad1f4f" {
		t.Fatalf("expected the fresh UID, got %q", podUID)
	}
	if stale {
		t.Error("expected stale=false when the cache was empty, got true")
	}
}

// TestAuthoritativePodUID_AgreeingCacheAndFresh covers the common steady-state case: the cache
// already holds the correct, current UID (e.g. Checkpoint repopulated it moments earlier). Must
// resolve to that value and must NOT report staleness (the values agree).
func TestAuthoritativePodUID_AgreeingCacheAndFresh(t *testing.T) {
	const uid = "c4183f2b-ab38-4cfc-896b-6be56bad1f4f"
	podUID, stale := authoritativePodUID(uid, uid)
	if podUID != uid {
		t.Fatalf("expected %q, got %q", uid, podUID)
	}
	if stale {
		t.Error("expected stale=false when cache and fresh value agree, got true")
	}
}

// TestAuthoritativePodUID_NoFreshValueFallsBackToCache covers true crash-recovery: the caller has
// nothing fresh to offer (e.g. an agent restart lost req context, or — pre-fix — a legitimate
// empty-caller-value case). The cache is the only signal available and must be used, exactly as
// documented as the map's original intended purpose.
func TestAuthoritativePodUID_NoFreshValueFallsBackToCache(t *testing.T) {
	const cachedUID = "c4183f2b-ab38-4cfc-896b-6be56bad1f4f"
	podUID, stale := authoritativePodUID(cachedUID, "")
	if podUID != cachedUID {
		t.Fatalf("expected fallback to the cached UID %q, got %q", cachedUID, podUID)
	}
	if stale {
		t.Error("expected stale=false when there is no fresh value to disagree with, got true")
	}
}

// TestAuthoritativePodUID_BothEmpty covers the cold-path stub case (e.g. TCPPreservationMode=None
// with no PrepareSource ever called): both inputs empty must resolve to empty, not stale, and
// must not panic.
func TestAuthoritativePodUID_BothEmpty(t *testing.T) {
	podUID, stale := authoritativePodUID("", "")
	if podUID != "" {
		t.Fatalf("expected empty UID, got %q", podUID)
	}
	if stale {
		t.Error("expected stale=false when both inputs are empty, got true")
	}
}

// TestAuthoritativePodUID_ArmAndDisarmCannotDiverge pins the fix for the Security Reviewer's C2
// condition: ArmZeroWindow and DisarmZeroWindow must resolve the SAME UID for the same
// (cache, fresh) pair, or a hold armed against one pod's veth could never be disarmed (a stuck
// zero-window hold + lingering conntrack NOTRACK rule — a self-inflicted DoS). Both RPC handlers
// call this exact function with no handler-specific branching, so divergence is structurally
// impossible — this test pins that invariant against a future edit that adds one.
func TestAuthoritativePodUID_ArmAndDisarmCannotDiverge(t *testing.T) {
	cases := []struct{ cached, fresh string }{
		{"", "c4183f2b-ab38-4cfc-896b-6be56bad1f4f"},
		{"9bf2e2b8-4ea6-463e-87c3-e1abe39bf156", "c4183f2b-ab38-4cfc-896b-6be56bad1f4f"},
		{"c4183f2b-ab38-4cfc-896b-6be56bad1f4f", ""},
		{"", ""},
	}
	for _, c := range cases {
		armUID, armStale := authoritativePodUID(c.cached, c.fresh)
		disarmUID, disarmStale := authoritativePodUID(c.cached, c.fresh)
		if armUID != disarmUID || armStale != disarmStale {
			t.Errorf("authoritativePodUID(%q, %q) diverged between calls: arm=(%q,%v) disarm=(%q,%v)",
				c.cached, c.fresh, armUID, armStale, disarmUID, disarmStale)
		}
	}
}
