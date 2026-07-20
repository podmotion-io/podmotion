/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

// adr0357_conntrack_disarm_symmetry_test.go — ADR-0357 D3 / AC4 / §P-VERIFY assertion 3
// regression coverage: disarmConntrackNotrackForHold must be the ONE place that removes the
// ADR-0224 conntrack NOTRACK rule, called from BOTH the watchdog-fired path and
// DisarmZeroWindow's normal path — closing the leak where a watchdog-fired disarm reached
// disarmZeroWindowBPF but never network.DisarmConntrackNotrack.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/network"
)

// TestDisarmConntrackNotrackForHold_EmptyIPIsNoOp confirms the guard: an empty sourcePodIP
// (no NOTRACK was ever armed for this migration) must be a true no-op — the seam must not be
// invoked at all, not merely invoked-and-ignored.
func TestDisarmConntrackNotrackForHold_EmptyIPIsNoOp(t *testing.T) {
	origFn := disarmConntrackNotrackFn
	called := false
	disarmConntrackNotrackFn = func(context.Context, network.ConntrackNotrackRule) error {
		called = true
		return nil
	}
	defer func() { disarmConntrackNotrackFn = origFn }()

	disarmConntrackNotrackForHold(context.Background(), "mig-empty-ip", "")
	if called {
		t.Fatal("disarmConntrackNotrackForHold must not call the disarm seam when sourcePodIP is empty")
	}
}

// TestDisarmConntrackNotrackForHold_CallsSeamWithCorrectRule confirms the helper builds the
// same ConntrackNotrackRule shape (PodIP + "pm-notrack-<migration>" comment) the pre-extraction
// inline code used, and is warn-only: a seam error must not panic or propagate.
func TestDisarmConntrackNotrackForHold_CallsSeamWithCorrectRule(t *testing.T) {
	origFn := disarmConntrackNotrackFn
	var gotRule network.ConntrackNotrackRule
	calls := 0
	disarmConntrackNotrackFn = func(_ context.Context, rule network.ConntrackNotrackRule) error {
		calls++
		gotRule = rule
		return errors.New("injected: iptables -D failed") // warn-only path must tolerate this
	}
	defer func() { disarmConntrackNotrackFn = origFn }()

	disarmConntrackNotrackForHold(context.Background(), "mig-123", "10.0.0.9")

	if calls != 1 {
		t.Fatalf("expected the disarm seam called exactly once, got %d", calls)
	}
	if gotRule.PodIP != "10.0.0.9" {
		t.Errorf("PodIP = %q, want %q", gotRule.PodIP, "10.0.0.9")
	}
	if gotRule.Comment != "pm-notrack-mig-123" {
		t.Errorf("Comment = %q, want %q", gotRule.Comment, "pm-notrack-mig-123")
	}
}

// TestDisarmConntrackNotrackForHold_TwoNonTestCallSites is the literal §P-VERIFY assertion 3
// grep-verification this ADR requires: disarmConntrackNotrackForHold must have >=2 non-test
// call sites in server.go — the watchdog-fired goroutine (inside ArmZeroWindow) and
// DisarmZeroWindow's normal path — and there must be zero remaining inline duplicate of the
// extracted NOTRACK-disarm block (a second literal "network.DisarmConntrackNotrack(" call
// outside the helper's own definition would mean the extraction was incomplete).
func TestDisarmConntrackNotrackForHold_TwoNonTestCallSites(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "server.go"))
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	text := string(src)

	callSites := strings.Count(text, "disarmConntrackNotrackForHold(")
	// Each call site appears twice in the source: once as a call, once is NOT true here since
	// the function definition itself is "func disarmConntrackNotrackForHold(ctx context.Context"
	// which also contains the substring "disarmConntrackNotrackForHold(" — subtract 1 for the
	// definition itself.
	nonDefCallSites := callSites - 1
	if nonDefCallSites < 2 {
		t.Fatalf("expected >=2 non-test call sites of disarmConntrackNotrackForHold in server.go (watchdog + normal path), got %d (total occurrences including definition: %d)",
			nonDefCallSites, callSites)
	}

	// Zero remaining inline duplicate: network.DisarmConntrackNotrack must never be CALLED
	// directly anywhere in server.go — the only reference is the disarmConntrackNotrackFn var
	// initializer (a function-value assignment, not a call: "= network.DisarmConntrackNotrack",
	// no trailing "("). A literal call form "network.DisarmConntrackNotrack(" anywhere would
	// mean an inline duplicate of the extracted D3 block survived the refactor.
	if n := strings.Count(text, "network.DisarmConntrackNotrack("); n != 0 {
		t.Fatalf("expected zero direct-call references \"network.DisarmConntrackNotrack(\" in server.go (all calls must go through the disarmConntrackNotrackFn seam / disarmConntrackNotrackForHold helper) — a surviving inline duplicate of the extracted D3 block was found (%d occurrence(s))", n)
	}
	if !strings.Contains(text, "disarmConntrackNotrackFn = network.DisarmConntrackNotrack") {
		t.Fatal("expected the disarmConntrackNotrackFn seam to be initialized from network.DisarmConntrackNotrack exactly as documented")
	}
}
