// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 The PodMotion Authors

package server

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
)

// These tests pin the ADR-0325-remediation design (§3.2) hardening instrumentation added to
// resolvePodNetnsSandboxWaiting: on BOTH the success and fail-closed legs, the wait loop must
// report (migrationName, attempts, elapsed, resolved) via sandboxWaitObserveFn — the seam that
// lets a future session distinguish "genuinely never appeared in the budget" (a real defect) from
// "appeared on attempt N but we only tried once" (the one-shot-race bug the bounded wait itself,
// already present on main, was built to close — see adr0325_sandbox_wait_test.go). This does NOT
// change resolution behavior; it only proves the diagnostic facts are captured correctly, for both
// pod shapes the design's validation plan calls out (bare Deployment / no-Service, and
// Service-backed) — neither of which affects this resolver, which operates purely on the
// replacement pod's UID and is identical for both shapes, so a single fixture suffices here (the
// shape-dependent behavior is exercised by the existing end-to-end Restore()-level tests instead).

// (A) Success leg: sandbox appears after N losing probes — observe must report the correct
// attempt count, a resolved=true, and a bounded elapsed duration.
func TestResolvePodNetnsSandboxWaiting_Instrumentation_ReportsOnSuccess(t *testing.T) {
	const ns, migration, replUID = "pm-sbwait", "sbwait-instr-a", "reptest-instr-a-uid"
	cl := sandboxWaitFixture(t, ns, migration, replUID)
	s := New("pm-w2", &criu.StubCheckpointer{}, cl)

	origPoll := replacementSandboxPollInterval
	replacementSandboxPollInterval = 5 * time.Millisecond
	defer func() { replacementSandboxPollInterval = origPoll }()

	var calls int32
	origFn := sandboxIDForPodUIDFn
	sandboxIDForPodUIDFn = func(_ context.Context, podUID string) (string, error) {
		if atomic.AddInt32(&calls, 1) <= 2 {
			return "", errNoSandboxForPodUID
		}
		return "sandbox-" + podUID, nil
	}
	defer func() { sandboxIDForPodUIDFn = origFn }()

	var mu sync.Mutex
	var obsMigration string
	var obsAttempts int
	var obsElapsed time.Duration
	var obsResolved bool
	var obsCalled bool
	origObs := sandboxWaitObserveFn
	sandboxWaitObserveFn = func(migrationName string, attempts int, elapsed time.Duration, resolved bool) {
		mu.Lock()
		defer mu.Unlock()
		obsCalled = true
		obsMigration = migrationName
		obsAttempts = attempts
		obsElapsed = elapsed
		obsResolved = resolved
	}
	defer func() { sandboxWaitObserveFn = origObs }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id, attempted := s.resolvePodNetnsSandboxWaiting(ctx, migration)
	if !attempted || id == "" {
		t.Fatalf("resolvePodNetnsSandboxWaiting returned (id=%q, attempted=%v), want a resolved id", id, attempted)
	}

	mu.Lock()
	defer mu.Unlock()
	if !obsCalled {
		t.Fatal("sandboxWaitObserveFn was never invoked on the success leg")
	}
	if obsMigration != migration {
		t.Errorf("observed migration = %q, want %q", obsMigration, migration)
	}
	if !obsResolved {
		t.Error("observed resolved = false, want true (the sandbox DID resolve)")
	}
	// calls>=3: two losing probes + the winning one; the observed attempt count must match the
	// real number of resolver invocations, not a hardcoded 1.
	wantAttempts := int(atomic.LoadInt32(&calls))
	if obsAttempts != wantAttempts {
		t.Errorf("observed attempts = %d, want %d (must equal the real resolver call count)", obsAttempts, wantAttempts)
	}
	if obsAttempts < 3 {
		t.Errorf("observed attempts = %d, want >=3 (proves the loop actually retried across the race)", obsAttempts)
	}
	if obsElapsed <= 0 {
		t.Error("observed elapsed <= 0, want a positive duration")
	}
}

// (B) Fail-closed leg: sandbox never appears — observe must report resolved=false and an elapsed
// duration bounded by (roughly) the wait budget, proving the instrumentation fires on the failure
// path too, not just on success.
func TestResolvePodNetnsSandboxWaiting_Instrumentation_ReportsOnFailClosed(t *testing.T) {
	const ns, migration, replUID = "pm-sbwait", "sbwait-instr-b", "reptest-instr-b-uid"
	cl := sandboxWaitFixture(t, ns, migration, replUID)
	s := New("pm-w2", &criu.StubCheckpointer{}, cl)

	origPoll, origBudget := replacementSandboxPollInterval, replacementSandboxWaitBudget
	replacementSandboxPollInterval = 5 * time.Millisecond
	replacementSandboxWaitBudget = 60 * time.Millisecond
	defer func() {
		replacementSandboxPollInterval = origPoll
		replacementSandboxWaitBudget = origBudget
	}()

	origFn := sandboxIDForPodUIDFn
	sandboxIDForPodUIDFn = func(context.Context, string) (string, error) { return "", errNoSandboxForPodUID }
	defer func() { sandboxIDForPodUIDFn = origFn }()

	var mu sync.Mutex
	var obsAttempts int
	var obsElapsed time.Duration
	var obsResolved, obsCalled bool
	origObs := sandboxWaitObserveFn
	sandboxWaitObserveFn = func(_ string, attempts int, elapsed time.Duration, resolved bool) {
		mu.Lock()
		defer mu.Unlock()
		obsCalled = true
		obsAttempts = attempts
		obsElapsed = elapsed
		obsResolved = resolved
	}
	defer func() { sandboxWaitObserveFn = origObs }()

	id, attempted := s.resolvePodNetnsSandboxWaiting(context.Background(), migration)
	if id != "" || !attempted {
		t.Fatalf("got (id=%q, attempted=%v), want ('', true) — must fail closed", id, attempted)
	}

	mu.Lock()
	defer mu.Unlock()
	if !obsCalled {
		t.Fatal("sandboxWaitObserveFn was never invoked on the fail-closed leg")
	}
	if obsResolved {
		t.Error("observed resolved = true, want false (the sandbox never appeared)")
	}
	if obsAttempts < 1 {
		t.Errorf("observed attempts = %d, want >=1", obsAttempts)
	}
	if obsElapsed > 2*time.Second {
		t.Errorf("observed elapsed = %s, want roughly bounded by the wait budget (%s)", obsElapsed, replacementSandboxWaitBudget)
	}
}
