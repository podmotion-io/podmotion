// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

// adr0354_broker_cmd_test.go — D6.1, D6.4, D6.5, D6.9 (ADR-0354 §"Named regression tests").
// See docs/adr/0354-restore-broker-exec-caller-deadline-binding.md.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
	"github.com/podmotion-io/podmotion/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestBrokerCmdResult_HonorsCallerDeadline_AbortsNotFiveMinutes is ADR-0354 D6.1.
//
// Drives the REAL brokerCmd shim (nsenterCmd -> brokerCmd.result() -> netnsBrokerClientFn() ->
// netnsbroker.Client.Exec -> Client.do) against a fake broker that accepts the connection and
// never responds (a wedged exec on a stuck/degraded broker). The caller ctx carries a 50ms
// deadline. Before the D2 fix, result() rooted its own
// context.WithTimeout(context.Background(), brokerExecTimeout) — a FRESH 5-minute budget — so
// the caller's 50ms deadline was invisible to it and this call would still be blocked when this
// test's own bound fires. After D2, result()'s budget is derived from the caller ctx
// (brokerExecBudget = min(remaining(ctx), brokerExecTimeout)), so the exec aborts at ~50ms.
func TestBrokerCmdResult_HonorsCallerDeadline_AbortsNotFiveMinutes(t *testing.T) {
	sock := startFakeBroker(t, blockUntilDone)
	origFn := netnsBrokerClientFn
	netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
	defer func() { netnsBrokerClientFn = origFn }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	out, err := nsenterCmd(ctx, "true").Output()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected an error from a wedged broker exec, got success (out=%q)", out)
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("brokerCmd.result() took %v to abort a wedged exec with a 50ms caller deadline — "+
			"expected < 500ms (D2: budget derived from caller ctx, not the fresh 5-minute "+
			"brokerExecTimeout this test would otherwise have to wait out)", elapsed)
	}
}

// TestBrokerExecBudget_ClampMinNotWiden is ADR-0354 D6.4.
//
// Table test on the REAL remainingOrCeiling/brokerExecBudget/brokerCriuOpBudget helpers
// (server.go): a caller with less remaining budget than the ceiling gets its own (shorter)
// remaining budget; a caller with MORE remaining budget than the ceiling, or no deadline at
// all, is clamped DOWN to the ceiling — never widened past it. This is the mechanical proof
// that D2/D2b "can only tighten, never widen" the effective exec ceiling.
func TestBrokerExecBudget_ClampMinNotWiden(t *testing.T) {
	const ceiling = 30 * time.Second

	t.Run("caller with less remaining than ceiling: tightens to caller's remaining", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		got := remainingOrCeiling(ctx, ceiling)
		if got <= 0 || got > 3*time.Second || got < 2*time.Second {
			t.Fatalf("remainingOrCeiling(3s-remaining caller, 30s ceiling) = %v, want ~3s (tightened to caller budget)", got)
		}
	})

	t.Run("caller with more remaining than ceiling: clamped to ceiling, not widened", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
		defer cancel()
		got := remainingOrCeiling(ctx, ceiling)
		if got != ceiling {
			t.Fatalf("remainingOrCeiling(9m-remaining caller, 30s ceiling) = %v, want exactly the 30s ceiling (must clamp DOWN, never widen to the caller's 9m)", got)
		}
	})

	t.Run("caller with no deadline: the ceiling itself, never unbounded", func(t *testing.T) {
		got := remainingOrCeiling(context.Background(), ceiling)
		if got != ceiling {
			t.Fatalf("remainingOrCeiling(no-deadline caller, 30s ceiling) = %v, want exactly the 30s ceiling", got)
		}
	})

	t.Run("caller already past its deadline: clamps to zero, not negative", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), -1*time.Second)
		defer cancel()
		got := remainingOrCeiling(ctx, ceiling)
		if got != 0 {
			t.Fatalf("remainingOrCeiling(already-expired caller, 30s ceiling) = %v, want exactly 0 (never negative)", got)
		}
	})

	t.Run("brokerExecBudget mirrors remainingOrCeiling against brokerExecTimeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		got := brokerExecBudget(ctx)
		if got <= 0 || got > 3*time.Second {
			t.Fatalf("brokerExecBudget(3s caller) = %v, want <= 3s and > 0", got)
		}
		noDeadline := brokerExecBudget(context.Background())
		if noDeadline != brokerExecTimeout {
			t.Fatalf("brokerExecBudget(no-deadline caller) = %v, want exactly brokerExecTimeout (%v)", noDeadline, brokerExecTimeout)
		}
	})

	t.Run("brokerCriuOpBudget mirrors remainingOrCeiling against brokerCriuOpTimeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		got := brokerCriuOpBudget(ctx)
		if got <= 0 || got > 3*time.Second {
			t.Fatalf("brokerCriuOpBudget(3s caller) = %v, want <= 3s and > 0", got)
		}
		wide, cancel2 := context.WithTimeout(context.Background(), 9*time.Minute)
		defer cancel2()
		gotWide := brokerCriuOpBudget(wide)
		if gotWide != brokerCriuOpTimeout {
			t.Fatalf("brokerCriuOpBudget(9m caller) = %v, want clamped to brokerCriuOpTimeout (%v), never widened", gotWide, brokerCriuOpTimeout)
		}
	})
}

// TestBrokerExecCtxCancel_AbortsWedgedRead_NoDeadline is ADR-0354 D6.5 — the cancellation-
// dimension companion to D6.1 (which exercises the *deadline* dimension do() already honored
// before ADR-0354). Drives the REAL brokerCmd shim against a fake broker that reads the request
// then never writes a response line (a wedged ReadBytes, the "Abort while an exec is mid-flight"
// shape) with a caller ctx that carries NO deadline but is cancel()-led ~50ms in. Before DR-1's
// do() cancel-watcher, nothing in do() re-checked ctx.Done() after the dial — a cancelled ctx
// could not unblock a wedged read, so this exec would run to the fresh 5-minute
// brokerExecTimeout clamp regardless of cancellation. After DR-1's context.AfterFunc watcher,
// cancellation re-deadlines the conn immediately, cutting the read at ~cancel latency.
func TestBrokerExecCtxCancel_AbortsWedgedRead_NoDeadline(t *testing.T) {
	sock := startFakeBroker(t, blockUntilDone)
	origFn := netnsBrokerClientFn
	netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
	defer func() { netnsBrokerClientFn = origFn }()

	ctx, cancel := context.WithCancel(context.Background()) // NO deadline
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := nsenterCmd(ctx, "true").Output()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a wedged read aborted by ctx cancellation, got success")
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("brokerCmd.result() took %v to abort a wedged read after ~50ms cancellation — "+
			"expected < 500ms (DR-1: do()'s context.AfterFunc cancel watcher must unblock the "+
			"pending ReadBytes at cancel latency, not run to brokerExecTimeout)", elapsed)
	}
}

// TestBrokerDeadlineAbortMetric_DistinctFromBrokerError is ADR-0354 D6.9 (D7 observability
// guard). Drives (a) a caller-deadline-enforced abort and (b) a genuine broker-unreachable
// SpawnErr through the REAL brokerCmd.result() shim and asserts the D7
// BrokerExecDeadlineAbortsTotal counter increments ONLY for case (a) — proving the "the
// invariant-#8 guardrail fired as designed" signal is separable from "the broker genuinely
// failed," which post-incident review depends on.
func TestBrokerDeadlineAbortMetric_DistinctFromBrokerError(t *testing.T) {
	const leg = "broker_cmd"
	counter := metrics.BrokerExecDeadlineAbortsTotal.WithLabelValues(leg)

	t.Run("caller-deadline abort increments the counter", func(t *testing.T) {
		before := testutil.ToFloat64(counter)

		sock := startFakeBroker(t, blockUntilDone)
		origFn := netnsBrokerClientFn
		netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
		defer func() { netnsBrokerClientFn = origFn }()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := nsenterCmd(ctx, "true").Output()
		if err == nil {
			t.Fatal("expected an error from the deadline-wedged exec")
		}

		after := testutil.ToFloat64(counter)
		if after != before+1 {
			t.Fatalf("BrokerExecDeadlineAbortsTotal{leg=%q} = %v after a caller-deadline abort, want %v (before=%v)",
				leg, after, before+1, before)
		}
	})

	t.Run("broker-unreachable SpawnErr does NOT increment the counter", func(t *testing.T) {
		before := testutil.ToFloat64(counter)

		// Point at a socket path nothing listens on: a broker-unreachable failure, NOT a
		// caller-deadline abort. Ample ctx budget so the failure is unambiguously the dial
		// rejection, not a deadline race.
		origFn := netnsBrokerClientFn
		netnsBrokerClientFn = func() *netnsbroker.Client {
			return netnsbroker.NewClientForTesting("/nonexistent/adr0354-d69/broker.sock", 500*time.Millisecond, 2*time.Second)
		}
		defer func() { netnsBrokerClientFn = origFn }()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // ample budget
		defer cancel()
		out, err := nsenterCmd(ctx, "true").Output()
		if err == nil {
			t.Fatalf("expected an error dialing a nonexistent broker socket, got success (out=%q)", out)
		}
		if ctx.Err() != nil {
			t.Fatalf("test setup invariant violated: ctx expired (%v) before the dial-reject fired — "+
				"cannot distinguish broker-unreachable from a deadline abort", ctx.Err())
		}
		if !strings.Contains(err.Error(), "netns-broker exec") {
			t.Fatalf("expected a netns-broker exec error, got: %v", err)
		}

		after := testutil.ToFloat64(counter)
		if after != before {
			t.Fatalf("BrokerExecDeadlineAbortsTotal{leg=%q} = %v after a broker-unreachable SpawnErr (ample ctx budget), want unchanged %v — "+
				"the deadline-abort signal must never conflate with a genuine broker failure", leg, after, before)
		}
	})
}
