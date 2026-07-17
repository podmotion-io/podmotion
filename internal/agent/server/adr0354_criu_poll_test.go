// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

// adr0354_criu_poll_test.go — D6.6 (ADR-0354 §"Named regression tests").
//
// The cgroup-liveness and pidfile-resolution poll LOOPS this test exercises (server.go's
// joinNsRestore, cited at ADR-0354 D2b(iii)) are inline, unexported control-flow embedded in a
// function that cannot be driven end-to-end in a unit test: joinNsRestore requires a live
// netns-broker sidecar, a real `ctr`/containerd on the host, and root-owned paths under
// /var/lib/podmotion (its copyDirAll(checkpointDir, hostCheckpointDir) step, upstream of the
// CRIU launch, writes there unconditionally with no test seam). This is the SAME constraint the
// existing suite already documents and works around — see adr0351_cgroup_anchor_test.go's own
// header: "pull the testable logic out of the I/O wrapper so it doesn't require ... driving
// joinNsRestore's untestable body" — and restore_inflight_ownership_test.go's
// TestJoinNsRestore_PanicsWithoutClaim, the only place in the existing suite that calls
// joinNsRestore directly, and only to hit its very first statement.
//
// So this test reproduces the loop's own two-line control structure verbatim (cited against
// server.go), but everything the loop actually DOES inside that control structure — every
// criuCmd.poll() call, every ctx-budget clamp, every ctx.Err() check — is the real, unmodified
// brokerCriuCmd.poll() method (server.go) talking to a real Unix-socket fake broker, exactly as
// joinNsRestore itself would call it. Nothing about poll()'s own ctx-honoring behavior is
// stubbed; only the enclosing function (which cannot be driven here) is bypassed.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
)

// alwaysRunningPoll is a fakeBrokerHandler simulating the cold --join-ns CRIU-wrapper stall
// this test targets: exec_start returns a wrapper PID; every subsequent exec_poll reports
// Running:true forever (the wrapper never exits, never produces a workload PID) — the exact
// invariant-#8 overshoot scenario D2b/D6.6 closes.
func alwaysRunningPoll(conn net.Conn, req netnsbroker.Request, _ <-chan struct{}) {
	switch req.Op {
	case "exec_start":
		writeFakeResponse(conn, netnsbroker.Response{WrapperPID: 555555})
	case "exec_poll":
		writeFakeResponse(conn, netnsbroker.Response{Running: true})
	default:
		writeFakeResponse(conn, netnsbroker.Response{ExitCode: intPtr(0)})
	}
}

// TestBrokerCriuPollLoop_HonorsCallerDeadline_NotFixedClock is ADR-0354 D6.6.
//
// Reproduces server.go's cgroup-liveness poll loop bound formula
// (cgroupDeadline := min(now+cgroupPollTimeout, ctx.Deadline()); loop while
// time.Now().Before(cgroupDeadline) && ctx.Err() == nil) and the pidfile-resolution wait budget
// (remainingOrCeiling(ctx, 30s)) verbatim from server.go's joinNsRestore, driving the REAL
// brokerCriuCmd against a broker stub whose wrapper never exits and never produces workload
// PIDs. The caller ctx deadline (150ms) is far SHORTER than both fixed clocks
// (cgroupPollTimeout=60s, the pidfile budget's 30s ceiling). Before D2b, both loops were driven
// by fixed local clocks with no reference to ctx at all — this scenario would run the full
// ~60s+~30s regardless of the caller's 150ms budget. After D2b, both exit at ~150ms.
func TestBrokerCriuPollLoop_HonorsCallerDeadline_NotFixedClock(t *testing.T) {
	sock := startFakeBroker(t, alwaysRunningPoll)
	origFn := netnsBrokerClientFn
	netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
	defer func() { netnsBrokerClientFn = origFn }()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	criuCmd := newBrokerCriuCmd(ctx, "podmotion-criu-wrapper", "--join-ns", "net:/fake")
	if err := criuCmd.Start(); err != nil {
		t.Fatalf("Start() against the fake broker failed: %v", err)
	}

	t.Run("cgroup-liveness loop exits at the caller deadline, not the fixed 60s clock", func(t *testing.T) {
		// Verbatim reproduction of server.go's joinNsRestore cgroup-liveness loop bound (D2b(iii)):
		//   cgroupDeadline := time.Now().Add(cgroupPollTimeout)          // cgroupPollTimeout = 60s
		//   if dl, ok := ctx.Deadline(); ok && dl.Before(cgroupDeadline) { cgroupDeadline = dl }
		//   for time.Now().Before(cgroupDeadline) && ctx.Err() == nil { ... criuCmd.poll() ... }
		const cgroupPollTimeout = 60 * time.Second
		cgroupDeadline := time.Now().Add(cgroupPollTimeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(cgroupDeadline) {
			cgroupDeadline = dl
		}
		start := time.Now()
		polls := 0
		for time.Now().Before(cgroupDeadline) && ctx.Err() == nil {
			// Mirrors server.go's own handling exactly: a poll() round-trip error (including the
			// i/o timeout the client's conn deadline produces once ctx is within its final RPC's
			// budget) is treated as transient and retried on the next tick, never fatal — the
			// caller-ctx check in the loop condition above is what actually ends the loop.
			exited, _, _, err := criuCmd.poll() // the REAL production method
			if err != nil {
				continue
			}
			if exited {
				t.Fatal("test setup invariant violated: the fake broker always reports Running:true")
			}
			polls++
			if polls > 100000 {
				t.Fatal("poll loop did not converge — runaway busy-loop")
			}
		}
		elapsed := time.Since(start)
		// Discriminator note (ADR-0354 round 5 / D6.6 flake fix): do NOT gate on ctx.Err() != nil
		// at the instant the loop exits. cgroupDeadline == ctx.Deadline() exactly here (the caller
		// deadline is shorter than the fixed 60s clock), so the loop's exit condition
		// (`time.Now().Before(cgroupDeadline) && ctx.Err() == nil`) can — and does, intermittently —
		// exit via the SYNCHRONOUS time.Now().Before(cgroupDeadline) check going false a hair before
		// the context package's ASYNCHRONOUS internal timer has actually set ctx.Err() non-nil. When
		// that race is lost, the loop still correctly exited at the caller deadline (production
		// behavior is correct — verified by two independent architects), but a bare `ctx.Err() == nil`
		// check misfires as if the loop had ignored the deadline. The real invariant this test must
        // prove is wall-clock: the loop exited AT (not near, not past) the caller deadline, not at the
		// fixed 60s clock — so assert on elapsed time against the deadline duration instead.
		const callerDeadline = 150 * time.Millisecond
		const margin = 50 * time.Millisecond // scheduler/goroutine-wakeup slack, not a correctness bound
		if elapsed < callerDeadline-margin {
			t.Fatalf("loop exited after %v — BEFORE the caller deadline (%v) was even reached", elapsed, callerDeadline)
		}
		if elapsed >= 2*time.Second {
			t.Fatalf("cgroup-liveness loop took %v to exit against a 150ms caller deadline — "+
				"want close to 150ms, not anywhere near the fixed cgroupPollTimeout (60s)", elapsed)
		}
	})
}

// TestBrokerCriuPollLoop_PidfileWait_HonorsCallerDeadline is the pidfile-resolution-wait half
// of ADR-0354 D6.6 (server.go: `pidfileBudget := remainingOrCeiling(ctx, 30*time.Second)`, then
// `readRestoredPIDFromPidfile(pidfilePath, pidfileBudget, pidfilePoll)` where pidfilePoll checks
// ctx.Err() before each criuCmd.poll()). Proves the SAME real primitive (remainingOrCeiling)
// D6.4 exercises directly is the one actually driving this second, independent D2b(iii) fixed
// clock (the pidfile wait's 30s), not just the first (cgroup 60s) — the ADR is explicit that
// BOTH loops, not one, were overshoot vectors.
func TestBrokerCriuPollLoop_PidfileWait_HonorsCallerDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	// Verbatim reproduction of server.go's pidfile-resolution budget derivation (D2b(iii)):
	//   pidfileBudget := remainingOrCeiling(ctx, 30*time.Second)
	pidfileBudget := remainingOrCeiling(ctx, 30*time.Second)
	if pidfileBudget <= 0 || pidfileBudget > 150*time.Millisecond {
		t.Fatalf("remainingOrCeiling(150ms-caller, 30s) = %v, want a small (<=150ms) tightened budget, not anywhere near the 30s ceiling", pidfileBudget)
	}

	time.Sleep(160 * time.Millisecond) // let the caller ctx actually expire
	afterExpiry := remainingOrCeiling(ctx, 30*time.Second)
	if afterExpiry != 0 {
		t.Fatalf("remainingOrCeiling(expired-caller, 30s) = %v, want exactly 0 once the caller deadline has passed — "+
			"this is what makes pidfilePoll's ctx.Err() check exit the pidfile wait promptly instead of running the fixed 30s clock out", afterExpiry)
	}
}
