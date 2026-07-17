// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

// adr0354_rollback_test.go — D6.2 and D6.7 (ADR-0354 §"Named regression tests").
//
// Both drive the REAL fail-closed rollback leg: the ADR-0353 single-owner restore lock
// (claimRestore/releaseRestore/isRestoreClaimed — the actual production symbols, not a
// synthetic re-implementation) together with brokerCriuCmd.Signal(), the CRIU-wrapper kill
// D3/D2b names as "a member of the same fail-closed leg" governed by rollbackExecBudget. This
// is the one instance of the D3 rollback-context primitive
// (context.WithTimeout(context.WithoutCancel(ctx), rollbackExecBudget)) actually wired into the
// landed code (server.go's brokerCriuCmd.Signal()); the plain nsenterCmd placeholder-teardown
// execs in joinNsRestore's own defer still bind to the raw forward ctx rather than a
// WithoutCancel-derived rollback ctx — see the accompanying report for that separate finding.
//
// See docs/adr/0354-restore-broker-exec-caller-deadline-binding.md.

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
)

// execSignalRecorder returns a fakeBrokerHandler that, on receiving an exec_signal request,
// increments received, waits delay (respecting the harness's done channel), then responds
// success. Any other op gets an immediate exit-0 response (unused by these tests but keeps the
// handler generically safe).
func execSignalRecorder(received *int32, delay time.Duration) fakeBrokerHandler {
	return func(conn net.Conn, req netnsbroker.Request, done <-chan struct{}) {
		if req.Op != "exec_signal" {
			writeFakeResponse(conn, netnsbroker.Response{ExitCode: intPtr(0)})
			return
		}
		atomic.AddInt32(received, 1)
		select {
		case <-time.After(delay):
		case <-done:
			return
		}
		writeFakeResponse(conn, netnsbroker.Response{}) // exec_signal success: Error == ""
	}
}

// newTestCriuCmd builds a real brokerCriuCmd bound to ctx (mirroring newBrokerCriuCmd's own
// construction) and sets its wrapperPID directly (same-package field access — not exported,
// this test is a white-box regression test of this exact shim, matching the codebase's own
// established pattern of same-package field/const access in adr03NN_*_test.go files).
func newTestCriuCmd(ctx context.Context, wrapperPID int) *brokerCriuCmd {
	c := newBrokerCriuCmd(ctx, "podmotion-criu-wrapper", "--join-ns", "net:/fake")
	c.wrapperPID = wrapperPID
	return c
}

// TestRestoreRollbackLeg_BrokerExecBounded_ReleasesLock is ADR-0354 D6.2.
//
// Drives the REAL ADR-0353 lock (claimRestore/releaseRestore/isRestoreClaimed) together with
// the REAL brokerCriuCmd.Signal() abort-leg kill against a fake broker, with the FORWARD
// migration ctx already expired — the exact precondition under which the fail-closed rollback
// leg is entered in production (forward deadline blown -> abort/kill -> release the ADR-0353
// claim). Asserts: (1) the cleanup exec (exec_signal) was still ATTEMPTED and DELIVERED despite
// the forward ctx already being Done — not silently skipped, the D3 "stop-here safety"
// assertion; (2) it returned comfortably within rollbackExecBudget, not the old fixed 30s/5m
// clamp; (3) the ADR-0353 claim, released via the same unconditional defer-shaped call every
// real call site uses, is gone immediately after — proving the rollback leg does not hold the
// lock open past the bounded cleanup.
//
// This test cannot even be constructed against the pre-ADR-0354 signature: pre-fix
// newBrokerCriuCmd took no ctx parameter at all (`newBrokerCriuCmd(args ...string)`), so this
// file fails to compile against that code — the sharpest possible "fails before, passes after."
func TestRestoreRollbackLeg_BrokerExecBounded_ReleasesLock(t *testing.T) {
	const migName = "adr0354-d6.2-rollback"
	if !claimRestore(migName, "gRPC") {
		t.Fatal("setup: claimRestore must succeed against an empty registry")
	}
	// Unconditional cleanup in case an assertion fails before the in-test release below runs —
	// mirrors every real call site's defer releaseRestore(...), never conditional on success.
	defer func() {
		if isRestoreClaimed(migName) {
			releaseRestore(migName)
		}
	}()

	var received int32
	sock := startFakeBroker(t, execSignalRecorder(&received, 100*time.Millisecond))
	origFn := netnsBrokerClientFn
	netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
	defer func() { netnsBrokerClientFn = origFn }()

	// The forward migration ctx is ALREADY Done — the deadline-blown / operator-Abort
	// precondition under which the fail-closed rollback leg fires.
	forwardCtx, forwardCancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	forwardCancel()
	time.Sleep(5 * time.Millisecond) // make sure the deadline has genuinely elapsed
	if forwardCtx.Err() == nil {
		t.Fatal("test setup invariant violated: forward ctx must already be Done")
	}

	criuCmd := newTestCriuCmd(forwardCtx, 424242)

	start := time.Now()
	err := criuCmd.Signal(int(syscall.SIGKILL))
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Signal() returned an error with the forward ctx already Done: %v — the kill "+
			"must still be DELIVERED (D2b asymmetry: WithoutCancel severs the Done-ness before "+
			"deriving the bounded ctx)", err)
	}
	if atomic.LoadInt32(&received) != 1 {
		t.Fatalf("fake broker never received exec_signal (got %d) — the cleanup exec was skipped "+
			"instead of attempted, exactly the D3 stop-here safety regression this test guards", received)
	}
	if elapsed >= rollbackExecBudget {
		t.Fatalf("Signal() took %v, want comfortably under rollbackExecBudget (%v)", elapsed, rollbackExecBudget)
	}

	releaseRestore(migName)
	if isRestoreClaimed(migName) {
		t.Fatal("ADR-0353 claim still held after the bounded rollback-leg kill returned — the " +
			"lock must be releasable immediately once the bounded cleanup completes, not held " +
			"open by a wedged-looking forward ctx")
	}
}

// TestBrokerCriuSignal_DeliversKillUnderRollbackBudget_ForwardCtxDone is ADR-0354 D6.7 — the
// abort-asymmetry guard.
//
// Same fail-closed shape as D6.2, but drives the WEDGED-broker case: the fake broker never
// responds to exec_signal at all. Asserts Signal() (a) still returns (does not hang forever)
// and (b) is bounded by rollbackExecBudget specifically — not the old flat 30s
// (context.Background()+30s, today's pre-fix clamp) and not brokerExecTimeout's 5 minutes. This
// FAILS against a naive "just thread c.ctx directly" alternative fix (the kill would never even
// be attempted — Client.do's dial-time ctx.Done() check rejects before dialing, since the
// forward ctx is already Done, so the fake broker would never see the exec_signal at all) AND
// against today's flat Background()+30s (delivered, but bounded by 30s, not 10s) — it PASSES
// only with the WithoutCancel(c.ctx)+rollbackExecBudget binding this ADR lands.
func TestBrokerCriuSignal_DeliversKillUnderRollbackBudget_ForwardCtxDone(t *testing.T) {
	sock := startFakeBroker(t, blockUntilDone)
	origFn := netnsBrokerClientFn
	netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
	defer func() { netnsBrokerClientFn = origFn }()

	forwardCtx, forwardCancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	forwardCancel()
	time.Sleep(5 * time.Millisecond)

	criuCmd := newTestCriuCmd(forwardCtx, 424243)

	start := time.Now()
	err := criuCmd.Signal(int(syscall.SIGKILL))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Signal() to return an error once the wedged broker exceeds rollbackExecBudget")
	}
	const slack = 3 * time.Second
	if elapsed < rollbackExecBudget-slack || elapsed > rollbackExecBudget+slack {
		t.Fatalf("Signal() against a wedged broker took %v, want ~rollbackExecBudget (%v, +/-%v) — "+
			"not the old flat 30s clamp and not brokerExecTimeout's 5 minutes", elapsed, rollbackExecBudget, slack)
	}
}
