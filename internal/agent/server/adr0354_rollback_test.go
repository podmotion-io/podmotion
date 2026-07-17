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

// TestJoinNsRestoreTeardown_BoundedByRollbackBudget_ForwardCtxDone is the ADR-0354 D3
// completeness regression test for the two nsenterCmd placeholder-teardown sites landed on
// this branch: joinNsRestore's placeholder-teardown defer (server.go, "On any error after this
// point: kill placeholder to release the rootfs mount") and the sibling "kill any stale
// placeholder from a previous attempt" cleanup block inside setupRestoreOverlayfs. Neither site
// is independently callable (both are inline blocks, not their own functions), so — following
// this file's own D6.8 convention in adr0354_netns_exec_test.go for the joinNsRestore
// loopback-up netns_exec site — the exact rollbackCtx-derivation and nsenterCmd call sequence
// is reproduced verbatim from server.go rather than re-implemented or paraphrased:
//
//	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackExecBudget)
//	defer cancel()
//	_ = nsenterCmd(rollbackCtx, "ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()
//	_ = nsenterCmd(rollbackCtx, "ctr", "--namespace", "k8s.io", "container", "rm", placeholderID).Run()
//
// Drives this sequence with the forward ctx ALREADY Done/cancelled before the block runs — the
// exact precondition both fixed sites' comments call out ("must still fire even if the forward
// migration ctx is already Done/cancelled by the time this defer runs"). Asserts both execs are
// DELIVERED (not skipped) and complete comfortably inside rollbackExecBudget.
//
// This test fails against the pre-fix code, which bound these same two nsenterCmd calls
// directly to the raw (already-Done) ctx instead of a WithoutCancel-derived rollbackCtx: with a
// forward ctx that is already cancelled, brokerCmd.result()'s
// context.WithTimeout(callerCtx, brokerExecBudget(callerCtx)) derives its own Done-ness from
// the already-cancelled parent, so ctx.Done() is already closed before dial — Client.do's
// dial-time ctx.Done() check (exercised directly below in the "raw ctx" subtest) rejects before
// ever reaching the fake broker, and the exec is never attempted at all. Swap in `forwardCtx`
// for `rollbackCtx` in the "fixed" subtest below to see it fail.
func TestJoinNsRestoreTeardown_BoundedByRollbackBudget_ForwardCtxDone(t *testing.T) {
	placeholderID := "pm-placeholder-adr0354-d3-completeness"

	t.Run("fixed: rollbackCtx binding still delivers both teardown execs", func(t *testing.T) {
		var received int32
		sock := startFakeBroker(t, execSignalCountingRecorder(&received, 20*time.Millisecond))
		origFn := netnsBrokerClientFn
		netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
		defer func() { netnsBrokerClientFn = origFn }()

		// The forward migration ctx is ALREADY Done — the exact precondition under which the
		// fail-closed placeholder-teardown fires in production.
		forwardCtx, forwardCancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		forwardCancel()
		time.Sleep(5 * time.Millisecond)
		if forwardCtx.Err() == nil {
			t.Fatal("test setup invariant violated: forward ctx must already be Done")
		}

		start := time.Now()

		// Verbatim reproduction of the fixed defer/cleanup block (server.go).
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(forwardCtx), rollbackExecBudget)
		defer cancel()
		killErr := nsenterCmd(rollbackCtx, "ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()
		rmErr := nsenterCmd(rollbackCtx, "ctr", "--namespace", "k8s.io", "container", "rm", placeholderID).Run()

		elapsed := time.Since(start)

		if killErr != nil {
			t.Fatalf("task kill exec returned an error with the forward ctx already Done: %v — "+
				"the teardown exec must still be DELIVERED (D3 asymmetry: WithoutCancel severs the "+
				"Done-ness before deriving the bounded rollbackCtx)", killErr)
		}
		if rmErr != nil {
			t.Fatalf("container rm exec returned an error with the forward ctx already Done: %v", rmErr)
		}
		if atomic.LoadInt32(&received) != 2 {
			t.Fatalf("fake broker received %d exec ops, want 2 (task kill + container rm) — a "+
				"teardown exec was skipped instead of attempted, exactly the D3 stop-here safety "+
				"regression this test guards", received)
		}
		if elapsed >= rollbackExecBudget {
			t.Fatalf("teardown execs took %v, want comfortably under rollbackExecBudget (%v)", elapsed, rollbackExecBudget)
		}
	})

	t.Run("raw ctx (pre-fix shape): binding directly to the already-Done forward ctx never even dials", func(t *testing.T) {
		var received int32
		sock := startFakeBroker(t, execSignalCountingRecorder(&received, 20*time.Millisecond))
		origFn := netnsBrokerClientFn
		netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
		defer func() { netnsBrokerClientFn = origFn }()

		forwardCtx, forwardCancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		forwardCancel()
		time.Sleep(5 * time.Millisecond)

		// This is the PRE-FIX shape: nsenterCmd bound directly to the raw forward ctx instead of
		// a rollbackCtx. Demonstrates why the fix is necessary — the exec is never attempted.
		killErr := nsenterCmd(forwardCtx, "ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()

		if killErr == nil {
			t.Fatal("expected an error binding a teardown exec directly to an already-Done forward ctx")
		}
		if atomic.LoadInt32(&received) != 0 {
			t.Fatalf("fake broker received %d exec ops against the raw already-Done ctx, want 0 — "+
				"this subtest's premise (raw ctx binding never dials) is invalid if the broker saw a request", received)
		}
	})
}

// TestSetupRestoreOverlayfsStaleTeardown_BoundedByRollbackBudget_ForwardCtxDone is the sibling
// ADR-0354 D3 completeness regression test for setupRestoreOverlayfs's "kill any stale
// placeholder from a previous attempt" cleanup block, which additionally binds a third
// nsenterCmd call ("rm", "-rf", bundleDir) to the same rollbackCtx — reproduced verbatim here
// alongside the task-kill/container-rm pair. Same fail-closed precondition and assertions as
// TestJoinNsRestoreTeardown_BoundedByRollbackBudget_ForwardCtxDone above.
func TestSetupRestoreOverlayfsStaleTeardown_BoundedByRollbackBudget_ForwardCtxDone(t *testing.T) {
	placeholderID := "pm-placeholder-adr0354-d3-completeness-overlayfs"
	bundleDir := "/run/containerd/io.containerd.runtime.v2.task/k8s.io/" + placeholderID

	var received int32
	sock := startFakeBroker(t, execSignalCountingRecorder(&received, 20*time.Millisecond))
	origFn := netnsBrokerClientFn
	netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
	defer func() { netnsBrokerClientFn = origFn }()

	forwardCtx, forwardCancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	forwardCancel()
	time.Sleep(5 * time.Millisecond)
	if forwardCtx.Err() == nil {
		t.Fatal("test setup invariant violated: forward ctx must already be Done")
	}

	start := time.Now()

	// Verbatim reproduction of setupRestoreOverlayfs's stale-placeholder cleanup block
	// (server.go), including the adjacent bundleDir rm -rf brought under the same rollbackCtx.
	rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(forwardCtx), rollbackExecBudget)
	defer rollbackCancel()
	killErr := nsenterCmd(rollbackCtx, "ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()
	rmContainerErr := nsenterCmd(rollbackCtx, "ctr", "--namespace", "k8s.io", "container", "rm", placeholderID).Run()
	_, rmBundleErr := nsenterCmd(rollbackCtx, "rm", "-rf", bundleDir).CombinedOutput()

	elapsed := time.Since(start)

	if killErr != nil {
		t.Fatalf("task kill exec returned an error with the forward ctx already Done: %v", killErr)
	}
	if rmContainerErr != nil {
		t.Fatalf("container rm exec returned an error with the forward ctx already Done: %v", rmContainerErr)
	}
	if rmBundleErr != nil {
		t.Fatalf("bundleDir rm -rf exec returned an error with the forward ctx already Done: %v", rmBundleErr)
	}
	if atomic.LoadInt32(&received) != 3 {
		t.Fatalf("fake broker received %d exec ops, want 3 (task kill + container rm + rm -rf "+
			"bundleDir) — a stale-teardown exec was skipped instead of attempted", received)
	}
	if elapsed >= rollbackExecBudget {
		t.Fatalf("stale-teardown execs took %v, want comfortably under rollbackExecBudget (%v)", elapsed, rollbackExecBudget)
	}
}

// execSignalCountingRecorder returns a fakeBrokerHandler that, on receiving any "exec" op,
// increments received, waits delay (respecting the harness's done channel), then responds with
// exit code 0. Used by the D3 completeness tests above, which drive plain nsenterCmd (Op
// "exec") rather than execSignalRecorder's exec_signal-specific op.
func execSignalCountingRecorder(received *int32, delay time.Duration) fakeBrokerHandler {
	return func(conn net.Conn, req netnsbroker.Request, done <-chan struct{}) {
		if req.Op != "exec" {
			writeFakeResponse(conn, netnsbroker.Response{ExitCode: intPtr(0)})
			return
		}
		atomic.AddInt32(received, 1)
		select {
		case <-time.After(delay):
		case <-done:
			return
		}
		writeFakeResponse(conn, netnsbroker.Response{ExitCode: intPtr(0)})
	}
}
