/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestThawSourcePID_RoutesThroughBrokerNotDirectKill is the C-06 (MUST_ROUTE_BROKER)
// contract test for the source-thaw signal ownership.
//
// C-06 grounding (MUST_ROUTE_BROKER): the earlier "source runs peer=podmotion-agent, so a
// direct SIGCONT is permitted" premise is UNVERIFIED against a live containerd-managed source
// workload — the empirical AppArmor peer-label capture for a SIGCONT (operation=signal,
// signal=cont) is owed to the Sprint-44 live baseline and has NOT been taken (the only real
// dmesg line in the corpus is class=PTRACE, not class=SIGNAL). The broker route is chosen
// because it is correct-by-construction regardless of the label: if a containerd-managed source
// runs under the runtime default profile and the confined agent's own syscall.Kill(pid, SIGCONT)
// is in fact AppArmor-DENIED, a direct kill would leave the source frozen forever — an
// invariant-1 / ADR-0012 break (the source is the only surviving copy on the abort/rollback
// path). Routing through the unconfined netns-broker (SignalPID) forecloses that hazard whether
// the direct path would have been permitted or denied. The thaw MUST therefore route through the
// broker, not a direct kill.
//
// Falsifiability: this test starts a real child process, SIGSTOPs it, then calls
// thawSourcePID with NO broker socket present. Under the PRE-C-06 logic (direct
// syscall.Kill SIGCONT), the child would be resumed (State T → S/R). Under the
// post-C-06 logic (broker route), the direct kill is gone; the broker dial fails
// because no broker is running in the test sandbox, so the child stays STOPPED. The
// assertion "the child is NOT directly resumed" therefore FAILS on the old direct-kill
// code and PASSES on the broker-routed code — it is the test that would have caught a
// regression back to the direct kill.
func TestThawSourcePID_RoutesThroughBrokerNotDirectKill(t *testing.T) {
	// A long-lived child we can freeze and inspect. `sleep 60` stays alive well past
	// the test and is trivially SIGSTOP/SIGCONT-controllable.
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	pid := int32(cmd.Process.Pid)
	// Guarantee the child is reaped and gone at test end regardless of outcome.
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// Freeze the child: SIGSTOP puts it in State T, exactly as CRIU --leave-stopped
	// leaves a dumped source workload.
	if err := syscall.Kill(int(pid), syscall.SIGSTOP); err != nil {
		t.Fatalf("SIGSTOP child: %v", err)
	}
	// Wait for the kernel to reflect State T before proceeding.
	if !waitForStopped(t, pid, true) {
		t.Fatalf("child never reached State T after SIGSTOP")
	}

	// Attempt the thaw. With the broker route and no broker socket, this delivers no
	// SIGCONT to the child; it logs an error and returns. It must NOT directly resume.
	thawSourcePID(pid, "test-c06-source-thaw")

	// Give any (erroneous) direct SIGCONT time to take effect, then assert the child is
	// STILL stopped — i.e. thawSourcePID did NOT deliver a direct kill.
	if resumed := waitForStopped(t, pid, false); resumed {
		t.Fatalf("thawSourcePID directly resumed the frozen source (child left State T) — " +
			"the source-thaw is using a direct syscall.Kill instead of routing through the " +
			"netns-broker (C-06 MUST_ROUTE_BROKER violated)")
	}

	// Sanity: a genuine direct SIGCONT DOES resume the child, proving the process is
	// signal-responsive and the negative assertion above was meaningful (not a dead PID).
	if err := syscall.Kill(int(pid), syscall.SIGCONT); err != nil {
		t.Fatalf("control SIGCONT to child failed: %v", err)
	}
	// waitForStopped(pid, false) returns true once the child is observed NOT stopped
	// (resumed). If it never resumes, the harness/PID is not signal-responsive and the
	// earlier negative assertion would be meaningless.
	if resumed := waitForStopped(t, pid, false); !resumed {
		t.Fatalf("control SIGCONT did not resume the child — test harness broken, negative assertion is not meaningful")
	}
}

// waitForStopped polls the child's /proc state for up to ~500ms. It returns true when
// the observed "stopped" state matches want. procIsStopped lives in
// frozen_source_registry.go (same package).
func waitForStopped(t *testing.T, pid int32, want bool) bool {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		stopped, err := procIsStopped(pid)
		if err == nil && stopped == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Final read for the caller's decision.
	stopped, _ := procIsStopped(pid)
	return stopped == want
}
