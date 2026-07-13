/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

//go:build linux

package server

// adr0346_selfpath_test.go — ADR-0346 D3/D5 discharge requirement 11.
//
// The two in-netns primitives that re-execute this agent's OWN binary
// (probeOldIPInPodNetnsImpl, __inetns_probe / StartReachabilityEcho, __inetns_echo)
// must transmit the FIXED self-path sentinel (netnsbroker.NetnsExecSelfToken) as
// argv[0], never a live os.Executable()/"/proc/self/exe" path. The broker's
// exact-match netnsExecAllowlist keys on the sentinel and substitutes its own
// pinned self path server-side; a transmitted filesystem path matches nothing and
// is rejected ("not in broker allowlist"), which fails the probe closed and never
// starts the echo listener — dead reachability verification on every migration.
//
// This test drives the REAL server call sites (the free probe impl, and the full
// StartReachabilityEcho gRPC handler via a fake k8s client that resolves a live
// RestoredPID) through a capture seam, then proves two things:
//   1. Transmission: the captured argv[0] IS the sentinel and is NOT a path.
//   2. Real-broker acceptance: feeding the captured argv into the actual broker
//      netnsbroker.Handle gets PAST the allowlist gate (no "not in broker
//      allowlist"). Under the os.Executable() regression this assertion fails
//      because the real broker rejects the path — so the test is falsifiable
//      against exactly the regression the validation panel caught.
//
// This is the production-parity counterpart to netnsbroker T4
// (adr0347_test.go), which hand-wrote the sentinel into its own Handle() request
// and therefore never exercised what server.go actually sends.

import (
	"context"
	"os"
	"strings"
	"testing"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// assertSentinelTransmitted checks a captured argv against the two D3/D5 properties
// and then drives the REAL broker Handle for op to prove the transmitted argv[0]
// clears the exact-match allowlist gate (SrcPID<=0 + empty NetnsPath makes Handle
// fail AFTER the allowlist check, at target resolution — no nsenter/spawn side
// effect, so the assertion is hermetic).
func assertSentinelTransmitted(t *testing.T, op, wantHelper string, argv []string) {
	t.Helper()
	if len(argv) < 2 {
		t.Fatalf("%s: captured argv too short: %v", op, argv)
	}
	if argv[0] != netnsbroker.NetnsExecSelfToken {
		t.Fatalf("%s: argv[0] = %q, want the self-path sentinel %q (a live os.Executable()/proc/self/exe path is the regression the broker allowlist rejects)",
			op, argv[0], netnsbroker.NetnsExecSelfToken)
	}
	if strings.Contains(argv[0], "/") {
		t.Fatalf("%s: argv[0] = %q contains a path separator — a filesystem path was transmitted instead of the sentinel (regression)", op, argv[0])
	}
	if self, err := os.Executable(); err == nil && argv[0] == self {
		t.Fatalf("%s: argv[0] equals os.Executable() %q — the exact regression (a live self path, not the sentinel)", op, self)
	}
	if argv[1] != wantHelper {
		t.Fatalf("%s: argv[1] = %q, want helper subcommand %q", op, argv[1], wantHelper)
	}

	// Real-broker acceptance: the sentinel must clear the allowlist gate. SrcPID<=0
	// with an empty NetnsPath makes doNetnsExec/doNetnsExecStart fail at target
	// resolution (AFTER the allowlist match), never at the allowlist. The regression
	// (a path in argv[0]) would fail AT the allowlist with "not in broker allowlist".
	resp := netnsbroker.Handle(netnsbroker.Request{Op: op, SrcPID: 0, NetnsPath: "", Argv: argv})
	if strings.Contains(resp.Error, "not in broker allowlist") {
		t.Fatalf("%s: real broker rejected the transmitted argv[0]=%q at the allowlist: %q — server is not sending the sentinel the broker accepts",
			op, argv[0], resp.Error)
	}
}

func TestSelfPathProbeTransmitsSentinelNotExecutablePath(t *testing.T) {
	var gotArgv []string
	origExec := netnsSelfExecFn
	netnsSelfExecFn = func(_ context.Context, _ int, _ string, argv ...string) netnsbroker.ExecResult {
		gotArgv = append([]string(nil), argv...)
		// RST/refused classification => probe reports the IP live; proves the handler
		// consumes a normal broker result, not just that a call happened.
		return netnsbroker.ExecResult{ExitCode: inetnsProbeExitRefused}
	}
	defer func() { netnsSelfExecFn = origExec }()

	ok, out := probeOldIPInPodNetnsImpl(context.Background(), os.Getpid(), "10.244.0.5")
	if !ok {
		t.Fatalf("probe should report live on inetnsProbeExitRefused; out=%q", out)
	}
	assertSentinelTransmitted(t, "netns_exec", "__inetns_probe", gotArgv)
}

func TestStartReachabilityEchoTransmitsSentinelNotExecutablePath(t *testing.T) {
	var gotArgv []string
	origStart := netnsSelfExecStartFn
	netnsSelfExecStartFn = func(_ context.Context, replPID int, _ string, argv ...string) (int, error) {
		gotArgv = append([]string(nil), argv...)
		return replPID, nil // pretend the detached listener started
	}
	defer func() { netnsSelfExecStartFn = origStart }()

	// A live RestoredPID (this test process's own PID) makes restoredPIDForMigration
	// resolve replPID>0, so the real StartReachabilityEcho handler reaches the echo
	// exec seam instead of deferring on an unresolved PID.
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-echo", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "p", PodNamespace: "default"},
		Status:     pmv1.PodMigrationStatus{RestoredPID: int32(os.Getpid())},
	}
	s := newFakeAgentServerWithPM(t, pm)

	resp, err := s.StartReachabilityEcho(context.Background(), &agentpb.StartReachabilityEchoRequest{
		MigrationName: "mig-echo",
		ListenIp:      "127.0.0.1",
		ListenPort:    17999,
		Nonce:         "adr0346-d11-nonce",
		TtlS:          5,
	})
	if err != nil {
		t.Fatalf("StartReachabilityEcho rpc err: %v", err)
	}
	if !resp.Started {
		t.Fatalf("expected Started=true once the echo seam returns a PID; detail=%s", resp.Detail)
	}
	assertSentinelTransmitted(t, "netns_exec_start", "__inetns_echo", gotArgv)
}
