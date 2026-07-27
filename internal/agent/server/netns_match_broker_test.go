/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

// netns_match_broker_test.go — regression coverage for the netns_match broker-delegation path
// (server.go's netnsMatchFn / brokerNetnsMatch / netnsbroker.Client.NetnsMatch, broker.go's
// doNetnsMatch), closing the coverage gap the original ADR-0306 pidNetnsMatchesPath unit tests
// (restore_pidfile_test.go) left: those tests all called the function against os.Getpid() — the
// test binary's OWN pid — never against a genuinely separate process, and go test itself runs
// unconfined, so none of them could ever go red if AppArmor mediation for this call regressed.
//
// This file cannot exercise real AppArmor mediation either (same constraint — go test runs
// unconfined and this environment is not root), but it DOES exercise the two things those tests
// structurally could not: (1) a real, separate OS process distinct from the test binary's own
// PID, stated via the exact netns_match wire op over a real Unix socket, using the SAME
// netnsbroker.Client/Request/Response code every production call site uses; and (2) the full
// pidNetnsMatchesPath -> netnsMatchFn -> brokerNetnsMatch -> netnsbroker.Client.NetnsMatch ->
// wire -> fake broker -> doNetnsMatch-equivalent round trip, proving the delegation wiring itself
// (not just the comparison arithmetic) is correct.

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
)

// spawnSeparateProcess starts a genuinely separate, long-lived child process (distinct PID from
// the test binary) and returns its PID plus a cleanup func. Using `sleep` rather than forking
// keeps this dependency-free and matches the "real separate process, not self" property the QA
// finding calls for — the exact property os.Getpid()-based tests structurally cannot have.
func spawnSeparateProcess(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("spawnSeparateProcess: could not start sleep subprocess (environment lacks it): %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid
}

// TestPidNetnsMatchesPath_BrokerDelegation_SeparateProcess drives pidNetnsMatchesPath through its
// PRODUCTION routing (netnsMatchFn=brokerNetnsMatch, unchanged from the package default — this
// test does NOT override netnsMatchFn) against a real fake-broker Unix socket and a real, separate
// child process. It proves: (a) the request that reaches the broker is the netns_match op with
// the child's PID, not the test binary's own; (b) a match reported by the broker round-trips back
// to pidNetnsMatchesPath as (true, nil); (c) a mismatch/broker-error round-trips as (false,
// non-nil), never a silent false positive.
func TestPidNetnsMatchesPath_BrokerDelegation_SeparateProcess(t *testing.T) {
	self := os.Getpid()
	child := spawnSeparateProcess(t)
	if child == self {
		t.Fatalf("spawned child PID %d equals test binary PID — precondition violated, this test requires a genuinely separate process", child)
	}

	t.Run("match: broker reports the child's netns identifies the expected path", func(t *testing.T) {
		var gotOp string
		var gotPID int
		var gotPath string
		sock := startFakeBroker(t, func(conn net.Conn, req netnsbroker.Request, _ <-chan struct{}) {
			gotOp = req.Op
			gotPID = req.SignalPID
			gotPath = req.ExpectedNetnsPath
			writeFakeResponse(conn, netnsbroker.Response{Match: true})
		})
		origClientFn := netnsBrokerClientFn
		netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
		defer func() { netnsBrokerClientFn = origClientFn }()

		match, err := pidNetnsMatchesPath(child, "/var/run/netns/cni-deadbeef")
		if err != nil {
			t.Fatalf("pidNetnsMatchesPath: unexpected error: %v", err)
		}
		if !match {
			t.Fatalf("pidNetnsMatchesPath: got match=false, want true (broker reported Match:true)")
		}
		if gotOp != "netns_match" {
			t.Fatalf("broker saw op %q, want %q", gotOp, "netns_match")
		}
		if gotPID != child {
			t.Fatalf("broker saw SignalPID=%d, want the spawned child's PID %d (not the test binary's own %d) — delegation must forward the TARGET pid, never substitute self", gotPID, child, self)
		}
		if gotPath != "/var/run/netns/cni-deadbeef" {
			t.Fatalf("broker saw ExpectedNetnsPath=%q, want the caller-supplied path", gotPath)
		}
	})

	t.Run("mismatch: broker reports Match:false, caller sees (false, nil)", func(t *testing.T) {
		sock := startFakeBroker(t, func(conn net.Conn, _ netnsbroker.Request, _ <-chan struct{}) {
			writeFakeResponse(conn, netnsbroker.Response{Match: false})
		})
		origClientFn := netnsBrokerClientFn
		netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
		defer func() { netnsBrokerClientFn = origClientFn }()

		match, err := pidNetnsMatchesPath(child, "/var/run/netns/cni-somethingelse")
		if err != nil {
			t.Fatalf("pidNetnsMatchesPath: unexpected error on a clean mismatch: %v", err)
		}
		if match {
			t.Fatalf("pidNetnsMatchesPath: got match=true, want false (broker reported Match:false)")
		}
	})

	t.Run("broker error fails closed: never a silent (true,nil) or (false,nil)", func(t *testing.T) {
		sock := startFakeBroker(t, func(conn net.Conn, _ netnsbroker.Request, _ <-chan struct{}) {
			writeFakeResponse(conn, netnsbroker.Response{Error: "netns_match: stat /proc/<pid>/ns/net: no such process"})
		})
		origClientFn := netnsBrokerClientFn
		netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
		defer func() { netnsBrokerClientFn = origClientFn }()

		match, err := pidNetnsMatchesPath(child, "/var/run/netns/cni-deadbeef")
		if err == nil {
			t.Fatalf("pidNetnsMatchesPath: expected a non-nil error on broker-reported failure, got nil (match=%v)", match)
		}
		if match {
			t.Fatalf("pidNetnsMatchesPath: got match=true alongside a broker error — must fail closed (false)")
		}
		if !strings.Contains(err.Error(), "netns_match") {
			t.Fatalf("error %q should reference netns_match", err.Error())
		}
	})
}

// TestDoNetnsMatch_SeparateProcess drives netnsbroker.Handle directly (the broker's own
// pure-logic dispatch core, no socket) against a real separate child process and a real
// filesystem path standing in for the netns bind-mount target, proving the actual /proc/<pid>/
// ns/net stat crosses a genuine process boundary rather than reading the test binary's own namespace.
func TestDoNetnsMatch_SeparateProcess(t *testing.T) {
	self := os.Getpid()
	child := spawnSeparateProcess(t)
	if child == self {
		t.Fatalf("spawned child PID %d equals test binary PID", child)
	}

	t.Run("rejects pid <= 0", func(t *testing.T) {
		for _, pid := range []int{0, -1} {
			resp := netnsbroker.Handle(netnsbroker.Request{Op: "netns_match", SignalPID: pid, ExpectedNetnsPath: "/var/run/netns/cni-x"})
			if resp.Error == "" {
				t.Fatalf("pid %d: expected rejection, got success %+v", pid, resp)
			}
		}
	})

	t.Run("rejects an ExpectedNetnsPath outside the /run/netns|/var/run/netns convention (SC-1)", func(t *testing.T) {
		resp := netnsbroker.Handle(netnsbroker.Request{Op: "netns_match", SignalPID: child, ExpectedNetnsPath: "/etc/passwd"})
		if resp.Error == "" {
			t.Fatalf("expected SC-1 path-shape rejection for /etc/passwd, got success %+v", resp)
		}
		if resp.Match {
			t.Fatalf("a rejected request must never report Match:true")
		}
	})

	t.Run("a genuinely different process's netns compared against a bogus path fails closed with an error, not a silent mismatch", func(t *testing.T) {
		// /var/run/netns/cni-doesnotexist is shaped correctly (passes SC-1) but does not exist on
		// disk, so the second stat must fail — proving the child PID's OWN /proc/<pid>/ns/net stat
		// (the first stat) succeeded against a real separate process before the second stat failed.
		resp := netnsbroker.Handle(netnsbroker.Request{
			Op:                "netns_match",
			SignalPID:         child,
			ExpectedNetnsPath: "/var/run/netns/cni-doesnotexist",
		})
		if resp.Error == "" {
			t.Fatalf("expected a stat error for a nonexistent ExpectedNetnsPath, got success %+v", resp)
		}
		if resp.Match {
			t.Fatalf("a stat-error response must never report Match:true")
		}
		// The error surfaces the SECOND stat's failure (the bogus path) — proving the FIRST
		// stat (child's own /proc/<pid>/ns/net, a real cross-process read) already succeeded;
		// had it failed instead (e.g. a self-check bug substituting the wrong PID), the error
		// would reference /proc/<pid>/ns/net, not ExpectedNetnsPath.
		if !strings.Contains(resp.Error, "cni-doesnotexist") {
			t.Fatalf("error %q should reference the ExpectedNetnsPath stat that failed (proving the earlier /proc/%d/ns/net stat against the separate child process succeeded first)", resp.Error, child)
		}
	})
}
