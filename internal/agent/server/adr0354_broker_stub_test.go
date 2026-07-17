// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

// adr0354_broker_stub_test.go — shared fake-broker test harness for the ADR-0354 D6.1-D6.9
// regression suite (adr0354_*_test.go in this package).
//
// This is a REAL Unix domain socket listener speaking the exact same line-delimited JSON wire
// protocol netnsbroker.Client.do (internal/agent/netnsbroker/client.go) uses in production,
// decoded/encoded with the SAME netnsbroker.Request/Response types — never a re-implementation
// of the client's own logic or a synthetic ExecResult. It stands in only for the external
// boundary the ADR-0354 tests are explicitly permitted to fake (the actual netns-broker
// sidecar process and its root-owned socket at /run/podmotion/netns-broker.sock, which this
// non-root test environment cannot bind). Every production code path downstream of the fake
// listener — brokerCmd.result(), brokerCriuCmd.Start()/poll()/Signal(),
// resolveReplVethPeer, ReadReplVethMAC, netnsbroker.Client.do()/Exec()/ExecStart()/ExecPoll()/
// ExecSignal()/NetnsExec() — runs unmodified, real production code.
//
// Test files point production code at this fake broker via two ADR-0354 test-injection seams
// added alongside the D2/D2b/D2c implementation:
//   - netnsbroker.NewClientForTesting(socketPath, dialTimeout, opTimeout) — client.go, exported,
//     never called by non-test production code.
//   - the package-level netnsBrokerClientFn var (server.go) — mirrors the pre-existing
//     readReplVethMACFn/joinNsRestoreFn/brokerNetnsExecFn indirection pattern already used
//     throughout this file for test injection.

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
)

// fakeBrokerHandler decides how the fake broker responds to one accepted connection, given the
// decoded Request. done is closed when the test harness is torn down (t.Cleanup) — a handler
// that intentionally never responds (simulating a wedged/blocked broker exec) MUST select on
// done so its goroutine does not leak past the test.
type fakeBrokerHandler func(conn net.Conn, req netnsbroker.Request, done <-chan struct{})

// startFakeBroker starts a real Unix socket listener under t.TempDir() and returns the socket
// path. Every accepted connection is read as one JSON request line and dispatched to handler in
// its own goroutine (supporting sequential or concurrent dials, matching brokerCmd/brokerCriuCmd's
// real call pattern of a fresh dial per RPC). Torn down automatically via t.Cleanup.
func startFakeBroker(t *testing.T, handler fakeBrokerHandler) string {
	t.Helper()
	// A Unix socket path is capped at ~108 bytes (sun_path) on Linux; t.TempDir() embeds the
	// full (often long, subtest-qualified) test name, which regularly blows that budget and
	// fails the bind with EINVAL. Use a short, independent temp dir instead.
	dir, err := os.MkdirTemp("", "adr0354")
	if err != nil {
		t.Fatalf("startFakeBroker: MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "b.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("startFakeBroker: listen %s: %v", sockPath, err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
	})
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return // listener closed at cleanup
			}
			go func(c net.Conn) {
				defer c.Close()
				line, rerr := bufio.NewReader(c).ReadBytes('\n')
				if rerr != nil {
					return
				}
				var req netnsbroker.Request
				if jerr := json.Unmarshal(line, &req); jerr != nil {
					return
				}
				handler(c, req, done)
			}(conn)
		}
	}()
	return sockPath
}

// testBrokerClient returns a netnsbroker.Client dialing the given fake-broker socketPath, with
// generous dial/op ceilings so the CALLER ctx (not the client's own opTimeout) is what bounds
// each ADR-0354 test — mirrors netnsbroker.NewClient()'s real defaults being overridden per-call
// by brokerCmd/brokerCriuCmd's D2/D2b budgets.
func testBrokerClient(socketPath string) *netnsbroker.Client {
	return netnsbroker.NewClientForTesting(socketPath, 5*time.Second, 5*time.Minute)
}

// writeFakeResponse marshals resp as the wire-format JSON response line and writes it to conn,
// ignoring write errors (the client may have already given up and closed its side).
func writeFakeResponse(conn net.Conn, resp netnsbroker.Response) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = conn.Write(b)
}

// intPtr is a small helper for netnsbroker.Response.ExitCode (*int).
func intPtr(v int) *int { return &v }

// blockUntilDone is a fakeBrokerHandler that accepts the connection and NEVER writes a response
// (a wedged broker exec — ADR-0354 D6.1/D6.5's "inject a broker transport stub whose exec
// blocks indefinitely" / "never writes a response line"). It blocks only until the test harness
// tears down, so it never leaks past the test.
func blockUntilDone(_ net.Conn, _ netnsbroker.Request, done <-chan struct{}) {
	<-done
}

// genericExecSuccess is a fakeBrokerHandler that immediately reports exit-0 success for any op
// carrying an ExitCode-shaped response (exec/netns_exec/resolve_veth) — used where the test only
// needs the RPC to succeed fast and is not exercising blocking/deadline behavior on that call.
func genericExecSuccess(conn net.Conn, _ netnsbroker.Request, _ <-chan struct{}) {
	writeFakeResponse(conn, netnsbroker.Response{ExitCode: intPtr(0)})
}
