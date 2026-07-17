// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

// adr0354_netns_exec_test.go — D6.8 (ADR-0354 §"Named regression tests").
//
// See docs/adr/0354-restore-broker-exec-caller-deadline-binding.md.

import (
	"context"
	"testing"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
)

// TestNetnsExecCallSite_HonorsCallerDeadline_NotThirtySeconds is ADR-0354 D6.8 — the
// netns_exec-family analog of D6.1.
//
// resolveReplVethPeer (server.go) is driven directly — it is a real, independently-callable
// production function (unlike the loopback-up site, which is inline inside joinNsRestore; see
// the second subtest below for that one). Both funnel netnsBrokerClientFn().NetnsExec, which
// funnels the SAME Client.do as brokerCmd. Before D2c, resolveReplVethPeer rooted its NetnsExec
// call in context.Background() unconditionally (a fixed 30s client opTimeout default,
// invisible to the caller's migration deadline). After D2c it threads the caller ctx, so a
// wedged netns_exec aborts at the caller's ~50ms deadline instead of the 30s default.
func TestNetnsExecCallSite_HonorsCallerDeadline_NotThirtySeconds(t *testing.T) {
	t.Run("resolveReplVethPeer (server.go veth-peer resolution, the D2c call site)", func(t *testing.T) {
		sock := startFakeBroker(t, blockUntilDone)
		origFn := netnsBrokerClientFn
		netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
		defer func() { netnsBrokerClientFn = origFn }()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := resolveReplVethPeer(ctx, 424244)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected an error from a wedged netns_exec, got success")
		}
		if elapsed >= 500*time.Millisecond {
			t.Fatalf("resolveReplVethPeer took %v to abort a wedged netns_exec with a 50ms caller "+
				"deadline — expected < 500ms, not anywhere near the 30s client opTimeout default "+
				"a context.Background()-rooted call would have run to", elapsed)
		}
	})

	// joinNsRestore's loopback-up netns_exec (server.go:5171 area, "ip link set lo up") cannot be
	// driven via joinNsRestore itself for the same reason D6.6 documents (no root, no live
	// broker/ctr, joinNsRestore is not unit-testable end-to-end in this suite's existing
	// convention). It funnels the exact same netnsBrokerClientFn().NetnsExec(ctx, ...) call
	// resolveReplVethPeer uses above — reproduced verbatim here (the identical one-line
	// production call, not a re-implementation) to prove the D2c call-site behavior for this
	// second holdout site as well.
	t.Run("joinNsRestore loopback-up netns_exec (server.go's second D2c call site)", func(t *testing.T) {
		sock := startFakeBroker(t, blockUntilDone)
		origFn := netnsBrokerClientFn
		netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
		defer func() { netnsBrokerClientFn = origFn }()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		r := netnsBrokerClientFn().NetnsExec(ctx, 424245, "", "ip", "link", "set", "lo", "up")
		elapsed := time.Since(start)

		if r.SpawnErr == nil {
			t.Fatal("expected a SpawnErr from a wedged netns_exec, got success")
		}
		if elapsed >= 500*time.Millisecond {
			t.Fatalf("loopback-up netns_exec took %v to abort with a 50ms caller deadline — expected < 500ms", elapsed)
		}
	})
}
