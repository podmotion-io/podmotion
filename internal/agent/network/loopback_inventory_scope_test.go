/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

// loopback_inventory_scope_test.go — regression for the sprint46B9 redis Strict
// live-proof failure.
//
// The redis Strict migration reached Restored=True then rolled back at TCPVerifying:
//
//	VerifyTCP failed: 4-tuple 127.0.0.1:54056->127.0.0.1:6379 not found in
//	destination /proc/net/tcp[6] (verified=1/2)
//
// The single held ClusterIP connection verified fine (1/2); the second, unmatchable
// "connection" was a transient intra-pod loopback readiness-probe connection
// (redis-cli ping → 127.0.0.1:6379) that was ESTABLISHED at the freeze instant, was
// captured into the Strict "expected" inventory, and no longer exists after restore
// (its ephemeral client port belongs to a redis-cli process that has since exited).
// verified=1/2 under Strict => rollback.
//
// The fix scopes the TCP-continuity inventory to MIGRATABLE connections: intra-pod
// loopback connections (both ends on 127.0.0.0/8 or ::1) are categorically outside the
// sequence-continuity contract (no external peer; CRIU restores both ends atomically)
// and are excluded at capture / verify / restore-poll time. This test pins the
// primitive so the exact loopback tuple can never re-enter the inventory.

import (
	"net"
	"testing"
)

func TestIsIntraPodLoopback(t *testing.T) {
	tests := []struct {
		name     string
		src, dst string
		want     bool
	}{
		{
			// The exact tuple that rolled back the sprint46B9 redis Strict proof.
			name: "redis_readiness_probe_v4_loopback_both_ends",
			src:  "127.0.0.1", dst: "127.0.0.1", want: true,
		},
		{
			// Loopback range is the whole 127.0.0.0/8, not just 127.0.0.1.
			name: "v4_loopback_range_both_ends",
			src:  "127.0.0.1", dst: "127.0.0.53", want: true,
		},
		{
			name: "v6_loopback_both_ends",
			src:  "::1", dst: "::1", want: true,
		},
		{
			// The real held connection in the same failing run — MUST NOT be filtered.
			name: "held_clusterip_connection_pod_cidr",
			src:  "10.244.2.210", dst: "10.244.2.71", want: false,
		},
		{
			// Fail-safe direction: a connection with only one loopback end (does not occur
			// for ESTABLISHED TCP, but if it ever appeared we must KEEP it, never drop a
			// possibly-real held connection).
			name: "only_src_loopback_is_kept",
			src:  "127.0.0.1", dst: "10.244.2.71", want: false,
		},
		{
			name: "only_dst_loopback_is_kept",
			src:  "10.244.2.210", dst: "127.0.0.1", want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsIntraPodLoopback(net.ParseIP(tc.src), net.ParseIP(tc.dst))
			if got != tc.want {
				t.Errorf("IsIntraPodLoopback(%s, %s) = %v, want %v", tc.src, tc.dst, got, tc.want)
			}
		})
	}
}

// TestFilterMigratableTCP_ReproducesSprint46B9Wedge reconstructs the exact freeze
// inventory from the failing run — one held ClusterIP connection plus one transient
// loopback readiness-probe connection — and asserts the loopback tuple is dropped so
// VerifyTCP sees ConnectionsExpected=1 (the held connection), not 2.
func TestFilterMigratableTCP_ReproducesSprint46B9Wedge(t *testing.T) {
	held := SocketEntry{
		SrcIP:   net.ParseIP("10.244.2.210"),
		SrcPort: 41946,
		DstIP:   net.ParseIP("10.244.2.71"),
		DstPort: 6379,
		SndNxt:  0x11223344,
		RcvNxt:  0x55667788,
	}
	loopbackProbe := SocketEntry{
		SrcIP:   net.ParseIP("127.0.0.1"),
		SrcPort: 54056,
		DstIP:   net.ParseIP("127.0.0.1"),
		DstPort: 6379,
	}

	inventory := []SocketEntry{held, loopbackProbe}
	got := FilterMigratableTCP(inventory)

	if len(got) != 1 {
		t.Fatalf("FilterMigratableTCP returned %d entries, want 1 (held connection only); got=%+v", len(got), got)
	}
	if got[0].SrcIP.String() != "10.244.2.210" || got[0].SrcPort != 41946 ||
		got[0].DstIP.String() != "10.244.2.71" || got[0].DstPort != 6379 {
		t.Errorf("surviving entry is not the held ClusterIP connection: got %s:%d->%s:%d",
			got[0].SrcIP, got[0].SrcPort, got[0].DstIP, got[0].DstPort)
	}

	// The input slice must not be mutated.
	if len(inventory) != 2 {
		t.Errorf("FilterMigratableTCP mutated its input: len=%d, want 2", len(inventory))
	}
}

func TestFilterMigratableTCP_EdgeCases(t *testing.T) {
	// All-loopback (probe-only pod): filters to nil so the caller's Strict non-vacuity
	// guard sees ConnectionsExpected=0 and correctly fails closed rather than certifying
	// continuity over a connection it cannot preserve.
	allLoopback := []SocketEntry{
		{SrcIP: net.ParseIP("127.0.0.1"), SrcPort: 40001, DstIP: net.ParseIP("127.0.0.1"), DstPort: 6379},
		{SrcIP: net.ParseIP("::1"), SrcPort: 40002, DstIP: net.ParseIP("::1"), DstPort: 6379},
	}
	if got := FilterMigratableTCP(allLoopback); len(got) != 0 {
		t.Errorf("FilterMigratableTCP(all-loopback) = %+v, want empty", got)
	}

	// Empty input → empty output, no panic.
	if got := FilterMigratableTCP(nil); len(got) != 0 {
		t.Errorf("FilterMigratableTCP(nil) = %+v, want empty", got)
	}

	// No loopback at all → every entry preserved in order.
	realOnly := []SocketEntry{
		{SrcIP: net.ParseIP("10.244.2.210"), SrcPort: 41946, DstIP: net.ParseIP("10.244.2.71"), DstPort: 6379},
		{SrcIP: net.ParseIP("10.244.2.211"), SrcPort: 41947, DstIP: net.ParseIP("10.96.0.10"), DstPort: 6379},
	}
	got := FilterMigratableTCP(realOnly)
	if len(got) != 2 {
		t.Fatalf("FilterMigratableTCP(real-only) dropped entries: got %d, want 2", len(got))
	}
}
