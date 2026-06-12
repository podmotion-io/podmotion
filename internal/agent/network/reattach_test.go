/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"net"
	"testing"
)

func TestIpPortToSeqXlatKey(t *testing.T) {
	srcIP := net.ParseIP("10.244.1.50").To4()
	dstIP := net.ParseIP("10.244.0.50").To4()
	key := ipPortToSeqXlatKey(srcIP, 12345, dstIP, 5432)
	if key.SrcPort != 12345 || key.DstPort != 5432 {
		t.Fatalf("unexpected ports: %+v", key)
	}
	if key.SrcIP[0] != 10 || key.DstIP[0] != 10 {
		t.Fatalf("unexpected IPs: %+v", key)
	}
}

func TestSeedRelayFromSnapshots_EmptySnapshots(t *testing.T) {
	ctx := context.Background()
	mgr := &eBPFManagerStub{}
	results, err := SeedRelayFromSnapshots(ctx, 1, nil, "flannel.1", mgr)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected empty results, got %d", len(results))
	}
}

// TestSeedRelayFromFreshSocket_ZeroDeltas verifies that when the restored container PID
// is not accessible (non-Linux, pid=0), SeedRelayFromFreshSocket produces zero deltas and
// calls ArmRelay (stub) without error. Zero deltas are safe: PM_SEQ_XLAT becomes a
// transparent passthrough.
func TestSeedRelayFromFreshSocket_ZeroDeltas(t *testing.T) {
	ctx := context.Background()
	mgr := &eBPFManagerStub{}

	localIP := net.ParseIP("10.244.1.50").To4()
	peerIP := net.ParseIP("10.244.0.50").To4()

	// sourceFinalSndNxt == freshSndNxt (both zero since /proc won't have the socket):
	// seq_delta = 0, ack_delta = 0.
	result, err := SeedRelayFromFreshSocket(
		ctx,
		0, // freshPID=0 → SocketInventory returns empty
		localIP, 12345,
		peerIP, 5432,
		0x100, 0x200, // sourceFinalSndNxt, sourceFinalRcvNxt
		"flannel.1",
		mgr,
	)
	if err != nil {
		t.Fatal(err)
	}
	// fresh seq is 0 (socket not found), so deltas == source values mod 2^32.
	expectedSeqDelta := int32(0x100)
	expectedAckDelta := int32(0x200)
	if result.SeqDelta != expectedSeqDelta {
		t.Errorf("SeqDelta: got %d, want %d", result.SeqDelta, expectedSeqDelta)
	}
	if result.AckDelta != expectedAckDelta {
		t.Errorf("AckDelta: got %d, want %d", result.AckDelta, expectedAckDelta)
	}
}

// TestSeedRelayFromSnapshots_InvalidIP verifies that a malformed IP in a SeqSnapshot
// returns an error rather than silently computing garbage deltas.
func TestSeedRelayFromSnapshots_InvalidIP(t *testing.T) {
	ctx := context.Background()
	mgr := &eBPFManagerStub{}

	snaps := []SeqSnapshot{{
		SrcIP:   "not-an-ip",
		SrcPort: 12345,
		DstIP:   "10.244.0.50",
		DstPort: 5432,
		SndNxt:  100,
		RcvNxt:  200,
	}}

	_, err := SeedRelayFromSnapshots(ctx, 0, snaps, "flannel.1", mgr)
	if err == nil {
		t.Fatal("expected error for invalid IP, got nil")
	}
}
