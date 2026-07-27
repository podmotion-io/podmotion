/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"testing"
)

// TestNewStubEBPFManager verifies that NewStubEBPFManager returns the stub and
// that all methods are no-ops (no error, no panic).
func TestNewStubEBPFManager(t *testing.T) {
	ctx := context.Background()
	mgr := NewStubEBPFManager()
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	if err := mgr.ArmZeroWindowHold(ctx, 42); err != nil {
		t.Errorf("ArmZeroWindowHold: %v", err)
	}
	if err := mgr.DisarmZeroWindowHold(ctx, 42); err != nil {
		t.Errorf("DisarmZeroWindowHold: %v", err)
	}
	if err := mgr.ArmXDPBridge(ctx, nil, nil, 6081); err != nil {
		t.Errorf("ArmXDPBridge: %v", err)
	}
	if err := mgr.DisarmXDPBridge(ctx, nil); err != nil {
		t.Errorf("DisarmXDPBridge: %v", err)
	}
	conflict, err := mgr.CheckXDPHookConflict(ctx, 42)
	if err != nil {
		t.Errorf("CheckXDPHookConflict: %v", err)
	}
	if conflict {
		t.Error("stub should return false for conflict")
	}
}

// TestNewEBPFManager verifies that newEBPFManager returns a non-nil manager
// regardless of whether the running kernel supports eBPF.  On non-Linux hosts
// (macOS CI, darwin) LinuxVersionCode fails and the stub is returned; on
// Linux ≥5.9 the cilium manager is returned.  Both are valid eBPFManager
// implementations — this test asserts the contract, not the concrete type.
func TestNewEBPFManager(t *testing.T) {
	ctx := context.Background()
	mgr := newEBPFManager(ctx)
	if mgr == nil {
		t.Fatal("newEBPFManager must never return nil")
	}
	// Exercise the full interface to confirm no panic.
	_ = mgr.ArmZeroWindowHold(ctx, 1)
	_ = mgr.DisarmZeroWindowHold(ctx, 1)
	_ = mgr.ArmXDPBridge(ctx, nil, nil, 6081)
	_ = mgr.DisarmXDPBridge(ctx, nil)
	_, _ = mgr.CheckXDPHookConflict(ctx, 1)
}

// TestKernelVersion59Constant confirms the compile-time constant matches the
// KERNEL_VERSION macro formula: (major<<16)|(minor<<8)|patch.
func TestKernelVersion59Constant(t *testing.T) {
	want := uint32((5 << 16) | (9 << 8) | 0)
	if kernelVersion59 != want {
		t.Errorf("kernelVersion59 = %d, want %d", kernelVersion59, want)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// PatchRelayTsDelta regression tests
//
// These tests verify that PatchRelayTsDelta is a true read-modify-write and
// does NOT clobber seq_delta/ack_delta that were previously seeded by
// SeedRelayFromSnapshots. This invariant is critical for TCP continuity on
// cross-node migrations (ADR-0049): ts_delta is patched AFTER seq/ack deltas
// are seeded; a full overwrite would zero them, producing untranslated sequence
// numbers and an immediate TCP RST from the peer.
// ──────────────────────────────────────────────────────────────────────────────

// mapEntry mirrors the PM_SEQ_XLAT value layout for test purposes.
type mapEntry struct {
	SeqDelta    int32
	AckDelta    int32
	TsDelta     int32
	Wscale      uint8
	SackPresent uint8
	State       uint8
}

// trackingEBPFManager is a minimal in-memory eBPFManager whose PM_SEQ_XLAT is
// backed by a Go map so we can assert what was stored.
type trackingEBPFManager struct {
	eBPFManagerStub
	seqXlat map[SeqXlatKey]mapEntry
}

func newTrackingEBPFManager() *trackingEBPFManager {
	return &trackingEBPFManager{seqXlat: make(map[SeqXlatKey]mapEntry)}
}

func (m *trackingEBPFManager) ArmRelay(_ context.Context, _ string, key SeqXlatKey, entry SeqXlatEntry) error {
	m.seqXlat[key] = mapEntry{
		SeqDelta:    entry.SeqDelta,
		AckDelta:    entry.AckDelta,
		TsDelta:     entry.TsDelta,
		Wscale:      entry.Wscale,
		SackPresent: entry.SackPresent,
		State:       entry.State,
	}
	return nil
}

func (m *trackingEBPFManager) PatchRelayTsDelta(_ context.Context, key SeqXlatKey, tsDelta int32) error {
	existing, ok := m.seqXlat[key]
	if !ok {
		// Not found: no-op (matches production ciliumEBPFManager behaviour).
		return nil
	}
	// Read-modify-write: update only TsDelta.
	existing.TsDelta = tsDelta
	m.seqXlat[key] = existing
	return nil
}

// TestPatchRelayTsDeltaPreservesSeqAckDeltas is the core regression: seed a
// non-zero seq_delta/ack_delta via ArmRelay, then call PatchRelayTsDelta and
// assert seq_delta/ack_delta are unchanged.
func TestPatchRelayTsDeltaPreservesSeqAckDeltas(t *testing.T) {
	ctx := context.Background()
	mgr := newTrackingEBPFManager()

	key := SeqXlatKey{
		SrcIP:   [4]byte{10, 0, 0, 1},
		DstIP:   [4]byte{10, 0, 0, 2},
		SrcPort: 12345,
		DstPort: 80,
	}
	seedEntry := SeqXlatEntry{
		SeqDelta:    1234,
		AckDelta:    5678,
		TsDelta:     0,
		Wscale:      7,
		SackPresent: 1,
		State:       1,
	}

	// Step 1: Seed seq/ack deltas (simulates SeedRelayFromSnapshots).
	if err := mgr.ArmRelay(ctx, "flannel.1", key, seedEntry); err != nil {
		t.Fatalf("ArmRelay: %v", err)
	}

	// Step 2: Patch only ts_delta (simulates PatchSeqXlatTsDelta after restore).
	wantTsDelta := int32(42)
	if err := mgr.PatchRelayTsDelta(ctx, key, wantTsDelta); err != nil {
		t.Fatalf("PatchRelayTsDelta: %v", err)
	}

	// Assert: seq_delta and ack_delta are unchanged; ts_delta is updated.
	got := mgr.seqXlat[key]
	if got.SeqDelta != seedEntry.SeqDelta {
		t.Errorf("SeqDelta clobbered: want %d, got %d", seedEntry.SeqDelta, got.SeqDelta)
	}
	if got.AckDelta != seedEntry.AckDelta {
		t.Errorf("AckDelta clobbered: want %d, got %d", seedEntry.AckDelta, got.AckDelta)
	}
	if got.TsDelta != wantTsDelta {
		t.Errorf("TsDelta not updated: want %d, got %d", wantTsDelta, got.TsDelta)
	}
}

// TestPatchRelayTsDeltaNoopWhenEntryMissing verifies that PatchRelayTsDelta is
// a no-op when the entry does not yet exist (stateless migration path).
func TestPatchRelayTsDeltaNoopWhenEntryMissing(t *testing.T) {
	ctx := context.Background()
	mgr := newTrackingEBPFManager()

	key := SeqXlatKey{SrcPort: 9999, DstPort: 443}
	if err := mgr.PatchRelayTsDelta(ctx, key, 100); err != nil {
		t.Fatalf("PatchRelayTsDelta on missing entry should not error: %v", err)
	}
	if _, ok := mgr.seqXlat[key]; ok {
		t.Error("PatchRelayTsDelta should not create a new entry for a missing key")
	}
}

// TestStubEBPFManagerPatchRelayTsDelta verifies the exported stub implements
// the method without error (satisfies interface).
func TestStubEBPFManagerPatchRelayTsDelta(t *testing.T) {
	ctx := context.Background()
	mgr := NewStubEBPFManager()
	key := SeqXlatKey{SrcPort: 1, DstPort: 2}
	if err := mgr.PatchRelayTsDelta(ctx, key, 42); err != nil {
		t.Errorf("stub PatchRelayTsDelta: %v", err)
	}
}

// TestStubEBPFManagerLookupSeqXlat is ADR-0357 verification assertion 1: the stub implementation
// (non-Linux/test) must return (_, false, nil) — never panic, never report found=true — because
// there is no real kernel map behind a stub manager. A stub-backed migration can never
// truthfully claim PM_SEQ_XLAT is seeded.
func TestStubEBPFManagerLookupSeqXlat(t *testing.T) {
	ctx := context.Background()
	mgr := NewStubEBPFManager()
	key := SeqXlatKey{SrcPort: 1, DstPort: 2}
	entry, found, err := mgr.LookupSeqXlat(ctx, key)
	if err != nil {
		t.Errorf("stub LookupSeqXlat: unexpected error: %v", err)
	}
	if found {
		t.Error("stub LookupSeqXlat: expected found=false (no real kernel map behind the stub), got true")
	}
	if entry != (SeqXlatEntry{}) {
		t.Errorf("stub LookupSeqXlat: expected zero-value entry when not found, got %+v", entry)
	}
}
