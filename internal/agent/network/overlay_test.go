// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/network"
)

var errFDBNotFound = errors.New("neighbor entry not found")

// mockOverlayFDBManager implements FDBManager for barrier tests.
type mockOverlayFDBManager struct {
	confirmErr error
}

func (m *mockOverlayFDBManager) AddFDBEntry(_ context.Context, _ network.FDBEntry) error {
	return nil
}
func (m *mockOverlayFDBManager) RemoveFDBEntry(_ context.Context, _ network.FDBEntry) error {
	return nil
}
func (m *mockOverlayFDBManager) ConfirmOverlayReady(_ context.Context, _ network.FDBEntry) error {
	return m.confirmErr
}

func sampleFDBEntry() *network.FDBEntry {
	return &network.FDBEntry{
		IfName: "flannel.1",
		PodIP:  net.ParseIP("10.244.1.5"),
		PodMAC: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02},
		VTEPIP: net.ParseIP("192.168.1.2"),
	}
}

func TestCheckAtomicityBarrier_AllSatisfied(t *testing.T) {
	p := network.BarrierPredicates{
		SeqXlatSeeded:        true,
		SourceConntrackArmed: true,
		DestConntrackArmed:   true,
		RestoreComplete:      true,
		FDBManager:           &mockOverlayFDBManager{},
	}
	result, err := network.CheckAtomicityBarrier(context.Background(), p)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !result.BPredicate {
		t.Error("expected predicate B to be satisfied")
	}
	if !result.CFdbSource || !result.DFdbDest {
		t.Error("expected predicates C+D to be satisfied (nil FDB entries = stateless migration)")
	}
	if !result.EPredicate {
		t.Error("expected predicate E to be satisfied")
	}
	if !result.FPredicate {
		t.Error("expected predicate F to be satisfied")
	}
}

func TestCheckAtomicityBarrier_MissingB(t *testing.T) {
	p := network.BarrierPredicates{
		SeqXlatSeeded:        false,
		SourceConntrackArmed: true,
		DestConntrackArmed:   true,
		RestoreComplete:      true,
		FDBManager:           &mockOverlayFDBManager{},
	}
	_, err := network.CheckAtomicityBarrier(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for unsatisfied predicate B")
	}
}

func TestCheckAtomicityBarrier_FDBConfirmFails(t *testing.T) {
	fdbEntry := sampleFDBEntry()
	p := network.BarrierPredicates{
		SeqXlatSeeded:        true,
		SourceFDBEntry:       fdbEntry,
		DestFDBEntry:         fdbEntry,
		SourceConntrackArmed: true,
		DestConntrackArmed:   true,
		RestoreComplete:      true,
		FDBManager:           &mockOverlayFDBManager{confirmErr: errFDBNotFound},
	}
	_, err := network.CheckAtomicityBarrier(context.Background(), p)
	if err == nil {
		t.Fatal("expected error when FDB confirm fails")
	}
}

func TestCheckAtomicityBarrier_NoFDBManager(t *testing.T) {
	p := network.BarrierPredicates{
		SeqXlatSeeded:        true,
		SourceConntrackArmed: true,
		DestConntrackArmed:   true,
		RestoreComplete:      true,
		FDBManager:           nil,
	}
	result, err := network.CheckAtomicityBarrier(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.CFdbSource || !result.DFdbDest {
		t.Error("expected C+D to be trivially satisfied when FDBManager is nil")
	}
}

func TestCheckAtomicityBarrier_MultipleFailures(t *testing.T) {
	p := network.BarrierPredicates{
		SeqXlatSeeded:        false,
		SourceConntrackArmed: false,
		DestConntrackArmed:   false,
		RestoreComplete:      false,
		FDBManager:           nil,
	}
	_, err := network.CheckAtomicityBarrier(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for multiple unsatisfied predicates")
	}
}

// TestCheckAtomicityBarrier_EmptySnapshot_SeqXlatSeededTrue verifies ADR-0163:
// when TCPSeqSnapshots is empty (cold/stateless migration), barrier B is trivially
// satisfied and SeqXlatSeeded must be true so CheckAtomicityBarrier does not
// emit "B: PM_SEQ_XLAT not seeded" (Sprint 32 gate blocker B5).
func TestCheckAtomicityBarrier_EmptySnapshot_SeqXlatSeededTrue(t *testing.T) {
	// Simulate the controller-side computation: len(snapshots)==0 => seqXlatSeeded=true.
	snapshots := []network.SeqSnapshot{}
	relaySeedConfirmed := false // relay never called — no snapshots to seed
	seqXlatSeeded := len(snapshots) == 0 || relaySeedConfirmed

	p := network.BarrierPredicates{
		SeqXlatSeeded:        seqXlatSeeded,
		SourceConntrackArmed: true,
		DestConntrackArmed:   true,
		RestoreComplete:      true,
		FDBManager:           nil,
	}
	result, err := network.CheckAtomicityBarrier(context.Background(), p)
	if err != nil {
		t.Fatalf("empty-snapshot cold migration: CheckAtomicityBarrier returned error: %v", err)
	}
	if !result.BPredicate {
		t.Error("empty-snapshot cold migration: expected predicate B satisfied (ADR-0163 barrier-B trivially satisfied)")
	}
}

// TestCheckAtomicityBarrier_NonEmptySnapshot_RelaySeedConfirmed verifies ADR-0163:
// when TCPSeqSnapshots is non-empty, seqXlatSeeded must equal relaySeedConfirmed.
func TestCheckAtomicityBarrier_NonEmptySnapshot_RelaySeedConfirmed(t *testing.T) {
	snapshots := []network.SeqSnapshot{{SrcIP: "10.0.0.1", SrcPort: 1234, DstIP: "10.0.0.2", DstPort: 5678}}

	t.Run("relay_seeded", func(t *testing.T) {
		relaySeedConfirmed := true
		seqXlatSeeded := len(snapshots) == 0 || relaySeedConfirmed
		p := network.BarrierPredicates{
			SeqXlatSeeded:        seqXlatSeeded,
			SourceConntrackArmed: true,
			DestConntrackArmed:   true,
			RestoreComplete:      true,
		}
		_, err := network.CheckAtomicityBarrier(context.Background(), p)
		if err != nil {
			t.Fatalf("relay seeded: unexpected barrier error: %v", err)
		}
	})

	t.Run("relay_not_seeded", func(t *testing.T) {
		relaySeedConfirmed := false
		seqXlatSeeded := len(snapshots) == 0 || relaySeedConfirmed
		p := network.BarrierPredicates{
			SeqXlatSeeded:        seqXlatSeeded,
			SourceConntrackArmed: true,
			DestConntrackArmed:   true,
			RestoreComplete:      true,
		}
		_, err := network.CheckAtomicityBarrier(context.Background(), p)
		if err == nil {
			t.Fatal("relay not seeded with non-empty snapshots: expected barrier error for unsatisfied B")
		}
	})
}

func TestComputePAWSTsDelta(t *testing.T) {
	cases := []struct {
		name   string
		srcNs  int64
		dstNs  int64
		wantMs int32
	}{
		{"zero offset", 0, 0, 0},
		{"1ms positive", 0, 1_000_000, 1},
		{"500ms positive", 0, 500_000_000, 500},
		{"1s negative skew", 1_000_000_000, 0, -1000},
		{"equal clocks", 5_000_000_000, 5_000_000_000, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := network.ComputePAWSTsDelta(tc.srcNs, tc.dstNs)
			if got != tc.wantMs {
				t.Errorf("ComputePAWSTsDelta(%d, %d) = %d, want %d", tc.srcNs, tc.dstNs, got, tc.wantMs)
			}
		})
	}
}
