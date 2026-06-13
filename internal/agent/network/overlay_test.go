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
