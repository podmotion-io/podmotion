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

// requireFDBInterface skips host-netlink-dependent tests when the VXLAN/overlay device
// they operate on is absent (e.g. kindnet substrate, CI without flannel). Arch-C fix per
// ADR-0192 §13: these are environment-dependent tests, not unit tests; skip (not fail)
// so the test suite is green on kindnet substrates while still asserting on flannel nodes.
func requireFDBInterface(t *testing.T, name string) {
	t.Helper()
	if _, err := net.InterfaceByName(name); err != nil {
		t.Skipf("skipping: interface %q not present on host (%v)", name, err)
	}
}

func validEntry() FDBEntry {
	return FDBEntry{
		IfName: "flannel.1",
		PodIP:  net.ParseIP("10.244.1.50"),
		PodMAC: net.HardwareAddr{0x02, 0xde, 0xad, 0xbe, 0xef, 0x01},
		VTEPIP: net.ParseIP("192.168.252.8"),
	}
}

func TestFDBManagerStub_AddFDBEntry(t *testing.T) {
	requireFDBInterface(t, "flannel.1")
	mgr := NewFDBManager()
	ctx := context.Background()

	if err := mgr.AddFDBEntry(ctx, validEntry()); err != nil {
		t.Fatalf("AddFDBEntry: unexpected error: %v", err)
	}
}

func TestFDBManagerStub_RemoveFDBEntry(t *testing.T) {
	requireFDBInterface(t, "flannel.1")
	mgr := NewFDBManager()
	ctx := context.Background()

	if err := mgr.RemoveFDBEntry(ctx, validEntry()); err != nil {
		t.Fatalf("RemoveFDBEntry: unexpected error: %v", err)
	}
}

func TestFDBManagerStub_ConfirmOverlayReady(t *testing.T) {
	requireFDBInterface(t, "flannel.1")
	mgr := NewFDBManager()
	ctx := context.Background()

	if err := mgr.ConfirmOverlayReady(ctx, validEntry()); err != nil {
		t.Fatalf("ConfirmOverlayReady: unexpected error: %v", err)
	}
}

func TestValidateFDBEntry(t *testing.T) {
	tests := []struct {
		name    string
		entry   FDBEntry
		wantErr bool
	}{
		{
			name:    "valid",
			entry:   validEntry(),
			wantErr: false,
		},
		{
			name: "missing IfName",
			entry: FDBEntry{
				PodIP:  net.ParseIP("10.244.1.50"),
				PodMAC: net.HardwareAddr{0x02, 0xde, 0xad, 0xbe, 0xef, 0x01},
				VTEPIP: net.ParseIP("192.168.252.8"),
			},
			wantErr: true,
		},
		{
			name: "nil PodIP",
			entry: FDBEntry{
				IfName: "flannel.1",
				PodMAC: net.HardwareAddr{0x02, 0xde, 0xad, 0xbe, 0xef, 0x01},
				VTEPIP: net.ParseIP("192.168.252.8"),
			},
			wantErr: true,
		},
		{
			name: "nil PodMAC",
			entry: FDBEntry{
				IfName: "flannel.1",
				PodIP:  net.ParseIP("10.244.1.50"),
				VTEPIP: net.ParseIP("192.168.252.8"),
			},
			wantErr: true,
		},
		{
			name: "nil VTEPIP",
			entry: FDBEntry{
				IfName: "flannel.1",
				PodIP:  net.ParseIP("10.244.1.50"),
				PodMAC: net.HardwareAddr{0x02, 0xde, 0xad, 0xbe, 0xef, 0x01},
			},
			wantErr: true,
		},
	}

	ctx := context.Background()
	mgr := NewFDBManager()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.wantErr {
				// The valid case calls ifaceIndex(entry.IfName) via the host netlink stack.
				// Skip when the interface is not present (kindnet substrate, CI without flannel).
				requireFDBInterface(t, tc.entry.IfName)
			}
			err := mgr.AddFDBEntry(ctx, tc.entry)
			if (err != nil) != tc.wantErr {
				t.Errorf("AddFDBEntry(%s): wantErr=%v, got err=%v", tc.name, tc.wantErr, err)
			}
		})
	}
}

// TestNewFDBManager verifies that NewFDBManager returns a non-nil FDBManager.
func TestNewFDBManager(t *testing.T) {
	mgr := NewFDBManager()
	if mgr == nil {
		t.Fatal("NewFDBManager must not return nil")
	}
}
