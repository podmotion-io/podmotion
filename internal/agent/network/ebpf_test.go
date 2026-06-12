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
