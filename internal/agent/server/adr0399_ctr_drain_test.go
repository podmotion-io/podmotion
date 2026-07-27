/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

// adr0399_ctr_drain_test.go — ADR-0399 unit coverage for the fail-closed storage
// drain shared by BOTH live checkpoint seizes (the containerd-native default path
// and the raw-CRIU fallback).
//
// ADR-0394 wired the drain only before the raw-CRIU Dump; the containerd-native
// `ctr tasks checkpoint` path is tried FIRST and returns before that drain is ever
// reached, so the default path dumped over unflushed writeback (fail-open by
// omission). ADR-0399 §Decision-1 adds a fail-closed drain immediately before
// ctrCheckpoint, and §Decision-3 keeps a SECOND symmetric drain before the raw
// Dump (correctness-required on the recoverable-failure fallthrough). Both seize
// sites go through drainPodVolumesFailClosed, so these assertions pin the contract
// both paths inherit.

import (
	"context"
	"errors"
	"testing"

	pmstorage "github.com/podmotion-io/podmotion/internal/agent/storage"
)

// withDrainFn swaps the package drain seam for the duration of a test and restores
// it, so the fail-closed contract can be exercised without a real host mount.
func withDrainFn(t *testing.T, fn func(context.Context, string) ([]pmstorage.DrainResult, error)) {
	t.Helper()
	prev := drainPodVolumesFn
	drainPodVolumesFn = fn
	t.Cleanup(func() { drainPodVolumesFn = prev })
}

// TestDrainFailClosed_UnverifiedFlush_HardStops is the load-bearing fail-closed
// phase-integrity assertion for the ctr path: when the drain primitive returns an error
// (an un-drainable / non-distinct CSI mount), the helper returns a non-nil error
// that WRAPS the cause. In the handler this error is returned before ctrCheckpoint
// (and before the raw Dump) is ever called — the checkpoint hard-stops rather than
// dumping over an unproven-consistent volume.
func TestDrainFailClosed_UnverifiedFlush_HardStops(t *testing.T) {
	sentinel := errors.New("drain: /mnt/csi is not a distinct mountpoint")
	called := false
	withDrainFn(t, func(_ context.Context, podUID string) ([]pmstorage.DrainResult, error) {
		called = true
		if podUID != "pod-abc" {
			t.Fatalf("helper passed wrong podUID: %q", podUID)
		}
		// An unverified result set accompanying the error must NOT be treated as a
		// proven flush.
		return []pmstorage.DrainResult{{MountPath: "/mnt/csi", Synced: true, BlocksTotal: 1, IsMountpoint: false}}, sentinel
	})

	err := drainPodVolumesFailClosed(context.Background(), "mig-1", "pod-abc")
	if err == nil {
		t.Fatal("expected fail-closed error when the drain is unverified, got nil (would dump over unflushed writeback)")
	}
	if !called {
		t.Fatal("drain primitive was never invoked")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("fail-closed error must wrap the underlying drain cause, got: %v", err)
	}
}

// TestDrainFailClosed_NoCSIVolume_Proceeds asserts a pod with no CSI volume mount
// drains to (nil, nil) and the helper returns nil — nothing to drain is not a
// failure and must NOT hard-stop the checkpoint on either path.
func TestDrainFailClosed_NoCSIVolume_Proceeds(t *testing.T) {
	withDrainFn(t, func(_ context.Context, _ string) ([]pmstorage.DrainResult, error) {
		return nil, nil
	})
	if err := drainPodVolumesFailClosed(context.Background(), "mig-1", "pod-no-vol"); err != nil {
		t.Fatalf("pod with no CSI volume must proceed (nil), got: %v", err)
	}
}

// TestDrainFailClosed_VerifiedFlush_Proceeds asserts a verified flush returns nil
// (the checkpoint proceeds to the seize).
func TestDrainFailClosed_VerifiedFlush_Proceeds(t *testing.T) {
	withDrainFn(t, func(_ context.Context, _ string) ([]pmstorage.DrainResult, error) {
		return []pmstorage.DrainResult{{MountPath: "/mnt/csi", Synced: true, BlocksTotal: 4096, IsMountpoint: true}}, nil
	})
	if err := drainPodVolumesFailClosed(context.Background(), "mig-1", "pod-ok"); err != nil {
		t.Fatalf("a verified flush must proceed (nil), got: %v", err)
	}
}

// TestDrainFailClosed_EmptyPodUID_IsNoOp asserts the podUID guard: an empty podUID
// short-circuits to nil WITHOUT invoking the drain primitive. This preserves the
// original `if podUID != ""` guard both seize sites had, so an empty podUID (no
// pod-scoped volume to drain) never turns into a spurious checkpoint hard-stop nor
// hits the resolver's empty-UID error.
func TestDrainFailClosed_EmptyPodUID_IsNoOp(t *testing.T) {
	called := false
	withDrainFn(t, func(_ context.Context, _ string) ([]pmstorage.DrainResult, error) {
		called = true
		return nil, errors.New("resolver should never be reached for empty podUID")
	})
	if err := drainPodVolumesFailClosed(context.Background(), "mig-1", ""); err != nil {
		t.Fatalf("empty podUID must be a no-op returning nil, got: %v", err)
	}
	if called {
		t.Fatal("empty podUID must NOT invoke the drain primitive")
	}
}
