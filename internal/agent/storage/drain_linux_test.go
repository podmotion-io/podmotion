/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build linux

package storage_test

// drain_linux_test.go — ADR-0394 below-app storage I/O drain unit coverage.
//
// The single most important assertion here is the fail-closed drain regression (ADR-0394): a
// failed/unverified drain must NOT be treated as a proven flush. That is enforced
// two ways — DrainResult.Verified() rejects every combination missing any of the
// three load-bearing signals, and DrainVolumeMount returns a fail-closed error on
// a non-distinct mountpoint (a syncfs of the node root fs, not the pod volume),
// on a zero-block path, and on a symlinked leaf (O_NOFOLLOW, §Decision-4a).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pmstorage "github.com/podmotion-io/podmotion/internal/agent/storage"
)

// TestDrainResult_Verified_Predicate is the §Decision-3a fail-closed regression:
// the go-True predicate accepts ONLY Synced && BlocksTotal>0 && IsMountpoint, and
// rejects every combination with any one signal missing. meminfo is deliberately
// not part of the predicate.
func TestDrainResult_Verified_Predicate(t *testing.T) {
	cases := []struct {
		name   string
		res    pmstorage.DrainResult
		verify bool
	}{
		{"all-three-present", pmstorage.DrainResult{Synced: true, BlocksTotal: 1, IsMountpoint: true}, true},
		{"not-synced", pmstorage.DrainResult{Synced: false, BlocksTotal: 1, IsMountpoint: true}, false},
		{"zero-blocks", pmstorage.DrainResult{Synced: true, BlocksTotal: 0, IsMountpoint: true}, false},
		{"not-mountpoint", pmstorage.DrainResult{Synced: true, BlocksTotal: 1, IsMountpoint: false}, false},
		{"synced-only", pmstorage.DrainResult{Synced: true}, false},
		{"blocks-only", pmstorage.DrainResult{BlocksTotal: 1}, false},
		{"mountpoint-only", pmstorage.DrainResult{IsMountpoint: true}, false},
		{"meminfo-does-not-rescue", pmstorage.DrainResult{Synced: true, BlocksTotal: 1, IsMountpoint: false, DirtyBeforeKB: 100, DirtyAfterKB: 0}, false},
		{"zero-value", pmstorage.DrainResult{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.Verified(); got != tc.verify {
				t.Fatalf("Verified() = %v, want %v for %+v", got, tc.verify, tc.res)
			}
		})
	}
}

// TestDrainVolumeMount_NonDistinctMountpoint_FailsClosed is the load-bearing
// §Decision-3a assertion at the syscall boundary: a real, populated directory that
// is NOT a distinct mountpoint from its parent (an ordinary subdir on the node fs)
// must return a fail-closed error, NOT a bare WARNING with a "successful" flush.
// syncfs of that path would flush the node root fs while claiming the pod volume.
func TestDrainVolumeMount_NonDistinctMountpoint_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "mount")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	res, err := pmstorage.DrainVolumeMount(context.Background(), sub)
	if err == nil {
		t.Fatalf("expected fail-closed error for non-distinct mountpoint, got nil (res=%+v)", res)
	}
	if !strings.Contains(err.Error(), "not a distinct mountpoint") {
		t.Fatalf("expected 'not a distinct mountpoint' error, got: %v", err)
	}
	if res.Verified() {
		t.Fatalf("result must not be Verified() on a non-distinct mountpoint: %+v", res)
	}
	// It is a real, populated fs (tmpdir), so blocks>0 — proving blocks alone is
	// NOT sufficient and distinctness is what catches the wrong-fs flush.
	if res.BlocksTotal == 0 {
		t.Fatalf("expected a populated fs under BlocksTotal>0, got 0 (test premise broken)")
	}
	if res.IsMountpoint {
		t.Fatalf("subdir of tmpdir must not be a distinct mountpoint")
	}
}

// TestDrainVolumeMount_SymlinkLeaf_FailsClosed asserts the §Decision-4a O_NOFOLLOW
// hardening: a symlink at the mount leaf is refused (ELOOP), not silently followed
// to an attacker-chosen filesystem.
func TestDrainVolumeMount_SymlinkLeaf_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(dir, "mount")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	res, err := pmstorage.DrainVolumeMount(context.Background(), link)
	if err == nil {
		t.Fatalf("expected O_NOFOLLOW fail-closed error for symlinked leaf, got nil (res=%+v)", res)
	}
	if res.Verified() {
		t.Fatalf("symlinked leaf must not yield a Verified() result: %+v", res)
	}
}

// TestDrainVolumeMount_Nonexistent_FailsClosed asserts an unopenable path is an
// error, never a claimed flush.
func TestDrainVolumeMount_Nonexistent_FailsClosed(t *testing.T) {
	res, err := pmstorage.DrainVolumeMount(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatalf("expected error opening a nonexistent mount, got nil (res=%+v)", res)
	}
	if res.Verified() {
		t.Fatalf("nonexistent path must not yield Verified(): %+v", res)
	}
}

// TestResolvePodCSIVolumeMounts_EmptyPodUID_Errors guards the resolver against an
// empty podUID (which would otherwise glob a wrong, overly-broad path).
func TestResolvePodCSIVolumeMounts_EmptyPodUID_Errors(t *testing.T) {
	if _, err := pmstorage.ResolvePodCSIVolumeMounts(""); err == nil {
		t.Fatalf("expected error for empty podUID, got nil")
	}
}

// TestDrainPodVolumes_NoCSIVolume_IsNotAnError asserts a pod with no CSI volume
// mount drains to (nil, nil): nothing to drain is not a failure, so it must not
// hard-stop the checkpoint. Uses a random UID that resolves to no mounts under the
// (absent in the test env) kubelet path.
func TestDrainPodVolumes_NoCSIVolume_IsNotAnError(t *testing.T) {
	results, err := pmstorage.DrainPodVolumes(context.Background(), "no-such-pod-uid-0000")
	if err != nil {
		t.Fatalf("pod with no CSI volume must not error, got: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no drain results for a pod with no CSI volume, got %d", len(results))
	}
}
