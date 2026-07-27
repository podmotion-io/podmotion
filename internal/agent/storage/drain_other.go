/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build !linux

package storage

// drain_other.go — non-Linux stub for the storage I/O drain primitive (ADR-0394).
// syncfs(2) and the /proc/1/root host-namespace access path are Linux-only; on
// other platforms these are no-ops so the package still compiles for tooling/tests.

import "context"

// DrainResult mirrors the Linux struct so callers compile cross-platform.
type DrainResult struct {
	MountPath     string
	FSType        int64
	ParentFSType  int64
	IsMountpoint  bool
	BlocksTotal   uint64
	Synced        bool
	DurationMs    int64
	DirtyBeforeKB int64
	DirtyAfterKB  int64
}

// Verified mirrors the Linux predicate. On a non-Linux no-op nothing is proven.
func (r DrainResult) Verified() bool {
	return r.Synced && r.BlocksTotal > 0 && r.IsMountpoint
}

// ResolvePodCSIVolumeMounts is a no-op on non-Linux platforms.
func ResolvePodCSIVolumeMounts(string) ([]string, error) { return nil, nil }

// DrainVolumeMount is a no-op on non-Linux platforms.
func DrainVolumeMount(context.Context, string) (DrainResult, error) {
	return DrainResult{}, nil
}

// DrainPodVolumes is a no-op on non-Linux platforms.
func DrainPodVolumes(context.Context, string) ([]DrainResult, error) { return nil, nil }

// DrainPodVolumesErr is a no-op on non-Linux platforms.
func DrainPodVolumesErr(context.Context, string) error { return nil }
