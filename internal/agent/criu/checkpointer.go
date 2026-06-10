/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package criu owns all CRIU integration code for PodMotion (Agent 1).
//
// Architecture:
//   - Checkpointer interface: cold dump, pre-dump round, restore
//   - go-criu bindings wrap CRIU RPC — CRIU runs as a separate process (ADR-0002)
//   - StubCheckpointer used in M3/M4; replaced with CRIUCheckpointer once the node
//     image has CRIU installed and the kind cluster is running
//
// CRIU invocation model:
//   criu dump  --tree <PID> --images-dir <dir> --track-mem  (pre-dump)
//   criu dump  --tree <PID> --images-dir <dir> --prev-images-dir <prev> (final dump)
//   criu restore --images-dir <dir> --restore-detached
//
// All invocations go through go-criu RPC (LGPL-2.1, Apache-compatible).
// PodMotion never statically links CRIU (GPLv2). See ADR-0002.
package criu

import (
	"context"
	"time"
)

// CheckpointResult holds the output of a successful CRIU dump.
type CheckpointResult struct {
	// ImagesDir is the local path where CRIU wrote dump images.
	ImagesDir string
	// DirtyPagesMB is the number of dirty pages in the final dump (for stats).
	DirtyPagesMB int64
	// FreezeDurationMs is how long the container was frozen.
	FreezeDurationMs int64
	// RoundNumber is 0 for a cold/final dump; >0 for a pre-dump round.
	RoundNumber int
	// CheckpointedAt is when the dump completed.
	CheckpointedAt time.Time
}

// RestoreResult holds the output of a successful CRIU restore.
type RestoreResult struct {
	// PID is the root PID of the restored process tree.
	PID int
	// RestoredAt is when the restore completed.
	RestoredAt time.Time
}

// PreDumpOptions configures a single pre-dump round.
type PreDumpOptions struct {
	// ContainerID is the containerd container ID.
	ContainerID string
	// Namespace is the containerd namespace (usually "k8s.io").
	Namespace string
	// ImagesDir is where to write this round's dump images.
	ImagesDir string
	// PrevImagesDir is the previous round's images dir (empty for round 0).
	PrevImagesDir string
	// TrackMem enables dirty page tracking for the next round.
	TrackMem bool
}

// DumpOptions configures the final (freezing) CRIU dump.
type DumpOptions struct {
	ContainerID   string
	Namespace     string
	ImagesDir     string
	PrevImagesDir string // last pre-dump dir; empty for cold migration
	LeaveRunning  bool   // keep process running after dump (not valid for final freeze)
}

// RestoreOptions configures CRIU restore on the destination node.
type RestoreOptions struct {
	ContainerID string
	Namespace   string
	ImagesDir   string
	// BundleDir is the OCI bundle directory for the container (runc spec).
	BundleDir string
	// Detached restores the process tree detached from CRIU (normal production mode).
	Detached bool
}

// Checkpointer is the interface Agent 1 exposes to the orchestration layer.
// All methods are idempotent where possible — safe to retry on controller restart.
type Checkpointer interface {
	// PreDump performs one iterative pre-dump round without freezing the container.
	// Returns the dump result including dirty page count for convergence tracking.
	PreDump(ctx context.Context, opts PreDumpOptions) (CheckpointResult, error)

	// Dump performs the final (freezing) dump. The container is frozen for the
	// duration. Returns once the dump images are written to ImagesDir.
	Dump(ctx context.Context, opts DumpOptions) (CheckpointResult, error)

	// Restore recreates the container from dump images on the destination node.
	// The container starts running immediately after restore completes.
	Restore(ctx context.Context, opts RestoreOptions) (RestoreResult, error)

	// Abort cleans up any in-progress dump or restore, restoring the container
	// to a running state if it was frozen. Safe to call at any point.
	Abort(ctx context.Context, containerID, namespace string) error
}

// StubCheckpointer is used in M3 and tests. It records calls without invoking CRIU.
// Replace with CRIUCheckpointer once the kind node image is running.
type StubCheckpointer struct {
	// InjectDumpError makes Dump return this error (for failure path testing).
	InjectDumpError error
	// InjectRestoreError makes Restore return this error.
	InjectRestoreError error
	// SimulatedDirtyMB controls the reported dirty page count.
	SimulatedDirtyMB int64
	// SimulatedFreezeDurationMs controls the reported freeze window.
	SimulatedFreezeDurationMs int64

	// Recorded calls for test assertions.
	PreDumpCalls  []PreDumpOptions
	DumpCalls     []DumpOptions
	RestoreCalls  []RestoreOptions
	AbortCalls    []string
}

func (s *StubCheckpointer) PreDump(_ context.Context, opts PreDumpOptions) (CheckpointResult, error) {
	s.PreDumpCalls = append(s.PreDumpCalls, opts)
	dirtyMB := s.SimulatedDirtyMB
	if dirtyMB == 0 {
		dirtyMB = 128
	}
	return CheckpointResult{
		ImagesDir:        opts.ImagesDir,
		DirtyPagesMB:     dirtyMB,
		FreezeDurationMs: 0, // pre-dump doesn't freeze
		RoundNumber:      len(s.PreDumpCalls),
		CheckpointedAt:   time.Now(),
	}, nil
}

func (s *StubCheckpointer) Dump(_ context.Context, opts DumpOptions) (CheckpointResult, error) {
	s.DumpCalls = append(s.DumpCalls, opts)
	if s.InjectDumpError != nil {
		return CheckpointResult{}, s.InjectDumpError
	}
	freezeMs := s.SimulatedFreezeDurationMs
	if freezeMs == 0 {
		freezeMs = 150 // 150ms simulated freeze window
	}
	return CheckpointResult{
		ImagesDir:        opts.ImagesDir,
		DirtyPagesMB:     s.SimulatedDirtyMB,
		FreezeDurationMs: freezeMs,
		RoundNumber:      0,
		CheckpointedAt:   time.Now(),
	}, nil
}

func (s *StubCheckpointer) Restore(_ context.Context, opts RestoreOptions) (RestoreResult, error) {
	s.RestoreCalls = append(s.RestoreCalls, opts)
	if s.InjectRestoreError != nil {
		return RestoreResult{}, s.InjectRestoreError
	}
	return RestoreResult{
		PID:        99999, // fake PID
		RestoredAt: time.Now(),
	}, nil
}

func (s *StubCheckpointer) Abort(_ context.Context, containerID, _ string) error {
	s.AbortCalls = append(s.AbortCalls, containerID)
	return nil
}
