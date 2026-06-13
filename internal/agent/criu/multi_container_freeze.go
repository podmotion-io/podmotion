/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package criu

// multi_container_freeze.go — ConsistentFreeze for multi-container pod checkpointing.
//
// Implements ADR-0107: atomic cgroup-level freeze of all containers in a pod,
// with sidecar ordering and dump sequencing (sidecars first, app container last).
//
// Cgroup v2: write "1" to <podCgroupPath>/cgroup.freeze, poll cgroup.events for "frozen 1".
// Cgroup v1: write "FROZEN" to <podCgroupPath>/freezer.state, poll until it reads "FROZEN".
// Maximum freeze-confirmation wait: 200ms (ADR-0107 §1).
//
// CRIU is invoked as a subprocess via go-criu RPC (ADR-0002 — never statically linked).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// FreezeConfirmTimeout is the maximum time to wait for the cgroup to report frozen=1
// after writing the freeze command. Per ADR-0107 §1 Decision.
const FreezeConfirmTimeout = 200 * time.Millisecond

// freezePollInterval is how often to re-read the cgroup events file while polling.
const freezePollInterval = 2 * time.Millisecond

// ErrConsistentFreezeTimeout is returned when the cgroup does not reach frozen=1
// within FreezeConfirmTimeout.
var ErrConsistentFreezeTimeout = errors.New("ConsistentFreezeTimeout")

// ErrConsistentFreezePartialDump is returned when CRIU dump of one or more containers
// fails — see ADR-0107 §4 invariant I2.
var ErrConsistentFreezePartialDump = errors.New("PartialDumpFailed")

// ContainerRole classifies a container within a pod for ordering purposes.
// Order: NativeSidecar < RegularSidecar < App (ADR-0107 §3).
type ContainerRole int

const (
	// ContainerRoleNativeSidecar is an initContainer with restartPolicy=Always.
	ContainerRoleNativeSidecar ContainerRole = iota
	// ContainerRoleRegularSidecar is a non-app, non-init sidecar container.
	ContainerRoleRegularSidecar
	// ContainerRoleApp is the primary application container.
	ContainerRoleApp
)

// PodContainer describes one container in a pod for multi-container freeze.
type PodContainer struct {
	// Name is the container name as it appears in the pod spec.
	Name string
	// Pid is the host-namespace root PID of the container.
	Pid int32
	// Role determines dump ordering (ADR-0107 §3).
	Role ContainerRole
	// SpecIndex is the container's position in the pod spec (for stable ordering
	// within a Role group).
	SpecIndex int
	// CheckpointDir is where CRIU dump images for this container should be written.
	// Must follow the layout: ${CHECKPOINT_DIR}/${container_name}/
	CheckpointDir string
}

// CgroupVersion is the cgroup hierarchy version in use on the node.
type CgroupVersion int

const (
	CgroupV2 CgroupVersion = 2
	CgroupV1 CgroupVersion = 1
)

// FreezeResult is returned by ConsistentFreeze on success.
type FreezeResult struct {
	// FrozenAt is the wall-clock time at which cgroup.events confirmed "frozen 1".
	FrozenAt time.Time
	// FreezeDurationMs is the elapsed time from the freeze write to frozen confirmation.
	FreezeDurationMs int64
	// DumpResults maps container name → CheckpointResult for each dumped container.
	DumpResults map[string]CheckpointResult
}

// ConsistentFreezeOptions configures a multi-container consistent freeze+dump.
type ConsistentFreezeOptions struct {
	// PodCgroupPath is the path to the pod-level cgroup directory.
	// e.g. /sys/fs/cgroup/kubepods/pod<uid>
	PodCgroupPath string
	// CgroupVersion specifies whether the node uses cgroup v1 or v2.
	CgroupVersion CgroupVersion
	// Containers is the ordered list of containers to checkpoint.
	// ConsistentFreeze will sort them by Role,SpecIndex before dumping.
	Containers []PodContainer
	// Checkpointer is the CRIU checkpointer to use for individual container dumps.
	// Uses go-criu RPC (ADR-0002).
	Checkpointer Checkpointer
	// DumpOptions provides default CRIU dump options (Pid and CheckpointDir are
	// overridden per container).
	DumpOptions DumpOptions
}

// ConsistentFreeze atomically freezes all containers in the pod using the cgroup
// freezer, then dumps each container in the ordering mandated by ADR-0107 §3:
//
//  1. Native sidecars (initContainers with restartPolicy=Always)
//  2. Regular sidecar containers (non-app, non-init)
//  3. Application container(s)
//
// The entire pod cgroup is frozen before any CRIU dump begins (ADR-0107 §1 invariant I1).
// If CRIU dump of any container fails, all partial checkpoint artifacts are removed and
// ErrConsistentFreezePartialDump is returned (invariant I2).
//
// On darwin this is a no-op returning darwinError() — CRIU is Linux-only.
func ConsistentFreeze(ctx context.Context, opts ConsistentFreezeOptions) (FreezeResult, error) {
	if runtime.GOOS == "darwin" {
		return FreezeResult{}, darwinError()
	}
	return consistentFreezeImpl(ctx, opts)
}

// consistentFreezeImpl is the platform-independent implementation of ConsistentFreeze.
// It is separated from ConsistentFreeze to allow unit testing on darwin without the
// OS guard blocking execution — tests call this function directly.
func consistentFreezeImpl(ctx context.Context, opts ConsistentFreezeOptions) (FreezeResult, error) {
	if err := ctx.Err(); err != nil {
		return FreezeResult{}, fmt.Errorf("context cancelled before ConsistentFreeze: %w", err)
	}

	if len(opts.Containers) == 0 {
		return FreezeResult{}, fmt.Errorf("ConsistentFreeze: no containers specified")
	}

	if opts.Checkpointer == nil {
		return FreezeResult{}, fmt.Errorf("ConsistentFreeze: Checkpointer must not be nil")
	}

	logger := logf.FromContext(ctx)

	// ── Step 1: Atomic cgroup freeze ─────────────────────────────────────────────

	freezeStart := time.Now()

	if err := writeCgroupFreeze(opts.PodCgroupPath, opts.CgroupVersion); err != nil {
		return FreezeResult{}, fmt.Errorf("ConsistentFreeze: writing freeze command: %w", err)
	}

	// Poll for frozen confirmation (max 200ms, ADR-0107 §1).
	if err := waitFrozen(ctx, opts.PodCgroupPath, opts.CgroupVersion, FreezeConfirmTimeout); err != nil {
		// Thaw before returning so the pod is not stuck frozen.
		_ = writeCgroupThaw(opts.PodCgroupPath, opts.CgroupVersion)
		return FreezeResult{}, fmt.Errorf("ConsistentFreeze: %w: %w", ErrConsistentFreezeTimeout, err)
	}

	frozenAt := time.Now()
	freezeDurationMs := frozenAt.Sub(freezeStart).Milliseconds()

	logger.Info("ConsistentFreeze: pod cgroup frozen",
		"podCgroupPath", opts.PodCgroupPath,
		"freezeDurationMs", freezeDurationMs,
		"containerCount", len(opts.Containers),
	)

	// ── Step 2: CRIU dump each container in spec order (sidecars first, app last) ─

	ordered := sortedContainers(opts.Containers)
	dumpResults := make(map[string]CheckpointResult, len(ordered))
	var dumpedDirs []string // for cleanup on partial failure

	for _, c := range ordered {
		if err := ctx.Err(); err != nil {
			// Context cancelled mid-dump — clean up and thaw.
			zeroizeCheckpoints(dumpedDirs)
			_ = writeCgroupThaw(opts.PodCgroupPath, opts.CgroupVersion)
			return FreezeResult{}, fmt.Errorf("ConsistentFreeze: context cancelled during dump of %q: %w", c.Name, err)
		}

		containerDir := c.CheckpointDir
		if containerDir == "" {
			containerDir = filepath.Join(opts.DumpOptions.ImagesDir, c.Name)
		}

		if err := os.MkdirAll(containerDir, 0o700); err != nil {
			zeroizeCheckpoints(dumpedDirs)
			_ = writeCgroupThaw(opts.PodCgroupPath, opts.CgroupVersion)
			return FreezeResult{}, fmt.Errorf("%w: MkdirAll(%s): %w", ErrConsistentFreezePartialDump, containerDir, err)
		}

		containerOpts := opts.DumpOptions
		containerOpts.Pid = c.Pid
		containerOpts.ImagesDir = containerDir
		containerOpts.ContainerID = c.Name

		logger.Info("ConsistentFreeze: dumping container",
			"container", c.Name,
			"pid", c.Pid,
			"role", c.Role,
			"imagesDir", containerDir,
		)

		result, err := opts.Checkpointer.Dump(ctx, containerOpts)
		if err != nil {
			// Invariant I2: partial dump → remove all artifacts and fail.
			zeroizeCheckpoints(dumpedDirs)
			_ = writeCgroupThaw(opts.PodCgroupPath, opts.CgroupVersion)
			return FreezeResult{}, fmt.Errorf("%w: container %q dump failed: %w", ErrConsistentFreezePartialDump, c.Name, err)
		}

		dumpedDirs = append(dumpedDirs, containerDir)
		dumpResults[c.Name] = result

		logger.Info("ConsistentFreeze: container dump complete",
			"container", c.Name,
			"freezeDurationMs", result.FreezeDurationMs,
		)
	}

	return FreezeResult{
		FrozenAt:         frozenAt,
		FreezeDurationMs: freezeDurationMs,
		DumpResults:      dumpResults,
	}, nil
}

// ── cgroup freeze/thaw helpers ────────────────────────────────────────────────

// writeCgroupFreeze writes the freeze command to the pod-level cgroup.
func writeCgroupFreeze(podCgroupPath string, ver CgroupVersion) error {
	return writeCgroupFreezerFile(podCgroupPath, ver, true)
}

// writeCgroupThaw writes the thaw command to the pod-level cgroup.
func writeCgroupThaw(podCgroupPath string, ver CgroupVersion) error {
	return writeCgroupFreezerFile(podCgroupPath, ver, false)
}

func writeCgroupFreezerFile(podCgroupPath string, ver CgroupVersion, freeze bool) error {
	var path, value string
	if ver == CgroupV2 {
		path = filepath.Join(podCgroupPath, "cgroup.freeze")
		if freeze {
			value = "1"
		} else {
			value = "0"
		}
	} else {
		path = filepath.Join(podCgroupPath, "freezer.state")
		if freeze {
			value = "FROZEN"
		} else {
			value = "THAWED"
		}
	}
	return os.WriteFile(path, []byte(value), 0o600)
}

// waitFrozen polls the cgroup events file until the pod cgroup is fully frozen
// or timeout expires. Returns ErrConsistentFreezeTimeout if not frozen in time.
func waitFrozen(ctx context.Context, podCgroupPath string, ver CgroupVersion, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("cgroup not frozen within %s", timeout)
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		frozen, err := isCgroupFrozen(podCgroupPath, ver)
		if err != nil {
			return fmt.Errorf("polling cgroup frozen state: %w", err)
		}
		if frozen {
			return nil
		}
		time.Sleep(freezePollInterval)
	}
}

// isCgroupFrozen returns true when the cgroup reports frozen state.
// Cgroup v2: cgroup.events contains "frozen 1".
// Cgroup v1: freezer.state reads "FROZEN".
func isCgroupFrozen(podCgroupPath string, ver CgroupVersion) (bool, error) {
	var eventsPath string
	if ver == CgroupV2 {
		eventsPath = filepath.Join(podCgroupPath, "cgroup.events")
	} else {
		eventsPath = filepath.Join(podCgroupPath, "freezer.state")
	}

	data, err := os.ReadFile(eventsPath)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", eventsPath, err)
	}

	content := strings.TrimSpace(string(data))
	if ver == CgroupV2 {
		// cgroup.events is a multi-line file; look for the "frozen 1" entry.
		for _, line := range strings.Split(content, "\n") {
			if strings.TrimSpace(line) == "frozen 1" {
				return true, nil
			}
		}
		return false, nil
	}
	// cgroup v1 freezer.state: "FROZEN", "FREEZING", or "THAWED".
	return content == "FROZEN", nil
}

// ── container ordering ─────────────────────────────────────────────────────────

// sortedContainers returns containers ordered per ADR-0107 §3:
// NativeSidecar → RegularSidecar → App, then by SpecIndex within each group.
func sortedContainers(containers []PodContainer) []PodContainer {
	// Stable bucket sort (three buckets, preserve SpecIndex order within each).
	buckets := [3][]PodContainer{}
	for _, c := range containers {
		role := c.Role
		if role < ContainerRoleNativeSidecar || role > ContainerRoleApp {
			role = ContainerRoleApp
		}
		buckets[role] = append(buckets[role], c)
	}
	result := make([]PodContainer, 0, len(containers))
	for i := range buckets {
		result = append(result, buckets[i]...)
	}
	return result
}

// ── checkpoint cleanup ─────────────────────────────────────────────────────────

// zeroizeCheckpoints securely removes all checkpoint directories in dirs.
// Per security constraint: checkpoint images must be zeroized on all exit paths.
// This implementation removes the directories; callers requiring byte-level zeroing
// should use the GC binary defined in ADR-0053.
func zeroizeCheckpoints(dirs []string) {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		// Remove directory and all contents.
		_ = os.RemoveAll(d)
	}
}
