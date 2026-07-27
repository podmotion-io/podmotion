/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build linux

package storage

// drain_linux.go — below-app storage I/O drain primitive (ADR-0394).
//
// After the migration freeze (the app can no longer issue new I/O) and before the
// CRIU dump, force any already-submitted writeback on the pod's volume mount to
// complete via syncfs(2), then VERIFY the flush actually targeted a real, mounted
// filesystem and actually completed. It never assumes success from a bare syscall
// return: current handoff is assumed-consistent, not proven-drained, and this
// primitive exists to close exactly that gap — a flush condition that goes true
// without a real, freshly-verified flush would just restate the defect.
//
// Fail-closed (ADR-0394 §Decision-3/3a): a drain that cannot be proven to have hit
// a distinct, populated volume filesystem returns a non-nil error, and callers
// HARD-STOP the freeze/checkpoint phase rather than dumping over an
// unproven-consistent volume. IsMountpoint==true is load-bearing, not a warning:
// a syncfs of the node root fs (which the mountpoint directory lives on) also
// "succeeds" with blocks>0, so distinctness is the only signal proving the flush
// hit the pod VOLUME.
//
// Backend-agnostic: it operates on whatever filesystem backs the pod volume mount
// (a Longhorn block device's ext4, an NFS mount) — it is a flush, not a copier,
// and introduces no new data-path authority.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// hostRootPrefix is how the agent reaches the host mount namespace's filesystem
// tree from inside its own container: with hostPID=true, PID 1 is the host init,
// so /proc/1/root is the host root. This is the same proven access path
// cmd/agent/main.go uses for its checkpoint-tmpfs statfs verification.
const hostRootPrefix = "/proc/1/root"

// DrainResult captures the freshly-measured evidence that a syncfs drain actually
// happened against the intended volume. Every field is measured, not inferred.
type DrainResult struct {
	// MountPath is the host-namespace path that was drained.
	MountPath string
	// FSType is the f_type from fstatfs on the opened mount fd (e.g. 0xef53 ext4).
	FSType int64
	// ParentFSType is the f_type of the mount's parent directory.
	ParentFSType int64
	// IsMountpoint is true when the mount fd's filesystem is distinct from its
	// parent directory's (different fsid or type) — proving syncfs targeted the
	// pod VOLUME, not the node root fs the mountpoint directory lives on.
	IsMountpoint bool
	// BlocksTotal is f_blocks from fstatfs — a real, populated filesystem has >0.
	BlocksTotal uint64
	// Synced is true only when syncfs(2) returned success.
	Synced bool
	// DurationMs is how long the syncfs call blocked (it blocks until writeback
	// completes).
	DurationMs int64
	// DirtyBeforeKB / DirtyAfterKB are Dirty+Writeback from /proc/meminfo bracketing
	// the syncfs call — corroborating, node-global evidence only, never load-bearing.
	DirtyBeforeKB int64
	DirtyAfterKB  int64
}

// Verified reports whether this DrainResult proves a real, fresh flush of a
// distinct, populated volume filesystem — the ADR-0394 §Decision-3a go-True
// predicate. All three signals are required; meminfo is deliberately excluded
// (it is node-global corroboration, not per-volume proof).
func (r DrainResult) Verified() bool {
	return r.Synced && r.BlocksTotal > 0 && r.IsMountpoint
}

// ResolvePodCSIVolumeMounts returns the host-namespace mount paths of every CSI
// (Longhorn, etc.) volume attached to the pod, reachable from the agent via
// /proc/1/root. Backend-agnostic: any kubelet CSI volume mount dir matches.
func ResolvePodCSIVolumeMounts(podUID string) ([]string, error) {
	if podUID == "" {
		return nil, fmt.Errorf("resolve volume mounts: empty podUID")
	}
	glob := filepath.Join(hostRootPrefix, "var/lib/kubelet/pods", podUID,
		"volumes/kubernetes.io~csi/*/mount")
	matches, err := filepath.Glob(glob)
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", glob, err)
	}
	return matches, nil
}

// DrainVolumeMount forces already-submitted writeback on a single volume mount to
// disk via syncfs(2), then verifies the flush against three independent signals —
// none of which is "the call did not return an error":
//
//  1. fstatfs the opened fd: f_blocks > 0 proves the path is a real, populated
//     filesystem, not an empty stand-in directory a syncfs would no-op against.
//  2. Compare the mount's fsid/type to its PARENT dir's: a genuine mountpoint
//     differs from its parent, proving syncfs hit the VOLUME (the Longhorn ext4),
//     not the node root fs the mountpoint dir lives on. A syncfs on a non-mount
//     path silently "succeeds" against the wrong fs — this is what catches it, and
//     per ADR-0394 §Decision-3a a non-distinct mount is a HARD FAILURE, not a
//     warning: this function returns an error and callers abort the phase.
//  3. The syncfs(2) return value itself.
//
// The mount leaf is opened O_NOFOLLOW (ADR-0394 §Decision-4a) so a symlink swap on
// the leaf cannot redirect the flush to an attacker-chosen filesystem — a symlink
// yields a fail-closed error, not a silent flush of the wrong fs.
//
// /proc/meminfo Dirty+Writeback is bracketed around the call for operator
// corroboration only; it is node-global and never gates the result.
func DrainVolumeMount(ctx context.Context, mountPath string) (DrainResult, error) {
	logger := logf.FromContext(ctx)
	res := DrainResult{MountPath: mountPath}

	// O_NOFOLLOW on the leaf: refuse to follow a symlink at the final mount
	// component (defense-in-depth against a future node-local redirect).
	f, err := os.OpenFile(mountPath, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return res, fmt.Errorf("drain: open volume mount %s (O_NOFOLLOW): %w", mountPath, err)
	}
	defer func() { _ = f.Close() }()

	// Layer 1 + 2: fstatfs the mount fd and statfs its parent directory.
	var stMount, stParent unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &stMount); err != nil {
		return res, fmt.Errorf("drain: fstatfs mount %s: %w", mountPath, err)
	}
	res.FSType = int64(stMount.Type)
	res.BlocksTotal = uint64(stMount.Blocks)
	if err := unix.Statfs(filepath.Dir(mountPath), &stParent); err == nil {
		res.ParentFSType = int64(stParent.Type)
		res.IsMountpoint = stMount.Fsid != stParent.Fsid || stMount.Type != stParent.Type
	}
	if res.BlocksTotal == 0 {
		return res, fmt.Errorf("drain: %s fstatfs reports 0 blocks — not a real mounted "+
			"filesystem; refusing to claim a flush", mountPath)
	}
	// ADR-0394 §Decision-3a: distinctness is load-bearing. If the mount is not a
	// distinct mountpoint from its parent (or the parent statfs failed so we cannot
	// prove distinctness), a syncfs here would flush the node root fs while claiming
	// the pod volume — the exact assumed-consistent defect ADR-0394 closes. Fail closed.
	if !res.IsMountpoint {
		return res, fmt.Errorf("drain: %s is not a distinct mountpoint from its parent "+
			"(mount fsType 0x%x, parent fsType 0x%x) — a syncfs here would target the node "+
			"root fs, not the pod volume; refusing to claim a flush", mountPath,
			res.FSType, res.ParentFSType)
	}

	res.DirtyBeforeKB = readDirtyWritebackKB()

	// Layer 3: the syscall itself.
	start := time.Now()
	syncErr := unix.Syncfs(int(f.Fd()))
	res.DurationMs = time.Since(start).Milliseconds()
	if syncErr != nil {
		return res, fmt.Errorf("drain: syncfs(%s) failed: %w", mountPath, syncErr)
	}
	res.Synced = true

	res.DirtyAfterKB = readDirtyWritebackKB()

	logger.Info("storage drain: syncfs completed and verified",
		"mountPath", mountPath,
		"fsType", fmt.Sprintf("0x%x", res.FSType),
		"isMountpoint", res.IsMountpoint,
		"blocksTotal", res.BlocksTotal,
		"durationMs", res.DurationMs,
		"dirtyBeforeKB", res.DirtyBeforeKB,
		"dirtyAfterKB", res.DirtyAfterKB,
		"dirtyDrainedKB", res.DirtyBeforeKB-res.DirtyAfterKB,
	)
	return res, nil
}

// DrainPodVolumes resolves and drains every CSI volume mount of the pod. This is
// the entry point wired into the checkpoint freeze path. A pod with no CSI volume
// returns (nil, nil) — nothing to drain is not an error. Fail-closed
// (ADR-0394 §Decision-3): each mount is drained and reported, and the first
// per-mount failure is returned as a non-nil error so the caller HARD-STOPS the
// freeze/checkpoint phase rather than dumping over an unproven-consistent volume.
// Remaining mounts are still attempted so the log surfaces every mount's state.
func DrainPodVolumes(ctx context.Context, podUID string) ([]DrainResult, error) {
	mounts, err := ResolvePodCSIVolumeMounts(podUID)
	if err != nil {
		return nil, err
	}
	if len(mounts) == 0 {
		return nil, nil
	}
	var results []DrainResult
	var firstErr error
	for _, m := range mounts {
		r, derr := DrainVolumeMount(ctx, m)
		results = append(results, r)
		if derr != nil && firstErr == nil {
			firstErr = derr
		} else if derr == nil && !r.Verified() {
			// Defense in depth: a nil error must coincide with a verified result.
			// If it ever does not, treat the mount as unverified (fail closed).
			firstErr = fmt.Errorf("drain: %s returned no error but is unverified "+
				"(synced=%t blocks=%d isMountpoint=%t)", m, r.Synced, r.BlocksTotal, r.IsMountpoint)
		}
	}
	return results, firstErr
}

// DrainPodVolumesErr is the func-typed adapter wired into the multi-container
// freeze barrier's VolumeDrainer hook: it drains and returns only the fail-closed
// error (the criu package needs the abort signal, not the per-mount results).
func DrainPodVolumesErr(ctx context.Context, podUID string) error {
	_, err := DrainPodVolumes(ctx, podUID)
	return err
}

// readDirtyWritebackKB returns Dirty+Writeback in KB from the host /proc/meminfo.
// Best-effort corroboration only; -1 on any read/parse miss (meminfo absence is
// never a drain failure and never gates the result).
func readDirtyWritebackKB() int64 {
	data, err := os.ReadFile(filepath.Join(hostRootPrefix, "proc/meminfo"))
	if err != nil {
		return -1
	}
	var total int64
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Dirty:") || strings.HasPrefix(line, "Writeback:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, perr := strconv.ParseInt(fields[1], 10, 64); perr == nil {
					total += v
					found = true
				}
			}
		}
	}
	if !found {
		return -1
	}
	return total
}
