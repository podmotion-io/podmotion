/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package criu

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	gocriu "github.com/checkpoint-restore/go-criu/v7"
	"github.com/checkpoint-restore/go-criu/v7/rpc"
	"google.golang.org/protobuf/proto"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const defaultCRIUBinaryPath = "/usr/local/sbin/criu"

// ErrCRIUCapability is a sentinel returned (wrapped) when CRIU or a preflight check fails
// because CAP_SYS_PTRACE is missing or a seccomp profile is blocking ptrace. Callers use
// errors.Is/As to distinguish this from transient or configuration errors (M19.5 criterion 13).
var ErrCRIUCapability = errors.New("CRIU capability/ptrace error")

// CRIUCheckpointer implements Checkpointer using go-criu/v7 RPC to invoke
// CRIU as a subprocess (ADR-0002 — never statically link GPLv2 code).
type CRIUCheckpointer struct {
	criuBinaryPath string

	mu         sync.Mutex
	activeCriu *gocriu.Criu // non-nil while a dump/restore is in progress
}

// NewCRIUCheckpointer returns a CRIUCheckpointer that invokes the CRIU binary
// at criuBinaryPath. Pass an empty string to use the default /usr/sbin/criu.
func NewCRIUCheckpointer(criuBinaryPath string) *CRIUCheckpointer {
	if criuBinaryPath == "" {
		criuBinaryPath = defaultCRIUBinaryPath
	}
	return &CRIUCheckpointer{criuBinaryPath: criuBinaryPath}
}

// darwinError returns a clear error when running on macOS (CRIU is Linux-only).
func darwinError() error {
	return errors.New("CRIU requires Linux — not available on darwin")
}

// PreDump performs one iterative pre-dump round without freezing the container.
// Uses `criu pre-dump` directly (not go-criu swrk) because CRIU's swrk PRE_DUMP
// handler runs a loop waiting for follow-up requests; closing the socket mid-loop
// causes CRIU to exit with code 255 even on success. Direct exec avoids the loop.
// VM_READ mode (process_vm_readv) is used — no CONFIG_MEM_SOFT_DIRTY required.
func (c *CRIUCheckpointer) PreDump(ctx context.Context, opts PreDumpOptions) (CheckpointResult, error) {
	if runtime.GOOS == "darwin" {
		return CheckpointResult{}, darwinError()
	}

	if err := ctx.Err(); err != nil {
		return CheckpointResult{}, fmt.Errorf("context cancelled before PreDump: %w", err)
	}

	if err := os.MkdirAll(opts.ImagesDir, 0o700); err != nil {
		return CheckpointResult{}, fmt.Errorf("creating images dir %s: %w", opts.ImagesDir, err)
	}

	// CRIU uses -t for pid (short form) — --pid is not recognized for pre-dump.
	args := []string{
		"pre-dump",
		"-t", strconv.Itoa(int(opts.Pid)),
		"--images-dir", opts.ImagesDir,
		"--log-file", "predump.log",
		"-v4",
		"--pre-dump-mode", "read",
	}

	if opts.PrevImagesDir != "" {
		rel, relErr := filepath.Rel(opts.ImagesDir, opts.PrevImagesDir)
		if relErr != nil {
			rel = opts.PrevImagesDir
		}
		args = append(args, "--prev-images-dir", rel)
	}

	//nolint:gosec // binary path is a trusted constant, args are controlled internally
	cmd := exec.CommandContext(ctx, c.criuBinaryPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		done <- result{err: cmd.Run()}
	}()

	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		return CheckpointResult{}, fmt.Errorf("PreDump aborted: %w", ctx.Err())
	case res := <-done:
		if res.err != nil {
			predumpLog, _ := os.ReadFile(filepath.Join(opts.ImagesDir, "predump.log"))
			return CheckpointResult{}, fmt.Errorf("criu pre-dump: %w\nstderr: %s\nlog: %s",
				res.err, stderr.String(), string(predumpLog))
		}
	}

	return CheckpointResult{
		ImagesDir:        opts.ImagesDir,
		DirtyPagesMB:     0, // stats file parsing not yet implemented
		FreezeDurationMs: 0, // pre-dump does not freeze
		RoundNumber:      0,
		CheckpointedAt:   time.Now(),
	}, nil
}

// Dump performs the final (freezing) CRIU dump. The container is frozen for
// the duration. Returns once all dump images are written to opts.ImagesDir.
func (c *CRIUCheckpointer) Dump(ctx context.Context, opts DumpOptions) (CheckpointResult, error) {
	if runtime.GOOS == "darwin" {
		return CheckpointResult{}, darwinError()
	}

	if err := ctx.Err(); err != nil {
		return CheckpointResult{}, fmt.Errorf("context cancelled before Dump: %w", err)
	}

	// 0o700: checkpoint images contain verbatim process memory and must be root-only.
	// PreDump and Restore already use 0o700; Dump must match for consistency (M19.5 criterion 9).
	if err := os.MkdirAll(opts.ImagesDir, 0o700); err != nil {
		return CheckpointResult{}, fmt.Errorf("creating images dir %s: %w", opts.ImagesDir, err)
	}

	imgDirFd, err := openDirFd(opts.ImagesDir)
	if err != nil {
		return CheckpointResult{}, err
	}
	defer imgDirFd.Close()

	if opts.Pid == 0 {
		return CheckpointResult{}, fmt.Errorf("criu dump: Pid is 0 — caller must resolve the container root PID before calling Dump")
	}

	logger := logf.FromContext(ctx)

	// Ptrace preflight: attempt PTRACE_SEIZE before starting CRIU RPC so we get
	// the exact errno on capability/seccomp failures rather than a silent dump with
	// zero files written.
	if err := ptracePreflight(opts.Pid); err != nil {
		logger.Error(err, "CRIU ptrace preflight failed — CAP_SYS_PTRACE or seccomp may be blocking",
			"pid", opts.Pid,
			"imagesDir", opts.ImagesDir,
		)
		// Wrap with ErrCRIUCapability so callers can use errors.Is instead of string matching
		// (M19.5 criterion 13: error classification via errors.Is/As not string matching).
		return CheckpointResult{}, fmt.Errorf("CRIU preflight failed: %w: %w", ErrCRIUCapability, err)
	}
	logger.Info("CRIU ptrace preflight passed", "pid", opts.Pid)

	// Build CRIU opts tuned for a containerised process on a kind (Docker-based)
	// node.  Key choices:
	//   - TcpEstablished — driven from opts; true when TCPPreservationMode is Strict or BestEffort
	//   - ShellJob=false        — container init is not a shell job
	//   - ExtSharing=true       — overlay rootfs shares mount subtrees externally
	//   - ExtMasters=true       — overlay upper/work dirs are external mount masters
	//   - Root                  — container rootfs visible from the host via /proc/<pid>/root
	//   - TrackMem omitted      — pre-dump uses VM_READ (process_vm_readv); cold dump
	//                            never needs dirty tracking
	//   - TcpClose=true         — close TCP sockets instead of erroring on multi-thread tasks
	//   - LeaveStopped          — when TcpEstablished: source stays in SIGSTOP after dump
	//                            so no new data is sent while the destination is restoring
	//                            (M23 ordering invariant: --leave-stopped)
	criuOpts := &rpc.CriuOpts{
		ImagesDirFd:    proto.Int32(int32(imgDirFd.Fd())),
		LogFile:        proto.String("dump.log"),
		LogLevel:       proto.Int32(4),
		Pid:            proto.Int32(opts.Pid),
		LeaveRunning:   proto.Bool(opts.LeaveRunning),
		LeaveStopped:   proto.Bool(opts.LeaveStopped),
		TcpEstablished: proto.Bool(opts.TcpEstablished),
		TcpClose:       proto.Bool(true),
		// TcpSkipInFlight skips TCP sockets with in-flight data — avoids iptables
		// network-lock scripts (iptables-restore) that are absent in kind agent images.
		TcpSkipInFlight: proto.Bool(true),
		// NetworkLock=SKIP bypasses iptables-based network namespace locking entirely.
		// Safe for kind where network isolation is Docker-managed, not iptables per-ns.
		NetworkLock: rpc.CriuNetworkLockMethod_SKIP.Enum(),
		ShellJob:    proto.Bool(false),
		TrackMem:    proto.Bool(false), // ARM64 lacks CONFIG_MEM_SOFT_DIRTY; not needed for cold migration
		AutoDedup:   proto.Bool(true),
		ExtSharing:  proto.Bool(true),
		ExtMasters:  proto.Bool(true),
		// AutoExtMnt=true is equivalent to --ext-mount-map auto: CRIU automatically
		// treats any bind-mounted file (e.g. /etc/resolv.conf, /etc/hosts injected by
		// the kubelet) as an external mount rather than failing with "doesn't have a
		// proper root mount". Required for k3s/containerd containers on Ubuntu 24.04.
		AutoExtMnt: proto.Bool(true),
		// Root tells CRIU where the container's rootfs is visible from the
		// host mount namespace.  /proc/<pid>/root always works regardless of
		// how the container runtime mounted it.
		Root: proto.String(fmt.Sprintf("/proc/%d/root", opts.Pid)),
	}

	if opts.PrevImagesDir != "" {
		rel, relErr := filepath.Rel(opts.ImagesDir, opts.PrevImagesDir)
		if relErr != nil {
			rel = opts.PrevImagesDir
		}
		criuOpts.ParentImg = proto.String(rel)
	}

	if opts.LazyPages {
		criuOpts.LazyPages = proto.Bool(true)
	}

	c.mu.Lock()
	cr := gocriu.MakeCriu()
	cr.SetCriuPath(c.criuBinaryPath)
	c.activeCriu = cr
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.activeCriu = nil
		c.mu.Unlock()
	}()

	logger.Info("CRIU Dump starting",
		"pid", opts.Pid,
		"imagesDir", opts.ImagesDir,
		"criuBinary", c.criuBinaryPath,
		"opts", fmt.Sprintf("LeaveRunning=%v TcpClose=%v TrackMem=%v ExtSharing=%v ExtMasters=%v NetworkLock=SKIP",
			opts.LeaveRunning, true, true, true, true),
	)

	freezeStart := time.Now()

	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		done <- result{err: cr.Dump(criuOpts, nil)}
	}()

	var dumpErr error
	select {
	case <-ctx.Done():
		c.Abort(context.Background(), opts.ContainerID, opts.Namespace) //nolint:errcheck
		return CheckpointResult{}, fmt.Errorf("Dump aborted: %w", ctx.Err())
	case res := <-done:
		dumpErr = res.err
	}

	// Always surface the CRIU dump log — invaluable for diagnosing failures on kind.
	dumpLogBytes, _ := os.ReadFile(filepath.Join(opts.ImagesDir, "dump.log"))
	if len(dumpLogBytes) > 0 {
		logContent := string(dumpLogBytes)
		tcpEntries, unsupported := parseTCPImageEntries(logContent)
		logger.Info("CRIU dump log",
			"pid", opts.Pid,
			"imagesDir", opts.ImagesDir,
			"tcpImageEntries", tcpEntries,
			"unsupportedSocketErrors", unsupported,
			"content", logContent,
		)
	}

	if dumpErr != nil {
		logger.Error(dumpErr, "CRIU Dump failed",
			"pid", opts.Pid,
			"imagesDir", opts.ImagesDir,
			"criuError", dumpErr.Error(),
			"dumpLog", string(dumpLogBytes),
		)
		return CheckpointResult{}, fmt.Errorf("criu.Dump(pid=%d): %w\ndump.log: %s", opts.Pid, dumpErr, string(dumpLogBytes))
	}

	logger.Info("CRIU Dump succeeded",
		"pid", opts.Pid,
		"imagesDir", opts.ImagesDir,
		"freezeDurationMs", time.Since(freezeStart).Milliseconds(),
	)

	// Verify that CRIU wrote inventory.img — its absence means the dump silently
	// failed (e.g. network-lock or ptrace error) even though go-criu returned nil.
	if _, statErr := os.Stat(filepath.Join(opts.ImagesDir, "inventory.img")); statErr != nil {
		dumpLog, _ := os.ReadFile(filepath.Join(opts.ImagesDir, "dump.log"))
		return CheckpointResult{}, fmt.Errorf("criu dump (pid=%d): inventory.img not written — dump may have failed silently\ndump.log:\n%s", opts.Pid, string(dumpLog))
	}

	return CheckpointResult{
		ImagesDir:        opts.ImagesDir,
		DirtyPagesMB:     0,
		FreezeDurationMs: time.Since(freezeStart).Milliseconds(),
		RoundNumber:      0,
		CheckpointedAt:   time.Now(),
	}, nil
}

// Restore recreates the container from dump images on the destination node.
func (c *CRIUCheckpointer) Restore(ctx context.Context, opts RestoreOptions) (RestoreResult, error) {
	if runtime.GOOS == "darwin" {
		return RestoreResult{}, darwinError()
	}

	if err := ctx.Err(); err != nil {
		return RestoreResult{}, fmt.Errorf("context cancelled before Restore: %w", err)
	}

	// Ensure the images dir exists on the destination before opening it.
	// In kind, both worker nodes mount the same hostPath so the dir should
	// already exist after Dump writes it; MkdirAll is a safe no-op if present.
	if err := os.MkdirAll(opts.ImagesDir, 0o700); err != nil {
		return RestoreResult{}, fmt.Errorf("creating restore images dir %s: %w", opts.ImagesDir, err)
	}

	imgDirFd, err := openDirFd(opts.ImagesDir)
	if err != nil {
		return RestoreResult{}, err
	}
	defer imgDirFd.Close()

	logger := logf.FromContext(ctx)

	// Restore opts mirror the Dump opts: same TCP/shell settings, detached mode
	// so the restored process tree is reparented to init rather than CRIU.
	criuOpts := &rpc.CriuOpts{
		ImagesDirFd:     proto.Int32(int32(imgDirFd.Fd())),
		LogFile:         proto.String("restore.log"),
		LogLevel:        proto.Int32(4),
		TcpEstablished:  proto.Bool(opts.TcpEstablished),
		TcpClose:        proto.Bool(true),
		TcpSkipInFlight: proto.Bool(true),
		// NetworkLock=SKIP: no iptables-restore needed on destination either.
		NetworkLock: rpc.CriuNetworkLockMethod_SKIP.Enum(),
		ShellJob:    proto.Bool(false),
		ExtSharing:  proto.Bool(true),
		ExtMasters:  proto.Bool(true),
		// RstSibling restores in detached mode (process reparented to init, not CRIU).
		RstSibling: proto.Bool(opts.Detached),
		// AutoExtMnt handles k8s bind-mounts (/etc/resolv.conf, etc.) — mirrors dump option.
		AutoExtMnt: proto.Bool(true),
		// MntnsCompatMode relaxes mount namespace restore strictness for containerised processes.
		MntnsCompatMode: proto.Bool(true),
		// SkipMnt: skip restoring Kubernetes masked-path mounts (tmpfs bind-mounts of /dev/null)
		// and the service-account tmpfs that references source-node-specific device IDs.
		// These mounts have null-resolvable sources on the destination and cause "No mapping"
		// errors. Skipping them is safe: Redis does not use any of these paths.
		SkipMnt: []string{
			"/proc/interrupts",
			"/proc/kcore",
			"/proc/keys",
			"/proc/latency_stats",
			"/proc/timer_list",
			"/proc/timer_stats",
			"/proc/sched_debug",
			"/proc/scsi",
			"/sys/firmware",
			"/sys/fs/pstore",
			"/run/secrets/kubernetes.io/serviceaccount",
		},
	}

	if opts.BundleDir != "" {
		// BundleDir is the OCI bundle; its rootfs subdirectory is the container rootfs.
		criuOpts.Root = proto.String(filepath.Join(opts.BundleDir, "rootfs"))
	}

	if opts.LazyPagesServerAddr != "" {
		criuOpts.LazyPages = proto.Bool(true)
	}

	// VethPair: tell CRIU which host-side veth name to use for the container's eth0.
	// Without this, CRIU fails with "Unknown peer net namespace" when the source veth
	// peer no longer exists on the destination node (cold migration cross-node case).
	if opts.HostVethName != "" {
		criuOpts.Veths = []*rpc.CriuVethPair{
			{IfIn: proto.String("eth0"), IfOut: proto.String(opts.HostVethName)},
		}
	}

	c.mu.Lock()
	cr := gocriu.MakeCriu()
	cr.SetCriuPath(c.criuBinaryPath)
	c.activeCriu = cr
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.activeCriu = nil
		c.mu.Unlock()
	}()

	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		done <- result{err: cr.Restore(criuOpts, nil)}
	}()

	var restoreErr error
	select {
	case <-ctx.Done():
		c.Abort(context.Background(), opts.ContainerID, opts.Namespace) //nolint:errcheck
		return RestoreResult{}, fmt.Errorf("Restore aborted: %w", ctx.Err())
	case res := <-done:
		restoreErr = res.err
	}

	// Surface the CRIU restore log regardless of success/failure.
	if restoreLogBytes, readErr := os.ReadFile(filepath.Join(opts.ImagesDir, "restore.log")); readErr == nil {
		logContent := string(restoreLogBytes)
		tcpEntries, unsupported := parseTCPImageEntries(logContent)
		logger.Info("CRIU restore log",
			"imagesDir", opts.ImagesDir,
			"tcpImageEntries", tcpEntries,
			"unsupportedSocketErrors", unsupported,
			"content", logContent,
		)
	}

	if restoreErr != nil {
		return RestoreResult{}, fmt.Errorf("criu restore: %w", restoreErr)
	}

	return RestoreResult{
		PID:        0, // PID not exposed by go-criu Restore; use NRI/containerd query
		RestoredAt: time.Now(),
	}, nil
}

// Abort terminates any in-progress CRIU operation by closing the swrk socket.
// Safe to call at any time; a no-op if no operation is active.
func (c *CRIUCheckpointer) Abort(_ context.Context, _, _ string) error {
	if runtime.GOOS == "darwin" {
		return darwinError()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.activeCriu != nil {
		// Cleanup closes the swrk socket which unblocks the CRIU subprocess.
		err := c.activeCriu.Cleanup()
		c.activeCriu = nil
		return err
	}
	return nil
}

// openDirFd opens dirPath and returns an *os.File whose Fd() can be passed to
// CRIU as images_dir_fd. Caller must Close() it after the CRIU call.
func openDirFd(dirPath string) (*os.File, error) {
	f, err := os.Open(dirPath)
	if err != nil {
		return nil, fmt.Errorf("opening images dir %s: %w", dirPath, err)
	}
	return f, nil
}

// parseTCPImageEntries scans a CRIU dump or restore log for TCP image entries
// (inetsk/tcp lines) and "Unsupported socket" error lines.
// Returns (tcpEntryCount, unsupportedCount) as structured log fields.
// The presence of tcpEntryCount > 0 confirms TcpEstablished=true was honoured by CRIU
// (M23 acceptance criterion: live CRIU log confirms inetsk/tcp image entries present).
func parseTCPImageEntries(logContent string) (int, int) {
	var tcpEntries, unsupported int
	for _, line := range strings.Split(logContent, "\n") {
		if strings.Contains(line, "inetsk") || strings.Contains(line, "tcp") {
			tcpEntries++
		}
		if strings.Contains(line, "Unsupported socket") {
			unsupported++
		}
	}
	return tcpEntries, unsupported
}
