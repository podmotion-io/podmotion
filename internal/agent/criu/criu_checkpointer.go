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

	// Kubernetes-injected file bind-mounts that CRIU cannot map to a proper root inside
	// the container's mount namespace. These are re-provided by the container runtime on
	// restore and must not be saved into the checkpoint image.
	skipMnts := []string{
		"/dev/termination-log",
		"/etc/resolv.conf",
		"/etc/hostname",
		"/etc/hosts",
		"/data", // container volume mount (e.g. Redis /data) — no proper root mount in container mnt ns; re-attached by storage tier on restore (Sprint 31 root_cause=b)
		// sysfs and cgroupfs are managed by the container runtime; CRIU must not dump
		// these mounts because the destination runtime provides them fresh on restore.
		// Without skipping, CRIU restore fails: "Can't umount at ./sys: Device or resource
		// busy" — the bind-mounted sysfs from the kind host cannot be umounted inside the
		// restore context. --skip-mnt is a dump-time flag; skipping at dump means the
		// images contain no sysfs/cgroupfs entries and restore never attempts to recreate them.
		"/sys",
		"/sys/fs/cgroup",
		// dmi sysfs absent on kind control-plane nodes — bind-mount restore fails with
		// "No such file or directory". These paths are not needed for checkpoint/restore
		// correctness; the workload does not depend on DMI identity at runtime.
		"/sys/devices/virtual/dmi/id/product_name",
		"/sys/devices/virtual/dmi/id/product_uuid",
		"/sys/devices/virtual/dmi/id/board_serial",
		"/sys/devices/virtual/dmi/id/chassis_serial",
		"/sys/devices/virtual/dmi/id/sys_vendor",
		// kernel 6.17+ (Ubuntu 24.04 HWE) mounts powercap as its own independent tmpfs
		// (s_dev 0x904, mnt_id separate from /sys). When /sys parent is skipped, CRIU's
		// mount-tree builder finds powercap as an orphan ("No parent found for mountpoint")
		// and aborts the dump. Must be skipped independently of /sys.
		"/sys/devices/virtual/powercap",
	}

	// Build CLI args. We use exec (not swrk RPC) for the final dump because CRIU 4.2
	// swrk mode does not honour AutoExtMnt / External["mnt[]{:AUTO_OPTIONS}"] for some
	// bind-mounted files (e.g. /dev/termination-log, /etc/resolv.conf, /data) inside
	// the container mount namespace. The CLI --external flag works correctly on the same
	// kernel/CRIU version. This mirrors the PreDump approach.
	dumpArgs := []string{
		"dump",
		"-t", strconv.Itoa(int(opts.Pid)),
		"--images-dir", opts.ImagesDir,
		"--log-file", "dump.log",
		"-v4",
		"--root", fmt.Sprintf("/proc/%d/root", opts.Pid),
		"--auto-dedup",
		// NOTE: --ext-sharing / --ext-masters are NOT valid options in CRIU 4.2
		// (the runtime binary). Passing them causes CRIU to abort during argument
		// parsing with "unrecognized option" and exit status 1 before the log file
		// is opened (empty dump.log) — which masked the real failure on Sprint 31.
		// CRIU 4.2 handles shared/master mounts automatically via --external below.
		"--external", "mnt[]{:AUTO_OPTIONS}",
		"--network-lock", "skip",
	}
	if opts.LeaveRunning {
		dumpArgs = append(dumpArgs, "--leave-running")
	}
	if opts.LeaveStopped {
		dumpArgs = append(dumpArgs, "--leave-stopped")
	}
	if opts.TcpEstablished {
		dumpArgs = append(dumpArgs, "--tcp-established")
	} else {
		dumpArgs = append(dumpArgs, "--tcp-close")
		dumpArgs = append(dumpArgs, "--skip-in-flight")
		// Cold network migration (tcpPreservationMode=None): we do NOT preserve any
		// network state — the pod is restored into a fresh (empty) network namespace
		// provisioned by the destination CNI. Dump the net namespace as empty so CRIU
		// does NOT invoke the external `ip` tool to save addresses/routes. The agent
		// image is minimal and does not ship iproute2, so without --empty-ns net CRIU
		// fails with: execvp("ip", ...) failed: No such file or directory ->
		// "net: IP tool failed on addr save" -> "Dumping FAILED" (Sprint 31).
		dumpArgs = append(dumpArgs, "--empty-ns", "net")
	}
	if opts.TrackMem {
		dumpArgs = append(dumpArgs, "--track-mem")
	}
	if opts.PrevImagesDir != "" {
		rel, relErr := filepath.Rel(opts.ImagesDir, opts.PrevImagesDir)
		if relErr != nil {
			rel = opts.PrevImagesDir
		}
		dumpArgs = append(dumpArgs, "--prev-images-dir", rel)
	}
	if opts.LazyPages {
		dumpArgs = append(dumpArgs, "--lazy-pages")
	}
	// SkipMnt: kubernetes-injected file bind-mounts that have no proper root inside the
	// container's mount namespace. These are re-provided by the container runtime on restore
	// and must not be saved into the checkpoint image.
	for _, m := range skipMnts {
		dumpArgs = append(dumpArgs, "--skip-mnt", m)
	}

	logger.Info("CRIU Dump starting",
		"pid", opts.Pid,
		"imagesDir", opts.ImagesDir,
		"criuBinary", c.criuBinaryPath,
		"opts", fmt.Sprintf("LeaveRunning=%v TcpEstablished=%v TcpClose=%v TrackMem=%v LeaveStopped=%v",
			opts.LeaveRunning, opts.TcpEstablished, !opts.TcpEstablished, opts.TrackMem, opts.LeaveStopped),
	)

	freezeStart := time.Now()

	logger.Info("CRIU Dump CLI invocation",
		"binary", c.criuBinaryPath,
		"args", strings.Join(dumpArgs, " "),
	)

	//nolint:gosec // binary path is a trusted constant, args are controlled internally
	cmd := exec.CommandContext(ctx, c.criuBinaryPath, dumpArgs...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Redirect combined stdout+stderr to the stderr buffer so CRIU's early error messages
	// (e.g. before the log file is opened) are captured.
	cmd.Stdout = &stderr

	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		done <- result{err: cmd.Run()}
	}()

	var dumpErr error
	select {
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
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
		return CheckpointResult{}, fmt.Errorf("criu.Dump(pid=%d): %w\nstderr: %s\ndump.log: %s", opts.Pid, dumpErr, stderr.String(), string(dumpLogBytes))
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
		TcpEstablished: proto.Bool(opts.TcpEstablished),
		// TcpClose and TcpEstablished are mutually exclusive on restore too. With
		// TcpClose=true CRIU logs "Will drop all TCP connections on restore" and tears
		// the socket down, defeating ADR-0131 seq_delta=0. When restoring an established
		// connection (TcpEstablished=true) TcpClose MUST be false so TCP_REPAIR rebuilds
		// the exact socket state captured at freeze.
		TcpClose: proto.Bool(!opts.TcpEstablished),
		// TcpSkipInFlight on restore: mirror the dump policy — only skip in-flight for
		// non-TCP-stateful restores. For TCP-stateful restores the connection state must
		// be fully intact (no in-flight data was present at dump time per ADR-0049).
		TcpSkipInFlight: proto.Bool(!opts.TcpEstablished),
		// NetworkLock on restore: CRIU uses this to prevent the peer from racing segments
		// during the restore window. Mirror the dump policy — use IPTABLES for TCP-stateful.
		NetworkLock: func() *rpc.CriuNetworkLockMethod {
			if opts.TcpEstablished {
				return rpc.CriuNetworkLockMethod_IPTABLES.Enum()
			}
			return rpc.CriuNetworkLockMethod_SKIP.Enum()
		}(),
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
			// Additional containerd/runc-injected proc submounts that CRIU autodetects as
			// external mounts with a (null) source on restore (mount.c:3120). These are
			// re-provided by the destination runtime's own bundle, so skipping them on
			// restore is safe — Redis does not depend on them. Without this the restore
			// hard-fails with "is autodetected external mount" (ADR-0131 restore path).
			"/proc/bus",
			"/proc/fs",
			"/proc/irq",
			"/proc/sys",
			"/proc/sysrq-trigger",
			"/proc/acpi",
			"/proc/asound",
			"/sys/fs/bpf",
			"/sys/fs/cgroup",
			// Container-runtime VOLUME mount (e.g. Redis /data) — skipped on dump (no proper
			// root in container mnt ns) and re-attached by the destination storage tier on
			// restore. Mirror the dump-side skip so CRIU does not try to restore it.
			"/data",
		},
	}

	// Cold network migration (tcpPreservationMode=None) is dumped with --empty-ns net,
	// so the restore MUST also declare the net namespace empty. CRIU represents this in
	// the RPC opts.empty_ns bitmask using the kernel CLONE_NEWNET flag (0x40000000).
	// Without this, restore tries to recreate the (non-existent, empty) saved network
	// state and/or invoke the `ip` tool, which is absent from the minimal agent image.
	if !opts.TcpEstablished {
		const cloneNewNet = 0x40000000 // CLONE_NEWNET — mirrors `criu --empty-ns net`
		criuOpts.EmptyNs = proto.Uint32(cloneNewNet)
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

// ExportedParseTCPImageEntries is the exported wrapper around parseTCPImageEntries
// for use in package-level tests (package criu_test).
func ExportedParseTCPImageEntries(logContent string) (int, int) {
	return parseTCPImageEntries(logContent)
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
