/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package criu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	gocriu "github.com/checkpoint-restore/go-criu/v7"
	"github.com/checkpoint-restore/go-criu/v7/rpc"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const defaultCRIUBinaryPath = "/usr/local/sbin/criu"

// ErrCRIUCapability is a sentinel returned (wrapped) when CRIU or a preflight check fails
// because CAP_SYS_PTRACE is missing or a seccomp profile is blocking ptrace. Callers use
// errors.Is/As to distinguish this from transient or configuration errors (M19.5 criterion 13).
var ErrCRIUCapability = errors.New("CRIU capability/ptrace error")

// removedLink records a network link deleted from the container netns pre-dump
// so that it can be recreated on the restore side if needed.
type removedLink struct {
	name     string
	ifindex  int
	linkType int // ARPHRD_ constant, e.g. 768=ipip, 776=sit
}

// CRIUCheckpointer implements Checkpointer using go-criu/v7 RPC to invoke
// CRIU as a subprocess (ADR-0002 — never statically link GPLv2 code).
type CRIUCheckpointer struct {
	criuBinaryPath string

	mu              sync.Mutex
	activeCriu      *gocriu.Criu // non-nil while a dump/restore is in progress
	removedNetLinks []removedLink // links deleted pre-dump for restore-side recreation
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
		// /sys and all children: skip the entire sysfs subtree at dump time.
		//
		// Gate10 analysis: neither including /sys as external (ext_key='pm-sys') nor
		// skip-at-dump prevents compat-mode from trying to umount the destination's /sys.
		// CRIU 4.2 compat-mode umount pass iterates the destination's mount table and
		// umounts entries not in the source image's NON-EXTERNAL mounts — external image
		// entries (E) do NOT prevent umount of the destination's corresponding mount.
		// Fix: skip /sys at dump time AND add /sys to SkipMnt on restore. SkipMnt on
		// restore tells compat-mode to leave that mountpoint alone (no umount, no mount).
		"/sys",
		"/sys/fs/cgroup",
		"/sys/fs/bpf",
		"/sys/kernel/tracing",
		"/sys/kernel/debug",
		"/sys/fs/fuse/connections",
		"/sys/kernel/config",
		"/sys/devices/virtual/dmi/id/product_name",
		"/sys/devices/virtual/dmi/id/product_uuid",
		"/sys/devices/virtual/dmi/id/board_serial",
		"/sys/devices/virtual/dmi/id/chassis_serial",
		"/sys/devices/virtual/dmi/id/sys_vendor",
		"/sys/devices/virtual/powercap",
		"/sys/firmware",
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
		// /sys is in skipMnts — no external declaration needed for /sys.
		// compat-mode umount is prevented via SkipMnt on restore side.
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
		// ADR-0162-rev: CRIU 4.2 does not honor --external net[] for ARPHRD_TUNNEL (ipip).
		// Delete tunnel devices from the container netns before the final dump.
		// tunl0/sit0/etc are always DOWN on Flannel-VXLAN clusters (no pod traffic).
		removed, rmErr := deleteUnsupportedNetLinks(opts.Pid, logger)
		if rmErr != nil {
			logger.Error(rmErr, "pre-dump: failed to remove tunnel links — dump may fail")
			// non-fatal: proceed; CRIU will report the error explicitly
		}
		c.removedNetLinks = removed
		if len(removed) > 0 {
			names := make([]string, len(removed))
			for i, r := range removed {
				names[i] = r.name
			}
			logger.Info("pre-dump: deleted unsupported tunnel links from container netns",
				"pid", opts.Pid, "links", names)
		}
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

// cgroupRegFileFd is one regular-file fd whose recorded path is under /sys/fs/cgroup,
// enumerated from the checkpoint images for ADR-0180 InheritFd redirection.
type cgroupRegFileFd struct {
	Fd   int    // restored-task fd number == CRIU InheritFd NUM
	Path string // recorded /sys/fs/cgroup path == CRIU InheritFd Key (RES)
}

// enumerateCgroupRegFileFds parses files.img + fdinfo-*.img in imagesDir via pycriu and
// returns every regular-file fd whose recorded path is under /sys/fs/cgroup (ADR-0180,
// predicate-based — never cpu.max-hardcoded). Mirrors the server-side enumeration; used
// by the go-criu RPC restore path.
func enumerateCgroupRegFileFds(imagesDir string) ([]cgroupRegFileFd, error) {
	script := `
import pycriu, glob, json, sys, os
cpdir = sys.argv[1]
id2path = {}
fi = os.path.join(cpdir, 'files.img')
if os.path.exists(fi):
    with open(fi, 'rb') as f:
        files = pycriu.images.load(f)
    for e in files.get('entries', []):
        if e.get('type') == 'REG' and 'reg' in e:
            id2path[e['id']] = e['reg'].get('name')
out, seen = [], set()
for img in sorted(glob.glob(os.path.join(cpdir, 'fdinfo-*.img'))):
    with open(img, 'rb') as f:
        fdinfo = pycriu.images.load(f)
    for e in fdinfo.get('entries', []):
        if e.get('type') != 'REG':
            continue
        p = id2path.get(e.get('id'))
        if p and p.startswith('/sys/fs/cgroup'):
            k = (e.get('fd'), p)
            if k in seen:
                continue
            seen.add(k)
            out.append({'fd': e.get('fd'), 'path': p})
print(json.dumps(out))
`
	cmd := exec.Command("python3", "-c", script, imagesDir)
	cmd.Env = append(os.Environ(), "PYTHONPATH=/usr/lib/python3/dist-packages")
	raw, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		return nil, fmt.Errorf("enumerateCgroupRegFileFds pycriu: %w: %s", err, stderr)
	}
	var parsed []struct {
		Fd   int    `json:"fd"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("enumerateCgroupRegFileFds parse %q: %w", string(raw), err)
	}
	fds := make([]cgroupRegFileFd, 0, len(parsed))
	for _, p := range parsed {
		fds = append(fds, cgroupRegFileFd{Fd: p.Fd, Path: p.Path})
	}
	return fds, nil
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
		// MntnsCompatMode: false — use CRIU 4.2 mount-v2 mode (default).
		// Compat-mode (MntnsCompatMode=true) does an umount pass that tries to remove
		// /sys from the destination namespace → EBUSY (sysfs is kernel-referenced).
		// Mount-v2 uses MOVE_MOUNT_SET_GROUP and does NOT run the umount pass, so it avoids
		// the EBUSY error. /sys is in skipMnts at dump time so it is not in the image;
		// mount-v2 only mounts what is in the image (no umount of foreign destination mounts).
		// A previous attempt with MntnsCompatMode=false hit "BUG at criu/mount.c:48" because
		// the image had external mounts with a non-standard root. With the stripped image
		// (5 regular entries: /, /proc, /dev, /dev/pts, /dev/mqueue) mount-v2 should work.
		MntnsCompatMode: proto.Bool(false),
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
			// NOTE: /sys is NOT in SkipMnt — CRIU 4.2 SkipMnt is dump-only (--skip-mnt
			// help says "ignore this mountpoint when dumping the mount namespace"). It has no
			// effect on the restore-side compat-mode umount pass. /sys is skipped at dump via
			// skipMnts; compat-mode is disabled (MntnsCompatMode=false) to avoid the umount pass.
			"/var/run/secrets/kubernetes.io/serviceaccount",
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
		// pm-sys reverse-maps the dump-side --external mnt[/sys]:pm-sys declaration. Without this,
		// compat-mode treats /sys as a stale mount and umounts it; the host-bind-mounted sysfs
		// returns EBUSY. Key must match criu_checkpointer.go dump args exactly.
		External: []string{"mnt[pm-sys]:/sys"},
	}

	// ADR-0180: redirect every regular-file fd whose recorded path is under /sys/fs/cgroup
	// (predicate-based, never cpu.max-hardcoded — Arch-A S5) via CRIU InheritFd so the
	// files-reg.c regular-file restore pass dups an agent-held cgroupfs descriptor instead of
	// open()-ing the absent image path (abort at files-reg.c:2353). On the go-criu RPC (swrk)
	// path InheritFd.Fd is a fd number in the CRIU swrk process; go-criu's Prepare() execs
	// `criu swrk` and only sets CloseOnExec on its control socketpair, so a fd the agent holds
	// open WITHOUT O_CLOEXEC at the exact target number is inherited by the swrk child. We dup
	// each opened cgroupfs source to its target fd number (NUM) with O_CLOEXEC cleared and
	// record InheritFd{Key: recordedPath, Fd: NUM}.
	//
	// Cleanup contract (ADR-0180 OC-2 / Standing Rule 7): every dup'd cgroup fd is closed on
	// EVERY exit path of Restore via the deferred closer below (success, failure, ctx-cancel/
	// Abort). No cgroup fd is leaked into the agent process.
	var heldInheritFds []int
	closeHeldInheritFds := func() {
		for i, fd := range heldInheritFds {
			if fd >= 0 {
				_ = unix.Close(fd)
				heldInheritFds[i] = -1
			}
		}
	}
	defer closeHeldInheritFds()
	if cgFds, enumErr := enumerateCgroupRegFileFds(opts.ImagesDir); enumErr != nil {
		// Degrade-and-continue: proceed without InheritFd. Restore then either succeeds (no
		// cgroup fd held) or aborts loudly at files-reg.c:2353 — never worse than pre-ADR-0180.
		logger.Info("ADR-0180: cgroup InheritFd enumeration failed; proceeding without InheritFd", "err", enumErr)
	} else {
		for _, cg := range cgFds {
			if cg.Fd < 3 {
				continue // std streams; CRIU does not request inherit-fd for them
			}
			src := cg.Path
			if _, statErr := os.Stat(src); statErr != nil {
				// Recorded pod-cgroup path may not exist on the destination pre-restore; fall
				// back to the cgroup-v2 root file of the same controller (e.g. cpu.max). The
				// restore still advances past files-reg.c:2353 (S1); the post-restore cgroup
				// move + Go live re-read corrects the quota value (S2).
				src = filepath.Join("/sys/fs/cgroup", filepath.Base(cg.Path))
			}
			f, oerr := os.OpenFile(src, os.O_RDONLY, 0)
			if oerr != nil {
				closeHeldInheritFds()
				return RestoreResult{}, fmt.Errorf("ADR-0180: open cgroup inherit source %q for fd[%d] (recorded %q): %w",
					src, cg.Fd, cg.Path, oerr)
			}
			// dup the opened source to the exact target fd number so the swrk child sees it at
			// NUM. unix.Dup3 with flags=0 clears O_CLOEXEC on the new fd (inheritable by exec).
			if derr := unix.Dup3(int(f.Fd()), cg.Fd, 0); derr != nil {
				_ = f.Close()
				closeHeldInheritFds()
				return RestoreResult{}, fmt.Errorf("ADR-0180: dup cgroup inherit fd %d->%d: %w", int(f.Fd()), cg.Fd, derr)
			}
			_ = f.Close() // the dup at cg.Fd is the held descriptor now
			heldInheritFds = append(heldInheritFds, cg.Fd)
			criuOpts.InheritFd = append(criuOpts.InheritFd, &rpc.InheritFd{
				// CRIU files-reg.c:2611 stores rfi->path = rfe->name+1 (no leading slash).
				// inherit-fd match is literal strcmp — key must omit the leading '/'. ADR-0188.
				Key: proto.String(strings.TrimPrefix(cg.Path, "/")),
				Fd:  proto.Int32(int32(cg.Fd)),
			})
			logger.Info("ADR-0180: redirecting cgroup reg-file fd via InheritFd",
				"fd", cg.Fd, "recordedPath", cg.Path, "hostSource", src)
		}
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

// deleteUnsupportedNetLinks enters the network namespace of pid, enumerates tunnel
// links (ARPHRD_TUNNEL/SIT/GRE/etc.) that are DOWN, deletes them via RTM_DELLINK,
// and returns the list of removed links so the caller can recreate them post-restore.
//
// ADR-0162-rev: CRIU 4.2 aborts strict-mode netns dump at net.c:650 for ARPHRD_TUNNEL
// devices (tunl0) because --external net[idx]:name is NOT consulted before the abort.
// Deleting these always-DOWN devices before the dump is the correct fix.
//
// Safety invariants:
//   - Only links with operstate "unknown" or "down" are deleted (never UP tunnels).
//   - The goroutine is locked to its OS thread for the duration of the netns switch.
//   - The original netns is always restored via defer before UnlockOSThread.
//
// If the /proc/<pid>/root tree is unreadable the function returns nil and logs a warning
// so the caller continues (safe degradation).
func deleteUnsupportedNetLinks(pid int32, logger interface {
	Info(string, ...interface{})
	Error(error, string, ...interface{})
}) ([]removedLink, error) {
	// Tunnel ARPHRD_ types that CRIU 4.2 cannot handle (net/network.c).
	unsupportedTypes := map[int]bool{
		768: true, // ARPHRD_TUNNEL  ipip / tunl0
		776: true, // ARPHRD_SIT     sit  / sit0
		778: true, // ARPHRD_IPGRE   gre
		813: true, // ARPHRD_GRETAP  gretap
		823: true, // ARPHRD_IP6GRE  ip6gre
	}

	sysNetRoot := fmt.Sprintf("/proc/%d/root/sys/class/net", pid)
	entries, err := os.ReadDir(sysNetRoot)
	if err != nil {
		logger.Info("deleteUnsupportedNetLinks: cannot read container sys/class/net — skipping",
			"pid", pid, "err", err)
		return nil, nil //nolint:nilerr // safe degradation per ADR-0162
	}

	// Collect candidates before entering the netns (reads from /proc are host-visible).
	type candidate struct {
		name     string
		ifindex  int
		linkType int
	}
	var candidates []candidate

	for _, e := range entries {
		iface := e.Name()
		ifaceDir := fmt.Sprintf("%s/%s", sysNetRoot, iface)

		typeBytes, readErr := os.ReadFile(ifaceDir + "/type")
		if readErr != nil {
			continue
		}
		linkType, parseErr := strconv.Atoi(strings.TrimSpace(string(typeBytes)))
		if parseErr != nil || !unsupportedTypes[linkType] {
			continue
		}

		// Only delete if operstate is "unknown" or "down" — never touch an UP tunnel.
		stateBytes, stateErr := os.ReadFile(ifaceDir + "/operstate")
		if stateErr != nil {
			logger.Info("deleteUnsupportedNetLinks: cannot read operstate — skipping interface",
				"pid", pid, "iface", iface)
			continue
		}
		state := strings.TrimSpace(strings.ToLower(string(stateBytes)))
		if state != "unknown" && state != "down" {
			logger.Info("deleteUnsupportedNetLinks: tunnel link is UP — skipping deletion",
				"pid", pid, "iface", iface, "operstate", state)
			continue
		}

		idxBytes, idxErr := os.ReadFile(ifaceDir + "/ifindex")
		if idxErr != nil {
			logger.Info("deleteUnsupportedNetLinks: cannot read ifindex — skipping",
				"pid", pid, "iface", iface)
			continue
		}
		ifindex, idxParseErr := strconv.Atoi(strings.TrimSpace(string(idxBytes)))
		if idxParseErr != nil {
			continue
		}

		candidates = append(candidates, candidate{name: iface, ifindex: ifindex, linkType: linkType})
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	// Enter the container network namespace.
	// LockOSThread ensures the kernel thread netns switch is visible for the duration.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origNsFd, openErr := unix.Open(fmt.Sprintf("/proc/self/ns/net"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return nil, fmt.Errorf("deleteUnsupportedNetLinks: open host netns: %w", openErr)
	}
	defer unix.Close(origNsFd)

	targetNsFd, openErr := unix.Open(fmt.Sprintf("/proc/%d/ns/net", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return nil, fmt.Errorf("deleteUnsupportedNetLinks: open container netns for pid %d: %w", pid, openErr)
	}
	defer unix.Close(targetNsFd)

	if setnsErr := unix.Setns(targetNsFd, unix.CLONE_NEWNET); setnsErr != nil {
		return nil, fmt.Errorf("deleteUnsupportedNetLinks: setns into container netns for pid %d: %w", pid, setnsErr)
	}
	// Always restore host netns before returning, even on error.
	defer func() {
		if restoreErr := unix.Setns(origNsFd, unix.CLONE_NEWNET); restoreErr != nil {
			logger.Error(restoreErr, "deleteUnsupportedNetLinks: CRITICAL — failed to restore host netns")
		}
	}()

	var removed []removedLink
	var firstErr error

	for _, c := range candidates {
		if delErr := netlinkDelLink(c.ifindex); delErr != nil {
			logger.Error(delErr, "deleteUnsupportedNetLinks: RTM_DELLINK failed — skipping",
				"iface", c.name, "ifindex", c.ifindex, "linkType", c.linkType)
			if firstErr == nil {
				firstErr = delErr
			}
			continue
		}
		// Verify the device is actually gone. tunl0/gre0 are NETIF_F_NETNS_LOCAL:
		// the kernel reports RTM_DELLINK success but the device persists in the netns.
		// Check via /proc/<pid>/root/sys/class/net/<name> which is readable from the
		// host regardless of our current netns context.
		netDevPath := fmt.Sprintf("/proc/%d/root/sys/class/net/%s", pid, c.name)
		if _, statErr := os.Stat(netDevPath); statErr == nil {
			// Device still exists — RTM_DELLINK was a silent no-op (NETIF_F_NETNS_LOCAL).
			err := fmt.Errorf("cannot remove %s (ifindex %d type %d) from container netns: device is kernel netns-local fallback (ipip/gre module loaded on node); strict-TCP migration requires VXLAN CNI backend", c.name, c.ifindex, c.linkType)
			logger.Error(err, "deleteUnsupportedNetLinks: post-delete verification failed — device persists after RTM_DELLINK",
				"iface", c.name, "ifindex", c.ifindex, "linkType", c.linkType, "procPath", netDevPath)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		logger.Info("deleteUnsupportedNetLinks: deleted unsupported tunnel links from container netns",
			"iface", c.name, "ifindex", c.ifindex, "linkType", c.linkType)
		removed = append(removed, removedLink{
			name:     c.name,
			ifindex:  c.ifindex,
			linkType: c.linkType,
		})
	}

	return removed, firstErr
}

// netlinkDelLink sends RTM_DELLINK for the interface identified by ifindex using a raw
// NETLINK_ROUTE socket. The caller must already be in the target network namespace.
func netlinkDelLink(ifindex int) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlinkDelLink: socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlinkDelLink: bind: %w", err)
	}

	// Build RTM_DELLINK message: NlMsghdr + IfInfomsg (family=AF_UNSPEC, index=ifindex).
	const ifInfoMsgSize = 16 // sizeof(struct ifinfomsg): family(1)+pad(1)+type(2)+index(4)+flags(4)+change(4)
	msgLen := unix.SizeofNlMsghdr + ifInfoMsgSize

	buf := make([]byte, msgLen)

	// NlMsghdr
	hdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	hdr.Len = uint32(msgLen)
	hdr.Type = unix.RTM_DELLINK
	hdr.Flags = unix.NLM_F_REQUEST | unix.NLM_F_ACK
	hdr.Seq = 1
	hdr.Pid = 0

	// IfInfomsg: family=AF_UNSPEC, index=ifindex, flags=0, change=0
	buf[unix.SizeofNlMsghdr+0] = unix.AF_UNSPEC // family
	// pad, type = 0 (already zeroed)
	// index at offset 4 (little-endian int32)
	buf[unix.SizeofNlMsghdr+4] = byte(ifindex)
	buf[unix.SizeofNlMsghdr+5] = byte(ifindex >> 8)
	buf[unix.SizeofNlMsghdr+6] = byte(ifindex >> 16)
	buf[unix.SizeofNlMsghdr+7] = byte(ifindex >> 24)

	if err := unix.Sendto(fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlinkDelLink: sendto: %w", err)
	}

	// Read ACK (NLMSG_ERROR with err=0 means success).
	resp := make([]byte, 4096)
	n, _, recvErr := unix.Recvfrom(fd, resp, 0)
	if recvErr != nil {
		return fmt.Errorf("netlinkDelLink: recvfrom: %w", recvErr)
	}
	msgs, parseErr := syscall.ParseNetlinkMessage(resp[:n])
	if parseErr != nil {
		return fmt.Errorf("netlinkDelLink: parse netlink response: %w", parseErr)
	}
	for _, msg := range msgs {
		if msg.Header.Type == syscall.NLMSG_ERROR {
			if len(msg.Data) < 4 {
				return fmt.Errorf("netlinkDelLink: short NLMSG_ERROR data")
			}
			// NlMsgerr.Error is a negative errno stored as int32 LE.
			errno := int32(msg.Data[0]) | int32(msg.Data[1])<<8 | int32(msg.Data[2])<<16 | int32(msg.Data[3])<<24
			if errno != 0 {
				return fmt.Errorf("netlinkDelLink: kernel returned errno %d: %w", -errno, unix.Errno(-errno))
			}
		}
	}
	return nil
}

