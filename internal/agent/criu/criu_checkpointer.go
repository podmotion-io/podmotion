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

// hostCRIUWrapperPath is the host-node install location of podmotion-criu-wrapper
// (ADR-0181/0183: the install-criu-wrapper init container copies it here). Under
// SD-1 (ADR-0231/0234) the de-privileged agent cannot itself setns(CLONE_NEWNS)
// into the host mount namespace, so the CRIU checkpoint/pre-dump binary — which is
// the HOST criu (glibc 2.39), dynamically linked and NOT runnable against the
// debian:12-slim agent-container glibc (~2.36) — is launched in the host mount
// namespace via the privileged netns-broker sidecar, which nsenters host mnt ns and
// execve's this wrapper, which in turn execve's /usr/sbin/criu. With no --cgroup-fd
// args the wrapper is a pure "exec criu in host mnt ns" shim. This is the same
// allowlisted host-ns launch primitive the restore path uses (server.go joinNsRestore).
const hostCRIUWrapperPath = "/opt/podmotion/bin/podmotion-criu-wrapper"

// HostNSProcess is a handle to a command spawned DETACHED in the HOST mount namespace.
// The checkpointer drives it: it Polls until the command exits (surfacing exit code +
// captured combined stdout/stderr), or — on context cancel/abort — Signals it (SIGKILL)
// so an aborted dump/pre-dump cannot keep writing checkpoint images into ImagesDir after
// the caller has returned "aborted" and started zeroizing (invariant 7: checkpoints
// zeroized on ALL exit paths — the kill makes that zeroize race-free).
type HostNSProcess interface {
	// Poll reports whether the process has exited. When exited, exitCode and output
	// (combined stdout+stderr) are valid. A non-zero exit is NOT an err; err is set only
	// on a poll/broker transport failure.
	Poll(ctx context.Context) (exited bool, exitCode int, output []byte, err error)
	// Signal delivers signal sig to the process (SIGKILL on abort). Best-effort.
	Signal(ctx context.Context, sig int) error
}

// HostNSRunner spawns argv DETACHED inside the HOST mount namespace and returns a
// handle the checkpointer polls/signals. It is injected into CRIUCheckpointer so the
// criu package stays free of any netns-broker import (no cycle) and remains
// unit-testable. In the agent binary it is backed by the privileged netns-broker
// sidecar's async exec ops (ExecStart/ExecPoll/ExecSignal — ADR-0234), the same
// primitive the live Restore path uses, so an aborted dump can SIGKILL the CRIU child.
// When nil, CRIUCheckpointer falls back to a direct in-container exec of the CRIU binary
// (kind/dev, where the node and agent container share the same glibc, and unit tests).
type HostNSRunner func(ctx context.Context, argv ...string) (HostNSProcess, error)

// hostNSPollInterval is how often runCRIUCLI polls a detached host-ns CRIU child.
// Matches the broker's brokerCriuWrapperPollInterval (50ms) so abort latency is bounded.
const hostNSPollInterval = 50 * time.Millisecond

// sigKill is the signal number the checkpointer asks the broker to deliver on abort.
// (The broker maps 0→SIGKILL; we pass the explicit SIGKILL number for clarity.)
const sigKill = 9

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

	// hostNSRun, when non-nil, runs the CRIU dump/pre-dump CLI in the HOST mount
	// namespace (via the podmotion-criu-wrapper through the privileged netns-broker)
	// so the dynamically-linked host CRIU binary links against the host glibc rather
	// than the older agent-container glibc. When nil, PreDump/Dump exec the CRIU
	// binary directly in the agent container's mount namespace (kind/dev/tests).
	hostNSRun HostNSRunner

	mu              sync.Mutex
	activeCriu      *gocriu.Criu  // non-nil while a dump/restore is in progress
	removedNetLinks []removedLink // links deleted pre-dump for restore-side recreation

	// pidLocks serializes CRIU seize operations (pre-dump / dump) against a given
	// target process tree. CRIU seizes the tree with PTRACE_SEIZE + PTRACE_INTERRUPT
	// (compel infect.c); the kernel permits exactly ONE tracer per task, so two CRIU
	// processes launched against the same root PID collide — the loser fails with
	// "Unable to interrupt task: <pid> (Operation not permitted)" (EPERM) and aborts
	// the whole dump. Callers above the checkpointer (the controller's pre-copy loop,
	// the migration estimator's probe pre-dump) can each independently drive a
	// pre-dump for the same source container, so this is a substrate-level invariant,
	// not something any single caller can guarantee: the checkpointer OWNS CRIU, so it
	// owns "one CRIU seize per process tree at a time." Keyed by PID (not global) so
	// two DIFFERENT pods on the same node still checkpoint concurrently. A PID is only
	// reused after the prior task fully exits, by which point no CRIU op holds its
	// lock, so a stale entry is harmless.
	pidLocks sync.Map // map[int32]*sync.Mutex
}

// lockForPID returns the per-PID serialization mutex, creating it on first use. The
// returned mutex guards the CRIU seize window for that process tree so concurrent
// pre-dump/dump invocations against the same PID cannot collide on PTRACE_SEIZE.
func (c *CRIUCheckpointer) lockForPID(pid int32) *sync.Mutex {
	m, _ := c.pidLocks.LoadOrStore(pid, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// NewCRIUCheckpointer returns a CRIUCheckpointer that invokes the CRIU binary
// at criuBinaryPath. Pass an empty string to use the default /usr/sbin/criu.
func NewCRIUCheckpointer(criuBinaryPath string) *CRIUCheckpointer {
	if criuBinaryPath == "" {
		criuBinaryPath = defaultCRIUBinaryPath
	}
	return &CRIUCheckpointer{criuBinaryPath: criuBinaryPath}
}

// SetHostNSRunner installs the host-mount-namespace runner used to launch the CRIU
// dump/pre-dump CLI. When set, PreDump and Dump run CRIU in the host mount namespace
// (via podmotion-criu-wrapper through the netns-broker) so the host CRIU binary links
// against the host glibc — fixing the "GLIBC_2.38 not found" failure that occurred when
// the host binary was exec'd directly in the older-glibc agent container. Must be called
// before any PreDump/Dump. Passing nil restores direct in-container exec (kind/dev/tests).
func (c *CRIUCheckpointer) SetHostNSRunner(r HostNSRunner) {
	c.hostNSRun = r
}

// runCRIUCLI runs `criu <criuArgs...>` and returns (combinedOutput, error). When a
// host-namespace runner is installed it launches the CRIU binary in the host mount
// namespace via the podmotion-criu-wrapper (no --cgroup-fd args → pure exec-criu shim),
// spawning it DETACHED and polling to completion; otherwise it execs the CRIU binary
// directly in the agent container. In BOTH cases an aborted run ACTIVELY terminates the
// CRIU child before returning: the direct path kills its local process, the host-ns path
// SIGKILLs the broker-side child. This guarantees no CRIU keeps writing checkpoint images
// into ImagesDir after runCRIUCLI returns "aborted", so the caller's zeroize path is
// race-free (invariant 7). The returned bytes are CRIU's combined stdout+stderr so an
// early fatal emitted to stdout before the -o log file is opened is not lost. The caller
// reads the CRIU --log-file (predump.log/dump.log) from ImagesDir separately.
func (c *CRIUCheckpointer) runCRIUCLI(ctx context.Context, criuArgs []string) (output []byte, err error) {
	if c.hostNSRun != nil {
		// Launch host CRIU in the host mount namespace via the wrapper. Zero --cgroup-fd
		// args: argv is [wrapper, "--", criuBinary, criuArgs...] so the wrapper's first
		// token is "--" and it execs criu directly (no fd delivery) in host mnt ns.
		argv := append([]string{hostCRIUWrapperPath, "--", c.criuBinaryPath}, criuArgs...)

		// Spawn detached. Use a Background context for the spawn RPC itself so a caller
		// ctx that is ALREADY cancelled still lets us learn the child PID (needed to kill
		// it); the poll loop below observes ctx cancellation and SIGKILLs.
		proc, startErr := c.hostNSRun(context.Background(), argv...)
		if startErr != nil {
			return nil, fmt.Errorf("host-ns criu launch: %w", startErr)
		}

		// abortKill SIGKILLs the detached child and drains one final poll so the broker
		// reaps it (best-effort — errors are non-fatal on the abort path).
		abortKill := func() {
			killCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = proc.Signal(killCtx, sigKill)
			// One reaping poll so the broker Wait()s the killed child (no zombie leak).
			_, _, _, _ = proc.Poll(killCtx)
		}

		ticker := time.NewTicker(hostNSPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				// Aborted: actively kill the CRIU child BEFORE returning so it cannot keep
				// writing images into ImagesDir concurrently with the caller's zeroize.
				abortKill()
				return nil, ctx.Err()
			case <-ticker.C:
				// Poll with the caller ctx so a broker transport hang is bounded; on ctx
				// cancel Poll returns and the next loop iteration hits the ctx.Done() case.
				exited, exitCode, out, pollErr := proc.Poll(ctx)
				if pollErr != nil {
					if ctx.Err() != nil {
						// Poll failed because ctx was cancelled — kill and report abort.
						abortKill()
						return nil, ctx.Err()
					}
					// Genuine broker/transport failure: kill the child (it may still be
					// running and writing images) before surfacing the error.
					abortKill()
					return out, fmt.Errorf("host-ns criu poll: %w", pollErr)
				}
				if !exited {
					continue
				}
				if exitCode != 0 {
					return out, fmt.Errorf("exit status %d", exitCode)
				}
				return out, nil
			}
		}
	}

	// Direct in-container exec (kind/dev/tests: node and container share glibc).
	//nolint:gosec // binary path is a trusted constant, args are controlled internally
	cmd := exec.CommandContext(ctx, c.criuBinaryPath, criuArgs...)
	var buf bytes.Buffer
	cmd.Stderr = &buf
	cmd.Stdout = &buf
	type result struct{ err error }
	done := make(chan result, 1)
	go func() { done <- result{err: cmd.Run()} }()
	select {
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return buf.Bytes(), ctx.Err()
	case res := <-done:
		return buf.Bytes(), res.err
	}
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
	// --stats (-S) makes CRIU write a stats-dump image into ImagesDir carrying the real
	// dirty-page accounting (decoded below by decodeCRIUStats) — see criu_stats.go.
	args := []string{
		"pre-dump",
		"-t", strconv.Itoa(int(opts.Pid)),
		"--images-dir", opts.ImagesDir,
		"--log-file", "predump.log",
		"-v4",
		"--pre-dump-mode", "read",
		"--stats",
	}

	if opts.PrevImagesDir != "" {
		rel, relErr := filepath.Rel(opts.ImagesDir, opts.PrevImagesDir)
		if relErr != nil {
			rel = opts.PrevImagesDir
		}
		args = append(args, "--prev-images-dir", rel)
	}

	// Serialize the CRIU seize against this process tree: a concurrent pre-dump/dump
	// for the same PID would collide on PTRACE_SEIZE and fail with EPERM ("Unable to
	// interrupt task"). Held for the duration of the CRIU child so no second CRIU op
	// can seize the tree until this one has detached. See pidLocks.
	if opts.Pid != 0 {
		pidLock := c.lockForPID(opts.Pid)
		pidLock.Lock()
		defer pidLock.Unlock()
	}

	// Run CRIU pre-dump. Under SD-1 this runs in the host mount namespace via the
	// netns-broker + podmotion-criu-wrapper (host CRIU binary → host glibc); on
	// kind/dev/tests it execs directly in the agent container. runCRIUCLI handles both.
	stderrBytes, runErr := c.runCRIUCLI(ctx, args)
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			return CheckpointResult{}, fmt.Errorf("PreDump aborted: %w", runErr)
		}
		predumpLog, _ := os.ReadFile(filepath.Join(opts.ImagesDir, "predump.log"))
		return CheckpointResult{}, fmt.Errorf("criu pre-dump: %w\nstderr: %s\nlog: %s",
			runErr, string(stderrBytes), string(predumpLog))
	}

	// fail-closed phase-gate (item 1a/1b): read CRIU's own --stats output for the real dirty-page count.
	// PreDump must NEVER report DirtyPagesMB: 0 as a stand-in for "couldn't measure" — a
	// decode failure here fails the whole call closed, because 0 is indistinguishable from
	// "genuinely no dirty pages" to every caller (EstimateCheckpoint chief among them).
	dirtyMB, statsErr := decodeCRIUStats(opts.ImagesDir)
	if statsErr != nil {
		return CheckpointResult{}, fmt.Errorf("PreDump: stats image parse failed: %w", statsErr)
	}

	return CheckpointResult{
		ImagesDir:        opts.ImagesDir,
		DirtyPagesMB:     dirtyMB,
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

	// Serialize the CRIU seize against this process tree (see pidLocks). A pre-dump
	// round for the same PID may still be finishing when the final Dump is issued; the
	// two would otherwise collide on PTRACE_SEIZE and abort the dump with EPERM. Held
	// across the ptrace preflight and the CRIU dump child.
	pidLock := c.lockForPID(opts.Pid)
	pidLock.Lock()
	defer pidLock.Unlock()

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
		// ADR-0228: container-runtime masking tmpfs mounts over /proc/*.
		//
		// containerd/runc inject small read-only tmpfs mounts (type tmpfs, source tmpfs,
		// mode=755, size=65536k) over these /proc paths to hide host kernel internals from
		// the container (the CRI "maskedPaths" default set). They appear in the dump-side
		// mount table as e.g.:
		//   type tmpfs source tmpfs mnt_id 12198 s_dev 0x38d / @ ./proc/scsi flags ... mode=755
		//
		// CRIU's mountpoint dump pass (criu/filesystems.c dump_tmpfs) tar-serializes the
		// CONTENT of every tmpfs mount it does not skip. For these masking mounts it shells
		// out to `tar` (via /bin/sh) to capture the (empty) tmpfs content. In the constrained
		// agent container that fork is denied:
		//   mnt: Dumping mountpoints
		//   mnt: 	12198: 38d:/ @ ./proc/scsi
		//   /bin/sh: 1: Cannot fork
		//   tar: Child returned status 2
		//   tar: Error is not recoverable: exiting now
		//   Error (criu/util.c:657): exited, status=2
		//   Error (criu/filesystems.c:426): Can't dump tmpfs content
		//   Error (criu/cr-dump.c:2128): Dumping FAILED.
		// This is the t=15s frontier that surfaced once ADR-0227 (--manage-cgroups=ignore)
		// cleared the earlier cgroup-walk wall: the dump advanced from the cgroup stage into
		// the mountpoint stage and hit the FIRST masking tmpfs it tried to tar.
		//
		// These masking mounts carry NO workload state — they are empty tmpfs the runtime
		// re-provides from its own bundle on restore. The restore-side SkipMnt list (below)
		// ALREADY skips this exact set; the dump side did not, so the dump tried to tar them.
		// removal/skip-symmetry: skip them at dump time too so CRIU never tar-dumps
		// their content. Skipping the content does not lose state (tmpfs is empty) and keeps
		// the dump/restore skip sets symmetric. No `tar` fork is attempted for a skipped mount.
		"/proc/acpi",
		"/proc/asound",
		"/proc/kcore",
		"/proc/keys",
		"/proc/latency_stats",
		"/proc/scsi",
		"/proc/timer_list",
		// dump/restore skip symmetry: the restore-side SkipMnt list (below) skips these
		// masked /proc/* mounts too, but the dump side historically did not. On the raw
		// go-criu Dump path this asymmetry is latent — a masked bind CRIU cannot resolve to
		// a proper root (e.g. /proc/interrupts) aborts the mountpoint-dump pass at
		// criu/mount.c:753 "doesn't have a proper root mount" BEFORE the network pass. This
		// is the exact class of failure that hard-fails postgres via `ctr tasks checkpoint`
		// (which does not carry this list at all) and is routed to this raw path via
		// ErrCtrMaskedMount. containerd/runc bind these masked /proc entries per the OCI
		// default maskedPaths set; they carry no migratable workload state and are re-provided
		// by the destination runtime on restore. Skip them at dump so the mount pass never
		// tries to resolve their root, keeping the dump and restore skip sets symmetric
		// (mirrors the restore-side SkipMnt block below — do not let the two drift).
		"/proc/interrupts",
		"/proc/timer_stats",
		"/proc/sched_debug",
		"/proc/bus",
		"/proc/fs",
		"/proc/irq",
		"/proc/sys",
		"/proc/sysrq-trigger",
		// ADR-0228: Kubernetes projected service-account token tmpfs.
		//
		// The kubelet mounts the projected SA token as its own tmpfs:
		//   type tmpfs source tmpfs mnt_id 12345 s_dev 0x32b / @ ./run/secrets/kubernetes.io/serviceaccount
		//   flags 0x200001 options size=32548448k,inode64,noswap
		// It is the SAME failure class as the /proc/* masking mounts above: CRIU's
		// mountpoint dump pass tar-serializes its content and the `tar`/`/bin/sh` fork
		// is denied in the constrained agent container, producing the identical
		// filesystems.c:426 "Can't dump tmpfs content" abort — just one mount later in
		// the dump order once the /proc/* masking mounts are skipped (healthy-descent
		// frontier advance). The projected token is NOT migrated state: it is
		// re-provided by the DESTINATION kubelet's own projected-volume plumbing on
		// restore, which is exactly why the restore-side SkipMnt list below already
		// skips /var/run/secrets/kubernetes.io/serviceaccount. Skip it at dump too to
		// keep the dump/restore skip sets symmetric. Both /run and /var/run
		// spellings are listed because the path appears as /run/... in this pod's mount
		// table while the restore side carries the canonical /var/run/... form
		// (/var/run is conventionally a symlink to /run); --skip-mnt matches the path
		// literally, so list both to be robust across runtimes.
		"/run/secrets/kubernetes.io/serviceaccount",
		"/var/run/secrets/kubernetes.io/serviceaccount",
		// ADR-0230: container /dev tmpfs + its overmounting tmpfs children.
		//
		// runc/containerd mounts the container's /dev as a fresh tmpfs (mode=755,
		// size=65536k) and then OVERMOUNTS it with /dev/shm, /dev/mqueue, /dev/pts and
		// the /dev/termination-log bind. Those child mounts obscure the parent /dev
		// tmpfs, so CRIU's per-mount dump pass (criu/mount.c dump_one_mountpoint ->
		// mnt_is_fully_visible) classifies /dev as NOT fully visible:
		//   mnt: 	12334: 384:/ @ ./dev
		//   mnt: Mount is not fully visible ./dev(12334)
		// For an obscured tmpfs CRIU cannot read the real content through the agent's
		// view, so it falls back to entering the SOURCE mount namespace directly to
		// read it — criu/namespaces.c restore_ns()/switch_ns_by_fd() issues
		// setns(<mnt-ns-fd>, CLONE_NEWNS). In the constrained agent container that
		// setns is denied:
		//   Error (criu/namespaces.c:258): Can't setns 12/mnt: Operation not permitted
		//   Error (criu/mount.c:1809): mnt: Unable to dump a file system for 12334:./dev
		//   Error (criu/cr-dump.c:2128): Dumping FAILED.
		// EPERM here is NOT a missing capability (the agent holds CAP_SYS_ADMIN, and
		// setns is seccomp-allowed): setns(CLONE_NEWNS) is gated by CAP_SYS_ADMIN
		// EFFECTIVE in the USER NAMESPACE THAT OWNS the target mount namespace. The
		// workload pod's mount ns is owned by its own user namespace, not the agent's,
		// so the agent's host-userns CAP_SYS_ADMIN does not carry into it — exactly the
		// constraint the daemonset HOLD-A comment documents for the netns-broker. We do
		// NOT escalate the agent to privileged to win that setns; instead we eliminate
		// the need for it. ADR-0227's --manage-cgroups=ignore and ADR-0228's masked-tmpfs
		// skips advanced the dump frontier into the mountpoint pass; /dev is the FIRST
		// obscured-parent tmpfs CRIU tries to read via setns (healthy-descent frontier
		// advance).
		//
		// The container /dev tmpfs carries NO migratable workload state: it is the
		// standard device-node set (/dev/null, /dev/zero, /dev/urandom, /dev/console,
		// ...) that the DESTINATION runtime re-provides verbatim from the OCI spec on
		// restore, and its tmpfs children (shm/mqueue/pts) are likewise runtime-provided.
		// Redis opens none of /dev as persistent state. Skip /dev (and its overmounting
		// tmpfs children, for removal symmetry so no child is dumped without its
		// parent) at dump time. --skip-mnt short-circuits dump_one_mountpoint BEFORE the
		// visibility check fires, so CRIU never attempts the setns. The restore-side
		// SkipMnt below mirrors this exact set (dump/restore skip symmetry).
		"/dev",
		"/dev/shm",
		"/dev/mqueue",
		"/dev/pts",
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
		// ADR-0227: --manage-cgroups=ignore. CRIU's default cgroup mode walks and
		// serializes the source pod's full cgroup membership. On a cgroup-v2 kind node
		// the BestEffort QoS scope lives at
		// kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice and is
		// NOT visible from the agent container's mount namespace, so the walk fails at
		// cgroup.c:742 ("failed walking ... for the besteffort kubepods cgroup scope:
		// No such file or directory") -> cr-dump.c:1737 Dump core failed -> Dumping FAILED.
		// The container runtime (kubelet/containerd) owns cgroup lifecycle, not CRIU:
		// CRIU must not try to serialize/restore it. This is symmetric with the restore
		// path, which already passes --manage-cgroups=ignore (ADR-0128, server.go:2435).
		// In go-criu RPC terms this is rpc.CriuCgMode_IGNORE; the dump path is CLI-exec
		// (see comment above on swrk AutoExtMnt limitations), so it is passed as a flag.
		"--manage-cgroups=ignore",
	}
	if opts.LeaveRunning {
		dumpArgs = append(dumpArgs, "--leave-running")
	}
	if opts.LeaveStopped {
		dumpArgs = append(dumpArgs, "--leave-stopped")
	}
	// TCP-disposition flags (--tcp-established/--tcp-close plus --skip-in-flight) come from the
	// pure helper criuTCPDumpFlags so the flag set is unit-testable without invoking CRIU
	// (TestCRIUTCPDumpFlags_SkipInFlightBothPaths). --skip-in-flight is now emitted on BOTH the
	// preservation and the cold-close path — see the helper for the ADR-0131/ADR-0352 rationale
	// (a co-resident in-flight socket must not abort a dump that is preserving a held connection).
	dumpArgs = append(dumpArgs, criuTCPDumpFlags(opts.TcpEstablished)...)
	if opts.TcpEstablished {
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
		// Cold network migration (tcpPreservationMode=None): we do NOT preserve any
		// network state — the pod is restored into a fresh (empty) network namespace
		// provisioned by the destination CNI. Dump the net namespace as empty so CRIU
		// does NOT invoke the external `ip` tool to save addresses/routes. The agent
		// image is minimal and does not ship iproute2, so without --empty-ns net CRIU
		// fails with: exec of "ip" failed: No such file or directory ->
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

	// Run CRIU dump. Under SD-1 this runs in the host mount namespace via the
	// netns-broker + podmotion-criu-wrapper (host CRIU binary → host glibc); on
	// kind/dev/tests it execs directly in the agent container. runCRIUCLI captures
	// combined stdout+stderr (CRIU's early errors before the log file is opened).
	stderrBytes, dumpErr := c.runCRIUCLI(ctx, dumpArgs)
	if dumpErr != nil && (errors.Is(dumpErr, context.Canceled) || errors.Is(dumpErr, context.DeadlineExceeded)) {
		return CheckpointResult{}, fmt.Errorf("Dump aborted: %w", dumpErr)
	}
	stderr := bytes.NewBuffer(stderrBytes)

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
		ImagesDirFd:    proto.Int32(int32(imgDirFd.Fd())),
		LogFile:        proto.String("restore.log"),
		LogLevel:       proto.Int32(4),
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
		// NetworkLock on this (runtime-dead) RPC restore path: derive from TcpEstablished per the
		// pre-R1 policy. This path (CRIUCheckpointer.Restore via PostCopyManager/PostCopyRestorer)
		// is never instantiated in non-test code (ADR-0192 R2 §4 — wrong-layer revert).
		// The LIVE restore fix is on buildCRIURestoreArgs (server.go:2079-2129), which passes
		// "--network-lock skip" to honor the dump/restore-pair invariant (dump uses --network-lock
		// skip unconditionally at criu_checkpointer.go:233). If a future post-copy mode instantiates
		// this path, that ADR MUST set NetworkLock=SKIP here as well.
		NetworkLock: func() *rpc.CriuNetworkLockMethod {
			if opts.TcpEstablished {
				return rpc.CriuNetworkLockMethod_IPTABLES.Enum()
			}
			return rpc.CriuNetworkLockMethod_SKIP.Enum()
		}(),
		ShellJob:   proto.Bool(false),
		ExtSharing: proto.Bool(true),
		ExtMasters: proto.Bool(true),
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
			// ADR-0230: mirror the dump-side /dev skip set. The /dev tmpfs and
			// its tmpfs children (shm/mqueue/pts) are not in the dump image (skipped at
			// dump to avoid the obscured-parent setns), so the restore must not expect to
			// recreate them — the destination runtime re-provides /dev from the OCI spec.
			// Keeping the dump and restore skip sets identical preserves removal symmetry.
			"/dev",
			"/dev/shm",
			"/dev/mqueue",
			"/dev/pts",
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
	// LANDMINE (do NOT wire into the live SD-1 agent): this go-criu RPC restore path
	// execs `criu swrk` at c.criuBinaryPath IN-CONTAINER (the agent's mount namespace).
	// On the KVM/AMI nodes that is the HOST criu (glibc 2.39) run against the debian:12-slim
	// container glibc (~2.36) → the exact "GLIBC_2.38 not found" bug this file's dump/pre-dump
	// path was fixed for (host-ns launch via broker+wrapper). Unlike dump/pre-dump, this
	// Restore method is NOT plumbed through hostNSRun — it is currently DEAD CODE (no live
	// caller; the live restore goes through server.go joinNsRestore, which runs criu in the
	// host mount namespace via the broker+wrapper). If a future post-copy mode ever wires this
	// method live, it MUST first route this swrk exec through the host mount namespace the same
	// way (broker+wrapper), or it will re-trigger the glibc failure.
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

// criuTCPDumpFlags is the single source of truth for the TCP-disposition CRIU dump flags.
// Extracting it makes the flag set testable in isolation (no live CRIU needed).
//
//   - tcpEstablished=true (BestEffort/Strict): ESTABLISHED sockets are snapshotted via
//     TCP_REPAIR (--tcp-established). --skip-in-flight is REQUIRED alongside it, not optional:
//     a real held connection almost always has a co-resident socket in a transitional/in-flight
//     state (SYN-SENT/SYN-RECV, or an ESTABLISHED socket carrying an unacked in-flight segment
//     that CRIU rejects at criu/sk-inet.c:185 "inet: In-flight connection"). WITHOUT
//     --skip-in-flight that single socket aborts the ENTIRE dump (cr-dump.c "Dumping FAILED"),
//     taking the preservable ESTABLISHED connection down with it — the exact cycle-2 live-proof
//     checkpoint failure (dump collected ESTABLISHED src 10.244.x then died on in-flight
//     socket 0x30cc26). --skip-in-flight lets CRIU drop ONLY the un-snapshottable in-flight
//     socket (its peer retransmits the SYN) while --tcp-established still preserves the held
//     connection byte-exact. The two flags are complementary, not alternatives.
//     (ADR-0131 D2 raw-CRIU established fallback; ADR-0352 Strict held-connection dump.)
//   - tcpEstablished=false (None/cold): all TCP is closed (--tcp-close); --skip-in-flight is
//     likewise emitted so a transitional socket cannot abort the cold dump either.
func criuTCPDumpFlags(tcpEstablished bool) []string {
	if tcpEstablished {
		return []string{"--tcp-established", "--skip-in-flight"}
	}
	return []string{"--tcp-close", "--skip-in-flight"}
}

// ExportedCRIUTCPDumpFlags is the exported wrapper around criuTCPDumpFlags
// for use in package-level tests (package criu_test).
func ExportedCRIUTCPDumpFlags(tcpEstablished bool) []string {
	return criuTCPDumpFlags(tcpEstablished)
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
