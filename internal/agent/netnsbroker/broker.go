// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

// Package netnsbroker implements the SD-1-NETNS-BROKER privileged sidecar
// (ADR-0148 Amendment SD-1-NETNS-BROKER) and its in-process client.
//
// The broker is the SOLE container in the agent pod that runs privileged:true.
// It exposes exactly two operations over a root-owned Unix domain socket
// (mode 0600): create a per-migration netns bind-mount in the HOST mount
// namespace, and tear one down. The bind-mount privilege (CAP_SYS_ADMIN /
// host-mount-ns mount/umount2) is irreducible — CRIU must open the netns path
// from the host mount namespace via --join-ns net:<path>. SD-1 moves that
// irreducible privilege out of the long-lived, broad-surface main agent and
// into this narrow-surface sidecar that does ONLY these two mount operations
// and speaks no gRPC.
//
// Host-mount-ns entry mechanism (ADR-0148 Amendment SD-1-NETNS-BROKER, revised):
// the bind/umount that must be visible host-wide is performed by an nsenter
// subprocess (`nsenter --mount=/proc/1/ns/mnt -- <op>`), NOT by an in-process
// unix.Setns(CLONE_NEWNS). The Linux kernel forbids setns(CLONE_NEWNS) from a
// multithreaded process (EINVAL), and the Go runtime is irreducibly
// multithreaded — runtime.LockOSThread pins a goroutine to a thread but does
// NOT make the process single-threaded, so the kernel's "is this process
// multithreaded?" check (more than one task sharing the mm/files) still trips.
// privileged:true gives the broker CAP_SYS_ADMIN in the host init userns so
// ns_capable() passes, but that does not lift the multithreaded restriction.
// A forked nsenter is single-threaded at the moment it calls setns, so it
// succeeds. This is the same nsenter chain migrationnetns.go used before the
// SD-1 broker refactor; SD-1 keeps that mechanism and relocates the privilege
// into the sidecar. The fresh-netns UNSHARE for the srcPID=0 destination-prewarm
// path is still done in-process on a locked OS thread — unshare(CLONE_NEWNET) is
// NOT subject to the multithreaded restriction; only setns(CLONE_NEWNS) is.
//
// SC-1 (Security Reviewer condition): socket mode 0600 authenticates the
// filesystem caller, NOT the request. Every op therefore validates
// migrationUID (non-empty, syntactically a migration token) and, on create,
// srcPID (a live, in-migration PID when supplied). The broker never accepts an
// arbitrary host path from the client — it computes the target path itself
// from migrationUID, so a compromised main agent cannot direct the privileged
// sidecar to bind-mount over an arbitrary host location.
package netnsbroker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// SocketPath is the broker's listening Unix domain socket. Created mode 0600,
	// owned root:root. The main agent dials this; no other client is authorized.
	SocketPath = "/run/podmotion/netns-broker.sock"

	// NetnsBaseDir is the base directory under which per-migration netns bind
	// mounts are created (one subdir per migrationUID). Lives on the rshared
	// /run/podmotion mount so the bind propagates host<->container.
	NetnsBaseDir = "/run/podmotion/netns"

	// hostMountNs is the host init mount-namespace handle. The agent pod runs
	// hostPID:true, so /proc/1 resolves to the host init process and
	// /proc/1/ns/mnt is the host mount namespace. nsenter --mount=<this> runs a
	// subprocess in that namespace so the bind-mount is visible host-wide (CRIU
	// runs there). We use the path form (`--mount=/proc/1/ns/mnt`) rather than an
	// fd because nsenter resolves it itself in a single-threaded child.
	hostMountNs = "/proc/1/ns/mnt"

	// hostMountNsArg is the nsenter flag selecting the host init mount namespace.
	hostMountNsArg = "--mount=" + hostMountNs

	// hostMountInfo is host init's mountinfo, visible because the agent pod runs
	// hostPID:true. Idempotency (is the bind already a live nsfs mount?) reads
	// this — it reflects the HOST mount namespace, where the broker's nsenter
	// binds land. /proc/self/mountinfo would show only the container's view.
	hostMountInfo = "/proc/1/mountinfo"
)

// migrationUIDRe constrains migrationUID to the safe token set used by the
// PodMigration controller (UIDs, names: alphanumerics, hyphen). This is SC-1's
// syntactic gate — it forbids path-traversal (`.`, `/`) and shell metacharacters
// so the broker-computed target path cannot escape NetnsBaseDir.
var migrationUIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)

// Request is the JSON wire request accepted on the broker socket.
type Request struct {
	Op string `json:"op"` // "create" | "teardown" | "exec" | "exec_start" | "exec_poll" | "exec_signal" | "signal_pid" | "resolve_veth"
	// MigrationUID names the per-migration netns dir. Validated by migrationUIDRe.
	// Required on create/teardown; ignored on exec*.
	MigrationUID string `json:"migrationUID"`
	// SrcPID, when > 0 on a create, selects /proc/<srcPID>/ns/net as the netns to
	// bind (the pod-in-migration's netns). When 0, the broker unshares a FRESH
	// network namespace on a locked thread and binds that — the destination-prewarm
	// behavior PrepareDestinationNetns relied on (createBindMountedNetns).
	SrcPID int `json:"srcPID,omitempty"`

	// ADR-0231: Argv is the host-mount-namespace command for the "exec" op. The
	// broker runs `nsenter --mount=/proc/1/ns/mnt -- <Argv...>` on the agent's
	// behalf — the restore-path host-mount-ns work (ctr image pull/snapshot, the
	// CRIU wrapper, rootfs mkdir/touch/mount) that the de-privileged main agent
	// cannot itself perform because setns(CLONE_NEWNS) into the host mount ns needs
	// CAP_SYS_ADMIN effective in the HOST init userns (which only privileged:true
	// confers — the broker has it, the SD-1 agent does not). Argv[0] is validated
	// against execAllowlist; the broker never runs an arbitrary client-supplied
	// binary (SC-1-EXEC).
	Argv []string `json:"argv,omitempty"`

	// ADR-0234: ASYNC exec ops (exec_start / exec_poll / exec_signal) for the
	// LONG-RUNNING CRIU restore wrapper. The synchronous "exec" op runs the
	// command to completion (cmd.Run) and is unsuitable for the CRIU wrapper,
	// which on the cold --join-ns path never self-exits: it stays as the
	// foreground workload parent for the lifetime of the workload (ADR-0192).
	// The agent must launch it, then poll a cgroup-PID liveness signal while the
	// wrapper still runs, then reap it asynchronously. exec_start spawns the
	// wrapper DETACHED in the host mount namespace and returns its host PID;
	// exec_poll reports whether it has exited (+ exit code + stderr tail + the
	// broker-cgroup PID set so the agent can run the ADR-0128 new-entrant diff);
	// exec_signal delivers a signal (Abort). WrapperPID identifies the spawned
	// process on poll/signal. Signal is the signal number for exec_signal.
	WrapperPID int `json:"wrapperPID,omitempty"`
	Signal     int `json:"signal,omitempty"`

	// ADR-0312 (signal_pid op): deliver SIGCONT/SIGSTOP to an ARBITRARY host PID —
	// specifically the CRIU-restored workload root, which runs under containerd's
	// default AppArmor profile (a runtime-defined, unpredictable peer label). The
	// de-privileged main agent's own `podmotion-agent` profile denies that cross-
	// profile signal (apparmor DENIED operation="signal" ... peer="runc"); the
	// unconfined broker is not subject to AppArmor signal mediation regardless of
	// the target's profile, so the resume is delegated here. This is a distinct,
	// deliberately narrow surface from exec_signal (which signals only wrapper PIDs
	// the broker itself spawned via asyncExecReg): signal_pid targets a PID the
	// broker never spawned, so it does NOT consult asyncExecReg and instead calls
	// syscall.Kill directly. SC-1: only SIGCONT/SIGSTOP are accepted, and the
	// client-supplied ExpectedStartTime (field 22 of /proc/<pid>/stat) is re-read
	// and matched before the kill to defeat PID reuse.
	SignalPID int `json:"signalPID,omitempty"`
	// ExpectedStartTime is field 22 (starttime, clock ticks since boot) of
	// /proc/<SignalPID>/stat, captured by the client when it recorded the PID. The
	// broker re-reads the live value and refuses to signal on any mismatch.
	ExpectedStartTime uint64 `json:"expectedStartTime,omitempty"`
}

// Response is the JSON wire response. Error is "" on success.
type Response struct {
	// Path is the bind-mount path on success (create only). Empty on teardown.
	Path string `json:"path,omitempty"`
	// Error is a human-readable error string, or "" on success. JSON null<->"".
	// For the exec op, Error is set ONLY on a broker-side failure (validation,
	// nsenter spawn failure). A non-zero EXIT of the executed command is NOT a
	// broker error — it is reported via ExitCode + Stdout/Stderr so the agent
	// reconstructs the subprocess result exactly as if it had run nsenter itself.
	Error string `json:"error,omitempty"`

	// ADR-0231 (exec op only): the host-mount-ns command result. ExitCode is the
	// executed command's exit status (0 on success; -1 if it could not be spawned).
	// Stdout/Stderr are the captured streams. Combined is stdout+stderr interleaved
	// (CombinedOutput semantics) for callers that used .CombinedOutput().
	ExitCode *int   `json:"exitCode,omitempty"`
	Stdout   []byte `json:"stdout,omitempty"`
	Stderr   []byte `json:"stderr,omitempty"`
	Combined []byte `json:"combined,omitempty"`

	// ADR-0234 (async exec ops only).
	// WrapperPID: on exec_start, the host PID of the detached CRIU wrapper.
	WrapperPID int `json:"wrapperPID,omitempty"`
	// Running: on exec_poll, true while the wrapper is still alive; false once it
	// has exited (and been reaped). When false, ExitCode/Stderr carry the result.
	Running bool `json:"running,omitempty"`
	// CgroupPIDs: on exec_poll, the PIDs currently resident in the BROKER's own
	// cgroup. Because the wrapper is the broker's child, --manage-cgroups=ignore
	// lands the CRIU-restored tree in the broker cgroup; the agent diffs this set
	// against the exec_start snapshot to detect the restored workload (ADR-0128
	// new-entrant liveness signal, relocated to the broker cgroup).
	CgroupPIDs []int `json:"cgroupPIDs,omitempty"`
}

// netnsPathFor returns the broker-computed bind target for a migrationUID.
// SC-1: the client never supplies a path; it is derived here from the
// validated UID, so a compromised caller cannot mount over an arbitrary host path.
func netnsPathFor(migrationUID string) string {
	return filepath.Join(NetnsBaseDir, migrationUID, "bind")
}

// validateUID enforces SC-1's request authentication for migrationUID.
func validateUID(migrationUID string) error {
	if migrationUID == "" {
		return fmt.Errorf("migrationUID is required")
	}
	if !migrationUIDRe.MatchString(migrationUID) {
		return fmt.Errorf("migrationUID %q is not a valid migration token", migrationUID)
	}
	return nil
}

// validateSrcPID enforces SC-1's request authentication for srcPID on create.
// A srcPID of 0 means "unshare a fresh netns" (destination-prewarm path) and is
// allowed. A positive srcPID must reference a live process whose net namespace
// is openable — the pod-in-migration. The broker does not attempt to prove the
// PID is "owned by a live node-owned migration" beyond liveness here; the
// controller already gates which migrations reach this RPC and the socket is
// root-only. Liveness rejects a stale/dead PID whose number may have been reused
// for an unrelated process before the bind would capture the wrong netns.
func validateSrcPID(srcPID int) error {
	if srcPID < 0 {
		return fmt.Errorf("srcPID %d is negative", srcPID)
	}
	if srcPID == 0 {
		return nil // fresh-unshare path
	}
	nsPath := fmt.Sprintf("/proc/%d/ns/net", srcPID)
	if _, err := os.Stat(nsPath); err != nil {
		return fmt.Errorf("srcPID %d netns not accessible (process not live?): %w", srcPID, err)
	}
	return nil
}

// Handle dispatches a single decoded Request and returns its Response. It is the
// pure-logic core, exported for unit testing without a live socket.
func Handle(req Request) Response {
	switch req.Op {
	case "create":
		path, err := doCreate(req.MigrationUID, req.SrcPID)
		return toResponse(path, err)
	case "teardown":
		err := doTeardown(req.MigrationUID)
		return toResponse("", err)
	case "exec":
		// ADR-0231: run an allowlisted host-mount-ns command on the agent's behalf.
		return doExec(req.Argv)
	case "exec_start":
		// ADR-0234: spawn the long-running CRIU wrapper detached, return its host PID.
		return doExecStart(req.Argv)
	case "exec_poll":
		// ADR-0234: report wrapper liveness/exit + broker-cgroup PID set.
		return doExecPoll(req.WrapperPID)
	case "exec_signal":
		// ADR-0234: signal the wrapper (Abort path).
		return doExecSignal(req.WrapperPID, req.Signal)
	case "signal_pid":
		// ADR-0312: deliver SIGCONT/SIGSTOP to the CRIU-restored workload root (a PID
		// the broker never spawned) so AppArmor does not mediate the cross-profile
		// resume. Signal allowlist + PID-reuse (starttime) guard enforced here.
		return doSignalPID(req.SignalPID, req.Signal, req.ExpectedStartTime)
	case "resolve_veth":
		// Enter the pod's NET namespace and read eth0's veth peer ifindex on the
		// de-privileged agent's behalf (the agent's AppArmor profile denies the
		// ptrace-read needed to open another pod's /proc/<pid>/ns/net).
		return doResolveVeth(req.SrcPID)
	default:
		return toResponse("", fmt.Errorf("unknown op %q (want create|teardown|exec|exec_start|exec_poll|exec_signal|signal_pid|resolve_veth)", req.Op))
	}
}

// execAllowlist is the SC-1-EXEC binary allowlist for the "exec" op. The broker
// runs ONLY these binaries (matched on Argv[0], absolute or bare) in the host
// mount namespace. This is the security boundary that keeps the "exec" op from
// becoming an arbitrary-command proxy: a compromised de-privileged agent cannot
// direct the privileged broker to run anything outside the CRIU restore path's
// known host-mount-ns command set. The set is exactly the binaries the restore
// path (server.go joinNsRestore / setupRestoreOverlayfs) invokes via nsenterCmd:
//   - ctr / /usr/local/bin/ctr — containerd image pull, snapshot, task lifecycle
//   - /opt/podmotion/bin/podmotion-criu-wrapper — the CRIU launcher (ADR-0181/0183)
//   - mkdir / touch / rm / mount / umount / sh (bare "sh" and absolute "/bin/sh")
//     — rootfs scaffolding + ext-mount setup; the absolute "/bin/sh" form is the
//     one server.go's kubeletVolumeGlobFn uses to `cat /proc/self/mountinfo` for
//     kubelet volume host-target resolution during re-attach restore.
// Adding a new restore-path host-mount-ns command requires adding it here AND a
// a runtime-dependency assertion (the binary must exist on the node) — same
// discipline as any other ADR runtime-dependency (see ADR-0231).
//
// FOLLOW-ON: a cleaner primitive would be a DEDICATED broker op that reads
// /proc/self/mountinfo directly (mirroring the existing signal_pid dedicated op),
// avoiding a general-shell exec on the restore path entirely.
var execAllowlist = map[string]struct{}{
	"ctr":                                       {},
	"/usr/local/bin/ctr":                        {},
	"/opt/podmotion/bin/podmotion-criu-wrapper": {},
	"mkdir":   {},
	"touch":   {},
	"rm":      {},
	"mount":   {},
	"umount":  {},
	"sh":      {},
	"/bin/sh": {},
	"ls":      {},
}

// doExec runs an allowlisted host-mount-namespace command via nsenterHostMnt and
// returns its exit code + captured output. A non-zero command exit is reported in
// the Response (ExitCode/Stderr), NOT as a broker Error — the agent reconstructs
// the subprocess result exactly as if it had run nsenter locally. Only a broker-
// side failure (empty/forbidden argv, nsenter spawn failure) sets Response.Error.
func doExec(argv []string) Response {
	if len(argv) == 0 {
		return Response{Error: "exec: empty argv"}
	}
	if _, ok := execAllowlist[argv[0]]; !ok {
		// SC-1-EXEC: hard reject. Do not run, do not leak which binaries are allowed.
		return Response{Error: fmt.Sprintf("exec: binary %q not in broker allowlist", argv[0])}
	}

	cmd := nsenterHostMnt(argv...)
	var stdout, stderr, combined bytes.Buffer
	// Tee both streams into a combined buffer so we satisfy both .Output() and
	// .CombinedOutput() call sites with one round-trip.
	cmd.Stdout = io.MultiWriter(&stdout, &combined)
	cmd.Stderr = io.MultiWriter(&stderr, &combined)

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			// Could not spawn nsenter at all (binary missing, fork failure). This is
			// a broker-side failure distinct from a non-zero command exit.
			return Response{Error: fmt.Sprintf("exec: spawn nsenter for %q: %v", argv[0], runErr)}
		}
	}
	return Response{
		ExitCode: &exitCode,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Combined: combined.Bytes(),
	}
}

// doResolveVeth enters the pod's NET namespace (/proc/<srcPID>/ns/net) and runs
// `ip -o link show eth0`, returning the raw output for the agent to parse the
// eth0@if<N> host-side veth peer ifindex from. This is the netns counterpart to
// doExec (which enters the host MOUNT namespace): the zero-window-hold arm path
// needs the pod netns, not the host mount ns. The privileged broker (unconfined,
// hostPID:true) can open the workload's netns; the AppArmor-confined main agent
// cannot (ptrace-read DENIED against peer=cri-containerd.apparmor.d).
//
// SC-1: srcPID is validated (positive + live) exactly like create's srcPID; the
// broker builds the fixed argv itself (`nsenter --net=/proc/<pid>/ns/net -- ip -o
// link show eth0`) — no client-supplied argv is executed, so this cannot become an
// arbitrary-command proxy. A non-zero ip(8) exit is reported via ExitCode/Stderr,
// not as a broker Error (mirrors doExec).
func doResolveVeth(srcPID int) Response {
	if srcPID <= 0 {
		return Response{Error: fmt.Sprintf("resolve_veth: srcPID %d must be positive", srcPID)}
	}
	if err := validateSrcPID(srcPID); err != nil {
		return Response{Error: fmt.Sprintf("resolve_veth: %v", err)}
	}

	cmd := nsenterNetNs(srcPID, "ip", "-o", "link", "show", "eth0")
	var stdout, stderr, combined bytes.Buffer
	cmd.Stdout = io.MultiWriter(&stdout, &combined)
	cmd.Stderr = io.MultiWriter(&stderr, &combined)

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return Response{Error: fmt.Sprintf("resolve_veth: spawn nsenter for srcPID %d: %v", srcPID, runErr)}
		}
	}
	return Response{
		ExitCode: &exitCode,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Combined: combined.Bytes(),
	}
}

// nsenterNetNs builds an *exec.Cmd that runs `nsenter --net=/proc/<pid>/ns/net --
// <args...>` — the command executes in the target pod's NETWORK namespace. Unlike
// nsenterHostMnt (host mount ns), this enters a pod netns; opening /proc/<pid>/ns/net
// is permitted here because the broker is unconfined (no AppArmor ptrace mediation).
func nsenterNetNs(pid int, args ...string) *exec.Cmd {
	netNsArg := fmt.Sprintf("--net=/proc/%d/ns/net", pid)
	full := append([]string{netNsArg, "--"}, args...)
	return exec.Command("nsenter", full...)
}

func toResponse(path string, err error) Response {
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{Path: path}
}

// ADR-0234: async exec registry for the long-running CRIU restore wrapper.
//
// The synchronous "exec" op (doExec) runs to completion; the CRIU wrapper on the
// cold --join-ns path does not self-exit, so it is launched DETACHED here and
// reaped via exec_poll. entry holds the spawned *exec.Cmd, a bounded stderr
// buffer (CRIU diagnostics when it fails before opening its -o logfile), the
// PID-set snapshot of the BROKER cgroup at spawn time (the new-entrant baseline
// for the ADR-0128 liveness diff, relocated to the broker cgroup because the
// wrapper is now the broker's child), and the once-only reap result.
type asyncExecEntry struct {
	cmd        *exec.Cmd
	stderr     *bytes.Buffer
	reaped     bool
	exitCode   int
	beforePIDs map[int]bool
}

var (
	asyncExecMu  sync.Mutex
	asyncExecReg = map[int]*asyncExecEntry{}
)

// asyncExecStderrCap bounds the stderr buffer for a detached wrapper. CRIU's
// pre-logfile diagnostics are short; 64 KiB is ample and caps broker memory.
const asyncExecStderrCap = 64 << 10

// validateCriuWrapperArgv is the SC-1-EXEC security gate for the ASYNC path. The
// async ops exist ONLY to launch the CRIU restore wrapper, so the gate is
// TIGHTER than doExec's binary allowlist: argv[0] MUST be exactly the
// PodMotion-owned wrapper binary (ADR-0181/0183), not any allowlisted binary.
// This keeps the detached-spawn surface from becoming a general async-exec proxy:
// the only thing the agent can start-and-leave-running via the broker is the CRIU
// wrapper. The wrapper itself validates its --cgroup-fd=N:path args and execs
// /usr/sbin/criu; the broker does not re-parse criu's flags here (the wrapper is
// the trusted PodMotion-built launcher), but it DOES pin argv[0] so no other
// binary can be detached. (This mirrors ADR-0231's execAllowlist binary
// gate; the async path narrows it to a single binary.)
const criuWrapperBin = "/opt/podmotion/bin/podmotion-criu-wrapper"

func validateCriuWrapperArgv(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("exec_start: empty argv")
	}
	if argv[0] != criuWrapperBin {
		// Do not leak which binary is permitted; mirror SC-1-EXEC's opacity.
		return fmt.Errorf("exec_start: binary %q not permitted on the async path", argv[0])
	}
	return nil
}

// brokerCgroupPIDs returns the PIDs resident in the BROKER's own cgroup v2. The
// wrapper is spawned as a broker child, so with --manage-cgroups=ignore the
// CRIU-restored process tree lands here, not in the agent cgroup. The agent
// diffs this set (via exec_poll) against the exec_start snapshot to detect the
// new workload entrant (ADR-0128 liveness signal).
func brokerCgroupPIDs() (map[int]bool, error) {
	selfCgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, fmt.Errorf("read broker /proc/self/cgroup: %w", err)
	}
	var rel string
	for _, line := range strings.Split(string(selfCgroup), "\n") {
		// cgroup v2 unified line: "0::<path>".
		if strings.HasPrefix(line, "0::") {
			rel = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if rel == "" {
		return nil, fmt.Errorf("broker has no cgroup v2 unified entry")
	}
	procsPath := filepath.Join("/sys/fs/cgroup", rel, "cgroup.procs")
	data, err := os.ReadFile(procsPath)
	if err != nil {
		return nil, fmt.Errorf("read broker cgroup.procs (%s): %w", procsPath, err)
	}
	pids := make(map[int]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if pid, convErr := strconv.Atoi(line); convErr == nil {
			pids[pid] = true
		}
	}
	return pids, nil
}

// doExecStart spawns the CRIU restore wrapper DETACHED in the host mount
// namespace and returns its host PID. It does NOT wait — the agent polls via
// exec_poll. The pre-spawn broker-cgroup PID snapshot is recorded so exec_poll
// can return the new-entrant baseline diff context.
func doExecStart(argv []string) Response {
	if err := validateCriuWrapperArgv(argv); err != nil {
		return Response{Error: err.Error()}
	}

	// Snapshot the broker cgroup BEFORE the wrapper forks so the agent's ADR-0128
	// diff sees the restored tree as the new entrant. Best-effort: a snapshot error
	// is non-fatal (the agent's exit-code path still detects failure); record an
	// empty baseline so every later PID reads as "new".
	beforePIDs, _ := brokerCgroupPIDs()
	if beforePIDs == nil {
		beforePIDs = map[int]bool{}
	}

	cmd := nsenterHostMnt(argv...)
	stderr := &bytes.Buffer{}
	cmd.Stderr = &capWriter{buf: stderr, cap: asyncExecStderrCap}

	if err := cmd.Start(); err != nil {
		return Response{Error: fmt.Sprintf("exec_start: spawn wrapper: %v", err)}
	}
	pid := cmd.Process.Pid

	asyncExecMu.Lock()
	asyncExecReg[pid] = &asyncExecEntry{cmd: cmd, stderr: stderr, beforePIDs: beforePIDs}
	asyncExecMu.Unlock()

	return Response{WrapperPID: pid}
}

// doExecPoll reports whether the wrapper PID is still running. It performs a
// NON-BLOCKING reap: if the process has exited it Wait()s once, records the exit
// code + stderr, and reports Running:false; otherwise Running:true. Either way it
// returns the current broker-cgroup PID set (and the spawn baseline implicitly via
// the agent's own snapshot) so the agent can run the new-entrant liveness diff.
func doExecPoll(pid int) Response {
	asyncExecMu.Lock()
	entry, ok := asyncExecReg[pid]
	asyncExecMu.Unlock()
	if !ok {
		return Response{Error: fmt.Sprintf("exec_poll: unknown wrapper PID %d", pid)}
	}

	cgPIDs, _ := brokerCgroupPIDs()
	cgList := make([]int, 0, len(cgPIDs))
	for p := range cgPIDs {
		cgList = append(cgList, p)
	}

	asyncExecMu.Lock()
	defer asyncExecMu.Unlock()
	if entry.reaped {
		ec := entry.exitCode
		return Response{
			Running:    false,
			ExitCode:   &ec,
			Stderr:     entry.stderr.Bytes(),
			CgroupPIDs: cgList,
		}
	}

	// Non-blocking liveness probe: signal 0 reports whether the PID is still alive
	// without delivering a signal. The wrapper is a broker child, so once it exits
	// it is a zombie until we Wait() it — signal 0 still succeeds on a zombie, so we
	// additionally test the ProcessState after a non-blocking wait.
	if alive := processAlive(pid); alive {
		// Still running (or zombie not yet reaped). Try a non-blocking reap: if the
		// process has become a zombie, Wait returns immediately; if still running,
		// we must NOT block the broker, so we only reap when /proc shows it dead.
		if !processZombieOrDead(pid) {
			return Response{Running: true, CgroupPIDs: cgList}
		}
	}

	// Process has exited (dead or zombie) — reap it exactly once.
	waitErr := entry.cmd.Wait()
	exitCode := 0
	if entry.cmd.ProcessState != nil {
		exitCode = entry.cmd.ProcessState.ExitCode()
	} else if waitErr != nil {
		exitCode = -1
	}
	entry.reaped = true
	entry.exitCode = exitCode
	ec := exitCode
	return Response{
		Running:    false,
		ExitCode:   &ec,
		Stderr:     entry.stderr.Bytes(),
		CgroupPIDs: cgList,
	}
}

// doExecSignal delivers a signal to the wrapper PID (Abort path). It does not
// reap — the next exec_poll reaps. An unknown PID is reported as an error.
func doExecSignal(pid, signal int) Response {
	asyncExecMu.Lock()
	entry, ok := asyncExecReg[pid]
	asyncExecMu.Unlock()
	if !ok {
		return Response{Error: fmt.Sprintf("exec_signal: unknown wrapper PID %d", pid)}
	}
	sig := syscall.Signal(signal)
	if signal == 0 {
		sig = syscall.SIGKILL
	}
	if err := entry.cmd.Process.Signal(sig); err != nil {
		return Response{Error: fmt.Sprintf("exec_signal: signal %d to PID %d: %v", signal, pid, err)}
	}
	return Response{}
}

// signalPIDAllowed is the SC-1 server-side signal allowlist for the signal_pid op.
// signal_pid exists ONLY to resume/pause the CRIU-restored workload tree, so the
// broker accepts EXACTLY SIGCONT and SIGSTOP and rejects everything else loudly.
// This keeps the "signal an arbitrary PID" surface from becoming a general kill
// proxy: a compromised de-privileged agent cannot direct the unconfined broker to
// send SIGKILL/SIGTERM/etc. to any host process.
func signalPIDAllowed(signal int) bool {
	return signal == int(syscall.SIGCONT) || signal == int(syscall.SIGSTOP)
}

// procStartTime returns field 22 (starttime, clock ticks since boot) of
// /proc/<pid>/stat — the PID-reuse identity guard for signal_pid. The comm field
// (2nd) may contain spaces and parentheses, so parse from the last ')'.
func procStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(data)
	rparen := strings.LastIndex(s, ")")
	if rparen < 0 || rparen+2 >= len(s) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	// Fields after comm: state is index 0 (overall field 3); starttime is overall
	// field 22 ⇒ index 19 in the post-comm slice.
	fields := strings.Fields(s[rparen+2:])
	const startTimeIdx = 19
	if len(fields) <= startTimeIdx {
		return 0, fmt.Errorf("truncated /proc/%d/stat", pid)
	}
	return strconv.ParseUint(fields[startTimeIdx], 10, 64)
}

// doSignalPID delivers SIGCONT or SIGSTOP to an arbitrary host PID — the CRIU-
// restored workload root, which the broker did NOT spawn (so asyncExecReg is not
// consulted; syscall.Kill is used directly). The unconfined broker is not subject
// to AppArmor signal mediation, so the cross-profile resume the confined main
// agent is DENIED succeeds here (ADR-0312).
//
// SC-1 constraints:
//   (a) only SIGCONT/SIGSTOP are accepted — any other signal is a loud reject.
//   (b) PID-reuse guard: the client supplies the starttime it captured when it
//       recorded the PID; the broker re-reads /proc/<pid>/stat field 22 and
//       refuses to signal on any mismatch (the PID has been reused for an
//       unrelated process). expectedStartTime==0 is treated as "no identity
//       supplied" and rejected — we never signal without a verified identity.
func doSignalPID(pid, signal int, expectedStartTime uint64) Response {
	if pid <= 0 {
		return Response{Error: fmt.Sprintf("signal_pid: pid %d must be positive", pid)}
	}
	if !signalPIDAllowed(signal) {
		// Do not run; SC-1 hard reject (only cont/stop permitted on this surface).
		return Response{Error: fmt.Sprintf("signal_pid: signal %d not permitted (only SIGCONT/SIGSTOP)", signal)}
	}
	if expectedStartTime == 0 {
		return Response{Error: fmt.Sprintf("signal_pid: no expected starttime supplied for pid %d — refusing to signal without a PID-reuse identity", pid)}
	}
	liveStart, err := procStartTime(pid)
	if err != nil {
		return Response{Error: fmt.Sprintf("signal_pid: read starttime for pid %d (process gone?): %v", pid, err)}
	}
	if liveStart != expectedStartTime {
		return Response{Error: fmt.Sprintf("signal_pid: pid %d starttime mismatch (expected %d, live %d) — PID reused, refusing to signal", pid, expectedStartTime, liveStart)}
	}
	if err := syscall.Kill(pid, syscall.Signal(signal)); err != nil {
		return Response{Error: fmt.Sprintf("signal_pid: kill(%d, %d): %v", pid, signal, err)}
	}
	return Response{}
}

// processAlive reports whether /proc/<pid> still exists (the process has not been
// fully reaped). A zombie still has a /proc entry, so this is necessary but not
// sufficient for "running".
func processAlive(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// processZombieOrDead reports whether the process is a zombie (exited, awaiting
// reap) or already gone. It reads the State field of /proc/<pid>/stat. A 'Z'
// state (or a missing /proc entry) means the process has exited and Wait() will
// not block.
func processZombieOrDead(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true // gone
	}
	// /proc/<pid>/stat: "pid (comm) State ...". comm may contain spaces/parens, so
	// find the last ')' and read the field after it.
	s := string(data)
	close := strings.LastIndex(s, ")")
	if close < 0 || close+2 >= len(s) {
		return false
	}
	state := s[close+2]
	return state == 'Z' || state == 'X' || state == 'x'
}

// capWriter is a bounded io.Writer: it appends to buf until cap bytes, then drops
// further writes (keeping the HEAD — CRIU's earliest diagnostics are the most
// useful and arrive first). It bounds broker memory for a detached wrapper whose
// stderr the broker accumulates across the wrapper's lifetime.
type capWriter struct {
	buf *bytes.Buffer
	cap int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.buf.Len() >= w.cap {
		return len(p), nil // silently drop past the cap; report full write
	}
	room := w.cap - w.buf.Len()
	if len(p) > room {
		w.buf.Write(p[:room])
		return len(p), nil
	}
	return w.buf.Write(p)
}

// doCreate creates /run/podmotion/netns/<uid>/ and bind-mounts the selected
// netns to .../<uid>/bind in the HOST mount namespace, returning the bind path.
//
// All host-mount-ns mutations (mkdir, touch, bind) are performed by nsenter
// subprocesses entering /proc/1/ns/mnt — single-threaded children that may call
// setns(CLONE_NEWNS), which an in-process multithreaded Go goroutine may not.
//
// Idempotent: if the bind path is already an nsfs mount, it is returned as-is.
func doCreate(migrationUID string, srcPID int) (string, error) {
	if err := validateUID(migrationUID); err != nil {
		return "", err
	}
	if err := validateSrcPID(srcPID); err != nil {
		return "", err
	}

	bindPath := netnsPathFor(migrationUID)
	dir := filepath.Dir(bindPath)

	// Idempotency fast-path: if the bind target is already a live nsfs mount in the
	// HOST mount namespace, the netns is already prepared — reuse it. Reads host
	// init's mountinfo (hostPID:true), which reflects the namespace nsenter binds into.
	if isNsfsMounted(bindPath) {
		return bindPath, nil
	}

	// Create the per-migration dir + bind target file in the HOST mount namespace.
	// These must exist host-side for the subsequent host-ns bind; os.MkdirAll here
	// would create them only in the broker container's private mount namespace, so
	// we create them via nsenter in the host mount namespace (matches the prior
	// createBindMountedNetns mkdir/touch chain).
	if out, err := nsenterHostMnt("mkdir", "-p", dir).CombinedOutput(); err != nil {
		return "", fmt.Errorf("mkdir %s in host mount ns: %w\n%s", dir, err, out)
	}
	if out, err := nsenterHostMnt("sh", "-c",
		fmt.Sprintf("[ -e %q ] || touch %q", bindPath, bindPath),
	).CombinedOutput(); err != nil {
		return "", fmt.Errorf("create bind target %s in host mount ns: %w\n%s", bindPath, err, out)
	}

	if srcPID > 0 {
		// Bind an EXISTING pod netns: /proc/<srcPID>/ns/net -> bindPath, in host mount ns.
		srcNs := fmt.Sprintf("/proc/%d/ns/net", srcPID)
		if err := bindInHostMountNs(srcNs, bindPath); err != nil {
			return "", fmt.Errorf("bind srcPID %d netns: %w", srcPID, err)
		}
		return bindPath, nil
	}

	// Fresh-unshare path (destination prewarm): on a locked OS thread, unshare a
	// new network namespace and bind THAT thread's /proc/<tid>/ns/net into the
	// host mount namespace. Mirrors the prior createBindMountedNetns goroutine.
	if err := unshareAndBind(bindPath); err != nil {
		return "", err
	}
	return bindPath, nil
}

// doTeardown unmounts and removes /run/podmotion/netns/<uid>/. "Not mounted" /
// absent is treated as success (idempotent). The unmount and removals run in the
// HOST mount namespace via nsenter because the bind-mount and bind-target file
// were created there by doCreate.
func doTeardown(migrationUID string) error {
	if err := validateUID(migrationUID); err != nil {
		return err
	}
	bindPath := netnsPathFor(migrationUID)
	dir := filepath.Dir(bindPath)

	// Lazy detach unmount in the host mount namespace — tolerate "not mounted".
	if out, err := nsenterHostMnt("umount", "-l", bindPath).CombinedOutput(); err != nil {
		if !isNotMountedOutput(out) {
			return fmt.Errorf("unmount %s in host mount ns: %w\n%s", bindPath, err, out)
		}
	}
	// Remove the bind-target file in the host mount namespace.
	if out, err := nsenterHostMnt("rm", "-f", bindPath).CombinedOutput(); err != nil {
		return fmt.Errorf("remove %s in host mount ns: %w\n%s", bindPath, err, out)
	}
	// Remove the now-empty per-migration dir in the host mount namespace.
	// `rmdir` on a non-empty dir is non-fatal (idempotent teardown).
	if out, err := nsenterHostMnt("rmdir", dir).CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "not empty") &&
			!strings.Contains(string(out), "No such file") {
			return fmt.Errorf("remove dir %s in host mount ns: %w\n%s", dir, err, out)
		}
	}
	return nil
}

// unshareAndBind runs on a dedicated locked OS thread: it saves the current
// netns, unshares CLONE_NEWNET (creating a fresh netns on this thread), binds
// the thread's netns into the host mount namespace via nsenter, then restores.
// The thread is intentionally NOT unlocked so the Go runtime recycles it rather
// than returning a thread with a swapped netns to the pool.
//
// NOTE: unshare(CLONE_NEWNET) is performed in-process here on purpose — it is
// NOT subject to the multithreaded-process restriction that forbids in-process
// setns(CLONE_NEWNS). Only the host-mount-ns BIND is delegated to nsenter.
func unshareAndBind(bindPath string) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// not unlocked on purpose — see doc comment.

		origNS, err := os.Open("/proc/self/ns/net")
		if err != nil {
			done <- fmt.Errorf("open current netns: %w", err)
			return
		}
		defer origNS.Close()

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("unshare CLONE_NEWNET: %w", err)
			return
		}

		tid := unix.Gettid()
		threadNetns := fmt.Sprintf("/proc/%d/ns/net", tid)

		if err := bindInHostMountNs(threadNetns, bindPath); err != nil {
			_ = unix.Setns(int(origNS.Fd()), unix.CLONE_NEWNET)
			done <- err
			return
		}

		if err := unix.Setns(int(origNS.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("restore original netns: %w", err)
			return
		}
		done <- nil
	}()
	return <-done
}

// bindInHostMountNs performs `mount --bind src target` inside the HOST mount
// namespace via an nsenter subprocess (`nsenter --mount=/proc/1/ns/mnt -- mount
// --bind src target`). nsenter forks a single-threaded child that may legally
// call setns(CLONE_NEWNS) — an in-process Go goroutine may not (EINVAL from a
// multithreaded process even under privileged:true / CAP_SYS_ADMIN).
//
// IMPORTANT: the src path (e.g. /proc/<tid>/ns/net) is resolved by nsenter's
// child AFTER it has joined the host mount namespace. /proc is the same procfs
// across the host mount ns on a hostPID:true pod, so /proc/<tid>/ns/net and
// /proc/<srcPID>/ns/net resolve to the intended netns from the host mount ns.
func bindInHostMountNs(src, target string) error {
	if out, err := nsenterHostMnt("mount", "--bind", src, target).CombinedOutput(); err != nil {
		return fmt.Errorf("bind mount %s -> %s in host mount ns: %w\n%s", src, target, err, out)
	}
	return nil
}

// nsenterHostMnt builds an *exec.Cmd that runs `nsenter --mount=/proc/1/ns/mnt --
// <args...>` — the command executes in the HOST mount namespace as a fresh
// single-threaded process. This is the syscall-free replacement for the prior
// in-process unix.Setns(CLONE_NEWNS) host-mount-ns entry, which returns EINVAL
// from the multithreaded Go runtime regardless of CAP_SYS_ADMIN.
func nsenterHostMnt(args ...string) *exec.Cmd {
	full := append([]string{hostMountNsArg, "--"}, args...)
	return exec.Command("nsenter", full...)
}

// isNotMountedOutput reports whether umount's stderr indicates the target was
// not a mount point (idempotent teardown success). umount(8) phrasing varies by
// util-linux version: "not mounted", "not currently mounted", "not found".
func isNotMountedOutput(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "not mounted") ||
		strings.Contains(s, "not currently mounted") ||
		strings.Contains(s, "not found") ||
		strings.Contains(s, "No such file")
}

// isNsfsMounted reports whether path is a live nsfs (network-namespace) bind
// mount in the HOST mount namespace. Reads /proc/1/mountinfo (host init's
// mountinfo, visible with hostPID:true) so the binds nsenter creates in the host
// mount namespace are visible — the broker container's own /proc/self/mountinfo
// would not show them.
func isNsfsMounted(path string) bool {
	data, err := os.ReadFile(hostMountInfo)
	if err != nil {
		// Fall back to self mountinfo if host mountinfo is inaccessible.
		data, err = os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			return false
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[4] != path {
			continue
		}
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep >= 0 && sep+1 < len(fields) && fields[sep+1] == "nsfs" {
			return true
		}
	}
	return false
}

// decode/encode helpers shared by the listener.

func decodeRequest(b []byte) (Request, error) {
	var req Request
	if err := json.Unmarshal(b, &req); err != nil {
		return Request{}, err
	}
	return req, nil
}

func encodeResponse(resp Response) ([]byte, error) {
	return json.Marshal(resp)
}
