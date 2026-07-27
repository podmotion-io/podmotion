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

// ADR-0346 D4: netnsPathRe is the SR-4 containment gate for the netns_exec*/
// NetnsPath client-supplied-path case (srcPID <= 0). It enforces properties
// (a) and (c); property (b) — traversal/proc rejection — and (d) — symlink-safe
// leaf resolution — are NOT expressible in a regex and are enforced in
// validateNetnsPath below.
//
// (a) fully anchored: ^...$
// (b) traversal/proc rejection is enforced in validateNetnsPath, NOT here — a
//     single regex expressing "no .. segment anywhere" is brittle (D4).
// (c) scoped to /run/netns/<name> or /var/run/netns/<name>, <name> a single
//     bounded metacharacter-free component.
var netnsPathRe = regexp.MustCompile(`^(?:/run/netns|/var/run/netns)/[A-Za-z0-9_.-]{1,64}$`)

// containerIDRe validates the holder_sentinel op's ContainerID. containerd/CRI
// container IDs are lowercase hex; accept the general alphanumeric container-token
// shape (bounded length, no path/traversal characters) since the value is used
// only as a substring to match against /proc/<pid>/cgroup content — never as a
// filesystem path (the sentinel path is fixed server-side).
var containerIDRe = regexp.MustCompile(`^[a-zA-Z0-9]{8,128}$`)

// validateNetnsPath enforces all four SR-4 properties (ADR-0346 D4 a-d) on a
// client-supplied NetnsPath (the srcPID<=0 branch only). It is the sole gate
// before netnsPath reaches any nsenter --net= invocation.
func validateNetnsPath(netnsPath string) error {
	if netnsPath == "" {
		return fmt.Errorf("netnsPath is required when srcPID <= 0")
	}
	// (b) traversal/proc rejection: Clean must be a no-op (nothing collapsed
	// away) and the cleaned value must not contain /proc/.
	cleaned := filepath.Clean(netnsPath)
	if cleaned != netnsPath {
		return fmt.Errorf("netnsPath %q is not clean (traversal?)", netnsPath)
	}
	if strings.Contains(cleaned, "/proc/") {
		return fmt.Errorf("netnsPath %q must not reference /proc", netnsPath)
	}
	// (a) anchored + (c) scoped bounded name.
	if !netnsPathRe.MatchString(cleaned) {
		return fmt.Errorf("netnsPath %q does not match the /run/netns|/var/run/netns bind-mount convention", netnsPath)
	}
	// (d) symlink-safe resolved leaf: resolve and assert the result is still
	// lexically under one of the two allowed roots.
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return fmt.Errorf("netnsPath %q: resolve: %w", netnsPath, err)
	}
	if !strings.HasPrefix(resolved, "/run/netns/") && !strings.HasPrefix(resolved, "/var/run/netns/") {
		return fmt.Errorf("netnsPath %q resolves to %q, outside the netns bind-mount scope", netnsPath, resolved)
	}
	return nil
}

// Request is the JSON wire request accepted on the broker socket.
type Request struct {
	Op string `json:"op"` // "create" | "teardown" | "exec" | "exec_start" | "exec_poll" | "exec_signal" | "signal_pid" | "kill_source_pid" | "proc_alive" | "resolve_veth" | "holder_sentinel" | "netns_exec" | "netns_exec_start" | "move_cgroup" | "netns_match"
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

	// ADR-0326: netns_exec / netns_exec_start generalize the broker's pre-existing
	// nsenterNetNs helper (previously used only by doResolveVeth's hardcoded
	// `ip -o link show eth0`) into a general in-pod-netns exec, closing the twelve
	// AppArmor-denied direct-agent `nsenter --net=` call sites on the confined
	// restore-path agent (server.go). Reuses the Argv field above with op-scoped
	// semantics (SC-1-EXEC): argv[0] must be exactly "ip" or the broker's own
	// os.Executable()-pinned self path — the broker NEVER execs a client-supplied
	// path, only its own re-resolved one (see netnsExecSelfPath / doNetnsExec).
	//
	// The target netns is selected exactly like doResolveVeth/doCreate: SrcPID > 0
	// selects /proc/<SrcPID>/ns/net (validated by the existing validateSrcPID
	// liveness check, reused unchanged). NetnsPath is a narrow ADR-0326
	// implementation-time addition beyond ADR-0323's original text: some call
	// sites (ReadReplVethMAC) resolve a stable CNI bind-mount netns path (e.g.
	// /var/run/netns/cni-<id>) rather than a live PID (ADR-0325 UNIVERSAL
	// POD-NETNS INTEGRATION) — SrcPID cannot express that. When SrcPID <= 0,
	// NetnsPath is validated against netnsPathRe (a closed, traversal-safe
	// pattern matching only the /var/run/netns|/run/netns bind-mount convention)
	// before being used verbatim as the nsenter --net= target. SrcPID takes
	// precedence when both are supplied.
	NetnsPath string `json:"netnsPath,omitempty"`

	// ExpectedNetnsPath (netns_match op) is the netns bind-mount path the caller
	// expects SignalPID's network namespace to be a member of — the ADR-0306 item
	// (a) restart-durable identity cross-check on the Restore idempotent-confirm
	// path (server.go's pidNetnsMatchesPath). The de-privileged SD-1 agent cannot
	// stat /proc/<SignalPID>/ns/net itself: that crosses a ptrace_may_access gate
	// AppArmor mediates against the TARGET's peer profile — for the CRIU-restored
	// workload root that is the container runtime's default profile, which the
	// narrow `podmotion-agent` profile's ptrace(read) grants (peer=podmotion-agent,
	// peer=unconfined) do not cover — the same delegation class as proc_alive/
	// resolve_veth/holder_sentinel above (see their doc comments for the incident
	// history this pattern exists to avoid). The unconfined broker performs BOTH
	// stats (SignalPID's /proc/<pid>/ns/net and this path) and the inode/dev
	// compare itself, returning only the boolean Match — never raw stat data — so
	// no additional client-side trust is required. Validated by netnsPathRe (the
	// same closed, traversal-safe /run/netns|/var/run/netns convention netns_exec's
	// NetnsPath already enforces) — ADR-0325 documents sandboxNetnsPath as always
	// producing exactly this bind-mount shape, so no legitimate caller needs a
	// wider pattern. A separate field from NetnsPath rather than reusing it: NetnsPath
	// selects the namespace an op executes IN (netns_exec/netns_exec_start); this
	// field is a value to COMPARE against, a distinct role worth keeping visually
	// distinct on the wire even though both are validated identically.
	ExpectedNetnsPath string `json:"expectedNetnsPath,omitempty"`

	// ContainerID (holder_sentinel op) is the containerd container ID of the
	// replacement pod's restore-target (holder-running) container. The de-privileged
	// SD-1 agent cannot itself observe the holder-ready sentinel: reading it means
	// dereferencing /proc/<holderPID>/root/run/podmotion/holder-ready, and opening
	// another container's /proc/<pid>/root routes through a ptrace_may_access gate
	// that the narrow `podmotion-agent` AppArmor profile denies (it permits
	// ptrace-read only against peer=unconfined; the holder runs under
	// cri-containerd.apparmor.d) — the exact `apparmor DENIED operation="ptrace"`
	// signature (identical class to resolve_veth/signal_pid). The unconfined,
	// hostPID broker resolves the holder init PID from this container ID (a plain
	// /proc/<pid>/cgroup substring scan — not ptrace-gated) and stats the sentinel
	// at a FIXED server-side relative path, so a client never supplies a filesystem
	// path (no traversal surface). Validated by containerIDRe.
	ContainerID string `json:"containerID,omitempty"`

	// ADR-0351 D2 (move_cgroup op, sprint53-kind): CgroupPath is a cgroupFsRoot
	// ("/sys/fs/cgroup")-RELATIVE leaf path (already resolved + path-confined by the
	// agent's resolveCgroupAnchorTarget — the broker re-validates independently below,
	// never trusts the client's confinement alone) that SignalPID's whole thread
	// group should be moved into via a cgroup.procs write. Reuses SignalPID +
	// ExpectedStartTime for the target PID / PID-reuse guard, exactly like
	// signal_pid/kill_source_pid/proc_alive above — this is a fourth op on that same
	// "arbitrary host PID the broker never spawned" surface, not a new PID field.
	//
	// Why this must run in the broker and not the de-privileged main agent: a
	// cgroup v2 cgroup.procs write is permitted only when the target cgroup is a
	// descendant of the WRITER's own cgroup namespace root (kernel-enforced,
	// independent of DAC/mount visibility). The SD-1 main agent (privileged:false)
	// gets a fresh, path-less cgroup namespace from containerd's default CRI mount-
	// merge/namespace behavior, rooted at the agent's OWN container scope — a
	// sibling of, not an ancestor of, the target pod's kubepods cgroup, so the
	// kernel refuses the write with ENOENT regardless of the mount-visibility fix
	// (charts/podmotion/templates/daemonset.yaml, commit c425b7e) that made the
	// PATH readable. The unconfined netns-broker (privileged:true, the SOLE
	// privileged:true container in the pod) is not cgroup-namespace-isolated from
	// the host by containerd's same default behavior (verified live, sprint53-kind:
	// its pre-existing "cat" exec-allowlist entry already depends on this same
	// property to resolve host-absolute /proc/<pid>/cgroup paths — see execAllowlist
	// doc comment above), so its cgroup namespace root is the host root and the
	// target pod cgroup is always a descendant. No nsenter is needed for the write
	// itself (unlike the host-MOUNT-namespace "exec" op) — cgroup namespace, not
	// mount namespace, is what gates this operation, and the broker's own process
	// already sits in the host cgroup namespace.
	CgroupPath string `json:"cgroupPath,omitempty"`

	// ExpectedPodUID is the destination pod UID the caller (server.go) extracted
	// from the SAME trusted NRI-carried input (containerCgroupsPath) that produced
	// CgroupPath, BEFORE any symlink resolution. Required on move_cgroup. The
	// broker independently re-checks that the resolved CgroupPath still contains
	// this UID (see cgroupPathContainsPodUID) — on every other platform, a
	// de-privileged agent's own private cgroup namespace makes it kernel-
	// impossible to reach a DIFFERENT pod's cgroup even given a wrong/attacker-
	// influenced path; the broker has no such backstop (it is deliberately
	// host-cgroup-namespace-rooted — see CgroupPath's doc comment above), so this
	// check is what keeps move_cgroup's blast radius equivalent to "this one
	// migration's own destination pod" rather than "any pod under the shared
	// kubepods root" (Chad, 2026-07-19: kind's posture must stay uniform with the
	// other platforms', not merely code-identical to them).
	ExpectedPodUID string `json:"expectedPodUID,omitempty"`
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

	// Found (holder_sentinel op only): true when the holder-ready sentinel exists
	// inside the resolved holder container's root (the holder has parked and
	// signalled quiescence). false is a valid, non-error negative — the barrier
	// keeps polling — and is reported with Error=="". A broker-side failure
	// (unresolvable container ID validation, etc.) sets Error instead.
	Found bool `json:"found,omitempty"`

	// Alive (proc_alive op only): true when the target PID is present under
	// /proc and NOT a zombie/dead task. A false reading is a genuine "the
	// process is gone or a zombie", never a permission artifact — see doProcAlive.
	Alive bool `json:"alive,omitempty"`
	// StartTime (proc_alive op only): field 22 of /proc/<pid>/stat at the moment
	// of this check, returned so the CALLER can capture it as the ExpectedStartTime
	// for a later re-check (PID-reuse guard), mirroring signal_pid's own guard.
	StartTime uint64 `json:"startTime,omitempty"`

	// Match (netns_match op only): true only when SignalPID's /proc/<pid>/ns/net
	// inode/dev genuinely matches a stat of ExpectedNetnsPath. Any stat failure on
	// either side (target gone, path unresolvable) is reported via Error instead,
	// never a silent Match:false — the caller's identity check must fail closed on
	// "could not verify," not conflate it with "verified and different" (mirrors
	// pidNetnsMatchesPath's original (bool, error) contract on the agent side).
	Match bool `json:"match,omitempty"`
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

// ADR-0346 D3/D5: netnsExecSelfToken is the fixed sentinel a client sends to
// request the self allowlist entry. It is NEVER a live path — this is what
// makes the self entry match regardless of agent-vs-broker os.Executable()/
// symlink skew, or the /proc/self/exe fallback a caller uses when
// os.Executable() errors. It is the package-internal spelling of the exported
// wire-contract constant NetnsExecSelfToken (types.go); both name ONE literal so
// the broker allowlist and every cross-package client (internal/agent/server)
// cannot drift (a single source of truth).
const netnsExecSelfToken = NetnsExecSelfToken

var (
	netnsExecSelfPathOnce sync.Once
	netnsExecSelfPathVal  string
	netnsExecSelfPathErr  error
)

// netnsExecSelfPath resolves the broker's own binary path exactly once
// (os.Executable() then EvalSymlinks), pinning it for both Serve() and direct
// Handle() calls in unit tests (ADR-0346 D5). Same "resolve once at startup"
// primitive the absolute-pinning scope item applies to nsenter/ip.
func netnsExecSelfPath() (string, error) {
	netnsExecSelfPathOnce.Do(func() {
		p, err := os.Executable()
		if err != nil {
			netnsExecSelfPathErr = fmt.Errorf("netnsExecSelfPath: os.Executable: %w", err)
			return
		}
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			netnsExecSelfPathErr = fmt.Errorf("netnsExecSelfPath: EvalSymlinks(%q): %w", p, err)
			return
		}
		netnsExecSelfPathVal = resolved
	})
	return netnsExecSelfPathVal, netnsExecSelfPathErr
}

// ADR-0347 A1: pinnedNsenter/pinnedIP are the broker's own nsenter/ip binary
// paths, each resolved to an absolute path exactly ONCE (sync.Once, the same
// resolve-once-at-startup primitive netnsExecSelfPath uses above) from the
// broker's trusted startup PATH via exec.LookPath. This is a source-of-truth
// primitive, not a per-call chain: PATH is consulted once, before any client
// request can influence anything, and is never re-asked per call. A resolution
// failure is fail-CLOSED at the point of use — the site that needs the binary
// returns that error and NO bare "nsenter"/"ip" is ever execed (ADR-0347 A1's
// load-bearing security property: no silent bare-name PATH-shadow fallback).
//
// SR-DEP (Security Reviewer, sprint46 surgical fix): nsenter and ip are pinned
// by SEPARATE sync.Once resolvers because they sit on DIFFERENT op classes with
// different criticality. nsenter is required by EVERY broker op (host-mount-ns
// bind/teardown, the host-mount-ns `exec` set, and the CRIU-restore wrapper
// launch via exec_start) — a broker that cannot resolve nsenter cannot do its
// irreducible, safety-critical job, so it fails loud at startup. ip is used
// ONLY by the reachability/IP-config ops (resolve_veth, and netns_exec* with
// argv[0]=="ip"), ALL of which already fail CLOSED on an unresolvable ip
// (ADR-0348 D4) — ip is NOT on the bind/teardown/CRIU-restore path. Coupling
// both pins into one resolver made an unresolvable ip crash-loop the WHOLE
// privileged broker, taking down the ip-free restore/teardown/rollback path
// (including the ADR-0012 source-survival rollback) with it — an over-broad
// runtime dependency and an unbounded blast radius for a non-safety binary.
// Split so each site depends on exactly the binary it execs.
var (
	pinNsenterOnce sync.Once
	pinnedNsenter  string
	pinNsenterErr  error

	pinIPOnce sync.Once
	pinnedIP  string
	pinIPErr  error
)

// resolvePinnedNsenter pins nsenter to an absolute path exactly once. Called by
// every nsenter-spawning site (nsenterHostMnt / nsenterNetNs / nsenterNetNsPath)
// and by Serve() at startup (fail-loud — nsenter is required by every op class).
func resolvePinnedNsenter() error {
	pinNsenterOnce.Do(func() {
		p, err := exec.LookPath("nsenter")
		if err != nil {
			pinNsenterErr = fmt.Errorf("resolve nsenter at broker startup: %w", err)
			return
		}
		pinnedNsenter = p
	})
	return pinNsenterErr
}

// resolvePinnedIP pins ip to an absolute path exactly once. Called by the
// ip-consuming reachability sites (resolveNetnsExecBinary "ip" case, doResolveVeth)
// and best-effort by Serve() at startup. An unresolvable ip is fail-CLOSED at
// these sites (ADR-0348 D4), never a bare-name exec, and never blocks the
// ip-free host-mount-ns / CRIU-restore path (SR-DEP).
func resolvePinnedIP() error {
	pinIPOnce.Do(func() {
		p, err := exec.LookPath("ip")
		if err != nil {
			pinIPErr = fmt.Errorf("resolve ip at broker startup: %w", err)
			return
		}
		pinnedIP = p
	})
	return pinIPErr
}

// resolvePinnedBinaries resolves BOTH pins. Retained as the single entry point
// for the ADR-0347 discharge tests (which assert both are pinned once) and any
// caller that needs both; it returns the first resolution error. Per-op sites
// use the narrow resolver for the one binary they exec (SR-DEP).
func resolvePinnedBinaries() error {
	if err := resolvePinnedNsenter(); err != nil {
		return err
	}
	return resolvePinnedIP()
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
	case "kill_source_pid":
		// ADR-0356: terminate a source-tree PID the broker never spawned. Deliberately
		// a SEPARATE op from signal_pid rather than widening its SC-1 SIGCONT/SIGSTOP
		// allowlist to include SIGKILL — that allowlist exists specifically to keep
		// signal_pid from becoming a general kill proxy for a compromised de-privileged
		// agent (see signalPIDAllowed's doc comment). This op sends EXACTLY SIGKILL,
		// hardcoded server-side — the client cannot select a signal at all, only invoke
		// "terminate this PID-reuse-identified process" — so it adds no new "signal an
		// arbitrary PID with an arbitrary signal" surface. Same PID-reuse (starttime)
		// guard as signal_pid.
		return doKillSourcePID(req.SignalPID, req.ExpectedStartTime)
	case "proc_alive":
		// Report liveness of a PID the broker never spawned (the CRIU-restored
		// workload root) without delivering any signal. See doProcAlive for why
		// this cannot be done in-process by the de-privileged agent.
		return doProcAlive(req.SignalPID, req.ExpectedStartTime)
	case "resolve_veth":
		// Enter the pod's NET namespace and read eth0's veth peer ifindex on the
		// de-privileged agent's behalf (the agent's AppArmor profile denies the
		// ptrace-read needed to open another pod's /proc/<pid>/ns/net).
		return doResolveVeth(req.SrcPID)
	case "holder_sentinel":
		// Observe the holder-quiescent sentinel inside the restore-target
		// container's root on the de-privileged agent's behalf: the agent's
		// AppArmor profile denies the ptrace-read needed to dereference another
		// container's /proc/<pid>/root (the exact same class as resolve_veth).
		return doHolderSentinel(req.ContainerID)
	case "netns_exec":
		// ADR-0326: run an allowlisted ("ip" or the broker's own pinned self path)
		// command inside the target pod's NET namespace, run-to-completion.
		return doNetnsExec(req.SrcPID, req.NetnsPath, req.Argv)
	case "move_cgroup":
		// ADR-0351 D2 (sprint53-kind): move an already-restored PID's whole thread
		// group into its container's own cgroup v2 scope. See CgroupPath's doc
		// comment on Request for why this must be a broker op.
		return doMoveCgroup(req.SignalPID, req.CgroupPath, req.ExpectedStartTime, req.ExpectedPodUID)
	case "netns_exec_start":
		// ADR-0326: spawn an allowlisted command inside the target pod's NET
		// namespace DETACHED (the __inetns_echo listener, which must outlive the
		// originating RPC). Reuses the same asyncExecReg/exec_poll/exec_signal
		// machinery as the host-mount-ns exec_start path — that registry is keyed
		// generically on the spawned PID, not on which op launched it, so
		// exec_poll/exec_signal already reap/signal netns_exec_start children
		// exactly as they do exec_start children (ADR-0326 Decision item 4).
		return doNetnsExecStart(req.SrcPID, req.NetnsPath, req.Argv)
	case "netns_match":
		// ADR-0306 item (a) delegation (round 2, replacing the withdrawn AppArmor
		// profile-widening approach): stat SignalPID's /proc/<pid>/ns/net and
		// ExpectedNetnsPath in the unconfined broker and report whether they
		// identify the same netns — see ExpectedNetnsPath's doc comment on Request.
		return doNetnsMatch(req.SignalPID, req.ExpectedNetnsPath)
	default:
		return toResponse("", fmt.Errorf("unknown op %q (want create|teardown|exec|exec_start|exec_poll|exec_signal|signal_pid|kill_source_pid|proc_alive|resolve_veth|holder_sentinel|netns_exec|netns_exec_start|move_cgroup|netns_match)", req.Op))
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
//
// Adding a new restore-path host-mount-ns command requires adding it here AND a
// a runtime-dependency assertion (the binary must exist on the node) — same
// discipline as any other ADR runtime-dependency (see ADR-0231).
//
// FOLLOW-ON: a cleaner primitive would be a DEDICATED broker op that reads
// /proc/self/mountinfo directly (mirroring the existing signal_pid dedicated op),
// avoiding a general-shell exec on the restore path entirely.
var execAllowlist = map[string]struct{}{
	"ctr":                {},
	"/usr/local/bin/ctr": {},
	"/opt/podmotion/bin/podmotion-criu-wrapper": {},
	"mkdir":   {},
	"touch":   {},
	"rm":      {},
	"mount":   {},
	"umount":  {},
	"sh":      {},
	"/bin/sh": {},
	"ls":      {},
	// ADR-0128: cat /proc/<pausePID>/cgroup — resolve the pod sandbox's host-ABSOLUTE
	// cgroup v2 path in the broker's HOST cgroup namespace (the de-privileged agent's
	// own cgroupns renders /proc/<pid>/cgroup relative, stripping the kubepods ancestry
	// and yielding a "../.." path that fails the cgroup.procs move with ENOENT).
	"cat":      {},
	"/bin/cat": {},
}

// ADR-0346 D3: netnsExecAllowlist is the SC-1-EXEC allowlist for
// netns_exec/netns_exec_start. It is DISTINCT from execAllowlist (host-mount-ns
// "exec" op, above) — do not merge them; that would silently widen both
// surfaces (ADR-0346 Context 3). Exactly two client-facing match keys:
//   - "ip"               — resolves to the ip binary in the target netns.
//   - netnsExecSelfToken — resolves to netnsExecSelfPath() (D5), the broker's
//                          own pinned binary, for __inetns_probe/__inetns_echo.
//
// Matching is exact string equality against Argv[0] (map-key lookup) — never
// prefix, never substring. The EXECUTED argv[0] is always the broker-resolved
// value, never the client-transmitted string (D3).
var netnsExecAllowlist = map[string]struct{}{
	"ip":               {},
	netnsExecSelfToken: {},
}

// resolveNetnsExecBinary maps a validated netnsExecAllowlist key to the
// broker-side binary it actually executes (ADR-0346 D3). Call ONLY after
// confirming the key is present in netnsExecAllowlist.
func resolveNetnsExecBinary(key string) (string, error) {
	switch key {
	case "ip":
		// ADR-0347 A2: return the pinned absolute ip path, never the bare "ip"
		// string — the EXECUTED argv[0] is always broker-resolved (D3), and the
		// pin removes the per-call PATH re-resolution surface (ADR-0347 A1).
		// SR-DEP: only the ip pin is needed here (not nsenter).
		if err := resolvePinnedIP(); err != nil {
			return "", fmt.Errorf("resolveNetnsExecBinary: %w", err)
		}
		return pinnedIP, nil
	case netnsExecSelfToken:
		return netnsExecSelfPath()
	default:
		// Unreachable if callers gate on netnsExecAllowlist first.
		return "", fmt.Errorf("resolveNetnsExecBinary: key %q not in netnsExecAllowlist", key)
	}
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

	cmd, err := nsenterHostMnt(argv...)
	if err != nil {
		return Response{Error: fmt.Sprintf("exec: %v", err)}
	}
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

	// ADR-0347 A2: resolve the pin first so pinnedIP is populated, then pass the
	// pinned absolute path as the inner argv[0] — never the bare "ip" string
	// (a bare name would be PATH-searched by nsenter when it exec's its child).
	// SR-DEP: the inner binary is ip; nsenterNetNs resolves the outer nsenter pin.
	if err := resolvePinnedIP(); err != nil {
		return Response{Error: fmt.Sprintf("resolve_veth: %v", err)}
	}
	cmd, err := nsenterNetNs(srcPID, pinnedIP, "-o", "link", "show", "eth0")
	if err != nil {
		return Response{Error: fmt.Sprintf("resolve_veth: %v", err)}
	}
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

// holderReadySentinelRelPath is the FIXED, server-pinned relative path (under the
// resolved container's root) of the holder-quiescent sentinel written by
// cmd/holder (/run/podmotion/holder-ready). It is a constant so a client never
// supplies any part of the privileged read path — the only client-supplied value
// is the container ID, matched as a substring against /proc/<pid>/cgroup.
const holderReadySentinelRelPath = "run/podmotion/holder-ready"

// doHolderSentinel resolves the restore-target container's holder init PID from
// the supplied container ID and reports whether the holder-ready sentinel exists
// inside that container's root. It runs the whole /proc-crossing observation in
// the unconfined broker because the confined `podmotion-agent` profile denies the
// ptrace-read that dereferencing /proc/<pid>/root requires (see the ContainerID
// field doc + resolve_veth/signal_pid for the identical delegation class).
//
// A missing sentinel — OR a not-yet-resolvable container PID — is a valid negative
// (Found:false, Error:""), not a failure: the barrier polls until the holder parks
// or its own deadline fires. Error is set only on a malformed container ID.
func doHolderSentinel(containerID string) Response {
	if !containerIDRe.MatchString(containerID) {
		return Response{Error: fmt.Sprintf("holder_sentinel: containerID %q is not a valid container token", containerID)}
	}
	pid := findContainerInitPIDByCgroup(containerID)
	if pid <= 0 {
		// Container process not visible yet (StartContainer fired, entrypoint not
		// forked, or the cgroup entry not populated). Keep polling.
		return Response{Found: false}
	}
	sentinelPath := fmt.Sprintf("/proc/%d/root/%s", pid, holderReadySentinelRelPath)
	if _, err := os.Stat(sentinelPath); err == nil {
		return Response{Found: true}
	}
	return Response{Found: false}
}

// findContainerInitPIDByCgroup scans /proc for a process whose cgroup membership
// contains containerID and returns its PID (0 if none). Reading /proc/<pid>/cgroup
// is a plain procfs read (NOT ptrace-mediated), so it succeeds even under the
// confined agent — but it is done here so the resolve + the ptrace-gated
// /proc/<pid>/root stat that follows both live in the one unconfined process. The
// broker is hostPID:true, so /proc enumerates every host process; a cgroup-ns
// relativized path still contains the full cri-containerd-<id>.scope leaf, so the
// substring match holds.
func findContainerInitPIDByCgroup(containerID string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := 0
		for _, c := range e.Name() {
			if c < '0' || c > '9' {
				pid = -1
				break
			}
			pid = pid*10 + int(c-'0')
		}
		if pid <= 0 {
			continue
		}
		cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			continue
		}
		if strings.Contains(string(cgroupData), containerID) {
			return pid
		}
	}
	return 0
}

// nsenterNetNs builds an *exec.Cmd that runs `nsenter --net=/proc/<pid>/ns/net --
// <args...>` — the command executes in the target pod's NETWORK namespace. Unlike
// nsenterHostMnt (host mount ns), this enters a pod netns; opening /proc/<pid>/ns/net
// is permitted here because the broker is unconfined (no AppArmor ptrace mediation).
//
// ADR-0347 A2: the outer program is pinnedNsenter (an absolute path resolved
// exactly once at broker startup), never the bare name "nsenter" — a bare
// name would re-resolve against the process PATH, a client-influenceable
// surface, on every call.
func nsenterNetNs(pid int, args ...string) (*exec.Cmd, error) {
	if err := resolvePinnedNsenter(); err != nil { // SR-DEP: outer program is nsenter
		return nil, err
	}
	netNsArg := fmt.Sprintf("--net=/proc/%d/ns/net", pid)
	full := append([]string{netNsArg, "--"}, args...)
	return exec.Command(pinnedNsenter, full...), nil
}

// resolveNetnsExecTarget implements ADR-0346 D2's single source of truth:
// srcPID takes precedence when > 0 (validated via the EXISTING validateSrcPID,
// unchanged); only when srcPID <= 0 is netnsPath consulted, gated by
// validateNetnsPath (D4). Never both; never a fallback chain between them.
func resolveNetnsExecTarget(srcPID int, netnsPath string) (nsArg string, err error) {
	if srcPID > 0 {
		if err := validateSrcPID(srcPID); err != nil {
			return "", err
		}
		return fmt.Sprintf("/proc/%d/ns/net", srcPID), nil
	}
	if err := validateNetnsPath(netnsPath); err != nil {
		return "", err
	}
	return netnsPath, nil
}

// nsenterNetNsPath is nsenterNetNs generalized to an arbitrary --net= target (a
// /proc/<pid>/ns/net string OR a validated /run/netns|/var/run/netns bind
// path) instead of only a PID. nsenterNetNs (PID-only) stays unchanged and is
// still used by doResolveVeth.
//
// ADR-0347 A2: outer program is pinnedNsenter, never the bare "nsenter" name.
func nsenterNetNsPath(netnsTarget string, args ...string) (*exec.Cmd, error) {
	if err := resolvePinnedNsenter(); err != nil { // SR-DEP: outer program is nsenter
		return nil, err
	}
	netNsArg := "--net=" + netnsTarget
	full := append([]string{netNsArg, "--"}, args...)
	return exec.Command(pinnedNsenter, full...), nil
}

// doNetnsExec runs an allowlisted (ADR-0346 D3) command inside the target
// pod's NET namespace (D2 target selection), run-to-completion. Mirrors
// doResolveVeth's body shape: a non-zero exit is reported via
// ExitCode/Stderr, NOT a broker Error. Argv[0] must be exactly "ip" or
// netnsExecSelfToken (D3); the EXECUTED binary is always the broker-resolved
// value (resolveNetnsExecBinary), never the client string.
func doNetnsExec(srcPID int, netnsPath string, argv []string) Response {
	if len(argv) == 0 {
		return Response{Error: "netns_exec: empty argv"}
	}
	if _, ok := netnsExecAllowlist[argv[0]]; !ok {
		// SC-1-EXEC: hard reject, do not leak the permitted set (mirrors doExec).
		return Response{Error: fmt.Sprintf("netns_exec: binary %q not in broker allowlist", argv[0])}
	}
	binary, err := resolveNetnsExecBinary(argv[0])
	if err != nil {
		return Response{Error: fmt.Sprintf("netns_exec: %v", err)}
	}
	nsTarget, err := resolveNetnsExecTarget(srcPID, netnsPath)
	if err != nil {
		return Response{Error: fmt.Sprintf("netns_exec: %v", err)}
	}

	execArgv := append([]string{binary}, argv[1:]...)
	cmd, err := nsenterNetNsPath(nsTarget, execArgv...)
	if err != nil {
		return Response{Error: fmt.Sprintf("netns_exec: %v", err)}
	}
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
			return Response{Error: fmt.Sprintf("netns_exec: spawn nsenter for %q: %v", argv[0], runErr)}
		}
	}
	return Response{
		ExitCode: &exitCode,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Combined: combined.Bytes(),
	}
}

// doNetnsExecStart spawns an allowlisted (ADR-0346 D3) command DETACHED
// inside the target pod's NET namespace and returns its host PID (for the
// __inetns_echo listener, which must outlive the originating RPC). Reuses
// asyncExecReg/doExecPoll/doExecSignal UNCHANGED (D1) — the registry is keyed
// generically on PID, not on which op launched it.
func doNetnsExecStart(srcPID int, netnsPath string, argv []string) Response {
	if len(argv) == 0 {
		return Response{Error: "netns_exec_start: empty argv"}
	}
	if _, ok := netnsExecAllowlist[argv[0]]; !ok {
		return Response{Error: fmt.Sprintf("netns_exec_start: binary %q not in broker allowlist", argv[0])}
	}
	binary, err := resolveNetnsExecBinary(argv[0])
	if err != nil {
		return Response{Error: fmt.Sprintf("netns_exec_start: %v", err)}
	}
	nsTarget, err := resolveNetnsExecTarget(srcPID, netnsPath)
	if err != nil {
		return Response{Error: fmt.Sprintf("netns_exec_start: %v", err)}
	}

	beforePIDs, _ := brokerCgroupPIDs()
	if beforePIDs == nil {
		beforePIDs = map[int]bool{}
	}

	execArgv := append([]string{binary}, argv[1:]...)
	cmd, err := nsenterNetNsPath(nsTarget, execArgv...)
	if err != nil {
		return Response{Error: fmt.Sprintf("netns_exec_start: %v", err)}
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = &capWriter{buf: stderr, cap: asyncExecStderrCap}

	if err := cmd.Start(); err != nil {
		return Response{Error: fmt.Sprintf("netns_exec_start: spawn: %v", err)}
	}
	pid := cmd.Process.Pid

	asyncExecMu.Lock()
	asyncExecReg[pid] = &asyncExecEntry{cmd: cmd, stderr: stderr, beforePIDs: beforePIDs}
	asyncExecMu.Unlock()

	return Response{WrapperPID: pid}
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

	cmd, err := nsenterHostMnt(argv...)
	if err != nil {
		return Response{Error: fmt.Sprintf("exec_start: %v", err)}
	}
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
//
//	(a) only SIGCONT/SIGSTOP are accepted — any other signal is a loud reject.
//	(b) PID-reuse guard: the client supplies the starttime it captured when it
//	    recorded the PID; the broker re-reads /proc/<pid>/stat field 22 and
//	    refuses to signal on any mismatch (the PID has been reused for an
//	    unrelated process). expectedStartTime==0 is treated as "no identity
//	    supplied" and rejected — we never signal without a verified identity.
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

// doKillSourcePID delivers SIGKILL — and ONLY SIGKILL, hardcoded, never client-selectable
// — to a source-tree PID the broker never spawned (ADR-0356). See the kill_source_pid case
// in Handle for why this is a separate op from signal_pid rather than an addition to its
// SC-1 SIGCONT/SIGSTOP allowlist.
//
// Used by the ADR-0356 Tier1-Longhorn early source release to terminate the source process
// directly at the kernel level — whether it is currently SIGSTOPped (a LeaveStopped=true
// dump) or still normally running (the containerd-native ctr-checkpoint fast path, which
// does not stop the container) — BEFORE the source pod is deleted through Kubernetes. A
// plain pod delete resumes/signals the container through the normal app-level shutdown
// path, giving a workload that manages its own on-disk lock/state file (e.g. PostgreSQL's
// postmaster.pid) on a volume SHARED with the already-restored destination a window to
// corrupt that shared state; SIGKILL delivered here never reaches any application signal
// handler.
//
// Same PID-reuse (starttime) guard as doSignalPID: expectedStartTime==0 is rejected, and a
// live/expected starttime mismatch means the PID has been reused by an unrelated process —
// refuse to signal rather than kill the wrong thing.
func doKillSourcePID(pid int, expectedStartTime uint64) Response {
	if pid <= 0 {
		return Response{Error: fmt.Sprintf("kill_source_pid: pid %d must be positive", pid)}
	}
	if expectedStartTime == 0 {
		return Response{Error: fmt.Sprintf("kill_source_pid: no expected starttime supplied for pid %d — refusing to kill without a PID-reuse identity", pid)}
	}
	liveStart, err := procStartTime(pid)
	if err != nil {
		return Response{Error: fmt.Sprintf("kill_source_pid: read starttime for pid %d (process gone?): %v", pid, err)}
	}
	if liveStart != expectedStartTime {
		return Response{Error: fmt.Sprintf("kill_source_pid: pid %d starttime mismatch (expected %d, live %d) — PID reused, refusing to kill", pid, expectedStartTime, liveStart)}
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return Response{Error: fmt.Sprintf("kill_source_pid: kill(%d, SIGKILL): %v", pid, err)}
	}
	return Response{}
}

// cgroupFsRoot is the broker's own view of the cgroup v2 mount point. The broker
// is privileged:true and unconfined, so this is the real host cgroupfs root
// (never a namespaced/masked view) — see CgroupPath's doc comment on Request. A
// package var (not a bare constant), mirroring server.go's identically-named
// cgroupFsRoot, so tests can point it at a fixture tree instead of a real host
// /sys/fs/cgroup.
var cgroupFsRoot = "/sys/fs/cgroup"

// moveCgroupAllowedRoots mirrors the allowlist server.go's resolveCgroupAnchorTarget
// (ADR-0351 D2.4/BD-10) enforces agent-side. The broker is the actual privileged
// write surface, so it re-derives and re-checks confinement independently here
// rather than trusting the agent's prior resolution — a compromised or buggy
// de-privileged agent must not be able to direct the broker to write an arbitrary
// PID into an arbitrary cgroup. Kept in exact sync with server.go's allowedCgroupRoots
// (vanilla kubeadm/KVM cgroupRoot="/" and kind's cgroupRoot=/kubelet layout).
func moveCgroupAllowedRoots() []string {
	return []string{
		filepath.Join(cgroupFsRoot, "kubepods"),
		filepath.Join(cgroupFsRoot, "kubelet.slice", "kubelet-kubepods"),
	}
}

// cgroupPathContainsPodUID mirrors server.go's cgroupUIDVariants/cgroupContainsPodUID
// (can't import them directly — server.go imports this package, not the reverse).
// cgroup v2 on systemd encodes pod UIDs with underscores
// (kubepods-besteffort-pod<uid_with_underscores>.slice), so both forms are checked.
func cgroupPathContainsPodUID(path, podUID string) bool {
	underscored := strings.ReplaceAll(podUID, "-", "_")
	if strings.Contains(path, podUID) {
		return true
	}
	return underscored != podUID && strings.Contains(path, underscored)
}

// doMoveCgroup implements the move_cgroup op (ADR-0351 D2, sprint53-kind): writes
// pid into the cgroup.procs file of the container's own cgroup v2 scope, run from
// the broker's own (host-rooted) cgroup namespace — see CgroupPath's doc comment
// on Request for why the de-privileged main agent cannot do this write itself.
//
// Same PID-reuse (starttime) guard as doSignalPID/doKillSourcePID: expectedStartTime
// ==0 is rejected, and a live/expected mismatch means the PID has been reused —
// refuse rather than move the wrong process's tree into a container's cgroup.
//
// cgroupPath is independently re-confined here (EvalSymlinks + prefix check against
// moveCgroupAllowedRoots) rather than trusted from the client — see
// moveCgroupAllowedRoots' doc comment.
//
// expectedPodUID is re-derived and re-checked here too, not just trusted as a
// caller-computed boolean: on kind the broker shares the host cgroup namespace
// (no kernel-level per-pod isolation backstop), so the allowlist-root check alone
// only proves "somewhere under kubepods," not "this migration's destination pod."
// Requiring the resolved path to actually contain expectedPodUID closes that gap.
func doMoveCgroup(pid int, cgroupPath string, expectedStartTime uint64, expectedPodUID string) Response {
	if pid <= 0 {
		return Response{Error: fmt.Sprintf("move_cgroup: pid %d must be positive", pid)}
	}
	if cgroupPath == "" {
		return Response{Error: "move_cgroup: empty cgroupPath"}
	}
	if expectedPodUID == "" {
		return Response{Error: fmt.Sprintf("move_cgroup: no expected pod UID supplied for pid %d — refusing to move without a destination-pod identity", pid)}
	}
	if expectedStartTime == 0 {
		return Response{Error: fmt.Sprintf("move_cgroup: no expected starttime supplied for pid %d — refusing to move without a PID-reuse identity", pid)}
	}
	liveStart, err := procStartTime(pid)
	if err != nil {
		return Response{Error: fmt.Sprintf("move_cgroup: read starttime for pid %d (process gone?): %v", pid, err)}
	}
	if liveStart != expectedStartTime {
		return Response{Error: fmt.Sprintf("move_cgroup: pid %d starttime mismatch (expected %d, live %d) — PID reused, refusing to move", pid, expectedStartTime, liveStart)}
	}

	candidate := filepath.Join(cgroupFsRoot, cgroupPath)
	resolved, rerr := filepath.EvalSymlinks(candidate)
	if rerr != nil {
		return Response{Error: fmt.Sprintf("move_cgroup: resolve cgroup path %q: %v", candidate, rerr)}
	}
	allowed := false
	for _, root := range moveCgroupAllowedRoots() {
		if strings.HasPrefix(resolved, root) {
			allowed = true
			break
		}
	}
	if !allowed {
		return Response{Error: fmt.Sprintf("move_cgroup: cgroup path %q resolves to %q, outside %s — refusing (path-confinement)",
			cgroupPath, resolved, strings.Join(moveCgroupAllowedRoots(), " or "))}
	}
	if !cgroupPathContainsPodUID(resolved, expectedPodUID) {
		return Response{Error: fmt.Sprintf("move_cgroup: cgroup path %q does not contain expected pod UID %q — refusing (pod-confinement)",
			resolved, expectedPodUID)}
	}

	procsPath := filepath.Join(resolved, "cgroup.procs")
	if werr := os.WriteFile(procsPath, []byte(strconv.Itoa(pid)), 0o644); werr != nil {
		return Response{Error: fmt.Sprintf("move_cgroup: write pid %d to %s: %v", pid, procsPath, werr)}
	}
	return Response{}
}

// doProcAlive reports whether pid is alive (present under /proc and not a
// zombie), reading /proc/<pid>/stat directly in the broker's own UNCONFINED
// process. This exists because the confined main agent's own read of
// /proc/<restoredPID>/stat for a CRIU-restored workload root crosses a
// ptrace_may_access kernel gate that AppArmor mediates under the "ptrace"
// class against the TARGET's peer profile (the workload runs under
// containerd's default profile, e.g. cri-containerd.apparmor.d — never
// podmotion-agent or unconfined, the only two peers this profile's narrow
// `ptrace (read)` grants cover). A denied read previously surfaced to the
// caller as a plain os.ReadFile error — indistinguishable from "the process
// genuinely exited" — so ADR-0228's liveness gate (verifyRestoredPIDAlive)
// silently misclassified a live, healthy, just-restored workload as dead and
// triggered its fail-closed reap (ADR-0351 G5), SIGKILLing the very process
// the restore had just succeeded in bringing up. The broker is unconfined
// (privileged:true, no AppArmor profile — same reasoning as ResolveVeth /
// holder_sentinel / signal_pid above), so its read of the target's /proc/<pid>
// entries is never subject to this mediation: a false reading here can only
// come from the process actually being gone, exactly the semantics
// verifyRestoredPIDAlive needs.
//
// expectedStartTime, when non-zero, re-validates the PID's identity the same
// way doSignalPID does (field 22 of /proc/<pid>/stat) — a defense against a
// stale caller re-checking a PID that has since been reused by an unrelated
// process. expectedStartTime==0 skips the guard (used for the FIRST read,
// when the caller has no prior starttime to compare against) and the read
// starttime is always returned in Response.StartTime so the caller can latch
// it for a subsequent guarded re-check.
func doProcAlive(pid int, expectedStartTime uint64) Response {
	if pid <= 0 {
		return Response{Error: fmt.Sprintf("proc_alive: pid %d must be positive", pid)}
	}
	liveStart, err := procStartTime(pid)
	if err != nil {
		// The process is gone (or /proc/<pid>/stat is otherwise unreadable for a
		// reason that is NOT AppArmor mediation, since this call runs unconfined) —
		// a genuine "not alive", not a permission artifact.
		return Response{Alive: false}
	}
	if expectedStartTime != 0 && liveStart != expectedStartTime {
		// PID reused since the caller's earlier read — the ORIGINAL process it was
		// tracking is gone, even though some (different) process now occupies pid.
		return Response{Alive: false, StartTime: liveStart}
	}
	return Response{Alive: !processZombieOrDead(pid), StartTime: liveStart}
}

// doNetnsMatch is the netns_match op's pure logic: stat pid's /proc/<pid>/ns/net
// and expectedNetnsPath, and report whether they identify the same netns (same
// inode+dev on the nsfs pseudo-filesystem). Both stats run in THIS unconfined
// broker process, so neither crosses the ptrace_may_access gate that denies the
// de-privileged agent's own direct stat of a foreign PID's /proc/<pid>/ns/net —
// see ExpectedNetnsPath's doc comment on Request for the full rationale. This is
// a direct broker-side port of the agent's original pidNetnsMatchesPath
// (server.go), moved here unchanged in comparison logic — only the caller
// changed, not the identity check itself.
//
// expectedNetnsPath is validated against netnsPathRe (the same closed
// /run/netns|/var/run/netns convention netns_exec's NetnsPath already enforces)
// before use — SC-1: the broker never stats an arbitrary client-supplied path.
// Any stat failure on either side fails closed with Error set (never a silent
// Match:false), mirroring pidNetnsMatchesPath's original (bool, error) contract.
func doNetnsMatch(pid int, expectedNetnsPath string) Response {
	if pid <= 0 {
		return Response{Error: fmt.Sprintf("netns_match: pid %d must be positive", pid)}
	}
	if !netnsPathRe.MatchString(expectedNetnsPath) {
		return Response{Error: fmt.Sprintf("netns_match: expectedNetnsPath %q does not match the required /run/netns|/var/run/netns bind-mount convention", expectedNetnsPath)}
	}
	var pidStat, expStat unix.Stat_t
	pidNsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	if err := unix.Stat(pidNsPath, &pidStat); err != nil {
		return Response{Error: fmt.Sprintf("netns_match: stat %s: %v", pidNsPath, err)}
	}
	if err := unix.Stat(expectedNetnsPath, &expStat); err != nil {
		return Response{Error: fmt.Sprintf("netns_match: stat %s: %v", expectedNetnsPath, err)}
	}
	return Response{Match: pidStat.Ino == expStat.Ino && pidStat.Dev == expStat.Dev}
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
	if out, err := nsenterHostMntCombined("mkdir", "-p", dir); err != nil {
		return "", fmt.Errorf("mkdir %s in host mount ns: %w\n%s", dir, err, out)
	}
	if out, err := nsenterHostMntCombined("sh", "-c",
		fmt.Sprintf("[ -e %q ] || touch %q", bindPath, bindPath),
	); err != nil {
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
	if out, err := nsenterHostMntCombined("umount", "-l", bindPath); err != nil {
		if !isNotMountedOutput(out) {
			return fmt.Errorf("unmount %s in host mount ns: %w\n%s", bindPath, err, out)
		}
	}
	// Remove the bind-target file in the host mount namespace.
	if out, err := nsenterHostMntCombined("rm", "-f", bindPath); err != nil {
		return fmt.Errorf("remove %s in host mount ns: %w\n%s", bindPath, err, out)
	}
	// Remove the now-empty per-migration dir in the host mount namespace.
	// `rmdir` on a non-empty dir is non-fatal (idempotent teardown).
	if out, err := nsenterHostMntCombined("rmdir", dir); err != nil {
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
	if out, err := nsenterHostMntCombined("mount", "--bind", src, target); err != nil {
		return fmt.Errorf("bind mount %s -> %s in host mount ns: %w\n%s", src, target, err, out)
	}
	return nil
}

// nsenterHostMnt builds an *exec.Cmd that runs `nsenter --mount=/proc/1/ns/mnt --
// <args...>` — the command executes in the HOST mount namespace as a fresh
// single-threaded process. This is the syscall-free replacement for the prior
// in-process unix.Setns(CLONE_NEWNS) host-mount-ns entry, which returns EINVAL
// from the multithreaded Go runtime regardless of CAP_SYS_ADMIN.
//
// ADR-0347 A2: outer program is pinnedNsenter, never the bare "nsenter" name.
func nsenterHostMnt(args ...string) (*exec.Cmd, error) {
	// SR-DEP: the host-mount-ns path (bind/teardown, the `exec` set, and the
	// CRIU-restore wrapper launch via exec_start) spawns ONLY nsenter and never
	// ip — resolve just the nsenter pin so an unresolvable ip cannot fail this
	// safety-critical, ip-free path closed.
	if err := resolvePinnedNsenter(); err != nil {
		return nil, err
	}
	full := append([]string{hostMountNsArg, "--"}, args...)
	return exec.Command(pinnedNsenter, full...), nil
}

// nsenterHostMntCombined is nsenterHostMnt + CombinedOutput() folded into one
// call, for the run-to-completion mkdir/touch/umount/rm/rmdir/mount call sites
// in doCreate/doTeardown/bindInHostMountNs that only need the combined output
// and an error — a pin-resolution failure (ADR-0347 A1) surfaces the same way
// a spawn failure always has, via the returned error.
func nsenterHostMntCombined(args ...string) ([]byte, error) {
	cmd, err := nsenterHostMnt(args...)
	if err != nil {
		return nil, err
	}
	return cmd.CombinedOutput()
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
