// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package netnsbroker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Client dials the netns-broker Unix domain socket. The main agent (de-privileged
// under SD-1) uses it to request per-migration netns bind/teardown from the
// privileged sidecar instead of running nsenter+mount itself.
type Client struct {
	// SocketPath overrides the default broker socket path (testing). Empty => SocketPath.
	socketPath string
	// dialTimeout bounds connect; opTimeout bounds the whole request/response.
	dialTimeout time.Duration
	opTimeout   time.Duration
}

// NewClient returns a Client dialing the default broker socket.
func NewClient() *Client {
	return &Client{
		socketPath:  SocketPath,
		dialTimeout: 5 * time.Second,
		opTimeout:   30 * time.Second,
	}
}

// NewClientForTesting returns a Client dialing socketPath instead of the production
// SocketPath (ADR-0354 D6 test-injection seam). SocketPath is an unexported struct field
// and the production default (const SocketPath, /run/podmotion/netns-broker.sock) requires
// root to bind, so cross-package regression tests (internal/agent/server) need a way to
// point brokerCmd/brokerCriuCmd/resolveReplVethPeer at a fake, test-owned broker listener
// exercising the SAME do()/wire-protocol code this Client uses in production — never a
// re-implementation of the transport. Not called by any non-test production code path.
func NewClientForTesting(socketPath string, dialTimeout, opTimeout time.Duration) *Client {
	return &Client{socketPath: socketPath, dialTimeout: dialTimeout, opTimeout: opTimeout}
}

func (c *Client) path() string {
	if c.socketPath != "" {
		return c.socketPath
	}
	return SocketPath
}

// Create requests a per-migration netns bind-mount and returns the host bind path.
// srcPID > 0 binds /proc/<srcPID>/ns/net (pod-in-migration); srcPID == 0 makes the
// broker unshare a fresh netns and bind it (destination-prewarm path).
func (c *Client) Create(ctx context.Context, migrationUID string, srcPID int) (string, error) {
	resp, err := c.do(ctx, Request{Op: "create", MigrationUID: migrationUID, SrcPID: srcPID})
	if err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", fmt.Errorf("netns-broker create %s: %s", migrationUID, resp.Error)
	}
	return resp.Path, nil
}

// ExecResult is now defined in types.go (ADR-0346 D6 — shared with the
// non-linux stub in broker_other.go).

// Exec asks the privileged broker to run an allowlisted command in the HOST mount
// namespace (ADR-0231). The de-privileged SD-1 agent cannot itself enter the host
// mount namespace (setns(CLONE_NEWNS) needs CAP_SYS_ADMIN in the host init userns,
// which only privileged:true confers), so the restore-path host-mount-ns work
// (ctr image pull, the CRIU wrapper, rootfs scaffolding) is delegated here.
//
// opTimeout overrides the client's default per-request timeout: CRIU restore can
// run far longer than the 30s netns-bind default. Pass 0 to use the default.
func (c *Client) Exec(ctx context.Context, opTimeout time.Duration, argv ...string) ExecResult {
	prev := c.opTimeout
	if opTimeout > 0 {
		c.opTimeout = opTimeout
	}
	resp, err := c.do(ctx, Request{Op: "exec", Argv: argv})
	c.opTimeout = prev
	if err != nil {
		return ExecResult{ExitCode: -1, SpawnErr: fmt.Errorf("netns-broker exec %v: %w", argv, err)}
	}
	if resp.Error != "" {
		return ExecResult{ExitCode: -1, SpawnErr: fmt.Errorf("netns-broker exec %v: %s", argv, resp.Error)}
	}
	exit := 0
	if resp.ExitCode != nil {
		exit = *resp.ExitCode
	}
	return ExecResult{
		ExitCode: exit,
		Stdout:   resp.Stdout,
		Stderr:   resp.Stderr,
		Combined: resp.Combined,
	}
}

// ExecStart asks the privileged broker to spawn the long-running CRIU restore
// wrapper DETACHED in the host mount namespace and returns its host PID (ADR-0234).
// Unlike Exec (run-to-completion), this returns as soon as the wrapper has forked:
// the wrapper on the cold --join-ns path never self-exits, so the agent must poll
// liveness (ExecPoll) while it still runs and reap it asynchronously. argv[0] must
// be the PodMotion CRIU wrapper binary — the broker rejects any other binary on
// the async path (tighter than Exec's allowlist).
func (c *Client) ExecStart(ctx context.Context, argv ...string) (int, error) {
	resp, err := c.do(ctx, Request{Op: "exec_start", Argv: argv})
	if err != nil {
		return 0, fmt.Errorf("netns-broker exec_start %v: %w", argv, err)
	}
	if resp.Error != "" {
		return 0, fmt.Errorf("netns-broker exec_start %v: %s", argv, resp.Error)
	}
	if resp.WrapperPID <= 0 {
		return 0, fmt.Errorf("netns-broker exec_start %v: broker returned no wrapper PID", argv)
	}
	return resp.WrapperPID, nil
}

// PollResult is the outcome of an ExecPoll. Running is true while the wrapper is
// still alive; once it exits, ExitCode/Stderr carry the result. CgroupPIDs is the
// PID set currently resident in the BROKER's cgroup — the wrapper is a broker
// child, so the CRIU-restored tree (--manage-cgroups=ignore) lands there; the
// agent diffs this against its pre-start snapshot to detect the new workload
// entrant (ADR-0128 liveness signal, relocated to the broker cgroup).
type PollResult struct {
	Running    bool
	ExitCode   int
	Stderr     []byte
	CgroupPIDs []int
}

// ExecPoll asks the broker whether the wrapper PID is still running and returns
// the broker-cgroup PID set for the new-entrant liveness diff (ADR-0234). When the
// wrapper has exited, the broker reaps it once and reports Running:false with the
// exit code and stderr tail.
func (c *Client) ExecPoll(ctx context.Context, wrapperPID int) (PollResult, error) {
	resp, err := c.do(ctx, Request{Op: "exec_poll", WrapperPID: wrapperPID})
	if err != nil {
		return PollResult{}, fmt.Errorf("netns-broker exec_poll %d: %w", wrapperPID, err)
	}
	if resp.Error != "" {
		return PollResult{}, fmt.Errorf("netns-broker exec_poll %d: %s", wrapperPID, resp.Error)
	}
	exit := 0
	if resp.ExitCode != nil {
		exit = *resp.ExitCode
	}
	return PollResult{
		Running:    resp.Running,
		ExitCode:   exit,
		Stderr:     resp.Stderr,
		CgroupPIDs: resp.CgroupPIDs,
	}, nil
}

// ExecSignal asks the broker to deliver a signal to the wrapper PID (Abort path,
// ADR-0234). signal 0 is mapped to SIGKILL broker-side.
func (c *Client) ExecSignal(ctx context.Context, wrapperPID, signal int) error {
	resp, err := c.do(ctx, Request{Op: "exec_signal", WrapperPID: wrapperPID, Signal: signal})
	if err != nil {
		return fmt.Errorf("netns-broker exec_signal %d: %w", wrapperPID, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("netns-broker exec_signal %d: %s", wrapperPID, resp.Error)
	}
	return nil
}

// SignalPID asks the unconfined broker to deliver SIGCONT/SIGSTOP to an arbitrary
// host PID — the CRIU-restored workload root (ADR-0312). The de-privileged SD-1
// agent's own `podmotion-agent` AppArmor profile denies that signal because the
// restored tree runs under containerd's default profile (a runtime-defined peer
// label, e.g. runc/cri-containerd.apparmor.d) that the agent's signal rule does
// not cover — the exact apparmor DENIED operation="signal" ... signal=cont
// signature. The unconfined broker is not subject to AppArmor signal mediation, so
// the resume succeeds there regardless of the target's profile. expectedStarttime
// is field 22 of /proc/<pid>/stat captured when the caller recorded the PID; the
// broker re-reads it and refuses on mismatch (PID-reuse guard). The broker accepts
// only SIGCONT/SIGSTOP server-side.
func (c *Client) SignalPID(ctx context.Context, pid, sig int, expectedStarttime uint64) error {
	resp, err := c.do(ctx, Request{Op: "signal_pid", SignalPID: pid, Signal: sig, ExpectedStartTime: expectedStarttime})
	if err != nil {
		return fmt.Errorf("netns-broker signal_pid %d: %w", pid, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("netns-broker signal_pid %d: %s", pid, resp.Error)
	}
	return nil
}

// ResolveVeth asks the privileged broker to enter the pod's NETWORK namespace
// (/proc/<srcPID>/ns/net) and run `ip -o link show eth0`, returning the raw ip(8)
// output. The de-privileged SD-1 agent cannot do this itself: opening another
// pod's /proc/<pid>/ns/net routes through a ptrace_may_access gate that the narrow
// `podmotion-agent` AppArmor profile denies (it allows ptrace-read only against
// peer=unconfined; the workload runs under cri-containerd.apparmor.d) — the exact
// "apparmor DENIED operation=ptrace" signature. The broker runs unconfined
// (privileged:true, no AppArmor profile) and hostPID:true, so the netns-entry
// ptrace read is permitted there. srcPID must be > 0 (a live in-migration PID).
// SpawnErr is set only on a broker-side failure; a non-zero ip(8) exit is reported
// via ExitCode/Stderr so the caller reconstructs the result as if it ran nsenter itself.
func (c *Client) ResolveVeth(ctx context.Context, srcPID int) ExecResult {
	resp, err := c.do(ctx, Request{Op: "resolve_veth", SrcPID: srcPID})
	if err != nil {
		return ExecResult{ExitCode: -1, SpawnErr: fmt.Errorf("netns-broker resolve_veth %d: %w", srcPID, err)}
	}
	if resp.Error != "" {
		return ExecResult{ExitCode: -1, SpawnErr: fmt.Errorf("netns-broker resolve_veth %d: %s", srcPID, resp.Error)}
	}
	exit := 0
	if resp.ExitCode != nil {
		exit = *resp.ExitCode
	}
	return ExecResult{
		ExitCode: exit,
		Stdout:   resp.Stdout,
		Stderr:   resp.Stderr,
		Combined: resp.Combined,
	}
}

// HolderSentinelReady asks the unconfined broker whether the holder-quiescent
// sentinel (/run/podmotion/holder-ready) has been written inside the restore-target
// container identified by containerID. The de-privileged SD-1 agent cannot observe
// it directly: dereferencing /proc/<holderPID>/root routes through a ptrace_may_access
// gate that the `podmotion-agent` AppArmor profile denies against the holder's
// cri-containerd.apparmor.d peer profile — the same delegation class as ResolveVeth.
// A false return with a nil error is a valid negative (holder not yet parked / PID
// not yet resolvable); the caller keeps polling. A non-nil error means the broker
// was unreachable or rejected the request.
func (c *Client) HolderSentinelReady(ctx context.Context, containerID string) (bool, error) {
	resp, err := c.do(ctx, Request{Op: "holder_sentinel", ContainerID: containerID})
	if err != nil {
		return false, fmt.Errorf("netns-broker holder_sentinel %s: %w", containerID, err)
	}
	if resp.Error != "" {
		return false, fmt.Errorf("netns-broker holder_sentinel %s: %s", containerID, resp.Error)
	}
	return resp.Found, nil
}

// NetnsExec asks the privileged broker to run an allowlisted ("ip" or the self
// sentinel) command inside the target pod's NET namespace, run-to-completion
// (ADR-0346). Exactly one of srcPID (a live PID, takes precedence) or
// netnsPath (a /run/netns|/var/run/netns bind path) must resolve — see
// broker-side D2. Fail-closed (D6): SpawnErr is set on any
// broker-unreachable/rejected case; never a silent zero-value success.
func (c *Client) NetnsExec(ctx context.Context, srcPID int, netnsPath string, argv ...string) ExecResult {
	resp, err := c.do(ctx, Request{Op: "netns_exec", SrcPID: srcPID, NetnsPath: netnsPath, Argv: argv})
	if err != nil {
		return ExecResult{ExitCode: -1, SpawnErr: fmt.Errorf("netns-broker netns_exec %v: %w", argv, err)}
	}
	if resp.Error != "" {
		return ExecResult{ExitCode: -1, SpawnErr: fmt.Errorf("netns-broker netns_exec %v: %s", argv, resp.Error)}
	}
	exit := 0
	if resp.ExitCode != nil {
		exit = *resp.ExitCode
	}
	return ExecResult{
		ExitCode: exit,
		Stdout:   resp.Stdout,
		Stderr:   resp.Stderr,
		Combined: resp.Combined,
	}
}

// NetnsExecStart asks the privileged broker to spawn an allowlisted command
// DETACHED inside the target pod's NET namespace and returns its host PID
// (ADR-0346) — used by the __inetns_echo listener, which must outlive the
// originating RPC. Reap/signal via the existing ExecPoll/ExecSignal (unchanged).
// Fail-closed (D6): a non-nil error is returned on any broker-unreachable/
// rejected case; never a zero-value "success" PID.
func (c *Client) NetnsExecStart(ctx context.Context, srcPID int, netnsPath string, argv ...string) (int, error) {
	resp, err := c.do(ctx, Request{Op: "netns_exec_start", SrcPID: srcPID, NetnsPath: netnsPath, Argv: argv})
	if err != nil {
		return 0, fmt.Errorf("netns-broker netns_exec_start %v: %w", argv, err)
	}
	if resp.Error != "" {
		return 0, fmt.Errorf("netns-broker netns_exec_start %v: %s", argv, resp.Error)
	}
	if resp.WrapperPID <= 0 {
		return 0, fmt.Errorf("netns-broker netns_exec_start %v: broker returned no wrapper PID", argv)
	}
	return resp.WrapperPID, nil
}

// Teardown requests unmount+removal of the per-migration netns. Idempotent broker-side.
func (c *Client) Teardown(ctx context.Context, migrationUID string) error {
	resp, err := c.do(ctx, Request{Op: "teardown", MigrationUID: migrationUID})
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("netns-broker teardown %s: %s", migrationUID, resp.Error)
	}
	return nil
}

func (c *Client) do(ctx context.Context, req Request) (Response, error) {
	dialCtx, cancel := context.WithTimeout(ctx, c.dialTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", c.path())
	if err != nil {
		return Response{}, fmt.Errorf("dial netns-broker %s: %w", c.path(), err)
	}
	defer conn.Close()

	// ADR-0354 DR-1: DialContext only observes ctx cancellation during the dial
	// itself — once connected, nothing previously re-checked ctx.Done(), so a
	// cancelled caller ctx (Abort, errgroup-cancel) could not unblock a wedged
	// write/read; it ran to the opTimeout/deadline clamp below instead. This
	// watcher re-deadlines the conn the moment ctx is cancelled, so the blocking
	// read at ReadBytes below is cut at cancel latency, not the clamp. Client-side
	// and cancellation-only: no wire message, broker-side code, socket path, or
	// allowlist change.
	cancelStop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer cancelStop()

	deadline := time.Now().Add(c.opTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("marshal request: %w", err)
	}
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Response{}, fmt.Errorf("write request: %w", ctxErr)
		}
		return Response{}, fmt.Errorf("write request: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Response{}, fmt.Errorf("read response: %w", ctxErr)
		}
		return Response{}, fmt.Errorf("read response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}
