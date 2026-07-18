// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

// adr0356_kill_frozen_source_test.go — regression proof for the sprint49 fix to ADR-0356's
// Tier1-Longhorn early source release.
//
// Root cause this closes (found live, sprint49 postgres Tier1-Longhorn proof, two distinct
// gaps in the same session):
//
//  1. A plain Kubernetes pod delete does not safely tear down a source container — even with
//     GracePeriodSeconds(0), the container runtime's stop sequence still resumes/signals the
//     app before SIGKILL lands, giving a workload that manages its own on-disk lock file (in
//     a volume SHARED with the already-restored destination, e.g. PostgreSQL's
//     postmaster.pid on the same Longhorn PV) a window to run its own shutdown code and
//     corrupt that shared state. Fix: killFrozenSource/brokerKillSourcePID delivers SIGKILL
//     directly via the broker's dedicated kill_source_pid op, BEFORE the pod is ever deleted.
//  2. Not every checkpoint path freezes the source into SIGSTOP: the containerd-native
//     "ctr tasks checkpoint" fast path (Checkpoint's default branch) never registers a
//     frozen-source record, since it does not stop the container — the source keeps running
//     normally afterward. Without a fallback, killFrozenSource silently no-op'd
//     (killed=false) for every such migration, and the unsafe pod-delete path still ran,
//     fully reintroducing the race. Fix: killFrozenSource falls back to resolving and
//     killing the CURRENT container root PID via FindContainerPID when no frozen-source
//     record exists.
//
// Also asserts the broker-boundary distinction: the kill MUST go through the dedicated
// kill_source_pid op, never signal_pid — signal_pid's SC-1 allowlist is restricted to
// EXACTLY SIGCONT/SIGSTOP specifically so it cannot become a general kill proxy for a
// compromised de-privileged agent (doSignalPID/signalPIDAllowed), so a regression that
// tried to route the kill through signal_pid would be rejected in production every time.

import (
	"context"
	"net"
	"os/exec"
	"sync"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
)

// killSourcePIDRecorder records every op observed by the fake broker (so tests can assert
// which op fired — kill_source_pid vs signal_pid), answers proc_alive as "alive" with a
// fixed starttime (killFrozenSource probes liveness via the broker before killing), and
// answers kill_source_pid with success.
func killSourcePIDRecorder(opsSeen *[]string, mu *sync.Mutex) fakeBrokerHandler {
	return func(conn net.Conn, req netnsbroker.Request, done <-chan struct{}) {
		mu.Lock()
		*opsSeen = append(*opsSeen, req.Op)
		mu.Unlock()
		switch req.Op {
		case "proc_alive":
			writeFakeResponse(conn, netnsbroker.Response{Alive: true, StartTime: 999})
		case "kill_source_pid":
			writeFakeResponse(conn, netnsbroker.Response{}) // success: Error == ""
		case "signal_pid":
			// The real broker would reject SIGKILL here (SC-1 allowlist is
			// SIGCONT/SIGSTOP only) — mirror that rejection so a regression that
			// routes the kill through signal_pid fails loudly instead of the fake
			// silently accepting what production would refuse.
			writeFakeResponse(conn, netnsbroker.Response{Error: "signal_pid: signal not permitted (only SIGCONT/SIGSTOP)"})
		default:
			writeFakeResponse(conn, netnsbroker.Response{ExitCode: intPtr(0)})
		}
	}
}

func opsSeenOnly(op string) func(opsSeen []string) bool {
	return func(opsSeen []string) bool {
		return len(opsSeen) == 1 && opsSeen[0] == op
	}
}

// TestBrokerKillSourcePID_UsesDedicatedOp_NotSignalPID is the direct regression guard: a
// source process must be terminated via the broker's dedicated kill_source_pid op (SIGKILL
// hardcoded server-side), never via signal_pid.
func TestBrokerKillSourcePID_UsesDedicatedOp_NotSignalPID(t *testing.T) {
	var opsSeen []string
	var mu sync.Mutex
	sock := startFakeBroker(t, killSourcePIDRecorder(&opsSeen, &mu))
	origFn := netnsBrokerClientFn
	netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
	defer func() { netnsBrokerClientFn = origFn }()

	const sourcePID = int32(424247)
	const startTime = uint64(654321)

	if err := brokerKillSourcePID(context.Background(), sourcePID, startTime); err != nil {
		t.Fatalf("brokerKillSourcePID returned an error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !opsSeenOnly("kill_source_pid")(opsSeen) {
		t.Fatalf("brokerKillSourcePID sent ops %v, want exactly [\"kill_source_pid\"] — a source "+
			"process must be killed via the dedicated kill_source_pid op (SIGKILL hardcoded "+
			"server-side), never via signal_pid, which the broker's SC-1 allowlist would reject "+
			"(only SIGCONT/SIGSTOP permitted) — reintroducing this would make the ADR-0356 kill "+
			"fail every time, exactly the live regression this test guards", opsSeen)
	}
}

// TestKillFrozenSource_NoRecord_IsIdempotentNoOp asserts killFrozenSource is a safe,
// error-free no-op (killed=false) when no frozen-source record exists AND no fallback pod
// UID is supplied — e.g. already thawed, already killed, or never frozen with no ctr-native
// fallback available. This mirrors thawFrozenSource's own idempotency contract.
func TestKillFrozenSource_NoRecord_IsIdempotentNoOp(t *testing.T) {
	s := &AgentServer{frozenSourcePIDs: make(map[string]int32)}
	killed, err := s.killFrozenSource(context.Background(), "no-such-migration", "" /* no fallback pod UID */)
	if err != nil {
		t.Fatalf("expected nil error for a migration with no frozen-source record, got: %v", err)
	}
	if killed {
		t.Fatal("expected killed=false when no frozen-source record exists")
	}
}

// TestKillFrozenSource_DeliversSIGKILL_AndClearsRecord drives killFrozenSource end-to-end
// against a real process (the test's own child, so the broker's proc_alive/starttime path
// is genuinely exercised) and a fake broker, asserting: the kill_source_pid op fires exactly
// once, killed=true, and the frozen-source record is cleared afterward (a second call is a
// safe no-op, not a second broker call).
func TestKillFrozenSource_DeliversSIGKILL_AndClearsRecord(t *testing.T) {
	var opsSeen []string
	var mu sync.Mutex
	sock := startFakeBroker(t, killSourcePIDRecorder(&opsSeen, &mu))
	origFn := netnsBrokerClientFn
	netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
	defer func() { netnsBrokerClientFn = origFn }()

	// A real, currently-running process so the broker's proc_alive/starttime resolution
	// exercises a genuine target, exactly as it would against a real frozen source.
	cmd := realSleepCmdForTest(t)
	pid := int32(cmd.Process.Pid)
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	const migName = "pm-kill-frozen-test"
	s := &AgentServer{frozenSourcePIDs: map[string]int32{migName: pid}}

	killed, err := s.killFrozenSource(context.Background(), migName, "" /* frozen record takes priority over any fallback */)
	if err != nil {
		t.Fatalf("killFrozenSource returned an error: %v", err)
	}
	if !killed {
		t.Fatal("expected killed=true for a registered frozen-source PID")
	}
	mu.Lock()
	kills := 0
	for _, op := range opsSeen {
		if op == "kill_source_pid" {
			kills++
		}
	}
	mu.Unlock()
	if kills != 1 {
		t.Fatalf("expected exactly 1 kill_source_pid call, got %d (ops: %v)", kills, opsSeen)
	}
	s.frozenSourcePIDsMu.Lock()
	_, stillRegistered := s.frozenSourcePIDs[migName]
	s.frozenSourcePIDsMu.Unlock()
	if stillRegistered {
		t.Fatal("expected the frozen-source record to be cleared after killFrozenSource")
	}

	// Idempotency: a second call with no record left must be a safe no-op, not a second
	// broker call.
	killed2, err2 := s.killFrozenSource(context.Background(), migName, "")
	if err2 != nil {
		t.Fatalf("expected nil error on idempotent replay, got: %v", err2)
	}
	if killed2 {
		t.Fatal("expected killed=false on idempotent replay (record already cleared)")
	}
	mu.Lock()
	kills2 := 0
	for _, op := range opsSeen {
		if op == "kill_source_pid" {
			kills2++
		}
	}
	mu.Unlock()
	if kills2 != 1 {
		t.Fatalf("expected no additional kill_source_pid call on idempotent replay, got %d total", kills2)
	}
}

// TestKillFrozenSource_FallsBackToLiveContainerPID_WhenNoFrozenRecord is the direct
// regression proof for the second, live-found gap (sprint49, same session): the
// containerd-native "ctr tasks checkpoint" fast path (Checkpoint's default branch) never
// registers a frozen-source record, since it does not stop the container. Without a
// fallback, killFrozenSource would silently no-op (killed=false) for every such migration,
// and the unsafe graceful pod-delete path would still run — fully reintroducing the
// ADR-0356 race. This proves killFrozenSource resolves and kills the CURRENT container
// root PID via fallbackPodUID when no frozen-source record exists.
func TestKillFrozenSource_FallsBackToLiveContainerPID_WhenNoFrozenRecord(t *testing.T) {
	var opsSeen []string
	var mu sync.Mutex
	sock := startFakeBroker(t, killSourcePIDRecorder(&opsSeen, &mu))
	origFn := netnsBrokerClientFn
	netnsBrokerClientFn = func() *netnsbroker.Client { return testBrokerClient(sock) }
	defer func() { netnsBrokerClientFn = origFn }()

	const fakePodUID = "uid-ctr-native-checkpoint"
	const liveContainerPID = int32(999999)
	origFind := findContainerPIDFn
	findContainerPIDFn = func(podUID string) (int32, error) {
		if podUID != fakePodUID {
			t.Fatalf("findContainerPIDFn called with unexpected pod UID %q, want %q", podUID, fakePodUID)
		}
		return liveContainerPID, nil
	}
	defer func() { findContainerPIDFn = origFind }()

	s := &AgentServer{frozenSourcePIDs: make(map[string]int32)} // no frozen record — the ctr-native case

	killed, err := s.killFrozenSource(context.Background(), "pm-ctr-native-test", fakePodUID)
	if err != nil {
		t.Fatalf("killFrozenSource returned an error: %v", err)
	}
	if !killed {
		t.Fatal("expected killed=true via the live-container-PID fallback")
	}
	mu.Lock()
	defer mu.Unlock()
	kills := 0
	for _, op := range opsSeen {
		if op == "kill_source_pid" {
			kills++
		}
	}
	if kills != 1 {
		t.Fatalf("expected exactly 1 kill_source_pid call via the fallback path, got %d (ops: %v)", kills, opsSeen)
	}
}

// realSleepCmdForTest starts a short-lived real child process so tests can exercise the
// broker's proc_alive/starttime path against a genuine target.
func realSleepCmdForTest(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start test child process: %v", err)
	}
	return cmd
}
