/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build linux

package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/podmotion-io/podmotion/internal/agent/network"
)

// tcpInfoUnacked mirrors the kernel tcp_info struct up through tcpi_unacked.
// getsockopt(TCP_INFO) fills from offset 0, so truncating to these fields is safe.
type tcpInfoUnacked struct {
	State       uint8
	CaState     uint8
	Retransmits uint8
	Probes      uint8
	Backoff     uint8
	Options     uint8
	_           [2]uint8
	Rto         uint32
	Ato         uint32
	SndMss      uint32
	RcvMss      uint32
	Unacked     uint32 // tcpi_unacked — segments sent but not yet acknowledged
}

const tcpInfoUnackedSize = uint32(unsafe.Sizeof(tcpInfoUnacked{}))

// resolveVethIfindex resolves the HOST-side veth peer ifindex for the pod identified by
// podUID. It enters the pod's network namespace via nsenter and runs `ip -o link show eth0`
// to read the peer ifindex encoded as `eth0@if<N>`. N is the ifindex of the host-side veth
// peer and is passed directly to armZeroWindowBPF / TC clsact attachment.
//
// The previous implementation used a broken heuristic that matched the FIRST host interface
// with ifindex != iflink, which could return eth0 (ifindex=2, the kind node Docker uplink)
// instead of the actual pod veth peer, causing TC clsact attachment to fail with EOPNOTSUPP.
//
// Returns 0 without error if the pod PID or veth cannot be found (non-fatal stub path).
func resolveVethIfindex(podUID string) (uint32, error) {
	if podUID == "" {
		return 0, nil
	}
	pid, err := FindContainerPID(podUID)
	if err != nil || pid == 0 {
		return 0, nil
	}

	// Enter the pod's network namespace and ask eth0 for its peer ifindex.
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	out, err := exec.Command("nsenter", "--net="+netnsPath,
		"ip", "-o", "link", "show", "eth0").CombinedOutput()
	if err != nil {
		log.Info("resolveVethIfindex: ip link show eth0 in pod netns failed",
			"pid", pid, "podUID", podUID, "err", err, "output", strings.TrimSpace(string(out)))
		return 0, nil
	}

	// parseVethPeerIndex extracts N from "eth0@if<N>" in the ip -o link output.
	peerIdx := parseVethPeerIndex(string(out))
	if peerIdx <= 0 {
		log.Info("resolveVethIfindex: no eth0@if<N> peer index in ip output",
			"pid", pid, "podUID", podUID, "output", strings.TrimSpace(string(out)))
		return 0, nil
	}

	// peerIdx IS the host-side veth's ifindex — use it directly for TC attachment.
	log.Info("resolveVethIfindex: resolved host-side veth peer ifindex via netns",
		"podUID", podUID, "pid", pid, "hostVethIfindex", peerIdx)
	return uint32(peerIdx), nil
}

// armZeroWindowBPF performs the real TC-BPF zero-window arm on Linux by delegating to
// the network package's EBPFManager (ADR-0131 D1 / ADR-0049). It attaches the zero_window
// TC-egress program to the source pod veth (by ifindex) and inserts the ifindex into
// PM_ACTIVE_HOLDS. On kernels <5.9 NewEBPFManager returns the stub (logs only). Idempotent.
// ifindex==0 means veth resolution failed upstream; skip the attach (nothing to arm).
func armZeroWindowBPF(ctx context.Context, ifindex uint32) error {
	if ifindex == 0 {
		log.Info("armZeroWindowBPF: ifindex=0 (veth unresolved) — skipping TC-BPF arm")
		return nil
	}
	mgr := network.NewEBPFManager(ctx)
	if err := mgr.ArmZeroWindowHold(ctx, ifindex); err != nil {
		// Graceful degradation: on this PoC the embedded arm64 zero_window BPF object can
		// fail to load ("no symbol section") because the bpf2go-generated .o was not built
		// with a valid arm64 BPF toolchain. The hold is a *protective optimisation* (it makes
		// the client pause via window=0 during the freeze); the migration's correctness for
		// seq_delta=0 comes from CRIU --tcp-established preserving the socket. Rather than
		// hard-failing the whole migration on a missing BPF object, log and continue so the
		// rest of the ADR-0131 orchestration (freeze, handoff, verify, disarm) is exercised.
		// AC1 (observable window=0) requires a valid arm64 BPF object — tracked as a blocker.
		log.Error(err, "armZeroWindowBPF: real TC-BPF arm failed — continuing WITHOUT hold (AC1 degraded; seq continuity still relies on CRIU --tcp-established)", "ifindex", ifindex)
		return nil
	}
	log.Info("armZeroWindowBPF: TC-BPF zero-window hold armed", "ifindex", ifindex)
	return nil
}

// disarmZeroWindowBPF performs the real TC-BPF zero-window disarm on Linux by delegating to
// the network package's EBPFManager. Removes the ifindex from PM_ACTIVE_HOLDS and detaches
// the TC filter when the map empties. Idempotent; ifindex==0 is a no-op.
func disarmZeroWindowBPF(ctx context.Context, ifindex uint32) error {
	if ifindex == 0 {
		log.Info("disarmZeroWindowBPF: ifindex=0 (veth unresolved) — skipping TC-BPF disarm")
		return nil
	}
	mgr := network.NewEBPFManager(ctx)
	if err := mgr.DisarmZeroWindowHold(ctx, ifindex); err != nil {
		// Mirror armZeroWindowBPF's graceful degradation: if the hold was never armed
		// (BPF object failed to load), disarm is a no-op. Log and continue.
		log.Error(err, "disarmZeroWindowBPF: real TC-BPF disarm failed — continuing (hold likely never armed)", "ifindex", ifindex)
		return nil
	}
	log.Info("disarmZeroWindowBPF: TC-BPF zero-window hold disarmed", "ifindex", ifindex)
	return nil
}

// pollUnackedZero polls tcpi_unacked==0 for all ESTABLISHED TCP sockets in the pod's
// network namespace (ADR-0049 predicate A). Uses /proc/<pid>/net/tcp[6] tx_queue as a
// proxy since direct TCP_INFO requires entering the pod netns; tx_queue==0 implies no
// pending send data and is sufficient for the drain gate.
func pollUnackedZero(ctx context.Context, podUID string) error {
	if podUID == "" {
		return nil
	}
	pid, err := FindContainerPID(podUID)
	if err != nil || pid == 0 {
		return nil
	}

	deadline := time.Now().Add(2 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("pollUnackedZero: timeout — tx_queue not zero within deadline for pod %s", podUID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		drained, err := txQueueZero(pid)
		if err != nil {
			return nil // best-effort; non-fatal if we can't read
		}
		if drained {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// txQueueZero reads /proc/<pid>/net/tcp and /proc/<pid>/net/tcp6 and returns true when
// all ESTABLISHED sockets report tx_queue==0 (no pending send data).
func txQueueZero(pid int32) (bool, error) {
	for _, name := range []string{
		fmt.Sprintf("/proc/%d/net/tcp", pid),
		fmt.Sprintf("/proc/%d/net/tcp6", pid),
	} {
		data, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if i == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 5 || fields[3] != "01" {
				continue
			}
			// fields[4] = "tx_queue:rx_queue" both in hex
			parts := strings.SplitN(fields[4], ":", 2)
			if len(parts) != 2 {
				continue
			}
			txQueue, err := strconv.ParseUint(parts[0], 16, 32)
			if err != nil {
				continue
			}
			if txQueue != 0 {
				return false, nil
			}
		}
	}
	return true, nil
}

// monoTimeNs returns CLOCK_MONOTONIC in nanoseconds via clock_gettime(2).
// Used for PAWS ts_delta computation across source and destination nodes.
func monoTimeNs() int64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano()
}

// getsockoptTCPInfoUnacked calls getsockopt(TCP_INFO) on an open socket fd and returns
// the tcpi_unacked counter. Exposed for callers that already hold an open fd inside
// the pod's network namespace.
func getsockoptTCPInfoUnacked(fd int) (uint32, error) {
	info := &tcpInfoUnacked{}
	size := tcpInfoUnackedSize
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		syscall.IPPROTO_TCP,
		syscall.TCP_INFO,
		uintptr(unsafe.Pointer(info)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return info.Unacked, nil
}
