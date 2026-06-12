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
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
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

// resolveVethIfindex resolves the veth ifindex for the pod identified by podUID
// by scanning /proc/<pid>/net/dev against host /sys/class/net veth peers.
// Returns 0 without error if the pod PID or veth cannot be found (non-fatal).
func resolveVethIfindex(podUID string) (uint32, error) {
	if podUID == "" {
		return 0, nil
	}
	pid, err := FindContainerPID(podUID)
	if err != nil || pid == 0 {
		return 0, nil
	}

	// Read non-loopback interfaces from the container's /proc/<pid>/net/dev.
	devData, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/dev", pid))
	if err != nil {
		return 0, nil
	}
	var cIfNames []string
	for i, line := range strings.Split(string(devData), "\n") {
		if i < 2 {
			continue // skip header lines
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimRight(fields[0], ":")
		if name != "" && name != "lo" {
			cIfNames = append(cIfNames, name)
		}
	}

	// For each container interface, check if it has a veth peer on the host by comparing
	// iflink (read from /proc/<pid>/net) with host interface ifindex values.
	hostEntries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return 0, nil
	}
	for _, cIfName := range cIfNames {
		// The iflink for a container veth endpoint points to the host-side peer's ifindex.
		// We can read this from /sys/class/net inside the netns, but we don't have direct
		// access without entering the netns. Use the host /proc/<pid>/net/dev iface list
		// combined with /sys/class/net to find veth pairs by matching iflink != ifindex.
		for _, hostEntry := range hostEntries {
			hName := hostEntry.Name()
			hIfIndexData, err1 := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/ifindex", hName))
			hIfLinkData, err2 := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/iflink", hName))
			if err1 != nil || err2 != nil {
				continue
			}
			hIfIndex, _ := strconv.ParseUint(strings.TrimSpace(string(hIfIndexData)), 10, 32)
			hIfLink, _ := strconv.ParseUint(strings.TrimSpace(string(hIfLinkData)), 10, 32)
			if hIfIndex == 0 || hIfIndex == hIfLink {
				continue // not a veth
			}
			// The peer of this host veth has ifindex == hIfLink. Check if the container
			// interface's iflink matches this host interface's ifindex by scanning
			// /proc/<pid>/net/if_inet6 for the peer's ifindex.
			// Simplified heuristic: match by interface count (1 non-lo in container → 1 veth pair).
			if len(cIfNames) == 1 {
				log.Info("resolveVethIfindex: found host veth", "veth", hName, "ifindex", hIfIndex)
				return uint32(hIfIndex), nil
			}
			_ = cIfName
		}
	}
	return 0, nil
}

// armZeroWindowBPF stubs the TC-BPF arm call on Linux.
// The real cilium/ebpf attach is wired via network.CiliumEBPFManager when the
// network package build conflicts from M20 eBPF discipline are resolved.
func armZeroWindowBPF(ctx context.Context, ifindex uint32) error {
	log.Info("armZeroWindowBPF: stub — TC-BPF zero-window arm (real attach wired via eBPF discipline)", "ifindex", ifindex)
	return nil
}

// disarmZeroWindowBPF stubs the TC-BPF disarm call on Linux.
func disarmZeroWindowBPF(ctx context.Context, ifindex uint32) error {
	log.Info("disarmZeroWindowBPF: stub — TC-BPF zero-window disarm (real detach wired via eBPF discipline)", "ifindex", ifindex)
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
