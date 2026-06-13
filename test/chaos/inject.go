//go:build chaos_test

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package chaos

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

// InjectStorageLag injects artificial I/O latency for storage backends on nodeName.
//
// For remote-backed storage (Longhorn gRPC, Ceph librbd, NFS/iSCSI) the latency
// is applied via tc netem on the node's primary network interface (typically eth0
// on kind nodes). This matches the tc netem approach mandated by ADR-0097 §2.
//
// dm-delay is NOT used; it requires mapped devices and is unavailable on Ubuntu 24.04
// kind nodes with kernel 6.x unified cgroup hierarchy.
//
// delayMs is the one-way egress latency in milliseconds.
// Returns a restore function that removes the qdisc when called.
func InjectStorageLag(ctx context.Context, f *FaultFixture, nodeName string, delayMs int) (restore func(), err error) {
	iface := nodeNetIface(nodeName)

	addArgs := []string{
		"exec", nodeName, "--",
		"nsenter", "-t", "1", "-n", "--",
		"tc", "qdisc", "add", "dev", iface, "root", "netem", "delay", fmt.Sprintf("%dms", delayMs),
	}
	if out, err := exec.CommandContext(ctx, "kubectl", addArgs...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("InjectStorageLag tc add on %s: %w: %s", nodeName, err, out)
	}

	restore = func() {
		delArgs := []string{
			"exec", nodeName, "--",
			"nsenter", "-t", "1", "-n", "--",
			"tc", "qdisc", "del", "dev", iface, "root",
		}
		// Best-effort restore; ignore errors (node may already be gone in failure scenarios).
		_ = exec.Command("kubectl", delArgs...).Run()
	}
	return restore, nil
}

// InjectLocalStorageLag throttles the block device on nodeName to triggerMs-speed I/O
// using cgroup v2 io.max. This targets local storage (hostPath, emptyDir, local PV)
// on kind nodes running kernel 6.x with unified cgroup hierarchy.
//
// blkMajMin is the "MAJ:MIN" string for the block device (e.g. "8:0"). The caller
// must obtain this from the kind node (e.g. `ls -la /dev/sda | awk '{print $5":"$6}'`).
// bandwidthBps is the throttle in bytes/sec (e.g. 1048576 for 1 MiB/s).
func InjectLocalStorageLag(ctx context.Context, _ *FaultFixture, nodeName, blkMajMin string, bandwidthBps int) (restore func(), err error) {
	throttleLine := fmt.Sprintf("%s rbps=%d wbps=%d riops=max wiops=max", blkMajMin, bandwidthBps, bandwidthBps)
	addArgs := []string{
		"exec", nodeName, "--",
		"sh", "-c",
		fmt.Sprintf("echo '%s' > /sys/fs/cgroup/system.slice/io.max", throttleLine),
	}
	if out, execErr := exec.CommandContext(ctx, "kubectl", addArgs...).CombinedOutput(); execErr != nil {
		return nil, fmt.Errorf("InjectLocalStorageLag io.max on %s: %w: %s", nodeName, execErr, out)
	}

	restore = func() {
		// Reset by writing "max" bandwidth for both directions.
		resetLine := fmt.Sprintf("%s rbps=max wbps=max riops=max wiops=max", blkMajMin)
		resetArgs := []string{
			"exec", nodeName, "--",
			"sh", "-c",
			fmt.Sprintf("echo '%s' > /sys/fs/cgroup/system.slice/io.max", resetLine),
		}
		_ = exec.Command("kubectl", resetArgs...).Run()
	}
	return restore, nil
}

// InjectNetworkPartition uses tc netem to drop all packets on the named interface
// on nodeName, simulating a full network partition.
// Returns a restore function that removes the loss qdisc.
func InjectNetworkPartition(ctx context.Context, _ *FaultFixture, nodeName, iface string) (restore func(), err error) {
	if iface == "" {
		iface = nodeNetIface(nodeName)
	}
	addArgs := []string{
		"exec", nodeName, "--",
		"nsenter", "-t", "1", "-n", "--",
		"tc", "qdisc", "add", "dev", iface, "root", "netem", "loss", "100%",
	}
	if out, execErr := exec.CommandContext(ctx, "kubectl", addArgs...).CombinedOutput(); execErr != nil {
		return nil, fmt.Errorf("InjectNetworkPartition tc add on %s/%s: %w: %s", nodeName, iface, execErr, out)
	}
	restore = func() {
		delArgs := []string{
			"exec", nodeName, "--",
			"nsenter", "-t", "1", "-n", "--",
			"tc", "qdisc", "del", "dev", iface, "root",
		}
		_ = exec.Command("kubectl", delArgs...).Run()
	}
	return restore, nil
}

// InjectOverlayFault injects a fault into the overlay network path between two nodes.
// It applies a tc netem qdisc with the specified loss and delay parameters on the
// overlay interface (e.g., flannel.1, calico-vxlan, cilium_vxlan) on nodeName.
// This is used by G10 chaos scenarios targeting the OverlayHandoff phase.
func InjectOverlayFault(ctx context.Context, _ *FaultFixture, nodeName, overlayIface string, lossPercent int, delayMs int) (restore func(), err error) {
	netemArgs := buildNetemArgs(lossPercent, delayMs)
	addArgs := append([]string{
		"exec", nodeName, "--",
		"nsenter", "-t", "1", "-n", "--",
		"tc", "qdisc", "add", "dev", overlayIface, "root", "netem",
	}, netemArgs...)

	if out, execErr := exec.CommandContext(ctx, "kubectl", addArgs...).CombinedOutput(); execErr != nil {
		return nil, fmt.Errorf("InjectOverlayFault tc add on %s/%s: %w: %s", nodeName, overlayIface, execErr, out)
	}
	restore = func() {
		delArgs := []string{
			"exec", nodeName, "--",
			"nsenter", "-t", "1", "-n", "--",
			"tc", "qdisc", "del", "dev", overlayIface, "root",
		}
		_ = exec.Command("kubectl", delArgs...).Run()
	}
	return restore, nil
}

// nodeNetIface returns the primary network interface name for a kind node.
// On kind clusters this is typically "eth0".
func nodeNetIface(_ string) string {
	return "eth0"
}

// buildNetemArgs constructs the netem parameter list for tc qdisc add.
func buildNetemArgs(lossPercent int, delayMs int) []string {
	var args []string
	if delayMs > 0 {
		args = append(args, "delay", strconv.Itoa(delayMs)+"ms")
	}
	if lossPercent > 0 {
		args = append(args, "loss", strconv.Itoa(lossPercent)+"%")
	}
	return args
}
