/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build linux

package network

import (
	"net"
	"os/exec"
)

// ProbeTCClsact actively tests whether the kernel can attach a clsact qdisc to a
// veth-class interface (RTM_NEWQDISC with "clsact" kind). It creates a transient
// veth pair via "ip link", attempts the attach via ensureClsactQdisc, records
// success or failure, and tears the interfaces down unconditionally via defer.
// Returns true if clsact attach succeeded (capable), false on EOPNOTSUPP or any
// other failure (conservative: fail-safe). (ADR-0169)
func ProbeTCClsact() bool {
	const (
		probeLinkA = "pmprobe-a0"
		probeLinkB = "pmprobe-b0"
	)

	// Clean up any stale probe interfaces from a prior crash.
	_ = exec.Command("ip", "link", "delete", probeLinkA).Run()

	// Create transient veth pair.
	if err := exec.Command("ip", "link", "add",
		probeLinkA, "type", "veth", "peer", "name", probeLinkB).Run(); err != nil {
		// Cannot create veth — conservative: report not capable.
		return false
	}

	// Always tear down on return.
	defer func() {
		_ = exec.Command("ip", "link", "delete", probeLinkA).Run()
	}()

	// Resolve ifindex of the probe interface.
	iface, err := net.InterfaceByName(probeLinkA)
	if err != nil {
		return false
	}
	ifindex := iface.Index

	// Attempt clsact qdisc attach — this is the actual capability test.
	err = ensureClsactQdisc(ifindex)
	return err == nil
}
