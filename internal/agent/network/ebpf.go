/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package network owns all network-layer agent code for PodMotion (Agent 2).
//
// eBPF programs are compiled from bpf/ and loaded on the SOURCE NODE only,
// not inside any container.  The cilium/ebpf library is used as the Go-side
// loader/map interface; the actual .o objects are embedded at build time via
// bpf2go-generated files (bpf/ Makefile target "generate").
//
// ADR-0017: TCP preservation (zero-window hold + XDP bridge) is v0.2.
// In v0.1 (TIER_4) the eBPFManagerStub is wired and all methods are no-ops.
package network

import (
	"context"
	"fmt"
	"net"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// eBPFManager is the interface consumed by NetworkBridgeAgent.
// Production implementation loads real BPF objects; stub logs only.
type eBPFManager interface {
	// ArmZeroWindowHold loads zero_window.bpf.o on the TC egress hook of the
	// veth identified by ifindex, then inserts ifindex into PM_ACTIVE_HOLDS.
	// Idempotent — safe to call again if the hold is already armed.
	ArmZeroWindowHold(ctx context.Context, ifindex uint32) error

	// DisarmZeroWindowHold removes ifindex from PM_ACTIVE_HOLDS.
	// If the map becomes empty the TC filter is detached to avoid spurious work.
	DisarmZeroWindowHold(ctx context.Context, ifindex uint32) error

	// ArmXDPBridge populates PM_BRIDGE_MAP with srcIP→{dstIP, genevePort} and
	// attaches the XDP program to the ingress path of the underlay interface.
	// genevePort is in host byte order.
	ArmXDPBridge(ctx context.Context, srcIP, dstIP net.IP, genevePort uint16) error

	// DisarmXDPBridge deletes the srcIP entry from PM_BRIDGE_MAP.
	// If the map is empty afterwards the XDP program is detached.
	DisarmXDPBridge(ctx context.Context, srcIP net.IP) error
}

// eBPFManagerStub satisfies eBPFManager by logging intended operations only.
// Used in v0.1 (TIER_4) and in unit/integration tests where loading real BPF
// objects is impossible without a privileged kernel context.
type eBPFManagerStub struct{}

func (s *eBPFManagerStub) ArmZeroWindowHold(ctx context.Context, ifindex uint32) error {
	logf.FromContext(ctx).Info("ebpf stub: ArmZeroWindowHold", "ifindex", ifindex)
	return nil
}

func (s *eBPFManagerStub) DisarmZeroWindowHold(ctx context.Context, ifindex uint32) error {
	logf.FromContext(ctx).Info("ebpf stub: DisarmZeroWindowHold", "ifindex", ifindex)
	return nil
}

func (s *eBPFManagerStub) ArmXDPBridge(ctx context.Context, srcIP, dstIP net.IP, genevePort uint16) error {
	logf.FromContext(ctx).Info("ebpf stub: ArmXDPBridge",
		"srcIP", srcIP, "dstIP", dstIP, "genevePort", genevePort)
	return nil
}

func (s *eBPFManagerStub) DisarmXDPBridge(ctx context.Context, srcIP net.IP) error {
	logf.FromContext(ctx).Info("ebpf stub: DisarmXDPBridge", "srcIP", srcIP)
	return nil
}

// resolveIfindex converts an interface name (e.g. "veth1a2b3c") to its kernel ifindex.
// Used by the production eBPF manager; exposed here so bridge.go can use it without
// depending on the concrete manager type.
func resolveIfindex(ifname string) (uint32, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return 0, fmt.Errorf("ifindex lookup %q: %w", ifname, err)
	}
	return uint32(iface.Index), nil
}
