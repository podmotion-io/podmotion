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
// bpf2go-generated files in internal/agent/network/bpfloader/.
//
// ADR-0048/ADR-0049: cilium/ebpf is the production loader for kernel ≥5.9.
// Below that threshold (or in unit tests) the eBPFManagerStub is used.
package network

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/ebpf/features"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// kernelVersion59 is the LINUX_VERSION_CODE for 5.9.0, the minimum kernel
// required for BTF-enabled CO-RE programs used by the cilium/ebpf loader.
const kernelVersion59 = (5 << 16) | (9 << 8) | 0

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

	// CheckXDPHookConflict returns true when another XDP program (e.g. Cilium's
	// kube-proxy-replacement XDP hook) is already attached to the interface
	// identified by ifindex. Used by NetworkBridgeAgent to detect Cilium XDP
	// conflicts and fall back to TC ingress mode.
	CheckXDPHookConflict(ctx context.Context, ifindex uint32) (bool, error)
}

// newEBPFManager selects the production cilium/ebpf manager when the running
// kernel is ≥5.9, otherwise returns the stub.  Callers should use this rather
// than constructing either type directly.
func newEBPFManager(ctx context.Context) eBPFManager {
	log := logf.FromContext(ctx)
	code, err := features.LinuxVersionCode()
	if err != nil {
		log.Info("ebpf kernel version detection failed, using stub", "err", err)
		return &eBPFManagerStub{}
	}
	major := (code >> 16) & 0xff
	minor := (code >> 8) & 0xff
	patch := code & 0xff
	kernelStr := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	if code < kernelVersion59 {
		log.Info("ebpf kernel below 5.9, using stub", "kernel", kernelStr)
		return &eBPFManagerStub{}
	}
	log.Info("ebpf loader=cilium-ebpf", "kernel", kernelStr)
	return newCiliumEBPFManager()
}

// eBPFManagerStub satisfies eBPFManager by logging intended operations only.
// Use NewStubEBPFManager when a real kernel context is unavailable (unit tests,
// TIER_4 explicit opt-in, kernel <5.9 fallback).
type eBPFManagerStub struct{}

// NewStubEBPFManager returns the explicit stub for callers that need to opt
// out of the cilium/ebpf loader (unit tests, integration harnesses).
func NewStubEBPFManager() eBPFManager {
	return &eBPFManagerStub{}
}

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

func (s *eBPFManagerStub) CheckXDPHookConflict(ctx context.Context, ifindex uint32) (bool, error) {
	logf.FromContext(ctx).Info("ebpf stub: CheckXDPHookConflict", "ifindex", ifindex)
	return false, nil
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
