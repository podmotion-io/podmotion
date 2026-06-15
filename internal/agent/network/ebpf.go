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

// SeqXlatKey is the 4-tuple key for PM_SEQ_XLAT map entries.
type SeqXlatKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

// SeqXlatEntry holds the sequence/ack/timestamp translation deltas for one
// migrated TCP connection.  Fields are in host byte order.
type SeqXlatEntry struct {
	SeqDelta    int32
	AckDelta    int32
	TsDelta     int32
	Wscale      uint8
	SackPresent uint8
	// State: 0=inactive, 1=active, 2=teardown.
	State uint8
}

// VtepEntry describes the destination VTEP for a migrated pod IP.
type VtepEntry struct {
	DstVtepIP  [4]byte
	DstIfindex uint32
	VNI        uint32
}

// EBPFManager is the exported interface for callers outside the network package
// (e.g. internal/agent/server) that need to arm/disarm eBPF programs.
// It is identical to the unexported eBPFManager.
type EBPFManager interface {
	// EnsureXDPBridgeLoaded loads and pins the xdp_bridge program at node startup.
	// It is idempotent: if the pins already exist and the XDP link is live it
	// adopts the existing state without reloading.  hostIfname is the host-side
	// network interface (e.g. "eth0") to attach the XDP program to.
	// If xdpBridgeCapable is false the call is a no-op (returns nil).
	EnsureXDPBridgeLoaded(ctx context.Context, hostIfname string, xdpBridgeCapable bool) error
	ArmZeroWindowHold(ctx context.Context, ifindex uint32) error
	DisarmZeroWindowHold(ctx context.Context, ifindex uint32) error
	ArmXDPBridge(ctx context.Context, srcIP, dstIP net.IP, genevePort uint16) error
	DisarmXDPBridge(ctx context.Context, srcIP net.IP) error
	CheckXDPHookConflict(ctx context.Context, ifindex uint32) (bool, error)
	// ArmRelay attaches PM_RELAY_TC_EGRESS and PM_RELAY_TC_INGRESS to flannel.1
	// (or the interface named by ifname) and seeds PM_SEQ_XLAT with the provided entry.
	ArmRelay(ctx context.Context, ifname string, key SeqXlatKey, entry SeqXlatEntry) error
	// DisarmRelay removes the PM_SEQ_XLAT entry for key and detaches relay programs
	// when no entries remain.
	DisarmRelay(ctx context.Context, key SeqXlatKey) error
	// ArmVTEP populates PM_VTEP_MAP and attaches PM_XDP_VTEP to the destination
	// VTEP interface (dstIfname) and PM_XDP_SRC_GUARD to the source interface (srcIfname).
	ArmVTEP(ctx context.Context, podIP net.IP, ve VtepEntry, dstIfname, srcIfname string) error
	// DisarmVTEP removes the PM_VTEP_MAP entry for podIP.
	DisarmVTEP(ctx context.Context, podIP net.IP) error
	// PatchRelayTsDelta performs a read-modify-write on PM_SEQ_XLAT for the given key,
	// updating only the ts_delta field while preserving the existing seq_delta/ack_delta.
	// If the entry does not exist it is a no-op (returns nil).
	// This must be called INSTEAD of ArmRelay when only ts_delta needs to be updated.
	PatchRelayTsDelta(ctx context.Context, key SeqXlatKey, tsDelta int32) error
}

// eBPFManager is the interface consumed by NetworkBridgeAgent.
// Production implementation loads real BPF objects; stub logs only.
type eBPFManager interface {
	// EnsureXDPBridgeLoaded loads and pins the xdp_bridge program at node startup.
	EnsureXDPBridgeLoaded(ctx context.Context, hostIfname string, xdpBridgeCapable bool) error

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

	// ArmRelay attaches relay TC programs to ifname and seeds PM_SEQ_XLAT.
	ArmRelay(ctx context.Context, ifname string, key SeqXlatKey, entry SeqXlatEntry) error

	// DisarmRelay removes the PM_SEQ_XLAT entry and detaches when map is empty.
	DisarmRelay(ctx context.Context, key SeqXlatKey) error

	// ArmVTEP populates PM_VTEP_MAP and attaches XDP programs.
	ArmVTEP(ctx context.Context, podIP net.IP, ve VtepEntry, dstIfname, srcIfname string) error

	// DisarmVTEP removes the PM_VTEP_MAP entry for podIP.
	DisarmVTEP(ctx context.Context, podIP net.IP) error

	// PatchRelayTsDelta performs a read-modify-write on PM_SEQ_XLAT for the given key,
	// updating only the ts_delta field while preserving the existing seq_delta/ack_delta.
	PatchRelayTsDelta(ctx context.Context, key SeqXlatKey, tsDelta int32) error
}

// NewEBPFManager is the exported constructor for callers outside the network
// package.  It selects the real cilium/ebpf manager on kernel ≥5.9; otherwise
// returns the no-op stub.
func NewEBPFManager(ctx context.Context) EBPFManager {
	return newEBPFManager(ctx)
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

func (s *eBPFManagerStub) EnsureXDPBridgeLoaded(ctx context.Context, hostIfname string, xdpBridgeCapable bool) error {
	logf.FromContext(ctx).Info("ebpf stub: EnsureXDPBridgeLoaded (no-op)", "hostIfname", hostIfname, "xdpBridgeCapable", xdpBridgeCapable)
	return nil
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

func (s *eBPFManagerStub) ArmRelay(ctx context.Context, ifname string, key SeqXlatKey, entry SeqXlatEntry) error {
	logf.FromContext(ctx).Info("ebpf stub: ArmRelay", "ifname", ifname, "srcPort", key.SrcPort, "dstPort", key.DstPort)
	return nil
}

func (s *eBPFManagerStub) DisarmRelay(ctx context.Context, key SeqXlatKey) error {
	logf.FromContext(ctx).Info("ebpf stub: DisarmRelay", "srcPort", key.SrcPort, "dstPort", key.DstPort)
	return nil
}

func (s *eBPFManagerStub) ArmVTEP(ctx context.Context, podIP net.IP, ve VtepEntry, dstIfname, srcIfname string) error {
	logf.FromContext(ctx).Info("ebpf stub: ArmVTEP", "podIP", podIP, "dstIfname", dstIfname, "srcIfname", srcIfname)
	return nil
}

func (s *eBPFManagerStub) DisarmVTEP(ctx context.Context, podIP net.IP) error {
	logf.FromContext(ctx).Info("ebpf stub: DisarmVTEP", "podIP", podIP)
	return nil
}

func (s *eBPFManagerStub) PatchRelayTsDelta(ctx context.Context, key SeqXlatKey, tsDelta int32) error {
	logf.FromContext(ctx).Info("ebpf stub: PatchRelayTsDelta", "srcPort", key.SrcPort, "dstPort", key.DstPort, "tsDelta", tsDelta)
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
