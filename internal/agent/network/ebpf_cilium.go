// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package network

import (
	"context"
	"net"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ciliumEBPFManager is the production eBPFManager backed by cilium/ebpf and
// the bpf2go-generated bpfloader bindings.  Kernel ≥5.9 required.
// M20 owns full implementation; this file provides the constructor and
// wires the stub through for the M21 build to compile cleanly.
type ciliumEBPFManager struct {
	stub eBPFManagerStub
}

// newCiliumEBPFManager constructs a ciliumEBPFManager.
// The full attach/detach logic is M20's deliverable; the constructor is here
// so M21 build constraints resolve without a missing symbol.
func newCiliumEBPFManager() eBPFManager {
	return &ciliumEBPFManager{}
}

func (m *ciliumEBPFManager) ArmZeroWindowHold(ctx context.Context, ifindex uint32) error {
	logf.FromContext(ctx).Info("cilium-ebpf: ArmZeroWindowHold", "ifindex", ifindex)
	return m.stub.ArmZeroWindowHold(ctx, ifindex)
}

func (m *ciliumEBPFManager) DisarmZeroWindowHold(ctx context.Context, ifindex uint32) error {
	logf.FromContext(ctx).Info("cilium-ebpf: DisarmZeroWindowHold", "ifindex", ifindex)
	return m.stub.DisarmZeroWindowHold(ctx, ifindex)
}

func (m *ciliumEBPFManager) ArmXDPBridge(ctx context.Context, srcIP, dstIP net.IP, genevePort uint16) error {
	logf.FromContext(ctx).Info("cilium-ebpf: ArmXDPBridge", "srcIP", srcIP, "dstIP", dstIP)
	return m.stub.ArmXDPBridge(ctx, srcIP, dstIP, genevePort)
}

func (m *ciliumEBPFManager) DisarmXDPBridge(ctx context.Context, srcIP net.IP) error {
	logf.FromContext(ctx).Info("cilium-ebpf: DisarmXDPBridge", "srcIP", srcIP)
	return m.stub.DisarmXDPBridge(ctx, srcIP)
}

func (m *ciliumEBPFManager) CheckXDPHookConflict(ctx context.Context, ifindex uint32) (bool, error) {
	return m.stub.CheckXDPHookConflict(ctx, ifindex)
}
