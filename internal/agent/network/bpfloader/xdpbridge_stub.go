// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !linux

package bpfloader

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// XdpBridgeObjects is a compile-only stub on non-Linux platforms.
type XdpBridgeObjects struct {
	XdpBridgePrograms
	XdpBridgeMaps
	XdpBridgeVariables
}

// XdpBridgePrograms is a compile-only stub on non-Linux platforms.
type XdpBridgePrograms struct {
	PmXdpBridge *ebpf.Program `ebpf:"pm_xdp_bridge"`
}

// XdpBridgeMaps is a compile-only stub on non-Linux platforms.
type XdpBridgeMaps struct {
	PM_BRIDGE_MAP   *ebpf.Map `ebpf:"PM_BRIDGE_MAP"`
	PM_TUNNEL_IFACE *ebpf.Map `ebpf:"PM_TUNNEL_IFACE"`
}

// XdpBridgeVariables is a compile-only stub on non-Linux platforms.
type XdpBridgeVariables struct{}

func (o *XdpBridgeObjects) Close() error  { return nil }
func (p *XdpBridgePrograms) Close() error { return nil }
func (m *XdpBridgeMaps) Close() error     { return nil }

// LoadXdpBridgeObjects is not supported on non-Linux platforms.
func LoadXdpBridgeObjects(_ interface{}, _ *ebpf.CollectionOptions) error {
	return fmt.Errorf("xdp_bridge BPF loader not supported on this platform")
}

// LoadXdpBridge is not supported on non-Linux platforms.
func LoadXdpBridge() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("xdp_bridge BPF loader not supported on this platform")
}
