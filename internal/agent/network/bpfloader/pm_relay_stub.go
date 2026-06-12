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

// PmRelayObjects is a compile-only stub on non-Linux platforms.
type PmRelayObjects struct {
	PmRelayPrograms
	PmRelayMaps
}

// PmRelayPrograms is a compile-only stub on non-Linux platforms.
type PmRelayPrograms struct {
	PmRelayTcEgress  *ebpf.Program `ebpf:"pm_relay_tc_egress"`
	PmRelayTcIngress *ebpf.Program `ebpf:"pm_relay_tc_ingress"`
}

// PmRelayMaps is a compile-only stub on non-Linux platforms.
type PmRelayMaps struct {
	PmSeqXlat *ebpf.Map `ebpf:"PM_SEQ_XLAT"`
}

func (m *PmRelayObjects) Close()  {}
func (p *PmRelayPrograms) Close() {}
func (m *PmRelayMaps) Close()     {}

// LoadPmRelayObjects is not supported on non-Linux platforms.
func LoadPmRelayObjects(_ interface{}, _ *ebpf.CollectionOptions) error {
	return fmt.Errorf("pm_relay BPF loader not supported on this platform")
}

// LoadPmRelaySpec is not supported on non-Linux platforms.
func LoadPmRelaySpec() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("pm_relay BPF loader not supported on this platform")
}
