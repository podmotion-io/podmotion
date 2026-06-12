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

// PmXdpVtepObjects is a compile-only stub on non-Linux platforms.
type PmXdpVtepObjects struct {
	PmXdpVtepPrograms
	PmXdpVtepMaps
}

// PmXdpVtepPrograms is a compile-only stub on non-Linux platforms.
type PmXdpVtepPrograms struct {
	PmXdpVtep     *ebpf.Program `ebpf:"pm_xdp_vtep"`
	PmXdpSrcGuard *ebpf.Program `ebpf:"pm_xdp_src_guard"`
}

// PmXdpVtepMaps is a compile-only stub on non-Linux platforms.
type PmXdpVtepMaps struct {
	PmVtepMap *ebpf.Map `ebpf:"PM_VTEP_MAP"`
}

func (m *PmXdpVtepObjects) Close()  {}
func (p *PmXdpVtepPrograms) Close() {}
func (m *PmXdpVtepMaps) Close()     {}

// LoadPmXdpVtepObjects is not supported on non-Linux platforms.
func LoadPmXdpVtepObjects(_ interface{}, _ *ebpf.CollectionOptions) error {
	return fmt.Errorf("pm_xdp_vtep BPF loader not supported on this platform")
}

// LoadPmXdpVtepSpec is not supported on non-Linux platforms.
func LoadPmXdpVtepSpec() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("pm_xdp_vtep BPF loader not supported on this platform")
}
