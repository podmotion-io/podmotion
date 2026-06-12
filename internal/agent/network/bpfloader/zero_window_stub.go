// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package bpfloader provides bpf2go-generated bindings for PodMotion's eBPF programs.
// On non-Linux platforms all load functions return an error at runtime.
//
//go:build !linux

package bpfloader

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// ZeroWindowObjects contains all objects after they have been loaded into the kernel.
// On non-Linux platforms this is a compile-only stub; LoadZeroWindowObjects always errors.
type ZeroWindowObjects struct {
	ZeroWindowPrograms
	ZeroWindowMaps
}

// ZeroWindowPrograms contains all programs after they have been loaded into the kernel.
type ZeroWindowPrograms struct {
	PmZeroWindowHold *ebpf.Program `ebpf:"pm_zero_window_hold"`
}

// ZeroWindowMaps contains all maps after they have been loaded into the kernel.
type ZeroWindowMaps struct {
	PmActiveHolds *ebpf.Map `ebpf:"PM_ACTIVE_HOLDS"`
}

func (m *ZeroWindowObjects) Close()  {}
func (p *ZeroWindowPrograms) Close() {}
func (m *ZeroWindowMaps) Close()     {}

// LoadZeroWindowObjects is not supported on non-Linux platforms.
func LoadZeroWindowObjects(_ interface{}, _ *ebpf.CollectionOptions) error {
	return fmt.Errorf("zero_window BPF loader not supported on this platform")
}

// LoadZeroWindowSpec is not supported on non-Linux platforms.
func LoadZeroWindowSpec() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("zero_window BPF loader not supported on this platform")
}
