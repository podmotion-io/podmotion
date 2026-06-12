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

// PmSkLookupObjects is a compile-only stub on non-Linux platforms.
type PmSkLookupObjects struct {
	PmSkLookupPrograms
	PmSkLookupMaps
}

// PmSkLookupPrograms is a compile-only stub on non-Linux platforms.
type PmSkLookupPrograms struct {
	PmSkLookup *ebpf.Program `ebpf:"pm_sk_lookup"`
}

// PmSkLookupMaps is a compile-only stub on non-Linux platforms.
type PmSkLookupMaps struct {
	PmSkRedirectMap *ebpf.Map `ebpf:"PM_SK_REDIRECT_MAP"`
}

func (m *PmSkLookupObjects) Close()  {}
func (p *PmSkLookupPrograms) Close() {}
func (m *PmSkLookupMaps) Close()     {}

// LoadPmSkLookupObjects is not supported on non-Linux platforms.
func LoadPmSkLookupObjects(_ interface{}, _ *ebpf.CollectionOptions) error {
	return fmt.Errorf("pm_sk_lookup BPF loader not supported on this platform")
}

// LoadPmSkLookupSpec is not supported on non-Linux platforms.
func LoadPmSkLookupSpec() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("pm_sk_lookup BPF loader not supported on this platform")
}
