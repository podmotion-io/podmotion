/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build !linux

package network

// newCiliumEBPFManager returns the stub on non-Linux platforms.
// newEBPFManager already returns the stub via the kernel version check on
// non-Linux (LinuxVersionCode errors), so this path is only reached during
// cross-compilation testing.
func newCiliumEBPFManager() eBPFManager {
	return &eBPFManagerStub{}
}
