/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build !linux

package server

import (
	"context"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/network"
)

// resolveVethIfindex is a no-op stub on non-Linux platforms.
func resolveVethIfindex(_ string) (uint32, error) {
	return 0, nil
}

// armZeroWindowBPF is a no-op stub on non-Linux platforms.
// The variadic mgr parameter mirrors the Linux signature for interface compatibility.
func armZeroWindowBPF(_ context.Context, _ uint32, _ string, _ ...network.EBPFManager) error {
	return nil
}

// disarmZeroWindowBPF is a no-op stub on non-Linux platforms.
func disarmZeroWindowBPF(_ context.Context, _ uint32) error {
	return nil
}

// pollUnackedZero is a no-op stub on non-Linux platforms.
func pollUnackedZero(_ context.Context, _ string) error {
	return nil
}

// monoTimeNs returns the current monotonic clock value in nanoseconds.
// On non-Linux, returns wall-clock time as a fallback (acceptable for PAWS ts_delta
// which only needs rough cross-node time ordering).
func monoTimeNs() int64 {
	return time.Now().UnixNano()
}
