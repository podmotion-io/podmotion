/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build !linux

package server

import (
	"context"
)

// resolveVethIfindex is a no-op stub on non-Linux platforms.
func resolveVethIfindex(_ string) (uint32, error) {
	return 0, nil
}

// armZeroWindowBPF is a no-op stub on non-Linux platforms.
func armZeroWindowBPF(_ context.Context, _ uint32) error {
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
