// Copyright 2026 PodMotion Authors.
// Licensed under the Apache License, Version 2.0.

//go:build !linux

package criu

// ptracePreflight is a no-op on non-Linux platforms (CRIU is Linux-only).
func ptracePreflight(_ int32) error {
	return nil
}
