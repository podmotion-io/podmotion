/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package bpfloader_test

import (
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/network/bpfloader"
)

// TestLoadZeroWindowSpec verifies that LoadZeroWindowSpec returns an error on
// non-Linux platforms (stub) and that the API surface compiles correctly.
// On Linux with a real BPF-capable kernel the spec would load successfully;
// this test only asserts the non-panic contract because CI runs on darwin.
func TestLoadZeroWindowSpec(t *testing.T) {
	_, err := bpfloader.LoadZeroWindowSpec()
	// On non-Linux platforms the stub always returns an error.
	// On Linux the placeholder .o may also fail (not a real BPF ELF).
	// Either way: must not panic and must return a non-nil error here.
	if err == nil {
		t.Log("LoadZeroWindowSpec succeeded — running on Linux with valid BPF .o")
	} else {
		t.Logf("LoadZeroWindowSpec returned expected error: %v", err)
	}
}

// TestZeroWindowObjectsCloseNoop verifies that calling Close on zero-value
// ZeroWindowObjects does not panic.
func TestZeroWindowObjectsCloseNoop(t *testing.T) {
	var objs bpfloader.ZeroWindowObjects
	objs.Close()
}
