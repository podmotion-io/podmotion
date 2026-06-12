// Copyright 2026 PodMotion Authors.
// Licensed under the Apache License, Version 2.0.

//go:build linux

package criu

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// ptracePreflight is intentionally a no-op on Linux for the PoC phase.
//
// The preflight previously called PTRACE_SEIZE + PTRACE_DETACH to probe
// capabilities. However, PTRACE_SEIZE sets a kernel "ptrace-stopped"
// expectation that is not fully cleared by PTRACE_DETACH in all kernel
// versions, leaving the process in a state where CRIU's subsequent
// PTRACE_INTERRUPT returns EPERM.  Removing the preflight lets CRIU manage
// all ptrace state itself without interference.
//
// TODO(podmotion-io/podmotion#<issue>): re-enable preflight using PTRACE_ATTACH / PTRACE_DETACH (not SEIZE) — PTRACE_SEIZE requires CAP_SYS_PTRACE which is not available in all pod security profiles. Track under M15 security hardening.
func ptracePreflight(pid int32) error {
	// Suppress unused import warnings — syscall/unix are kept for future use.
	_ = unix.PTRACE_SEIZE
	_ = syscall.EPERM
	return nil
}
