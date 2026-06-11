// Copyright 2026 PodMotion Authors.
// Licensed under the Apache License, Version 2.0.

//go:build linux

package criu

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// ptracePreflight tries PTRACE_SEIZE on pid — the same first syscall CRIU
// issues. If it fails we get the exact errno before any CRIU RPC is started,
// surfacing CAP_SYS_PTRACE / seccomp issues immediately.
func ptracePreflight(pid int32) error {
	err := unix.PtraceSeize(int(pid))
	if err != nil {
		errno, _ := err.(syscall.Errno)
		return fmt.Errorf(
			"ptrace(PTRACE_SEIZE, %d) failed: %w (errno=%d) — check CAP_SYS_PTRACE and seccomp profile",
			pid, err, errno,
		)
	}
	// Detach immediately — this was only a capability probe.
	_ = unix.PtraceDetach(int(pid))
	return nil
}
