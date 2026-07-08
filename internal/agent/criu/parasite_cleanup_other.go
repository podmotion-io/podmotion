// Copyright 2026 PodMotion Authors.
// Licensed under the Apache License, Version 2.0.

//go:build !linux || !amd64

package criu

import "errors"

// errParasiteCleanupUnsupported is returned by CleanupLeakedParasiteMemfds on
// platforms other than linux/amd64. PodMotion's CRIU-supported scope is
// Linux/amd64 only (ADR-0146, ADR-0153); the ptrace-based remote-munmap
// implementation in parasite_cleanup.go uses amd64-specific register layouts
// (golang.org/x/sys/unix.PtraceRegsAmd64) and is not portable to arm64/darwin
// builds of the manager/operator binary, which never invoke CRIU directly.
var errParasiteCleanupUnsupported = errors.New("CleanupLeakedParasiteMemfds: unsupported on this platform (linux/amd64 only)")

// CleanupLeakedParasiteMemfds is a no-op stub on non-linux/amd64 platforms. See
// parasite_cleanup.go for the real implementation and its rationale
// (docs/sprints/SPRINT41-NR-BLOCK-2-POD-SCOPE-INVESTIGATION.md).
func CleanupLeakedParasiteMemfds(_ int32) (int, error) {
	return 0, errParasiteCleanupUnsupported
}
