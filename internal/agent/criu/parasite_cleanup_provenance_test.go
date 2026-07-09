// Copyright 2026 PodMotion Authors.
// Licensed under the Apache License, Version 2.0.

//go:build linux && amd64

package criu

// Provenance pin for ADR "Provenance pinning for the two Sprint 41 abort-path
// regression proofs" (D1).
//
// This test does not exercise runtime behavior. It reads source files at test
// time and asserts that the CRIU parasite-memfd leak-cleanup mechanism, and
// all five real production call sites of CleanupLeakedParasiteMemfds, are
// still present and wired the way this ADR recorded. It exists so that a
// future refactor which silently drops a call site (or renames the guard
// marker/mechanism this cleanup depends on) fails a fast, cheap, always-run
// unit test instead of only surfacing as a leaked-memfd defect much later.
//
// Remediation guidance: if this test fails after an intentional rename of a
// guarded symbol (criuParasiteMemfdName, withPtraceAttach, unix.PtraceAttach,
// or CleanupLeakedParasiteMemfds itself) or after an intentional removal/
// relocation of one of the five call sites, update the pinned string/marker
// here to match the new source of truth — do not treat this as an ordinary
// broken test to be silenced or deleted. If a call site was removed because
// the corresponding failure path no longer exists, that is a real regression
// in leak-cleanup coverage and must be raised, not papered over here.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProvenance_ParasiteCleanupMechanismMarkers pins the on-disk presence of
// the CRIUMFD marker and the ptrace-attach mechanism that
// CleanupLeakedParasiteMemfds relies on.
func TestProvenance_ParasiteCleanupMechanismMarkers(t *testing.T) {
	src, err := os.ReadFile("parasite_cleanup.go")
	if err != nil {
		t.Fatalf("failed to read parasite_cleanup.go: %v", err)
	}
	content := string(src)

	for _, marker := range []string{
		`criuParasiteMemfdName`,
		`/memfd:CRIUMFD (deleted)`,
		`withPtraceAttach`,
		`unix.PtraceAttach`,
		`func CleanupLeakedParasiteMemfds(pid int32) (int, error)`,
	} {
		if !strings.Contains(content, marker) {
			t.Errorf("parasite_cleanup.go: expected marker %q not found — mechanism this ADR pinned may have been renamed or removed; see file doc comment for remediation guidance", marker)
		}
	}
}

// TestProvenance_ParasiteCleanupCallSites pins all five real production call
// sites of CleanupLeakedParasiteMemfds: three same-package call sites in
// criu_checkpointer.go, and two cross-package call sites in
// internal/agent/server/server.go.
func TestProvenance_ParasiteCleanupCallSites(t *testing.T) {
	// Same-package call sites (internal/agent/criu/criu_checkpointer.go).
	checkpointerSrc, err := os.ReadFile("criu_checkpointer.go")
	if err != nil {
		t.Fatalf("failed to read criu_checkpointer.go: %v", err)
	}
	sameCall := `CleanupLeakedParasiteMemfds(opts.Pid)`
	if got := strings.Count(string(checkpointerSrc), sameCall); got < 3 {
		t.Errorf("criu_checkpointer.go: expected at least 3 call sites of %q (pre-dump-failure, dump-failure, silent-dump-failure), found %d", sameCall, got)
	}

	// Cross-package call sites (internal/agent/server/server.go), read via an
	// explicit relative path from this test file's own runtime.Caller
	// directory so the assertion does not depend on the test's working
	// directory at run time.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed to resolve this test file's path")
	}
	serverPath := filepath.Join(filepath.Dir(thisFile), "..", "server", "server.go")
	serverSrc, err := os.ReadFile(serverPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", serverPath, err)
	}
	qualifiedCall := `criu.CleanupLeakedParasiteMemfds(`
	if got := strings.Count(string(serverSrc), qualifiedCall); got < 2 {
		t.Errorf("%s: expected at least 2 call sites of %q, found %d", serverPath, qualifiedCall, got)
	}
}

// TestProvenance_NonLinuxStubNotPinnedForCallSites documents, deliberately,
// that parasite_cleanup_other.go's non-Linux/non-amd64 stub is NOT pinned for
// call-site presence by this ADR — the stub is a no-op by design and carries
// no leak-cleanup call sites to protect.
func TestProvenance_NonLinuxStubNotPinnedForCallSites(t *testing.T) {
	t.Log("parasite_cleanup_other.go is intentionally excluded from call-site provenance pinning: it is a non-linux/amd64 no-op stub with no production call sites to protect")
}
