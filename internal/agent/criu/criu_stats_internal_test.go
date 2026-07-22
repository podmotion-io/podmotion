/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package criu

// criu_stats_internal_test.go — fail-closed phase-gate remediation (item 1a/1b) unit coverage.
//
// decodeCRIUStats must fail closed (return an error, never a silent 0) whenever the CRIU
// --stats image is absent or cannot be decoded. This exercises exactly that real failure
// scenario — an ImagesDir with no stats-dump/stats-restore file at all, the same situation
// PreDump would hit today given the pre-fix stub. Requires python3 + pycriu importable in the
// test environment (same runtime requirement as the production code path and the sibling
// pycriu-based tests in internal/agent/server).

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// resolveRepoPycriuPathForCRIUTest mirrors resolveRepoPycriuPath (internal/agent/server/
// pycriu_corpus_test.go) — walks up from cwd to the module root (go.mod) so the vendored
// pycriu/ tree is importable outside the production agent-image path.
func resolveRepoPycriuPathForCRIUTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod / module root")
		}
		dir = parent
	}
}

func requirePycriu(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("pycriu decode is Linux-only")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	candidates := []string{"/usr/lib/python3/dist-packages", resolveRepoPycriuPathForCRIUTest(t)}
	for _, p := range candidates {
		cmd := exec.Command("python3", "-c", "import pycriu")
		cmd.Env = append(os.Environ(), "PYTHONPATH="+p)
		if err := cmd.Run(); err == nil {
			pycriuPythonPath = p
			return
		}
	}
	t.Skip("pycriu not importable in this environment")
}

// TestDecodeCRIUStats_MissingImage_FailsClosed asserts that an ImagesDir with no
// stats-dump/stats-restore file produces an error, never a fabricated (0, nil) —
// the exact class of bug this remediation item closes.
func TestDecodeCRIUStats_MissingImage_FailsClosed(t *testing.T) {
	requirePycriu(t)

	dir := t.TempDir()
	mb, err := decodeCRIUStats(dir)
	if err == nil {
		t.Fatalf("expected decodeCRIUStats to fail closed on missing stats image, got (%d, nil)", mb)
	}
}
