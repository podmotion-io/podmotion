/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// resolveNetnsBindByProcPathScript returns the EXACT shell script body used by
// resolveNetnsBindByProcPath in server.go (ADR-0325). Kept as a single source string here so a
// drift between this test and the production script is caught by comparing against the literal
// substring below, rather than only trusting a hand-copy.
func resolveNetnsBindByProcPathScript(procPath string) string {
	return fmt.Sprintf(
		`want=$(stat -L -c %%i %q 2>/dev/null); [ -z "$want" ] && exit 0; `+
			`for f in /var/run/netns/*; do i=$(stat -L -c %%i "$f" 2>/dev/null); `+
			`if [ "$i" = "$want" ]; then printf '%%s\n' "$f"; break; fi; done`,
		procPath)
}

// TestResolveNetnsBindByProcPathScript_MatchesProductionSourceText guards against silent drift
// between the test's copy of the inode-matching shell script and the literal text compiled into
// resolveNetnsBindByProcPath in server.go. If someone edits the production script without
// updating this test's copy, this test fails loudly rather than the test suite silently
// exercising stale logic.
func TestResolveNetnsBindByProcPathScript_MatchesProductionSourceText(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("reading server.go: %v", err)
	}
	// The literal format-string fragments that make up the production script, as they appear
	// in the Go source (with %% escaping preserved, since this is the fmt.Sprintf format string
	// itself, not its interpolated output).
	fragment1 := `want=$(stat -L -c %%i %q 2>/dev/null); [ -z "$want" ] && exit 0; `
	fragment2 := `for f in /var/run/netns/*; do i=$(stat -L -c %%i "$f" 2>/dev/null); `
	fragment3 := `if [ "$i" = "$want" ]; then printf '%%s\n' "$f"; break; fi; done`
	for _, frag := range []string{fragment1, fragment2, fragment3} {
		if !strings.Contains(string(src), frag) {
			t.Fatalf("resolveNetnsBindByProcPath production script fragment not found verbatim in server.go (drifted?): %q", frag)
		}
	}
}

// runInodeMatchScript executes the ADR-0325 inode-matching shell script against a real local
// filesystem (no broker/host-mount-namespace hop needed — the script itself is pure POSIX shell
// + stat, exercised here directly via /bin/sh, which is exactly the interpreter nsenterCmd hands
// the script to in production). This validates the SCRIPT LOGIC (empty netns dir, no match,
// exact-inode match) independent of the privileged broker plumbing, which cannot be exercised in
// a unit test.
func runInodeMatchScript(t *testing.T, procPath, netnsDir string) string {
	t.Helper()
	script := resolveNetnsBindByProcPathScript(procPath)
	// Rewrite the hard-coded /var/run/netns to our temp dir so the test is hermetic — this
	// preserves the exact matching logic while pointing the glob at a sandboxed directory.
	script = strings.ReplaceAll(script, "/var/run/netns/*", netnsDir+"/*")
	out, err := exec.Command("sh", "-c", script).Output()
	if err != nil {
		t.Fatalf("running inode-match script: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// TestInodeMatchScript_ExactMatchFound asserts that when a candidate bind file shares the same
// inode as the target path (simulated here with a hard link, since real netns bind mounts are
// unavailable/unprivileged in a unit-test sandbox but hard links share inode numbers exactly the
// same way stat -c %i reports), the script prints that candidate's path.
func TestInodeMatchScript_ExactMatchFound(t *testing.T) {
	dir := t.TempDir()
	netnsDir := filepath.Join(dir, "netns")
	if err := os.Mkdir(netnsDir, 0o755); err != nil {
		t.Fatalf("mkdir netnsDir: %v", err)
	}

	target := filepath.Join(dir, "target-file")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	// A decoy candidate with a DIFFERENT inode (should NOT match).
	decoy := filepath.Join(netnsDir, "cni-decoy")
	if err := os.WriteFile(decoy, []byte("y"), 0o644); err != nil {
		t.Fatalf("write decoy: %v", err)
	}

	// The real match candidate: a hard link to target (same inode).
	match := filepath.Join(netnsDir, "cni-real-match")
	if err := os.Link(target, match); err != nil {
		t.Fatalf("hard link match: %v", err)
	}

	got := runInodeMatchScript(t, target, netnsDir)
	if got != match {
		t.Fatalf("inode-match script: got %q, want %q (decoy=%q must not have matched)", got, match, decoy)
	}
}

// TestInodeMatchScript_NoMatchReturnsEmpty asserts that when no candidate shares the target's
// inode, the script prints nothing (the caller then falls back to the raw proc path).
func TestInodeMatchScript_NoMatchReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	netnsDir := filepath.Join(dir, "netns")
	if err := os.Mkdir(netnsDir, 0o755); err != nil {
		t.Fatalf("mkdir netnsDir: %v", err)
	}

	target := filepath.Join(dir, "target-file")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	decoy := filepath.Join(netnsDir, "cni-decoy")
	if err := os.WriteFile(decoy, []byte("y"), 0o644); err != nil {
		t.Fatalf("write decoy: %v", err)
	}

	got := runInodeMatchScript(t, target, netnsDir)
	if got != "" {
		t.Fatalf("inode-match script: expected empty output on no match, got %q", got)
	}
}

// TestInodeMatchScript_TargetMissing_ExitsCleanWithEmptyOutput asserts the `[ -z "$want" ] && exit
// 0` guard: when stat on the target path itself fails (nonexistent proc path — e.g. the pause
// process already exited), the script must exit cleanly with empty output, not error out into
// glob-expansion of a literal "/var/run/netns/*" or otherwise crash.
func TestInodeMatchScript_TargetMissing_ExitsCleanWithEmptyOutput(t *testing.T) {
	dir := t.TempDir()
	netnsDir := filepath.Join(dir, "netns")
	if err := os.Mkdir(netnsDir, 0o755); err != nil {
		t.Fatalf("mkdir netnsDir: %v", err)
	}
	missingTarget := filepath.Join(dir, "does-not-exist")

	got := runInodeMatchScript(t, missingTarget, netnsDir)
	if got != "" {
		t.Fatalf("inode-match script: expected empty output when target stat fails, got %q", got)
	}
}

// TestInodeMatchScript_EmptyNetnsDir_NoGlobLiteralLeak guards against the classic unquoted-glob
// bug: when the netns directory has zero entries, `for f in DIR/*` in POSIX sh (without nullglob)
// expands to the literal unmatched pattern "DIR/*" and iterates it ONCE as a nonexistent path.
// The script must not treat that literal pattern as a false match — it must still print nothing.
func TestInodeMatchScript_EmptyNetnsDir_NoGlobLiteralLeak(t *testing.T) {
	dir := t.TempDir()
	netnsDir := filepath.Join(dir, "netns-empty")
	if err := os.Mkdir(netnsDir, 0o755); err != nil {
		t.Fatalf("mkdir netnsDir: %v", err)
	}

	target := filepath.Join(dir, "target-file")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	got := runInodeMatchScript(t, target, netnsDir)
	if got != "" {
		t.Fatalf("inode-match script: expected empty output against an empty netns directory (unquoted-glob-literal must not falsely match), got %q", got)
	}
}
