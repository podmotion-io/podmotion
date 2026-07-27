/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestGodebugDirectivePresentInSource is a source-of-truth guard (ADR-0411 D1).
//
// The whole fix is a single //go:debug containermaxprocs=0 directive that MUST sit in the
// comment group immediately preceding `package main` — the only placement the Go toolchain
// honors. This test fails loudly if the directive is removed, reworded, or separated from the
// package clause by a blank line (any of which silently re-introduces the Go 1.25 cgroup-aware
// GOMAXPROCS fd that fails a holder-rooted CRIU dump at criu/files-reg.c:1790).
func TestGodebugDirectivePresentInSource(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	// The directive must be the last comment line immediately above `package main`,
	// with no blank line between them (Go only honors it in that contiguous position).
	re := regexp.MustCompile(`(?m)^//go:debug containermaxprocs=0\npackage main$`)
	if !re.Match(src) {
		t.Fatalf("//go:debug containermaxprocs=0 directive not found immediately preceding `package main` in cmd/holder/main.go; " +
			"the ADR-0411 fix has regressed — a holder-rooted CRIU dump will abort on the host-cgroupns cpu.max fd")
	}
}

// TestGodebugHonoredInBuiltBinary is the load-bearing property from ADR-0411 §7.1: the directive
// must actually be BAKED INTO the built binary's DefaultGODEBUG on the file-argument build path
// the Makefile uses (`go build ./cmd/holder/main.go`). A source directive that the toolchain does
// not honor would pass the source guard above yet leave the fd (and the dump failure) in place.
//
// This builds the holder exactly as `make build-linux` does and reads the directive back with
// `go version -m`, matching the provenance grep the ADR gates promotion on.
func TestGodebugHonoredInBuiltBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build-and-verify in -short mode")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go toolchain not on PATH: %v", err)
	}

	// Resolve the module root (parent of cmd/) so the file-argument build runs module-aware,
	// which is required for the //go:debug directive to be honored.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	moduleRoot := filepath.Dir(filepath.Dir(wd)) // cmd/holder -> cmd -> module root
	mainFile := filepath.Join("cmd", "holder", "main.go")

	out := filepath.Join(t.TempDir(), "holder-test-artifact")
	// Mirror the Makefile L186–187 invocation: file-argument style, CGO disabled.
	build := exec.Command(goBin, "build", "-o", out, "./"+filepath.ToSlash(mainFile))
	build.Dir = moduleRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build holder failed: %v\n%s", err, b)
	}

	vm := exec.Command(goBin, "version", "-m", out)
	b, err := vm.CombinedOutput()
	if err != nil {
		t.Fatalf("go version -m failed: %v\n%s", err, b)
	}
	// The toolchain records a honored //go:debug directive as a `build DefaultGODEBUG=...`
	// build setting containing containermaxprocs=0. Absence => the directive was NOT honored
	// on the real build path => the CRIU dump fix is not actually in the binary (HARD STOP).
	got := string(b)
	if !strings.Contains(got, "containermaxprocs=0") {
		t.Fatalf("built holder binary does not carry containermaxprocs=0 in its build settings; "+
			"the //go:debug directive was not honored on the file-argument build path.\ngo version -m output:\n%s", got)
	}
}
