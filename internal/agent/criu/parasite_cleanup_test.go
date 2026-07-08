/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build linux && amd64

package criu_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"golang.org/x/sys/unix"
)

// countCRIUMFDMappings returns how many "memfd:CRIUMFD (deleted)" VMA entries appear
// in /proc/<pid>/maps for pid — the exact signature of a leaked CRIU parasite mapping
// documented in docs/sprints/SPRINT41-NR-BLOCK-2-POD-SCOPE-INVESTIGATION.md.
func countCRIUMFDMappings(t *testing.T, pid int) int {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		t.Fatalf("reading /proc/%d/maps: %v", pid, err)
	}
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if strings.HasSuffix(scanner.Text(), "/memfd:CRIUMFD (deleted)") {
			count++
		}
	}
	return count
}

// injectFakeCRIUMFDMapping simulates a leaked CRIU parasite mapping in the target pid
// by performing the exact same operation compel's parasite_memfd_exchange() does
// (memfd_create + mmap(MAP_SHARED)) via ptrace-injected syscalls, entirely from this
// test process. This lets the test exercise the real CleanupLeakedParasiteMemfds code
// path against a real, kernel-verified CRIUMFD mapping without needing to race a real
// CRIU dump failure (which is timing-sensitive and non-deterministic to reproduce in
// under a second — the underlying leak is proven and documented via the live cluster
// investigation in SPRINT41-NR-BLOCK-2-POD-SCOPE-INVESTIGATION.md; this test isolates
// and proves the CLEANUP mechanism against the same real VMA shape).
func injectFakeCRIUMFDMapping(t *testing.T, pid int) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := unix.PtraceAttach(pid); err != nil {
		t.Fatalf("PTRACE_ATTACH: %v", err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("waitpid after attach: %v", err)
	}
	defer func() {
		if err := unix.PtraceDetach(pid); err != nil {
			t.Logf("PTRACE_DETACH warning: %v", err)
		}
	}()

	var regsBefore unix.PtraceRegsAmd64
	if err := unix.PtraceGetRegsAmd64(pid, &regsBefore); err != nil {
		t.Fatalf("PTRACE_GETREGS: %v", err)
	}

	origWord := make([]byte, 8)
	if _, err := unix.PtracePeekData(pid, uintptr(regsBefore.Rip), origWord); err != nil {
		t.Fatalf("PTRACE_PEEKTEXT: %v", err)
	}
	patched := []byte{0x0F, 0x05, 0xCC, 0x90, 0x90, 0x90, 0x90, 0x90} // syscall; int3; nop...
	if _, err := unix.PtracePokeData(pid, uintptr(regsBefore.Rip), patched); err != nil {
		t.Fatalf("PTRACE_POKETEXT: %v", err)
	}
	defer func() {
		_, _ = unix.PtracePokeData(pid, uintptr(regsBefore.Rip), origWord)
	}()

	doSyscall := func(nr, a1, a2, a3 uint64) int64 {
		regs := regsBefore
		regs.Rax = nr
		regs.Rdi = a1
		regs.Rsi = a2
		regs.Rdx = a3
		if err := unix.PtraceSetRegsAmd64(pid, &regs); err != nil {
			t.Fatalf("PTRACE_SETREGS pre-syscall %d: %v", nr, err)
		}
		if err := unix.PtraceSingleStep(pid); err != nil {
			t.Fatalf("PTRACE_SINGLESTEP syscall %d: %v", nr, err)
		}
		if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
			t.Fatalf("waitpid after syscall %d: %v", nr, err)
		}
		var regsAfter unix.PtraceRegsAmd64
		if err := unix.PtraceGetRegsAmd64(pid, &regsAfter); err != nil {
			t.Fatalf("PTRACE_GETREGS post-syscall %d: %v", nr, err)
		}
		return int64(regsAfter.Rax)
	}

	// Write the memfd name ("CRIUMFD") into scratch space below the tracee's stack
	// (red-zone-safe: we never return through this stack frame).
	nameScratch := regsBefore.Rsp - 512
	name := []byte("CRIUMFD\x00")
	var nameWord uint64
	for i, b := range name {
		nameWord |= uint64(b) << (8 * i)
	}
	nameBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		nameBytes[i] = byte(nameWord >> (8 * i))
	}
	if _, err := unix.PtracePokeData(pid, uintptr(nameScratch), nameBytes); err != nil {
		t.Fatalf("PTRACE_POKETEXT (memfd name): %v", err)
	}

	fd := doSyscall(unix.SYS_MEMFD_CREATE, nameScratch, 0, 0)
	if fd < 0 {
		t.Fatalf("remote memfd_create failed: errno %d", -fd)
	}
	const mapLen = 40960
	if ret := doSyscall(unix.SYS_FTRUNCATE, uint64(fd), mapLen, 0); ret < 0 {
		t.Fatalf("remote ftruncate failed: errno %d", -ret)
	}

	// mmap needs 6 args; reuse doSyscall's regs setup manually for r10/r8/r9.
	regs := regsBefore
	regs.Rax = unix.SYS_MMAP
	regs.Rdi = 0
	regs.Rsi = mapLen
	regs.Rdx = unix.PROT_READ | unix.PROT_WRITE
	regs.R10 = unix.MAP_SHARED
	regs.R8 = uint64(fd)
	regs.R9 = 0
	if err := unix.PtraceSetRegsAmd64(pid, &regs); err != nil {
		t.Fatalf("PTRACE_SETREGS pre-mmap: %v", err)
	}
	if err := unix.PtraceSingleStep(pid); err != nil {
		t.Fatalf("PTRACE_SINGLESTEP mmap: %v", err)
	}
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("waitpid after mmap: %v", err)
	}
	var regsAfterMmap unix.PtraceRegsAmd64
	if err := unix.PtraceGetRegsAmd64(pid, &regsAfterMmap); err != nil {
		t.Fatalf("PTRACE_GETREGS post-mmap: %v", err)
	}
	if int64(regsAfterMmap.Rax) < 0 {
		t.Fatalf("remote mmap failed: errno %d", -int64(regsAfterMmap.Rax))
	}

	if ret := doSyscall(unix.SYS_CLOSE, uint64(fd), 0, 0); ret < 0 {
		t.Fatalf("remote close failed: errno %d", -ret)
	}

	if err := unix.PtraceSetRegsAmd64(pid, &regsBefore); err != nil {
		t.Fatalf("PTRACE_SETREGS restore: %v", err)
	}
}

// TestCleanupLeakedParasiteMemfds_RemovesLeak is the regression test for the CRIU
// parasite-memfd leak documented in
// docs/sprints/SPRINT41-NR-BLOCK-2-POD-SCOPE-INVESTIGATION.md. It spawns a real
// long-lived process, injects a real kernel-verified "memfd:CRIUMFD (deleted)"
// mapping into it (the exact shape CRIU/compel leaves behind on a failed dump), then
// asserts CleanupLeakedParasiteMemfds removes it — and that a SECOND leaked mapping
// injected afterward is independently detected and removed too, proving the fix
// addresses the repeated-retry accumulation case (5 failed attempts -> 8 stacked
// leaked pairs in the live repro), not just a single leaked mapping.
func TestCleanupLeakedParasiteMemfds_RemovesLeak(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("ptrace-based parasite cleanup is Linux/amd64-only (ADR-0146/ADR-0153)")
	}

	victim := exec.Command("sleep", "300")
	if err := victim.Start(); err != nil {
		t.Fatalf("starting victim process: %v", err)
	}
	defer func() {
		_ = victim.Process.Kill()
		_, _ = victim.Process.Wait()
	}()
	pid := victim.Process.Pid
	time.Sleep(100 * time.Millisecond) // let the victim reach its steady pause state

	if got := countCRIUMFDMappings(t, pid); got != 0 {
		t.Fatalf("victim process has %d CRIUMFD mappings before test starts (expected 0)", got)
	}

	// --- Round 1: inject one leaked mapping, verify cleanup removes exactly it. ---
	injectFakeCRIUMFDMapping(t, pid)
	if got := countCRIUMFDMappings(t, pid); got != 1 {
		t.Fatalf("after injecting fake leak: got %d CRIUMFD mappings, want 1", got)
	}

	cleaned, err := criu.CleanupLeakedParasiteMemfds(int32(pid))
	if err != nil {
		t.Fatalf("CleanupLeakedParasiteMemfds round 1: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("CleanupLeakedParasiteMemfds round 1: cleaned=%d, want 1", cleaned)
	}
	if got := countCRIUMFDMappings(t, pid); got != 0 {
		t.Fatalf("after cleanup round 1: %d CRIUMFD mappings remain, want 0", got)
	}

	// A no-op cleanup call on an already-clean process must not error and must report 0.
	cleaned, err = criu.CleanupLeakedParasiteMemfds(int32(pid))
	if err != nil {
		t.Fatalf("CleanupLeakedParasiteMemfds no-op call: %v", err)
	}
	if cleaned != 0 {
		t.Fatalf("no-op cleanup: cleaned=%d, want 0", cleaned)
	}

	// --- Round 2+3: prove repeated leak/cleanup cycles don't accumulate (the exact
	// production failure mode: retries against the same live PID). ---
	for i := 2; i <= 3; i++ {
		injectFakeCRIUMFDMapping(t, pid)
		if got := countCRIUMFDMappings(t, pid); got != 1 {
			t.Fatalf("round %d: after injecting fake leak: got %d CRIUMFD mappings, want 1", i, got)
		}
		cleaned, err = criu.CleanupLeakedParasiteMemfds(int32(pid))
		if err != nil {
			t.Fatalf("round %d: CleanupLeakedParasiteMemfds: %v", i, err)
		}
		if cleaned != 1 {
			t.Fatalf("round %d: cleaned=%d, want 1", i, cleaned)
		}
		if got := countCRIUMFDMappings(t, pid); got != 0 {
			t.Fatalf("round %d: after cleanup: %d CRIUMFD mappings remain, want 0", i, got)
		}
	}

	// The victim process must still be alive and unaffected throughout — the whole
	// point of this cleanup is to operate on a still-running workload process without
	// disturbing it.
	if err := victim.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("victim process is no longer alive after cleanup cycles: %v", err)
	}
}

// TestCleanupLeakedParasiteMemfds_NoLeakIsNoop verifies the common case: a process
// that has never had a CRIU parasite injected reports zero cleaned mappings and no
// error (fast no-op path, exercised on every successful checkpoint).
func TestCleanupLeakedParasiteMemfds_NoLeakIsNoop(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("ptrace-based parasite cleanup is Linux/amd64-only (ADR-0146/ADR-0153)")
	}

	victim := exec.Command("sleep", "300")
	if err := victim.Start(); err != nil {
		t.Fatalf("starting victim process: %v", err)
	}
	defer func() {
		_ = victim.Process.Kill()
		_, _ = victim.Process.Wait()
	}()
	time.Sleep(50 * time.Millisecond)

	cleaned, err := criu.CleanupLeakedParasiteMemfds(int32(victim.Process.Pid))
	if err != nil {
		t.Fatalf("CleanupLeakedParasiteMemfds on clean process: %v", err)
	}
	if cleaned != 0 {
		t.Fatalf("cleaned=%d on a process with no leak, want 0", cleaned)
	}
}

// TestCleanupLeakedParasiteMemfds_NonexistentPID verifies the function returns an
// error (not a panic) when given a PID that does not exist, since Checkpoint's
// failure path may race with the container being torn down out from under it.
func TestCleanupLeakedParasiteMemfds_NonexistentPID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only")
	}
	// A PID that is extremely unlikely to exist.
	const bogusPID = 1<<31 - 2
	_, err := criu.CleanupLeakedParasiteMemfds(bogusPID)
	if err == nil {
		t.Fatalf("expected an error for a nonexistent PID, got nil")
	}
}
