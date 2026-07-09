// Copyright 2026 PodMotion Authors.
// Licensed under the Apache License, Version 2.0.

//go:build linux && amd64

package criu

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// criuParasiteMemfdName is the fixed name CRIU/compel gives the memfd it creates to
// inject parasite code into a dumped process (compel/src/lib/infect-priv.h:
// #define MEMFD_FNAME "CRIUMFD"). It always appears unlinked ("(deleted)") because
// memfd objects have no path — CRIU never links it into any directory.
const criuParasiteMemfdName = "/memfd:CRIUMFD (deleted)"

// leakedParasiteVMA is one mapped region backed by a leaked CRIUMFD memfd, parsed from
// /proc/<pid>/maps.
type leakedParasiteVMA struct {
	start, end uint64
}

// findLeakedParasiteMemfds scans /proc/<pid>/maps for CRIUMFD parasite mappings.
//
// Investigation (docs/sprints/SPRINT41-NR-BLOCK-2-POD-SCOPE-INVESTIGATION.md): every
// CRIU dump attempt (whether invoked via `ctr tasks checkpoint` or raw `criu dump`)
// injects a parasite via ptrace + a "CRIUMFD" memfd (compel's parasite-injection
// mechanism). On a SUCCESSFUL dump, CRIU's own compel_cure()/compel_cure_remote()
// unmaps this region before exiting. On a FAILED/aborted dump, cure is only reached
// on some error paths — CRIU's own source acknowledges the risk (compel_stop_daemon()
// comment: "Looks like a previous attempt failed ... parasite will try to cure
// itself" — an optimistic assumption that does not hold for every failure class, as
// directly reproduced: 5 failed attempts against the same live PID left 8 stacked
// leaked CRIUMFD VMA pairs, +1 pair per attempt, and re-invoking CRIU does NOT clean
// up a pre-existing stray mapping — compel's parasite_memfd_exchange() unconditionally
// creates a fresh memfd every time with no check of existing VMAs).
//
// There is no external cleanup primitive for this: not in the criu CLI (no `criu cure`
// or equivalent subcommand), not in the RPC protocol (criu-rpc.proto has no
// cure/cleanup message), and not in go-criu (github.com/checkpoint-restore/go-criu/v7
// exposes Dump/Restore/PreDump/Cleanup, where Cleanup only tears down the client-side
// swrk control socket — unrelated to target-process parasite state). CRIU's real cure
// function (compel_cure_remote(), compel/src/lib/infect.c) is internal C code in the
// GPLv2 compel library and is never statically linked into this Apache-2.0 binary
// (ADR-0002) nor exposed via any subprocess/RPC interface we can call.
//
// The only reachable remediation is to perform the equivalent remote munmap ourselves
// via ptrace — mechanically the same technique compel_cure_remote() itself uses
// (PTRACE_ATTACH + an injected syscall), just invoked externally against the leaked
// VMA ranges we can observe directly in /proc/<pid>/maps.
func findLeakedParasiteMemfds(pid int32) ([]leakedParasiteVMA, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, fmt.Errorf("findLeakedParasiteMemfds: open maps: %w", err)
	}
	defer f.Close()

	var found []leakedParasiteVMA
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasSuffix(line, criuParasiteMemfdName) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		addrRange := fields[0]
		parts := strings.SplitN(addrRange, "-", 2)
		if len(parts) != 2 {
			continue
		}
		start, errStart := strconv.ParseUint(parts[0], 16, 64)
		end, errEnd := strconv.ParseUint(parts[1], 16, 64)
		if errStart != nil || errEnd != nil {
			continue
		}
		found = append(found, leakedParasiteVMA{start: start, end: end})
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("findLeakedParasiteMemfds: scan maps: %w", scanErr)
	}
	return found, nil
}

// CleanupLeakedParasiteMemfds detects and unmaps any leaked CRIUMFD parasite mappings
// still resident in the target process's address space, and should be called after
// EVERY checkpoint/dump attempt against a still-alive PID — success or failure — so a
// process that is retried (rollback keeps the source pod's process alive rather than
// restarting it) never accumulates stale parasite mappings across attempts.
//
// On a normal successful dump this is a fast no-op: CRIU's own cure path has already
// removed the mapping, so findLeakedParasiteMemfds returns nothing to clean.
//
// Returns the number of leaked VMA pairs that were unmapped, and the first error
// encountered (best-effort: attempts every leaked region even if one fails).
func CleanupLeakedParasiteMemfds(pid int32) (int, error) {
	leaked, err := findLeakedParasiteMemfds(pid)
	if err != nil {
		return 0, err
	}
	if len(leaked) == 0 {
		return 0, nil
	}

	cleaned := 0
	var firstErr error
	err = withPtraceAttach(pid, func(tid int) error {
		for _, vma := range leaked {
			if unmapErr := remoteMunmap(tid, vma.start, vma.end-vma.start); unmapErr != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("remote munmap of leaked CRIUMFD [0x%x-0x%x]: %w", vma.start, vma.end, unmapErr)
				}
				continue
			}
			cleaned++
		}
		return nil
	})
	if err != nil {
		if firstErr == nil {
			firstErr = err
		}
	}
	return cleaned, firstErr
}

// withPtraceAttach attaches to pid via PTRACE_ATTACH, waits for it to stop, runs fn,
// then always restores execution via PTRACE_DETACH — even if fn returns an error.
//
// PTRACE_ATTACH (not PTRACE_SEIZE) is used deliberately: ptrace_linux.go documents that
// PTRACE_SEIZE leaves kernel ptrace-stopped state that interferes with CRIU's own
// subsequent PTRACE_INTERRUPT (EPERM). PTRACE_ATTACH + PTRACE_DETACH cleanly restores
// the tracee to its pre-attach state with no lingering expectation, which is exactly
// the same mechanism CRIU/compel itself uses to attach to the target for its own
// parasite injection and cure sequence, so a subsequent real CRIU invocation against
// this PID is unaffected (verified directly: see parasite_cleanup_test.go).
func withPtraceAttach(pid int32, fn func(tid int) error) error {
	tid := int(pid)

	// ptrace calls (PTRACE_ATTACH/PEEKTEXT/POKETEXT/GETREGS/SETREGS/SINGLESTEP/DETACH)
	// must all be issued from the same OS thread — the kernel tracks the tracer by
	// thread ID, not process ID. Lock this goroutine to its OS thread for the
	// duration of the attach/cure/detach sequence (mirrors the same pattern already
	// used in deleteUnsupportedNetLinks for netns switches).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := unix.PtraceAttach(tid); err != nil {
		return fmt.Errorf("PTRACE_ATTACH pid %d: %w", pid, err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(tid, &ws, 0, nil); err != nil {
		_ = unix.PtraceDetach(tid)
		return fmt.Errorf("waitpid after PTRACE_ATTACH pid %d: %w", pid, err)
	}

	fnErr := fn(tid)

	if detachErr := unix.PtraceDetach(tid); detachErr != nil && fnErr == nil {
		fnErr = fmt.Errorf("PTRACE_DETACH pid %d: %w", pid, detachErr)
	}
	return fnErr
}

// remoteMunmap injects munmap(addr, length) into the ptrace-attached tracee tid by
// patching the instruction at its current RIP with a raw `syscall` opcode, setting up
// syscall-ABI registers, single-stepping exactly one instruction, and restoring the
// original bytes/registers afterward. This mirrors compel_cure_remote()'s own
// technique (compel/src/lib/infect.c) for unmapping the parasite memfd mapping — the
// only difference is this is invoked from an external process after the fact, against
// a mapping CRIU's own cure step failed to remove.
//
// amd64-only: PodMotion's supported scope is Linux/amd64 (ADR-0153, ADR-0146).
func remoteMunmap(tid int, addr, length uint64) error {
	var regsBefore unix.PtraceRegsAmd64
	if err := unix.PtraceGetRegsAmd64(tid, &regsBefore); err != nil {
		return fmt.Errorf("PTRACE_GETREGS: %w", err)
	}
	regs := regsBefore

	// Patch 8 bytes at the current instruction pointer with `syscall; int3` (0F 05 CC),
	// padded with NOPs. int3 is a hard stop so the single-step below cannot overrun past
	// the injected syscall into the process's real (now-corrupted-view) code stream.
	origWord := make([]byte, 8)
	if _, err := unix.PtracePeekData(tid, uintptr(regs.Rip), origWord); err != nil {
		return fmt.Errorf("PTRACE_PEEKTEXT at rip: %w", err)
	}
	patched := []byte{0x0F, 0x05, 0xCC, 0x90, 0x90, 0x90, 0x90, 0x90}
	if _, err := unix.PtracePokeData(tid, uintptr(regs.Rip), patched); err != nil {
		return fmt.Errorf("PTRACE_POKETEXT at rip: %w", err)
	}
	// Always restore the original bytes, regardless of what happens below.
	defer func() {
		_, _ = unix.PtracePokeData(tid, uintptr(regsBefore.Rip), origWord)
	}()

	// Syscall ABI (x86_64): rax=nr, rdi,rsi,rdx,r10,r8,r9=args.
	regs.Rax = unix.SYS_MUNMAP
	regs.Rdi = addr
	regs.Rsi = length
	if err := unix.PtraceSetRegsAmd64(tid, &regs); err != nil {
		return fmt.Errorf("PTRACE_SETREGS (pre-syscall): %w", err)
	}

	// Single-step executes exactly the injected `syscall` instruction, then traps on
	// the immediately-following int3.
	if err := unix.PtraceSingleStep(tid); err != nil {
		return fmt.Errorf("PTRACE_SINGLESTEP (syscall): %w", err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(tid, &ws, 0, nil); err != nil {
		return fmt.Errorf("waitpid after syscall singlestep: %w", err)
	}

	var regsAfter unix.PtraceRegsAmd64
	if err := unix.PtraceGetRegsAmd64(tid, &regsAfter); err != nil {
		return fmt.Errorf("PTRACE_GETREGS (post-syscall): %w", err)
	}
	ret := int64(regsAfter.Rax)

	// Restore original registers (RIP included) so execution resumes exactly where it
	// was before this injection — the tracee never observes the patch.
	if err := unix.PtraceSetRegsAmd64(tid, &regsBefore); err != nil {
		return fmt.Errorf("PTRACE_SETREGS (restore): %w", err)
	}

	if ret < 0 {
		return fmt.Errorf("remote munmap(0x%x, %d) returned errno %d: %w", addr, length, -ret, syscall.Errno(-ret))
	}
	return nil
}
