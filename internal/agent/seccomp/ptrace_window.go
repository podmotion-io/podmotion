/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package seccomp — SD-4 ptrace-window tracking (Phase 1).
//
// # SD-4 — bound CAP_SYS_PTRACE to the CRIU dump/restore window
//
// SD-1 dropped the agent's blanket privileged:true to a discrete capability set that
// includes CAP_SYS_PTRACE. That cap is held continuously by the steady-state agent
// process, but it is only LEGITIMATELY exercised inside two narrow windows: the CRIU
// dump on the SOURCE node and the CRIU restore on the DESTINATION node. SD-4 refines
// SD-1 so that ptrace is treated as in-window only during those two operations.
//
// Linux cannot drop an individual capability mid-process without an exec, and CRIU runs
// as a go-criu RPC subprocess (constitutional invariant §1.4.2) that the agent must be
// able to grant ptrace to. The three viable enforcement approaches considered:
//
//	A. Run CRIU under a minimal privileged helper while the main agent drops ptrace at
//	   startup. Requires re-exec plumbing through the go-criu RPC path.
//	B. prctl-based temporary elevation. Only feasible if the steady-state process has
//	   already dropped ptrace and holds it inheritable/ambient — not the current cap set.
//	C. A seccomp-BPF program that whitelists ptrace(2) ONLY while a window flag is set,
//	   blocking it during steady state.
//
// This file is **Phase 1** of approach C: the WINDOW TRACKING substrate. It records, on
// node-local tmpfs, exactly when each container is inside its CRIU dump/restore window.
// The cap is still held continuously by SD-1's discrete set; this file does not yet
// kernel-enforce the bound. A future seccomp-BPF program (SD-5, the CRIU ptrace
// arg-filter) can consult the window file as the in-window hint that gates whether
// ptrace request values are permitted at all. The open/close calls are wired around the
// actual CRIU dump and restore invocations in internal/agent/server/server.go so the
// window is precisely the freeze/restore boundary, never steady state.
//
// SD-4 Phase 2 (kernel-enforced ptrace bounding): requires dropping SYS_PTRACE from
// steady-state cap set and using inheritable/ambient caps or a privileged CRIU
// subprocess. Tracked as M23 scope after validating CRIU stability under SD-1 discrete
// caps (Phase 1 = window tracking, this file).
package seccomp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ptraceWindowDir is the node-local tmpfs directory holding one marker file per container
// currently inside its CRIU dump/restore window. On /run (tmpfs) so the markers are
// node-local and vanish on reboot — a rebooted node has no in-flight CRIU window to bound.
// A package var (not const) only so tests can redirect it off the privileged /run path.
var ptraceWindowDir = "/run/podmotion/ptrace-window"

// defaultFreezeWindowBudgetMs is the fallback freeze-window budget used by the stale-window
// sweeper when no per-request FreezeWindowBudgetMs is available to size the staleness bound.
// It mirrors the agent freeze budget (network.ebpf defaultFreezeBudget = 5000ms); the
// sweeper closes any window older than 2x this (SweepStaleWindows below).
const defaultFreezeWindowBudgetMs = 5000

// ptraceWindowPath returns the marker path for a container. containerID is sanitized to a
// bare base name so a hostile/odd ID cannot escape ptraceWindowDir via path separators.
func ptraceWindowPath(containerID string) string {
	return filepath.Join(ptraceWindowDir, sanitizeWindowKey(containerID))
}

// sanitizeWindowKey reduces an arbitrary container identifier to a single safe path
// segment: strip any directory components and replace remaining separators. The window
// key is an opaque tmpfs filename, never re-parsed, so collapsing is safe.
func sanitizeWindowKey(containerID string) string {
	key := filepath.Base(filepath.Clean("/" + containerID))
	key = strings.ReplaceAll(key, string(os.PathSeparator), "_")
	if key == "" || key == "." || key == ".." || key == "/" {
		return "_"
	}
	return key
}

// PtraceWindowOpen marks a container as inside its CRIU dump/restore window — the only
// interval in which the agent legitimately exercises CAP_SYS_PTRACE against that container
// (SD-4). Call it immediately BEFORE the CRIU dump (source) or CRIU restore (destination);
// the caller MUST defer PtraceWindowClose as a fallback so a panic/early-return never leaves
// a window stuck open (the sweeper is the second line of defense, not the first). The marker
// is created idempotently — re-opening an already-open window refreshes its mtime so the
// staleness clock restarts for a legitimately long pre-copy + freeze.
func PtraceWindowOpen(containerID string) error {
	if err := os.MkdirAll(ptraceWindowDir, 0o700); err != nil {
		return fmt.Errorf("create ptrace-window dir: %w", err)
	}
	p := ptraceWindowPath(containerID)
	// O_CREATE|O_TRUNC is idempotent: re-open refreshes the file and its mtime (staleness
	// clock restart). Content is a human-readable open timestamp for operator forensics; the
	// EXISTENCE of the file is the signal, not its content.
	data := []byte(fmt.Sprintf("ptrace-window-open containerID=%s opened=%s\n",
		containerID, time.Now().UTC().Format(time.RFC3339Nano)))
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return fmt.Errorf("write ptrace-window marker %s: %w", p, err)
	}
	return nil
}

// PtraceWindowClose clears the in-window marker for a container — call it immediately AFTER
// the CRIU dump/restore returns (success OR failure), and ALSO via a deferred fallback.
// Idempotent: closing an already-closed (or never-opened) window is a no-op success, so the
// happy-path explicit close and the deferred fallback do not conflict.
func PtraceWindowClose(containerID string) error {
	if err := os.Remove(ptraceWindowPath(containerID)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove ptrace-window marker for %s: %w", containerID, err)
	}
	return nil
}

// IsPtraceWindowOpen reports whether a container is currently inside its CRIU dump/restore
// window. This is the hint a future SD-5 seccomp-BPF ptrace arg-filter consults to decide
// whether ptrace request values are permitted at all for the agent at this instant. A read
// error other than not-exist is treated as "not open" (fail-closed): if we cannot prove the
// window is open, ptrace should be treated as out-of-window.
func IsPtraceWindowOpen(containerID string) bool {
	_, err := os.Stat(ptraceWindowPath(containerID))
	return err == nil
}

// SweepStaleWindows closes any ptrace window whose marker is older than maxAge. A window that
// outlives 2x the freeze budget is almost certainly an agent that died (or returned) without
// running its deferred PtraceWindowClose — leaving the container marked in-window forever,
// which would keep ptrace permitted indefinitely once SD-5's BPF filter is live. The sweeper
// is the stuck-window backstop behind the deferred close. Returns the number of stale windows
// it closed. Safe to call when the directory is absent.
func SweepStaleWindows(maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(ptraceWindowDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("scan ptrace-window dir: %w", err)
	}
	swept := 0
	now := time.Now()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, infoErr := e.Info()
		if infoErr != nil {
			// Racing removal (deferred close fired between ReadDir and Info) — nothing to do.
			if os.IsNotExist(infoErr) {
				continue
			}
			log.Error(infoErr, "ptrace-window sweep: stat failed — leaving marker in place", "file", e.Name())
			continue
		}
		if now.Sub(info.ModTime()) < maxAge {
			continue
		}
		p := filepath.Join(ptraceWindowDir, e.Name())
		if rmErr := os.Remove(p); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Error(rmErr, "ptrace-window sweep: failed to remove stale marker", "file", e.Name())
			continue
		}
		log.Info("ptrace-window sweep: closed stale window (deferred close did not fire — likely agent crash inside CRIU window) (SD-4)",
			"file", e.Name(), "ageMs", now.Sub(info.ModTime()).Milliseconds(), "maxAgeMs", maxAge.Milliseconds())
		swept++
	}
	return swept, nil
}

// StartStaleWindowSweeper runs SweepStaleWindows on a ticker until ctx is cancelled. It is
// started once at agent init (cmd/agent/main.go), alongside the seccomp crash-recovery scan.
// The staleness bound is 2x the freeze budget: a legitimate dump/restore window (pre-copy +
// freeze, or restore) completes well within one freeze budget, so 2x is a generous floor that
// never races a live window while still bounding a crashed one. interval governs how often the
// sweep runs; pass 0 to use the freeze budget as the interval.
func StartStaleWindowSweeper(stop <-chan struct{}, interval time.Duration) {
	maxAge := 2 * time.Duration(defaultFreezeWindowBudgetMs) * time.Millisecond
	if interval <= 0 {
		interval = time.Duration(defaultFreezeWindowBudgetMs) * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if n, err := SweepStaleWindows(maxAge); err != nil {
					log.Error(err, "ptrace-window stale sweep failed (SD-4)")
				} else if n > 0 {
					log.Info("ptrace-window stale sweep closed stuck window(s) (SD-4)", "closed", n)
				}
			}
		}
	}()
}
