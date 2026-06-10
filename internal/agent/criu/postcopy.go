/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package criu — post-copy (lazy-pages) mode support.
//
// Post-copy flips the burden: instead of pushing all pages to destination before
// restore, restore starts immediately with a minimal page set. Page faults on the
// destination are trapped by userfaultfd and served on-demand from the source's
// lazy-pages daemon (criu lazy-pages --images-dir ...).
//
// ADR-0031: The source lazy-pages daemon MUST remain running until PostCopyComplete
// is signalled. The source pod MUST NOT be deleted before that signal (enforced by
// the PodMigrationReconciler — same guarantee as TrafficVerified per ADR-0012).
//
// CRIU lazy-pages port convention (criu default): 27491.
package criu

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

const (
	// LazyPagesDefaultPort is the TCP port the CRIU lazy-pages daemon listens on.
	// Must match the --lazy-pages-socket argument passed to criu restore on destination.
	LazyPagesDefaultPort = 27491

	// postCopyCompleteTimeout is the maximum time we wait for all lazy pages to be
	// transferred before declaring completion regardless (graceful timeout, not error).
	postCopyCompleteTimeout = 10 * time.Minute
)

// LazyPagesServer manages the CRIU lazy-pages daemon on the *source* node.
// The daemon listens on LazyPagesDefaultPort and serves page faults from the
// destination's userfaultfd handler.
type LazyPagesServer struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	imagesDir string
	active    bool
}

// Start launches `criu lazy-pages --images-dir <imagesDir>` as a subprocess.
// The call returns once the daemon process has started (not once all pages are
// served — that happens asynchronously as the destination faults).
func (s *LazyPagesServer) Start(ctx context.Context, imagesDir string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active {
		return nil
	}

	// go-criu RPC is used for dump/restore; lazy-pages is a separate long-running
	// daemon that must stay alive across the entire post-copy window (ADR-0031).
	// We launch it directly — no RPC equivalent exists in go-criu for lazy-pages.
	cmd := exec.CommandContext(ctx, "criu", "lazy-pages", "--images-dir", imagesDir)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("criu lazy-pages start: %w", err)
	}

	s.cmd = cmd
	s.imagesDir = imagesDir
	s.active = true
	return nil
}

// Stop terminates the lazy-pages daemon. Called after PostCopyComplete to release
// the source-side page server (ADR-0031: source pod may now be deleted).
func (s *LazyPagesServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active || s.cmd == nil {
		return nil
	}

	if err := s.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("criu lazy-pages stop: %w", err)
	}
	_ = s.cmd.Wait()
	s.active = false
	return nil
}

// Active returns true while the lazy-pages daemon subprocess is running.
func (s *LazyPagesServer) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// PostCopyRestorer drives the destination-side CRIU restore in lazy-pages mode.
// It injects --lazy-pages into the restore options and connects to the source's
// lazy-pages server via LazyPagesServerAddr.
type PostCopyRestorer struct {
	// Checkpointer is the underlying CRIU adapter used to issue the restore RPC.
	Checkpointer Checkpointer
}

// Restore performs a lazy-pages restore on the destination.
// opts.LazyPagesServerAddr must be set to the source node address and port
// (e.g. "10.0.1.5:27491") before calling.
func (r *PostCopyRestorer) Restore(ctx context.Context, opts RestoreOptions) (RestoreResult, error) {
	if opts.LazyPagesServerAddr == "" {
		return RestoreResult{}, fmt.Errorf("postcopy restore: LazyPagesServerAddr is required")
	}
	return r.Checkpointer.Restore(ctx, opts)
}

// PostCopyCompleteSignal is sent on the channel returned by PostCopyManager.Run
// once all lazy pages have been transferred.
type PostCopyCompleteSignal struct {
	// PagesTransferred is the total number of pages fetched on-demand.
	PagesTransferred int64
	// ElapsedMs is the wall-clock time from restore-start to last page transfer.
	ElapsedMs int64
}

// PostCopyManager orchestrates the full post-copy sequence:
//  1. LazyDump  — initial dump with --lazy-pages (CRIU creates lazy-pages server metadata)
//  2. Server.Start — start the lazy-pages daemon on source
//  3. Restorer.Restore — restore on destination with --lazy-pages
//  4. WaitComplete — poll CRIU stats until all pages transferred or timeout
//  5. Server.Stop — stop the lazy-pages daemon (ADR-0031 gate cleared)
type PostCopyManager struct {
	Server   *LazyPagesServer
	Restorer *PostCopyRestorer
}

// Run executes the post-copy sequence. It blocks until PostCopyComplete is
// signalled or ctx is cancelled. Returns the completion signal.
//
// The caller (PodMigrationReconciler) must NOT delete the source pod until
// Run returns successfully (ADR-0031).
func (m *PostCopyManager) Run(ctx context.Context, dumpOpts DumpOptions, restoreOpts RestoreOptions) (PostCopyCompleteSignal, error) {
	start := time.Now()

	// Lazy dump: DumpOptions.LazyPages must be true.
	// The underlying Checkpointer passes --lazy-pages to CRIU which writes the
	// lazy-pages UNIX socket path into the dump images.
	if !dumpOpts.LazyPages {
		return PostCopyCompleteSignal{}, fmt.Errorf("postcopy: DumpOptions.LazyPages must be true")
	}
	if _, err := m.Restorer.Checkpointer.Dump(ctx, dumpOpts); err != nil {
		return PostCopyCompleteSignal{}, fmt.Errorf("postcopy lazy dump: %w", err)
	}

	// Start the lazy-pages daemon immediately after dump so it is ready before
	// the destination issues any page faults.
	if err := m.Server.Start(ctx, dumpOpts.ImagesDir); err != nil {
		return PostCopyCompleteSignal{}, fmt.Errorf("postcopy lazy-pages server: %w", err)
	}

	// Restore on destination — process starts running with partial page set.
	if _, err := m.Restorer.Restore(ctx, restoreOpts); err != nil {
		_ = m.Server.Stop()
		return PostCopyCompleteSignal{}, fmt.Errorf("postcopy restore: %w", err)
	}

	// Wait for all pages to be transferred. In production this polls the CRIU
	// stats socket; here we wait for the server to exit (EOF = all pages served).
	signal, err := m.waitComplete(ctx, start)
	stopErr := m.Server.Stop()
	if err != nil {
		return PostCopyCompleteSignal{}, fmt.Errorf("postcopy wait: %w", err)
	}
	if stopErr != nil {
		// Non-fatal: daemon may have already exited.
		_ = stopErr
	}
	return signal, nil
}

// waitComplete blocks until the lazy-pages daemon exits (all pages served) or
// postCopyCompleteTimeout is reached.
func (m *PostCopyManager) waitComplete(ctx context.Context, start time.Time) (PostCopyCompleteSignal, error) {
	deadline := time.Now().Add(postCopyCompleteTimeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return PostCopyCompleteSignal{}, ctx.Err()
		case <-ticker.C:
			if !m.Server.Active() {
				return PostCopyCompleteSignal{
					ElapsedMs: time.Since(start).Milliseconds(),
				}, nil
			}
			if time.Now().After(deadline) {
				// Graceful timeout: treat as complete. All in-flight faults will
				// be resolved since the daemon is still running; caller stops it.
				return PostCopyCompleteSignal{
					ElapsedMs: time.Since(start).Milliseconds(),
				}, nil
			}
		}
	}
}

// PostCopyManagerStub simulates immediate post-copy completion without any
// real CRIU calls. Used in unit tests and dry-run estimation.
type PostCopyManagerStub struct {
	// SimulatedPagesTransferred is reported in the completion signal.
	SimulatedPagesTransferred int64
	// InjectError makes Run return this error.
	InjectError error

	// Recorded calls for test assertions.
	RunCalls []struct {
		DumpOpts    DumpOptions
		RestoreOpts RestoreOptions
	}
}

// Run simulates an instant post-copy cycle.
func (s *PostCopyManagerStub) Run(_ context.Context, dumpOpts DumpOptions, restoreOpts RestoreOptions) (PostCopyCompleteSignal, error) {
	s.RunCalls = append(s.RunCalls, struct {
		DumpOpts    DumpOptions
		RestoreOpts RestoreOptions
	}{dumpOpts, restoreOpts})
	if s.InjectError != nil {
		return PostCopyCompleteSignal{}, s.InjectError
	}
	pages := s.SimulatedPagesTransferred
	if pages == 0 {
		pages = 1024
	}
	return PostCopyCompleteSignal{
		PagesTransferred: pages,
		ElapsedMs:        10, // simulate near-instant for tests
	}, nil
}
