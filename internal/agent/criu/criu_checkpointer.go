/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package criu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	gocriu "github.com/checkpoint-restore/go-criu/v7"
	"github.com/checkpoint-restore/go-criu/v7/rpc"
	"google.golang.org/protobuf/proto"
)

const defaultCRIUBinaryPath = "/usr/sbin/criu"

// CRIUCheckpointer implements Checkpointer using go-criu/v7 RPC to invoke
// CRIU as a subprocess (ADR-0002 — never statically link GPLv2 code).
type CRIUCheckpointer struct {
	criuBinaryPath string

	mu          sync.Mutex
	activeCriu  *gocriu.Criu // non-nil while a dump/restore is in progress
}

// NewCRIUCheckpointer returns a CRIUCheckpointer that invokes the CRIU binary
// at criuBinaryPath. Pass an empty string to use the default /usr/sbin/criu.
func NewCRIUCheckpointer(criuBinaryPath string) *CRIUCheckpointer {
	if criuBinaryPath == "" {
		criuBinaryPath = defaultCRIUBinaryPath
	}
	return &CRIUCheckpointer{criuBinaryPath: criuBinaryPath}
}

// darwinError returns a clear error when running on macOS (CRIU is Linux-only).
func darwinError() error {
	return errors.New("CRIU requires Linux — not available on darwin")
}

// PreDump performs one iterative pre-dump round without freezing the container.
// Writes images to opts.ImagesDir. Sets track-mem so the next round captures
// only dirty pages.
func (c *CRIUCheckpointer) PreDump(ctx context.Context, opts PreDumpOptions) (CheckpointResult, error) {
	if runtime.GOOS == "darwin" {
		return CheckpointResult{}, darwinError()
	}

	if err := ctx.Err(); err != nil {
		return CheckpointResult{}, fmt.Errorf("context cancelled before PreDump: %w", err)
	}

	if err := os.MkdirAll(opts.ImagesDir, 0o755); err != nil {
		return CheckpointResult{}, fmt.Errorf("creating images dir %s: %w", opts.ImagesDir, err)
	}

	imgDirFd, err := openDirFd(opts.ImagesDir)
	if err != nil {
		return CheckpointResult{}, err
	}
	defer imgDirFd.Close()

	criuOpts := &rpc.CriuOpts{
		ImagesDirFd: proto.Int32(int32(imgDirFd.Fd())),
		LogFile:     proto.String("predump.log"),
		LogLevel:    proto.Int32(4),
		TrackMem:    proto.Bool(opts.TrackMem),
	}

	if opts.PrevImagesDir != "" {
		// CRIU expects a path relative to ImagesDir or absolute for --prev-images-dir.
		rel, relErr := filepath.Rel(opts.ImagesDir, opts.PrevImagesDir)
		if relErr != nil {
			rel = opts.PrevImagesDir
		}
		criuOpts.ParentImg = proto.String(rel)
	}

	c.mu.Lock()
	cr := gocriu.MakeCriu()
	cr.SetCriuPath(c.criuBinaryPath)
	c.activeCriu = cr
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.activeCriu = nil
		c.mu.Unlock()
	}()

	// Run CRIU in a goroutine so we can honour ctx cancellation.
	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		done <- result{err: cr.PreDump(criuOpts, nil)}
	}()

	select {
	case <-ctx.Done():
		// Best-effort abort: close the swrk socket to unblock CRIU.
		c.Abort(context.Background(), opts.ContainerID, opts.Namespace) //nolint:errcheck
		return CheckpointResult{}, fmt.Errorf("PreDump aborted: %w", ctx.Err())
	case res := <-done:
		if res.err != nil {
			return CheckpointResult{}, fmt.Errorf("criu pre-dump: %w", res.err)
		}
	}

	return CheckpointResult{
		ImagesDir:        opts.ImagesDir,
		DirtyPagesMB:     0, // CRIU stats file parsing not yet implemented
		FreezeDurationMs: 0, // pre-dump does not freeze
		RoundNumber:      0,
		CheckpointedAt:   time.Now(),
	}, nil
}

// Dump performs the final (freezing) CRIU dump. The container is frozen for
// the duration. Returns once all dump images are written to opts.ImagesDir.
func (c *CRIUCheckpointer) Dump(ctx context.Context, opts DumpOptions) (CheckpointResult, error) {
	if runtime.GOOS == "darwin" {
		return CheckpointResult{}, darwinError()
	}

	if err := ctx.Err(); err != nil {
		return CheckpointResult{}, fmt.Errorf("context cancelled before Dump: %w", err)
	}

	if err := os.MkdirAll(opts.ImagesDir, 0o755); err != nil {
		return CheckpointResult{}, fmt.Errorf("creating images dir %s: %w", opts.ImagesDir, err)
	}

	imgDirFd, err := openDirFd(opts.ImagesDir)
	if err != nil {
		return CheckpointResult{}, err
	}
	defer imgDirFd.Close()

	criuOpts := &rpc.CriuOpts{
		ImagesDirFd:  proto.Int32(int32(imgDirFd.Fd())),
		LogFile:      proto.String("dump.log"),
		LogLevel:     proto.Int32(4),
		LeaveRunning: proto.Bool(opts.LeaveRunning),
		TcpEstablished: proto.Bool(true),
		ShellJob:     proto.Bool(true),
	}

	if opts.PrevImagesDir != "" {
		rel, relErr := filepath.Rel(opts.ImagesDir, opts.PrevImagesDir)
		if relErr != nil {
			rel = opts.PrevImagesDir
		}
		criuOpts.ParentImg = proto.String(rel)
		criuOpts.TrackMem = proto.Bool(true)
	}

	c.mu.Lock()
	cr := gocriu.MakeCriu()
	cr.SetCriuPath(c.criuBinaryPath)
	c.activeCriu = cr
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.activeCriu = nil
		c.mu.Unlock()
	}()

	freezeStart := time.Now()

	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		done <- result{err: cr.Dump(criuOpts, nil)}
	}()

	select {
	case <-ctx.Done():
		c.Abort(context.Background(), opts.ContainerID, opts.Namespace) //nolint:errcheck
		return CheckpointResult{}, fmt.Errorf("Dump aborted: %w", ctx.Err())
	case res := <-done:
		if res.err != nil {
			return CheckpointResult{}, fmt.Errorf("criu dump: %w", res.err)
		}
	}

	return CheckpointResult{
		ImagesDir:        opts.ImagesDir,
		DirtyPagesMB:     0,
		FreezeDurationMs: time.Since(freezeStart).Milliseconds(),
		RoundNumber:      0,
		CheckpointedAt:   time.Now(),
	}, nil
}

// Restore recreates the container from dump images on the destination node.
func (c *CRIUCheckpointer) Restore(ctx context.Context, opts RestoreOptions) (RestoreResult, error) {
	if runtime.GOOS == "darwin" {
		return RestoreResult{}, darwinError()
	}

	if err := ctx.Err(); err != nil {
		return RestoreResult{}, fmt.Errorf("context cancelled before Restore: %w", err)
	}

	imgDirFd, err := openDirFd(opts.ImagesDir)
	if err != nil {
		return RestoreResult{}, err
	}
	defer imgDirFd.Close()

	criuOpts := &rpc.CriuOpts{
		ImagesDirFd:     proto.Int32(int32(imgDirFd.Fd())),
		LogFile:         proto.String("restore.log"),
		LogLevel:        proto.Int32(4),
		TcpEstablished:  proto.Bool(true),
		ShellJob:        proto.Bool(true),
		RstSibling:      proto.Bool(opts.Detached),
	}

	c.mu.Lock()
	cr := gocriu.MakeCriu()
	cr.SetCriuPath(c.criuBinaryPath)
	c.activeCriu = cr
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.activeCriu = nil
		c.mu.Unlock()
	}()

	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		done <- result{err: cr.Restore(criuOpts, nil)}
	}()

	select {
	case <-ctx.Done():
		c.Abort(context.Background(), opts.ContainerID, opts.Namespace) //nolint:errcheck
		return RestoreResult{}, fmt.Errorf("Restore aborted: %w", ctx.Err())
	case res := <-done:
		if res.err != nil {
			return RestoreResult{}, fmt.Errorf("criu restore: %w", res.err)
		}
	}

	return RestoreResult{
		PID:        0, // PID not exposed by go-criu Restore; use NRI/containerd query
		RestoredAt: time.Now(),
	}, nil
}

// Abort terminates any in-progress CRIU operation by closing the swrk socket.
// Safe to call at any time; a no-op if no operation is active.
func (c *CRIUCheckpointer) Abort(_ context.Context, _, _ string) error {
	if runtime.GOOS == "darwin" {
		return darwinError()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.activeCriu != nil {
		// Cleanup closes the swrk socket which unblocks the CRIU subprocess.
		err := c.activeCriu.Cleanup()
		c.activeCriu = nil
		return err
	}
	return nil
}

// openDirFd opens dirPath and returns an *os.File whose Fd() can be passed to
// CRIU as images_dir_fd. Caller must Close() it after the CRIU call.
func openDirFd(dirPath string) (*os.File, error) {
	f, err := os.Open(dirPath)
	if err != nil {
		return nil, fmt.Errorf("opening images dir %s: %w", dirPath, err)
	}
	return f, nil
}
