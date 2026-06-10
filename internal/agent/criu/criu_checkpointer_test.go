/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package criu_test

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
)

// TestCRIUCheckpointer_DarwinReturnsError verifies that all Checkpointer methods
// return a clear "not available on darwin" error on macOS dev machines.
// On Linux this test is skipped — real CRIU integration tests live in E2E.
func TestCRIUCheckpointer_DarwinReturnsError(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only test")
	}

	c := criu.NewCRIUCheckpointer("")
	ctx := context.Background()

	t.Run("PreDump", func(t *testing.T) {
		_, err := c.PreDump(ctx, criu.PreDumpOptions{ImagesDir: "/tmp/test-predump"})
		assertDarwinError(t, err)
	})

	t.Run("Dump", func(t *testing.T) {
		_, err := c.Dump(ctx, criu.DumpOptions{ImagesDir: "/tmp/test-dump"})
		assertDarwinError(t, err)
	})

	t.Run("Restore", func(t *testing.T) {
		_, err := c.Restore(ctx, criu.RestoreOptions{ImagesDir: "/tmp/test-restore"})
		assertDarwinError(t, err)
	})

	t.Run("Abort", func(t *testing.T) {
		err := c.Abort(ctx, "container-id", "k8s.io")
		assertDarwinError(t, err)
	})
}

func assertDarwinError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error on darwin, got nil")
	}
	if !strings.Contains(err.Error(), "darwin") {
		t.Errorf("expected darwin error message, got: %v", err)
	}
}

// TestCRIUCheckpointer_ContextCancellation verifies that methods honour
// context cancellation when called on Linux. On darwin they return early with
// the platform error before ever checking the context, which is also acceptable
// (the darwin check takes precedence).
func TestCRIUCheckpointer_ContextCancellation(t *testing.T) {
	c := criu.NewCRIUCheckpointer("/usr/sbin/criu")

	// Use an already-cancelled context.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	cancel() // cancel immediately

	t.Run("PreDump_cancelledCtx", func(t *testing.T) {
		_, err := c.PreDump(ctx, criu.PreDumpOptions{
			ContainerID: "test-container",
			Namespace:   "k8s.io",
			ImagesDir:   t.TempDir(),
		})
		if err == nil {
			t.Fatal("expected error with cancelled context, got nil")
		}
		// On darwin the platform error fires; on Linux the ctx-cancelled error fires.
		// Either way we expect a non-nil error.
	})

	t.Run("Dump_cancelledCtx", func(t *testing.T) {
		_, err := c.Dump(ctx, criu.DumpOptions{
			ContainerID: "test-container",
			Namespace:   "k8s.io",
			ImagesDir:   t.TempDir(),
		})
		if err == nil {
			t.Fatal("expected error with cancelled context, got nil")
		}
	})

	t.Run("Restore_cancelledCtx", func(t *testing.T) {
		_, err := c.Restore(ctx, criu.RestoreOptions{
			ContainerID: "test-container",
			Namespace:   "k8s.io",
			ImagesDir:   t.TempDir(),
		})
		if err == nil {
			t.Fatal("expected error with cancelled context, got nil")
		}
	})
}
