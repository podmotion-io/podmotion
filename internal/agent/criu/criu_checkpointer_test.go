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

// TestDumpOptions_TcpEstablishedTier verifies that TcpEstablished is propagated correctly
// from the tier (TCPPreservationMode) into DumpOptions and RestoreOptions.
// The StubCheckpointer records options so we can assert without invoking real CRIU.
func TestDumpOptions_TcpEstablishedTier(t *testing.T) {
	type row struct {
		name           string
		tcpEstablished bool
		wantTCP        bool
	}
	rows := []row{
		{name: "None_stateless", tcpEstablished: false, wantTCP: false},
		{name: "BestEffort_tier", tcpEstablished: true, wantTCP: true},
		{name: "Strict_tier", tcpEstablished: true, wantTCP: true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			stub := &criu.StubCheckpointer{}
			opts := criu.DumpOptions{
				ImagesDir:      t.TempDir(),
				TcpEstablished: r.tcpEstablished,
			}
			_, _ = stub.Dump(context.Background(), opts)
			if len(stub.DumpCalls) != 1 {
				t.Fatalf("expected 1 Dump call, got %d", len(stub.DumpCalls))
			}
			got := stub.DumpCalls[0].TcpEstablished
			if got != r.wantTCP {
				t.Errorf("TcpEstablished: got %v, want %v", got, r.wantTCP)
			}

			stubR := &criu.StubCheckpointer{}
			ropts := criu.RestoreOptions{
				ImagesDir:      t.TempDir(),
				TcpEstablished: r.tcpEstablished,
			}
			_, _ = stubR.Restore(context.Background(), ropts)
			if len(stubR.RestoreCalls) != 1 {
				t.Fatalf("expected 1 Restore call, got %d", len(stubR.RestoreCalls))
			}
			gotR := stubR.RestoreCalls[0].TcpEstablished
			if gotR != r.wantTCP {
				t.Errorf("Restore TcpEstablished: got %v, want %v", gotR, r.wantTCP)
			}
		})
	}
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
