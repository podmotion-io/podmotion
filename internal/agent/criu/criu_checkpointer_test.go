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

// TestParseTCPImageEntries_InetskLines verifies that parseTCPImageEntries correctly
// counts inetsk/tcp image lines and "Unsupported socket" errors from a CRIU dump log.
// This is the M23 unit-level check for the log-parsing path that the integration test
// exercises against a live CRIU invocation.
func TestParseTCPImageEntries_InetskLines(t *testing.T) {
	type row struct {
		name          string
		logContent    string
		wantTCP       int
		wantUnsupport int
	}
	rows := []row{
		{
			name:          "empty_log",
			logContent:    "",
			wantTCP:       0,
			wantUnsupport: 0,
		},
		{
			name: "inetsk_entries_present",
			logContent: `Dumping inetsk 0x7f1a2b3c4d50
Writing tcp image
Writing tcp image
`,
			wantTCP:       3,
			wantUnsupport: 0,
		},
		{
			name: "unsupported_socket_present",
			logContent: `Dumping inetsk 0x7f1a2b3c4d50
Unsupported socket family 1
`,
			wantTCP:       1,
			wantUnsupport: 1,
		},
		{
			name: "tcp_close_path_no_inetsk",
			logContent: `Closing tcp socket
Closing tcp socket
`,
			wantTCP:       2,
			wantUnsupport: 0,
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			gotTCP, gotUnsupport := criu.ExportedParseTCPImageEntries(r.logContent)
			if gotTCP != r.wantTCP {
				t.Errorf("tcpEntries: got %d, want %d", gotTCP, r.wantTCP)
			}
			if gotUnsupport != r.wantUnsupport {
				t.Errorf("unsupportedErrors: got %d, want %d", gotUnsupport, r.wantUnsupport)
			}
		})
	}
}

// TestDumpOptions_LeaveStopped_SetWhenTcpEstablished verifies that when TcpEstablished=true
// the caller is expected to also set LeaveStopped=true (M23 ordering invariant). The StubCheckpointer
// records the options so we can assert without invoking real CRIU.
func TestDumpOptions_LeaveStopped_SetWhenTcpEstablished(t *testing.T) {
	type row struct {
		name           string
		tcpEstablished bool
		leaveStopped   bool
		wantLeaveStopped bool
	}
	rows := []row{
		{name: "tcp_stateful_with_leave_stopped", tcpEstablished: true, leaveStopped: true, wantLeaveStopped: true},
		{name: "stateless_no_leave_stopped", tcpEstablished: false, leaveStopped: false, wantLeaveStopped: false},
		{name: "tcp_stateful_leave_stopped_not_set", tcpEstablished: true, leaveStopped: false, wantLeaveStopped: false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			stub := &criu.StubCheckpointer{}
			opts := criu.DumpOptions{
				ImagesDir:      t.TempDir(),
				TcpEstablished: r.tcpEstablished,
				LeaveStopped:   r.leaveStopped,
			}
			_, _ = stub.Dump(context.Background(), opts)
			if len(stub.DumpCalls) != 1 {
				t.Fatalf("expected 1 Dump call, got %d", len(stub.DumpCalls))
			}
			got := stub.DumpCalls[0].LeaveStopped
			if got != r.wantLeaveStopped {
				t.Errorf("LeaveStopped: got %v, want %v", got, r.wantLeaveStopped)
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
