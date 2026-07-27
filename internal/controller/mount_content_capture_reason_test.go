/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentserver "github.com/podmotion-io/podmotion/internal/agent/server"
)

// TestMountContentCaptureFailedReason_AgentControllerAgree is the compiler/CI-enforced link between
// the agent-side reason constant (internal/agent/server/adr0415_mount_capture_gate.go:
// MountContentCaptureFailedReason) and this package's local copy (mountContentCaptureFailedReason,
// podmigration_controller.go) — ADR-0415 fail-closed capture gate. Mirrors the ADR-0246 shmem agree-test: the
// runtime classifier deliberately does NOT import the agent package, but this _test.go can, so the
// two literals are compared directly rather than kept in sync by convention alone.
func TestMountContentCaptureFailedReason_AgentControllerAgree(t *testing.T) {
	if mountContentCaptureFailedReason != agentserver.MountContentCaptureFailedReason {
		t.Fatalf("controller's mountContentCaptureFailedReason (%q) has drifted from "+
			"agentserver.MountContentCaptureFailedReason (%q) — update podmigration_controller.go's "+
			"constant to match",
			mountContentCaptureFailedReason, agentserver.MountContentCaptureFailedReason)
	}
}

// TestMountContentCaptureFailedReasonFromStatus exercises the controller-side classifier against a
// matching typed status, the sibling shmem-pagemap status (different Reason), and a bare
// FailedPrecondition (no details), to confirm the three failure classes sharing the gRPC code are
// told apart.
func TestMountContentCaptureFailedReasonFromStatus(t *testing.T) {
	t.Run("matching_reason", func(t *testing.T) {
		st := status.New(codes.FailedPrecondition, "checkpoint failed: owned mount content capture failed")
		st, err := st.WithDetails(&errdetails.ErrorInfo{
			Reason: mountContentCaptureFailedReason,
			Domain: "podmotion.io",
		})
		if err != nil {
			t.Fatalf("WithDetails: %v", err)
		}
		if !mountContentCaptureFailedReasonFromStatus(st) {
			t.Fatalf("expected mountContentCaptureFailedReasonFromStatus to return true")
		}
		// Must NOT be misclassified as the shmem-pagemap reason.
		if shmemPagemapMissingReasonFromStatus(st) {
			t.Fatalf("mount-capture status must not classify as shmem-pagemap-missing")
		}
	})

	t.Run("shmem_status_different_reason", func(t *testing.T) {
		st := status.New(codes.FailedPrecondition, "checkpoint failed: incomplete shmem pagemap")
		st, err := st.WithDetails(&errdetails.ErrorInfo{
			Reason: shmemPagemapMissingReason,
			Domain: "podmotion.io",
		})
		if err != nil {
			t.Fatalf("WithDetails: %v", err)
		}
		if mountContentCaptureFailedReasonFromStatus(st) {
			t.Fatalf("shmem-pagemap status must not classify as mount-content-capture-failed")
		}
	})

	t.Run("bare_status_no_details", func(t *testing.T) {
		st := status.New(codes.FailedPrecondition, "checkpoint failed: CRIU capability/ptrace error")
		if mountContentCaptureFailedReasonFromStatus(st) {
			t.Fatalf("expected false for a bare FailedPrecondition status")
		}
	})

	t.Run("nil_status", func(t *testing.T) {
		if mountContentCaptureFailedReasonFromStatus(nil) {
			t.Fatalf("expected false for nil status")
		}
	})
}
