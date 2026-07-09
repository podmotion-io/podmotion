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

// TestShmemPagemapMissingReason_AgentControllerAgree is the compiler/CI-enforced link between
// the agent-side reason constant (internal/agent/server/shmem_pagemap_guard.go:
// ShmemPagemapMissingReason) and this package's local copy (shmemPagemapMissingReason,
// podmigration_controller.go) — ADR-0246 typed-status redesign. The controller intentionally does
// NOT import internal/agent/server for the runtime check (grpcStatus.Details() classification
// must not require a Go-level dependency on the agent package, the same way codes.FailedPrecondition
// itself is a shared gRPC convention, not a cross-package Go symbol) — but this _test.go file CAN
// import it, so the two literals are compared directly here instead of being kept in sync by
// convention alone.
func TestShmemPagemapMissingReason_AgentControllerAgree(t *testing.T) {
	if shmemPagemapMissingReason != agentserver.ShmemPagemapMissingReason {
		t.Fatalf("controller's shmemPagemapMissingReason (%q) has drifted from "+
			"agentserver.ShmemPagemapMissingReason (%q) — update podmigration_controller.go's "+
			"constant to match",
			shmemPagemapMissingReason, agentserver.ShmemPagemapMissingReason)
	}
}

// TestShmemPagemapMissingReasonFromStatus exercises the controller-side classifier against both
// a matching and a non-matching typed status, and against the sibling ErrCRIUCapability-shaped
// status (same codes.FailedPrecondition, no ErrorInfo at all) to confirm the two failure classes
// that share a gRPC code are still correctly told apart.
func TestShmemPagemapMissingReasonFromStatus(t *testing.T) {
	t.Run("matching_reason", func(t *testing.T) {
		st := status.New(codes.FailedPrecondition, "checkpoint failed: incomplete shmem pagemap")
		st, err := st.WithDetails(&errdetails.ErrorInfo{
			Reason: shmemPagemapMissingReason,
			Domain: "podmotion.io",
		})
		if err != nil {
			t.Fatalf("WithDetails: %v", err)
		}
		if !shmemPagemapMissingReasonFromStatus(st) {
			t.Fatalf("expected shmemPagemapMissingReasonFromStatus to return true")
		}
	})

	t.Run("criu_capability_status_no_details", func(t *testing.T) {
		st := status.New(codes.FailedPrecondition, "checkpoint failed: CRIU capability/ptrace error")
		if shmemPagemapMissingReasonFromStatus(st) {
			t.Fatalf("expected shmemPagemapMissingReasonFromStatus to return false for a bare FailedPrecondition status")
		}
	})

	t.Run("nil_status", func(t *testing.T) {
		if shmemPagemapMissingReasonFromStatus(nil) {
			t.Fatalf("expected false for nil status")
		}
	})
}
