/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// adr0415_mount_capture_gate.go — ADR-0415 fail-closed capture gate: capture-everything-by-default fails CLOSED.
//
// Default-capture only eliminates the "we forgot this OS construct" bug class if a capture that
// FAILS cannot silently degrade into a skip. The systemic root cause named the exact anti-pattern:
// the former captureCtrDevShmContent's silent no-op/skip branches let a real capture failure
// (sandbox source unreachable, image write error) pass as success, so a restore later ENOENTed on
// content that was never captured. Under fail-closed capture gate that is forbidden: if capturing an owned mount's
// content fails, the checkpoint fails closed with an attributed reason (MountContentCaptureFailed),
// naming the mount — never skip-and-continue, never best-effort-no-op. A checkpoint that could not
// capture something the pod owns is a non-restorable image and must not leave the source node.
//
// This follows the EXACT ADR-0246 fail-closed-detector template (shmem_pagemap_guard.go:
// ErrIncompleteShmemPagemap / ShmemPagemapMissingReason / newShmemPagemapMissingStatus): a
// distinguishable sentinel error, a typed detail, and a typed codes.FailedPrecondition gRPC status
// carrying an errdetails.ErrorInfo{Reason: MountContentCaptureFailedReason} payload so the
// controller attributes the PodMigration condition reason from a stable reason code, not error prose.

import (
	"errors"
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrMountContentCaptureFailed is the distinguishable sentinel returned (wrapped) when the content
// of an owned pod-local mount that MUST be captured (ADR-0415 default-capture) could not be — e.g.
// the ctr fast path externalized /dev/shm (runc's CRIU skipped its content) and the agent could not
// reach the sandbox source dir to capture it, or the tar/write failed. Callers distinguish it via
// errors.Is; the controller maps it to the MountContentCaptureFailed condition reason.
var ErrMountContentCaptureFailed = errors.New("checkpoint incomplete: an owned pod-local mount's content could not be captured (ADR-0415 fail-closed capture gate; the checkpoint is non-restorable and must not ship)")

// MountContentCaptureFailedDetail is the typed detail carried alongside ErrMountContentCaptureFailed
// so the gRPC boundary (newMountContentCaptureFailedStatus) can build a structured status with an
// errdetails.ErrorInfo{Reason: MountContentCaptureFailedReason} payload naming the specific mount.
// Unwrap() preserves errors.Is(err, ErrMountContentCaptureFailed) for in-process callers.
type MountContentCaptureFailedDetail struct {
	Mountpoint string
	Cause      string
}

func (d *MountContentCaptureFailedDetail) Error() string {
	return fmt.Sprintf("%v: mount %q — %s", ErrMountContentCaptureFailed, d.Mountpoint, d.Cause)
}

func (d *MountContentCaptureFailedDetail) Unwrap() error { return ErrMountContentCaptureFailed }

// MountContentCaptureFailedReason is the stable, machine-readable errdetails.ErrorInfo.Reason value
// (ADR-0415 fail-closed capture gate) carried on the codes.FailedPrecondition gRPC status the Checkpoint RPC returns
// when an owned-mount content capture fails. The controller reads it via errdetails.ErrorInfo rather
// than error-message prose (see podmigration_controller.go mountContentCaptureFailedReasonFromStatus).
const MountContentCaptureFailedReason = "MOUNT_CONTENT_CAPTURE_FAILED"

// MountContentCaptureFailedReasonDomain is the errdetails.ErrorInfo.Domain paired with the reason.
const MountContentCaptureFailedReasonDomain = "podmotion.io"

// newMountContentCaptureFailedStatus wraps an owned-mount capture failure as a typed
// codes.FailedPrecondition gRPC status carrying an errdetails.ErrorInfo{Reason:
// MountContentCaptureFailedReason} payload (ADR-0415 fail-closed capture gate), mirroring newShmemPagemapMissingStatus.
func newMountContentCaptureFailedStatus(err error) error {
	st := status.New(codes.FailedPrecondition, fmt.Sprintf("checkpoint failed: %v", err))

	info := &errdetails.ErrorInfo{
		Reason: MountContentCaptureFailedReason,
		Domain: MountContentCaptureFailedReasonDomain,
	}
	var detail *MountContentCaptureFailedDetail
	if errors.As(err, &detail) {
		info.Metadata = map[string]string{
			"mountpoint": detail.Mountpoint,
			"cause":      detail.Cause,
		}
	}

	if withDetails, wdErr := st.WithDetails(info); wdErr == nil {
		return withDetails.Err()
	}
	return st.Err()
}
