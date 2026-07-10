/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// ctr_masked_mount_test.go — live-bug regression for the postgres checkpoint failure (2026-07-10).
//
// Live failure: postgres (TCPPreservationMode=None → tcpEstablished=false) checkpointed via
// `ctr tasks checkpoint`, whose runc-driven CRIU invocation carries NONE of the agent's
// --skip-mnt list. CRIU's mountpoint-dump pass aborted on the masked bind over /proc/interrupts:
//
//	Error (criu/mount.c:753): mnt: 625:./proc/interrupts doesn't have a proper root mount
//	Dumping FAILED.
//
// Because the failure is a MOUNT error, not a TCP one, the old classifier fell through to the
// fatal `return err` branch — it never emitted ErrCtrInFlightTCP, so the Checkpoint RPC hard-failed
// at server.go and never reached the raw go-criu Dump path where the dump-side skipMnts would have
// skipped /proc/interrupts. These tests pin the fix: a masked-mount dump abort classifies as
// ErrCtrMaskedMount (which the Checkpoint RPC now treats as a raw-CRIU fall-through, exactly like
// ErrCtrInFlightTCP), while a genuinely-fatal ctr failure stays fatal.

import (
	"errors"
	"testing"
)

func TestClassifyCtrCheckpointFailure_MaskedMount(t *testing.T) {
	rawErr := errors.New("exit status 1")
	// Verbatim CRIU mount-pass diagnostic from the live postgres dump.log (2026-07-10).
	out := "ctr: runc did not terminate successfully: exit status 1\n" +
		"--- criu-dump.log ---\n" +
		"(00.100258) Error (criu/mount.c:753): mnt: 625:./proc/interrupts doesn't have a proper root mount\n" +
		"(00.100300) Dumping FAILED.\n"

	// postgres is None → tcpEstablished=false; dump log WAS readable.
	got := classifyCtrCheckpointFailure(out, rawErr, true, false)
	if !errors.Is(got, ErrCtrMaskedMount) {
		t.Fatalf("masked-mount dump abort must classify as ErrCtrMaskedMount (raw-CRIU fall-through); got %v", got)
	}
	// It must NOT be misclassified as the TCP class.
	if errors.Is(got, ErrCtrInFlightTCP) {
		t.Errorf("masked-mount failure must not be ErrCtrInFlightTCP")
	}
}

func TestClassifyCtrCheckpointFailure_InFlightTCPStillClassified(t *testing.T) {
	rawErr := errors.New("exit status 1")
	out := "criu: inet: Connected TCP socket, consider using --tcp-established option\nsk-inet.c\n"
	got := classifyCtrCheckpointFailure(out, rawErr, true, true)
	if !errors.Is(got, ErrCtrInFlightTCP) {
		t.Fatalf("established-TCP failure must classify as ErrCtrInFlightTCP; got %v", got)
	}
}

func TestClassifyCtrCheckpointFailure_GenuineFatalStaysFatal(t *testing.T) {
	rawErr := errors.New("exit status 137")
	// An OOM/other fatal failure with a readable dump log and no mount/TCP diagnostic must NOT be
	// coerced into a fall-through sentinel — that would loop the raw-CRIU path onto the same wall.
	out := "ctr: task killed (OOM)\n--- criu-dump.log ---\n(00.5) Error (criu/cr-dump.c): killed\n"
	got := classifyCtrCheckpointFailure(out, rawErr, true, false)
	if errors.Is(got, ErrCtrMaskedMount) || errors.Is(got, ErrCtrInFlightTCP) {
		t.Fatalf("genuine fatal ctr failure must not classify as a raw-CRIU fall-through sentinel; got %v", got)
	}
	if !errors.Is(got, rawErr) {
		t.Errorf("fatal classification must wrap the raw exec error; got %v", got)
	}
}

func TestClassifyCtrCheckpointFailure_UnreadableLogFailSafeTCP(t *testing.T) {
	rawErr := errors.New("exit status 1")
	// Dump log unreadable + TCP preservation requested → ADR-0213 D2 fail-safe to TCP class so the
	// migration falls back to raw CRIU with --tcp-established rather than aborting.
	out := "ctr: runc did not terminate successfully: exit status 1\n"
	got := classifyCtrCheckpointFailure(out, rawErr, false, true)
	if !errors.Is(got, ErrCtrInFlightTCP) {
		t.Fatalf("unreadable log + tcpEstablished must fail-safe to ErrCtrInFlightTCP; got %v", got)
	}
}
