//go:build linux

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"encoding/binary"
	"errors"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ──────────────────────────────────────────────────────────────────────────────
// ADR-0357 D1.2 — LookupSeqXlat real bpf_map_lookup round-trip (§P-VERIFY assertion 1).
//
// Loading a real BPF collection requires CAP_BPF/CAP_SYS_ADMIN (BPF_PROG_LOAD). This test is
// skipped, not failed, when that privilege is unavailable — matching the established pattern in
// this package (adr0355_pmdst0_idempotency_test.go, tcprepair_export_test.go) for tests that
// need real kernel privilege the sandboxed CI/dev environment does not grant.
// ──────────────────────────────────────────────────────────────────────────────

// TestCiliumEBPFManager_LookupSeqXlat_RoundTrip seeds an entry via ArmRelay then confirms
// LookupSeqXlat returns found=true with the exact key/value round-tripped — the literal
// §P-VERIFY assertion 1 requirement for the new EBPFManager method.
func TestCiliumEBPFManager_LookupSeqXlat_RoundTrip(t *testing.T) {
	ctx := context.Background()
	m := newCiliumEBPFManager()

	key := SeqXlatKey{
		SrcIP:   [4]byte{10, 244, 1, 70},
		DstIP:   [4]byte{10, 244, 0, 70},
		SrcPort: 12345,
		DstPort: 5432,
	}
	entry := SeqXlatEntry{
		SeqDelta:    1234,
		AckDelta:    5678,
		TsDelta:     42,
		Wscale:      7,
		SackPresent: 1,
		State:       1,
	}

	if err := m.ArmRelay(ctx, "lo", key, entry); err != nil {
		t.Skipf("ArmRelay failed (likely no CAP_BPF/CAP_SYS_ADMIN in this environment): %v", err)
	}
	defer func() { _ = m.DisarmRelay(ctx, key) }()

	got, found, err := m.LookupSeqXlat(ctx, key)
	if err != nil {
		t.Fatalf("LookupSeqXlat: unexpected error: %v", err)
	}
	if !found {
		t.Fatal("LookupSeqXlat: expected found=true immediately after ArmRelay, got false")
	}
	if got != entry {
		t.Errorf("LookupSeqXlat: round-tripped entry mismatch: got %+v, want %+v", got, entry)
	}
}

// TestCiliumEBPFManager_LookupSeqXlat_NotFound confirms LookupSeqXlat reports found=false
// (nil error) for a key that was never armed — the entry-genuinely-absent case, distinct from
// an actual lookup error.
func TestCiliumEBPFManager_LookupSeqXlat_NotFound(t *testing.T) {
	ctx := context.Background()
	m := newCiliumEBPFManager()

	armedKey := SeqXlatKey{SrcIP: [4]byte{10, 244, 1, 71}, DstIP: [4]byte{10, 244, 0, 71}, SrcPort: 1, DstPort: 2}
	if err := m.ArmRelay(ctx, "lo", armedKey, SeqXlatEntry{State: 1}); err != nil {
		t.Skipf("ArmRelay failed (likely no CAP_BPF/CAP_SYS_ADMIN in this environment): %v", err)
	}
	defer func() { _ = m.DisarmRelay(ctx, armedKey) }()

	neverArmedKey := SeqXlatKey{SrcIP: [4]byte{10, 244, 1, 72}, DstIP: [4]byte{10, 244, 0, 72}, SrcPort: 3, DstPort: 4}
	_, found, err := m.LookupSeqXlat(ctx, neverArmedKey)
	if err != nil {
		t.Fatalf("LookupSeqXlat: unexpected error for absent key: %v", err)
	}
	if found {
		t.Error("LookupSeqXlat: expected found=false for a key that was never armed, got true")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// ADR-0204 — readNetlinkAck correlated-read regression tests.
//
// These exercise the Seq/Pid correlation + errno classification of readNetlinkAck
// WITHOUT a real netlink socket. We use a unix pipe: craft the exact bytes the
// kernel would deliver into the write end, then readNetlinkAck reads them from the
// read end via unix.Read. This reproduces the gate-bug case — a wrong-Seq datagram
// arriving before the correlated NLMSG_ERROR — deterministically.
// ──────────────────────────────────────────────────────────────────────────────

// buildNlmsgErr crafts a raw NLMSG_ERROR datagram (NlMsghdr + int32 errno + the
// echoed request header per the netlink protocol; readNetlinkAck only needs the
// errno word so the echoed header is zero-filled).
func buildNlmsgErr(seq, pid uint32, errno int32) []byte {
	const errBodyLen = 4 + nlmsgHdrSize // errno + echoed request hdr
	total := nlmsgHdrSize + errBodyLen
	buf := make([]byte, total)
	hdr := unix.NlMsghdr{
		Len:  uint32(total),
		Type: unix.NLMSG_ERROR,
		Seq:  seq,
		Pid:  pid,
	}
	copy(buf[:nlmsgHdrSize], (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:])
	binary.LittleEndian.PutUint32(buf[nlmsgHdrSize:], uint32(errno))
	return buf
}

// buildNoop crafts a non-error netlink message with an arbitrary type, used to
// supply a wrong-Seq datagram for the skip test.
func buildMsg(seq, pid uint32, typ uint16) []byte {
	total := nlmsgHdrSize
	buf := make([]byte, total)
	hdr := unix.NlMsghdr{
		Len:  uint32(total),
		Type: typ,
		Seq:  seq,
		Pid:  pid,
	}
	copy(buf[:nlmsgHdrSize], (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:])
	return buf
}

// newPipeFDs returns (readFD, writeFD) from a unix pipe; both are closed via the
// returned cleanup func.
func newPipeFDs(t *testing.T) (int, int, func()) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	return fds[0], fds[1], func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	}
}

func TestReadNetlinkAck_MatchingSeqPid_Success(t *testing.T) {
	rfd, wfd, cleanup := newPipeFDs(t)
	defer cleanup()

	const seq, pid = uint32(7), uint32(4242)
	if _, err := unix.Write(wfd, buildNlmsgErr(seq, pid, 0)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := readNetlinkAck(rfd, seq, pid); err != nil {
		t.Errorf("expected nil on errno=0 matching Seq/Pid, got %v", err)
	}
}

func TestReadNetlinkAck_WrongSeqSkipped(t *testing.T) {
	rfd, wfd, cleanup := newPipeFDs(t)
	defer cleanup()

	const seq, pid = uint32(11), uint32(909)
	// First datagram: wrong Seq (a stale RTM_NEWLINK-class message) — must be skipped.
	if _, err := unix.Write(wfd, buildMsg(seq+1, pid, unix.RTM_NEWLINK)); err != nil {
		t.Fatalf("write wrong-seq: %v", err)
	}
	// Second datagram: correct Seq/Pid, errno=0.
	if _, err := unix.Write(wfd, buildNlmsgErr(seq, pid, 0)); err != nil {
		t.Fatalf("write correct: %v", err)
	}
	if err := readNetlinkAck(rfd, seq, pid); err != nil {
		t.Errorf("expected nil after skipping wrong-Seq datagram, got %v", err)
	}
}

func TestReadNetlinkAck_WrongPidSkipped(t *testing.T) {
	rfd, wfd, cleanup := newPipeFDs(t)
	defer cleanup()

	const seq, pid = uint32(3), uint32(5000)
	// Datagram for a different socket port (wrong Pid) — must be skipped.
	if _, err := unix.Write(wfd, buildNlmsgErr(seq, pid+1, 0)); err != nil {
		t.Fatalf("write wrong-pid: %v", err)
	}
	if _, err := unix.Write(wfd, buildNlmsgErr(seq, pid, 0)); err != nil {
		t.Fatalf("write correct: %v", err)
	}
	if err := readNetlinkAck(rfd, seq, pid); err != nil {
		t.Errorf("expected nil after skipping wrong-Pid datagram, got %v", err)
	}
}

func TestReadNetlinkAck_EEXISTIsSuccess(t *testing.T) {
	rfd, wfd, cleanup := newPipeFDs(t)
	defer cleanup()

	const seq, pid = uint32(21), uint32(1212)
	if _, err := unix.Write(wfd, buildNlmsgErr(seq, pid, -int32(syscall.EEXIST))); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := readNetlinkAck(rfd, seq, pid); err != nil {
		t.Errorf("expected nil on -EEXIST (idempotent success), got %v", err)
	}
}

func TestReadNetlinkAck_RealErrno(t *testing.T) {
	rfd, wfd, cleanup := newPipeFDs(t)
	defer cleanup()

	const seq, pid = uint32(99), uint32(7) // pid must be non-zero distinct value
	if _, err := unix.Write(wfd, buildNlmsgErr(seq, pid, -int32(syscall.EPERM))); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := readNetlinkAck(rfd, seq, pid)
	if err == nil {
		t.Fatal("expected non-nil error on -EPERM")
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Errorf("expected surfaced EPERM, got %v", err)
	}
}

// TestNextNlSeq_MonotonicNonZero confirms the atomic Seq source never returns 0
// and advances (ADR-0204 Decision 3).
func TestNextNlSeq_MonotonicNonZero(t *testing.T) {
	a := nextNlSeq()
	b := nextNlSeq()
	if a == 0 || b == 0 {
		t.Errorf("nextNlSeq returned 0: a=%d b=%d", a, b)
	}
	if a == b {
		t.Errorf("nextNlSeq not advancing: a=%d b=%d", a, b)
	}
}
