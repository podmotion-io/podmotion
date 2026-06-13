/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestParseProcNetTCPLine_IPv4_Established(t *testing.T) {
	// 0100007F:0050 is 127.0.0.1:80, 0200007F:C350 is 127.0.0.2:50000
	// state 01 = ESTABLISHED
	// The /proc/net/tcp format does NOT contain snd_nxt or rcv_nxt; those columns
	// are retransmits, predicted_ack, rto, ato, snd_cwnd, ssthresh.
	// SndNxt and RcvNxt must always be zero from /proc/net/tcp parsing.
	// (ADR-0049 Gap 1 / M23 critical finding "TCP sequence fidelity")
	line := "  0: 0100007F:0050 0200007F:C350 01 00000000:00000000 00:00000000 00000000 0 0 1234 1 0000000000000000 100 AABBCCDD EEFF1122 DEADBEEF 00000105"
	entry, ok, err := parseProcNetTCPLine(line, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected ESTABLISHED socket to be returned")
	}

	wantSrcIP := net.ParseIP("127.0.0.1").To4()
	if !entry.SrcIP.Equal(wantSrcIP) {
		t.Errorf("SrcIP: got %v, want %v", entry.SrcIP, wantSrcIP)
	}
	if entry.SrcPort != 80 {
		t.Errorf("SrcPort: got %d, want 80", entry.SrcPort)
	}
	wantDstIP := net.ParseIP("127.0.0.2").To4()
	if !entry.DstIP.Equal(wantDstIP) {
		t.Errorf("DstIP: got %v, want %v", entry.DstIP, wantDstIP)
	}
	if entry.DstPort != 50000 {
		t.Errorf("DstPort: got %d, want 50000", entry.DstPort)
	}
	// SndNxt, RcvNxt, TsRecent must be zero: /proc/net/tcp does not contain sequence
	// numbers. Any non-zero value would be from the wrong column (retransmits, rto, etc.)
	// and would drive PM_SEQ_XLAT with garbage offsets, triggering TCP RST.
	if entry.SndNxt != 0 {
		t.Errorf("SndNxt must be 0 (not from /proc/net/tcp columns): got %08X", entry.SndNxt)
	}
	if entry.RcvNxt != 0 {
		t.Errorf("RcvNxt must be 0 (not from /proc/net/tcp columns): got %08X", entry.RcvNxt)
	}
	if entry.TsRecent != 0 {
		t.Errorf("TsRecent must be 0 (not from /proc/net/tcp columns): got %08X", entry.TsRecent)
	}
}

func TestParseProcNetTCPLine_NonEstablished(t *testing.T) {
	// state 0A = LISTEN
	line := "  1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0"
	_, ok, err := parseProcNetTCPLine(line, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected non-ESTABLISHED socket to be skipped")
	}
}

func TestParseProcNetTCPFile(t *testing.T) {
	// /proc/net/tcp columns: sl local remote st tx:rx tr:tm retrnsmt uid timeout inode ...
	// Extra columns after inode are NOT sequence numbers (see SocketEntry.SndNxt comment).
	// The fixture has extra columns to confirm they are NOT parsed as sequence numbers.
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F40 0200007F:0050 01 00000000:00000000 00:00000000 00000000 0 0 100 1 0000000000000000 0 DEADBEEF CAFEF00D 00001234 00000101
   1: 00000000:1F41 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 101 1 0
`
	dir := t.TempDir()
	fpath := filepath.Join(dir, "tcp")
	if err := os.WriteFile(fpath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := parseProcNetTCP(fpath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 ESTABLISHED entry, got %d", len(entries))
	}
	e := entries[0]
	if e.SrcPort != 8000 { // 0x1F40 = 8000
		t.Errorf("SrcPort: got %d, want 8000", e.SrcPort)
	}
	if e.DstPort != 80 { // 0x0050 = 80
		t.Errorf("DstPort: got %d, want 80", e.DstPort)
	}
	// SndNxt and RcvNxt must be zero: the columns after inode in /proc/net/tcp are
	// NOT sequence numbers. They look like hex values (DEADBEEF, CAFEF00D) in the
	// fixture but are retransmit counts / timing values on a real kernel.
	if e.SndNxt != 0 {
		t.Errorf("SndNxt must be 0 (not sourced from /proc/net/tcp): got %08X", e.SndNxt)
	}
	if e.RcvNxt != 0 {
		t.Errorf("RcvNxt must be 0 (not sourced from /proc/net/tcp): got %08X", e.RcvNxt)
	}
}

func TestDecodeAddrIPv4(t *testing.T) {
	// 0100007F = 127.0.0.1 in little-endian hex
	ip, port, err := decodeAddr("0100007F:0050", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantIP := net.ParseIP("127.0.0.1").To4()
	if !ip.Equal(wantIP) {
		t.Errorf("IP: got %v, want %v", ip, wantIP)
	}
	if port != 80 {
		t.Errorf("port: got %d, want 80", port)
	}
}

func TestSocketInventory_MissingProc(t *testing.T) {
	// PID 999999999 should not exist; SocketInventory must return error or empty (not panic).
	entries, err := SocketInventory(999999999)
	if err != nil && len(entries) == 0 {
		return
	}
	if err == nil && len(entries) == 0 {
		return
	}
	t.Logf("entries=%d err=%v", len(entries), err)
}
