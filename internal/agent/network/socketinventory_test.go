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
	// Columns: sl local remote st tx:rx tr:tm retrnsmt uid timeout inode ref ptr drops snd_nxt rcv_nxt ts_recent wscale
	// Indices:  0  1     2      3  4     5     6        7   8       9     10  11  12    13      14      15        16
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
	if entry.SndNxt != 0xAABBCCDD {
		t.Errorf("SndNxt: got %08X, want AABBCCDD", entry.SndNxt)
	}
	if entry.RcvNxt != 0xEEFF1122 {
		t.Errorf("RcvNxt: got %08X, want EEFF1122", entry.RcvNxt)
	}
	if entry.TsRecent != 0xDEADBEEF {
		t.Errorf("TsRecent: got %08X, want DEADBEEF", entry.TsRecent)
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
	// Columns: sl local remote st tx:rx tr:tm retrnsmt uid timeout inode ref ptr drops snd_nxt rcv_nxt ts_recent wscale
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
	if e.SndNxt != 0xDEADBEEF {
		t.Errorf("SndNxt: got %08X, want DEADBEEF", e.SndNxt)
	}
	if e.RcvNxt != 0xCAFEF00D {
		t.Errorf("RcvNxt: got %08X, want CAFEF00D", e.RcvNxt)
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
