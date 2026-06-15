/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestExportTCPRepairState_LiveSocket verifies GC-27: snd_nxt and rcv_nxt are
// non-zero after ExportTCPRepairState reads a live TCP socket via TCP_REPAIR.
//
// This test creates a local TCP connection, sends data to advance sequence
// numbers beyond the initial ISN, then calls ExportTCPRepairState on the
// current process PID. It requires CAP_NET_ADMIN (runs as root in CI/agent).
func TestExportTCPRepairState_LiveSocket(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("TestExportTCPRepairState_LiveSocket: requires root / CAP_NET_ADMIN for TCP_REPAIR")
	}

	// Create a listening TCP server on loopback.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverAddr := ln.Addr().String()

	type serverResult struct {
		conn net.Conn
		err  error
	}
	srvCh := make(chan serverResult, 1)
	go func() {
		c, e := ln.Accept()
		srvCh <- serverResult{c, e}
	}()

	// Connect client.
	clientConn, err := net.Dial("tcp4", serverAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	sr := <-srvCh
	if sr.err != nil {
		t.Fatalf("accept: %v", sr.err)
	}
	serverConn := sr.conn
	defer serverConn.Close()

	// Send enough data to advance SND.NXT well past the ISN.
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i & 0xFF)
	}
	for i := 0; i < 5; i++ {
		if _, werr := clientConn.Write(payload); werr != nil {
			t.Fatalf("client write %d: %v", i, werr)
		}
		buf := make([]byte, 8192)
		if _, rerr := serverConn.Read(buf); rerr != nil {
			t.Fatalf("server read %d: %v", i, rerr)
		}
	}
	// Let ACKs propagate.
	time.Sleep(50 * time.Millisecond)

	// ExportTCPRepairState on the current process PID.
	pid := int32(os.Getpid()) //nolint:gosec
	entries, err := ExportTCPRepairState(pid)
	if err != nil {
		t.Fatalf("ExportTCPRepairState(pid=%d): %v", pid, err)
	}
	if len(entries) == 0 {
		t.Fatalf("ExportTCPRepairState: no ESTABLISHED sockets found for pid %d", pid)
	}

	// Find our loopback connection in the results.
	_, serverPort, _ := net.SplitHostPort(serverAddr)
	var found *SocketEntry
	for i := range entries {
		e := &entries[i]
		t.Logf("socket: %s:%d -> %s:%d snd_nxt=0x%08X rcv_nxt=0x%08X",
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.SndNxt, e.RcvNxt)
		if e.DstIP.String() == "127.0.0.1" && strconv.Itoa(int(e.DstPort)) == serverPort {
			found = e
		}
	}

	if found == nil {
		t.Fatalf("GC-27 FAIL: did not find loopback socket to %s in ExportTCPRepairState output", serverAddr)
	}

	// GC-27: snd_nxt and rcv_nxt must be non-zero (data was sent).
	if found.SndNxt == 0 {
		t.Errorf("GC-27 FAIL: snd_nxt=0 for socket %s:%d->%s:%d; TCP_REPAIR export did not return sequence number",
			found.SrcIP, found.SrcPort, found.DstIP, found.DstPort)
	} else {
		t.Logf("GC-27 PASS: snd_nxt=0x%08X (%d)", found.SndNxt, found.SndNxt)
	}
	if found.RcvNxt == 0 {
		t.Errorf("GC-27 FAIL: rcv_nxt=0 for socket; TCP_REPAIR export did not return recv sequence number")
	} else {
		t.Logf("GC-27 PASS: rcv_nxt=0x%08X (%d)", found.RcvNxt, found.RcvNxt)
	}
}
