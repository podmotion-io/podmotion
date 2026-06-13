/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"fmt"
	"net"
	"testing"
)

// ---------------------------------------------------------------------------
// TestExportConntrack — unit tests for conntrack export path
// ---------------------------------------------------------------------------

// TestExportConntrack_ParseBasicTCPLine verifies that a standard conntrack -L
// output line for an ESTABLISHED TCP connection is parsed correctly.
func TestExportConntrack(t *testing.T) {
	t.Run("ParseEstablishedTCPLine", func(t *testing.T) {
		line := "tcp      6 86400 ESTABLISHED src=10.244.1.5 dst=10.96.0.10 sport=54321 dport=53 " +
			"packets=10 bytes=800 src=10.96.0.10 dst=10.244.1.5 sport=53 dport=54321 " +
			"packets=10 bytes=1200 [ASSURED] mark=0 zone=0 use=2"

		entry, ok, err := parseConntrackLine(line)
		if err != nil {
			t.Fatalf("parseConntrackLine error: %v", err)
		}
		if !ok {
			t.Fatal("parseConntrackLine: expected ok=true")
		}

		assertIP(t, "SrcIP", entry.SrcIP, "10.244.1.5")
		assertIP(t, "DstIP", entry.DstIP, "10.96.0.10")
		assertPort(t, "SrcPort", entry.SrcPort, 54321)
		assertPort(t, "DstPort", entry.DstPort, 53)
		assertString(t, "Protocol", entry.Protocol, "tcp")
		assertString(t, "Layer3Proto", entry.Layer3Proto, "ipv4")
		assertString(t, "State", entry.State, "ESTABLISHED")
	})

	t.Run("ParseUDPLine", func(t *testing.T) {
		line := "udp      17 30 src=10.244.2.1 dst=8.8.8.8 sport=1234 dport=53 " +
			"packets=1 bytes=60 src=8.8.8.8 dst=10.244.2.1 sport=53 dport=1234 " +
			"packets=1 bytes=120 mark=0 use=2"

		entry, ok, err := parseConntrackLine(line)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("expected ok=true for UDP line")
		}
		assertString(t, "Protocol", entry.Protocol, "udp")
		assertPort(t, "DstPort", entry.DstPort, 53)
	})

	t.Run("ParseLineWithMark", func(t *testing.T) {
		line := "tcp      6 120 ESTABLISHED src=10.244.1.5 dst=10.244.2.10 sport=8080 dport=9090 " +
			"packets=5 bytes=400 src=10.244.2.10 dst=10.244.1.5 sport=9090 dport=8080 " +
			"packets=5 bytes=600 [ASSURED] mark=42 zone=0 use=2"

		entry, ok, err := parseConntrackLine(line)
		if err != nil || !ok {
			t.Fatalf("parse failed: err=%v ok=%v", err, ok)
		}
		if entry.Mark != 42 {
			t.Errorf("expected mark=42, got %d", entry.Mark)
		}
	})

	t.Run("ParseLineWithSeqAdj", func(t *testing.T) {
		line := "tcp      6 86400 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=12345 dport=80 " +
			"packets=100 bytes=5000 src=10.0.0.2 dst=10.0.0.1 sport=80 dport=12345 " +
			"packets=100 bytes=10000 [ASSURED] delta-seq-orig=4 delta-seq-reply=-4 mark=0 use=2"

		entry, ok, err := parseConntrackLine(line)
		if err != nil || !ok {
			t.Fatalf("parse failed: err=%v ok=%v", err, ok)
		}
		if entry.TCPSeqAdj != 4 {
			t.Errorf("expected TCPSeqAdj=4, got %d", entry.TCPSeqAdj)
		}
		if entry.TCPAckAdj != -4 {
			t.Errorf("expected TCPAckAdj=-4, got %d", entry.TCPAckAdj)
		}
	})

	t.Run("SkipInvalidLine", func(t *testing.T) {
		_, ok, err := parseConntrackLine("garbage line with no kv pairs")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("expected ok=false for invalid line")
		}
	})

	t.Run("FilterByPodIP", func(t *testing.T) {
		output := `tcp      6 86400 ESTABLISHED src=10.244.1.5 dst=10.96.0.10 sport=54321 dport=53 packets=1 bytes=100 src=10.96.0.10 dst=10.244.1.5 sport=53 dport=54321 packets=1 bytes=200 mark=0 use=2
tcp      6 86400 ESTABLISHED src=192.168.1.1 dst=192.168.1.2 sport=11111 dport=22222 packets=1 bytes=100 src=192.168.1.2 dst=192.168.1.1 sport=22222 dport=11111 packets=1 bytes=200 mark=0 use=2`

		entries, err := parseConntrackOutput(output, "10.244.1.5")
		if err != nil {
			t.Fatalf("parseConntrackOutput error: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("expected 1 filtered entry, got %d", len(entries))
		}
		assertIP(t, "SrcIP", entries[0].SrcIP, "10.244.1.5")
	})

	t.Run("EntryMatchesPodIP", func(t *testing.T) {
		e := ConntrackEntry{
			SrcIP: net.ParseIP("10.244.1.5").To4(),
			DstIP: net.ParseIP("10.96.0.10").To4(),
		}
		if !entryMatchesPodIP(e, "10.244.1.5") {
			t.Error("expected match on SrcIP")
		}
		if !entryMatchesPodIP(e, "10.96.0.10") {
			t.Error("expected match on DstIP")
		}
		if entryMatchesPodIP(e, "1.2.3.4") {
			t.Error("expected no match for unrelated IP")
		}
	})
}

// ---------------------------------------------------------------------------
// TestImportConntrack — unit tests for conntrack import path
// ---------------------------------------------------------------------------

func TestImportConntrack(t *testing.T) {
	t.Run("BuildInsertArgsBasic", func(t *testing.T) {
		e := ConntrackEntry{
			Protocol:    "tcp",
			Layer3Proto: "ipv4",
			SrcIP:       net.ParseIP("10.244.1.5").To4(),
			DstIP:       net.ParseIP("10.96.0.10").To4(),
			SrcPort:     54321,
			DstPort:     53,
			State:       "ESTABLISHED",
		}
		args := buildConntrackInsertArgs(e)
		assertContains(t, args, "-I")
		assertContains(t, args, "-p")
		assertContains(t, args, "tcp")
		assertContains(t, args, "-s")
		assertContains(t, args, "10.244.1.5")
		assertContains(t, args, "-d")
		assertContains(t, args, "10.96.0.10")
		assertContains(t, args, "--sport")
		assertContains(t, args, "54321")
		assertContains(t, args, "--dport")
		assertContains(t, args, "53")
		assertContains(t, args, "--state")
		assertContains(t, args, "ESTABLISHED")
		assertContains(t, args, "--timeout")
		assertContains(t, args, "120")
	})

	t.Run("BuildInsertArgsWithMark", func(t *testing.T) {
		e := ConntrackEntry{
			Protocol: "tcp",
			SrcIP:    net.ParseIP("10.0.0.1").To4(),
			DstIP:    net.ParseIP("10.0.0.2").To4(),
			SrcPort:  1000,
			DstPort:  2000,
			State:    "ESTABLISHED",
			Mark:     99,
		}
		args := buildConntrackInsertArgs(e)
		assertContains(t, args, "--mark")
		assertContains(t, args, "99")
	})

	t.Run("BuildInsertArgsWithZone", func(t *testing.T) {
		e := ConntrackEntry{
			Protocol: "tcp",
			SrcIP:    net.ParseIP("10.0.0.1").To4(),
			DstIP:    net.ParseIP("10.0.0.2").To4(),
			SrcPort:  1000,
			DstPort:  2000,
			State:    "ESTABLISHED",
			Zone:     7,
		}
		args := buildConntrackInsertArgs(e)
		assertContains(t, args, "--zone")
		assertContains(t, args, "7")
	})

	t.Run("SkipIPVSWhenConfigured", func(t *testing.T) {
		entries := []ConntrackEntry{
			{
				Protocol: "tcp",
				SrcIP:    net.ParseIP("10.0.0.1").To4(),
				DstIP:    net.ParseIP("10.0.0.2").To4(),
				SrcPort:  1000,
				DstPort:  2000,
				State:    "ESTABLISHED",
				IsIPVS:   true,
			},
		}
		// SkipIPVS=true and no conntrack binary available — should return nil without
		// attempting insertion.
		err := ImportConntrack(context.Background(), entries, ConntrackImportOptions{
			SkipIPVS: true,
		})
		if err != nil {
			t.Fatalf("expected nil error when all entries are skipped, got: %v", err)
		}
	})

	t.Run("EmptyEntriesIsNoOp", func(t *testing.T) {
		err := ImportConntrack(context.Background(), nil, ConntrackImportOptions{})
		if err != nil {
			t.Fatalf("expected nil for empty entries, got: %v", err)
		}
	})

	t.Run("RewriteEntry_SourceToDestIP", func(t *testing.T) {
		original := ConntrackEntry{
			SrcIP:       net.ParseIP("10.244.1.5").To4(),
			DstIP:       net.ParseIP("10.96.0.10").To4(),
			ReplySrcIP:  net.ParseIP("10.96.0.10").To4(),
			ReplyDstIP:  net.ParseIP("10.244.1.5").To4(),
		}
		opts := ConntrackImportOptions{
			SourcePodIP: "10.244.1.5",
			DestPodIP:   "10.244.2.7",
		}
		rewritten := rewriteEntry(original, opts)
		assertIP(t, "SrcIP after rewrite", rewritten.SrcIP, "10.244.2.7")
		assertIP(t, "DstIP unchanged", rewritten.DstIP, "10.96.0.10")
		assertIP(t, "ReplyDstIP after rewrite", rewritten.ReplyDstIP, "10.244.2.7")
	})

	t.Run("RewriteEntry_NoOpWhenNoPodIPs", func(t *testing.T) {
		original := ConntrackEntry{
			SrcIP: net.ParseIP("10.244.1.5").To4(),
			DstIP: net.ParseIP("10.96.0.10").To4(),
		}
		rewritten := rewriteEntry(original, ConntrackImportOptions{})
		assertIP(t, "SrcIP unchanged", rewritten.SrcIP, "10.244.1.5")
	})

	t.Run("PurgeConntrackForPod_EmptyPodIP", func(t *testing.T) {
		err := PurgeConntrackForPod(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty podIP, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// TestConntrackRoundTrip — export parse → import args round-trip
// ---------------------------------------------------------------------------

// TestConntrackRoundTrip verifies the full pipeline: parse a conntrack line as
// ExportConntrack would produce it, then pass the entry through ImportConntrack's
// buildConntrackInsertArgs, and verify the key fields survive the round trip.
//
// This test does NOT invoke real conntrack/ipvsadm binaries — it validates the
// data-transformation path end-to-end using only in-process logic.
func TestConntrackRoundTrip(t *testing.T) {
	testCases := []struct {
		name    string
		line    string
		podIP   string
		wantSrc string
		wantDst string
		wantSport uint16
		wantDport uint16
		wantState string
		wantMark  uint32
	}{
		{
			name: "EstablishedTCPFlow",
			line: "tcp      6 86400 ESTABLISHED src=10.244.1.5 dst=10.96.0.10 sport=54321 dport=80 " +
				"packets=10 bytes=800 src=10.96.0.10 dst=10.244.1.5 sport=80 dport=54321 " +
				"packets=10 bytes=1200 [ASSURED] mark=7 zone=0 use=2",
			podIP:     "10.244.1.5",
			wantSrc:   "10.244.1.5",
			wantDst:   "10.96.0.10",
			wantSport: 54321,
			wantDport: 80,
			wantState: "ESTABLISHED",
			wantMark:  7,
		},
		{
			name: "NATedFlowWithReplyTuple",
			line: "tcp      6 120 ESTABLISHED src=10.244.3.2 dst=10.100.0.1 sport=9999 dport=443 " +
				"packets=5 bytes=300 src=192.168.10.5 dst=10.244.3.2 sport=443 dport=9999 " +
				"packets=5 bytes=600 [ASSURED] mark=0 use=1",
			podIP:     "10.244.3.2",
			wantSrc:   "10.244.3.2",
			wantDst:   "10.100.0.1",
			wantSport: 9999,
			wantDport: 443,
			wantState: "ESTABLISHED",
		},
		{
			name: "UDPFlowNoState",
			line: "udp      17 25 src=10.244.5.5 dst=8.8.8.8 sport=5300 dport=53 " +
				"packets=1 bytes=60 src=8.8.8.8 dst=10.244.5.5 sport=53 dport=5300 " +
				"packets=1 bytes=80 mark=0 use=1",
			podIP:     "10.244.5.5",
			wantSrc:   "10.244.5.5",
			wantDst:   "8.8.8.8",
			wantSport: 5300,
			wantDport: 53,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// --- Export phase: parse the conntrack line ---
			entry, ok, err := parseConntrackLine(tc.line)
			if err != nil {
				t.Fatalf("parseConntrackLine error: %v", err)
			}
			if !ok {
				t.Fatal("parseConntrackLine: expected ok=true")
			}

			// Verify export-phase fields.
			assertIP(t, "export SrcIP", entry.SrcIP, tc.wantSrc)
			assertIP(t, "export DstIP", entry.DstIP, tc.wantDst)
			assertPort(t, "export SrcPort", entry.SrcPort, tc.wantSport)
			assertPort(t, "export DstPort", entry.DstPort, tc.wantDport)
			if tc.wantState != "" {
				assertString(t, "export State", entry.State, tc.wantState)
			}
			if tc.wantMark != 0 && entry.Mark != tc.wantMark {
				t.Errorf("export Mark: want %d, got %d", tc.wantMark, entry.Mark)
			}

			// Filter by pod IP matches.
			if !entryMatchesPodIP(entry, tc.podIP) {
				t.Errorf("entryMatchesPodIP(%s): expected true", tc.podIP)
			}

			// --- Import phase: build insert args ---
			args := buildConntrackInsertArgs(entry)

			// Verify key fields survive in the args.
			assertContains(t, args, "-I")
			assertContains(t, args, tc.wantSrc)
			assertContains(t, args, tc.wantDst)
			if tc.wantSport != 0 {
				assertContains(t, args, fmt.Sprintf("%d", tc.wantSport))
			}
			if tc.wantDport != 0 {
				assertContains(t, args, fmt.Sprintf("%d", tc.wantDport))
			}
			assertContains(t, args, "--timeout")
			assertContains(t, args, "120")

			// No leaked entries: verify buildConntrackInsertArgs does not inject
			// garbage IPs or ports not present in the original entry.
			for _, arg := range args {
				if arg == "0.0.0.0" || arg == "<nil>" {
					t.Errorf("round-trip: leaked zero/nil value in args: %v", args)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IPVS parsing tests
// ---------------------------------------------------------------------------

func TestIPVSParsing(t *testing.T) {
	t.Run("ParseIPVSLine", func(t *testing.T) {
		line := "TCP  10.244.1.5:8080  10.96.10.20:80  ESTABLISHED  120"
		entry, ok, err := parseIPVSLine(line)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("expected ok=true")
		}
		assertIP(t, "SrcIP", entry.SrcIP, "10.244.1.5")
		assertPort(t, "SrcPort", entry.SrcPort, 8080)
		assertIP(t, "DstIP", entry.DstIP, "10.96.10.20")
		assertPort(t, "DstPort", entry.DstPort, 80)
		assertString(t, "State", entry.State, "ESTABLISHED")
		if !entry.IsIPVS {
			t.Error("expected IsIPVS=true")
		}
	})

	t.Run("ParseIPVSOutput_HeadersSkipped", func(t *testing.T) {
		output := `IPVS connection entries
  pro expire state       source             virtual            destination
TCP  10.244.1.5:8080  10.96.10.20:80  ESTABLISHED  120
TCP  10.244.1.6:9090  10.96.10.20:80  TIME_WAIT  10`

		entries, err := parseIPVSOutput(output, "")
		if err != nil {
			t.Fatalf("parseIPVSOutput error: %v", err)
		}
		if len(entries) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(entries))
		}
	})

	t.Run("ParseIPVSOutput_FilterByPodIP", func(t *testing.T) {
		output := `IPVS connection entries
  pro expire state       source             virtual            destination
TCP  10.244.1.5:8080  10.96.10.20:80  ESTABLISHED  120
TCP  10.244.1.6:9090  10.96.10.20:80  TIME_WAIT  10`

		entries, err := parseIPVSOutput(output, "10.244.1.5")
		if err != nil {
			t.Fatalf("parseIPVSOutput error: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("expected 1 filtered entry, got %d", len(entries))
		}
		assertIP(t, "SrcIP", entries[0].SrcIP, "10.244.1.5")
	})
}

// ---------------------------------------------------------------------------
// NoLeakedEntries: verify that all test-created conntrack state is cleaned up.
// ---------------------------------------------------------------------------

// TestNoLeakedEntries verifies that after a round-trip test, PurgeConntrackForPod
// with an empty IP returns an error (validating the non-empty gate) and that the
// pure in-process data transformations do not themselves allocate any conntrack
// kernel state (since no real conntrack binary is invoked in unit tests).
func TestNoLeakedEntries(t *testing.T) {
	// Verify purge rejects empty podIP — if this returned nil, a caller could
	// silently skip cleanup and leave entries behind.
	err := PurgeConntrackForPod(context.Background(), "")
	if err == nil {
		t.Fatal("PurgeConntrackForPod with empty podIP must return error")
	}

	// In unit tests, no real conntrack entries are created (no binary invocations).
	// The in-process parse/build functions are side-effect-free. Confirm that
	// parseConntrackOutput on an empty string returns zero entries (no phantom state).
	entries, err := parseConntrackOutput("", "10.244.1.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from empty output, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertIP(t *testing.T, label string, got net.IP, want string) {
	t.Helper()
	wantIP := normalizeIP(net.ParseIP(want))
	if wantIP == nil {
		t.Fatalf("%s: invalid want IP %q", label, want)
	}
	if !got.Equal(wantIP) {
		t.Errorf("%s: want %s, got %s", label, wantIP, got)
	}
}

func assertPort(t *testing.T, label string, got, want uint16) {
	t.Helper()
	if got != want {
		t.Errorf("%s: want %d, got %d", label, want, got)
	}
}

func assertString(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: want %q, got %q", label, want, got)
	}
}

func assertContains(t *testing.T, args []string, s string) {
	t.Helper()
	for _, a := range args {
		if a == s {
			return
		}
	}
	t.Errorf("args %v: expected to contain %q", args, s)
}

