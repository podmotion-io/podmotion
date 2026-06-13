/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build linux

package network

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// TestConntrackEntryMatchesPodIP — unit tests for entryMatchesPodIP helper
// ---------------------------------------------------------------------------

func TestConntrackEntryMatchesPodIP(t *testing.T) {
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
	if entryMatchesPodIP(e, "") {
		t.Error("expected no match for empty IP")
	}
}

// ---------------------------------------------------------------------------
// TestRewriteEntry — unit tests for ImportConntrack's tuple rewrite logic
// ---------------------------------------------------------------------------

func TestRewriteEntry(t *testing.T) {
	t.Run("RewriteSourceToDestIP", func(t *testing.T) {
		original := ConntrackEntry{
			SrcIP:        net.ParseIP("10.244.1.5").To4(),
			DstIP:        net.ParseIP("10.96.0.10").To4(),
			ReplySrcIP:   net.ParseIP("10.96.0.10").To4(),
			ReplyDstIP:   net.ParseIP("10.244.1.5").To4(),
		}
		opts := ConntrackImportOptions{
			SourcePodIP: "10.244.1.5",
			DestPodIP:   "10.244.2.7",
		}
		rewritten := rewriteEntry(original, opts)
		assertIP(t, "SrcIP after rewrite", rewritten.SrcIP, "10.244.2.7")
		assertIP(t, "DstIP unchanged", rewritten.DstIP, "10.96.0.10")
		assertIP(t, "ReplyDstIP after rewrite", rewritten.ReplyDstIP, "10.244.2.7")
		assertIP(t, "ReplySrcIP unchanged", rewritten.ReplySrcIP, "10.96.0.10")
	})

	t.Run("NoOpWhenNoPodIPs", func(t *testing.T) {
		original := ConntrackEntry{
			SrcIP: net.ParseIP("10.244.1.5").To4(),
			DstIP: net.ParseIP("10.96.0.10").To4(),
		}
		rewritten := rewriteEntry(original, ConntrackImportOptions{})
		assertIP(t, "SrcIP unchanged", rewritten.SrcIP, "10.244.1.5")
		assertIP(t, "DstIP unchanged", rewritten.DstIP, "10.96.0.10")
	})

	t.Run("NoOpWhenSourceNotMatched", func(t *testing.T) {
		original := ConntrackEntry{
			SrcIP: net.ParseIP("10.244.9.9").To4(),
			DstIP: net.ParseIP("10.96.0.10").To4(),
		}
		opts := ConntrackImportOptions{
			SourcePodIP: "10.244.1.5",
			DestPodIP:   "10.244.2.7",
		}
		rewritten := rewriteEntry(original, opts)
		assertIP(t, "SrcIP unchanged (no match)", rewritten.SrcIP, "10.244.9.9")
	})
}

// ---------------------------------------------------------------------------
// TestImportConntrack — unit tests for ImportConntrack data path
// ---------------------------------------------------------------------------

func TestImportConntrack(t *testing.T) {
	t.Run("EmptyEntriesIsNoOp", func(t *testing.T) {
		err := ImportConntrack(context.Background(), nil, ConntrackImportOptions{})
		if err != nil {
			t.Fatalf("expected nil for empty entries, got: %v", err)
		}
	})

	t.Run("SkipIPVSWhenConfigured", func(t *testing.T) {
		// All entries are IPVS and SkipIPVS=true — no netlink calls attempted.
		// Should return nil without error even if conntrack table is unavailable.
		entries := []ConntrackEntry{
			{
				Protocol:    syscall.IPPROTO_TCP,
				Layer3Proto: unix.AF_INET,
				SrcIP:       net.ParseIP("10.0.0.1").To4(),
				DstIP:       net.ParseIP("10.0.0.2").To4(),
				SrcPort:     1000,
				DstPort:     2000,
				State:       6, // TCP_CONNTRACK_ESTABLISHED
				IsIPVS:      true,
			},
		}
		err := ImportConntrack(context.Background(), entries, ConntrackImportOptions{
			SkipIPVS: true,
		})
		if err != nil {
			t.Fatalf("expected nil error when all IPVS entries skipped, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestPurgeConntrackForPod — validate input guard
// ---------------------------------------------------------------------------

func TestPurgeConntrackForPod(t *testing.T) {
	t.Run("EmptyPodIPReturnsError", func(t *testing.T) {
		err := PurgeConntrackForPod(context.Background(), "")
		if err == nil {
			t.Fatal("PurgeConntrackForPod with empty podIP must return error")
		}
	})
}

// ---------------------------------------------------------------------------
// TestBuildTupleAttr — verify netlink attribute construction
// ---------------------------------------------------------------------------

func TestBuildTupleAttr(t *testing.T) {
	// Build a CTA_TUPLE for a known IPv4 TCP flow and verify the byte output
	// contains the expected IP bytes and port bytes in network byte order.
	src := net.ParseIP("10.244.1.5").To4()
	dst := net.ParseIP("10.96.0.10").To4()
	sport := uint16(54321)
	dport := uint16(80)
	proto := uint8(syscall.IPPROTO_TCP)

	attr := buildTupleAttr(src, dst, sport, dport, proto, unix.AF_INET)
	if len(attr) == 0 {
		t.Fatal("buildTupleAttr returned empty bytes")
	}

	// The attribute bytes must contain the raw IPv4 address bytes.
	if !bytesContain(attr, src) {
		t.Errorf("tuple attr missing src IP bytes %v", src)
	}
	if !bytesContain(attr, dst) {
		t.Errorf("tuple attr missing dst IP bytes %v", dst)
	}

	// Port in network byte order (big-endian).
	var sportBE [2]byte
	sportBE[0] = byte(sport >> 8)
	sportBE[1] = byte(sport)
	if !bytesContain(attr, sportBE[:]) {
		t.Errorf("tuple attr missing sport bytes")
	}
}

// ---------------------------------------------------------------------------
// TestParseIPVSProcLine — verify /proc/net/ip_vs_conn hex parsing
// ---------------------------------------------------------------------------

func TestParseIPVSProcLine(t *testing.T) {
	// /proc/net/ip_vs_conn line format: Pro  FromIP  FPrt  ToIP  TPrt  DestIP  DPrt  State
	// IPs are 8-hex-char big-endian uint32. Ports are 4-hex-char big-endian uint16.
	// 10.244.1.5  = 0xF401A0A (wrong) — let's compute: 10=0x0A 244=0xF4 1=0x01 5=0x05 → 0Af40105
	// 10.96.0.10  = 0A600000A → 0A 60 00 0A → 0A60000A
	// port 54321  = 0xD431
	// port 80     = 0x0050
	line := "TCP 0AF40105 D431 0A60000A 0050 0A60000A 0050 ESTABLISHED"
	entry, ok := parseIPVSProcLine(line)
	if !ok {
		t.Fatal("parseIPVSProcLine returned ok=false")
	}
	if !entry.IsIPVS {
		t.Error("expected IsIPVS=true")
	}
	if entry.Protocol != syscall.IPPROTO_TCP {
		t.Errorf("expected TCP protocol, got %d", entry.Protocol)
	}
	assertIP(t, "SrcIP", entry.SrcIP, "10.244.1.5")
	assertPort(t, "SrcPort", entry.SrcPort, 54321)
	assertIP(t, "DstIP", entry.DstIP, "10.96.0.10")
	assertPort(t, "DstPort", entry.DstPort, 80)
}

// ---------------------------------------------------------------------------
// TestNormalizeIP
// ---------------------------------------------------------------------------

func TestNormalizeIP(t *testing.T) {
	ip4 := net.ParseIP("10.244.1.5") // returns 16-byte internally
	got := normalizeIP(ip4)
	if len(got) != 4 {
		t.Errorf("expected 4-byte IPv4, got %d bytes", len(got))
	}

	ip6 := net.ParseIP("::1")
	got6 := normalizeIP(ip6)
	if len(got6) != 16 {
		t.Errorf("expected 16-byte IPv6, got %d bytes", len(got6))
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

// bytesContain reports whether haystack contains needle as a contiguous subsequence.
func bytesContain(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
outer:
	for i := 0; i <= len(haystack)-len(needle); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}
