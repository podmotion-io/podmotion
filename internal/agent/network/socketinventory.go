/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SocketEntry describes a single ESTABLISHED TCP socket parsed from
// /proc/net/tcp or /proc/net/tcp6 inside a container's network namespace.
type SocketEntry struct {
	SrcIP    net.IP
	SrcPort  uint16
	DstIP    net.IP
	DstPort  uint16
	SndNxt   uint32
	RcvNxt   uint32
	TsRecent uint32
	WScale   uint8
	SACKEnabled bool
}

// SocketInventory reads the TCP socket table from the network namespace of
// the process at rootPID. It parses both /proc/net/tcp (IPv4) and
// /proc/net/tcp6 (IPv6), returning all sockets in state ESTABLISHED (01).
//
// rootPID is the host-namespace PID of the container's root process.
// The kernel exposes the container netns view at /proc/<pid>/net/tcp[6].
func SocketInventory(rootPID int32) ([]SocketEntry, error) {
	var entries []SocketEntry

	for _, fname := range []string{"tcp", "tcp6"} {
		path := fmt.Sprintf("/proc/%d/net/%s", rootPID, fname)
		parsed, err := parseProcNetTCP(path, fname == "tcp6")
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("socketinventory: parse %s: %w", path, err)
		}
		entries = append(entries, parsed...)
	}
	return entries, nil
}

// SocketInventoryFromNetns reads the TCP socket table from the given network
// namespace path (e.g. /proc/<pid>/ns/net or a named netns file).
// It reads the proc/net files via the proc entry for the given PID, falling
// back to SocketInventory(rootPID) since the kernel exposes per-netns views
// directly under /proc/<pid>/net/.
func SocketInventoryFromNetns(rootPID int32, _ string) ([]SocketEntry, error) {
	return SocketInventory(rootPID)
}

// parseProcNetTCP parses /proc/net/tcp or /proc/net/tcp6 at path.
// isIPv6 toggles the address decoding width (16 bytes vs 4 bytes).
// Only ESTABLISHED sockets (state field == "01") are returned.
// Fields captured per row (0-indexed after the sl: prefix):
//
//	col 1  local_address  hex encoded ip:port (little-endian)
//	col 2  rem_address    hex encoded ip:port
//	col 3  st            socket state (01 = ESTABLISHED)
//
// /proc/net/tcp format (space-separated):
//
//	sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
//
// NOTE: snd_nxt and rcv_nxt are NOT present in /proc/net/tcp[6] in any kernel
// version. The kernel's tcp4_seq_show / tcp6_seq_show never emit them.
// SndNxt / RcvNxt in SocketEntry are left zero; callers must source real
// sequence numbers from TCP_REPAIR getsockopt or the CRIU inetsk image.
func parseProcNetTCP(path string, isIPv6 bool) ([]SocketEntry, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []SocketEntry
	scanner := bufio.NewScanner(f)
	firstLine := true
	for scanner.Scan() {
		line := scanner.Text()
		if firstLine {
			firstLine = false
			continue // skip header
		}
		entry, ok, err := parseProcNetTCPLine(line, isIPv6)
		if err != nil {
			return nil, fmt.Errorf("parse line %q: %w", line, err)
		}
		if ok {
			entries = append(entries, entry)
		}
	}
	return entries, scanner.Err()
}

// parseProcNetTCPLine parses one data row from /proc/net/tcp or /proc/net/tcp6.
// Returns (entry, true, nil) for ESTABLISHED sockets, (zero, false, nil) for
// non-ESTABLISHED, and (zero, false, err) on parse errors.
func parseProcNetTCPLine(line string, isIPv6 bool) (SocketEntry, bool, error) {
	fields := strings.Fields(line)
	// Minimum fields: sl local rem st tx:rx tr:tm retrnsmt uid timeout inode (10 cols)
	if len(fields) < 10 {
		return SocketEntry{}, false, nil
	}

	state := fields[3]
	if state != "01" { // 01 = TCP_ESTABLISHED
		return SocketEntry{}, false, nil
	}

	srcIP, srcPort, err := decodeAddr(fields[1], isIPv6)
	if err != nil {
		return SocketEntry{}, false, fmt.Errorf("decode local addr %q: %w", fields[1], err)
	}
	dstIP, dstPort, err := decodeAddr(fields[2], isIPv6)
	if err != nil {
		return SocketEntry{}, false, fmt.Errorf("decode remote addr %q: %w", fields[2], err)
	}

	entry := SocketEntry{
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   dstIP,
		DstPort: dstPort,
		// SndNxt, RcvNxt, TsRecent are intentionally left zero.
		//
		// IMPORTANT: /proc/net/tcp[6] does NOT contain snd_nxt or rcv_nxt in any
		// column. The kernel's tcp4_seq_show / tcp6_seq_show emit (after inode):
		//   retransmits, predicted_ack, rto, ato, snd_cwnd, ssthresh
		// — none of which are sequence numbers.
		//
		// snd_nxt / rcv_nxt are only obtainable via:
		//   getsockopt(TCP_REPAIR_QUEUE) + TCP_QUEUE_SEQ   (CRIU mechanism), or
		//   inet_diag (INET_DIAG_INFO / TCP_INFO)
		//
		// Parsing positional columns from /proc/net/tcp and treating them as sequence
		// numbers drives PM_SEQ_XLAT with garbage offsets, injecting wrong sequence
		// numbers into the migrated flow and triggering peer RST. Leaving them zero
		// forces callers to obtain real values from the CRIU inetsk image or TCP_REPAIR.
		//
		// See: ADR-0049 Gap 1, M23 critical finding "TCP sequence fidelity".
	}

	// SACK is enabled when the kernel advertised SACK in the SYN exchange; it is not
	// directly readable from /proc/net/tcp. We conservatively assume enabled for
	// ESTABLISHED sockets (the kernel only keeps a socket in ESTABLISHED if the
	// handshake succeeded; SACK negotiation is best-effort and common in modern kernels).
	entry.SACKEnabled = true

	return entry, true, nil
}

// decodeAddr parses a hex-encoded "XXXXXXXX:PPPP" (IPv4) or
// "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PPPP" (IPv6) address as printed by the kernel
// in /proc/net/tcp[6]. The kernel stores addresses in host byte order (little-endian
// on x86/arm64), printed as a hex string with no byte-reversal.
func decodeAddr(s string, isIPv6 bool) (net.IP, uint16, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("unexpected addr format %q", s)
	}

	portRaw, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("parse port %q: %w", parts[1], err)
	}

	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, 0, fmt.Errorf("hex decode addr %q: %w", parts[0], err)
	}

	var ip net.IP
	if isIPv6 {
		if len(raw) != 16 {
			return nil, 0, fmt.Errorf("ipv6 addr %q: expected 16 bytes, got %d", parts[0], len(raw))
		}
		// The kernel prints each 32-bit word in little-endian; reverse each word.
		decoded := make([]byte, 16)
		for i := 0; i < 4; i++ {
			word := binary.LittleEndian.Uint32(raw[i*4 : i*4+4])
			binary.BigEndian.PutUint32(decoded[i*4:i*4+4], word)
		}
		ip = net.IP(decoded)
	} else {
		if len(raw) != 4 {
			return nil, 0, fmt.Errorf("ipv4 addr %q: expected 4 bytes, got %d", parts[0], len(raw))
		}
		// The kernel prints the IPv4 address as a little-endian 32-bit integer.
		word := binary.LittleEndian.Uint32(raw)
		decoded := make([]byte, 4)
		binary.BigEndian.PutUint32(decoded, word)
		ip = net.IP(decoded)
	}

	return ip, uint16(portRaw), nil
}

// parseHex32 parses a hex string (with or without "0x" prefix) as uint32.
func parseHex32(s string) (uint32, error) {
	s = strings.TrimPrefix(s, "0x")
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

// IsIntraPodLoopback reports whether the TCP 4-tuple identified by (srcIP, dstIP)
// is an intra-pod loopback connection: BOTH endpoints are on the loopback range
// (127.0.0.0/8 for IPv4, ::1 for IPv6).
//
// Such a connection has both ends inside the pod's own network namespace — it has
// no external peer. During a pod migration CRIU checkpoints and restores both ends
// atomically (or neither), so its continuity is guaranteed by the restore itself and
// NEVER by TCP sequence-number preservation against a surviving external peer. These
// connections are therefore categorically outside the TCP sequence-continuity
// contract and must not enter the continuity inventory:
//
//   - They are typically ephemeral kubelet exec/TCP health-probe connections (e.g.
//     a `redis-cli ping` readiness probe → 127.0.0.1:6379) that are re-established
//     every probe interval, so the specific ephemeral client port captured at the
//     freeze instant is gone after restore.
//   - Capturing one at freeze is an intermittent race against the probe cadence; the
//     captured-but-unrestorable loopback tuple then scores as an unmatched connection
//     in VerifyTCP and rolls back an otherwise-successful Strict migration.
//
// Requiring BOTH ends to be loopback is the fail-safe direction: a real held client
// connection always has a non-loopback remote peer and is therefore never filtered.
// This is a MIGRATION POLICY, not a fact about the socket table — the low-level
// enumerators (SocketInventory, ExportTCPRepairState) still report every socket
// honestly; callers building a continuity inventory apply this scoping themselves.
func IsIntraPodLoopback(srcIP, dstIP net.IP) bool {
	return srcIP != nil && dstIP != nil && srcIP.IsLoopback() && dstIP.IsLoopback()
}

// FilterMigratableTCP returns the subset of entries whose TCP continuity across a pod
// migration is meaningful — i.e. every ESTABLISHED socket EXCEPT intra-pod loopback
// connections (see IsIntraPodLoopback). The returned slice is a fresh allocation; the
// input is not mutated. Returns nil when no migratable entries remain (the caller's
// fail-closed / non-vacuity logic then treats the migration as having no held
// connections to preserve, which is the correct outcome for a probe-only pod).
func FilterMigratableTCP(entries []SocketEntry) []SocketEntry {
	var out []SocketEntry
	for _, e := range entries {
		if IsIntraPodLoopback(e.SrcIP, e.DstIP) {
			continue
		}
		out = append(out, e)
	}
	return out
}
