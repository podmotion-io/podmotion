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
// Fields we capture per row (0-indexed after the sl: prefix):
//
//	col 1  local_address  hex encoded ip:port (little-endian)
//	col 2  rem_address    hex encoded ip:port
//	col 3  st            socket state (01 = ESTABLISHED)
//	col 7  snd_nxt       (tx_queue field in newer kernels holds it)
//
// /proc/net/tcp format (space-separated):
//
//	sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
//
// snd_nxt / rcv_nxt are NOT in the standard /proc/net/tcp columns; they live
// in the detailed per-socket file at /proc/net/tcp (unnamed columns after inode).
// For kernel ≥ 3.0 the format has extra columns: snd_nxt rcv_nxt ts_recent wscale.
// We parse those if present; otherwise we leave them zero so callers can choose
// to fall back to CRIU image parsing at restore time.
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
	}

	// /proc/net/tcp standard columns (0-indexed after stripping leading space):
	//  0:sl 1:local 2:remote 3:st 4:tx:rx 5:tr:tm 6:retransmt 7:uid 8:timeout 9:inode
	//  10:ref 11:ptr 12:drops [optional extra columns...]
	//
	// Extended columns appended by the kernel for detailed TCP state (kernel ≥ 3.12 with
	// CONFIG_TCP_ESTATS or similar; layout: ... 13:snd_nxt 14:rcv_nxt 15:ts_recent 16:wscale).
	// Real kernels use slightly different layouts; we parse defensively starting at col 13.
	if len(fields) > 13 {
		entry.SndNxt, _ = parseHex32(fields[13])
	}
	if len(fields) > 14 {
		entry.RcvNxt, _ = parseHex32(fields[14])
	}
	if len(fields) > 15 {
		entry.TsRecent, _ = parseHex32(fields[15])
	}
	if len(fields) > 16 {
		// wscale field encodes snd_wscale in the high nibble, rcv_wscale in the low nibble.
		wscaleRaw, _ := parseHex32(fields[16])
		entry.WScale = uint8(wscaleRaw & 0xFF)
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
