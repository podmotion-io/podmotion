/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ConntrackEntry represents a single conntrack table entry captured at freeze time.
// The structure supports both iptables/netfilter conntrack and IPVS conntrack paths.
//
// ADR-0108: conntrack state must be exported at freeze and imported at restore so
// the kernel on the destination node sees the same flow state that the remote peer
// expects. Without import the first response packet from the restored pod triggers
// an RST because the kernel has no matching conntrack entry.
type ConntrackEntry struct {
	// Protocol is the L4 protocol name as returned by conntrack: "tcp", "udp", "icmp".
	Protocol string
	// Layer3Proto is the network layer protocol: "ipv4" or "ipv6".
	Layer3Proto string

	// SrcIP / DstIP are the original direction tuple.
	SrcIP  net.IP
	DstIP  net.IP
	SrcPort uint16
	DstPort uint16

	// State is the conntrack state string (e.g. "ESTABLISHED", "SYN_SENT").
	State string

	// TCPSeqAdj and TCPAckAdj are the sequence adjustment values maintained by
	// conntrack for NAT. Zero for non-NATed flows.
	TCPSeqAdj int32
	TCPAckAdj int32

	// Mark is the conntrack mark (nfmark) value; preserved across migration.
	Mark uint32

	// ReplyTuple is the reply direction (NATed IP/port, if any).
	ReplySrcIP  net.IP
	ReplyDstIP  net.IP
	ReplySrcPort uint16
	ReplyDstPort uint16

	// Zone is the conntrack zone ID; 0 for the default zone (most clusters).
	Zone uint16

	// IsIPVS indicates this entry was obtained from the IPVS connection table
	// (kube-proxy IPVS mode) rather than from netfilter conntrack.
	IsIPVS bool
}

// ConntrackExportOptions controls which entries ExportConntrack captures.
type ConntrackExportOptions struct {
	// PodIP restricts the export to entries where the original-direction source
	// or destination IP matches PodIP. Empty string = export all entries (not
	// recommended in production; useful for tests).
	PodIP string

	// IncludeIPVS also queries the IPVS connection table when kube-proxy runs in
	// IPVS mode. Entries are tagged with IsIPVS=true.
	IncludeIPVS bool

	// MaxEntries caps the number of entries returned. 0 = unlimited.
	MaxEntries int
}

// ExportConntrack captures the conntrack table entries at freeze time for a pod.
//
// It reads the kernel conntrack table via `conntrack -L` and, when IncludeIPVS is
// true, also reads the IPVS connection table via `ipvsadm -Lnc`. Both tools are
// invoked as subprocesses — custom parsing, no external conntrack packages.
//
// Call this immediately after CRIU freeze while the pod's network namespace is
// still active. The returned entries must be passed to ImportConntrack on the
// destination node.
func ExportConntrack(ctx context.Context, opts ConntrackExportOptions) ([]ConntrackEntry, error) {
	log := logf.FromContext(ctx)

	entries, err := readConntrackTable(ctx, opts.PodIP)
	if err != nil {
		return nil, fmt.Errorf("ExportConntrack: conntrack table: %w", err)
	}

	if opts.IncludeIPVS {
		ipvsEntries, err := readIPVSTable(ctx, opts.PodIP)
		if err != nil {
			// IPVS may not be loaded; log and continue rather than hard-fail.
			log.Info("ExportConntrack: IPVS table unavailable (non-fatal)", "err", err)
		} else {
			entries = append(entries, ipvsEntries...)
		}
	}

	if opts.MaxEntries > 0 && len(entries) > opts.MaxEntries {
		entries = entries[:opts.MaxEntries]
	}

	log.Info("ExportConntrack: captured entries", "count", len(entries), "podIP", opts.PodIP)
	return entries, nil
}

// readConntrackTable runs `conntrack -L` and parses its output.
// When podIP is non-empty, only entries matching that IP are returned.
func readConntrackTable(ctx context.Context, podIP string) ([]ConntrackEntry, error) {
	args := []string{"-L", "--output", "extended"}
	if podIP != "" {
		args = append(args, "--orig-src", podIP)
	}

	cmd := exec.CommandContext(ctx, "conntrack", args...)
	out, err := cmd.Output()
	if err != nil {
		// conntrack exits non-zero when the table is empty; treat that as empty.
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "0 flow entries") ||
				strings.Contains(stderr, "Can't open") {
				return nil, fmt.Errorf("conntrack: %s", stderr)
			}
			// Non-zero exit with output = possible "0 entries" case; parse what we got.
			if len(out) == 0 {
				return nil, nil
			}
		} else {
			return nil, fmt.Errorf("conntrack -L: %w", err)
		}
	}

	return parseConntrackOutput(string(out), podIP)
}

// parseConntrackOutput parses the text output of `conntrack -L --output extended`.
// Each line represents one flow entry. The extended output format is:
//
//	<proto> <proto_num> <timeout> [state] src=X dst=Y sport=P dport=Q \
//	    packets=N bytes=M src=X' dst=Y' sport=P' dport=Q' ... [mark=M] [zone=Z]
//
// podIP is used for secondary filtering in case --orig-src is not supported.
func parseConntrackOutput(output, podIP string) ([]ConntrackEntry, error) {
	var entries []ConntrackEntry
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, ok, err := parseConntrackLine(line)
		if err != nil {
			// Malformed lines are skipped; migration must not block on a single bad line.
			continue
		}
		if !ok {
			continue
		}
		if podIP != "" && !entryMatchesPodIP(entry, podIP) {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

// parseConntrackLine parses a single conntrack output line.
// Returns (entry, true, nil) on success, (zero, false, nil) for skipped lines.
func parseConntrackLine(line string) (ConntrackEntry, bool, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return ConntrackEntry{}, false, nil
	}

	var entry ConntrackEntry

	// Field 0: proto (tcp, udp, icmp, ipv6-icmp, …)
	entry.Protocol = fields[0]

	// Determine L3 proto from presence of IPv6 addresses later; default ipv4.
	entry.Layer3Proto = "ipv4"

	// Parse key=value tokens; conntrack -L --output extended emits:
	// src= dst= sport= dport= packets= bytes= [mark=] [zone=] [use=]
	// The original tuple comes first, reply tuple comes after a second src= token.
	origSeen := false
	replySeen := false

	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "ESTABLISHED", f == "SYN_SENT", f == "SYN_RECV",
			f == "FIN_WAIT", f == "CLOSE_WAIT", f == "LAST_ACK",
			f == "TIME_WAIT", f == "CLOSE", f == "LISTEN",
			f == "UNREPLIED", f == "ASSURED", f == "SEEN_REPLY":
			entry.State = f

		case strings.HasPrefix(f, "src="):
			ip := net.ParseIP(strings.TrimPrefix(f, "src="))
			if ip == nil {
				continue
			}
			if ip.To4() == nil {
				entry.Layer3Proto = "ipv6"
			}
			if !origSeen {
				entry.SrcIP = normalizeIP(ip)
				origSeen = true
			} else if !replySeen {
				entry.ReplySrcIP = normalizeIP(ip)
				replySeen = true
			}

		case strings.HasPrefix(f, "dst="):
			ip := net.ParseIP(strings.TrimPrefix(f, "dst="))
			if ip == nil {
				continue
			}
			if !origSeen {
				// dst before src shouldn't happen, skip
			} else if entry.DstIP == nil && !replySeen {
				entry.DstIP = normalizeIP(ip)
			} else if replySeen && entry.ReplyDstIP == nil {
				entry.ReplyDstIP = normalizeIP(ip)
			}

		case strings.HasPrefix(f, "sport="):
			p, err := strconv.ParseUint(strings.TrimPrefix(f, "sport="), 10, 16)
			if err != nil {
				continue
			}
			if entry.SrcPort == 0 && !replySeen {
				entry.SrcPort = uint16(p)
			} else if entry.ReplySrcPort == 0 {
				entry.ReplySrcPort = uint16(p)
			}

		case strings.HasPrefix(f, "dport="):
			p, err := strconv.ParseUint(strings.TrimPrefix(f, "dport="), 10, 16)
			if err != nil {
				continue
			}
			if entry.DstPort == 0 && !replySeen {
				entry.DstPort = uint16(p)
			} else if entry.ReplyDstPort == 0 {
				entry.ReplyDstPort = uint16(p)
			}

		case strings.HasPrefix(f, "mark="):
			v, err := strconv.ParseUint(strings.TrimPrefix(f, "mark="), 10, 32)
			if err == nil {
				entry.Mark = uint32(v)
			}

		case strings.HasPrefix(f, "zone="):
			v, err := strconv.ParseUint(strings.TrimPrefix(f, "zone="), 10, 16)
			if err == nil {
				entry.Zone = uint16(v)
			}

		case strings.HasPrefix(f, "delta-seq-orig="):
			v, err := strconv.ParseInt(strings.TrimPrefix(f, "delta-seq-orig="), 10, 32)
			if err == nil {
				entry.TCPSeqAdj = int32(v)
			}

		case strings.HasPrefix(f, "delta-seq-reply="):
			v, err := strconv.ParseInt(strings.TrimPrefix(f, "delta-seq-reply="), 10, 32)
			if err == nil {
				entry.TCPAckAdj = int32(v)
			}
		}
	}

	// Require at least src/dst for a valid entry.
	if entry.SrcIP == nil || entry.DstIP == nil {
		return ConntrackEntry{}, false, nil
	}

	return entry, true, nil
}

// readIPVSTable reads the IPVS connection table via `ipvsadm -Lnc`.
// IPVS is used by kube-proxy in IPVS mode; it maintains its own connection
// state independent of netfilter conntrack for load-balanced service IPs.
func readIPVSTable(ctx context.Context, podIP string) ([]ConntrackEntry, error) {
	cmd := exec.CommandContext(ctx, "ipvsadm", "-Lnc")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ipvsadm -Lnc: %w", err)
	}
	return parseIPVSOutput(string(out), podIP)
}

// parseIPVSOutput parses `ipvsadm -Lnc` output.
// Output format (after header lines):
//
//	TCP  src_ip:src_port  dest_ip:dest_port  state    expires
func parseIPVSOutput(output, podIP string) ([]ConntrackEntry, error) {
	var entries []ConntrackEntry
	scanner := bufio.NewScanner(strings.NewReader(output))
	headerSkip := 3 // skip "IPVS connection entries", blank line, column header
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if headerSkip > 0 {
			headerSkip--
			continue
		}
		if line == "" {
			continue
		}
		entry, ok, err := parseIPVSLine(line)
		if err != nil || !ok {
			continue
		}
		if podIP != "" && !entryMatchesPodIP(entry, podIP) {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

// parseIPVSLine parses one data row from ipvsadm -Lnc output.
// Format: PROTO  laddr:lport  faddr:fport  state  expires
func parseIPVSLine(line string) (ConntrackEntry, bool, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return ConntrackEntry{}, false, nil
	}

	var entry ConntrackEntry
	entry.Protocol = strings.ToLower(fields[0])
	entry.Layer3Proto = "ipv4"
	entry.IsIPVS = true

	srcIP, srcPort, err := parseIPPort(fields[1])
	if err != nil {
		return ConntrackEntry{}, false, err
	}
	dstIP, dstPort, err := parseIPPort(fields[2])
	if err != nil {
		return ConntrackEntry{}, false, err
	}

	entry.SrcIP = srcIP
	entry.SrcPort = srcPort
	entry.DstIP = dstIP
	entry.DstPort = dstPort
	entry.State = fields[3]

	if srcIP.To4() == nil {
		entry.Layer3Proto = "ipv6"
	}

	return entry, true, nil
}

// parseIPPort splits "1.2.3.4:5678" or "[::1]:5678" into IP and port.
func parseIPPort(s string) (net.IP, uint16, error) {
	// Use net.SplitHostPort which handles IPv6 brackets.
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, fmt.Errorf("parseIPPort %q: %w", s, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("parseIPPort %q: invalid IP %q", s, host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("parseIPPort %q: invalid port %q", s, portStr)
	}
	return normalizeIP(ip), uint16(port), nil
}

// entryMatchesPodIP reports whether the entry's original-direction source or
// destination IP equals podIP.
func entryMatchesPodIP(e ConntrackEntry, podIP string) bool {
	target := net.ParseIP(podIP)
	if target == nil {
		return false
	}
	target = normalizeIP(target)
	return e.SrcIP.Equal(target) || e.DstIP.Equal(target)
}

// normalizeIP returns the 4-byte form for IPv4 addresses and 16-byte form for IPv6.
func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}
