/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build linux

package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
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
	// Protocol is the L4 protocol number (e.g. syscall.IPPROTO_TCP).
	Protocol uint8
	// Layer3Proto is the AF family: unix.AF_INET or unix.AF_INET6.
	Layer3Proto uint8

	// SrcIP / DstIP are the original direction tuple.
	SrcIP  net.IP
	DstIP  net.IP
	SrcPort uint16
	DstPort uint16

	// State is the conntrack TCP state (CTA_PROTO_INFO TCP_CONNTRACK_*).
	State uint8

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

	// IncludeIPVS also reads the IPVS connection table when kube-proxy runs in
	// IPVS mode. Entries are tagged with IsIPVS=true.
	IncludeIPVS bool

	// MaxEntries caps the number of entries returned. 0 = unlimited.
	MaxEntries int
}

// Netlink / nfnetlink constants (NFNL_SUBSYS_CTNETLINK).
const (
	nfnlSubsysCtnetlink = 1
	ipctnlMsgCtGet      = 1

	// Attribute type numbers used in the nfnetlink conntrack protocol.
	ctaTupleOrig  = 1
	ctaTupleReply = 2
	ctaStatus     = 3
	ctaProtoinfo  = 4
	ctaTimeout    = 7
	ctaMark       = 8
	ctaZone       = 18

	ctaTupleIP    = 1
	ctaTupleProto = 2

	ctaIPv4Src = 1
	ctaIPv4Dst = 2
	ctaIPv6Src = 3
	ctaIPv6Dst = 4

	ctaProtoNum     = 1
	ctaProtoSrcPort = 2
	ctaProtoDstPort = 3

	ctaProtoinfoTCP      = 1
	ctaProtoinfoTCPState = 1

	nlaHdrLen = 4 // sizeof(nlattr): type(2) + len(2)
)

// nfnlHdr is the fixed header that follows the netlink header in nfnetlink messages.
// Layout: family(1) version(1) res_id(2).
type nfnlHdr struct {
	Family  uint8
	Version uint8
	ResID   uint16
}

// ExportConntrack captures the conntrack table entries at freeze time for a pod.
//
// Export uses pure netlink via NFNL_SUBSYS_CTNETLINK (IPCTNL_MSG_CT_GET dump),
// as required by ADR-0108 §2. No external tool dependency.
//
// Call this immediately after CRIU freeze while the pod's network namespace is
// still active. The returned entries must be passed to ImportConntrack on the
// destination node.
func ExportConntrack(ctx context.Context, opts ConntrackExportOptions) ([]ConntrackEntry, error) {
	log := logf.FromContext(ctx)

	entries4, err := dumpConntrackFamily(ctx, unix.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("ExportConntrack: IPv4 dump: %w", err)
	}
	entries6, err := dumpConntrackFamily(ctx, unix.AF_INET6)
	if err != nil {
		// IPv6 may not be configured; non-fatal.
		log.Info("ExportConntrack: IPv6 dump unavailable (non-fatal)", "err", err)
	}

	all := append(entries4, entries6...)

	if opts.IncludeIPVS {
		ipvsEntries, err := readIPVSConnections(ctx, opts.PodIP)
		if err != nil {
			log.Info("ExportConntrack: IPVS read unavailable (non-fatal)", "err", err)
		} else {
			all = append(all, ipvsEntries...)
		}
	}

	// Filter by pod IP if specified.
	var filtered []ConntrackEntry
	for _, e := range all {
		if opts.PodIP != "" && !entryMatchesPodIP(e, opts.PodIP) {
			continue
		}
		filtered = append(filtered, e)
	}

	if opts.MaxEntries > 0 && len(filtered) > opts.MaxEntries {
		filtered = filtered[:opts.MaxEntries]
	}

	log.Info("ExportConntrack: captured entries", "count", len(filtered), "podIP", opts.PodIP)
	return filtered, nil
}

// dumpConntrackFamily sends a NFNL_SUBSYS_CTNETLINK IPCTNL_MSG_CT_GET dump
// request for the given address family and parses all returned entries.
func dumpConntrackFamily(ctx context.Context, family uint8) ([]ConntrackEntry, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: 0}
	if err := unix.Bind(fd, addr); err != nil {
		return nil, fmt.Errorf("netlink bind: %w", err)
	}

	// Build the NFNL dump request.
	// nlmsghdr(16) + nfnlHdr(4) = 20 bytes minimum.
	msgType := uint16(nfnlSubsysCtnetlink<<8) | ipctnlMsgCtGet
	nlh := unix.NlMsghdr{
		Len:   uint32(unix.SizeofNlMsghdr + 4),
		Type:  msgType,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   1,
		Pid:   0,
	}
	nfh := nfnlHdr{Family: family, Version: 0, ResID: 0}

	buf := make([]byte, unix.SizeofNlMsghdr+4)
	nlhBytes := (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&nlh))[:]
	copy(buf, nlhBytes)
	buf[unix.SizeofNlMsghdr+0] = nfh.Family
	buf[unix.SizeofNlMsghdr+1] = nfh.Version
	binary.BigEndian.PutUint16(buf[unix.SizeofNlMsghdr+2:], nfh.ResID)

	_, err = unix.Write(fd, buf)
	if err != nil {
		return nil, fmt.Errorf("netlink write: %w", err)
	}

	var entries []ConntrackEntry
	recvBuf := make([]byte, 1<<20) // 1 MiB receive buffer

	for {
		// Check context cancellation before each receive.
		select {
		case <-ctx.Done():
			return entries, ctx.Err()
		default:
		}

		n, err := unix.Read(fd, recvBuf)
		if err != nil {
			return nil, fmt.Errorf("netlink read: %w", err)
		}

		msgs, err := syscall.ParseNetlinkMessage(recvBuf[:n])
		if err != nil {
			return nil, fmt.Errorf("netlink parse: %w", err)
		}

		done := false
		for _, msg := range msgs {
			if msg.Header.Type == unix.NLMSG_DONE || msg.Header.Type == unix.NLMSG_ERROR {
				done = true
				break
			}
			entry, ok, parseErr := parseCtNetlinkMsg(msg.Data, family)
			if parseErr != nil || !ok {
				continue
			}
			entries = append(entries, entry)
		}
		if done {
			break
		}
	}

	return entries, nil
}

// parseCtNetlinkMsg decodes a single nfnetlink conntrack message into a ConntrackEntry.
// The message Data starts with the nfnlHdr (4 bytes) followed by nested NLATTRs.
func parseCtNetlinkMsg(data []byte, family uint8) (ConntrackEntry, bool, error) {
	if len(data) < 4 {
		return ConntrackEntry{}, false, nil
	}
	// Skip nfnlHdr (4 bytes).
	data = data[4:]

	var e ConntrackEntry
	e.Layer3Proto = family

	for len(data) >= nlaHdrLen {
		nlaLen := int(binary.LittleEndian.Uint16(data[0:2]))
		nlaType := int(binary.LittleEndian.Uint16(data[2:4])) & 0x1FFF // mask nested flag
		if nlaLen < nlaHdrLen || nlaLen > len(data) {
			break
		}
		payload := data[nlaHdrLen:nlaLen]

		switch nlaType {
		case ctaTupleOrig:
			parseTuple(payload, &e.SrcIP, &e.DstIP, &e.SrcPort, &e.DstPort, &e.Protocol, family)
		case ctaTupleReply:
			parseTuple(payload, &e.ReplySrcIP, &e.ReplyDstIP, &e.ReplySrcPort, &e.ReplyDstPort, nil, family)
		case ctaMark:
			if len(payload) == 4 {
				e.Mark = binary.BigEndian.Uint32(payload)
			}
		case ctaZone:
			if len(payload) == 2 {
				e.Zone = binary.BigEndian.Uint16(payload)
			}
		case ctaProtoinfo:
			parseProtoinfo(payload, &e.State)
		}

		// Advance with 4-byte alignment.
		aligned := (nlaLen + 3) & ^3
		if aligned > len(data) {
			break
		}
		data = data[aligned:]
	}

	if e.SrcIP == nil || e.DstIP == nil {
		return ConntrackEntry{}, false, nil
	}
	return e, true, nil
}

// parseTuple decodes a CTA_TUPLE_* nested attribute into IP/port fields.
func parseTuple(data []byte, srcIP, dstIP *net.IP, srcPort, dstPort *uint16, proto *uint8, family uint8) {
	for len(data) >= nlaHdrLen {
		nlaLen := int(binary.LittleEndian.Uint16(data[0:2]))
		nlaType := int(binary.LittleEndian.Uint16(data[2:4])) & 0x1FFF
		if nlaLen < nlaHdrLen || nlaLen > len(data) {
			break
		}
		payload := data[nlaHdrLen:nlaLen]

		switch nlaType {
		case ctaTupleIP:
			parseIPTuple(payload, srcIP, dstIP, family)
		case ctaTupleProto:
			parseProtoTuple(payload, srcPort, dstPort, proto)
		}
		aligned := (nlaLen + 3) & ^3
		if aligned > len(data) {
			break
		}
		data = data[aligned:]
	}
}

// parseIPTuple decodes a CTA_TUPLE_IP nested attribute.
func parseIPTuple(data []byte, srcIP, dstIP *net.IP, family uint8) {
	for len(data) >= nlaHdrLen {
		nlaLen := int(binary.LittleEndian.Uint16(data[0:2]))
		nlaType := int(binary.LittleEndian.Uint16(data[2:4])) & 0x1FFF
		if nlaLen < nlaHdrLen || nlaLen > len(data) {
			break
		}
		payload := data[nlaHdrLen:nlaLen]

		switch {
		case (nlaType == ctaIPv4Src) && family == unix.AF_INET && len(payload) == 4:
			ip := make(net.IP, 4)
			copy(ip, payload)
			*srcIP = ip
		case (nlaType == ctaIPv4Dst) && family == unix.AF_INET && len(payload) == 4:
			ip := make(net.IP, 4)
			copy(ip, payload)
			*dstIP = ip
		case (nlaType == ctaIPv6Src) && family == unix.AF_INET6 && len(payload) == 16:
			ip := make(net.IP, 16)
			copy(ip, payload)
			*srcIP = ip
		case (nlaType == ctaIPv6Dst) && family == unix.AF_INET6 && len(payload) == 16:
			ip := make(net.IP, 16)
			copy(ip, payload)
			*dstIP = ip
		}
		aligned := (nlaLen + 3) & ^3
		if aligned > len(data) {
			break
		}
		data = data[aligned:]
	}
}

// parseProtoTuple decodes a CTA_TUPLE_PROTO nested attribute.
func parseProtoTuple(data []byte, srcPort, dstPort *uint16, proto *uint8) {
	for len(data) >= nlaHdrLen {
		nlaLen := int(binary.LittleEndian.Uint16(data[0:2]))
		nlaType := int(binary.LittleEndian.Uint16(data[2:4])) & 0x1FFF
		if nlaLen < nlaHdrLen || nlaLen > len(data) {
			break
		}
		payload := data[nlaHdrLen:nlaLen]

		switch nlaType {
		case ctaProtoNum:
			if len(payload) == 1 && proto != nil {
				*proto = payload[0]
			}
		case ctaProtoSrcPort:
			if len(payload) == 2 {
				*srcPort = binary.BigEndian.Uint16(payload)
			}
		case ctaProtoDstPort:
			if len(payload) == 2 {
				*dstPort = binary.BigEndian.Uint16(payload)
			}
		}
		aligned := (nlaLen + 3) & ^3
		if aligned > len(data) {
			break
		}
		data = data[aligned:]
	}
}

// parseProtoinfo decodes the CTA_PROTOINFO nested attribute to extract TCP state.
func parseProtoinfo(data []byte, state *uint8) {
	// CTA_PROTOINFO → CTA_PROTOINFO_TCP → CTA_PROTOINFO_TCP_STATE (1 byte).
	for len(data) >= nlaHdrLen {
		nlaLen := int(binary.LittleEndian.Uint16(data[0:2]))
		nlaType := int(binary.LittleEndian.Uint16(data[2:4])) & 0x1FFF
		if nlaLen < nlaHdrLen || nlaLen > len(data) {
			break
		}
		payload := data[nlaHdrLen:nlaLen]
		if nlaType == ctaProtoinfoTCP {
			// Nested: look for TCP_STATE.
			for len(payload) >= nlaHdrLen {
				innerLen := int(binary.LittleEndian.Uint16(payload[0:2]))
				innerType := int(binary.LittleEndian.Uint16(payload[2:4])) & 0x1FFF
				if innerLen < nlaHdrLen || innerLen > len(payload) {
					break
				}
				innerPayload := payload[nlaHdrLen:innerLen]
				if innerType == ctaProtoinfoTCPState && len(innerPayload) == 1 {
					*state = innerPayload[0]
				}
				innerAligned := (innerLen + 3) & ^3
				if innerAligned > len(payload) {
					break
				}
				payload = payload[innerAligned:]
			}
		}
		aligned := (nlaLen + 3) & ^3
		if aligned > len(data) {
			break
		}
		data = data[aligned:]
	}
}

// readIPVSConnections reads the IPVS connection table from /proc/net/ip_vs_conn.
// This file is a standard Linux kernel procfs interface requiring no external tools.
// Entries are tagged with IsIPVS=true.
func readIPVSConnections(ctx context.Context, podIP string) ([]ConntrackEntry, error) {
	const procPath = "/proc/net/ip_vs_conn"
	data, err := unix.Open(procPath, unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("readIPVSConnections: open %s: %w", procPath, err)
	}
	defer unix.Close(data)

	var buf [1 << 16]byte
	var content []byte
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		n, err := unix.Read(data, buf[:])
		if n > 0 {
			content = append(content, buf[:n]...)
		}
		if err != nil || n == 0 {
			break
		}
	}
	return parseIPVSProcOutput(string(content), podIP), nil
}

// parseIPVSProcOutput parses /proc/net/ip_vs_conn.
// Format (after header): Pro FromIP FPrt ToIP TPrt DestIP DPrt State
// All IPs are hex-encoded big-endian 32-bit values.
func parseIPVSProcOutput(content, podIP string) []ConntrackEntry {
	var entries []ConntrackEntry
	lines := splitLines(content)
	for i, line := range lines {
		if i == 0 || line == "" {
			continue // skip header
		}
		e, ok := parseIPVSProcLine(line)
		if !ok {
			continue
		}
		if podIP != "" && !entryMatchesPodIP(e, podIP) {
			continue
		}
		entries = append(entries, e)
	}
	return entries
}

// parseIPVSProcLine parses one line from /proc/net/ip_vs_conn.
func parseIPVSProcLine(line string) (ConntrackEntry, bool) {
	// Fields: Pro  FromIP  FPrt  ToIP  TPrt  DestIP  DPrt  State
	fields := splitFields(line)
	if len(fields) < 8 {
		return ConntrackEntry{}, false
	}
	var e ConntrackEntry
	e.IsIPVS = true

	// Protocol
	switch fields[0] {
	case "TCP":
		e.Protocol = syscall.IPPROTO_TCP
	case "UDP":
		e.Protocol = syscall.IPPROTO_UDP
	default:
		return ConntrackEntry{}, false
	}

	srcIP := parseHexIP(fields[1])
	if srcIP == nil {
		return ConntrackEntry{}, false
	}
	e.SrcIP = srcIP

	srcPort, err := parseHexPort(fields[2])
	if err != nil {
		return ConntrackEntry{}, false
	}
	e.SrcPort = srcPort

	dstIP := parseHexIP(fields[3])
	if dstIP == nil {
		return ConntrackEntry{}, false
	}
	e.DstIP = dstIP

	dstPort, err := parseHexPort(fields[4])
	if err != nil {
		return ConntrackEntry{}, false
	}
	e.DstPort = dstPort

	e.State = 0 // IPVS state not mapped to TCP conntrack state
	if srcIP.To4() != nil {
		e.Layer3Proto = unix.AF_INET
	} else {
		e.Layer3Proto = unix.AF_INET6
	}
	return e, true
}

// parseHexIP parses a 8-character big-endian hex IPv4 address from /proc/net/ip_vs_conn.
func parseHexIP(s string) net.IP {
	if len(s) != 8 {
		return nil
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		nibbleHi := hexVal(s[i*2])
		nibbleLo := hexVal(s[i*2+1])
		if nibbleHi < 0 || nibbleLo < 0 {
			return nil
		}
		b[i] = byte(nibbleHi<<4 | nibbleLo)
	}
	// /proc/net/ip_vs_conn stores in network byte order (big-endian).
	return net.IP(b[:])
}

// parseHexPort parses a 4-character hex port from /proc/net/ip_vs_conn.
func parseHexPort(s string) (uint16, error) {
	if len(s) != 4 {
		return 0, fmt.Errorf("invalid port hex %q", s)
	}
	var v uint16
	for _, c := range s {
		hv := hexVal(byte(c))
		if hv < 0 {
			return 0, fmt.Errorf("invalid hex char %c in port %q", c, s)
		}
		v = v<<4 | uint16(hv)
	}
	return v, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// splitLines splits a string into lines without using strings package to keep imports minimal.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// splitFields splits a line on whitespace (ASCII spaces/tabs).
func splitFields(s string) []string {
	var fields []string
	inField := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		isSpace := c == ' ' || c == '\t'
		if !isSpace && !inField {
			start = i
			inField = true
		} else if isSpace && inField {
			fields = append(fields, s[start:i])
			inField = false
		}
	}
	if inField {
		fields = append(fields, s[start:])
	}
	return fields
}

// entryMatchesPodIP reports whether the entry's original-direction source or
// destination IP equals podIP.
func entryMatchesPodIP(e ConntrackEntry, podIP string) bool {
	target := net.ParseIP(podIP)
	if target == nil {
		return false
	}
	if t4 := target.To4(); t4 != nil {
		target = t4
	}
	return e.SrcIP.Equal(target) || e.DstIP.Equal(target)
}

// normalizeIP returns the 4-byte form for IPv4 addresses and 16-byte form for IPv6.
func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}
