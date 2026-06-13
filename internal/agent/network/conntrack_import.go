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

// ConntrackImportOptions controls how ImportConntrack installs entries.
type ConntrackImportOptions struct {
	// DestPodIP is the IP assigned to the restored pod on the destination node.
	// When set, the original-direction source IP in each entry is rewritten from
	// the source pod IP to DestPodIP before insertion. Leave empty to preserve
	// the original IPs as-is (same-IP migration scenarios).
	DestPodIP string

	// SourcePodIP is the original pod IP on the source node. Used together with
	// DestPodIP to rewrite the tuple. Required when DestPodIP is set.
	SourcePodIP string

	// SkipIPVS controls whether IPVS entries (IsIPVS=true) are skipped on
	// import. Set true when kube-proxy is NOT running in IPVS mode on the
	// destination node.
	SkipIPVS bool
}

// ipctnlMsgCtNew is the nfnetlink message type for creating a conntrack entry.
// ADR-0108 §4: import via NFNL_SUBSYS_CTNETLINK IPCTNL_MSG_CT_NEW|NLM_F_CREATE|NLM_F_EXCL
// with "delete and replace" semantics for pre-existing entries.
const ipctnlMsgCtNew = 0

// ImportConntrack inserts the conntrack entries exported by ExportConntrack into
// the kernel conntrack table on the destination node.
//
// Called after CRIU restore, before the eBPF bridge is disarmed, so that the
// first response packet from the restored pod matches an existing conntrack entry
// and is not treated as an unexpected out-of-state packet.
//
// Implementation: entries are inserted via NFNL_SUBSYS_CTNETLINK IPCTNL_MSG_CT_NEW
// netlink messages with NLM_F_CREATE|NLM_F_EXCL.  Pre-existing entries are deleted
// then re-inserted ("delete and replace") per ADR-0108 §4.
// No external tool dependency (ADR-0108 §2).
//
// Source pod is NEVER deleted until TrafficVerified=True (ADR-0012). ImportConntrack
// does not enforce this gate — the caller (state machine) is responsible.
func ImportConntrack(ctx context.Context, entries []ConntrackEntry, opts ConntrackImportOptions) error {
	log := logf.FromContext(ctx)

	if len(entries) == 0 {
		log.Info("ImportConntrack: no entries to import")
		return nil
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("ImportConntrack: netlink socket: %w", err)
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, addr); err != nil {
		return fmt.Errorf("ImportConntrack: netlink bind: %w", err)
	}

	var imported, skipped int
	for i := range entries {
		e := rewriteEntry(entries[i], opts)

		if e.IsIPVS && opts.SkipIPVS {
			skipped++
			continue
		}

		if err := insertConntrackEntryNetlink(ctx, fd, e); err != nil {
			// Log but do not abort — a partially populated conntrack table is
			// better than blocking the restore. The eBPF bridge will handle
			// the first packet; conntrack will create a new entry automatically
			// when it sees the packet.
			log.Error(err, "ImportConntrack: failed to insert entry",
				"src", e.SrcIP, "dst", e.DstIP,
				"sport", e.SrcPort, "dport", e.DstPort,
				"proto", e.Protocol)
			skipped++
			continue
		}
		imported++
	}

	log.Info("ImportConntrack: complete", "imported", imported, "skipped", skipped)
	return nil
}

// rewriteEntry rewrites the source IP in an entry when a pod IP change is required
// (source pod IP → destination pod IP). Returns a modified copy.
func rewriteEntry(e ConntrackEntry, opts ConntrackImportOptions) ConntrackEntry {
	if opts.SourcePodIP == "" || opts.DestPodIP == "" {
		return e
	}
	srcPod := normalizeIP(net.ParseIP(opts.SourcePodIP))
	dstPod := normalizeIP(net.ParseIP(opts.DestPodIP))
	if srcPod == nil || dstPod == nil {
		return e
	}

	out := e // shallow copy
	if e.SrcIP.Equal(srcPod) {
		out.SrcIP = dstPod
	}
	if e.DstIP.Equal(srcPod) {
		out.DstIP = dstPod
	}
	if e.ReplySrcIP != nil && e.ReplySrcIP.Equal(srcPod) {
		out.ReplySrcIP = dstPod
	}
	if e.ReplyDstIP != nil && e.ReplyDstIP.Equal(srcPod) {
		out.ReplyDstIP = dstPod
	}
	return out
}

// insertConntrackEntryNetlink sends an IPCTNL_MSG_CT_NEW netlink message to insert
// a single conntrack entry. Implements ADR-0108 §4 "delete and replace" semantics:
// if EEXIST is returned the existing entry is deleted and the insert is retried.
func insertConntrackEntryNetlink(ctx context.Context, fd int, e ConntrackEntry) error {
	msg, err := buildCtNewMessage(e, unix.NLM_F_CREATE|unix.NLM_F_EXCL, 1)
	if err != nil {
		return fmt.Errorf("insertConntrackEntryNetlink: build message: %w", err)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return fmt.Errorf("insertConntrackEntryNetlink: send: %w", err)
	}

	nlErr := recvNetlinkAck(fd)
	if nlErr == nil {
		return nil
	}

	// EEXIST → delete-and-replace per ADR-0108 §4.
	if isEEXIST(nlErr) {
		if delErr := deleteConntrackEntryNetlink(ctx, fd, e); delErr != nil {
			return fmt.Errorf("insertConntrackEntryNetlink: delete before replace: %w", delErr)
		}
		// Retry without NLM_F_EXCL.
		msg2, err2 := buildCtNewMessage(e, unix.NLM_F_CREATE, 2)
		if err2 != nil {
			return fmt.Errorf("insertConntrackEntryNetlink: build retry message: %w", err2)
		}
		if _, err2 = unix.Write(fd, msg2); err2 != nil {
			return fmt.Errorf("insertConntrackEntryNetlink: retry send: %w", err2)
		}
		return recvNetlinkAck(fd)
	}
	return nlErr
}

// deleteConntrackEntryNetlink sends an IPCTNL_MSG_CT_DELETE for the entry's orig tuple.
func deleteConntrackEntryNetlink(_ context.Context, fd int, e ConntrackEntry) error {
	const ipctnlMsgCtDelete = 2
	msg, err := buildCtDeleteMessage(e, ipctnlMsgCtDelete)
	if err != nil {
		return err
	}
	if _, err := unix.Write(fd, msg); err != nil {
		return fmt.Errorf("deleteConntrackEntryNetlink: send: %w", err)
	}
	nlErr := recvNetlinkAck(fd)
	if nlErr == nil || isENOENT(nlErr) {
		return nil // deleted or not present — both fine
	}
	return nlErr
}

// PurgeConntrackForPod removes all conntrack entries matching podIP from the
// kernel table using netlink IPCTNL_MSG_CT_DELETE with NLM_F_DUMP semantics
// (enumerate, then delete each match). Called after the source pod is deleted
// (post TrafficVerified=True) to ensure no leaked conntrack entries remain.
//
// ADR-0108 §2: pure netlink — no external tool dependency.
func PurgeConntrackForPod(ctx context.Context, podIP string) error {
	log := logf.FromContext(ctx)
	if podIP == "" {
		return fmt.Errorf("PurgeConntrackForPod: podIP must not be empty")
	}

	// Export all entries for this pod, then delete each via netlink.
	entries, err := ExportConntrack(ctx, ConntrackExportOptions{PodIP: podIP})
	if err != nil {
		return fmt.Errorf("PurgeConntrackForPod: export: %w", err)
	}
	if len(entries) == 0 {
		log.Info("PurgeConntrackForPod: no entries to purge", "podIP", podIP)
		return nil
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("PurgeConntrackForPod: netlink socket: %w", err)
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, addr); err != nil {
		return fmt.Errorf("PurgeConntrackForPod: netlink bind: %w", err)
	}

	var deleted int
	for _, e := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := deleteConntrackEntryNetlink(ctx, fd, e); err != nil {
			log.Error(err, "PurgeConntrackForPod: delete entry (non-fatal)",
				"src", e.SrcIP, "dst", e.DstIP)
			continue
		}
		deleted++
	}

	log.Info("PurgeConntrackForPod: complete", "podIP", podIP, "deleted", deleted)
	return nil
}

// buildCtNewMessage constructs the raw netlink bytes for IPCTNL_MSG_CT_NEW.
func buildCtNewMessage(e ConntrackEntry, flags uint16, seq uint32) ([]byte, error) {
	family := e.Layer3Proto
	if family == 0 {
		if e.SrcIP.To4() != nil {
			family = unix.AF_INET
		} else {
			family = unix.AF_INET6
		}
	}

	var body []byte
	body = appendNfnlHdr(body, family)

	// CTA_TUPLE_ORIG
	origTuple := buildTupleAttr(e.SrcIP, e.DstIP, e.SrcPort, e.DstPort, e.Protocol, family)
	body = appendNestedAttr(body, ctaTupleOrig, origTuple)

	// CTA_TUPLE_REPLY
	replySrc := e.ReplySrcIP
	replyDst := e.ReplyDstIP
	replySport := e.ReplySrcPort
	replyDport := e.ReplyDstPort
	if replySrc == nil {
		replySrc = e.DstIP
	}
	if replyDst == nil {
		replyDst = e.SrcIP
	}
	if replySport == 0 {
		replySport = e.DstPort
	}
	if replyDport == 0 {
		replyDport = e.SrcPort
	}
	replyTuple := buildTupleAttr(replySrc, replyDst, replySport, replyDport, e.Protocol, family)
	body = appendNestedAttr(body, ctaTupleReply, replyTuple)

	// CTA_TIMEOUT: 120 seconds.
	body = appendUint32Attr(body, ctaTimeout, 120)

	// CTA_STATUS: IPS_CONFIRMED (4).
	body = appendUint32Attr(body, ctaStatus, 4)

	// CTA_PROTOINFO for TCP.
	if e.Protocol == syscall.IPPROTO_TCP && e.State != 0 {
		tcpState := []byte{e.State, 0}
		tcpStateAttr := appendNlaBytes(nil, ctaProtoinfoTCPState, tcpState[:1])
		body = appendNestedAttr(body, ctaProtoinfo, appendNestedAttr(nil, ctaProtoinfoTCP, tcpStateAttr))
	}

	if e.Mark != 0 {
		body = appendUint32Attr(body, ctaMark, e.Mark)
	}
	if e.Zone != 0 {
		body = appendUint16Attr(body, ctaZone, e.Zone)
	}

	msgType := uint16(nfnlSubsysCtnetlink<<8) | ipctnlMsgCtNew
	return buildNlMsg(msgType, unix.NLM_F_REQUEST|unix.NLM_F_ACK|flags, seq, body), nil
}

// buildCtDeleteMessage constructs the raw netlink bytes for IPCTNL_MSG_CT_DELETE.
func buildCtDeleteMessage(e ConntrackEntry, msgTypeVal int) ([]byte, error) {
	family := e.Layer3Proto
	if family == 0 {
		if e.SrcIP.To4() != nil {
			family = unix.AF_INET
		} else {
			family = unix.AF_INET6
		}
	}

	var body []byte
	body = appendNfnlHdr(body, family)
	origTuple := buildTupleAttr(e.SrcIP, e.DstIP, e.SrcPort, e.DstPort, e.Protocol, family)
	body = appendNestedAttr(body, ctaTupleOrig, origTuple)

	msgType := uint16(nfnlSubsysCtnetlink<<8) | uint16(msgTypeVal)
	return buildNlMsg(msgType, unix.NLM_F_REQUEST|unix.NLM_F_ACK, 3, body), nil
}

// buildNlMsg wraps body bytes in an NlMsghdr.
func buildNlMsg(msgType, flags uint16, seq uint32, body []byte) []byte {
	total := unix.SizeofNlMsghdr + len(body)
	h := unix.NlMsghdr{
		Len:   uint32(total),
		Type:  msgType,
		Flags: flags,
		Seq:   seq,
		Pid:   0,
	}
	buf := make([]byte, total)
	hBytes := (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&h))[:]
	copy(buf, hBytes)
	copy(buf[unix.SizeofNlMsghdr:], body)
	return buf
}

// appendNfnlHdr appends the 4-byte nfnetlink family header to buf.
func appendNfnlHdr(buf []byte, family uint8) []byte {
	return append(buf, family, 0, 0, 0)
}

// buildTupleAttr builds the CTA_TUPLE_IP + CTA_TUPLE_PROTO nested bytes.
func buildTupleAttr(src, dst net.IP, sport, dport uint16, proto, family uint8) []byte {
	// CTA_TUPLE_IP
	var ipAttr []byte
	if family == unix.AF_INET {
		s4 := src.To4()
		d4 := dst.To4()
		if s4 == nil || d4 == nil {
			s4 = src
			d4 = dst
		}
		ipAttr = appendNlaBytes(ipAttr, ctaIPv4Src, s4)
		ipAttr = appendNlaBytes(ipAttr, ctaIPv4Dst, d4)
	} else {
		s6 := src.To16()
		d6 := dst.To16()
		ipAttr = appendNlaBytes(ipAttr, ctaIPv6Src, s6)
		ipAttr = appendNlaBytes(ipAttr, ctaIPv6Dst, d6)
	}
	tupleIP := appendNestedAttr(nil, ctaTupleIP, ipAttr)

	// CTA_TUPLE_PROTO
	var protoAttr []byte
	protoAttr = appendNlaBytes(protoAttr, ctaProtoNum, []byte{proto})
	if sport != 0 {
		protoAttr = appendUint16AttrRaw(protoAttr, ctaProtoSrcPort, sport)
	}
	if dport != 0 {
		protoAttr = appendUint16AttrRaw(protoAttr, ctaProtoDstPort, dport)
	}
	tupleProto := appendNestedAttr(nil, ctaTupleProto, protoAttr)

	return append(tupleIP, tupleProto...)
}

// recvNetlinkAck reads a single netlink ack/error message from fd.
func recvNetlinkAck(fd int) error {
	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return fmt.Errorf("recvNetlinkAck: read: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return fmt.Errorf("recvNetlinkAck: parse: %w", err)
	}
	for _, msg := range msgs {
		if msg.Header.Type == unix.NLMSG_ERROR {
			if len(msg.Data) < 4 {
				return fmt.Errorf("truncated NLMSG_ERROR")
			}
			errno := int32(binary.LittleEndian.Uint32(msg.Data[:4]))
			if errno == 0 {
				return nil
			}
			return syscall.Errno(-errno)
		}
		if msg.Header.Type == unix.NLMSG_DONE {
			return nil
		}
	}
	return nil
}

func isEEXIST(err error) bool {
	if err == nil {
		return false
	}
	errno, ok := err.(syscall.Errno)
	return ok && errno == syscall.EEXIST
}

func isENOENT(err error) bool {
	if err == nil {
		return false
	}
	errno, ok := err.(syscall.Errno)
	return ok && errno == syscall.ENOENT
}

// --- NLA serialization helpers ---

// appendNlaBytes appends a netlink attribute with raw byte payload.
func appendNlaBytes(buf []byte, attrType int, data []byte) []byte {
	nlaLen := nlaHdrLen + len(data)
	out := make([]byte, nlaHdrLen)
	binary.LittleEndian.PutUint16(out[0:2], uint16(nlaLen))
	binary.LittleEndian.PutUint16(out[2:4], uint16(attrType))
	out = append(out, data...)
	// Pad to 4-byte alignment.
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return append(buf, out...)
}

// appendNestedAttr appends a nested NLA (NLA_F_NESTED flag set).
func appendNestedAttr(buf []byte, attrType int, nested []byte) []byte {
	const nlaFNested = 0x8000
	nlaLen := nlaHdrLen + len(nested)
	hdr := make([]byte, nlaHdrLen)
	binary.LittleEndian.PutUint16(hdr[0:2], uint16(nlaLen))
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(attrType|nlaFNested))
	out := append(hdr, nested...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return append(buf, out...)
}

// appendUint32Attr appends a big-endian uint32 NLA (network byte order for nfnetlink).
func appendUint32Attr(buf []byte, attrType int, v uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, v)
	return appendNlaBytes(buf, attrType, data)
}

// appendUint16Attr appends a big-endian uint16 NLA.
func appendUint16Attr(buf []byte, attrType int, v uint16) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, v)
	return appendNlaBytes(buf, attrType, data)
}

// appendUint16AttrRaw appends a big-endian uint16 NLA (port numbers in network byte order).
func appendUint16AttrRaw(buf []byte, attrType int, v uint16) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, v)
	return appendNlaBytes(buf, attrType, data)
}
