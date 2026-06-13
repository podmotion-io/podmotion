/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build linux

// Package network provides network-layer operations for pod migration.
package network

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ─── netlink helpers ─────────────────────────────────────────────────────────

// openNLSocket opens a netlink socket of the given protocol, bound to kernel.
func openNLSocket(proto int) (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	// Set a receive timeout so a lost/unmatched ACK can never block the cutover path
	// indefinitely (ADR-0135): nlRecvAll's unix.Read returns EAGAIN on timeout, which the
	// caller surfaces as an error and the controller requeues. Without this a missing ACK
	// hangs InjectIPHandoff and the whole gRPC call.
	tv := unix.Timeval{Sec: 5}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// nlSend serialises hdr + body and writes it to fd.
func nlSend(fd int, hdr unix.NlMsghdr, body []byte) error {
	hdr.Len = uint32(unix.SizeofNlMsghdr + len(body))
	buf := make([]byte, 0, int(hdr.Len))
	buf = append(buf, (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&hdr))[:]...)
	buf = append(buf, body...)
	_, err := unix.Write(fd, buf)
	return err
}

// nlRecvAll reads netlink response messages until NLMSG_DONE or NLMSG_ERROR.
// NLMSG_ERROR with errno == 0 (ACK) is treated as success.
func nlRecvAll(fd int) ([]syscall.NetlinkMessage, error) {
	recv := make([]byte, 1<<20)
	var out []syscall.NetlinkMessage
	for {
		n, err := unix.Read(fd, recv)
		if err != nil {
			return nil, err
		}
		msgs, err := syscall.ParseNetlinkMessage(recv[:n])
		if err != nil {
			return nil, err
		}
		done := false
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				done = true
			case unix.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					// errno is stored as a negative int32 in little-endian.
					errno := int32(binary.LittleEndian.Uint32(m.Data[:4]))
					if errno < 0 {
						return out, syscall.Errno(-errno)
					}
				}
				done = true
			default:
				out = append(out, m)
			}
		}
		if done {
			break
		}
	}
	return out, nil
}

// putRtAttr appends a type-length-value rtattr to buf, padded to 4-byte alignment.
func putRtAttr(buf []byte, attrType uint16, data []byte) []byte {
	attrLen := unix.SizeofRtAttr + len(data)
	h := make([]byte, unix.SizeofRtAttr)
	binary.NativeEndian.PutUint16(h[0:2], uint16(attrLen))
	binary.NativeEndian.PutUint16(h[2:4], attrType)
	buf = append(buf, h...)
	buf = append(buf, data...)
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

// parseRtAttrs returns a map of rtattr type → value bytes for a flat attribute list.
// Strips the NESTED (0x8000) and BYTEORDER (0x4000) flag bits from the type.
func parseRtAttrs(data []byte) map[uint16][]byte {
	out := make(map[uint16][]byte)
	for len(data) >= unix.SizeofRtAttr {
		attrLen := int(binary.NativeEndian.Uint16(data[0:2]))
		attrType := binary.NativeEndian.Uint16(data[2:4]) & 0x1FFF
		if attrLen < unix.SizeofRtAttr || attrLen > len(data) {
			break
		}
		out[attrType] = data[unix.SizeofRtAttr:attrLen]
		pad := (attrLen + 3) &^ 3
		if pad > len(data) {
			break
		}
		data = data[pad:]
	}
	return out
}

// put32 encodes v as a 4-byte native-endian slice.
func put32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

// ─── link operations ─────────────────────────────────────────────────────────

// linkIndexByName returns the ifindex of the named interface via RTM_GETLINK.
func linkIndexByName(name string) (int, error) {
	fd, err := openNLSocket(unix.NETLINK_ROUTE)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	ifim := unix.IfInfomsg{Family: unix.AF_UNSPEC}
	body := make([]byte, 0, unix.SizeofIfInfomsg+32)
	body = append(body, (*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(&ifim))[:]...)
	body = putRtAttr(body, unix.IFLA_IFNAME, append([]byte(name), 0))

	if err := nlSend(fd, unix.NlMsghdr{
		Type:  unix.RTM_GETLINK,
		Flags: unix.NLM_F_REQUEST,
		Seq:   1,
	}, body); err != nil {
		return 0, err
	}
	msgs, err := nlRecvAll(fd)
	if err != nil {
		return 0, fmt.Errorf("RTM_GETLINK %q: %w", name, err)
	}
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWLINK || len(m.Data) < unix.SizeofIfInfomsg {
			continue
		}
		ifim2 := (*unix.IfInfomsg)(unsafe.Pointer(&m.Data[0]))
		return int(ifim2.Index), nil
	}
	return 0, fmt.Errorf("interface %q not found", name)
}

// linkKind holds the name, ifindex, and IFLA_INFO_KIND for one network interface.
type linkKind struct {
	name    string
	ifindex int
	kind    string
}

// listLinksWithKind returns all interfaces with their IFLA_INFO_KIND type string.
func listLinksWithKind() ([]linkKind, error) {
	fd, err := openNLSocket(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	ifim := unix.IfInfomsg{Family: unix.AF_UNSPEC}
	body := (*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(&ifim))[:]

	if err := nlSend(fd, unix.NlMsghdr{
		Type:  unix.RTM_GETLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   1,
	}, body); err != nil {
		return nil, err
	}
	msgs, err := nlRecvAll(fd)
	if err != nil {
		return nil, fmt.Errorf("RTM_GETLINK dump: %w", err)
	}

	var links []linkKind
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWLINK || len(m.Data) < unix.SizeofIfInfomsg {
			continue
		}
		ifim2 := (*unix.IfInfomsg)(unsafe.Pointer(&m.Data[0]))
		attrs := parseRtAttrs(m.Data[unix.SizeofIfInfomsg:])

		lname := ""
		if b, ok := attrs[unix.IFLA_IFNAME]; ok && len(b) > 0 {
			// null-terminated string
			end := len(b)
			if b[end-1] == 0 {
				end--
			}
			lname = string(b[:end])
		}
		kind := ""
		if infoBytes, ok := attrs[unix.IFLA_LINKINFO]; ok {
			// IFLA_LINKINFO is nested; IFLA_INFO_KIND=1 names the driver.
			nested := parseRtAttrs(infoBytes)
			if kb, ok := nested[unix.IFLA_INFO_KIND]; ok && len(kb) > 0 {
				end := len(kb)
				if kb[end-1] == 0 {
					end--
				}
				kind = string(kb[:end])
			}
		}
		links = append(links, linkKind{
			name:    lname,
			ifindex: int(ifim2.Index),
			kind:    kind,
		})
	}
	return links, nil
}

// ─── route operations ────────────────────────────────────────────────────────

// addrFamily returns AF_INET for IPv4 addresses, AF_INET6 for IPv6, and the
// canonical 4- or 16-byte representation of ip.
func addrFamily(ip net.IP) (uint8, net.IP) {
	if ip4 := ip.To4(); ip4 != nil {
		return unix.AF_INET, ip4
	}
	return unix.AF_INET6, ip.To16()
}

// injectRoute writes a RTM_NEWROUTE (NLM_F_CREATE|NLM_F_REPLACE) to the kernel.
func injectRoute(ifindex int, dst *net.IPNet, scope, proto, rtype uint8, metric int) error {
	fd, err := openNLSocket(unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	family, dstIP := addrFamily(dst.IP)
	ones, _ := dst.Mask.Size()

	rtm := unix.RtMsg{
		Family:   family,
		Dst_len:  uint8(ones),
		Protocol: proto,
		Scope:    scope,
		Type:     rtype,
	}
	body := make([]byte, 0, 128)
	body = append(body, (*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&rtm))[:]...)
	body = putRtAttr(body, unix.RTA_DST, dstIP)
	body = putRtAttr(body, unix.RTA_OIF, put32(uint32(ifindex)))
	if metric > 0 {
		body = putRtAttr(body, unix.RTA_PRIORITY, put32(uint32(metric)))
	}

	if err := nlSend(fd, unix.NlMsghdr{
		Type:  unix.RTM_NEWROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_CREATE | unix.NLM_F_REPLACE | unix.NLM_F_ACK,
		Seq:   1,
	}, body); err != nil {
		return err
	}
	_, err = nlRecvAll(fd)
	return err
}

// deleteRoute removes a route via RTM_DELROUTE. ENOENT is silently ignored.
func deleteRoute(ifindex int, dst *net.IPNet) error {
	fd, err := openNLSocket(unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	family, dstIP := addrFamily(dst.IP)
	ones, _ := dst.Mask.Size()

	rtm := unix.RtMsg{Family: family, Dst_len: uint8(ones)}
	body := make([]byte, 0, 64)
	body = append(body, (*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&rtm))[:]...)
	body = putRtAttr(body, unix.RTA_DST, dstIP)
	body = putRtAttr(body, unix.RTA_OIF, put32(uint32(ifindex)))

	if err := nlSend(fd, unix.NlMsghdr{
		Type:  unix.RTM_DELROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   1,
	}, body); err != nil {
		return err
	}
	_, err = nlRecvAll(fd)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}

// lookupRouteOIF returns the output interface indices the kernel would use to
// reach ip, via a RTM_GETROUTE unicast lookup (not a dump).
func lookupRouteOIF(ip net.IP) ([]int, error) {
	fd, err := openNLSocket(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	family, ipBytes := addrFamily(ip)
	bits := 32
	if family == unix.AF_INET6 {
		bits = 128
	}

	rtm := unix.RtMsg{Family: family, Dst_len: uint8(bits)}
	body := make([]byte, 0, 64)
	body = append(body, (*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&rtm))[:]...)
	body = putRtAttr(body, unix.RTA_DST, ipBytes)

	if err := nlSend(fd, unix.NlMsghdr{
		Type:  unix.RTM_GETROUTE,
		Flags: unix.NLM_F_REQUEST,
		Seq:   1,
	}, body); err != nil {
		return nil, err
	}
	msgs, err := nlRecvAll(fd)
	if err != nil {
		return nil, fmt.Errorf("RTM_GETROUTE %s: %w", ip, err)
	}

	var oifs []int
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWROUTE || len(m.Data) < unix.SizeofRtMsg {
			continue
		}
		attrs := parseRtAttrs(m.Data[unix.SizeofRtMsg:])
		if oifBytes, ok := attrs[unix.RTA_OIF]; ok && len(oifBytes) == 4 {
			oifs = append(oifs, int(binary.NativeEndian.Uint32(oifBytes)))
		}
	}
	return oifs, nil
}

// routeEntry is a single route from a kernel dump.
type routeEntry struct {
	dst *net.IPNet
	oif int
}

// dumpRoutes returns all routes for the given address family.
// Pass unix.AF_UNSPEC to get both IPv4 and IPv6.
func dumpRoutes(family uint8) ([]routeEntry, error) {
	fd, err := openNLSocket(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	rtm := unix.RtMsg{Family: family}
	body := (*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&rtm))[:]

	if err := nlSend(fd, unix.NlMsghdr{
		Type:  unix.RTM_GETROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   1,
	}, body); err != nil {
		return nil, err
	}
	msgs, err := nlRecvAll(fd)
	if err != nil {
		return nil, fmt.Errorf("RTM_GETROUTE dump: %w", err)
	}

	var routes []routeEntry
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWROUTE || len(m.Data) < unix.SizeofRtMsg {
			continue
		}
		rtm2 := (*unix.RtMsg)(unsafe.Pointer(&m.Data[0]))
		attrs := parseRtAttrs(m.Data[unix.SizeofRtMsg:])

		dstBytes, hasDst := attrs[unix.RTA_DST]
		oifBytes, hasOIF := attrs[unix.RTA_OIF]
		if !hasDst || !hasOIF || len(oifBytes) != 4 {
			continue
		}
		var dstNet *net.IPNet
		switch rtm2.Family {
		case unix.AF_INET:
			if len(dstBytes) == 4 {
				dstNet = &net.IPNet{
					IP:   append(net.IP{}, dstBytes...),
					Mask: net.CIDRMask(int(rtm2.Dst_len), 32),
				}
			}
		case unix.AF_INET6:
			if len(dstBytes) == 16 {
				dstNet = &net.IPNet{
					IP:   append(net.IP{}, dstBytes...),
					Mask: net.CIDRMask(int(rtm2.Dst_len), 128),
				}
			}
		}
		if dstNet == nil {
			continue
		}
		routes = append(routes, routeEntry{
			dst: dstNet,
			oif: int(binary.NativeEndian.Uint32(oifBytes)),
		})
	}
	return routes, nil
}

// ─── XFRM policy detection ───────────────────────────────────────────────────

// XFRM netlink message types (uapi/linux/xfrm.h enum xfrm_msg_type).
// Not exported by golang.org/x/sys/unix; defined here from kernel headers.
const (
	xfrmMsgGetPolicy = 0x15 // XFRM_MSG_GETPOLICY
	xfrmMsgNewPolicy = 0x13 // XFRM_MSG_NEWPOLICY
)

// xfrmSelectorSize is sizeof(struct xfrm_selector) from uapi/linux/xfrm.h.
// Layout we parse:
//
//	daddr [16]byte  @0   — destination address (IPv4 in first 4 bytes for AF_INET)
//	saddr [16]byte  @16  — source address
//	dport uint16    @32  big-endian
//	dport_mask      @34
//	sport uint16    @36
//	sport_mask      @38
//	family uint16   @40  native-endian (AF_INET=2, AF_INET6=10)
//	prefixlen_d u8  @42
//	prefixlen_s u8  @43
const xfrmSelectorSize = 56

// xfrmSelectorOverlapsCIDR reports whether either endpoint of the selector
// falls within podCIDR.
func xfrmSelectorOverlapsCIDR(sel []byte, podCIDR *net.IPNet) bool {
	if len(sel) < xfrmSelectorSize {
		return false
	}
	family := binary.NativeEndian.Uint16(sel[40:42])
	prefixD := int(sel[42])
	prefixS := int(sel[43])

	switch family {
	case unix.AF_INET:
		daddr := net.IP(sel[0:4])
		saddr := net.IP(sel[16:20])
		if prefixD > 0 && podCIDR.Contains(daddr) {
			return true
		}
		if prefixS > 0 && podCIDR.Contains(saddr) {
			return true
		}
	case unix.AF_INET6:
		daddr := net.IP(sel[0:16])
		saddr := net.IP(sel[16:32])
		if prefixD > 0 && podCIDR.Contains(daddr) {
			return true
		}
		if prefixS > 0 && podCIDR.Contains(saddr) {
			return true
		}
	}
	return false
}

// xfrmPoliciesHitCIDR returns true if any XFRM policy has an endpoint within podCIDR.
func xfrmPoliciesHitCIDR(podCIDR *net.IPNet) (bool, error) {
	if podCIDR == nil {
		return false, nil
	}
	fd, err := openNLSocket(unix.NETLINK_XFRM)
	if err != nil {
		return false, fmt.Errorf("NETLINK_XFRM socket: %w", err)
	}
	defer unix.Close(fd)

	if err := nlSend(fd, unix.NlMsghdr{
		Type:  xfrmMsgGetPolicy,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   1,
	}, nil); err != nil {
		return false, fmt.Errorf("XFRM_MSG_GETPOLICY send: %w", err)
	}
	msgs, err := nlRecvAll(fd)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("XFRM policy recv: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Type != xfrmMsgNewPolicy {
			continue
		}
		// xfrm_userpolicy_info opens with xfrm_selector at byte 0.
		if xfrmSelectorOverlapsCIDR(m.Data, podCIDR) {
			return true, nil
		}
	}
	return false, nil
}

// ─── Public API ──────────────────────────────────────────────────────────────

// InjectMigrationHostRoute injects a /32 (IPv4) or /128 (IPv6) host route on the
// source node directing podIP traffic out the WireGuard tunnel interface. This
// replaces FDB injection (ADR-0048) on WireGuard-encrypted overlay clusters (ADR-0102).
//
// Called AFTER CRIURestoreInitiated — not at ZeroWindowEngaged — to avoid redirecting
// packets to a destination before the pod netns exists (ADR-0102 §6 ordering contract).
//
// WireGuard interfaces are PtP/NOARP; Gw must be nil and Scope must be LINK.
// Metric 50 ensures this route wins over CNI daemon routes (Calico 200, Cilium 100+).
func InjectMigrationHostRoute(podIP net.IP, wgInterface string) error {
	ifindex, err := linkIndexByName(wgInterface)
	if err != nil {
		return fmt.Errorf("WireGuard interface %q not found: %w", wgInterface, err)
	}
	bits := 32
	if podIP.To4() == nil {
		bits = 128 // IPv6 — ADR-0081
	}
	dst := &net.IPNet{IP: podIP, Mask: net.CIDRMask(bits, bits*4)}
	if err := injectRoute(ifindex, dst, unix.RT_SCOPE_LINK, unix.RTPROT_STATIC, unix.RTN_UNICAST, 50); err != nil {
		return fmt.Errorf("inject WireGuard host route %s via %s: %w", podIP, wgInterface, err)
	}
	return nil
}

// SetPodIPHostRoute installs a /32 (or /128) link-scoped host route for podIP egressing the
// named device (e.g. "cni0"), so the kernel's route lookup selects the LOCAL bridge for the
// OLD pod IP instead of the default per-CIDR flannel.1 overlay route to the source node
// (ADR-0135). Without this route the neighbor entry from ADR-0133 D2 is never consulted,
// because the destination is routed out flannel.1 toward the source node's VTEP. Idempotent
// via NLM_F_REPLACE.
func SetPodIPHostRoute(ctx context.Context, ifName string, podIP net.IP) error {
	log := logf.FromContext(ctx)
	ifindex, err := linkIndexByName(ifName)
	if err != nil {
		return fmt.Errorf("SetPodIPHostRoute: interface %q not found: %w", ifName, err)
	}
	bits := 32
	if podIP.To4() == nil {
		bits = 128
	}
	dst := &net.IPNet{IP: podIP, Mask: net.CIDRMask(bits, bits*4)}
	if err := injectRoute(ifindex, dst, unix.RT_SCOPE_LINK, unix.RTPROT_STATIC, unix.RTN_UNICAST, 0); err != nil {
		return fmt.Errorf("SetPodIPHostRoute %s via %s: %w", podIP, ifName, err)
	}
	log.Info("route: RTM_NEWROUTE /32 link-scope (ADR-0135 handoff)", "ifName", ifName, "podIP", podIP)
	return nil
}

// DeletePodIPHostRoute removes the /32 host route installed by SetPodIPHostRoute. Idempotent.
func DeletePodIPHostRoute(ctx context.Context, ifName string, podIP net.IP) error {
	log := logf.FromContext(ctx)
	ifindex, err := linkIndexByName(ifName)
	if err != nil {
		// Interface gone is not an error for cleanup.
		return nil
	}
	bits := 32
	if podIP.To4() == nil {
		bits = 128
	}
	dst := &net.IPNet{IP: podIP, Mask: net.CIDRMask(bits, bits*4)}
	if err := deleteRoute(ifindex, dst); err != nil {
		return fmt.Errorf("DeletePodIPHostRoute %s via %s: %w", podIP, ifName, err)
	}
	log.Info("route: RTM_DELROUTE /32 (ADR-0135 source cleanup)", "ifName", ifName, "podIP", podIP)
	return nil
}

// CleanupMigrationHostRoute removes the host route injected by InjectMigrationHostRoute.
// Idempotent — ENOENT is not an error.
// Called from SourceCleanup after TrafficVerified=True (ADR-0012 gate, ADR-0102).
func CleanupMigrationHostRoute(podIP net.IP, wgInterface string) error {
	ifindex, err := linkIndexByName(wgInterface)
	if err != nil {
		return fmt.Errorf("WireGuard interface %q not found: %w", wgInterface, err)
	}
	bits := 32
	if podIP.To4() == nil {
		bits = 128
	}
	dst := &net.IPNet{IP: podIP, Mask: net.CIDRMask(bits, bits*4)}
	if err := deleteRoute(ifindex, dst); err != nil {
		return fmt.Errorf("cleanup WireGuard host route %s: %w", podIP, err)
	}
	return nil
}

// ConfirmLocalDeliveryRoute confirms that a /32 route for podIP on the destination node
// egresses the expected veth interface identified by podVethIfindex. Returns true only
// when the CNI daemon has attached the pod netns and the local delivery route is present.
//
// Uses positive ifindex match — not a negative interface-type filter — to avoid false
// positives from the default route, the source-side redirect, or unrelated veths
// (ADR-0102 §4, architect quorum requirement).
//
// podVethIfindex comes from the PrepareDestinationNetns gRPC response.
func ConfirmLocalDeliveryRoute(podIP net.IP, podVethIfindex int) (bool, error) {
	oifs, err := lookupRouteOIF(podIP)
	if err != nil {
		return false, fmt.Errorf("RouteGet %s: %w", podIP, err)
	}
	for _, oif := range oifs {
		if oif == podVethIfindex {
			return true, nil
		}
	}
	return false, nil
}

// DetectWireGuardInterface returns the name of the WireGuard tunnel interface on this
// node that carries traffic for the given pod CIDR. Returns "" if WireGuard is not in use.
//
// Selection algorithm: list all links of type "wireguard"; if exactly one, return it;
// if multiple (rare), select the one carrying a route that covers podCIDR.
func DetectWireGuardInterface(podCIDR *net.IPNet) (string, error) {
	links, err := listLinksWithKind()
	if err != nil {
		return "", fmt.Errorf("listing network links: %w", err)
	}
	var wgLinks []linkKind
	for _, l := range links {
		if l.kind == "wireguard" {
			wgLinks = append(wgLinks, l)
		}
	}
	if len(wgLinks) == 0 {
		return "", nil
	}
	if len(wgLinks) == 1 {
		return wgLinks[0].name, nil
	}
	// Multiple WireGuard interfaces — pick the one with a route covering podCIDR.
	routes, err := dumpRoutes(unix.AF_UNSPEC)
	if err == nil {
		for _, wl := range wgLinks {
			for _, r := range routes {
				if r.oif == wl.ifindex && r.dst != nil && podCIDR != nil && podCIDR.Contains(r.dst.IP) {
					return wl.name, nil
				}
			}
		}
	}
	// Fallback: return first WireGuard link.
	return wgLinks[0].name, nil
}

// DetectIPSecModeCNI detects CNI-managed IPSec by looking for XFRM policies whose
// source or destination addresses fall within the pod CIDR. Generic host-level XFRM
// policies (service mesh, host VPN) are not counted (ADR-0102 §9).
func DetectIPSecModeCNI(podCIDR *net.IPNet) (bool, error) {
	hit, err := xfrmPoliciesHitCIDR(podCIDR)
	if err != nil {
		return false, fmt.Errorf("listing XFRM policies: %w", err)
	}
	return hit, nil
}
