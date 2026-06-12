// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package network

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// flanneBackendData is the shape of flannel.alpha.coreos.com/backend-data annotation.
type flannelBackendData struct {
	VtepMAC string `json:"VtepMAC"`
}

// netlinkFDBManager is the production FDBManager backed by raw rtnetlink.
// It requires CAP_NET_ADMIN.
type netlinkFDBManager struct{}

// NewFDBManager returns the production FDB manager backed by raw rtnetlink.
func NewFDBManager() FDBManager {
	return &netlinkFDBManager{}
}

// AddFDBEntry installs AF_BRIDGE (FDB) and AF_INET (neighbor) entries.
func (m *netlinkFDBManager) AddFDBEntry(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("AddFDBEntry: %w", err)
	}
	ifindex, err := ifaceIndex(e.IfName)
	if err != nil {
		return fmt.Errorf("AddFDBEntry: %w", err)
	}

	if err := netlinkNeighSet(unix.AF_BRIDGE, ifindex, nil, e.PodMAC, e.VTEPIP,
		unix.RTM_NEWNEIGH, unix.NLM_F_CREATE|unix.NLM_F_REPLACE); err != nil {
		return fmt.Errorf("AddFDBEntry AF_BRIDGE: %w", err)
	}
	log.Info("fdb: RTM_NEWNEIGH AF_BRIDGE", "ifName", e.IfName, "podMAC", e.PodMAC, "vtepIP", e.VTEPIP)

	if err := netlinkNeighSet(unix.AF_INET, ifindex, e.PodIP.To4(), e.PodMAC, nil,
		unix.RTM_NEWNEIGH, unix.NLM_F_CREATE|unix.NLM_F_REPLACE); err != nil {
		return fmt.Errorf("AddFDBEntry AF_INET: %w", err)
	}
	log.Info("fdb: RTM_NEWNEIGH AF_INET", "ifName", e.IfName, "podIP", e.PodIP, "podMAC", e.PodMAC)
	return nil
}

// RemoveFDBEntry deletes AF_BRIDGE and AF_INET entries; ENOENT is success.
func (m *netlinkFDBManager) RemoveFDBEntry(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("RemoveFDBEntry: %w", err)
	}
	ifindex, err := ifaceIndex(e.IfName)
	if err != nil {
		return fmt.Errorf("RemoveFDBEntry: %w", err)
	}

	if err := netlinkNeighSet(unix.AF_BRIDGE, ifindex, nil, e.PodMAC, e.VTEPIP,
		unix.RTM_DELNEIGH, 0); err != nil && !isEnoent(err) {
		return fmt.Errorf("RemoveFDBEntry AF_BRIDGE: %w", err)
	}
	log.Info("fdb: RTM_DELNEIGH AF_BRIDGE", "ifName", e.IfName, "podMAC", e.PodMAC)

	if err := netlinkNeighSet(unix.AF_INET, ifindex, e.PodIP.To4(), e.PodMAC, nil,
		unix.RTM_DELNEIGH, 0); err != nil && !isEnoent(err) {
		return fmt.Errorf("RemoveFDBEntry AF_INET: %w", err)
	}
	log.Info("fdb: RTM_DELNEIGH AF_INET", "ifName", e.IfName, "podIP", e.PodIP)
	return nil
}

// ConfirmOverlayReady performs RTM_GETNEIGH read-back for both entries.
func (m *netlinkFDBManager) ConfirmOverlayReady(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("ConfirmOverlayReady: %w", err)
	}
	ifindex, err := ifaceIndex(e.IfName)
	if err != nil {
		return fmt.Errorf("ConfirmOverlayReady: %w", err)
	}

	if err := netlinkNeighConfirm(unix.AF_BRIDGE, ifindex, nil, e.PodMAC); err != nil {
		return fmt.Errorf("ConfirmOverlayReady AF_BRIDGE: %w", err)
	}
	log.Info("fdb: RTM_GETNEIGH AF_BRIDGE confirmed", "ifName", e.IfName, "podMAC", e.PodMAC)

	if err := netlinkNeighConfirm(unix.AF_INET, ifindex, e.PodIP.To4(), e.PodMAC); err != nil {
		return fmt.Errorf("ConfirmOverlayReady AF_INET: %w", err)
	}
	log.Info("fdb: RTM_GETNEIGH AF_INET confirmed", "ifName", e.IfName, "podIP", e.PodIP)
	return nil
}

// DiscoverVTEPMAC implements VTEPMACDiscoverer.
// It tries the flannel annotation first, falling back to RTM_GETLINK on ifName.
func DiscoverVTEPMAC(ctx context.Context, flannelAnnotationJSON, ifName string) (net.HardwareAddr, error) {
	log := logf.FromContext(ctx)

	if flannelAnnotationJSON != "" {
		var data flannelBackendData
		if err := json.Unmarshal([]byte(flannelAnnotationJSON), &data); err == nil && data.VtepMAC != "" {
			mac, err := net.ParseMAC(data.VtepMAC)
			if err == nil {
				log.Info("vtep mac from flannel annotation", "mac", mac)
				return mac, nil
			}
		}
	}

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("DiscoverVTEPMAC RTM_GETLINK fallback: %w", err)
	}
	log.Info("vtep mac from RTM_GETLINK fallback", "ifName", ifName, "mac", iface.HardwareAddr)
	return iface.HardwareAddr, nil
}

// validateFDBEntry returns an error if any required field is missing or invalid.
func validateFDBEntry(e FDBEntry) error {
	if e.IfName == "" {
		return fmt.Errorf("IfName must not be empty")
	}
	if e.PodIP == nil {
		return fmt.Errorf("PodIP must not be nil")
	}
	if len(e.PodMAC) == 0 {
		return fmt.Errorf("PodMAC must not be empty")
	}
	if e.VTEPIP == nil {
		return fmt.Errorf("VTEPIP must not be nil")
	}
	return nil
}

func ifaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("ifaceIndex %q: %w", name, err)
	}
	return iface.Index, nil
}

func isEnoent(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "no such") ||
		err == syscall.ENOENT || err == unix.ENOENT
}

// netlinkNeighSet sends RTM_NEWNEIGH or RTM_DELNEIGH via a raw netlink socket.
//
// For AF_BRIDGE: dst (NDA_DST) = vtepIP, lladdr (NDA_LLADDR) = podMAC, podIP ignored.
// For AF_INET:   dst (NDA_DST) = podIP (IPv4 4-byte), lladdr (NDA_LLADDR) = podMAC.
func netlinkNeighSet(family, ifindex int, dst4 net.IP, lladdr net.HardwareAddr, vtepIP net.IP,
	msgType, flags uint16) error {

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	// NdMsg is the rtnetlink neighbor message header.
	type ndMsg struct {
		Family  uint8
		Pad1    uint8
		Pad2    uint16
		IfIndex int32
		State   uint16
		Flags   uint8
		Type    uint8
	}
	const ndMsgSize = 12
	const NUD_PERMANENT = 0x80
	const NTF_SELF = 0x02

	nd := ndMsg{
		Family:  uint8(family),
		IfIndex: int32(ifindex),
		State:   NUD_PERMANENT,
	}
	if family == unix.AF_BRIDGE {
		nd.Flags = NTF_SELF
	}

	ndBytes := (*[ndMsgSize]byte)(unsafe.Pointer(&nd))[:]

	attrs := buildNeighAttrs(family, dst4, lladdr, vtepIP)

	nlmsgLen := uint32(unix.SizeofNlMsghdr + ndMsgSize + len(attrs))
	hdr := unix.NlMsghdr{
		Len:   nlmsgLen,
		Type:  msgType,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | flags,
		Seq:   1,
		Pid:   uint32(os.Getpid()),
	}
	hdrBytes := (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&hdr))[:]

	msg := make([]byte, 0, nlmsgLen)
	msg = append(msg, hdrBytes...)
	msg = append(msg, ndBytes...)
	msg = append(msg, attrs...)

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(fd, msg, 0, sa); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}
	return netlinkRecvAck(fd)
}

func buildNeighAttrs(family int, dst4 net.IP, lladdr net.HardwareAddr, vtepIP net.IP) []byte {
	var attrs []byte

	if family == unix.AF_BRIDGE {
		// NDA_LLADDR = source pod MAC
		attrs = append(attrs, nlAttr(unix.NDA_LLADDR, []byte(lladdr))...)
		// NDA_DST = destination VTEP IP (IPv4)
		if vtep4 := vtepIP.To4(); vtep4 != nil {
			attrs = append(attrs, nlAttr(unix.NDA_DST, []byte(vtep4))...)
		}
	} else {
		// AF_INET: NDA_DST = pod IP (IPv4), NDA_LLADDR = pod MAC
		if dst4 != nil {
			attrs = append(attrs, nlAttr(unix.NDA_DST, []byte(dst4))...)
		}
		attrs = append(attrs, nlAttr(unix.NDA_LLADDR, []byte(lladdr))...)
	}
	return attrs
}

// netlinkNeighConfirm issues RTM_GETNEIGH and scans the dump for a matching entry.
func netlinkNeighConfirm(family, ifindex int, dst4 net.IP, lladdr net.HardwareAddr) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink confirm socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink confirm bind: %w", err)
	}

	type ndMsg struct {
		Family  uint8
		Pad1    uint8
		Pad2    uint16
		IfIndex int32
		State   uint16
		Flags   uint8
		Type    uint8
	}
	const ndMsgSize = 12

	nd := ndMsg{Family: uint8(family), IfIndex: int32(ifindex)}
	ndBytes := (*[ndMsgSize]byte)(unsafe.Pointer(&nd))[:]

	nlmsgLen := uint32(unix.SizeofNlMsghdr + ndMsgSize)
	hdr := unix.NlMsghdr{
		Len:   nlmsgLen,
		Type:  unix.RTM_GETNEIGH,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   2,
		Pid:   uint32(os.Getpid()),
	}
	hdrBytes := (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, ndBytes...)

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(fd, msg, 0, sa); err != nil {
		return fmt.Errorf("netlink confirm send: %w", err)
	}

	buf := make([]byte, 32768)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			return fmt.Errorf("netlink confirm read: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return fmt.Errorf("netlink confirm parse: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Type == unix.NLMSG_DONE {
				return fmt.Errorf("neighbor entry not found in RTM_GETNEIGH dump (family=%d)", family)
			}
			if m.Header.Type == unix.RTM_NEWNEIGH {
				if neighMatchesEntry(family, m.Data, dst4, lladdr) {
					return nil
				}
			}
		}
	}
}

// neighMatchesEntry parses a RTM_NEWNEIGH message body and checks if it matches.
func neighMatchesEntry(family int, data []byte, dst4 net.IP, lladdr net.HardwareAddr) bool {
	const ndMsgSize = 12
	if len(data) < ndMsgSize {
		return false
	}
	attrs, err := syscall.ParseNetlinkRouteAttr(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: unix.RTM_NEWNEIGH},
		Data:   data,
	})
	if err != nil {
		return false
	}
	var foundLLAddr, foundDst bool
	for _, a := range attrs {
		switch a.Attr.Type {
		case unix.NDA_LLADDR:
			if net.HardwareAddr(a.Value).String() == lladdr.String() {
				foundLLAddr = true
			}
		case unix.NDA_DST:
			if family == unix.AF_INET && dst4 != nil {
				if net.IP(a.Value).Equal(dst4) {
					foundDst = true
				}
			} else {
				foundDst = true
			}
		}
	}
	if family == unix.AF_BRIDGE {
		return foundLLAddr
	}
	return foundLLAddr && foundDst
}

// nlAttr builds a netlink attribute (type + aligned value).
func nlAttr(attrType uint16, val []byte) []byte {
	const align = 4
	l := 4 + len(val)
	padded := (l + align - 1) &^ (align - 1)
	b := make([]byte, padded)
	binary.LittleEndian.PutUint16(b[0:2], uint16(l))
	binary.LittleEndian.PutUint16(b[2:4], attrType)
	copy(b[4:], val)
	return b
}

// netlinkRecvAck reads the ACK/error response from a netlink socket.
func netlinkRecvAck(fd int) error {
	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return fmt.Errorf("netlink ack read: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return fmt.Errorf("netlink ack parse: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Type == unix.NLMSG_ERROR {
			errno := int32(binary.LittleEndian.Uint32(m.Data[:4]))
			if errno == 0 {
				return nil
			}
			return fmt.Errorf("netlink errno: %d", -errno)
		}
	}
	return nil
}
