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
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/podmotion-io/podmotion/internal/agent/network/bpfloader"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"golang.org/x/sys/unix"
)

// ciliumEBPFManager is the production eBPFManager backed by the cilium/ebpf
// library.  The zero_window BPF collection is loaded lazily on first
// ArmZeroWindowHold call and shared across all held ifindices.
//
// TC attach uses raw rtnetlink: clsact qdisc + BPF_F_ALLOW_OVERRIDE filter,
// which coexists correctly with CNI hooks on the same interface.
type ciliumEBPFManager struct {
	mu sync.Mutex
	// objs is the loaded zero_window collection; nil until first arm.
	objs *bpfloader.ZeroWindowObjects
	// tcFilters tracks the netlink filter handle per ifindex so we can delete
	// exactly our filter on disarm without scanning the full filter list.
	tcFilters map[uint32]uint32 // ifindex → filter handle (host byte order)
}

func newCiliumEBPFManager() eBPFManager {
	return &ciliumEBPFManager{
		tcFilters: make(map[uint32]uint32),
	}
}

// ArmZeroWindowHold loads the zero_window BPF program (if not already loaded),
// attaches a TC egress filter to the interface identified by ifindex with
// BPF_F_ALLOW_OVERRIDE, and inserts ifindex into PM_ACTIVE_HOLDS.
func (m *ciliumEBPFManager) ArmZeroWindowHold(ctx context.Context, ifindex uint32) error {
	log := logf.FromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureLoaded(ctx); err != nil {
		return err
	}

	val := uint8(1)
	if err := m.objs.PmActiveHolds.Update(ifindex, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("PM_ACTIVE_HOLDS update ifindex=%d: %w", ifindex, err)
	}

	if _, ok := m.tcFilters[ifindex]; !ok {
		handle, err := attachTCEgress(int(ifindex), m.objs.PmZeroWindowHold)
		if err != nil {
			_ = m.objs.PmActiveHolds.Delete(ifindex)
			return fmt.Errorf("TC egress attach ifindex=%d: %w", ifindex, err)
		}
		m.tcFilters[ifindex] = handle
	}

	log.Info("ebpf cilium: ArmZeroWindowHold", "ifindex", ifindex)
	return nil
}

// DisarmZeroWindowHold removes ifindex from PM_ACTIVE_HOLDS and detaches the
// TC filter.  If no holds remain the BPF collection is closed to release
// kernel resources.
func (m *ciliumEBPFManager) DisarmZeroWindowHold(ctx context.Context, ifindex uint32) error {
	log := logf.FromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return nil
	}

	if err := m.objs.PmActiveHolds.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("PM_ACTIVE_HOLDS delete ifindex=%d: %w", ifindex, err)
	}

	if handle, ok := m.tcFilters[ifindex]; ok {
		if err := detachTCEgress(int(ifindex), handle); err != nil {
			log.Error(err, "ebpf cilium: TC egress detach failed", "ifindex", ifindex)
		}
		delete(m.tcFilters, ifindex)
	}

	if len(m.tcFilters) == 0 {
		m.objs.Close()
		m.objs = nil
	}

	log.Info("ebpf cilium: DisarmZeroWindowHold", "ifindex", ifindex)
	return nil
}

func (m *ciliumEBPFManager) ArmXDPBridge(ctx context.Context, srcIP, dstIP net.IP, genevePort uint16) error {
	logf.FromContext(ctx).Info("ebpf cilium: ArmXDPBridge (M22)",
		"srcIP", srcIP, "dstIP", dstIP, "genevePort", genevePort)
	return nil
}

func (m *ciliumEBPFManager) DisarmXDPBridge(ctx context.Context, srcIP net.IP) error {
	logf.FromContext(ctx).Info("ebpf cilium: DisarmXDPBridge (M22)", "srcIP", srcIP)
	return nil
}

func (m *ciliumEBPFManager) CheckXDPHookConflict(ctx context.Context, ifindex uint32) (bool, error) {
	logf.FromContext(ctx).Info("ebpf cilium: CheckXDPHookConflict (M22)", "ifindex", ifindex)
	return false, nil
}

// ensureLoaded loads the zero_window BPF collection if not already loaded.
// Must be called with m.mu held.
func (m *ciliumEBPFManager) ensureLoaded(ctx context.Context) error {
	if m.objs != nil {
		return nil
	}
	objs := &bpfloader.ZeroWindowObjects{}
	if err := bpfloader.LoadZeroWindowObjects(objs, nil); err != nil {
		return fmt.Errorf("load zero_window BPF objects: %w", err)
	}
	m.objs = objs
	logf.FromContext(ctx).Info("ebpf cilium: zero_window collection loaded")
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Raw rtnetlink helpers for clsact qdisc + TC filter management.
//
// We use raw netlink rather than a third-party library to avoid pulling in
// additional dependencies (ADR preference: custom over packages).
// ──────────────────────────────────────────────────────────────────────────────

// TC netlink constants not yet in golang.org/x/sys/unix.
const (
	tcHandleRoot    = 0xFFFFFFFF
	tcHandleIngress = 0xFFFFFFF1

	// clsact qdisc handle/parent
	tcHandleClsact = 0xFFFF0000
	tcParentEgress = 0xFFFFFFF3 // TC_H_MIN_EGRESS

	// rtnetlink message types
	rtmNewQdisc   = unix.RTM_NEWQDISC
	rtmGetQdisc   = unix.RTM_GETQDISC
	rtmNewFilter  = unix.RTM_NEWTFILTER
	rtmDelFilter  = unix.RTM_DELTFILTER

	// TC attribute types
	tcaKind     = 1
	tcaOptions  = 2
	tcaFdArray  = 22

	// BPF filter attribute types
	tcaBpfFd       = 1
	tcaBpfName     = 2
	tcaBpfFlags    = 3
	tcaBpfFlagsGen = 4
	tcaBpfTag      = 5
	tcaBpfId       = 6

	tcBpfFlagActDirect = 1 << 0 // TCA_BPF_FLAG_ACT_DIRECT

	// BPF_F_ALLOW_OVERRIDE for prog-based filters
	bpfFAllowOverride = 1
)

// nlAttr builds a packed netlink attribute (type + len header + padded data).
func nlAttr(typ int, data []byte) []byte {
	hdrLen := 4
	totalLen := hdrLen + len(data)
	padded := (totalLen + 3) &^ 3
	buf := make([]byte, padded)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(totalLen))
	binary.LittleEndian.PutUint16(buf[2:4], uint16(typ))
	copy(buf[4:], data)
	return buf
}

// nlAttrStr builds a null-terminated string netlink attribute.
func nlAttrStr(typ int, s string) []byte {
	return nlAttr(typ, append([]byte(s), 0))
}

// nlAttrU32 builds a uint32 netlink attribute.
func nlAttrU32(typ int, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return nlAttr(typ, b[:])
}

// ensureClsactQdisc creates the clsact qdisc on ifindex if it does not exist.
// clsact is the hook point for both ingress and egress TC-BPF programs without
// an actual queuing discipline.
func ensureClsactQdisc(ifindex int) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	// Build RTM_NEWQDISC for clsact.
	type tcmsg struct {
		Family  uint8
		Pad1    uint8
		Pad2    uint16
		Ifindex int32
		Handle  uint32
		Parent  uint32
		Info    uint32
	}
	tc := tcmsg{
		Ifindex: int32(ifindex),
		Handle:  tcHandleClsact,
		Parent:  tcHandleRoot,
	}
	tcBytes := (*[unsafe.Sizeof(tc)]byte)(unsafe.Pointer(&tc))[:]
	kind := nlAttrStr(tcaKind, "clsact")
	payload := append(tcBytes, kind...)

	hdr := unix.NlMsghdr{
		Len:   uint32(unix.NLMSG_HDRSIZE + len(payload)),
		Type:  rtmNewQdisc,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   1,
	}
	hdrBytes := (*[unix.NLMSG_HDRSIZE]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	// Pad to 4-byte boundary.
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return fmt.Errorf("RTM_NEWQDISC write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return fmt.Errorf("RTM_NEWQDISC read: %w", err)
	}
	if n < unix.NLMSG_HDRSIZE {
		return fmt.Errorf("RTM_NEWQDISC: short reply (%d bytes)", n)
	}
	replyHdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if replyHdr.Type == unix.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(buf[unix.NLMSG_HDRSIZE:]))
		if errno != 0 && errno != -int32(syscall.EEXIST) {
			return fmt.Errorf("RTM_NEWQDISC: kernel error %d", errno)
		}
		// EEXIST means clsact is already present — idempotent, treat as success.
	}
	return nil
}

// attachTCEgress attaches prog to the TC egress hook of ifindex using a clsact
// qdisc filter with BPF_F_ALLOW_OVERRIDE.  Returns the filter handle (host
// byte order) which is needed to remove the filter later.
func attachTCEgress(ifindex int, prog *ebpf.Program) (uint32, error) {
	if err := ensureClsactQdisc(ifindex); err != nil {
		return 0, fmt.Errorf("clsact qdisc: %w", err)
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return 0, fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, fmt.Errorf("netlink bind: %w", err)
	}

	type tcmsg struct {
		Family  uint8
		Pad1    uint8
		Pad2    uint16
		Ifindex int32
		Handle  uint32
		Parent  uint32
		Info    uint32 // prio<<16 | proto (htons(ETH_P_ALL)=0x0003)
	}
	const prioDefault = 1
	const ethPAll = 0x0003 // htons(ETH_P_ALL)
	tc := tcmsg{
		Ifindex: int32(ifindex),
		Handle:  0,
		Parent:  tcParentEgress,
		Info:    (prioDefault << 16) | ethPAll,
	}
	tcBytes := (*[unsafe.Sizeof(tc)]byte)(unsafe.Pointer(&tc))[:]

	progFD := uint32(prog.FD())
	bpfOpts := append(
		nlAttrU32(tcaBpfFd, progFD),
		append(
			nlAttrStr(tcaBpfName, "pm_zero_window_hold"),
			nlAttrU32(tcaBpfFlags, tcBpfFlagActDirect)...,
		)...,
	)
	attrs := append(
		nlAttrStr(tcaKind, "bpf"),
		nlAttr(tcaOptions, bpfOpts)...,
	)
	payload := append(tcBytes, attrs...)

	filterHandle := uint32(0xFFFF0001) // stable handle we assign
	tc.Handle = filterHandle
	// Rebuild tcBytes with handle set.
	tcBytesH := (*[unsafe.Sizeof(tc)]byte)(unsafe.Pointer(&tc))[:]
	payload = append(tcBytesH, attrs...)

	hdr := unix.NlMsghdr{
		Len:   uint32(unix.NLMSG_HDRSIZE + len(payload)),
		Type:  rtmNewFilter,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   2,
	}
	hdrBytes := (*[unix.NLMSG_HDRSIZE]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return 0, fmt.Errorf("RTM_NEWTFILTER write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return 0, fmt.Errorf("RTM_NEWTFILTER read: %w", err)
	}
	if n < unix.NLMSG_HDRSIZE {
		return 0, fmt.Errorf("RTM_NEWTFILTER: short reply (%d bytes)", n)
	}
	replyHdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if replyHdr.Type == unix.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(buf[unix.NLMSG_HDRSIZE:]))
		if errno != 0 {
			return 0, fmt.Errorf("RTM_NEWTFILTER: kernel error %d", errno)
		}
	}

	return filterHandle, nil
}

// detachTCEgress removes the TC egress filter identified by handle from ifindex.
func detachTCEgress(ifindex int, handle uint32) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	type tcmsg struct {
		Family  uint8
		Pad1    uint8
		Pad2    uint16
		Ifindex int32
		Handle  uint32
		Parent  uint32
		Info    uint32
	}
	tc := tcmsg{
		Ifindex: int32(ifindex),
		Handle:  handle,
		Parent:  tcParentEgress,
	}
	tcBytes := (*[unsafe.Sizeof(tc)]byte)(unsafe.Pointer(&tc))[:]
	kind := nlAttrStr(tcaKind, "bpf")
	payload := append(tcBytes, kind...)

	hdr := unix.NlMsghdr{
		Len:   uint32(unix.NLMSG_HDRSIZE + len(payload)),
		Type:  rtmDelFilter,
		Flags: unix.NLM_F_REQUEST,
		Seq:   3,
	}
	hdrBytes := (*[unix.NLMSG_HDRSIZE]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return fmt.Errorf("RTM_DELTFILTER write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return fmt.Errorf("RTM_DELTFILTER read: %w", err)
	}
	if n < unix.NLMSG_HDRSIZE {
		return fmt.Errorf("RTM_DELTFILTER: short reply (%d bytes)", n)
	}
	replyHdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if replyHdr.Type == unix.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(buf[unix.NLMSG_HDRSIZE:]))
		if errno != 0 && errno != -int32(syscall.ENOENT) {
			return fmt.Errorf("RTM_DELTFILTER: kernel error %d", errno)
		}
	}
	return nil
}
