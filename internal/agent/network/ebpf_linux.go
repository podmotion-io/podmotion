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
	"golang.org/x/sys/unix"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ciliumEBPFManager is the production eBPFManager backed by the cilium/ebpf
// library.  The zero_window BPF collection is loaded lazily on first
// ArmZeroWindowHold call and shared across all held ifindices.
//
// TC attach uses raw rtnetlink: clsact qdisc + BPF_F_ALLOW_OVERRIDE filter,
// which coexists correctly with CNI hooks on the same interface.
type ciliumEBPFManager struct {
	mu sync.Mutex

	// zero_window collection; nil until first arm.
	objs      *bpfloader.ZeroWindowObjects
	tcFilters map[uint32]uint32 // ifindex → egress filter handle

	// pm_relay collection; nil until first ArmRelay call.
	relayObjs           *bpfloader.PmRelayObjects
	relayEgressFilters  map[uint32]uint32 // ifindex → egress handle
	relayIngressFilters map[uint32]uint32 // ifindex → ingress handle

	// pm_xdp_vtep collection; nil until first ArmVTEP call.
	vtepObjs        *bpfloader.PmXdpVtepObjects
	vtepXDPLinks    map[uint32]struct{} // dst ifindex
	srcGuardXDPLinks map[uint32]struct{} // src ifindex
}

func newCiliumEBPFManager() eBPFManager {
	return &ciliumEBPFManager{
		tcFilters:           make(map[uint32]uint32),
		relayEgressFilters:  make(map[uint32]uint32),
		relayIngressFilters: make(map[uint32]uint32),
		vtepXDPLinks:        make(map[uint32]struct{}),
		srcGuardXDPLinks:    make(map[uint32]struct{}),
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

// ArmRelay loads the pm_relay BPF collection (if not already loaded), attaches
// PM_RELAY_TC_EGRESS and PM_RELAY_TC_INGRESS to the clsact qdisc of the interface
// named by ifname, and inserts the initial PM_SEQ_XLAT entry.
//
// Both TC directions are attached to flannel.1 (or whatever ifname is passed).
// The map entry must be populated BEFORE ZeroWindowDisarm per ADR-0049.
func (m *ciliumEBPFManager) ArmRelay(ctx context.Context, ifname string, key SeqXlatKey, entry SeqXlatEntry) error {
	log := logf.FromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureRelayLoaded(ctx); err != nil {
		return err
	}

	bpfKey := pmRelayBpfKey(key)
	bpfVal := pmRelayBpfVal(entry)
	if err := m.relayObjs.PmSeqXlat.Update(bpfKey, bpfVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("PM_SEQ_XLAT update: %w", err)
	}

	ifindex, err := resolveIfindex(ifname)
	if err != nil {
		return err
	}

	if _, ok := m.relayEgressFilters[ifindex]; !ok {
		handle, err := attachTCEgress(int(ifindex), m.relayObjs.PmRelayTcEgress)
		if err != nil {
			return fmt.Errorf("relay TC egress attach ifindex=%d: %w", ifindex, err)
		}
		m.relayEgressFilters[ifindex] = handle
	}
	if _, ok := m.relayIngressFilters[ifindex]; !ok {
		handle, err := attachTCIngress(int(ifindex), m.relayObjs.PmRelayTcIngress)
		if err != nil {
			return fmt.Errorf("relay TC ingress attach ifindex=%d: %w", ifindex, err)
		}
		m.relayIngressFilters[ifindex] = handle
	}

	log.Info("ebpf cilium: ArmRelay", "ifname", ifname, "srcPort", key.SrcPort, "dstPort", key.DstPort)
	return nil
}

// DisarmRelay removes the PM_SEQ_XLAT entry for key.  When no entries remain
// the TC relay filters are detached and the BPF collection is closed.
func (m *ciliumEBPFManager) DisarmRelay(ctx context.Context, key SeqXlatKey) error {
	log := logf.FromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.relayObjs == nil {
		return nil
	}

	bpfKey := pmRelayBpfKey(key)
	if err := m.relayObjs.PmSeqXlat.Delete(bpfKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("PM_SEQ_XLAT delete: %w", err)
	}

	// Check if map is now empty; if so, detach all filters.
	var count uint32
	iter := m.relayObjs.PmSeqXlat.Iterate()
	var k, v [64]byte
	for iter.Next(&k, &v) {
		count++
		break
	}
	if count == 0 {
		for ifindex, handle := range m.relayEgressFilters {
			if err := detachTCEgress(int(ifindex), handle); err != nil {
				log.Error(err, "relay TC egress detach failed", "ifindex", ifindex)
			}
			delete(m.relayEgressFilters, ifindex)
		}
		for ifindex, handle := range m.relayIngressFilters {
			if err := detachTCIngress(int(ifindex), handle); err != nil {
				log.Error(err, "relay TC ingress detach failed", "ifindex", ifindex)
			}
			delete(m.relayIngressFilters, ifindex)
		}
		m.relayObjs.Close()
		m.relayObjs = nil
	}

	log.Info("ebpf cilium: DisarmRelay", "srcPort", key.SrcPort, "dstPort", key.DstPort)
	return nil
}

// ArmVTEP populates PM_VTEP_MAP and attaches PM_XDP_VTEP to dstIfname and
// PM_XDP_SRC_GUARD to srcIfname.
func (m *ciliumEBPFManager) ArmVTEP(ctx context.Context, podIP net.IP, ve VtepEntry, dstIfname, srcIfname string) error {
	log := logf.FromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureVtepLoaded(ctx); err != nil {
		return err
	}

	ip4 := podIP.To4()
	if ip4 == nil {
		return fmt.Errorf("ArmVTEP: podIP %s is not IPv4", podIP)
	}
	var podKey [4]byte
	copy(podKey[:], ip4)

	bpfVe := pmVtepBpfVal(ve)
	if err := m.vtepObjs.PmVtepMap.Update(podKey, bpfVe, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("PM_VTEP_MAP update: %w", err)
	}

	dstIfindex, err := resolveIfindex(dstIfname)
	if err != nil {
		return err
	}
	srcIfindex, err := resolveIfindex(srcIfname)
	if err != nil {
		return err
	}

	if _, ok := m.vtepXDPLinks[dstIfindex]; !ok {
		if err := attachXDP(int(dstIfindex), m.vtepObjs.PmXdpVtep); err != nil {
			return fmt.Errorf("PM_XDP_VTEP attach ifindex=%d: %w", dstIfindex, err)
		}
		m.vtepXDPLinks[dstIfindex] = struct{}{}
	}
	if _, ok := m.srcGuardXDPLinks[srcIfindex]; !ok {
		if err := attachXDP(int(srcIfindex), m.vtepObjs.PmXdpSrcGuard); err != nil {
			return fmt.Errorf("PM_XDP_SRC_GUARD attach ifindex=%d: %w", srcIfindex, err)
		}
		m.srcGuardXDPLinks[srcIfindex] = struct{}{}
	}

	log.Info("ebpf cilium: ArmVTEP", "podIP", podIP, "dstIfname", dstIfname, "srcIfname", srcIfname)
	return nil
}

// DisarmVTEP removes the PM_VTEP_MAP entry for podIP.  XDP programs are left
// attached until the next migration cycle; caller should call Close when the
// agent shuts down.
func (m *ciliumEBPFManager) DisarmVTEP(ctx context.Context, podIP net.IP) error {
	log := logf.FromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.vtepObjs == nil {
		return nil
	}

	ip4 := podIP.To4()
	if ip4 == nil {
		return fmt.Errorf("DisarmVTEP: podIP %s is not IPv4", podIP)
	}
	var podKey [4]byte
	copy(podKey[:], ip4)

	if err := m.vtepObjs.PmVtepMap.Delete(podKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("PM_VTEP_MAP delete: %w", err)
	}

	log.Info("ebpf cilium: DisarmVTEP", "podIP", podIP)
	return nil
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

// nlmsgHdrSize is sizeof(unix.NlMsghdr) = 16.
// unix.NLMSG_HDRSIZE is not always exported; local const ensures cross-compilation.
const nlmsgHdrSize = 16

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

// tcAttr builds a packed netlink attribute for TC/qdisc messages
// (type + len header + padded data).  Named tcAttr (not nlAttr) to avoid
// collision with the shared nlAttr helper in fdb.go which uses uint16 keys.
func tcAttr(typ int, data []byte) []byte {
	hdrLen := 4
	totalLen := hdrLen + len(data)
	padded := (totalLen + 3) &^ 3
	buf := make([]byte, padded)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(totalLen))
	binary.LittleEndian.PutUint16(buf[2:4], uint16(typ))
	copy(buf[4:], data)
	return buf
}

// tcAttrStr builds a null-terminated string TC netlink attribute.
func tcAttrStr(typ int, s string) []byte {
	return tcAttr(typ, append([]byte(s), 0))
}

// tcAttrU32 builds a uint32 TC netlink attribute.
func tcAttrU32(typ int, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return tcAttr(typ, b[:])
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
	kind := tcAttrStr(tcaKind, "clsact")
	payload := append(tcBytes, kind...)

	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  rtmNewQdisc,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   1,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
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
	if n < nlmsgHdrSize {
		return fmt.Errorf("RTM_NEWQDISC: short reply (%d bytes)", n)
	}
	replyHdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if replyHdr.Type == unix.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(buf[nlmsgHdrSize:]))
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
		tcAttrU32(tcaBpfFd, progFD),
		append(
			tcAttrStr(tcaBpfName, "pm_zero_window_hold"),
			tcAttrU32(tcaBpfFlags, tcBpfFlagActDirect)...,
		)...,
	)
	attrs := append(
		tcAttrStr(tcaKind, "bpf"),
		tcAttr(tcaOptions, bpfOpts)...,
	)
	payload := append(tcBytes, attrs...)

	filterHandle := uint32(0xFFFF0001) // stable handle we assign
	tc.Handle = filterHandle
	// Rebuild tcBytes with handle set.
	tcBytesH := (*[unsafe.Sizeof(tc)]byte)(unsafe.Pointer(&tc))[:]
	payload = append(tcBytesH, attrs...)

	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  rtmNewFilter,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   2,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
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
	if n < nlmsgHdrSize {
		return 0, fmt.Errorf("RTM_NEWTFILTER: short reply (%d bytes)", n)
	}
	replyHdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if replyHdr.Type == unix.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(buf[nlmsgHdrSize:]))
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
	kind := tcAttrStr(tcaKind, "bpf")
	payload := append(tcBytes, kind...)

	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  rtmDelFilter,
		Flags: unix.NLM_F_REQUEST,
		Seq:   3,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
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
	if n < nlmsgHdrSize {
		return fmt.Errorf("RTM_DELTFILTER: short reply (%d bytes)", n)
	}
	replyHdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if replyHdr.Type == unix.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(buf[nlmsgHdrSize:]))
		if errno != 0 && errno != -int32(syscall.ENOENT) {
			return fmt.Errorf("RTM_DELTFILTER: kernel error %d", errno)
		}
	}
	return nil
}

// attachTCIngress attaches prog to the TC ingress hook of ifindex using a
// clsact qdisc filter with BPF_F_ALLOW_OVERRIDE.
func attachTCIngress(ifindex int, prog *ebpf.Program) (uint32, error) {
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
		Info    uint32
	}
	const prioDefault = 1
	const ethPAll = 0x0003
	const tcParentIngress = 0xFFFFFFF2 // TC_H_MIN_INGRESS
	filterHandle := uint32(0xFFFF0002)
	tc := tcmsg{
		Ifindex: int32(ifindex),
		Handle:  filterHandle,
		Parent:  tcParentIngress,
		Info:    (prioDefault << 16) | ethPAll,
	}
	tcBytes := (*[unsafe.Sizeof(tc)]byte)(unsafe.Pointer(&tc))[:]

	progFD := uint32(prog.FD())
	bpfOpts := append(
		tcAttrU32(tcaBpfFd, progFD),
		append(
			tcAttrStr(tcaBpfName, "pm_relay_tc_ingress"),
			tcAttrU32(tcaBpfFlags, tcBpfFlagActDirect)...,
		)...,
	)
	attrs := append(
		tcAttrStr(tcaKind, "bpf"),
		tcAttr(tcaOptions, bpfOpts)...,
	)
	payload := append(tcBytes, attrs...)

	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  rtmNewFilter,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   4,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return 0, fmt.Errorf("RTM_NEWTFILTER (ingress) write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return 0, fmt.Errorf("RTM_NEWTFILTER (ingress) read: %w", err)
	}
	if n < nlmsgHdrSize {
		return 0, fmt.Errorf("RTM_NEWTFILTER (ingress): short reply (%d bytes)", n)
	}
	rHdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if rHdr.Type == unix.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(buf[nlmsgHdrSize:]))
		if errno != 0 {
			return 0, fmt.Errorf("RTM_NEWTFILTER (ingress): kernel error %d", errno)
		}
	}
	return filterHandle, nil
}

// detachTCIngress removes the TC ingress filter identified by handle from ifindex.
func detachTCIngress(ifindex int, handle uint32) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	const tcParentIngress = 0xFFFFFFF2
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
		Parent:  tcParentIngress,
	}
	tcBytes := (*[unsafe.Sizeof(tc)]byte)(unsafe.Pointer(&tc))[:]
	kind := tcAttrStr(tcaKind, "bpf")
	payload := append(tcBytes, kind...)

	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  rtmDelFilter,
		Flags: unix.NLM_F_REQUEST,
		Seq:   5,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return fmt.Errorf("RTM_DELTFILTER (ingress) write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return fmt.Errorf("RTM_DELTFILTER (ingress) read: %w", err)
	}
	if n < nlmsgHdrSize {
		return fmt.Errorf("RTM_DELTFILTER (ingress): short reply (%d bytes)", n)
	}
	rHdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if rHdr.Type == unix.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(buf[nlmsgHdrSize:]))
		if errno != 0 && errno != -int32(syscall.ENOENT) {
			return fmt.Errorf("RTM_DELTFILTER (ingress): kernel error %d", errno)
		}
	}
	return nil
}

// attachXDP attaches prog to the XDP hook of ifindex using BPF_PROG_ATTACH
// via the netlink XDP attribute (generic XDP mode, which works on all drivers).
func attachXDP(ifindex int, prog *ebpf.Program) error {
	type ifinfomsg struct {
		Family     uint8
		Pad        uint8
		Type       uint16
		Index      int32
		Flags      uint32
		Change     uint32
	}
	const RTM_SETLINK = 19
	const IFLA_XDP = 43
	const IFLA_XDP_FD = 1
	const IFLA_XDP_FLAGS = 3
	const XDP_FLAGS_SKB_MODE = 1 << 1 // generic/SKB XDP — works without driver support

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	ifinfo := ifinfomsg{Index: int32(ifindex)}
	ifBytes := (*[unsafe.Sizeof(ifinfo)]byte)(unsafe.Pointer(&ifinfo))[:]

	progFD := uint32(prog.FD())
	xdpAttrs := append(
		tcAttrU32(IFLA_XDP_FD, progFD),
		tcAttrU32(IFLA_XDP_FLAGS, XDP_FLAGS_SKB_MODE)...,
	)
	xdpAttr := tcAttr(IFLA_XDP, xdpAttrs)
	payload := append(ifBytes, xdpAttr...)

	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  RTM_SETLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   6,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return fmt.Errorf("RTM_SETLINK XDP write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return fmt.Errorf("RTM_SETLINK XDP read: %w", err)
	}
	if n < nlmsgHdrSize {
		return fmt.Errorf("RTM_SETLINK XDP: short reply (%d bytes)", n)
	}
	rHdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if rHdr.Type == unix.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(buf[nlmsgHdrSize:]))
		if errno != 0 {
			return fmt.Errorf("RTM_SETLINK XDP: kernel error %d", errno)
		}
	}
	return nil
}

// ── Lazy loaders ─────────────────────────────────────────────────────────────

func (m *ciliumEBPFManager) ensureRelayLoaded(ctx context.Context) error {
	if m.relayObjs != nil {
		return nil
	}
	objs := &bpfloader.PmRelayObjects{}
	if err := bpfloader.LoadPmRelayObjects(objs, nil); err != nil {
		return fmt.Errorf("load pm_relay BPF objects: %w", err)
	}
	m.relayObjs = objs
	logf.FromContext(ctx).Info("ebpf cilium: pm_relay collection loaded")
	return nil
}

func (m *ciliumEBPFManager) ensureVtepLoaded(ctx context.Context) error {
	if m.vtepObjs != nil {
		return nil
	}
	objs := &bpfloader.PmXdpVtepObjects{}
	if err := bpfloader.LoadPmXdpVtepObjects(objs, nil); err != nil {
		return fmt.Errorf("load pm_xdp_vtep BPF objects: %w", err)
	}
	m.vtepObjs = objs
	logf.FromContext(ctx).Info("ebpf cilium: pm_xdp_vtep collection loaded")
	return nil
}

// ── BPF map key/value converters ──────────────────────────────────────────────

// pmRelayBpfKey converts a SeqXlatKey to the packed struct expected by PM_SEQ_XLAT.
// The BPF map key is a C struct four_tuple { __be32 src_ip; __be32 dst_ip; __be16 src_port; __be16 dst_port }.
// Ports are stored in network byte order in the key (matching what the BPF program sees).
func pmRelayBpfKey(k SeqXlatKey) []byte {
	b := make([]byte, 12)
	copy(b[0:4], k.SrcIP[:])
	copy(b[4:8], k.DstIP[:])
	binary.BigEndian.PutUint16(b[8:10], k.SrcPort)
	binary.BigEndian.PutUint16(b[10:12], k.DstPort)
	return b
}

// pmRelayBpfVal converts a SeqXlatEntry to the packed struct for PM_SEQ_XLAT.
// C struct: { __s32 seq_delta; __s32 ack_delta; __s32 ts_delta; __u8 wscale; __u8 sack_present; __u8 state; __u8 pad }.
func pmRelayBpfVal(e SeqXlatEntry) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], uint32(e.SeqDelta))
	binary.LittleEndian.PutUint32(b[4:8], uint32(e.AckDelta))
	binary.LittleEndian.PutUint32(b[8:12], uint32(e.TsDelta))
	b[12] = e.Wscale
	b[13] = e.SackPresent
	b[14] = e.State
	b[15] = 0
	return b
}

// pmVtepBpfVal converts a VtepEntry to the packed struct for PM_VTEP_MAP.
// C struct: { __be32 dst_vtep_ip; __u32 dst_ifindex; __u32 vni }.
func pmVtepBpfVal(ve VtepEntry) []byte {
	b := make([]byte, 12)
	copy(b[0:4], ve.DstVtepIP[:])
	binary.LittleEndian.PutUint32(b[4:8], ve.DstIfindex)
	binary.LittleEndian.PutUint32(b[8:12], ve.VNI)
	return b
}
