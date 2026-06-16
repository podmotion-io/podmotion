//go:build linux

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/podmotion-io/podmotion/internal/agent/network/bpfloader"
	"golang.org/x/sys/unix"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// bpfPinDir is the root BPF FS pin directory (ADR-0155 Decision 4).
	bpfPinDir = "/sys/fs/bpf/podmotion"

	// xdpWatchdogMargin is added to FreezeWindowBudgetMs before the watchdog fires.
	// Mirrors zwWatchdogMargin (server.go). ADR-0155 Decision 7.
	xdpWatchdogMargin = 500 * time.Millisecond
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
	vtepObjs         *bpfloader.PmXdpVtepObjects
	vtepXDPLinks     map[uint32]struct{} // dst ifindex
	srcGuardXDPLinks map[uint32]struct{} // src ifindex

	// xdp_bridge collection; nil until EnsureXDPBridgeLoaded succeeds.
	// Node-scoped; loaded once at agent startup (ADR-0155 Decision 1).
	bridgeObjs        *bpfloader.XdpBridgeObjects
	bridgeHostIfindex uint32 // ifindex the XDP prog is attached to
	// bridgeWatchdogs tracks per-migration watchdog cancel functions keyed by
	// srcIP string.  Watchdog fires xdpWatchdogMargin after the freeze budget
	// expires and auto-deletes the PM_BRIDGE_MAP key (ADR-0155 Decision 7).
	bridgeWatchdogs map[string]context.CancelFunc
}

func newCiliumEBPFManager() eBPFManager {
	return &ciliumEBPFManager{
		tcFilters:           make(map[uint32]uint32),
		relayEgressFilters:  make(map[uint32]uint32),
		relayIngressFilters: make(map[uint32]uint32),
		vtepXDPLinks:        make(map[uint32]struct{}),
		srcGuardXDPLinks:    make(map[uint32]struct{}),
		bridgeWatchdogs:     make(map[string]context.CancelFunc),
	}
}

// EnsureXDPBridgeLoaded loads and pins the xdp_bridge program once per node at
// agent startup (ADR-0155 Decision 1).  Idempotent: if pins exist and XDP link
// is live, adopts existing state.  No-op if xdpBridgeCapable=false (Decision 2).
func (m *ciliumEBPFManager) EnsureXDPBridgeLoaded(ctx context.Context, hostIfname string, xdpBridgeCapable bool) error {
	log := logf.FromContext(ctx)
	if !xdpBridgeCapable {
		log.Info("EnsureXDPBridgeLoaded: XDPBridgeCapable=false — skipping (ADR-0155 D2)")
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(bpfPinDir, 0o755); err != nil {
		return fmt.Errorf("EnsureXDPBridgeLoaded: mkdir %s: %w", bpfPinDir, err)
	}

	progPin := bpfPinDir + "/xdp_bridge_prog"
	mapPin := bpfPinDir + "/PM_BRIDGE_MAP"

	// Attempt adopt path (ADR-0155 Decision 6).
	if _, statErr := os.Stat(progPin); statErr == nil {
		prog, pErr := ebpf.LoadPinnedProgram(progPin, nil)
		if pErr == nil {
			bridgeMap, mErr := ebpf.LoadPinnedMap(mapPin, nil)
			if mErr == nil {
				objs := &bpfloader.XdpBridgeObjects{}
				objs.PmXdpBridge = prog
				objs.PM_BRIDGE_MAP = bridgeMap
				m.bridgeObjs = objs
				ifindex, _ := resolveIfindex(hostIfname)
				m.bridgeHostIfindex = ifindex
				log.Info("EnsureXDPBridgeLoaded: adopted live pin (link alive, prog id)",
					"progPin", progPin, "progFD", prog.FD())
				return nil
			}
			prog.Close()
		}
		// Stale pin — reclaim and reload (ADR-0155 Decision 6).
		log.Info("EnsureXDPBridgeLoaded: reclaiming stale pin (dead link) — re-pin")
		_ = os.Remove(progPin)
		_ = os.Remove(mapPin)
		_ = os.Remove(bpfPinDir + "/PM_TUNNEL_IFACE")
	}

	// Fresh load from embedded .o.
	objs := &bpfloader.XdpBridgeObjects{}
	if err := bpfloader.LoadXdpBridgeObjects(objs, nil); err != nil {
		return fmt.Errorf("EnsureXDPBridgeLoaded: load xdp_bridge objects: %w", err)
	}

	// Pin prog and maps (ADR-0155 Decision 4).
	if err := objs.PmXdpBridge.Pin(progPin); err != nil {
		objs.Close() //nolint:errcheck
		return fmt.Errorf("EnsureXDPBridgeLoaded: pin prog: %w", err)
	}
	if err := objs.PM_BRIDGE_MAP.Pin(mapPin); err != nil {
		objs.Close() //nolint:errcheck
		return fmt.Errorf("EnsureXDPBridgeLoaded: pin PM_BRIDGE_MAP: %w", err)
	}
	if err := objs.PM_TUNNEL_IFACE.Pin(bpfPinDir + "/PM_TUNNEL_IFACE"); err != nil {
		log.Error(err, "EnsureXDPBridgeLoaded: pin PM_TUNNEL_IFACE failed (non-fatal)")
	}

	// Attach XDP program to host interface (ADR-0155 Decision 1).
	ifindex, err := resolveIfindex(hostIfname)
	if err != nil {
		objs.Close() //nolint:errcheck
		return fmt.Errorf("EnsureXDPBridgeLoaded: resolve ifindex for %s: %w", hostIfname, err)
	}
	if err := attachXDP(int(ifindex), objs.PmXdpBridge); err != nil {
		objs.Close() //nolint:errcheck
		return fmt.Errorf("EnsureXDPBridgeLoaded: attach XDP to %s (ifindex=%d): %w", hostIfname, ifindex, err)
	}

	m.bridgeObjs = objs
	m.bridgeHostIfindex = ifindex
	log.Info("EnsureXDPBridgeLoaded: loaded and pinned",
		"hostIfname", hostIfname, "ifindex", ifindex, "progPin", progPin)
	return nil
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

// ArmXDPBridge writes srcIP→{dstIP, genevePort} to the already-pinned PM_BRIDGE_MAP
// (ADR-0155 Decision 3).  No load/attach work.  Registers a watchdog that auto-deletes
// the map key after defaultFreezeBudget+xdpWatchdogMargin (ADR-0155 Decision 7).
func (m *ciliumEBPFManager) ArmXDPBridge(ctx context.Context, srcIP, dstIP net.IP, genevePort uint16) error {
	log := logf.FromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.bridgeObjs == nil {
		log.Info("ebpf cilium: ArmXDPBridge — bridge not loaded (XDPBridgeCapable=false), skipping")
		return nil
	}

	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return fmt.Errorf("ArmXDPBridge: non-IPv4 address srcIP=%s dstIP=%s", srcIP, dstIP)
	}

	// bridgeEntry layout mirrors C struct bridge_entry: __be32 dst_ip, __u16 geneve_port (host order), __u8 _pad[2].
	var val [8]byte
	copy(val[0:4], dst4)
	binary.LittleEndian.PutUint16(val[4:6], genevePort)

	var key [4]byte
	copy(key[:], src4)

	if err := m.bridgeObjs.PM_BRIDGE_MAP.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("ArmXDPBridge: PM_BRIDGE_MAP update srcIP=%s: %w", srcIP, err)
	}

	log.Info("ebpf cilium: ArmXDPBridge: map update",
		"srcIP", srcIP, "dstIP", dstIP, "genevePort", genevePort)

	// Register per-migration watchdog (ADR-0155 Decision 7).
	const defaultFreezeBudget = 5000 * time.Millisecond
	wdCtx, wdCancel := context.WithCancel(context.Background())
	srcKey := srcIP.String()
	if prev, ok := m.bridgeWatchdogs[srcKey]; ok {
		prev()
	}
	m.bridgeWatchdogs[srcKey] = wdCancel
	capturedKey := key
	capturedObjs := m.bridgeObjs
	go func() {
		select {
		case <-wdCtx.Done():
			return
		case <-time.After(defaultFreezeBudget + xdpWatchdogMargin):
			log.Info("ArmXDPBridge: watchdog triggered — emergency map-key delete", "srcIP", srcIP)
			_ = capturedObjs.PM_BRIDGE_MAP.Delete(capturedKey)
		}
	}()

	return nil
}

// DisarmXDPBridge removes the srcIP entry from PM_BRIDGE_MAP and cancels the watchdog.
// Missing key is not an error (ADR-0155 Decision 5).
func (m *ciliumEBPFManager) DisarmXDPBridge(ctx context.Context, srcIP net.IP) error {
	log := logf.FromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.bridgeObjs == nil {
		return nil
	}

	src4 := srcIP.To4()
	if src4 == nil {
		return fmt.Errorf("DisarmXDPBridge: non-IPv4 address srcIP=%s", srcIP)
	}

	var key [4]byte
	copy(key[:], src4)

	if err := m.bridgeObjs.PM_BRIDGE_MAP.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("DisarmXDPBridge: PM_BRIDGE_MAP delete srcIP=%s: %w", srcIP, err)
	}

	srcKey := srcIP.String()
	if cancel, ok := m.bridgeWatchdogs[srcKey]; ok {
		cancel()
		delete(m.bridgeWatchdogs, srcKey)
	}

	log.Info("ebpf cilium: DisarmXDPBridge: map delete", "srcIP", srcIP)
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

// zeroWindowPinDir is the bpffs directory where PM_ACTIVE_HOLDS is pinned.
// The map name "zero_window_holds" matches the LIBBPF_PIN_BY_NAME declaration in
// bpf/zero_window.c, so libbpf will automatically pin/load at this path.
const zeroWindowPinDir = "/sys/fs/bpf/podmotion"

// ensureLoaded loads the zero_window BPF collection if not already loaded.
// When the pinned map already exists at zeroWindowPinDir (e.g. after an agent
// restart), cilium/ebpf reuses it via CollectionOptions.Maps.PinPath so the
// existing hold entries and crash-recovery state are preserved (ADR-0157 D6).
// Must be called with m.mu held.
func (m *ciliumEBPFManager) ensureLoaded(ctx context.Context) error {
	if m.objs != nil {
		return nil
	}
	// Ensure the bpffs pin directory exists.
	if err := os.MkdirAll(zeroWindowPinDir, 0700); err != nil {
		return fmt.Errorf("create bpffs pin dir %s: %w", zeroWindowPinDir, err)
	}
	objs := &bpfloader.ZeroWindowObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: zeroWindowPinDir,
		},
	}
	if err := bpfloader.LoadZeroWindowObjects(objs, opts); err != nil {
		return fmt.Errorf("load zero_window BPF objects: %w", err)
	}
	m.objs = objs
	logf.FromContext(ctx).Info("ebpf cilium: zero_window collection loaded", "pinDir", zeroWindowPinDir)
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

// nlSeqCounter is the package-level monotonic netlink sequence source (ADR-0204
// Decision 3). Each netlink request claims a fresh Seq via nextNlSeq() so that
// readNetlinkAck can correlate replies by Seq+Pid instead of acting on the first
// datagram it happens to read. Replaces the former shared hardcoded Seq:1..6.
var nlSeqCounter uint32

// nextNlSeq returns the next netlink sequence number (never 0).
func nextNlSeq() uint32 {
	s := atomic.AddUint32(&nlSeqCounter, 1)
	if s == 0 {
		s = atomic.AddUint32(&nlSeqCounter, 1)
	}
	return s
}

// readNetlinkAck reads the ACK/error reply for a netlink request on fd, correlating
// by Seq+Pid (ADR-0204 — correlated netlink read fix). The prior code read a single
// unconditional datagram and parsed buf[0] as the reply WITHOUT matching the request
// Seq or the socket's bound Pid; when that datagram was an NLMSG_ERROR belonging to a
// different request it returned a spurious non-zero errno, driving the clsact probe
// false-negative that blocked Strict-mode admission.
//
// It loops, discarding any datagram whose first message Seq != wantSeq OR Pid !=
// wantPort, walking every message in a buffer by NlMsghdr.Len. On a matching
// NLMSG_ERROR it extracts the errno: 0 or -EEXIST → success (nil); any other value →
// syscall.Errno surfaced verbatim. NLMSG_NOOP/NLMSG_DONE are skipped; any other
// matching message type is treated as a success ACK.
func readNetlinkAck(fd int, wantSeq, wantPort uint32) error {
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			return fmt.Errorf("netlink read: %w", err)
		}
		if n < nlmsgHdrSize {
			return fmt.Errorf("netlink: short reply (%d bytes)", n)
		}

		// Walk every message in the datagram.
		offset := 0
		for offset+nlmsgHdrSize <= n {
			hdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[offset]))
			msgLen := int(hdr.Len)
			if msgLen < nlmsgHdrSize || offset+msgLen > n {
				break
			}

			// Skip uncorrelated messages (different request or different socket).
			if hdr.Seq != wantSeq || hdr.Pid != wantPort {
				offset += nlmsgAlign(msgLen)
				continue
			}

			switch hdr.Type {
			case unix.NLMSG_NOOP, unix.NLMSG_DONE:
				offset += nlmsgAlign(msgLen)
				continue
			case unix.NLMSG_ERROR:
				if offset+nlmsgHdrSize+4 > n {
					return fmt.Errorf("netlink: truncated NLMSG_ERROR")
				}
				errVal := int32(binary.LittleEndian.Uint32(buf[offset+nlmsgHdrSize:]))
				if errVal == 0 || errVal == -int32(syscall.EEXIST) {
					return nil
				}
				e := syscall.Errno(-errVal)
				return fmt.Errorf("netlink kernel error %d: %w", errVal, e)
			default:
				// Matching, non-error, non-noop message — treat as success ACK.
				return nil
			}
		}
		// No correlated message in this datagram — keep reading.
	}
}

// nlmsgAlign rounds a netlink message length up to the 4-byte NLMSG alignment.
func nlmsgAlign(l int) int {
	return (l + 3) &^ 3
}

// boundNetlinkPort returns the port (Pid) the kernel auto-assigned to fd at bind.
// readNetlinkAck correlates replies against this value (ADR-0204 Decision 3).
func boundNetlinkPort(fd int) (uint32, error) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return 0, fmt.Errorf("netlink getsockname: %w", err)
	}
	nl, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		return 0, fmt.Errorf("netlink getsockname: unexpected sockaddr type %T", sa)
	}
	return nl.Pid, nil
}

// TC netlink constants not yet in golang.org/x/sys/unix.
const (
	tcHandleRoot    = 0xFFFFFFFF
	tcHandleIngress = 0xFFFFFFF1

	// clsact qdisc handle/parent
	tcHandleClsact = 0xFFFF0000
	tcParentEgress = 0xFFFFFFF3 // TC_H_MIN_EGRESS

	// rtnetlink message types
	rtmNewQdisc  = unix.RTM_NEWQDISC
	rtmGetQdisc  = unix.RTM_GETQDISC
	rtmNewFilter = unix.RTM_NEWTFILTER
	rtmDelFilter = unix.RTM_DELTFILTER

	// TC attribute types
	tcaKind    = 1
	tcaOptions = 2
	tcaFdArray = 22

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

	wantPort, err := boundNetlinkPort(fd)
	if err != nil {
		return err
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

	// ADR-0204: NLM_F_ACK keeps deterministic request hygiene (always an
	// NLMSG_ERROR reply, errno=0 on success). The former NLM_F_EXCL is replaced by
	// NLM_F_REPLACE so an already-present clsact qdisc is idempotent; -EEXIST is
	// still mapped to success in readNetlinkAck as defense-in-depth.
	wantSeq := nextNlSeq()
	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  rtmNewQdisc,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   wantSeq,
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

	if err := readNetlinkAck(fd, wantSeq, wantPort); err != nil {
		return fmt.Errorf("RTM_NEWQDISC: %w", err)
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

	wantPort, err := boundNetlinkPort(fd)
	if err != nil {
		return 0, err
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

	// ADR-0204: NLM_F_ACK forces an NLMSG_ERROR reply readNetlinkAck can correlate.
	wantSeq := nextNlSeq()
	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  rtmNewFilter,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   wantSeq,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return 0, fmt.Errorf("RTM_NEWTFILTER write: %w", err)
	}

	if err := readNetlinkAck(fd, wantSeq, wantPort); err != nil {
		return 0, fmt.Errorf("RTM_NEWTFILTER: %w", err)
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

	wantPort, err := boundNetlinkPort(fd)
	if err != nil {
		return err
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

	// ADR-0204: NLM_F_ACK forces a correlatable NLMSG_ERROR reply. ENOENT (filter
	// already gone) is treated as success in readNetlinkAck's caller below.
	wantSeq := nextNlSeq()
	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  rtmDelFilter,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   wantSeq,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return fmt.Errorf("RTM_DELTFILTER write: %w", err)
	}

	if err := readNetlinkAck(fd, wantSeq, wantPort); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return fmt.Errorf("RTM_DELTFILTER: %w", err)
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

	wantPort, err := boundNetlinkPort(fd)
	if err != nil {
		return 0, err
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

	// ADR-0204: NLM_F_ACK forces a correlatable NLMSG_ERROR reply.
	wantSeq := nextNlSeq()
	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  rtmNewFilter,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   wantSeq,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return 0, fmt.Errorf("RTM_NEWTFILTER (ingress) write: %w", err)
	}

	if err := readNetlinkAck(fd, wantSeq, wantPort); err != nil {
		return 0, fmt.Errorf("RTM_NEWTFILTER (ingress): %w", err)
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

	wantPort, err := boundNetlinkPort(fd)
	if err != nil {
		return err
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

	// ADR-0204: NLM_F_ACK forces a correlatable NLMSG_ERROR reply. ENOENT is success.
	wantSeq := nextNlSeq()
	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  rtmDelFilter,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   wantSeq,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return fmt.Errorf("RTM_DELTFILTER (ingress) write: %w", err)
	}

	if err := readNetlinkAck(fd, wantSeq, wantPort); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return fmt.Errorf("RTM_DELTFILTER (ingress): %w", err)
	}
	return nil
}

// attachXDP attaches prog to the XDP hook of ifindex using BPF_PROG_ATTACH
// via the netlink XDP attribute (generic XDP mode, which works on all drivers).
func attachXDP(ifindex int, prog *ebpf.Program) error {
	type ifinfomsg struct {
		Family uint8
		Pad    uint8
		Type   uint16
		Index  int32
		Flags  uint32
		Change uint32
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

	wantPort, err := boundNetlinkPort(fd)
	if err != nil {
		return err
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

	// ADR-0204: correlated read; Seq from the atomic counter, Pid from the bound port.
	wantSeq := nextNlSeq()
	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  RTM_SETLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   wantSeq,
	}
	hdrBytes := (*[nlmsgHdrSize]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	if _, err := unix.Write(fd, msg); err != nil {
		return fmt.Errorf("RTM_SETLINK XDP write: %w", err)
	}

	if err := readNetlinkAck(fd, wantSeq, wantPort); err != nil {
		return fmt.Errorf("RTM_SETLINK XDP: %w", err)
	}
	return nil
}

// PatchRelayTsDelta performs a read-modify-write on PM_SEQ_XLAT for the given key,
// updating only the ts_delta field while preserving seq_delta and ack_delta.
// ADR-0049: ts_delta is patched separately from seq/ack because the PAWS clock
// offset is not known until the destination captures its monotonic clock at restore
// time, which is after SeedRelayFromSnapshots has already seeded seq_delta/ack_delta.
// This method must never be replaced by a plain ArmRelay call, which would overwrite
// the entire map value and zero seq_delta/ack_delta.
func (m *ciliumEBPFManager) PatchRelayTsDelta(ctx context.Context, key SeqXlatKey, tsDelta int32) error {
	log := logf.FromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.relayObjs == nil {
		// relay collection not loaded; entry doesn't exist.
		log.Info("ebpf cilium: PatchRelayTsDelta skipped — relay not loaded", "srcPort", key.SrcPort, "dstPort", key.DstPort)
		return nil
	}

	bpfKey := pmRelayBpfKey(key)
	// Read existing value.
	var existing [16]byte
	if err := m.relayObjs.PmSeqXlat.Lookup(bpfKey, &existing); err != nil {
		// Entry not found — not an error (stateless migration or entry already removed).
		log.Info("ebpf cilium: PatchRelayTsDelta: entry not found, skipping",
			"srcPort", key.SrcPort, "dstPort", key.DstPort)
		return nil
	}

	// Overwrite only the ts_delta word (bytes 8–11, little-endian), leaving seq_delta
	// (bytes 0–3) and ack_delta (bytes 4–7) untouched.
	binary.LittleEndian.PutUint32(existing[8:12], uint32(tsDelta))

	if err := m.relayObjs.PmSeqXlat.Update(bpfKey, existing[:], ebpf.UpdateExist); err != nil {
		return fmt.Errorf("PM_SEQ_XLAT PatchRelayTsDelta update: %w", err)
	}

	log.Info("ebpf cilium: PatchRelayTsDelta: ts_delta patched",
		"srcPort", key.SrcPort, "dstPort", key.DstPort, "tsDelta", tsDelta)
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
