// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

// This file implements the three ADR-0158 KindnetProvider operations:
//   InjectHostRoute  — /32 link-scoped host route via SetPodIPHostRoute (reuses wgroute.go)
//   RemoveHostRoute  — /32 removal via DeletePodIPHostRoute (reuses wgroute.go)
//   InjectGratuitousARP — AF_PACKET raw socket gARP frame (ADR-0158 Decision 2)
//
// Interface selection: BridgeIfname is resolved by the caller (provider runtime discovery,
// ADR-0154 Decision 3). Neither "cni0" nor any other literal appears here (ADR-0158 Decision 5).

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

// InjectHostRoute installs a /32 link-scoped host route for podIP on the
// runtime-discovered BridgeIfname, reusing SetPodIPHostRoute (wgroute.go:565,
// ADR-0158 Decision 3). The interface name must come from provider runtime
// discovery — no "cni0" literal (ADR-0158 Decision 5).
func (k *KindnetProvider) InjectHostRoute(ctx context.Context, podIP, _ string) error {
	log := logf.FromContext(ctx)
	if k.BridgeIfname == "" {
		return fmt.Errorf("KindnetProvider.InjectHostRoute: BridgeIfname is empty — provider did not resolve a bridge interface")
	}
	ip := net.ParseIP(podIP)
	if ip == nil {
		return fmt.Errorf("KindnetProvider.InjectHostRoute: podIP %q is not a valid IP", podIP)
	}
	if err := SetPodIPHostRoute(ctx, k.BridgeIfname, ip); err != nil {
		return fmt.Errorf("KindnetProvider.InjectHostRoute: %w", err)
	}
	log.Info("KindnetProvider: /32 host route injected (ADR-0158 D3)", "podIP", podIP, "iface", k.BridgeIfname)
	return nil
}

// RemoveHostRoute removes the /32 host route for podIP installed by InjectHostRoute,
// reusing DeletePodIPHostRoute (wgroute.go:588). Idempotent — ENOENT is silently ignored.
func (k *KindnetProvider) RemoveHostRoute(ctx context.Context, podIP string) error {
	log := logf.FromContext(ctx)
	if k.BridgeIfname == "" {
		// If no interface was ever set, the route was never installed — no-op.
		return nil
	}
	ip := net.ParseIP(podIP)
	if ip == nil {
		return fmt.Errorf("KindnetProvider.RemoveHostRoute: podIP %q is not a valid IP", podIP)
	}
	if err := DeletePodIPHostRoute(ctx, k.BridgeIfname, ip); err != nil {
		return fmt.Errorf("KindnetProvider.RemoveHostRoute: %w", err)
	}
	log.Info("KindnetProvider: /32 host route removed (ADR-0158 D3)", "podIP", podIP, "iface", k.BridgeIfname)
	return nil
}

// InjectGratuitousARP emits a gratuitous ARP announcement via an AF_PACKET raw socket
// bound to ifaceName (ADR-0158 Decision 2). The frame is an ARP request (opcode 1) with:
//
//	SHA = dest-node interface MAC (resolved via net.InterfaceByName)
//	SPA = migrated-pod OLD IP
//	THA = ff:ff:ff:ff:ff:ff (broadcast)
//	TPA = migrated-pod OLD IP (SPA == TPA → gratuitous)
//	Ethernet dst = ff:ff:ff:ff:ff:ff
//	Ethernet src = dest-node interface MAC
//
// Setting SPA == TPA with opcode 1 is the canonical gratuitous-ARP announcement:
// it causes every neighbor to update its ARP cache mapping OLD IP → dest-node MAC.
func (k *KindnetProvider) InjectGratuitousARP(ctx context.Context, podIP, ifaceName string) error {
	return SendGratuitousARP(ctx, podIP, ifaceName)
}

// SendGratuitousARP is the privileged agent-path implementation of gratuitous ARP
// (ADR-0158 Decision 1 + Decision 2). It is called from KindnetProvider.InjectGratuitousARP
// and may be called directly by FlannelProvider and other providers.
//
// The frame is emitted via AF_PACKET raw socket; the caller must have CAP_NET_RAW.
func SendGratuitousARP(ctx context.Context, podIP, ifaceName string) error {
	log := logf.FromContext(ctx)

	// Resolve the interface.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("SendGratuitousARP: interface %q not found: %w", ifaceName, err)
	}
	if len(iface.HardwareAddr) < 6 {
		return fmt.Errorf("SendGratuitousARP: interface %q has no valid MAC (%v)", ifaceName, iface.HardwareAddr)
	}

	ip := net.ParseIP(podIP)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("SendGratuitousARP: podIP %q is not a valid IPv4 address", podIP)
	}
	ipv4 := ip.To4()

	srcMAC := iface.HardwareAddr
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Build the 42-byte Ethernet + ARP frame:
	//   14 bytes Ethernet header + 28 bytes ARP payload
	frame := make([]byte, 42)

	// Ethernet header (14 bytes)
	//   [0:6]   dst MAC = broadcast
	//   [6:12]  src MAC = dest-node iface MAC
	//   [12:14] EtherType = 0x0806 (ARP)
	copy(frame[0:6], broadcastMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)

	// ARP payload (28 bytes, offset 14)
	//   [14:16] HTYPE = 1 (Ethernet)
	//   [16:18] PTYPE = 0x0800 (IPv4)
	//   [18]    HLEN = 6
	//   [19]    PLEN = 4
	//   [20:22] Opcode = 1 (ARP request)
	//   [22:28] SHA = src MAC (dest-node iface MAC)
	//   [28:32] SPA = pod OLD IP
	//   [32:38] THA = ff:ff:ff:ff:ff:ff
	//   [38:42] TPA = pod OLD IP (= SPA → gratuitous)
	binary.BigEndian.PutUint16(frame[14:16], 1)    // HTYPE Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // PTYPE IPv4
	frame[18] = 6                                   // HLEN
	frame[19] = 4                                   // PLEN
	binary.BigEndian.PutUint16(frame[20:22], 1)    // Opcode = request
	copy(frame[22:28], srcMAC)                     // SHA
	copy(frame[28:32], ipv4)                       // SPA
	copy(frame[32:38], broadcastMAC)               // THA = broadcast
	copy(frame[38:42], ipv4)                       // TPA = SPA (gratuitous)

	// Open AF_PACKET raw socket.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return fmt.Errorf("SendGratuitousARP: AF_PACKET socket: %w", err)
	}
	defer unix.Close(fd)

	// Bind to the specific interface.
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  iface.Index,
		Hatype:   unix.ARPHRD_ETHER,
	}
	if err := unix.Bind(fd, addr); err != nil {
		return fmt.Errorf("SendGratuitousARP: bind to %q (ifindex=%d): %w", ifaceName, iface.Index, err)
	}

	// Send the frame.
	to := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  iface.Index,
		Halen:    6,
	}
	copy(to.Addr[:6], broadcastMAC)
	if err := unix.Sendto(fd, frame, 0, to); err != nil {
		return fmt.Errorf("SendGratuitousARP: sendto %q: %w", ifaceName, err)
	}

	log.Info("KindnetProvider: gratuitous ARP emitted (ADR-0158 D2)",
		"podIP", podIP, "iface", ifaceName, "ifaceMAC", srcMAC.String())
	return nil
}

// htons converts a uint16 from host byte order to network byte order.
func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

// WireDestinationVeth wires hostVeth to the substrate-appropriate upstream (ADR-0167 C1).
//
// Bridge path (Flannel/Calico): enslaveVethToBridge(hostVeth, bridgeName) — unchanged behavior.
// Host-route path (kindnet/ptp): detected by EOPNOTSUPP from the enslave attempt.
//
// On EOPNOTSUPP the provider:
//  1. Validates hostIface: ARPHRD_ETHER + IFF_UP + absence of IFLA_LINKINFO kind=bridge (C3 guard).
//  2. If valid: injects /32 host route for podIP via hostVeth via SetPodIPHostRoute (C1).
//  3. Emits structured Info log naming detected substrate + chosen wiring (C4).
//  4. If kind=bridge found despite EOPNOTSUPP: returns fatal error (C3 degraded-bridge guard).
//
// The route MUST be added AFTER bringUpInterface(hostVeth) — the caller (PrepareDestinationNetns)
// is responsible for calling bringUpInterface BEFORE calling this method.
//
// All non-EOPNOTSUPP errors from the enslave attempt are propagated unchanged (C1 invariant).
func (k *KindnetProvider) WireDestinationVeth(ctx context.Context, hostVeth, bridgeName, podIP, migrationName string) error {
	log := logf.FromContext(ctx)

	err := enslaveVethToBridge(hostVeth, bridgeName)
	if err == nil {
		// Bridge-enslave succeeded — bridge-mode substrate, done.
		return nil
	}

	// C1: unwrap to raw errno and compare exactly to EOPNOTSUPP.
	// Any other errno remains fatal and is returned unchanged.
	rawErrno := unwrapErrno(err)
	if rawErrno != syscall.EOPNOTSUPP {
		return fmt.Errorf("enslaveVethToBridge(%s→%s): %w", hostVeth, bridgeName, err)
	}

	// EOPNOTSUPP received — the target is not a bridge device.
	// C3: validate the resolved host interface before committing to host-route path.
	iface, lookErr := net.InterfaceByName(bridgeName)
	if lookErr != nil {
		// C4: log on guard trip.
		log.Info("WireDestinationVeth: C3 guard — cannot validate interface type; treating as fatal",
			"substrate", "unknown",
			"wiring", "none",
			"iface", bridgeName,
			"errno", "EOPNOTSUPP",
			"migration", migrationName,
			"err", lookErr,
		)
		return fmt.Errorf("WireDestinationVeth: EOPNOTSUPP from enslave + interface lookup failed: %w", lookErr)
	}

	// Check ARPHRD_ETHER.
	if iface.Flags&net.FlagLoopback != 0 {
		log.Info("WireDestinationVeth: C3 guard — loopback interface, not Ethernet; fatal",
			"substrate", "unknown", "wiring", "none", "iface", bridgeName,
			"errno", "EOPNOTSUPP", "migration", migrationName)
		return fmt.Errorf("WireDestinationVeth: EOPNOTSUPP from enslave but interface %q is loopback, not ARPHRD_ETHER", bridgeName)
	}
	// IFF_UP check.
	if iface.Flags&net.FlagUp == 0 {
		log.Info("WireDestinationVeth: C3 guard — interface is not IFF_UP; fatal",
			"substrate", "unknown", "wiring", "none", "iface", bridgeName,
			"errno", "EOPNOTSUPP", "migration", migrationName)
		return fmt.Errorf("WireDestinationVeth: EOPNOTSUPP from enslave but interface %q is not IFF_UP", bridgeName)
	}
	// C3: absence of IFLA_LINKINFO kind=bridge — check RTM_GETLINK link-info.
	isBridge, bridgeCheckErr := isLinkKindBridge(bridgeName)
	if bridgeCheckErr != nil {
		// Cannot determine — treat conservatively as fatal to avoid misclassification.
		log.Info("WireDestinationVeth: C3 guard — cannot determine link kind; treating as fatal",
			"substrate", "unknown", "wiring", "none", "iface", bridgeName,
			"errno", "EOPNOTSUPP", "migration", migrationName, "err", bridgeCheckErr)
		return fmt.Errorf("WireDestinationVeth: EOPNOTSUPP from enslave + cannot determine link kind for %q: %w", bridgeName, bridgeCheckErr)
	}
	if isBridge {
		// C3 guard trip: EOPNOTSUPP + kind=bridge → degraded bridge, not ptp/host-local. Fatal.
		// C4: log the guard trip.
		log.Info("WireDestinationVeth: C3 guard — EOPNOTSUPP from a device with IFLA_LINKINFO kind=bridge (degraded bridge); substrate=bridge wiring=none (fatal)",
			"substrate", "bridge/degraded",
			"wiring", "none",
			"iface", bridgeName,
			"errno", "EOPNOTSUPP",
			"migration", migrationName,
		)
		return fmt.Errorf("WireDestinationVeth: EOPNOTSUPP from enslaving %s→%s but %s reports IFLA_LINKINFO kind=bridge — degraded bridge, not ptp/host-local: %w",
			hostVeth, bridgeName, bridgeName, err)
	}

	// C3 passed: ARPHRD_ETHER + IFF_UP + no kind=bridge → ptp/host-local substrate confirmed.
	// C4: structured Info log naming detected substrate + chosen wiring path.
	log.Info("WireDestinationVeth: EOPNOTSUPP — ptp/host-local substrate detected; using host-route wiring (ADR-0167)",
		"substrate", "kindnet/ptp",
		"wiring", "host-route",
		"iface", bridgeName,
		"errno", "EOPNOTSUPP",
		"migration", migrationName,
	)

	// Inject /32 host route for podIP via hostVeth.
	// bringUpInterface(hostVeth) has already been called by PrepareDestinationNetns before
	// this method is invoked, so the device is up.
	podIPParsed := net.ParseIP(podIP)
	if podIPParsed == nil {
		return fmt.Errorf("WireDestinationVeth: invalid podIP %q", podIP)
	}
	if err := SetPodIPHostRoute(ctx, hostVeth, podIPParsed); err != nil {
		return fmt.Errorf("WireDestinationVeth: host-route injection for %s via %s: %w", podIP, hostVeth, err)
	}
	return nil
}

// unwrapErrno extracts the raw syscall.Errno from an error chain, including
// errors wrapped by fmt.Errorf or similar. Returns 0 if no Errno is found.
func unwrapErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if e, ok := err.(syscall.Errno); ok {
		return e
	}
	// Walk the chain manually for wrapped errors.
	type unwrapper interface{ Unwrap() error }
	for {
		u, ok := err.(unwrapper)
		if !ok {
			break
		}
		err = u.Unwrap()
		if e, ok := err.(syscall.Errno); ok {
			errno = e
			return errno
		}
	}
	return 0
}

// isLinkKindBridge queries RTM_GETLINK for ifName and checks whether IFLA_LINKINFO
// reports kind="bridge". Returns (true, nil) if kind=bridge, (false, nil) if not,
// (false, err) if the query fails.
func isLinkKindBridge(ifName string) (bool, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return false, fmt.Errorf("isLinkKindBridge: interface %q not found: %w", ifName, err)
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return false, fmt.Errorf("isLinkKindBridge: netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return false, fmt.Errorf("isLinkKindBridge: netlink bind: %w", err)
	}

	// Build RTM_GETLINK request.
	type ifInfoMsg struct {
		Family uint8
		_      uint8
		Type   uint16
		Index  int32
		Flags  uint32
		Change uint32
	}
	const ifInfoMsgSize = 16
	ifm := ifInfoMsg{Index: int32(iface.Index)}
	ifmBytes := (*[ifInfoMsgSize]byte)(unsafe.Pointer(&ifm))[:]

	nlmsgLen := uint32(unix.SizeofNlMsghdr + ifInfoMsgSize)
	hdr := unix.NlMsghdr{
		Len:   nlmsgLen,
		Type:  unix.RTM_GETLINK,
		Flags: unix.NLM_F_REQUEST,
		Seq:   10,
	}
	hdrBytes := (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, ifmBytes...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return false, fmt.Errorf("isLinkKindBridge: sendto: %w", err)
	}

	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return false, fmt.Errorf("isLinkKindBridge: recvfrom: %w", err)
	}
	buf = buf[:n]

	// Parse netlink messages looking for RTM_NEWLINK with IFLA_LINKINFO/IFLA_INFO_KIND="bridge".
	for len(buf) >= unix.SizeofNlMsghdr {
		nlh := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
		if nlh.Type == unix.NLMSG_ERROR || nlh.Type == unix.NLMSG_DONE {
			break
		}
		if nlh.Type == unix.RTM_NEWLINK && int(nlh.Len) <= len(buf) {
			payload := buf[unix.SizeofNlMsghdr+ifInfoMsgSize : nlh.Len]
			if parseLinkKind(payload) == "bridge" {
				return true, nil
			}
		}
		if nlh.Len < unix.SizeofNlMsghdr {
			break
		}
		buf = buf[nlh.Len:]
	}
	return false, nil
}

// parseLinkKind extracts IFLA_INFO_KIND from the attribute payload of an RTM_NEWLINK message.
func parseLinkKind(attrs []byte) string {
	const (
		IFLA_LINKINFO  = 18
		IFLA_INFO_KIND = 1
	)
	// Walk top-level attributes looking for IFLA_LINKINFO.
	for len(attrs) >= 4 {
		attrLen := binary.LittleEndian.Uint16(attrs[0:2])
		attrType := binary.LittleEndian.Uint16(attrs[2:4])
		if attrLen < 4 || int(attrLen) > len(attrs) {
			break
		}
		if int(attrType)&0x3fff == IFLA_LINKINFO {
			// Walk nested attributes inside IFLA_LINKINFO.
			nested := attrs[4:attrLen]
			for len(nested) >= 4 {
				nLen := binary.LittleEndian.Uint16(nested[0:2])
				nType := binary.LittleEndian.Uint16(nested[2:4])
				if nLen < 4 || int(nLen) > len(nested) {
					break
				}
				if int(nType) == IFLA_INFO_KIND {
					kind := string(nested[4:nLen])
					// Strip null terminator if present.
					for len(kind) > 0 && kind[len(kind)-1] == 0 {
						kind = kind[:len(kind)-1]
					}
					return kind
				}
				// Align to 4 bytes.
				aligned := (int(nLen) + 3) &^ 3
				if aligned > len(nested) {
					break
				}
				nested = nested[aligned:]
			}
		}
		// Align to 4 bytes.
		aligned := (int(attrLen) + 3) &^ 3
		if aligned > len(attrs) {
			break
		}
		attrs = attrs[aligned:]
	}
	return ""
}
