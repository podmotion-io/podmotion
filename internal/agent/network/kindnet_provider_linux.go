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
