// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
)

const (
	// migrationVethPeer is the host-side veth name prefix inside the migration netns.
	migrationVethPeer = "pmdst0"
)

// MigrationNetns holds the state of a prepared destination network namespace.
type MigrationNetns struct {
	// NetnsPath is the bind-mount path of the netns. Under SD-1-NETNS-BROKER this
	// is the broker-computed path /run/podmotion/netns/<migrationUID>/bind.
	NetnsPath string
	// HostVethName is the veth end on the host bridge (e.g. pmh-<uid>).
	HostVethName string
	// MigrationUID is the per-migration token the broker keys the bind-mount by.
	// Required for TeardownMigrationNetns to address the right broker entry.
	MigrationUID string
}

// brokerUID maps a raw migration uid to the broker's accepted token shape. The
// broker validates against ^[A-Za-z0-9][A-Za-z0-9-]{0,127}$; migration uids are
// already in that set, but we prefix with "pm-mig-" to namespace broker entries
// and stay stable with the historical netns naming (pm-mig-<uid>).
func brokerUID(uid string) string {
	return "pm-mig-" + strings.ReplaceAll(uid, "-", "")
}

// PrepareDestinationNetns creates a migration netns on the destination node with:
//  1. A new network namespace bind-mounted to /run/podmotion/netns/pm-mig-<uid>.
//  2. A veth pair: <hostVeth> on the host side wired via provider.WireDestinationVeth
//     (bridge-enslave on Flannel; /32 host-route injection on kindnet/ptp — ADR-0167 C1).
//  3. The source pod IP added as a /32 secondary address on pmdst0 inside the netns.
//
// The loopback interface inside the netns is brought up. The host-side veth is wired
// via the provider's WireDestinationVeth method (ADR-0167 C1 provider-layer placement).
//
// provider must not be nil; pass &NoOpCNI{} for tcpPreservationMode=None contexts.
// uid is used to name the netns and veth; migrationName is used for C4 structured log fields.
//
// Requires CAP_NET_ADMIN and CAP_SYS_ADMIN (for unshare/setns).
func PrepareDestinationNetns(ctx context.Context, provider NetworkProvider, uid, podIP, podCIDR, bridgeName, migrationName string) (*MigrationNetns, error) {
	log := logf.FromContext(ctx)

	hostVeth := "pmh-" + truncUID(uid, 8)
	muid := brokerUID(uid)

	ip := net.ParseIP(podIP)
	if ip == nil {
		return nil, fmt.Errorf("PrepareDestinationNetns: invalid podIP %q", podIP)
	}

	// SD-1-NETNS-BROKER (ADR-0148 Amendment): the irreducible host-mount-namespace
	// bind privilege now lives in the privileged netns-broker sidecar. The main
	// agent is privileged:false and no longer runs nsenter+mount itself. We ask the
	// broker to create a FRESH netns (srcPID=0 — destination prewarm) bind-mounted
	// in the host mount namespace, and it returns the host path.
	//
	// Idempotency (M22/M24 freeze-go): the controller calls this RPC on every
	// DestinationPrewarm reconcile until DestinationNetnsReady=True. The broker's
	// create is idempotent — an already-present nsfs bind for this migrationUID is
	// returned as-is rather than failing, so the phase does not livelock. A stale
	// no-backing file is cleaned and recreated broker-side.
	broker := netnsbroker.NewClient()
	netnsPath, err := broker.Create(ctx, muid, 0)
	if err != nil {
		return nil, fmt.Errorf("PrepareDestinationNetns: broker create: %w", err)
	}

	// SP-5: bounded propagation barrier — wait up to 500 ms for the host-ns bind-mount
	// to propagate into the container via mountPropagation: HostToContainer.
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(netnsPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// SP-2: Arch-C regression guard — verify the path is os.Open-able in-process
	// (producer/consumer mount-namespace coherence). If this fails, mount propagation
	// is not active: check that /run/podmotion is rshared on the host and that
	// mountPropagation: HostToContainer is set on the agent container's run-podmotion mount.
	f, err := os.Open(netnsPath)
	if err != nil {
		return nil, fmt.Errorf("netns path not visible in container ns after bind-mount (mount propagation not active?): %w", err)
	}
	f.Close()

	if err := createVethPair(hostVeth, migrationVethPeer, netnsPath); err != nil {
		_ = broker.Teardown(ctx, muid) // SD-1: unmount+remove is broker-owned now
		return nil, fmt.Errorf("PrepareDestinationNetns: create veth: %w", err)
	}

	// SD-2 + SD-1: bring up host veth BEFORE wiring so that on the host-route path
	// (kindnet/ptp, ADR-0167) the device is IFF_UP when SetPodIPHostRoute issues RTM_NEWROUTE.
	// On the bridge path the bring-up order does not matter (bridge membership and IFF_UP
	// are orthogonal), so hoisting bringUpInterface before WireDestinationVeth is safe for both paths.
	if err := bringUpInterface(hostVeth); err != nil {
		_ = removeVeth(hostVeth)
		_ = broker.Teardown(ctx, muid) // SD-1: broker unmounts in host mount ns
		return nil, fmt.Errorf("PrepareDestinationNetns: bring up host veth: %w", err)
	}

	// SD-1 (ADR-0167 C1): substrate wiring via provider. On bridge-mode substrates:
	// enslaves hostVeth to bridgeName. On kindnet/ptp: detects EOPNOTSUPP, validates C3,
	// injects /32 host route for podIP via hostVeth, emits C4 log.
	// migrationNetns.go never branches on raw errno — that is the provider's responsibility.
	if err := provider.WireDestinationVeth(ctx, hostVeth, bridgeName, podIP, migrationName); err != nil {
		_ = removeVeth(hostVeth)
		_ = broker.Teardown(ctx, muid) // SD-1: broker unmounts in host mount ns
		return nil, fmt.Errorf("PrepareDestinationNetns: wire destination veth (bridge=%s): %w", bridgeName, err)
	}

	if err := configureNetnsInterfaces(netnsPath, ip); err != nil {
		_ = removeVeth(hostVeth)
		_ = broker.Teardown(ctx, muid) // SD-1: broker unmounts in host mount ns
		return nil, fmt.Errorf("PrepareDestinationNetns: configure netns: %w", err)
	}

	log.Info("migration netns ready",
		"netnsPath", netnsPath,
		"hostVeth", hostVeth,
		"podIP", podIP,
	)
	return &MigrationNetns{
		NetnsPath:    netnsPath,
		HostVethName: hostVeth,
		MigrationUID: muid,
	}, nil
}

// TeardownMigrationNetns removes the veth pair and bind-mount for the migration netns.
// ENOENT on any step is treated as success (idempotent).
//
// SD-1-NETNS-BROKER (ADR-0148 Amendment): the unmount+remove of the bind-mount —
// which must happen in the HOST mount namespace — is delegated to the privileged
// netns-broker sidecar (the main agent is privileged:false and cannot unmount in
// the host mount ns). The broker teardown is idempotent (treats not-mounted /
// absent as success). The veth removal stays in-process: it is a netlink
// operation the de-privileged agent still holds CAP_NET_ADMIN for.
func TeardownMigrationNetns(ctx context.Context, ns *MigrationNetns) error {
	log := logf.FromContext(ctx)
	var errs []error

	if err := removeVeth(ns.HostVethName); err != nil && !isEnoent(err) {
		errs = append(errs, fmt.Errorf("remove veth %s: %w", ns.HostVethName, err))
	}

	// Resolve the broker token. Newer MigrationNetns values carry MigrationUID
	// directly; for legacy values (e.g. a map entry restored without it) fall back
	// to deriving the token from the bind path's parent dir name.
	muid := ns.MigrationUID
	if muid == "" {
		muid = filepath.Base(filepath.Dir(ns.NetnsPath))
	}

	// Delegate unmount+remove in the host mount namespace to the broker (idempotent).
	if err := netnsbroker.NewClient().Teardown(ctx, muid); err != nil {
		errs = append(errs, fmt.Errorf("broker teardown netns %s: %w", muid, err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("TeardownMigrationNetns: %v", errs)
	}
	log.Info("migration netns torn down", "netnsPath", ns.NetnsPath, "migrationUID", muid)
	return nil
}

// createVethPair creates a veth pair with hostVeth on the host and peerVeth
// placed inside the netns at netnsPath.
func createVethPair(hostVeth, peerVeth, netnsPath string) error {
	// Idempotency: a prior aborted prepare can leak the host veth even after its
	// netns mount is gone. RTM_NEWLINK then fails with EEXIST (errno 17). Remove any
	// pre-existing host veth first so re-prepare succeeds. ENOENT is fine.
	if _, lookErr := net.InterfaceByName(hostVeth); lookErr == nil {
		_ = removeVeth(hostVeth)
	}

	// Open the target netns for the peer end.
	nsFD, err := os.Open(netnsPath)
	if err != nil {
		return fmt.Errorf("open netns %s: %w", netnsPath, err)
	}
	defer nsFD.Close()

	// Use ip(8) semantics via rtnetlink RTM_NEWLINK with IFLA_NET_NS_FD.
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	msg := buildVethNewlink(hostVeth, peerVeth, int(nsFD.Fd()))
	if err := netlinkSendRecv(fd, msg); err != nil {
		return fmt.Errorf("RTM_NEWLINK veth: %w", err)
	}
	return nil
}

// enslaveVethToBridge attaches hostVeth to the bridge named bridgeName via RTM_SETLINK.
func enslaveVethToBridge(hostVeth, bridgeName string) error {
	bridge, err := net.InterfaceByName(bridgeName)
	if err != nil {
		return fmt.Errorf("bridge %q not found: %w", bridgeName, err)
	}
	hostIf, err := net.InterfaceByName(hostVeth)
	if err != nil {
		return fmt.Errorf("veth %q not found: %w", hostVeth, err)
	}
	return netlinkSetMaster(hostIf.Index, bridge.Index)
}

// bringUpInterface sets IFF_UP on a named interface via RTM_NEWLINK / SIOCSIFFLAGS.
func bringUpInterface(ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("bringUpInterface %q: %w", ifname, err)
	}
	return netlinkSetUp(iface.Index)
}

// configureNetnsInterfaces enters the netns and:
//  1. Brings up loopback.
//  2. Brings up pmdst0.
//  3. Adds podIP/32 as a secondary address on pmdst0.
func configureNetnsInterfaces(netnsPath string, podIP net.IP) error {
	nsFD, err := os.Open(netnsPath)
	if err != nil {
		return fmt.Errorf("open netns: %w", err)
	}
	defer nsFD.Close()

	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()

		origNS, err := os.Open("/proc/self/ns/net")
		if err != nil {
			done <- fmt.Errorf("open current netns: %w", err)
			return
		}
		defer origNS.Close()

		if err := unix.Setns(int(nsFD.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("setns: %w", err)
			return
		}

		defer func() {
			_ = unix.Setns(int(origNS.Fd()), unix.CLONE_NEWNET)
		}()

		lo, err := net.InterfaceByName("lo")
		if err == nil {
			_ = netlinkSetUp(lo.Index)
		}

		dst, err := net.InterfaceByName(migrationVethPeer)
		if err != nil {
			done <- fmt.Errorf("pmdst0 not found inside netns: %w", err)
			return
		}
		if err := netlinkSetUp(dst.Index); err != nil {
			done <- fmt.Errorf("bring up pmdst0: %w", err)
			return
		}
		if err := netlinkAddrAdd(dst.Index, podIP); err != nil {
			done <- fmt.Errorf("add /32 addr: %w", err)
			return
		}
		done <- nil
	}()
	return <-done
}

// removeVeth deletes a named interface (which removes both ends of a veth pair).
func removeVeth(ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return netlinkDelLink(fd, iface.Index)
}

// HostVethPeerName derives the host-side veth interface name from a migration UID or
// migration name using the same formula as PrepareDestinationNetns ("pmh-" + first 8
// non-hyphen chars of uid). Used as a fallback by joinNsRestore when the stored host-veth
// name is not available (e.g. cold-path, pre-Gate30 callers).
func HostVethPeerName(uid string) string {
	return "pmh-" + truncUID(uid, 8)
}

// truncUID returns the first n runes of uid, safe for use in interface names.
func truncUID(uid string, n int) string {
	uid = strings.ReplaceAll(uid, "-", "")
	if len(uid) > n {
		return uid[:n]
	}
	return uid
}

// --- Raw netlink helpers ---

// netlinkSetUp sets IFF_UP on ifindex.
func netlinkSetUp(ifindex int) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	// RTM_NEWLINK with IFF_UP flag.
	type ifInfoMsg struct {
		Family uint8
		_      uint8
		Type   uint16
		Index  int32
		Flags  uint32
		Change uint32
	}
	const ifInfoMsgSize = 16
	const IFF_UP = 0x1

	ifm := ifInfoMsg{
		Index:  int32(ifindex),
		Flags:  IFF_UP,
		Change: IFF_UP,
	}
	ifmBytes := (*[ifInfoMsgSize]byte)(unsafe.Pointer(&ifm))[:]

	nlmsgLen := uint32(unix.SizeofNlMsghdr + ifInfoMsgSize)
	hdr := unix.NlMsghdr{
		Len:   nlmsgLen,
		Type:  unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   3,
	}
	hdrBytes := (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, ifmBytes...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return netlinkRecvAck(fd)
}

// netlinkSetMaster enslaves ifindex to masterIndex via RTM_NEWLINK + IFLA_MASTER attr.
func netlinkSetMaster(ifindex, masterIndex int) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	type ifInfoMsg struct {
		Family uint8
		_      uint8
		Type   uint16
		Index  int32
		Flags  uint32
		Change uint32
	}
	const ifInfoMsgSize = 16

	ifm := ifInfoMsg{Index: int32(ifindex)}
	ifmBytes := (*[ifInfoMsgSize]byte)(unsafe.Pointer(&ifm))[:]

	masterVal := make([]byte, 4)
	binary.LittleEndian.PutUint32(masterVal, uint32(masterIndex))
	masterAttr := nlAttr(unix.IFLA_MASTER, masterVal)

	nlmsgLen := uint32(unix.SizeofNlMsghdr + ifInfoMsgSize + uint32(len(masterAttr)))
	hdr := unix.NlMsghdr{
		Len:   nlmsgLen,
		Type:  unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   4,
	}
	hdrBytes := (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(append(hdrBytes, ifmBytes...), masterAttr...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return netlinkRecvAck(fd)
}

// netlinkAddrAdd adds podIP/32 as an AF_INET address on ifindex via RTM_NEWADDR.
func netlinkAddrAdd(ifindex int, podIP net.IP) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	type ifAddrMsg struct {
		Family    uint8
		Prefixlen uint8
		Flags     uint8
		Scope     uint8
		Index     uint32
	}
	const ifAddrMsgSize = 8
	const IFA_F_SECONDARY = 0x01
	const RT_SCOPE_HOST = 254

	ip4 := podIP.To4()
	if ip4 == nil {
		return fmt.Errorf("netlinkAddrAdd: only IPv4 supported, got %s", podIP)
	}

	addrm := ifAddrMsg{
		Family:    unix.AF_INET,
		Prefixlen: 32,
		Flags:     IFA_F_SECONDARY,
		Scope:     RT_SCOPE_HOST,
		Index:     uint32(ifindex),
	}
	addrmBytes := (*[ifAddrMsgSize]byte)(unsafe.Pointer(&addrm))[:]

	localAttr := nlAttr(unix.IFA_LOCAL, []byte(ip4))
	addrAttr := nlAttr(unix.IFA_ADDRESS, []byte(ip4))
	attrs := append(localAttr, addrAttr...)

	nlmsgLen := uint32(unix.SizeofNlMsghdr + ifAddrMsgSize + uint32(len(attrs)))
	hdr := unix.NlMsghdr{
		Len:   nlmsgLen,
		Type:  unix.RTM_NEWADDR,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE,
		Seq:   5,
	}
	hdrBytes := (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(append(hdrBytes, addrmBytes...), attrs...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return netlinkRecvAck(fd)
}

// netlinkDelLink deletes an interface by ifindex via RTM_DELLINK.
func netlinkDelLink(fd, ifindex int) error {
	type ifInfoMsg struct {
		Family uint8
		_      uint8
		Type   uint16
		Index  int32
		Flags  uint32
		Change uint32
	}
	const ifInfoMsgSize = 16
	ifm := ifInfoMsg{Index: int32(ifindex)}
	ifmBytes := (*[ifInfoMsgSize]byte)(unsafe.Pointer(&ifm))[:]
	nlmsgLen := uint32(unix.SizeofNlMsghdr + ifInfoMsgSize)
	hdr := unix.NlMsghdr{
		Len:   nlmsgLen,
		Type:  unix.RTM_DELLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   6,
	}
	hdrBytes := (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&hdr))[:]
	msg := append(hdrBytes, ifmBytes...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return netlinkRecvAck(fd)
}

// netlinkSendRecv sends msg on fd and reads the ACK.
func netlinkSendRecv(fd int, msg []byte) error {
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return netlinkRecvAck(fd)
}

// buildVethNewlink constructs a RTM_NEWLINK message to create a veth pair.
// hostVeth is the host-side name; peerVeth is placed in the netns identified by nsFD.
func buildVethNewlink(hostVeth, peerVeth string, nsFD int) []byte {
	type ifInfoMsg struct {
		Family uint8
		_      uint8
		Type   uint16
		Index  int32
		Flags  uint32
		Change uint32
	}
	const ifInfoMsgSize = 16

	ifm := ifInfoMsg{}
	ifmBytes := (*[ifInfoMsgSize]byte)(unsafe.Pointer(&ifm))[:]

	// IFLA_IFNAME = hostVeth name (null-terminated).
	nameAttr := nlAttr(unix.IFLA_IFNAME, append([]byte(hostVeth), 0))

	// IFLA_LINKINFO nesting: IFLA_INFO_KIND="veth" + IFLA_INFO_DATA with peer attrs.
	const IFLA_INFO_KIND = 1
	const IFLA_INFO_DATA = 2
	const VETH_INFO_PEER = 1

	kindVal := append([]byte("veth"), 0)
	kindAttr := nlAttr(IFLA_INFO_KIND, kindVal)

	// Peer ifInfoMsg + IFLA_IFNAME + IFLA_NET_NS_FD
	peerIfm := ifInfoMsg{}
	peerIfmBytes := (*[ifInfoMsgSize]byte)(unsafe.Pointer(&peerIfm))[:]
	peerNameAttr := nlAttr(unix.IFLA_IFNAME, append([]byte(peerVeth), 0))
	nsFDVal := make([]byte, 4)
	binary.LittleEndian.PutUint32(nsFDVal, uint32(nsFD))
	nsFDAttr := nlAttr(unix.IFLA_NET_NS_FD, nsFDVal)

	peerData := append(append(peerIfmBytes, peerNameAttr...), nsFDAttr...)
	peerAttr := nlAttr(VETH_INFO_PEER, peerData)

	infoData := nlAttr(IFLA_INFO_DATA, peerAttr)
	linkinfo := nlAttr(unix.IFLA_LINKINFO, append(kindAttr, infoData...))

	attrs := append(nameAttr, linkinfo...)

	nlmsgLen := uint32(unix.SizeofNlMsghdr + ifInfoMsgSize + uint32(len(attrs)))
	hdr := unix.NlMsghdr{
		Len:   nlmsgLen,
		Type:  unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   7,
	}
	hdrBytes := (*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(&hdr))[:]
	return append(append(hdrBytes, ifmBytes...), attrs...)
}
