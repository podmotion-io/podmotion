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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// migrationNetnsDir is the base directory for migration network namespaces.
	// Bind-mounted so the netns fd persists after the creating goroutine exits.
	migrationNetnsDir = "/run/podmotion/netns"

	// migrationVethPrefix is the host-side veth name prefix inside the migration netns.
	migrationVethPeer = "pmdst0"
)

// MigrationNetns holds the state of a prepared destination network namespace.
type MigrationNetns struct {
	// NetnsPath is the bind-mount path of the netns (e.g. /run/podmotion/netns/pm-mig-<uid>).
	NetnsPath string
	// HostVethName is the veth end on the host bridge (e.g. pmh-<uid>).
	HostVethName string
}

// PrepareDestinationNetns creates a migration netns on the destination node with:
//  1. A new network namespace bind-mounted to /run/podmotion/netns/pm-mig-<uid>.
//  2. A veth pair: <hostVeth> on the host side wired to cni0/flannel bridge, pmdst0 inside the netns.
//  3. The source pod IP added as a /32 secondary address on pmdst0 inside the netns.
//
// The loopback interface inside the netns is brought up. The host-side veth is
// enslaved to the bridge named by bridgeName (typically "cni0" for flannel).
//
// Requires CAP_NET_ADMIN and CAP_SYS_ADMIN (for unshare/setns).
func PrepareDestinationNetns(ctx context.Context, uid, podIP, podCIDR, bridgeName string) (*MigrationNetns, error) {
	log := logf.FromContext(ctx)

	if err := os.MkdirAll(migrationNetnsDir, 0o700); err != nil {
		return nil, fmt.Errorf("PrepareDestinationNetns: mkdir %s: %w", migrationNetnsDir, err)
	}

	netnsPath := filepath.Join(migrationNetnsDir, "pm-mig-"+uid)
	hostVeth := "pmh-" + truncUID(uid, 8)

	ip := net.ParseIP(podIP)
	if ip == nil {
		return nil, fmt.Errorf("PrepareDestinationNetns: invalid podIP %q", podIP)
	}

	// Idempotency (M22/M24 freeze-go): the controller calls this RPC on every
	// DestinationPrewarm reconcile until DestinationNetnsReady=True. A prior
	// reconcile may have already created the netns and its veth. If a live nsfs
	// bind mount already exists at netnsPath, the netns is prepared — return it
	// rather than failing with "already exists", which would livelock the phase.
	// A leftover empty file with NO backing mount is stale; tear it down and recreate.
	if _, statErr := os.Stat(netnsPath); statErr == nil {
		if isNsfsMounted(netnsPath) {
			log.Info("migration netns already prepared — reusing (idempotent)",
				"netnsPath", netnsPath, "hostVeth", hostVeth, "podIP", podIP)
			return &MigrationNetns{
				NetnsPath:    netnsPath,
				HostVethName: hostVeth,
			}, nil
		}
		log.Info("stale migration netns file with no backing mount — cleaning up before recreate",
			"netnsPath", netnsPath)
		_ = removeVeth(hostVeth)
		_ = unix.Unmount(netnsPath, unix.MNT_DETACH)
		_ = os.Remove(netnsPath)
	}

	if err := createBindMountedNetns(netnsPath); err != nil {
		return nil, fmt.Errorf("PrepareDestinationNetns: %w", err)
	}

	if err := createVethPair(hostVeth, migrationVethPeer, netnsPath); err != nil {
		_ = os.Remove(netnsPath)
		return nil, fmt.Errorf("PrepareDestinationNetns: create veth: %w", err)
	}

	if err := enslaveVethToBridge(hostVeth, bridgeName); err != nil {
		_ = removeVeth(hostVeth)
		_ = os.Remove(netnsPath)
		return nil, fmt.Errorf("PrepareDestinationNetns: enslave to bridge %s: %w", bridgeName, err)
	}

	if err := bringUpInterface(hostVeth); err != nil {
		_ = removeVeth(hostVeth)
		_ = os.Remove(netnsPath)
		return nil, fmt.Errorf("PrepareDestinationNetns: bring up host veth: %w", err)
	}

	if err := configureNetnsInterfaces(netnsPath, ip); err != nil {
		_ = removeVeth(hostVeth)
		_ = os.Remove(netnsPath)
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
	}, nil
}

// TeardownMigrationNetns removes the veth pair and bind-mount for the migration netns.
// ENOENT on any step is treated as success (idempotent).
// The unmount is performed in the HOST mount namespace (via nsenter) because the
// bind-mount was created there by createBindMountedNetns.
func TeardownMigrationNetns(ctx context.Context, ns *MigrationNetns) error {
	log := logf.FromContext(ctx)
	var errs []error

	if err := removeVeth(ns.HostVethName); err != nil && !isEnoent(err) {
		errs = append(errs, fmt.Errorf("remove veth %s: %w", ns.HostVethName, err))
	}
	// Unmount in host mount namespace — the bind-mount was created there.
	if out, err := exec.Command("nsenter", "--mount=/proc/1/ns/mnt", "--",
		"umount", "-l", ns.NetnsPath,
	).CombinedOutput(); err != nil {
		// EINVAL / not mounted: treat as success (idempotent).
		if !strings.Contains(string(out), "not mounted") && !strings.Contains(err.Error(), "exit status") {
			errs = append(errs, fmt.Errorf("unmount netns %s in host ns: %w\n%s", ns.NetnsPath, err, out))
		} else {
			// non-fatal: already unmounted or never mounted
			log.Info("TeardownMigrationNetns: umount returned non-zero (may be already unmounted)",
				"netnsPath", ns.NetnsPath, "err", err, "out", string(out))
		}
	}
	// Remove the file in the host mount namespace.
	if out, err := exec.Command("nsenter", "--mount=/proc/1/ns/mnt", "--",
		"rm", "-f", ns.NetnsPath,
	).CombinedOutput(); err != nil {
		errs = append(errs, fmt.Errorf("remove netns file %s in host ns: %w\n%s", ns.NetnsPath, err, out))
	}

	if len(errs) > 0 {
		return fmt.Errorf("TeardownMigrationNetns: %v", errs)
	}
	log.Info("migration netns torn down", "netnsPath", ns.NetnsPath)
	return nil
}

// isNsfsMounted reports whether path is a live network-namespace bind mount
// (filesystem type "nsfs"). Used to distinguish an already-prepared migration
// netns (reuse, idempotent) from a stale empty backing file (recreate).
// Reads /proc/1/mountinfo (host init's mountinfo, visible because the agent pod
// runs with hostPID:true) so that bind-mounts created in the host mount namespace
// by createBindMountedNetns are visible. The agent container's own /proc/self/mountinfo
// would not show host-namespace mounts.
func isNsfsMounted(path string) bool {
	// Read host mountinfo via PID 1 (host init process, visible with hostPID:true).
	data, err := os.ReadFile("/proc/1/mountinfo")
	if err != nil {
		// Fall back to self mountinfo if /proc/1/mountinfo is inaccessible.
		data, err = os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			return false
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		// mountinfo format: ... <mount-point> ... - <fstype> <source> <opts>
		// The mount point is field 5 (1-indexed); fstype follows the " - " separator.
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if fields[4] != path {
			continue
		}
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep >= 0 && sep+1 < len(fields) && fields[sep+1] == "nsfs" {
			return true
		}
	}
	return false
}

// createBindMountedNetns creates a new network namespace and bind-mounts it
// to path in the HOST mount namespace so it persists and is accessible to CRIU,
// which runs in the host mount namespace via nsenter.
//
// The bind-mount is performed via nsenter --mount=/proc/1/ns/mnt so that the
// resulting mount entry is visible from the host mount namespace — not only from
// the agent container's private mount namespace. CRIU receives the path via
// --join-ns net:<path> and must be able to open it from the host mount namespace.
func createBindMountedNetns(path string) error {
	// Create the bind-mount target file in the HOST mount namespace so CRIU
	// (running in the host mount namespace via nsenter) can open it.
	// We use nsenter to create the file on the host rather than os.OpenFile which
	// would create it only in the agent container's mount namespace.
	if out, err := exec.Command("nsenter", "--mount=/proc/1/ns/mnt", "--",
		"sh", "-c", fmt.Sprintf("[ -e %q ] || touch %q", path, path),
	).CombinedOutput(); err != nil {
		return fmt.Errorf("create netns bind-mount target on host: %w\n%s", err, out)
	}

	// We must lock the OS thread for unshare to work correctly.
	// The goroutine creates a new network namespace, then bind-mounts it into
	// the HOST mount namespace via nsenter so the path is visible to CRIU.
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// LockOSThread is intentionally not unlocked — the goroutine exits after
		// the work is done so Go runtime recycles the locked thread.

		// Save current netns fd so we can restore after creating the new one.
		origNS, err := os.Open("/proc/self/ns/net")
		if err != nil {
			done <- fmt.Errorf("open current netns: %w", err)
			return
		}
		defer origNS.Close()

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("unshare CLONE_NEWNET: %w", err)
			return
		}

		// Get the current thread ID so we can reference its netns via /proc/<tid>/ns/net.
		// After Unshare, /proc/self/ns/net (which resolves to /proc/<tid>/ns/net on Linux)
		// refers to the newly-created network namespace on this locked OS thread.
		tid := unix.Gettid()
		threadNetnsPath := fmt.Sprintf("/proc/%d/ns/net", tid)

		// Bind-mount the new netns into the HOST mount namespace via nsenter.
		// This makes the netns file visible to CRIU which runs in the host mount
		// namespace (nsenter --mount=/proc/1/ns/mnt). Without this, the bind-mount
		// would only appear in the agent container's private mount namespace and CRIU
		// would get ENOENT on --join-ns net:<path> (Sprint 32 cold-gate-attempt-1 root cause).
		if out, err := exec.Command("nsenter", "--mount=/proc/1/ns/mnt", "--",
			"mount", "--bind", threadNetnsPath, path,
		).CombinedOutput(); err != nil {
			// Restore original netns before returning the error.
			_ = unix.Setns(int(origNS.Fd()), unix.CLONE_NEWNET)
			done <- fmt.Errorf("bind mount netns in host mount namespace: %w\n%s", err, out)
			return
		}

		// Return to the original netns.
		if err := unix.Setns(int(origNS.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("restore original netns: %w", err)
			return
		}
		done <- nil
	}()
	return <-done
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
