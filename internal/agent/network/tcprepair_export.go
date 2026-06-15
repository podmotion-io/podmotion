/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package network — tcprepair_export.go implements D4 of ADR-0156: the
// TCP_REPAIR socket-state export protocol for the Strict-mode checkpoint path.
//
// Capture protocol (ADR-0156 D4):
//  1. Walk /proc/<pid>/net/tcp[6] to enumerate ESTABLISHED sockets and their
//     kernel inode numbers.
//  2. Walk /proc/<pid>/fd/ to find the FD numbers whose symlink targets match
//     each inode (format "socket:[<inode>]").
//  3. Obtain the real socket fd via pidfd_open(targetPID) + pidfd_getfd(fdNum)
//     (Linux 5.6+). This copies the fd from the target process's fd table into
//     the agent's fd table without requiring setns. The agent has CAP_SYS_PTRACE
//     (hostPID=true) which satisfies the PTRACE_MODE_ATTACH_REALCREDS check that
//     pidfd_getfd performs. unix.Open(O_RDONLY) on a /proc/<pid>/fd/<n> socket
//     symlink fails with ENXIO on Linux — you MUST use pidfd_getfd.
//  4. setsockopt(TCP_REPAIR, 1) → enter repair mode (no RST on close).
//  5. getsockopt(TCP_REPAIR_QUEUE, TCP_SEND_QUEUE) then
//     getsockopt(TCP_QUEUE_SEQ) → snd_nxt.
//  6. getsockopt(TCP_REPAIR_QUEUE, TCP_RECV_QUEUE) then
//     getsockopt(TCP_QUEUE_SEQ) → rcv_nxt.
//  7. setsockopt(TCP_REPAIR, 0) → exit repair mode; socket returned to normal.
//  8. Populate SeqSnapshot.SndNxt / RcvNxt with the captured values.
//
// This file does NOT use CGO. All syscalls go through golang.org/x/sys/unix.

package network

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// TCP_REPAIR socket option constants (linux/tcp.h).
// Defined explicitly because golang.org/x/sys/unix does not expose all of them
// as package-level constants in all builds.
const (
	tcpRepairOn  = 1
	tcpRepairOff = 0

	// TCP_REPAIR_QUEUE selects which queue TCP_QUEUE_SEQ reads from.
	tcpRepairQueue = 20 // TCP_REPAIR_QUEUE
	// TCP_QUEUE_SEQ returns the sequence number for the selected queue.
	tcpQueueSeq = 21 // TCP_QUEUE_SEQ

	// Queue selector values for TCP_REPAIR_QUEUE.
	tcpSendQueue = 1
	tcpRecvQueue = 2

	// SOL_TCP == IPPROTO_TCP
	solTCP = 6

	// TCP_REPAIR option number.
	tcpRepairOpt = 19
)

// socketInodeEntry extends SocketEntry with the kernel inode so we can
// locate the socket fd under /proc/<pid>/fd/.
type socketInodeEntry struct {
	SocketEntry
	Inode uint64
}

// ExportTCPRepairState reads the real TCP sequence numbers (snd_nxt, rcv_nxt)
// for all ESTABLISHED sockets of the container process identified by rootPID,
// using the TCP_REPAIR kernel mechanism (ADR-0156 D2/D4).
//
// For each ESTABLISHED socket the function:
//   - enters TCP_REPAIR mode,
//   - reads snd_nxt via TCP_SEND_QUEUE + TCP_QUEUE_SEQ,
//   - reads rcv_nxt via TCP_RECV_QUEUE + TCP_QUEUE_SEQ,
//   - exits TCP_REPAIR mode (socket fully restored to normal operation),
//
// and returns a slice of SocketEntry with non-zero SndNxt / RcvNxt.
//
// Errors accessing individual sockets are logged and skipped; the function
// returns an error only when the proc enumeration itself fails.
func ExportTCPRepairState(rootPID int32) ([]SocketEntry, error) {
	logger := logf.Log.WithName("tcprepair-export")

	// Step 1: enumerate ESTABLISHED sockets + inodes from /proc/<pid>/net/tcp[6].
	inodeEntries, err := parseEstablishedWithInodes(rootPID)
	if err != nil {
		return nil, fmt.Errorf("ExportTCPRepairState: enumerate sockets for pid %d: %w", rootPID, err)
	}
	if len(inodeEntries) == 0 {
		logger.Info("ExportTCPRepairState: no ESTABLISHED sockets found", "pid", rootPID)
		return nil, nil
	}

	// Step 2: build an inode → fd mapping from /proc/<pid>/fd/.
	inodeToFD, err := buildInodeFDMap(rootPID)
	if err != nil {
		// Non-fatal: if we cannot read the fd dir, return entries with zero seqs.
		logger.Error(err, "ExportTCPRepairState: cannot build inode→fd map (returning zero seq entries)",
			"pid", rootPID)
		out := make([]SocketEntry, len(inodeEntries))
		for i, e := range inodeEntries {
			out[i] = e.SocketEntry
		}
		return out, nil
	}

	// Step 3: open a pidfd for the target process (Linux 5.6+ pidfd_open syscall).
	// pidfd_getfd will use this to copy the target socket fd into our fd table.
	pidfd, pidfdErr := pidfdOpen(int(rootPID))
	if pidfdErr != nil {
		logger.Error(pidfdErr, "ExportTCPRepairState: pidfd_open failed — cannot copy socket fds (returning zero seqs)",
			"pid", rootPID)
		out := make([]SocketEntry, len(inodeEntries))
		for i, e := range inodeEntries {
			out[i] = e.SocketEntry
		}
		return out, nil
	}
	defer unix.Close(pidfd)

	var results []SocketEntry
	for _, ie := range inodeEntries {
		fdNum, ok := inodeToFD[ie.Inode]
		if !ok {
			logger.Info("ExportTCPRepairState: socket inode not found in fd map — socket owned by sibling process (skipping seq read)",
				"pid", rootPID, "inode", ie.Inode,
				"src", fmt.Sprintf("%s:%d", ie.SrcIP, ie.SrcPort),
				"dst", fmt.Sprintf("%s:%d", ie.DstIP, ie.DstPort))
			// Include with zero seqs rather than dropping the 4-tuple.
			results = append(results, ie.SocketEntry)
			continue
		}

		// Step 3b: copy the socket fd from the target process via pidfd_getfd.
		// This requires CAP_SYS_PTRACE (or PTRACE_MODE_ATTACH_REALCREDS permission).
		// The agent runs as root with hostPID=true so this is satisfied.
		sockFD, getfdErr := pidfdGetFD(pidfd, fdNum)
		if getfdErr != nil {
			logger.Error(getfdErr, "ExportTCPRepairState: pidfd_getfd failed (using zero seqs)",
				"pid", rootPID, "fdNum", fdNum, "inode", ie.Inode)
			results = append(results, ie.SocketEntry)
			continue
		}

		sndNxt, rcvNxt, repairErr := readTCPRepairSeqs(sockFD)
		unix.Close(sockFD)

		if repairErr != nil {
			logger.Error(repairErr, "ExportTCPRepairState: TCP_REPAIR read failed (using zero seqs)",
				"pid", rootPID, "fdNum", fdNum,
				"src", fmt.Sprintf("%s:%d", ie.SrcIP, ie.SrcPort),
				"dst", fmt.Sprintf("%s:%d", ie.DstIP, ie.DstPort))
			results = append(results, ie.SocketEntry)
			continue
		}

		entry := ie.SocketEntry
		entry.SndNxt = sndNxt
		entry.RcvNxt = rcvNxt
		logger.Info("ExportTCPRepairState: captured TCP_REPAIR seq state (ADR-0156 GC-27)",
			"pid", rootPID,
			"src", fmt.Sprintf("%s:%d", entry.SrcIP, entry.SrcPort),
			"dst", fmt.Sprintf("%s:%d", entry.DstIP, entry.DstPort),
			"snd_nxt", fmt.Sprintf("0x%08X", sndNxt),
			"rcv_nxt", fmt.Sprintf("0x%08X", rcvNxt))
		results = append(results, entry)
	}

	return results, nil
}

// pidfdOpen opens a pidfd for the process with the given PID.
// Returns the pidfd file descriptor; the caller must unix.Close it.
// Requires Linux 5.1+ (SYS_PIDFD_OPEN = 434 on amd64).
func pidfdOpen(pid int) (int, error) {
	fd, _, errno := unix.Syscall(unix.SYS_PIDFD_OPEN, uintptr(pid), 0, 0)
	if errno != 0 {
		return -1, fmt.Errorf("pidfd_open(%d): %w", pid, errno)
	}
	return int(fd), nil
}

// pidfdGetFD copies file descriptor targetFD from the process identified by
// pidfd into the calling process's fd table.
// Requires Linux 5.6+ (SYS_PIDFD_GETFD = 438 on amd64).
// The caller must unix.Close the returned fd.
func pidfdGetFD(pidfd, targetFD int) (int, error) {
	fd, _, errno := unix.Syscall(unix.SYS_PIDFD_GETFD,
		uintptr(pidfd), uintptr(targetFD), 0)
	if errno != 0 {
		return -1, fmt.Errorf("pidfd_getfd(pidfd=%d, targetFD=%d): %w", pidfd, targetFD, errno)
	}
	return int(fd), nil
}

// readTCPRepairSeqs enters TCP_REPAIR mode on sockFD, reads snd_nxt and
// rcv_nxt, then exits TCP_REPAIR mode. The socket is fully restored to normal
// operation before this function returns (D4 step 7).
//
// IMPORTANT: TCP_REPAIR requires CAP_NET_ADMIN. The agent runs as root with
// hostNetwork:true, so this is guaranteed in production. In unit tests or
// restricted environments the setsockopt call will return EPERM; the caller
// logs and skips.
func readTCPRepairSeqs(sockFD int) (sndNxt, rcvNxt uint32, err error) {
	// Step 4: enter repair mode.
	if err := tcpRepairSet(sockFD, tcpRepairOn); err != nil {
		return 0, 0, fmt.Errorf("TCP_REPAIR ON: %w", err)
	}

	// Ensure we always exit repair mode, even on error.
	defer func() {
		if offErr := tcpRepairSet(sockFD, tcpRepairOff); offErr != nil {
			if err == nil {
				err = fmt.Errorf("TCP_REPAIR OFF: %w (after successful seq read)", offErr)
			}
		}
	}()

	// Step 5: read snd_nxt (SEND queue).
	sndNxt, err = readQueueSeq(sockFD, tcpSendQueue)
	if err != nil {
		return 0, 0, fmt.Errorf("read snd_nxt (SEND queue): %w", err)
	}

	// Step 6: read rcv_nxt (RECV queue).
	rcvNxt, err = readQueueSeq(sockFD, tcpRecvQueue)
	if err != nil {
		return 0, 0, fmt.Errorf("read rcv_nxt (RECV queue): %w", err)
	}

	return sndNxt, rcvNxt, nil
}

// tcpRepairSet calls setsockopt(TCP_REPAIR, val) on sockFD.
func tcpRepairSet(sockFD, val int) error {
	v := int32(val) //nolint:gosec // small constant
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(sockFD),
		uintptr(solTCP),
		uintptr(tcpRepairOpt),
		uintptr(unsafe.Pointer(&v)),
		uintptr(4),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("setsockopt(TCP_REPAIR, %d): %w", val, errno)
	}
	return nil
}

// readQueueSeq selects queueSelector on TCP_REPAIR_QUEUE, then reads
// TCP_QUEUE_SEQ and returns the 32-bit sequence number.
func readQueueSeq(sockFD int, queueSelector int) (uint32, error) {
	// Select the queue.
	q := int32(queueSelector) //nolint:gosec
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(sockFD),
		uintptr(solTCP),
		uintptr(tcpRepairQueue),
		uintptr(unsafe.Pointer(&q)),
		uintptr(4),
		0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("setsockopt(TCP_REPAIR_QUEUE, %d): %w", queueSelector, errno)
	}

	// Read the sequence number.
	var seq uint32
	seqLen := uint32(4)
	_, _, errno = unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(sockFD),
		uintptr(solTCP),
		uintptr(tcpQueueSeq),
		uintptr(unsafe.Pointer(&seq)),
		uintptr(unsafe.Pointer(&seqLen)),
		0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("getsockopt(TCP_QUEUE_SEQ): %w", errno)
	}
	return seq, nil
}

// buildInodeFDMap walks /proc/<pid>/fd/ and builds a map from socket inode →
// fd number. Only "socket:[<inode>]" symlink targets are recorded.
func buildInodeFDMap(rootPID int32) (map[uint64]int, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", rootPID)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", fdDir, err)
	}
	m := make(map[uint64]int, len(entries))
	for _, e := range entries {
		fdNum, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		// Format: "socket:[<inode>]"
		if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		inodeStr := target[len("socket:[") : len(target)-1]
		inode, err := strconv.ParseUint(inodeStr, 10, 64)
		if err != nil {
			continue
		}
		m[inode] = fdNum
	}
	return m, nil
}

// parseEstablishedWithInodes parses /proc/<pid>/net/tcp[6] and returns
// ESTABLISHED socket entries with their kernel inode numbers populated.
func parseEstablishedWithInodes(rootPID int32) ([]socketInodeEntry, error) {
	var results []socketInodeEntry
	for _, fname := range []string{"tcp", "tcp6"} {
		path := fmt.Sprintf("/proc/%d/net/%s", rootPID, fname)
		parsed, err := parseNetTCPWithInodes(path, fname == "tcp6")
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		results = append(results, parsed...)
	}
	return results, nil
}

// parseNetTCPWithInodes parses /proc/net/tcp[6] and returns entries that
// include the socket inode field (column index 9, 0-indexed).
func parseNetTCPWithInodes(path string, isIPv6 bool) ([]socketInodeEntry, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []socketInodeEntry
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[3] != "01" { // ESTABLISHED
			continue
		}
		srcIP, srcPort, err := decodeAddr(fields[1], isIPv6)
		if err != nil {
			continue
		}
		dstIP, dstPort, err := decodeAddr(fields[2], isIPv6)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		entries = append(entries, socketInodeEntry{
			SocketEntry: SocketEntry{
				SrcIP:       srcIP,
				SrcPort:     srcPort,
				DstIP:       dstIP,
				DstPort:     dstPort,
				SACKEnabled: true,
			},
			Inode: inode,
		})
	}
	return entries, scanner.Err()
}

// decodeAddr is defined in socketinventory.go in this package and is reused
// directly here — no duplicate definition needed.
