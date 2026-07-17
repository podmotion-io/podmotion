// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package network

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// ADR-0355 D5 test 6 (DR-11): a standalone regression lock on the pmdst0 netlinkAddrAdd primitive,
// which has zero coverage today (sole call site migrationnetns.go, configureNetnsInterfaces). D1 no
// longer touches netlinkAddrAdd — this is NOT a D1-blast-radius guard — but the coverage gap is real
// independently, and it makes DR-11's "the shared primitive is untouched, still idempotent" claim
// dynamically checkable rather than static-grep-only.
//
// It runs against a REAL, freshly-unshared network namespace with REAL netlink (unix.Unshare +
// unix.Setns; never a mock), so it requires CAP_NET_ADMIN. It t.Skips (never silently passes — same
// convention as tcprepair_export_test.go) when not root.
func TestNetlinkAddrAdd_Pmdst0Idempotent_RealNetns(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("TestNetlinkAddrAdd_Pmdst0Idempotent_RealNetns: requires root / CAP_NET_ADMIN for unshare(CLONE_NEWNET) + netlink RTM_NEWADDR")
	}

	ip := net.ParseIP("10.244.0.41").To4()
	if ip == nil {
		t.Fatal("bad test IP")
	}

	done := make(chan error, 1)
	go func() {
		// Lock the goroutine to its OS thread and deliberately do NOT unlock: if the netns is left
		// mutated the Go runtime retires the thread on goroutine exit, so no thread ever returns to
		// the pool carrying our throwaway netns.
		runtime.LockOSThread()

		origNS, err := os.Open("/proc/self/ns/net")
		if err != nil {
			done <- fmt.Errorf("open orig netns: %w", err)
			return
		}
		defer origNS.Close()

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("unshare netns (need CAP_SYS_ADMIN): %w", err)
			return
		}
		defer func() { _ = unix.Setns(int(origNS.Fd()), unix.CLONE_NEWNET) }()

		// A fresh netns has a down loopback; use its ifindex as the target for the /32 add.
		lo, err := net.InterfaceByName("lo")
		if err != nil {
			done <- fmt.Errorf("lo in fresh netns: %w", err)
			return
		}
		if err := netlinkSetUp(lo.Index); err != nil {
			done <- fmt.Errorf("bring up lo: %w", err)
			return
		}

		// First add of the source pod IP as a /32 scope-host secondary (the pmdst0 primitive).
		if err := netlinkAddrAdd(lo.Index, ip); err != nil {
			done <- fmt.Errorf("first netlinkAddrAdd: %w", err)
			return
		}

		// Second add of the SAME /32: idempotent END-STATE — the address must remain present. The
		// primitive uses NLM_F_CREATE without NLM_F_REPLACE/EXCL, so the kernel MAY return EEXIST on
		// the duplicate; that is a tolerated idempotent outcome (the address is already there), NOT a
		// regression. Any OTHER error is a real regression.
		if err := netlinkAddrAdd(lo.Index, ip); err != nil && !errors.Is(err, syscall.EEXIST) {
			done <- fmt.Errorf("second netlinkAddrAdd returned unexpected non-EEXIST error: %w", err)
			return
		}

		// Confirm the /32 is present after both adds (a re-query in the same fresh netns).
		lo2, err := net.InterfaceByName("lo")
		if err != nil {
			done <- fmt.Errorf("re-lookup lo: %w", err)
			return
		}
		addrs, err := lo2.Addrs()
		if err != nil {
			done <- fmt.Errorf("list lo addrs: %w", err)
			return
		}
		found := false
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(ip) {
				found = true
				break
			}
		}
		if !found {
			done <- fmt.Errorf("preserved /32 %s not present on lo after two idempotent adds (addrs=%v)", ip, addrs)
			return
		}
		done <- nil
	}()

	if err := <-done; err != nil {
		t.Fatalf("%v", err)
	}
}
