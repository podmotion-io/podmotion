/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"fmt"
	"net"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// FDBEntry describes a single FDB/neighbor table entry to inject on a flannel.1
// VTEP interface.  Two entry kinds are needed per ADR-0048:
//
//   - AF_BRIDGE (RTM_NEWNEIGH with NDA_LLADDR) — maps source pod MAC → destination
//     VTEP IP for VXLAN encapsulation.
//   - AF_INET  (RTM_NEWNEIGH with NDA_DST)    — maps source pod IP → source pod MAC
//     so the kernel resolves the overlay neighbor without ARP.
type FDBEntry struct {
	// IfName is the interface to install the entry on (e.g. "flannel.1").
	IfName string
	// PodIP is the source pod's primary IP address (used for AF_INET neighbor).
	PodIP net.IP
	// PodMAC is the source pod's MAC address (used for both entry kinds).
	PodMAC net.HardwareAddr
	// VTEPIP is the destination node's VTEP (tunnel endpoint) IP address.
	// Used for AF_BRIDGE: the overlay knows to send VXLAN frames here for PodMAC.
	VTEPIP net.IP
}

// FDBManager is the interface for injecting and removing FDB/neighbor entries
// on VXLAN interfaces.  M19 ships stubs; M21 provides the real netlink
// implementation (RTM_NEWNEIGH/RTM_DELNEIGH via vishvananda/netlink or raw rtnetlink).
type FDBManager interface {
	// AddFDBEntry installs both the AF_BRIDGE and AF_INET neighbor entries
	// described by e on the interface identified by e.IfName.
	// RTM_NEWNEIGH NLM_F_CREATE|NLM_F_REPLACE is used for idempotency.
	AddFDBEntry(ctx context.Context, e FDBEntry) error

	// RemoveFDBEntry removes both neighbor entries installed by AddFDBEntry.
	// RTM_DELNEIGH is issued for each; ENOENT is treated as success.
	RemoveFDBEntry(ctx context.Context, e FDBEntry) error

	// ConfirmOverlayReady reads back the installed entries via RTM_GETNEIGH and
	// returns an error if either entry is absent.  Used as the C+D predicates of
	// the ADR-0049 atomicity barrier before ZeroWindowDisarm.
	ConfirmOverlayReady(ctx context.Context, e FDBEntry) error
}

// fdbManagerStub satisfies FDBManager by logging intended netlink operations.
// M21 replaces this with a real RTM_NEWNEIGH/RTM_DELNEIGH implementation.
type fdbManagerStub struct{}

// NewFDBManager returns the stub FDB manager.
// M21 will wire the real netlink implementation here once vishvananda/netlink
// (or raw rtnetlink) is vendored and the overlay injection logic is complete.
func NewFDBManager() FDBManager {
	return &fdbManagerStub{}
}

func (s *fdbManagerStub) AddFDBEntry(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("AddFDBEntry: %w", err)
	}
	log.Info("fdb stub: RTM_NEWNEIGH (AF_BRIDGE)",
		"ifName", e.IfName,
		"podMAC", e.PodMAC,
		"vtepIP", e.VTEPIP,
	)
	log.Info("fdb stub: RTM_NEWNEIGH (AF_INET)",
		"ifName", e.IfName,
		"podIP", e.PodIP,
		"podMAC", e.PodMAC,
	)
	return nil
}

func (s *fdbManagerStub) RemoveFDBEntry(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("RemoveFDBEntry: %w", err)
	}
	log.Info("fdb stub: RTM_DELNEIGH (AF_BRIDGE)",
		"ifName", e.IfName,
		"podMAC", e.PodMAC,
		"vtepIP", e.VTEPIP,
	)
	log.Info("fdb stub: RTM_DELNEIGH (AF_INET)",
		"ifName", e.IfName,
		"podIP", e.PodIP,
		"podMAC", e.PodMAC,
	)
	return nil
}

func (s *fdbManagerStub) ConfirmOverlayReady(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("ConfirmOverlayReady: %w", err)
	}
	log.Info("fdb stub: RTM_GETNEIGH read-back — overlay assumed ready",
		"ifName", e.IfName,
		"podIP", e.PodIP,
		"podMAC", e.PodMAC,
		"vtepIP", e.VTEPIP,
	)
	return nil
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
