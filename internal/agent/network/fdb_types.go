// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network

import (
	"context"
	"fmt"
	"net"
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
// on VXLAN interfaces.
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

// VTEPMACDiscoverer discovers the VTEP MAC for a node's flannel VTEP interface.
// Primary method: parse flannel.alpha.coreos.com/backend-data node annotation.
// Fallback: RTM_GETLINK on the named interface.
type VTEPMACDiscoverer interface {
	DiscoverVTEPMAC(ctx context.Context, flannelAnnotationJSON, ifName string) (net.HardwareAddr, error)
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
