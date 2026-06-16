// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !linux

package network

import (
	"context"
	"fmt"
	"net"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// SetPodIPNeigh is a no-op on non-Linux builds (ADR-0133 destination handoff stub).
func SetPodIPNeigh(ctx context.Context, ifName string, podIP net.IP, lladdr net.HardwareAddr) error {
	logf.FromContext(ctx).Info("neigh stub: SetPodIPNeigh (ADR-0133)", "ifName", ifName, "podIP", podIP, "lladdr", lladdr)
	return nil
}

// DeletePodIPNeigh is a no-op on non-Linux builds (ADR-0133 source cleanup stub).
func DeletePodIPNeigh(ctx context.Context, ifName string, podIP net.IP) error {
	logf.FromContext(ctx).Info("neigh stub: DeletePodIPNeigh (ADR-0133)", "ifName", ifName, "podIP", podIP)
	return nil
}

// DiscoverVTEPMAC returns the VTEP MAC via net.InterfaceByName on non-Linux builds.
// The flannel annotation path is unavailable here; falls back to the interface MAC.
func DiscoverVTEPMAC(_ context.Context, _ string, ifName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("DiscoverVTEPMAC stub: %w", err)
	}
	return iface.HardwareAddr, nil
}

// DiscoverFdbInterface returns "" on non-Linux builds — VXLAN link-type discovery
// requires RTM_GETLINK which is Linux-only (ADR-0192 Site B stub).
func DiscoverFdbInterface() (string, error) {
	return "", nil
}

// fdbManagerStub satisfies FDBManager for non-Linux builds (macOS dev, unit tests).
type fdbManagerStub struct{}

// NewFDBManager returns the stub FDB manager on non-Linux platforms.
func NewFDBManager() FDBManager {
	return &fdbManagerStub{}
}

func (s *fdbManagerStub) AddFDBEntry(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("AddFDBEntry: %w", err)
	}
	log.Info("fdb stub: RTM_NEWNEIGH (AF_BRIDGE)", "ifName", e.IfName, "podMAC", e.PodMAC, "vtepIP", e.VTEPIP)
	log.Info("fdb stub: RTM_NEWNEIGH (AF_INET)", "ifName", e.IfName, "podIP", e.PodIP, "podMAC", e.PodMAC)
	return nil
}

func (s *fdbManagerStub) RemoveFDBEntry(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("RemoveFDBEntry: %w", err)
	}
	log.Info("fdb stub: RTM_DELNEIGH (AF_BRIDGE)", "ifName", e.IfName, "podMAC", e.PodMAC)
	log.Info("fdb stub: RTM_DELNEIGH (AF_INET)", "ifName", e.IfName, "podIP", e.PodIP)
	return nil
}

func (s *fdbManagerStub) ConfirmOverlayReady(ctx context.Context, e FDBEntry) error {
	log := logf.FromContext(ctx)
	if err := validateFDBEntry(e); err != nil {
		return fmt.Errorf("ConfirmOverlayReady: %w", err)
	}
	log.Info("fdb stub: RTM_GETNEIGH read-back — overlay assumed ready",
		"ifName", e.IfName, "podIP", e.PodIP, "podMAC", e.PodMAC, "vtepIP", e.VTEPIP)
	return nil
}
