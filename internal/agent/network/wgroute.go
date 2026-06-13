/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build linux

// Package network provides network-layer operations for pod migration.
package network

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// InjectMigrationHostRoute injects a /32 (IPv4) or /128 (IPv6) host route on the
// source node directing podIP traffic out the WireGuard tunnel interface. This
// replaces FDB injection (ADR-0048) on WireGuard-encrypted overlay clusters (ADR-0102).
//
// Called AFTER CRIURestoreInitiated — not at ZeroWindowEngaged — to avoid redirecting
// packets to a destination before the pod netns exists (ADR-0102 §6 ordering contract).
//
// WireGuard interfaces are PtP/NOARP; Gw must be nil and Scope must be LINK.
// Metric 50 ensures this route wins over CNI daemon routes (Calico 200, Cilium 100+).
func InjectMigrationHostRoute(podIP net.IP, wgInterface string) error {
	link, err := netlink.LinkByName(wgInterface)
	if err != nil {
		return fmt.Errorf("WireGuard interface %q not found: %w", wgInterface, err)
	}
	bits := 32
	if podIP.To4() == nil {
		bits = 128 // IPv6 — ADR-0081
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   podIP,
			Mask: net.CIDRMask(bits, bits*4),
		},
		Scope:    netlink.SCOPE_LINK,
		Protocol: unix.RTPROT_STATIC,
		Type:     unix.RTN_UNICAST,
		Priority: 50,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("inject WireGuard host route %s via %s: %w", podIP, wgInterface, err)
	}
	return nil
}

// CleanupMigrationHostRoute removes the host route injected by InjectMigrationHostRoute.
// Idempotent — ENOENT is not an error.
// Called from SourceCleanup after TrafficVerified=True (ADR-0012 gate, ADR-0102).
func CleanupMigrationHostRoute(podIP net.IP, wgInterface string) error {
	link, err := netlink.LinkByName(wgInterface)
	if err != nil {
		return fmt.Errorf("WireGuard interface %q not found: %w", wgInterface, err)
	}
	bits := 32
	if podIP.To4() == nil {
		bits = 128
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   podIP,
			Mask: net.CIDRMask(bits, bits*4),
		},
	}
	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("cleanup WireGuard host route %s: %w", podIP, err)
	}
	return nil
}

// ConfirmLocalDeliveryRoute confirms that a /32 route for podIP on the destination node
// egresses the expected veth interface identified by podVethIfindex. Returns true only
// when the CNI daemon has attached the pod netns and the local delivery route is present.
//
// Uses positive ifindex match — not a negative interface-type filter — to avoid false
// positives from the default route, the source-side redirect, or unrelated veths
// (ADR-0102 §4, architect quorum requirement).
//
// podVethIfindex comes from the PrepareDestinationNetns gRPC response.
func ConfirmLocalDeliveryRoute(podIP net.IP, podVethIfindex int) (bool, error) {
	routes, err := netlink.RouteGet(podIP)
	if err != nil {
		return false, fmt.Errorf("RouteGet %s: %w", podIP, err)
	}
	for _, r := range routes {
		if r.LinkIndex == podVethIfindex {
			return true, nil
		}
	}
	return false, nil
}

// DetectWireGuardInterface returns the name of the WireGuard tunnel interface on this
// node that carries traffic for the given pod CIDR. Returns "" if WireGuard is not in use.
//
// Selection algorithm: list all links of type "wireguard"; if exactly one, return it;
// if multiple (rare), select the one carrying a route that covers podCIDR.
func DetectWireGuardInterface(podCIDR *net.IPNet) (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", fmt.Errorf("listing network links: %w", err)
	}
	var wgLinks []netlink.Link
	for _, l := range links {
		if l.Type() == "wireguard" {
			wgLinks = append(wgLinks, l)
		}
	}
	if len(wgLinks) == 0 {
		return "", nil
	}
	if len(wgLinks) == 1 {
		return wgLinks[0].Attrs().Name, nil
	}
	// Multiple WireGuard interfaces — pick the one with a route covering the pod CIDR.
	for _, wl := range wgLinks {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
			&netlink.Route{LinkIndex: wl.Attrs().Index}, netlink.RT_FILTER_OIF)
		if err != nil {
			continue
		}
		for _, r := range routes {
			if r.Dst != nil && podCIDR != nil && podCIDR.Contains(r.Dst.IP) {
				return wl.Attrs().Name, nil
			}
		}
	}
	// Fallback: return first WireGuard link
	return wgLinks[0].Attrs().Name, nil
}

// DetectIPSecModeCNI detects CNI-managed IPSec by looking for XFRM policies whose
// source or destination addresses fall within the pod CIDR. Generic host-level XFRM
// policies (service mesh, host VPN) are not counted (ADR-0102 §9).
func DetectIPSecModeCNI(podCIDR *net.IPNet) (bool, error) {
	policies, err := netlink.XfrmPolicyList(syscall.AF_UNSPEC)
	if err != nil {
		return false, fmt.Errorf("listing XFRM policies: %w", err)
	}
	if podCIDR == nil {
		return false, nil
	}
	for _, p := range policies {
		if p.Dst != nil && podCIDR.Contains(p.Dst.IP) {
			return true, nil
		}
		if p.Src != nil && podCIDR.Contains(p.Src.IP) {
			return true, nil
		}
	}
	return false, nil
}
