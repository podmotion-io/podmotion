/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// verify_cleanup.go — ADR-0284: agent-side VerifyCleanup(IP_RECLAIM) handler (GC-6), plus a
// minimal CUTOVER_COMPLETE handler kept alongside it because overriding the single generated
// VerifyCleanup method removes the Unimplemented fallthrough for BOTH scopes at once.
//
// This RPC completes the ADR-0244 (NR-BLOCK-2) IP-reclaim teardown by giving the controller's
// bounded-retry sweep a way to CONFIRM, from live datapath state, that every object DisarmTCRedirect
// and TeardownSourceRedirect are responsible for removing is actually gone on the calling node.
//
// Design invariant (ADR-0284): every probe reads LIVE datapath
// state directly (iptables -C existence check, ip route/neigh show, bridge fdb show, tc filter/qdisc
// show) — it NEVER infers cleanliness from a teardown RPC's return value. A probe whose underlying
// command errors is treated as present+blocking (fail-closed WITHIN the RPC): we would rather have
// the controller re-drive teardown than falsely report a leaked object as gone and reclaim a still-
// wired IP. The single reclaim-safety asymmetry is deliberate: false-"present" only costs a requeue;
// false-"clean" reclaims a live IP.

import (
	"context"
	"fmt"
	"net"
	"strings"

	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ipReclaimObjects is the full IP_RECLAIM object vocabulary (matches the proto doc on
// VerifyCleanupRequest.objects). When req.Objects is empty the handler probes all of them; when it
// is non-empty the handler probes only the requested subset (the proto contract: objects is an
// explicit list so a future ADR can change what is installed as data).
var ipReclaimObjects = []string{
	"tc_filter", "tc_qdisc", "dest_forward_accept", "dest_notrack",
	"source_notrack", "flannel1_route", "flannel1_neigh", "flannel1_fdb",
}

// cutoverCompleteObjects is the CUTOVER_COMPLETE vocabulary (source-node cni0 neigh + host route).
var cutoverCompleteObjects = []string{"cni0_neigh", "cni0_host_route"}

// VerifyCleanup probes whether the datapath objects for a given cleanup scope are still present on
// the calling node (ADR-0241 / ADR-0244 / ADR-0284). Read-only: no object is ever installed or
// removed here. Returns clean=true iff none of the requested objects are still present.
func (s *AgentServer) VerifyCleanup(ctx context.Context, req *agentpb.VerifyCleanupRequest) (*agentpb.VerifyCleanupResponse, error) {
	if req.OldPodIp == "" {
		return nil, status.Errorf(codes.InvalidArgument, "VerifyCleanup: old_pod_ip is required")
	}
	oldIP := net.ParseIP(req.OldPodIp)
	if oldIP == nil || oldIP.To4() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "VerifyCleanup: old_pod_ip %q is not a valid IPv4", req.OldPodIp)
	}

	switch req.Scope {
	case agentpb.CleanupScope_IP_RECLAIM:
		return s.verifyCleanupIPReclaim(ctx, req, oldIP), nil
	case agentpb.CleanupScope_CUTOVER_COMPLETE:
		return s.verifyCleanupCutoverComplete(ctx, req, oldIP), nil
	default:
		return nil, status.Errorf(codes.InvalidArgument,
			"VerifyCleanup: unsupported scope %v (want CUTOVER_COMPLETE or IP_RECLAIM)", req.Scope)
	}
}

// verifyCleanupIPReclaim runs the read-only presence probes for the ADR-0244 IP_RECLAIM objects.
func (s *AgentServer) verifyCleanupIPReclaim(ctx context.Context, req *agentpb.VerifyCleanupRequest, oldIP net.IP) *agentpb.VerifyCleanupResponse {
	// fdbIf names the flannel.1 VXLAN interface the SOURCE-node overlay objects
	// (flannel1_route / flannel1_neigh / flannel1_fdb) live on. On a VXLAN substrate
	// req.FdbIfname carries pm.Status.OverlayFdbIfname; on kindnet the operator sends
	// it empty and the literal "flannel.1" is the correct absent-device sentinel for
	// those source-node objects (they only exist on a VXLAN substrate).
	fdbIf := req.FdbIfname
	if fdbIf == "" {
		fdbIf = "flannel.1"
	}

	// tcIf is the interface the ADR-0139 tc-ingress OLD-IP/32 redirect is actually
	// INSTALLED on, which is NOT necessarily fdbIf. Per ADR-0199 the redirect is
	// installed (InjectIPHandoff) and torn down (DisarmTCRedirect) on the runtime-
	// discovered host interface when the substrate has no VXLAN device (kindnet, where
	// req.FdbIfname==""). The tc_filter/tc_qdisc probes MUST read that same interface,
	// or on kindnet they would probe a flannel.1 that does not exist, read "device
	// absent" as clean, and report Clean=true while a live redirect survives on eth0 —
	// reclaiming a still-wired IP. Mirror DisarmTCRedirect's discovery exactly.
	tcIf := req.FdbIfname
	tcDiscoveryFailed := false
	if tcIf == "" {
		discovered, discErr := discoverHostInterface(ctx)
		if discErr == nil && discovered != "" {
			tcIf = discovered
		} else {
			// FAIL CLOSED: if we cannot resolve the interface the redirect lives on,
			// we cannot prove the redirect is gone. Do not fall back to a flannel.1
			// literal here (that is the very absent-device false-clean this guards
			// against) — mark the tc objects present+blocking so the controller requeues.
			tcDiscoveryFailed = true
			log.Info("VerifyCleanup: host interface discovery failed for tc redirect probe; failing closed",
				"migration", req.MigrationName, "err", discErr)
		}
	}

	wanted := req.Objects
	if len(wanted) == 0 {
		wanted = ipReclaimObjects
	}

	log.Info("VerifyCleanup called (ADR-0284 GC-6, IP_RECLAIM)", "migration", req.MigrationName,
		"oldPodIP", req.OldPodIp, "fdbIf", fdbIf, "tcIf", tcIf, "objects", wanted)

	var present []string
	var reasons []string
	mark := func(obj string, isPresent bool, reason string) {
		if isPresent {
			present = append(present, obj)
			if reason != "" {
				reasons = append(reasons, fmt.Sprintf("%s: %s", obj, reason))
			}
		}
	}

	for _, obj := range wanted {
		switch obj {
		case "tc_filter":
			if tcDiscoveryFailed {
				mark(obj, true, "host interface discovery for tc redirect failed (fail-closed): cannot prove redirect absent")
				continue
			}
			p, r := probeTCFilterPresent(ctx, tcIf, oldIP)
			mark(obj, p, r)
		case "tc_qdisc":
			if tcDiscoveryFailed {
				mark(obj, true, "host interface discovery for tc redirect failed (fail-closed): cannot prove qdisc absent")
				continue
			}
			p, r := probeTCIngressQdiscPresent(ctx, tcIf)
			mark(obj, p, r)
		case "dest_forward_accept":
			p, r := probeForwardAcceptPresent(ctx, oldIP)
			mark(obj, p, r)
		case "dest_notrack", "source_notrack":
			// Both map to the same raw-table NOTRACK rules (removeOldIPNotrack is direction-agnostic
			// and removes all of them). The probe is symmetric; report under whichever object the
			// caller asked for so present_objects echoes the caller's own vocabulary.
			p, r := probeNotrackPresent(ctx, oldIP)
			mark(obj, p, r)
		case "flannel1_route":
			p, r := probeHostRoutePresent(ctx, fdbIf, oldIP)
			mark(obj, p, r)
		case "flannel1_neigh":
			p, r := probeNeighPresent(ctx, fdbIf, oldIP)
			mark(obj, p, r)
		case "flannel1_fdb":
			p, r := probeFDBPresent(ctx, fdbIf, req.ReplVethMac)
			mark(obj, p, r)
		default:
			// Unknown object identifier for this scope: fail closed (treat as present) so an
			// unrecognized name can never be silently counted as "clean".
			mark(obj, true, "unknown object identifier for IP_RECLAIM scope")
		}
	}

	return &agentpb.VerifyCleanupResponse{
		Clean:          len(present) == 0,
		PresentObjects: present,
		BlockingReason: strings.Join(reasons, "; "),
	}
}

// verifyCleanupCutoverComplete runs the read-only presence probes for the CUTOVER_COMPLETE objects
// (source-node cni0 neigh + cni0 host route removed by CleanupSourceIPHandoff). Minimal by design —
// the primary target of ADR-0284 is IP_RECLAIM; this branch exists only because the single method
// override removed the Unimplemented fallthrough for this scope too (ADR-0241 item 1 already relies
// on it via ConditionCni0CleanupVerified in some deployments).
func (s *AgentServer) verifyCleanupCutoverComplete(ctx context.Context, req *agentpb.VerifyCleanupRequest, oldIP net.IP) *agentpb.VerifyCleanupResponse {
	bridgeIf := req.BridgeIfname
	if bridgeIf == "" {
		bridgeIf = "cni0"
	}

	wanted := req.Objects
	if len(wanted) == 0 {
		wanted = cutoverCompleteObjects
	}

	log.Info("VerifyCleanup called (ADR-0284, CUTOVER_COMPLETE)", "migration", req.MigrationName,
		"oldPodIP", req.OldPodIp, "bridgeIf", bridgeIf, "objects", wanted)

	var present []string
	var reasons []string
	mark := func(obj string, isPresent bool, reason string) {
		if isPresent {
			present = append(present, obj)
			if reason != "" {
				reasons = append(reasons, fmt.Sprintf("%s: %s", obj, reason))
			}
		}
	}

	for _, obj := range wanted {
		switch obj {
		case "cni0_neigh":
			p, r := probeNeighPresent(ctx, bridgeIf, oldIP)
			mark(obj, p, r)
		case "cni0_host_route":
			p, r := probeHostRoutePresent(ctx, bridgeIf, oldIP)
			mark(obj, p, r)
		default:
			mark(obj, true, "unknown object identifier for CUTOVER_COMPLETE scope")
		}
	}

	return &agentpb.VerifyCleanupResponse{
		Clean:          len(present) == 0,
		PresentObjects: present,
		BlockingReason: strings.Join(reasons, "; "),
	}
}

// --- read-only presence probes (live datapath state; fail-closed on command error) ---

// probeNotrackPresent returns present=true if ANY ADR-0141 raw-table NOTRACK rule for oldIP still
// exists on the calling node, using the iptables -C existence-check pattern (the same primitive the
// install path uses for its delete-then-insert idempotency). Fail-closed: an iptables invocation
// error other than the expected "rule does not exist" is reported as present+blocking.
func probeNotrackPresent(ctx context.Context, oldIP net.IP) (bool, string) {
	cidr := oldIP.String() + "/32"
	comment := "podmotion ADR-0141 oldIP notrack"
	for _, chain := range []string{"PREROUTING", "OUTPUT"} {
		for _, dir := range []string{"-d", "-s"} {
			args := []string{"-t", "raw", "-C", chain, dir, cidr, "-j", "NOTRACK", "-m", "comment", "--comment", comment}
			out, err := newExecCmd("iptables", args...).CombinedOutput()
			if err == nil {
				// -C succeeded: the rule exists.
				return true, fmt.Sprintf("raw %s %s NOTRACK present", chain, dir)
			}
			msg := strings.ToLower(strings.TrimSpace(string(out)))
			if !isIPTablesAbsent(msg) {
				return true, fmt.Sprintf("raw %s %s NOTRACK check errored (fail-closed): %s", chain, dir, msg)
			}
		}
	}
	return false, ""
}

// probeForwardAcceptPresent returns present=true if either half of the ADR-0140 OLD-IP/32 FORWARD
// ACCEPT pair still exists (iptables -C existence pattern). Fail-closed on non-absence errors.
func probeForwardAcceptPresent(ctx context.Context, oldIP net.IP) (bool, string) {
	cidr := oldIP.String() + "/32"
	for _, spec := range [][]string{{"-d", cidr}, {"-s", cidr}} {
		args := append([]string{"-C", "FORWARD"}, spec...)
		args = append(args, "-j", "ACCEPT", "-m", "comment", "--comment", "podmotion ADR-0140 oldIP fwd")
		out, err := newExecCmd("iptables", args...).CombinedOutput()
		if err == nil {
			return true, fmt.Sprintf("FORWARD %v ACCEPT present", spec)
		}
		msg := strings.ToLower(strings.TrimSpace(string(out)))
		if !isIPTablesAbsent(msg) {
			return true, fmt.Sprintf("FORWARD %v ACCEPT check errored (fail-closed): %s", spec, msg)
		}
	}
	return false, ""
}

// probeTCFilterPresent returns present=true if a tc-ingress u32 filter matching oldIP/32 is still
// installed on ifName (`tc filter show dev <if> ingress`). Fail-closed: an error running tc — other
// than a missing device / missing qdisc (which imply no filter can exist) — reports present.
func probeTCFilterPresent(ctx context.Context, ifName string, oldIP net.IP) (bool, string) {
	out, err := newExecCmd("tc", "filter", "show", "dev", ifName, "ingress").CombinedOutput()
	if err != nil {
		msg := strings.ToLower(strings.TrimSpace(string(out)))
		if isTCDeviceOrQdiscAbsent(msg) {
			return false, ""
		}
		return true, fmt.Sprintf("tc filter show on %s errored (fail-closed): %s", ifName, msg)
	}
	// The u32 filter installs a `match ip dst <oldIP>/32` term; iproute2 renders the destination in
	// the filter dump. Presence of the OLD IP in the ingress filter dump == the redirect filter lives.
	if strings.Contains(string(out), oldIP.String()) {
		return true, "tc ingress u32 filter matching oldIP present"
	}
	return false, ""
}

// probeTCIngressQdiscPresent returns present=true if an ingress qdisc still exists on ifName
// (`tc qdisc show dev <if> ingress`). Fail-closed on unexpected tc errors; a missing device is absent.
func probeTCIngressQdiscPresent(ctx context.Context, ifName string) (bool, string) {
	out, err := newExecCmd("tc", "qdisc", "show", "dev", ifName, "ingress").CombinedOutput()
	if err != nil {
		msg := strings.ToLower(strings.TrimSpace(string(out)))
		if isTCDeviceOrQdiscAbsent(msg) {
			return false, ""
		}
		return true, fmt.Sprintf("tc qdisc show on %s errored (fail-closed): %s", ifName, msg)
	}
	if strings.Contains(strings.ToLower(string(out)), "ingress") {
		return true, "ingress qdisc present"
	}
	return false, ""
}

// probeHostRoutePresent returns present=true if a /32 route for oldIP still exists via ifName
// (`ip route show <oldIP>/32`). Fail-closed on unexpected errors.
func probeHostRoutePresent(ctx context.Context, ifName string, oldIP net.IP) (bool, string) {
	cidr := oldIP.String() + "/32"
	out, err := newExecCmd("ip", "route", "show", cidr).CombinedOutput()
	if err != nil {
		return true, fmt.Sprintf("ip route show %s errored (fail-closed): %s", cidr, strings.TrimSpace(string(out)))
	}
	// `ip route show <cidr>` prints nothing when the route is absent.
	body := strings.TrimSpace(string(out))
	if body == "" {
		return false, ""
	}
	// Route exists; confirm it is the one via our interface (defensive — any /32 for the OLD IP
	// blocks a clean verdict regardless of device, since the OLD IP must be fully unrouted on reclaim).
	if strings.Contains(body, "dev "+ifName) {
		return true, fmt.Sprintf("/32 route via %s present", ifName)
	}
	return true, fmt.Sprintf("/32 route present (%s)", body)
}

// probeNeighPresent returns present=true if an AF_INET neigh entry for oldIP still exists on ifName
// (`ip neigh show <oldIP> dev <if>`). Fail-closed on unexpected errors; empty output / FAILED /
// "no such device" all mean absent.
func probeNeighPresent(ctx context.Context, ifName string, oldIP net.IP) (bool, string) {
	out, err := newExecCmd("ip", "neigh", "show", oldIP.String(), "dev", ifName).CombinedOutput()
	if err != nil {
		msg := strings.ToLower(strings.TrimSpace(string(out)))
		if strings.Contains(msg, "no such device") || strings.Contains(msg, "cannot find device") {
			return false, ""
		}
		return true, fmt.Sprintf("ip neigh show %s dev %s errored (fail-closed): %s", oldIP, ifName, msg)
	}
	body := strings.TrimSpace(string(out))
	if body == "" {
		return false, ""
	}
	// A neigh entry in FAILED state with no lladdr is a negative cache entry, not the live
	// permanent entry SetPodIPNeigh installs — treat it as absent for reclaim purposes.
	if strings.Contains(strings.ToUpper(body), "FAILED") && !strings.Contains(strings.ToLower(body), "lladdr") {
		return false, ""
	}
	return true, "neigh entry present"
}

// probeFDBPresent returns present=true if an AF_BRIDGE FDB entry keyed on replVethMAC still exists
// on ifName (`bridge fdb show dev <if>`). If replVethMAC is empty the exact entry cannot be keyed, so
// this is reported as absent (best-effort, matching TeardownSourceRedirect's own treatment of a
// missing MAC as a non-blocking skip — a bare forwarding hint is harmless relative to a live client).
// Fail-closed on unexpected bridge errors.
func probeFDBPresent(ctx context.Context, ifName, replVethMAC string) (bool, string) {
	if replVethMAC == "" {
		return false, ""
	}
	mac, err := net.ParseMAC(replVethMAC)
	if err != nil {
		return false, ""
	}
	out, cmdErr := newExecCmd("bridge", "fdb", "show", "dev", ifName).CombinedOutput()
	if cmdErr != nil {
		msg := strings.ToLower(strings.TrimSpace(string(out)))
		if strings.Contains(msg, "no such device") || strings.Contains(msg, "cannot find device") {
			return false, ""
		}
		return true, fmt.Sprintf("bridge fdb show dev %s errored (fail-closed): %s", ifName, msg)
	}
	if strings.Contains(strings.ToLower(string(out)), strings.ToLower(mac.String())) {
		return true, "AF_BRIDGE FDB entry for repl_veth_mac present"
	}
	return false, ""
}

// isIPTablesAbsent reports whether an iptables -C stderr message means "the rule does not exist"
// (the expected negative result), as opposed to a genuine invocation error.
func isIPTablesAbsent(lowerMsg string) bool {
	return strings.Contains(lowerMsg, "does a matching rule exist") ||
		strings.Contains(lowerMsg, "bad rule") ||
		strings.Contains(lowerMsg, "no chain/target/match") ||
		strings.Contains(lowerMsg, "does not exist")
}

// isTCDeviceOrQdiscAbsent reports whether a tc stderr message means the device or the ingress qdisc
// is absent — either of which implies no ingress filter/qdisc can be present (a clean negative).
func isTCDeviceOrQdiscAbsent(lowerMsg string) bool {
	return strings.Contains(lowerMsg, "cannot find device") ||
		strings.Contains(lowerMsg, "no such device") ||
		strings.Contains(lowerMsg, "does not exist") ||
		strings.Contains(lowerMsg, "no such file")
}
