//go:build linux

/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/podmotion-io/podmotion/internal/agent/network"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// PrepareDestinationNetns creates the migration network namespace on the destination node,
// wires a veth pair into the cni0 bridge, assigns the source pod IP as a /32 on pmdst0,
// and discovers the local VTEP MAC for overlay FDB injection (ADR-0048).
//
// The returned dest_netns_fd is the bind-mounted netns path
// (e.g. /run/podmotion/netns/pm-mig-<uid>) which CRIU receives via
// --join-ns net:<dest_netns_fd> during restore.
//
// The returned dest_vtep_mac is the destination node's VTEP MAC address, for whatever
// VXLAN-class overlay device this node actually has (ADR-0386 — discovered via
// network.DiscoverFdbInterface's link-type discrimination, no "flannel.1" literal).
// The controller injects this into the AF_BRIDGE FDB on the source node so that VXLAN
// frames for the source pod IP are encapsulated toward the destination VTEP.
func (s *AgentServer) PrepareDestinationNetns(ctx context.Context, req *agentpb.PrepareDestinationNetnsRequest) (*agentpb.PrepareDestinationNetnsResponse, error) {
	log.Info("PrepareDestinationNetns called",
		"migration", req.MigrationName,
		"podIP", req.PodIp,
		"ns", req.PodNamespace,
	)

	if req.MigrationName == "" {
		return nil, status.Error(codes.InvalidArgument, "migration_name required")
	}
	if req.PodIp == "" {
		return nil, status.Error(codes.InvalidArgument, "pod_ip required")
	}

	// uid is used to name the netns bind-mount and host veth consistently.
	// We use MigrationName as the uid here — the controller passes a stable identifier.
	uid := req.MigrationName

	// ADR-0158 D5: discover bridge interface at runtime rather than hardcoding "cni0".
	// On kindnet/kind there is no cni0 bridge; the host interface is discovered dynamically.
	bridgeName, _ := discoverHostInterface(ctx)
	if bridgeName == "" {
		bridgeName = "cni0" // Flannel fallback only — kindnet discovery returns a non-empty name.
	}
	// ADR-0167 C1: use KindnetProvider as the wiring provider so that EOPNOTSUPP detection
	// and host-route fall-through live in the provider abstraction layer.
	// BridgeIfname is set to the runtime-discovered interface (ADR-0154 Decision 3).
	provider := &network.KindnetProvider{BridgeIfname: bridgeName}
	ns, err := network.PrepareDestinationNetns(ctx, provider, uid, req.PodIp, "", bridgeName, req.MigrationName)
	if err != nil {
		log.Error(err, "PrepareDestinationNetns: failed to create migration netns",
			"migration", req.MigrationName, "podIP", req.PodIp)
		return nil, status.Errorf(codes.Internal, "prepare destination netns: %v", err)
	}

	// ADR-0168 GC-10: persist the MigrationNetns handle for use by the Restore defer teardown.
	s.destMigrationNetnsMu.Lock()
	s.destMigrationNetns[req.MigrationName] = ns
	s.destMigrationNetnsMu.Unlock()

	// ADR-0168 B2: cache workload image for the Restore gRPC fallback path.
	if req.WorkloadImage != nil && *req.WorkloadImage != "" {
		s.destWorkloadImageMu.Lock()
		s.destWorkloadImage[req.MigrationName] = *req.WorkloadImage
		s.destWorkloadImageMu.Unlock()
		log.Info("PrepareDestinationNetns: cached workload image (ADR-0168 B2)",
			"migration", req.MigrationName, "image", *req.WorkloadImage)
	}

	// ADR-0386: resolve the VTEP device by link-type discrimination (network.DiscoverFdbInterface,
	// ADR-0192 Site B B4) instead of the "flannel.1" name literal this call site previously hardcoded.
	// DiscoverFdbInterface enumerates host interfaces via RTM_GETLINK and returns the first
	// IFLA_INFO_KIND=="vxlan" link it finds, whatever that device is actually named on this
	// substrate — it returns "" (not an error) when no VXLAN overlay device exists at all (e.g.
	// Cilium's geneve/native-routing datapath, kindnet). The flannel annotation JSON is not
	// available here (the server does not have k8s API access at this call site), so once a
	// device name is resolved we still fall through to DiscoverVTEPMAC's RTM_GETLINK path on it.
	fdbIfName, fdbErr := network.DiscoverFdbInterface()
	if fdbErr != nil {
		log.Info("PrepareDestinationNetns: VXLAN overlay device discovery error — returning empty mac",
			"migration", req.MigrationName, "err", fdbErr)
		return &agentpb.PrepareDestinationNetnsResponse{
			Ready:       true,
			DestNetnsFd: ns.NetnsPath,
			DestVtepMac: "",
		}, nil
	}
	if fdbIfName == "" {
		// No VXLAN-class device on this node at all — substrate has no FDB/VTEP overlay to
		// discover a MAC for (Cilium geneve/native routing, kindnet host-routing, etc.). This is
		// the expected, non-fatal steady state on those substrates, not a discovery failure.
		log.Info("PrepareDestinationNetns: no VXLAN overlay device on this node — returning empty mac",
			"migration", req.MigrationName)
		return &agentpb.PrepareDestinationNetnsResponse{
			Ready:       true,
			DestNetnsFd: ns.NetnsPath,
			DestVtepMac: "",
		}, nil
	}

	vtepMAC, err := network.DiscoverVTEPMAC(ctx, "", fdbIfName)
	if err != nil {
		// Non-fatal: the discovered device disappeared or is unreadable between discovery and
		// lookup. Return the netns path with an empty VTEP MAC and let the controller decide.
		log.Info("PrepareDestinationNetns: VTEP MAC discovery failed — returning empty mac",
			"migration", req.MigrationName, "fdbIfName", fdbIfName, "err", err)
		return &agentpb.PrepareDestinationNetnsResponse{
			Ready:       true,
			DestNetnsFd: ns.NetnsPath,
			DestVtepMac: "",
		}, nil
	}

	vtepMACStr := fmt.Sprintf("%s", vtepMAC)
	log.Info("PrepareDestinationNetns: ready",
		"migration", req.MigrationName,
		"netnsPath", ns.NetnsPath,
		"vtepMAC", vtepMACStr,
	)
	return &agentpb.PrepareDestinationNetnsResponse{
		Ready:       true,
		DestNetnsFd: ns.NetnsPath,
		DestVtepMac: vtepMACStr,
	}, nil
}
