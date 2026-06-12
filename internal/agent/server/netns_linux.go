/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

//go:build linux

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
// The returned dest_vtep_mac is the destination node's flannel.1 VTEP MAC address.
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

	ns, err := network.PrepareDestinationNetns(ctx, uid, req.PodIp, "", "cni0")
	if err != nil {
		log.Error(err, "PrepareDestinationNetns: failed to create migration netns",
			"migration", req.MigrationName, "podIP", req.PodIp)
		return nil, status.Errorf(codes.Internal, "prepare destination netns: %v", err)
	}

	// Discover the local VTEP MAC from the flannel.1 interface.
	// The flannel annotation JSON is not available here (the server does not have k8s API access
	// at this call site), so we fall directly to the RTM_GETLINK path on flannel.1.
	vtepMAC, err := network.DiscoverVTEPMAC(ctx, "", "flannel.1")
	if err != nil {
		// Non-fatal in environments where flannel.1 may not be present (e.g. Cilium, Calico).
		// Return the netns path with an empty VTEP MAC and let the controller decide.
		log.Info("PrepareDestinationNetns: VTEP MAC discovery failed — returning empty mac",
			"migration", req.MigrationName, "err", err)
		return &agentpb.PrepareDestinationNetnsResponse{
			Ready:      true,
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
		Ready:      true,
		DestNetnsFd: ns.NetnsPath,
		DestVtepMac: vtepMACStr,
	}, nil
}
