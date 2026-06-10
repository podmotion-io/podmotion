/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package iphandoff

import (
	"context"
	"strings"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// IPHandoffStrategy is the interface each CNI-specific handoff mechanism implements.
// Implementations must be safe for concurrent use.
type IPHandoffStrategy interface {
	// Name returns a short identifier used for logging and metrics.
	Name() string
}

// CNIMobilitySelector picks the correct IPHandoffStrategy based on the CNI plugin
// detected by the node agent and stored in NMC.spec.networkCapability.cniPlugin.
type CNIMobilitySelector struct {
	KubeClient    kubernetes.Interface
	DynamicClient dynamic.Interface
}

// Select returns the strategy appropriate for the detected CNI plugin name.
// cniPlugin matches what ProbeNetworkCapability() writes to NMC (e.g. "ovn-kubernetes",
// "calico", "cilium", "flannel").
func (s *CNIMobilitySelector) Select(ctx context.Context, cniPlugin string) IPHandoffStrategy {
	lower := strings.ToLower(cniPlugin)

	switch {
	case strings.Contains(lower, "ovn"):
		return &OVNKHandoff{DynamicClient: s.DynamicClient}
	case strings.Contains(lower, "calico"):
		return &CalicoHandoff{KubeClient: s.KubeClient}
	default:
		// Gratuitous ARP is the universal fallback but it is a stub in v0.1.
		// CNIs that do not have a dedicated handoff path (Cilium, Flannel, Weave)
		// rely on GARP + reconnect semantics per ADR-0017 (TIER_4 network).
		return &ARPHandoff{}
	}
}
