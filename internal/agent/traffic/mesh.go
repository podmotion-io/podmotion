/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package traffic

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var meshLog = logf.Log.WithName("mesh-sidecar")

// MeshType identifies the detected service mesh implementation.
// +kubebuilder:validation:Enum=Istio;Linkerd;None
type MeshType string

const (
	MeshTypeNone    MeshType = "None"
	MeshTypeIstio   MeshType = "Istio"
	MeshTypeLinkerd MeshType = "Linkerd"
)

// MeshSidecarVerifier implements Verifier and provides mesh-aware traffic
// control primitives. In v0.1/v0.2 service mesh is optional (ADR-0021);
// for multi-cluster (M14+) it becomes the required traffic sync layer.
//
// ShiftTraffic and DrainViaMesh are stubs in M14 — the xDS control-plane
// integration lands in a later milestone once the WAN checkpoint path is stable.
type MeshSidecarVerifier struct{}

var _ Verifier = (*MeshSidecarVerifier)(nil)

// DetectMesh inspects the pod's container list for well-known sidecar names.
// Returns the mesh type and true when a sidecar is found.
func (m *MeshSidecarVerifier) DetectMesh(pod *corev1.Pod) (MeshType, bool) {
	for _, c := range pod.Spec.Containers {
		switch c.Name {
		case "istio-proxy":
			return MeshTypeIstio, true
		case "linkerd-proxy":
			return MeshTypeLinkerd, true
		}
	}
	return MeshTypeNone, false
}

// ShiftTraffic stubs a weighted traffic shift via the mesh xDS control plane.
// percentage must be in [0, 100]; 100 means all traffic goes to destPodIP.
//
// Real implementation will call the Istiod / Linkerd control-plane API to
// update VirtualService weights or ServiceProfile traffic-split policies.
func (m *MeshSidecarVerifier) ShiftTraffic(_ context.Context, srcPodIP, destPodIP string, percentage int) error {
	if percentage < 0 || percentage > 100 {
		return fmt.Errorf("percentage must be 0-100, got %d", percentage)
	}
	meshLog.Info("stub: would shift traffic via mesh xDS update",
		"srcPodIP", srcPodIP, "destPodIP", destPodIP, "percentage", percentage)
	return nil
}

// DrainViaMesh stubs a graceful connection drain via the Envoy drain signal.
// Real implementation will POST to the Envoy admin /drain_listeners endpoint
// on the sidecar or trigger a ServiceAccount-scoped drain via the mesh API.
func (m *MeshSidecarVerifier) DrainViaMesh(_ context.Context, srcPodIP string) error {
	meshLog.Info("stub: would drain connections via Envoy drain signal", "srcPodIP", srcPodIP)
	return nil
}

// Verify satisfies the Verifier interface. For mesh mode it delegates to
// ShiftTraffic(100%) then DrainViaMesh after the destination pod IP is ready.
func (m *MeshSidecarVerifier) Verify(ctx context.Context, req VerifyRequest) error {
	if err := m.ShiftTraffic(ctx, req.SourcePodIP, req.DestPodIP, 100); err != nil {
		return fmt.Errorf("mesh traffic shift failed: %w", err)
	}
	if err := m.DrainViaMesh(ctx, req.SourcePodIP); err != nil {
		return fmt.Errorf("mesh drain failed: %w", err)
	}
	return nil
}
