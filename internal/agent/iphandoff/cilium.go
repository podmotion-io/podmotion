/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package iphandoff: CiliumHandoff in this file is dead code on the current
// preflight-gated path. ADR-0082 names it the v1.1 starting point for a future
// Cilium IP-mobility implementation; ADR-0313 removed "cilium" from
// ipMobilitySupported's supported-CNI case list and added a CNICompatible=False/
// CNIUnsupported NodeMigrationCapacity status condition at agent registration
// (internal/agent/nmcregistrar/registrar.go), so migrations on Cilium nodes are
// now refused at preflight before any code in this file would run. Do not delete —
// retained as the v1.1 starting point per ADR-0082.
package iphandoff

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const (
	ciliumEndpointPollInterval = 1 * time.Second
	ciliumEndpointReadyTimeout = 30 * time.Second
)

// CiliumHandoff implements IPHandoffStrategy for Cilium CNI clusters.
//
// IP ownership model (ADR-0046 rev): the destination pod is annotated with
// ipam.cilium.io/ip at admission time, forcing Cilium's CNI ADD to assign the
// original source pod IP. Requires Cilium multi-pool or CRD IPAM mode.
//
// After restore, CiliumEndpoint regeneration is required so that Cilium's eBPF
// ipcache and kube-proxy-replacement tables are updated for the new node location.
// The eBPF hold must not be released until CiliumEndpoint.Status.State == "ready".
//
// Note: kube-proxy-replacement=strict mode may conflict with the PodMotion XDP
// bridge. When detected, the agent falls back to TC ingress for the bridge.
type CiliumHandoff struct {
	KubeClient kubernetes.Interface
}

// AnnotateDestPodIPAM patches the destination pod with the Cilium IPAM annotation
// that forces CNI ADD to assign the specified IP. Must be called before the pod
// sandbox starts. Requires Cilium multi-pool or CRD IPAM mode on the cluster.
func (c *CiliumHandoff) AnnotateDestPodIPAM(ctx context.Context, namespace, destPodName, podIP string) error {
	patch := fmt.Sprintf(`{"metadata":{"annotations":{"ipam.cilium.io/ip":%q}}}`, podIP)
	_, err := c.KubeClient.CoreV1().Pods(namespace).Patch(
		ctx,
		destPodName,
		types.MergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("annotate pod %s/%s with Cilium IPAM: %w", namespace, destPodName, err)
	}
	return nil
}

// WaitForCiliumEndpointReady polls the destination pod's IP assignment until Cilium
// has regenerated the endpoint and updated the eBPF ipcache. Uses pod IP as proxy
// for endpoint regeneration complete (full CiliumEndpoint CR polling is M9 work).
//
// The full M9 implementation will watch CiliumEndpoint.Status.State == "ready"
// via the Cilium CRD client. For now, pod IP assignment is a sufficient proxy.
func (c *CiliumHandoff) WaitForCiliumEndpointReady(ctx context.Context, namespace, podName string) error {
	deadline := time.Now().Add(ciliumEndpointReadyTimeout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for Cilium endpoint %s/%s to become ready", namespace, podName)
		}

		pod, err := c.KubeClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err == nil && pod.Status.PodIP != "" && pod.Status.Phase != "Pending" {
			return nil
		}

		time.Sleep(ciliumEndpointPollInterval)
	}
}

func (c *CiliumHandoff) Name() string { return "cilium-ipam-pin" }
