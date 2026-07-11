/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package iphandoff: CiliumHandoff in this file was dead code on the preflight-gated
// path prior to ADR-0322. ADR-0313 refused migrations on Cilium nodes at preflight
// (CNICompatible=False/CNIUnsupported). ADR-0322 introduces the real ipcache/
// CiliumEndpoint readiness check (replacing the pod-IP proxy below) and wires a
// concrete call site into injectIPHandoff (podmigration_controller.go:3813), making
// this file reachable again.
package iphandoff

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	ciliumEndpointPollInterval = 1 * time.Second
	ciliumEndpointReadyTimeout = 30 * time.Second
)

// ciliumEndpointGVR is the cilium.io/v2 CiliumEndpoint resource, cluster-scoped-name
// but namespaced object (same namespace as the pod it tracks).
var ciliumEndpointGVR = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumendpoints",
}

// CiliumHandoff implements IPHandoffStrategy for Cilium CNI clusters.
//
// IP ownership model (ADR-0046 rev): the destination pod is annotated with
// ipam.cilium.io/ip at admission time, forcing Cilium's CNI ADD to assign the
// original source pod IP. Requires Cilium multi-pool or CRD IPAM mode.
//
// After restore, CiliumEndpoint regeneration is required so that Cilium's eBPF
// ipcache and kube-proxy-replacement tables are updated for the new node location.
// ADR-0322: WaitForCiliumEndpointReady polls the CiliumEndpoint CRD directly via
// DynamicClient rather than treating pod IP assignment as a proxy for endpoint
// regeneration — the eBPF hold/reachability gate must not be released until
// status.state=="ready" AND status.identity.id!=0 (non-zero identity confirms
// ipcache programming, not just object creation).
//
// Note: kube-proxy-replacement=strict mode may conflict with the PodMotion XDP
// bridge. When detected, the agent falls back to TC ingress for the bridge.
type CiliumHandoff struct {
	KubeClient    kubernetes.Interface
	DynamicClient dynamic.Interface
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

// WaitForCiliumEndpointReady polls the cilium.io/v2 CiliumEndpoint object (same name/
// namespace as the destination pod — Cilium mirrors pod identity) via DynamicClient
// until status.state=="ready" AND status.identity.id!=0. Fail-closed: any lookup error
// other than "not yet created" is returned immediately (never silently falls back to
// the old pod-IP proxy). Read-only — cilium-agent is the sole writer of this object.
func (c *CiliumHandoff) WaitForCiliumEndpointReady(ctx context.Context, namespace, podName string) error {
	if c.DynamicClient == nil {
		return fmt.Errorf("WaitForCiliumEndpointReady: DynamicClient is nil (not wired)")
	}
	deadline := time.Now().Add(ciliumEndpointReadyTimeout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for CiliumEndpoint %s/%s to become ready", namespace, podName)
		}

		obj, err := c.DynamicClient.Resource(ciliumEndpointGVR).Namespace(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			// Fail-closed on any error other than the object not yet existing —
			// a transient API error must not be swallowed into a false-ready result.
			if !isNotFound(err) {
				return fmt.Errorf("CiliumEndpoint lookup error for %s/%s: %w", namespace, podName, err)
			}
			// Not found yet — cilium-agent has not created the endpoint object.
			// Fall through to the poll-sleep and retry until the deadline.
		} else if ready(obj) {
			return nil
		}

		time.Sleep(ciliumEndpointPollInterval)
	}
}

// ready reports whether the given CiliumEndpoint unstructured object has
// status.state=="ready" and a non-zero status.identity.id (ipcache programmed).
func ready(obj *unstructured.Unstructured) bool {
	state, found, err := unstructured.NestedString(obj.Object, "status", "state")
	if err != nil || !found || state != "ready" {
		return false
	}
	identityID, found, err := unstructured.NestedInt64(obj.Object, "status", "identity", "id")
	if err != nil || !found || identityID == 0 {
		return false
	}
	return true
}

// isNotFound is a narrow, dependency-free NotFound check for the dynamic client's
// unstructured error path (avoids importing apierrors solely for this one check —
// kept local since this file otherwise has no other apimachinery errors dependency).
func isNotFound(err error) bool {
	type statusErr interface {
		Status() metav1.Status
	}
	if se, ok := err.(statusErr); ok {
		return se.Status().Reason == metav1.StatusReasonNotFound
	}
	return false
}

func (c *CiliumHandoff) Name() string { return "cilium-ipam-pin" }
