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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
// ADR-0322 (strengthened per ADR-0324 verification check C, sprint46B2): ConfirmEndpointOwnsPreservedIP
// polls the CiliumEndpoint CRD directly via DynamicClient rather than treating pod IP assignment
// as a proxy for endpoint regeneration — the cross-node reachability gate is released only when
// status.state=="ready" AND status.identity.id!=0 (non-zero identity confirms ipcache
// programming, not just object creation) AND status.networking.addressing advertises the preserved
// IP (confirming the ipam.cilium.io/ip pin was actually honored, not silently reassigned). This is
// the AUTHORITATIVE cross-node dataplane read that retires the ADR-0210 source-node nonce
// round-trip (see podmigration_controller.go tryEstablishCiliumDataplaneReachability).
//
// Note: kube-proxy-replacement=strict mode may conflict with the PodMotion XDP
// bridge. When detected, the agent falls back to TC ingress for the bridge.
type CiliumHandoff struct {
	KubeClient    kubernetes.Interface
	DynamicClient dynamic.Interface
	// ReadyTimeout / PollInterval override the poll bounds for ConfirmEndpointOwnsPreservedIP.
	// Zero means use the package defaults (ciliumEndpointReadyTimeout / ciliumEndpointPollInterval).
	// Set by tests to keep them fast and deterministic; production leaves them zero.
	ReadyTimeout time.Duration
	PollInterval time.Duration
}

func (c *CiliumHandoff) readyTimeout() time.Duration {
	if c.ReadyTimeout > 0 {
		return c.ReadyTimeout
	}
	return ciliumEndpointReadyTimeout
}

func (c *CiliumHandoff) pollInterval() time.Duration {
	if c.PollInterval > 0 {
		return c.PollInterval
	}
	return ciliumEndpointPollInterval
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

// ConfirmEndpointOwnsPreservedIP polls the replacement pod's cilium.io/v2 CiliumEndpoint until
// cilium-agent's OWN status write-back proves the preserved IP has actually been programmed onto
// the replacement endpoint on the destination node:
//
//	status.state == "ready"                              (endpoint regenerated, datapath programmed)
//	status.identity.id != 0                              (security identity allocated -> ipcache published)
//	status.networking.addressing[].ipv4 CONTAINS wantIP  (the endpoint OWNS the preserved IP)
//
// This is the AUTHORITATIVE cross-node dataplane fact, read directly from the CNI's source of
// truth (invariant #10 / SUBSTRATE-PRIMITIVE BIAS: read the write-back, do not infer with a probe).
// cilium-agent is the sole writer of this object, so a source-node agent cannot synthesize it
// (the anti-spoof property the ADR-0210 nonce round-trip was reaching for), and — unlike a
// source-node dial — the read is not confounded by ADR-0012 holding the source pod alive with the
// same IP on the source node. It STRENGTHENS ADR-0322's ready-only check: a ready endpoint that
// received a DIFFERENT IP (ipam.cilium.io/ip pin not honored under cluster-pool — ADR-0324
// verification check C) is correctly rejected here instead of falsely crediting a dataplane that never moved
// the IP. Returns the node IP the endpoint lives on (observability) and nil ONLY when all three
// predicates hold; otherwise a classified, fail-closed error whose message carries a stable token
// ("lookup error" | "does not advertise preserved IP" | "not ready") the caller maps to a Reason.
func (c *CiliumHandoff) ConfirmEndpointOwnsPreservedIP(ctx context.Context, namespace, podName, wantIP string) (string, error) {
	deadline := time.Now().Add(c.readyTimeout())
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timeout waiting for CiliumEndpoint %s/%s to be ready and own preserved IP %s (not ready within timeout)",
				namespace, podName, wantIP)
		}

		node, ok, err := c.EndpointReadyAdvertisesIP(ctx, namespace, podName, wantIP)
		if err != nil {
			// A DECIDED negative (nil DynamicClient / empty wantIP / real lookup error / ready-but-
			// wrong-IP) — return immediately rather than polling out the deadline. This preserves the
			// original wrapper's early-return-on-decided-error behavior byte-for-byte.
			return "", err
		}
		if ok {
			return node, nil
		}
		// Not yet programmed (object not found or not ready) — transient; retry until deadline.
		time.Sleep(c.pollInterval())
	}
}

// EndpointReadyAdvertisesIP is the SINGLE-SHOT core of the CiliumEndpoint readiness read (ADR-0405
// 3B): it issues exactly ONE Get and returns immediately, with no internal poll loop and no
// deadline. It answers the class question — "has cilium-agent programmed this endpoint's dataplane
// so wantIP is cluster-routable?" — once, so a caller can compose it with its own retry cadence
// (e.g. controller-runtime RequeueAfter on the reconcile loop, which must NOT be blocked for
// seconds per pass). ConfirmEndpointOwnsPreservedIP above is the blocking-poll wrapper around this
// core, retained for callers (the pod-IP-pin dataplane-reachability path) that want to block until
// ready. Both callers therefore read through this single source-of-truth core.
//
// Returns:
//   - (node, true, nil)  — programmed: status.state=="ready" AND status.identity.id!=0 AND
//     status.networking.addressing advertises wantIP.
//   - ("", false, nil)   — NOT YET programmed this pass (object missing, or not ready). Transient;
//     the caller should retry / requeue.
//   - ("", false, err)   — a DECIDED negative that must not be retried into a false-ready: nil
//     DynamicClient, empty wantIP, a real API lookup error, or ready-but-advertising-a-different-IP
//     (the unhonored ipam.cilium.io/ip pin, ADR-0324 verification check C). Fail-closed.
func (c *CiliumHandoff) EndpointReadyAdvertisesIP(ctx context.Context, namespace, podName, wantIP string) (string, bool, error) {
	if c.DynamicClient == nil {
		return "", false, fmt.Errorf("EndpointReadyAdvertisesIP: DynamicClient is nil (not wired)")
	}
	if wantIP == "" {
		return "", false, fmt.Errorf("EndpointReadyAdvertisesIP: wantIP is empty")
	}

	obj, err := c.DynamicClient.Resource(ciliumEndpointGVR).Namespace(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		// Fail-closed on any error other than the object not yet existing — a transient API
		// error must not be swallowed into a false-ready result.
		if !isNotFound(err) {
			return "", false, fmt.Errorf("CiliumEndpoint lookup error for %s/%s: %w", namespace, podName, err)
		}
		// Not found yet — cilium-agent has not created the endpoint object.
		return "", false, nil
	}
	if !ready(obj) {
		// Object exists but is still regenerating / has no allocated identity.
		return "", false, nil
	}
	node, _, _ := unstructured.NestedString(obj.Object, "status", "networking", "node")
	if endpointOwnsIP(obj, wantIP) {
		return node, true, nil
	}
	// Ready with a non-zero identity but NOT advertising wantIP. This is a DECIDED outcome, not a
	// transient: cilium-agent only marks an endpoint ready after its addressing is populated, so the
	// IP it owns is settled. Under cluster-pool IPAM this is the expected result of an unhonored
	// ipam.cilium.io/ip pin (ADR-0324 verification check C). Return immediately with a specific, actionable
	// error rather than crediting a dataplane that never programmed wantIP.
	return "", false, fmt.Errorf("CiliumEndpoint %s/%s is ready on node %s but does not advertise preserved IP %s (addressing=%v) — ipam.cilium.io/ip pin not honored",
		namespace, podName, node, wantIP, endpointAddresses(obj))
}

// endpointAddresses returns every non-empty ipv4 address in the CiliumEndpoint's
// status.networking.addressing list (cilium-agent's record of the IPs the endpoint owns).
func endpointAddresses(obj *unstructured.Unstructured) []string {
	var out []string
	addrs, found, err := unstructured.NestedSlice(obj.Object, "status", "networking", "addressing")
	if err != nil || !found {
		return out
	}
	for _, a := range addrs {
		m, ok := a.(map[string]interface{})
		if !ok {
			continue
		}
		if v4, ok := m["ipv4"].(string); ok && v4 != "" {
			out = append(out, v4)
		}
	}
	return out
}

// endpointOwnsIP reports whether wantIP appears in the endpoint's status.networking.addressing.
func endpointOwnsIP(obj *unstructured.Unstructured, wantIP string) bool {
	for _, ip := range endpointAddresses(obj) {
		if ip == wantIP {
			return true
		}
	}
	return false
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
