/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package iphandoff

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// bgpConvergenceHeuristic is the time we wait after annotating the node for BGP
// to propagate the /32 host route to peers. There is no deterministic API to
// confirm convergence without deploying a BGP speaker client; 30s covers most
// deployments with <50 BGP peers. M10 will replace this with a Calico Felix API probe.
const bgpConvergenceHeuristic = 30 * time.Second

// CalicoHandoff implements IPHandoffStrategy for Calico BGP clusters.
// It annotates the destination node to trigger a BGP /32 advertisement for the
// pod IP, then waits for convergence before declaring handoff complete.
type CalicoHandoff struct {
	KubeClient kubernetes.Interface
}

// AdvertiseOnDest annotates the destination node with the pod IP so that Calico's
// Felix/BIRD daemon picks it up and advertises a /32 host route to BGP peers.
// The annotation key bgp.calico.io/announce-host-route is read by the Calico node agent.
func (c *CalicoHandoff) AdvertiseOnDest(ctx context.Context, destNodeName, podIP string) error {
	patch := fmt.Sprintf(`{"metadata":{"annotations":{"bgp.calico.io/announce-host-route":%q}}}`, podIP)
	_, err := c.KubeClient.CoreV1().Nodes().Patch(
		ctx,
		destNodeName,
		types.MergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("annotate node %s for BGP /32 route %s: %w", destNodeName, podIP, err)
	}

	// Wait for BGP convergence heuristic. This is a deliberate sleep — there is no
	// synchronous API to confirm all BGP peers have received the new route.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(bgpConvergenceHeuristic):
	}

	return nil
}

// RemoveFromSource removes the BGP /32 advertisement annotation from the source node.
// Called after TrafficVerified=true so the old route is withdrawn cleanly.
func (c *CalicoHandoff) RemoveFromSource(ctx context.Context, sourceNodeName, podIP string) error {
	// Setting the annotation value to empty string signals Calico to withdraw the route.
	// A full annotation removal would also work but this is idempotent on re-runs.
	patch := `{"metadata":{"annotations":{"bgp.calico.io/announce-host-route":null}}}`
	_, err := c.KubeClient.CoreV1().Nodes().Patch(
		ctx,
		sourceNodeName,
		types.MergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("remove BGP /32 annotation from node %s: %w", sourceNodeName, err)
	}
	return nil
}

func (c *CalicoHandoff) Name() string { return "calico-bgp-host-route" }
