/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package estimation

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// GRPCProber implements Prober by calling the EstimateCheckpoint RPC on the
// node agent running on the pod's source node. This replaces StubProber in M5.
//
// The RPC performs one short pre-dump round (CRIU --track-mem, no image written)
// and returns the real dirty page count and elapsed time from the agent.
type GRPCProber struct {
	// AgentPool provides gRPC connections keyed by node name.
	AgentPool *agentclient.AgentClientPool
	// SampleSecs is the sampling window passed to the agent (default 2s).
	SampleSecs int32
}

// Probe calls EstimateCheckpoint on the agent for the pod's node and maps
// the response to a Probe struct.
func (g *GRPCProber) Probe(ctx context.Context, pod *corev1.Pod, _ string) (Probe, error) {
	if g.AgentPool == nil {
		return Probe{}, fmt.Errorf("GRPCProber: AgentPool is nil")
	}

	nodeName := pod.Spec.NodeName
	if nodeName == "" {
		return Probe{}, fmt.Errorf("GRPCProber: pod %s/%s has no NodeName", pod.Namespace, pod.Name)
	}

	agentCl, err := g.AgentPool.ForNode(ctx, nodeName)
	if err != nil {
		return Probe{}, fmt.Errorf("GRPCProber: agent connection for node %q: %w", nodeName, err)
	}

	sampleSecs := g.SampleSecs
	if sampleSecs <= 0 {
		sampleSecs = 2
	}

	resp, err := agentCl.EstimateCheckpoint(ctx, &agentpb.EstimateCheckpointRequest{
		PodName:      pod.Name,
		PodNamespace: pod.Namespace,
		SampleSecs:   sampleSecs,
	})
	if err != nil {
		return Probe{}, fmt.Errorf("GRPCProber: EstimateCheckpoint RPC: %w", err)
	}

	// DirtyPageRateMBPerSec * ElapsedMs gives us the dirty MB observed during the sample.
	elapsedMs := int64(sampleSecs) * 1000
	dirtyMB := float64(resp.DirtyPageRateMBPerSec) * float64(sampleSecs)

	return Probe{
		DirtyPagesMB: dirtyMB,
		ElapsedMs:    elapsedMs,
		RSSMb:        float64(resp.EstimatedCheckpointSizeMB),
	}, nil
}
