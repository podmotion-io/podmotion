/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package iphandoff

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ARPHandoff is a stub for gratuitous ARP (IPv4) and unsolicited NDP (IPv6) announcement.
// The real implementation requires a raw socket or eBPF program running on the destination
// node — both need elevated privileges not available in the controller binary.
// Full implementation is deferred to M10 (eBPF node agent integration).
type ARPHandoff struct{}

// SendGratuitousARP logs the intent and returns nil.
// In M10 this will invoke the node agent's gRPC endpoint to send the GARP/NDP packet
// directly from the destination node's network namespace.
func (a *ARPHandoff) SendGratuitousARP(ctx context.Context, destNode, podIP string) error {
	logger := log.FromContext(ctx)
	// Intentional stub: real GARP requires raw socket on the node (M10 eBPF path).
	logger.Info("would send GARP from destNode for podIP", "destNode", destNode, "podIP", podIP)
	return nil
}

func (a *ARPHandoff) Name() string { return "garp-stub" }
