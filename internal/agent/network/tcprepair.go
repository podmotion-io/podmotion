/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// TCPSocketState captures the in-kernel state of a single TCP connection
// sufficient to re-establish it on the destination node without a handshake.
//
// ADR-0017: This type is defined in M10 to lock down the interface shape for
// design review; the actual syscall implementation (TCP_REPAIR + SO_GET_FILTER)
// ships in v0.2.
type TCPSocketState struct {
	// SrcIP / DstIP are string-formatted IPv4 or IPv6 addresses.
	SrcIP string
	DstIP string

	SrcPort uint16
	DstPort uint16

	// SeqNum is the send sequence number at the moment of capture.
	SeqNum uint32
	// AckNum is the receive acknowledgement number at the moment of capture.
	AckNum uint32

	// TimestampDelta is added to the kernel's clock_gettime(CLOCK_MONOTONIC) on
	// the destination to reconstruct the original PAWS timestamp seen by the peer.
	// Computed as: (src_node_boot_ts + tcp_ts_val) - dest_node_boot_ts.
	// A zero value disables timestamp patching (safe for peers that ignore timestamps).
	TimestampDelta int64
}

// TCPRepairManager is the interface for exporting/importing live TCP socket state
// via the Linux TCP_REPAIR socket option.
//
// Export is called on the SOURCE node immediately after CRIU freeze (while the
// process is still checkpointed and all sockets are in CLOSE_WAIT from the
// kernel's perspective — TCP_REPAIR prevents RST on close).
//
// Import is called on the DESTINATION node after CRIU restore, before the eBPF
// bridge is disarmed, so that the re-injected sockets match the state that the
// remote peers still see.
type TCPRepairManager interface {
	// ExportSocketStates reads TCP_REPAIR state for all sockets owned by the
	// process with the given PID.  The PID must be in the container network
	// namespace — call nsenter or use setns before invoking.
	ExportSocketStates(ctx context.Context, pid int) ([]TCPSocketState, error)

	// ImportSocketStates applies the exported states to newly created sockets
	// in the destination container's network namespace.  The caller must have
	// already entered that namespace.
	ImportSocketStates(ctx context.Context, states []TCPSocketState) error
}

// TCPRepairManagerStub satisfies TCPRepairManager without touching any real sockets.
// All v0.1 migrations use this implementation; it is replaced by the kernel syscall
// implementation in v0.2 when TCP preservation gates are opened.
type TCPRepairManagerStub struct{}

func (s *TCPRepairManagerStub) ExportSocketStates(ctx context.Context, pid int) ([]TCPSocketState, error) {
	logf.FromContext(ctx).Info("tcprepair stub: ExportSocketStates (v0.2 feature)", "pid", pid)
	// Return empty slice — no socket state preserved in TIER_4 (cold migration).
	return nil, nil
}

func (s *TCPRepairManagerStub) ImportSocketStates(ctx context.Context, states []TCPSocketState) error {
	logf.FromContext(ctx).Info("tcprepair stub: ImportSocketStates (v0.2 feature)", "count", len(states))
	return nil
}
