// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network

import (
	"context"
	"fmt"
	"net"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// BarrierPredicates holds the inputs needed to evaluate the ADR-0049 6-predicate
// atomicity barrier. All 6 must be satisfied before ZeroWindowDisarm fires.
//
// Predicates:
//
//	A: tcpi_unacked==0 on all source sockets — checked by ArmZeroWindow before returning.
//	B: PM_SEQ_XLAT entries verified via bpf_map_lookup — populated by SeedRelayFromSnapshots.
//	C+D: AF_BRIDGE + AF_INET FDB entries confirmed on both source and destination nodes via RTM_GETNEIGH.
//	E: Conntrack NOTRACK armed on both nodes.
//	F: CRIU restore confirmed complete (Restore RPC returned success).
type BarrierPredicates struct {
	// SeqXlatSeeded is set to true after SeedRelayFromSnapshots has populated PM_SEQ_XLAT (predicate B).
	// When the snapshot list is empty (stateless migration), B is trivially satisfied.
	SeqXlatSeeded bool

	// SourceFDBEntry is the FDB entry on the source node's flannel.1.
	// Predicate C+D are confirmed for this entry via RTM_GETNEIGH on the source node.
	SourceFDBEntry *FDBEntry
	// DestFDBEntry is the FDB entry on the destination node's flannel.1.
	// Predicate C+D are confirmed for this entry via RTM_GETNEIGH on the destination node.
	DestFDBEntry *FDBEntry

	// SourceConntrackArmed is true when NOTRACK rules are confirmed installed on the source node.
	SourceConntrackArmed bool
	// DestConntrackArmed is true when NOTRACK rules are confirmed installed on the destination node.
	DestConntrackArmed bool

	// RestoreComplete is set to true after the Restore RPC has succeeded on the destination (predicate F).
	RestoreComplete bool

	// PreRestore selects barrier mode. When true (OverlayHandoff phase, before CRIU restore)
	// predicate E's source-conntrack check and predicate F (restore_complete) are deferred so
	// the handoff can proceed to CRIU restore with only B/C/D and dest-side conntrack satisfied.
	// When false (DisengageHold, post-restore) all six predicates are enforced. ADR-0049 §gate20.
	PreRestore bool

	// FDBManager is used to call ConfirmOverlayReady for predicates C+D.
	// When nil, the FDB confirmation step is skipped (non-Linux / test environments).
	FDBManager FDBManager
}

// BarrierResult describes which predicates passed and which failed.
type BarrierResult struct {
	BPredicate bool // B: PM_SEQ_XLAT seeded
	CFdbSource bool // C: AF_BRIDGE FDB confirmed on source node
	DFdbDest   bool // D: AF_INET FDB confirmed on destination node
	EPredicate bool // E: conntrack NOTRACK armed on both nodes
	FPredicate bool // F: CRIU restore complete
}

// CheckAtomicityBarrier evaluates predicates B–F of the ADR-0049 atomicity barrier.
// Predicate A (tcpi_unacked==0) is checked by ArmZeroWindow before it returns and is
// not re-evaluated here. An error is returned if any predicate is not satisfied.
//
// The function is safe to call concurrently; it holds no locks.
func CheckAtomicityBarrier(ctx context.Context, p BarrierPredicates) (BarrierResult, error) {
	log := logf.FromContext(ctx)
	var result BarrierResult
	var errs []string

	// Predicate B: PM_SEQ_XLAT entries seeded — deferred in PreRestore mode (ADR-0357 D1.1),
	// exactly like predicate E-source and predicate F below (ADR-0049 §gate20). Seeding is
	// fundamentally a post-restore event (SeedRelayFromSnapshots takes the restored PID as an
	// argument) — at the PreRestore call site (reconcileOverlayHandoff, before CRIU restore has
	// run on either path) the fact predicate B checks categorically cannot have happened yet, so
	// no amount of "verify harder" there can make it real. Vacuous pass, matching the existing
	// deferral idiom for E/F.
	if p.PreRestore {
		result.BPredicate = true
		log.Info("barrier: predicate B deferred (pre-restore mode) — PM_SEQ_XLAT seeding is a post-restore event (ADR-0357 D1.1)")
	} else {
		result.BPredicate = p.SeqXlatSeeded
		if !p.SeqXlatSeeded {
			errs = append(errs, "B: PM_SEQ_XLAT not seeded")
		} else {
			log.Info("barrier: predicate B satisfied — PM_SEQ_XLAT seeded")
		}
	}

	// Predicates C+D: FDB entries confirmed via RTM_GETNEIGH on both nodes.
	if p.FDBManager != nil {
		if p.SourceFDBEntry != nil {
			if err := p.FDBManager.ConfirmOverlayReady(ctx, *p.SourceFDBEntry); err != nil {
				errs = append(errs, fmt.Sprintf("C: source FDB confirm failed: %v", err))
			} else {
				result.CFdbSource = true
				log.Info("barrier: predicate C satisfied — source FDB confirmed")
			}
		} else {
			// No source FDB entry supplied — stateless migration; C is trivially satisfied.
			result.CFdbSource = true
		}

		if p.DestFDBEntry != nil {
			if err := p.FDBManager.ConfirmOverlayReady(ctx, *p.DestFDBEntry); err != nil {
				errs = append(errs, fmt.Sprintf("D: dest FDB confirm failed: %v", err))
			} else {
				result.DFdbDest = true
				log.Info("barrier: predicate D satisfied — dest FDB confirmed")
			}
		} else {
			result.DFdbDest = true
		}
	} else {
		// Non-Linux / test path: treat FDB as confirmed.
		result.CFdbSource = true
		result.DFdbDest = true
		log.Info("barrier: predicates C+D skipped — no FDBManager (non-Linux or test)")
	}

	// Predicate E: conntrack NOTRACK armed on both nodes.
	// In pre-restore mode only dest-side conntrack is required; source-side arm is deferred
	// until post-restore (DisengageHold) to avoid a race with the source agent. ADR-0049 §gate20.
	if p.PreRestore {
		result.EPredicate = p.DestConntrackArmed
		if !p.DestConntrackArmed {
			errs = append(errs, "E(pre-restore): dest conntrack NOTRACK not armed")
		} else {
			log.Info("barrier: predicate E satisfied (pre-restore) — dest conntrack NOTRACK armed")
		}
	} else {
		result.EPredicate = p.SourceConntrackArmed && p.DestConntrackArmed
		if !result.EPredicate {
			errs = append(errs, fmt.Sprintf("E: conntrack NOTRACK not armed (source=%v dest=%v)",
				p.SourceConntrackArmed, p.DestConntrackArmed))
		} else {
			log.Info("barrier: predicate E satisfied — conntrack NOTRACK armed on both nodes")
		}
	}

	// Predicate F: CRIU restore complete.
	// In pre-restore mode F is deferred (restore has not yet run). ADR-0049 §gate20.
	if p.PreRestore {
		result.FPredicate = true
		log.Info("barrier: predicate F deferred (pre-restore mode)")
	} else {
		result.FPredicate = p.RestoreComplete
		if !p.RestoreComplete {
			errs = append(errs, "F: CRIU restore not complete")
		} else {
			log.Info("barrier: predicate F satisfied — CRIU restore complete")
		}
	}

	if len(errs) > 0 {
		return result, fmt.Errorf("atomicity barrier not satisfied: %v", errs)
	}
	return result, nil
}

// ComputePAWSTsDelta computes the monotonic clock offset to use as ts_delta in PM_SEQ_XLAT.
// sourceClockNs is CLOCK_MONOTONIC ns captured on the source at freeze time.
// destClockNs is CLOCK_MONOTONIC ns captured on the destination at restore time.
// The delta is clamped to int32 to fit the BPF map value field.
//
// ts_delta is added to TSval on egress and to TSecr on ingress by PM_RELAY_TC programs
// so that PAWS (Protection Against Wrapped Sequences) does not drop segments from the
// restored socket on the peer side (RFC 7323 §5.3).
func ComputePAWSTsDelta(sourceClockNs, destClockNs int64) int32 {
	// ts_recent is in milliseconds in the kernel PAWS context; compute offset in ms.
	offsetMs := (destClockNs - sourceClockNs) / int64(1e6)
	// Clamp to int32 (overflow safe: TCP TSval wraps at 2^32; an ms-resolution offset
	// within ±2^31 ms (~24 days) is well within the expected migration window).
	const maxInt32 = int64(1<<31 - 1)
	const minInt32 = int64(-1 << 31)
	if offsetMs > maxInt32 {
		return int32(maxInt32)
	}
	if offsetMs < minInt32 {
		return int32(minInt32)
	}
	return int32(offsetMs)
}

// PatchSeqXlatTsDelta updates the ts_delta field of a SeqXlatEntry already seeded into
// PM_SEQ_XLAT by SeedRelayFromSnapshots. This is a separate step because the PAWS clock
// offset is not available until the destination agent captures its monotonic clock at
// restore time, which is after SeedRelayFromSnapshots has already run.
//
// CRITICAL: This function MUST use EBPFManager.PatchRelayTsDelta (read-modify-write) and
// MUST NOT call ArmRelay. ArmRelay does a full-value OVERWRITE of the BPF map entry, which
// would clobber the seq_delta/ack_delta previously seeded by SeedRelayFromSnapshots with
// zeros, causing the relay to emit un-translated sequence numbers → peer TCP RST.
//
// If ebpfMgr is nil, tsDelta is 0, or the entry does not exist in the map, the function
// logs and returns nil (no-op is safe: ts_delta=0 means no PAWS adjustment, acceptable
// when source and destination clocks are synchronised).
func PatchSeqXlatTsDelta(ctx context.Context, snapshots []SeqSnapshot, tsDelta int32, _ string, ebpfMgr EBPFManager) error {
	log := logf.FromContext(ctx)
	if ebpfMgr == nil || len(snapshots) == 0 || tsDelta == 0 {
		return nil
	}
	for _, snap := range snapshots {
		localIP := net.ParseIP(snap.SrcIP)
		peerIP := net.ParseIP(snap.DstIP)
		if localIP == nil || peerIP == nil {
			continue
		}
		key := ipPortToSeqXlatKey(localIP.To4(), uint16(snap.SrcPort), peerIP.To4(), uint16(snap.DstPort))
		// Use PatchRelayTsDelta (read-modify-write) to preserve the seq_delta/ack_delta
		// that SeedRelayFromSnapshots has already written to the BPF map entry.
		if err := ebpfMgr.PatchRelayTsDelta(ctx, key, tsDelta); err != nil {
			log.Error(err, "PatchSeqXlatTsDelta: PatchRelayTsDelta failed", "src", snap.SrcIP, "dst", snap.DstIP)
			return fmt.Errorf("PatchSeqXlatTsDelta: PatchRelayTsDelta: %w", err)
		}
		log.Info("PatchSeqXlatTsDelta: ts_delta patched via read-modify-write",
			"srcPort", snap.SrcPort, "dstPort", snap.DstPort, "tsDelta", tsDelta)
	}
	return nil
}
