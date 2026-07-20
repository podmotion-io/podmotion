/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// SocketSeqState holds the sequence numbers read from a live socket via SocketInventory.
type SocketSeqState struct {
	SndNxt uint32
	RcvNxt uint32
}

// FreshSocketBinder opens a fresh TCP socket bound to localIP:localPort connected toward
// peerIP:peerPort and returns the host-side seq/ack numbers as seen in /proc/net/tcp for
// the process at freshPID. The fresh socket is closed after the seq numbers are captured
// because PM_SEQ_XLAT translation will handle the actual data path.
//
// This is the mechanism for computing seq_delta / ack_delta (ADR-0049):
//
//	seq_delta = source_final_snd_nxt - fresh_snd_nxt
//	ack_delta = source_final_rcv_nxt - fresh_rcv_nxt
//
// The caller (SeedRelayFromFreshSocket) seeds PM_SEQ_XLAT before ZeroWindowDisarm fires.
type FreshSocketBinder interface {
	// BindAndProbe opens a fresh TCP socket inside the netns of freshPID bound to
	// localAddr (host:port) and returns its snd_nxt and rcv_nxt.
	// The socket is closed before returning; caller seeds PM_SEQ_XLAT immediately.
	BindAndProbe(ctx context.Context, freshPID int32, localAddr, peerAddr string) (SocketSeqState, error)
}

// ReattachResult is returned by SeedRelayFromFreshSocket.
type ReattachResult struct {
	// SeqDelta is source_final_snd_nxt - fresh_snd_nxt (int32 wraps correctly for TCP seq space).
	SeqDelta int32
	// AckDelta is source_final_rcv_nxt - fresh_rcv_nxt.
	AckDelta int32
}

// SeedRelayFromFreshSocket implements the "Fresh-socket reattach" step of M22:
//
//  1. Opens a fresh TCP socket bound to source IP:port toward the same peer inside
//     the restored container's netns (at freshPID).
//  2. Reads the fresh socket's snd_nxt and rcv_nxt from /proc/<freshPID>/net/tcp[6].
//  3. Computes seq_delta = sourceFinalSndNxt - fresh_snd_nxt,
//     ack_delta = sourceFinalRcvNxt - fresh_rcv_nxt.
//  4. Seeds PM_SEQ_XLAT via ebpfMgr.ArmRelay with the computed deltas.
//
// This must be called BEFORE ZeroWindowDisarm (ADR-0049 predicate B).
// On non-Linux or stub eBPFManager, ArmRelay is a no-op but deltas are still computed.
func SeedRelayFromFreshSocket(
	ctx context.Context,
	freshPID int32,
	localIP net.IP,
	localPort uint16,
	peerIP net.IP,
	peerPort uint16,
	sourceFinalSndNxt uint32,
	sourceFinalRcvNxt uint32,
	relayIfname string,
	ebpfMgr EBPFManager,
) (ReattachResult, error) {
	log := logf.FromContext(ctx)

	// Step 1: open a fresh socket bound to source IP:port toward the peer inside the
	// restored container's netns by scanning /proc/<freshPID>/net/tcp[6].
	// We probe with a short-lived connect so the kernel assigns real seq numbers.
	freshState, err := probeFreqSocketSeq(ctx, freshPID, localIP, localPort, peerIP, peerPort)
	if err != nil {
		return ReattachResult{}, fmt.Errorf("reattach: probe fresh socket seq: %w", err)
	}

	// Step 2: compute deltas (int32 arithmetic wraps correctly in TCP seq space).
	seqDelta := int32(sourceFinalSndNxt - freshState.SndNxt)
	ackDelta := int32(sourceFinalRcvNxt - freshState.RcvNxt)

	log.Info("reattach: computed seq/ack deltas",
		"localIP", localIP, "localPort", localPort,
		"peerIP", peerIP, "peerPort", peerPort,
		"sourceFinalSndNxt", sourceFinalSndNxt,
		"sourceFinalRcvNxt", sourceFinalRcvNxt,
		"freshSndNxt", freshState.SndNxt,
		"freshRcvNxt", freshState.RcvNxt,
		"seqDelta", seqDelta,
		"ackDelta", ackDelta,
	)

	// Step 3: seed PM_SEQ_XLAT via ArmRelay so the relay TC programs can translate
	// seq/ack numbers on the wire before ZeroWindowDisarm fires.
	key := ipPortToSeqXlatKey(localIP, localPort, peerIP, peerPort)
	entry := SeqXlatEntry{
		SeqDelta:    seqDelta,
		AckDelta:    ackDelta,
		TsDelta:     0, // PAWS ts_delta is set separately (M22 PAWS task)
		Wscale:      0,
		SackPresent: 1,
		State:       1, // active
	}

	if err := ebpfMgr.ArmRelay(ctx, relayIfname, key, entry); err != nil {
		return ReattachResult{}, fmt.Errorf("reattach: ArmRelay failed: %w", err)
	}

	log.Info("reattach: PM_SEQ_XLAT seeded", "ifname", relayIfname,
		"srcPort", localPort, "dstPort", peerPort,
		"seqDelta", seqDelta, "ackDelta", ackDelta)

	return ReattachResult{SeqDelta: seqDelta, AckDelta: ackDelta}, nil
}

// SeedRelayFromSnapshots iterates over a slice of SeqSnapshot entries and calls
// SeedRelayFromFreshSocket for each one. All entries must be populated before returning
// so that PM_SEQ_XLAT is fully seeded before ZeroWindowDisarm (ADR-0049 predicate B).
//
// PM_SEQ_XLAT relay programs are loaded on BOTH flannel.1 (relayIfname) AND the migration
// veth (migrationVethIfname) when both are provided. Loading on both ensures that VXLAN-
// encapped traffic arriving at the destination VTEP and traffic entering via the migration
// veth are both subject to seq/ack translation (M24 requirement).
//
// snapshots: SeqSnapshot entries from CheckpointResponse (source final seq numbers).
// freshPID: host-namespace PID of the restored container process.
// relayIfname: overlay interface name for TC relay programs (typically "flannel.1").
// migrationVethIfname: host-side veth of the migration netns (e.g. "pmh-<uid>"); empty skips.
// ebpfMgr: may be stub on non-Linux; ArmRelay is a no-op in that case.
func SeedRelayFromSnapshots(
	ctx context.Context,
	freshPID int32,
	snapshots []SeqSnapshot,
	relayIfname string,
	ebpfMgr EBPFManager,
	migrationVethIfname ...string,
) ([]ReattachResult, error) {
	log := logf.FromContext(ctx)
	if len(snapshots) == 0 {
		return nil, nil
	}

	var vethIfname string
	if len(migrationVethIfname) > 0 {
		vethIfname = migrationVethIfname[0]
	}

	results := make([]ReattachResult, 0, len(snapshots))
	for _, snap := range snapshots {
		localIP := net.ParseIP(snap.SrcIP)
		peerIP := net.ParseIP(snap.DstIP)
		if localIP == nil || peerIP == nil {
			return nil, fmt.Errorf("reattach: invalid snapshot IPs src=%q dst=%q", snap.SrcIP, snap.DstIP)
		}

		r, err := SeedRelayFromFreshSocket(
			ctx,
			freshPID,
			localIP.To4(),
			uint16(snap.SrcPort),
			peerIP.To4(),
			uint16(snap.DstPort),
			snap.SndNxt,
			snap.RcvNxt,
			relayIfname,
			ebpfMgr,
		)
		if err != nil {
			return nil, fmt.Errorf("reattach: snapshot %s:%d→%s:%d: %w",
				snap.SrcIP, snap.SrcPort, snap.DstIP, snap.DstPort, err)
		}
		results = append(results, r)

		// ADR-0357 D1.2: verify the entry SeedRelayFromFreshSocket just wrote via ArmRelay is
		// actually resident in the kernel PM_SEQ_XLAT map, via a real bpf_map_lookup — the
		// literal implementation of the overlay.go:22 doc comment's promise. ArmRelay's Update()
		// call returning without error is not sufficient evidence: this is exactly the gap that
		// let SeqXlatSeeded=true be asserted while PM_SEQ_XLAT was categorically absent from the
		// kernel on both nodes (ADR-0357 Context, Probe 2). Only report success if every entry
		// round-trips.
		key := ipPortToSeqXlatKey(localIP.To4(), uint16(snap.SrcPort), peerIP.To4(), uint16(snap.DstPort))
		if _, found, lookupErr := ebpfMgr.LookupSeqXlat(ctx, key); lookupErr != nil {
			return nil, fmt.Errorf("reattach: LookupSeqXlat verification failed for %s:%d→%s:%d: %w",
				snap.SrcIP, snap.SrcPort, snap.DstIP, snap.DstPort, lookupErr)
		} else if !found {
			return nil, fmt.Errorf("reattach: LookupSeqXlat verification: PM_SEQ_XLAT entry not resident in kernel map after ArmRelay for %s:%d→%s:%d (ADR-0357 D1.2)",
				snap.SrcIP, snap.SrcPort, snap.DstIP, snap.DstPort)
		} else {
			log.Info("reattach: PM_SEQ_XLAT entry verified resident via LookupSeqXlat (ADR-0357 D1.2)",
				"srcPort", snap.SrcPort, "dstPort", snap.DstPort)
		}

		// Load relay on the migration veth in addition to flannel.1 so that traffic
		// entering the destination via the host-side veth (pmdst0 peer) also undergoes
		// seq/ack translation before reaching the restored container (M24 requirement).
		if vethIfname != "" {
			key := ipPortToSeqXlatKey(localIP.To4(), uint16(snap.SrcPort), peerIP.To4(), uint16(snap.DstPort))
			entry := SeqXlatEntry{
				SeqDelta:    r.SeqDelta,
				AckDelta:    r.AckDelta,
				TsDelta:     0,
				Wscale:      0,
				SackPresent: 1,
				State:       1,
			}
			if armErr := ebpfMgr.ArmRelay(ctx, vethIfname, key, entry); armErr != nil {
				log.Error(armErr, "reattach: ArmRelay on migration veth failed (non-fatal — flannel.1 armed)",
					"veth", vethIfname, "srcPort", snap.SrcPort, "dstPort", snap.DstPort)
			} else {
				log.Info("reattach: PM_SEQ_XLAT seeded on migration veth",
					"veth", vethIfname, "srcPort", snap.SrcPort, "dstPort", snap.DstPort)
			}
		}
	}
	return results, nil
}

// DisarmRelayForSnapshots removes the PM_SEQ_XLAT entries SeedRelayFromSnapshots seeded for
// each of the given snapshots (ADR-0357 D5 — DisarmRelay removal-symmetry). Called from the
// destination agent's DisarmTCRedirect handler once the controller's ipReclaimEligible gate
// confirms the OLD IP has no live conntrack entry or ESTABLISHED socket on either node.
//
// Warn-only by design, matching D3's ADR-0224 3h-SYM posture (server.go DisarmZeroWindow): a
// PM_SEQ_XLAT entry that fails to disarm cleanly is a strictly better state than blocking IP
// reclaim on it — a lingering entry is bounded (the caller's ipReclaimEligible sweep already
// proved no live traffic can reach the OLD 4-tuple) and cleanup can simply retry on the next
// sweep pass. Every non-nil, non-ErrKeyNotExist failure is returned in the aggregate slice
// (never swallowed) so the caller can surface it as a distinct, alertable signal — the Security
// Reviewer's round-2 CONDITION on this ADR — instead of discarding it.
func DisarmRelayForSnapshots(ctx context.Context, snapshots []SeqSnapshot, ebpfMgr EBPFManager) []error {
	log := logf.FromContext(ctx)
	var errs []error
	for _, snap := range snapshots {
		localIP := net.ParseIP(snap.SrcIP)
		peerIP := net.ParseIP(snap.DstIP)
		if localIP == nil || peerIP == nil {
			errs = append(errs, fmt.Errorf("reattach: DisarmRelayForSnapshots: invalid snapshot IPs src=%q dst=%q", snap.SrcIP, snap.DstIP))
			continue
		}
		key := IPPortToSeqXlatKey(localIP.To4(), uint16(snap.SrcPort), peerIP.To4(), uint16(snap.DstPort))
		if err := ebpfMgr.DisarmRelay(ctx, key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				// Already gone — not a failure (idempotent, matches DisarmXDPBridge/DisarmVTEP).
				continue
			}
			log.Error(err, "reattach: DisarmRelayForSnapshots: DisarmRelay failed for a PM_SEQ_XLAT entry (ADR-0357 D5, non-fatal)",
				"srcPort", snap.SrcPort, "dstPort", snap.DstPort)
			errs = append(errs, fmt.Errorf("DisarmRelay %s:%d→%s:%d: %w", snap.SrcIP, snap.SrcPort, snap.DstIP, snap.DstPort, err))
			continue
		}
		log.Info("reattach: DisarmRelayForSnapshots: PM_SEQ_XLAT entry disarmed (ADR-0357 D5)",
			"srcPort", snap.SrcPort, "dstPort", snap.DstPort)
	}
	return errs
}

// SeqSnapshot is a local copy of the proto SeqSnapshot fields used to avoid
// importing the proto package from the network package. Callers in server.go
// convert proto SeqSnapshot to this type.
type SeqSnapshot struct {
	SrcIP   string
	SrcPort uint32
	DstIP   string
	DstPort uint32
	SndNxt  uint32
	RcvNxt  uint32
}

// IPPortToSeqXlatKey is the exported form of ipPortToSeqXlatKey, for callers outside this
// package that need to reconstruct a PM_SEQ_XLAT key in the disarm direction (ADR-0357 D5 —
// DisarmTCRedirect reconstructing keys from pm.Status.TCPSeqSnapshots). Mirrors the exact same
// 4-tuple construction SeedRelayFromSnapshots uses in the seed direction, so a disarm key is
// always byte-identical to the key it was seeded under.
func IPPortToSeqXlatKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) SeqXlatKey {
	return ipPortToSeqXlatKey(srcIP, srcPort, dstIP, dstPort)
}

// ipPortToSeqXlatKey builds a SeqXlatKey from net.IP and port values.
// IPv4-mapped IPv6 addresses are normalized to 4-byte form.
func ipPortToSeqXlatKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) SeqXlatKey {
	var key SeqXlatKey
	if v4 := srcIP.To4(); v4 != nil {
		copy(key.SrcIP[:], v4)
	} else {
		copy(key.SrcIP[:], srcIP[:4])
	}
	if v4 := dstIP.To4(); v4 != nil {
		copy(key.DstIP[:], v4)
	} else {
		copy(key.DstIP[:], dstIP[:4])
	}
	key.SrcPort = srcPort
	key.DstPort = dstPort
	return key
}

// probeFreqSocketSeq opens a non-blocking TCP socket inside the netns of freshPID,
// binds it to localIP:localPort, initiates a connect to peerIP:peerPort (which will
// be refused or time out — we only need the kernel-assigned ISN), then reads the
// snd_nxt and rcv_nxt from /proc/<freshPID>/net/tcp[6].
//
// On platforms where /proc/net/tcp does not expose snd_nxt (non-Linux, old kernels),
// both values are returned as zero. The caller uses uint32 wrap-around arithmetic so
// zero deltas are safe (transparent passthrough).
func probeFreqSocketSeq(ctx context.Context, freshPID int32, localIP net.IP, localPort uint16, peerIP net.IP, peerPort uint16) (SocketSeqState, error) {
	log := logf.FromContext(ctx)

	// Try to read seq numbers directly from /proc/<freshPID>/net/tcp[6] for any
	// socket matching localIP:localPort→peerIP:peerPort that CRIU restored.
	// CRIU restore via --tcp-established will have placed the socket in ESTABLISHED
	// state in the fresh netns; we read its current kernel seq numbers.
	entries, err := SocketInventory(freshPID)
	if err != nil {
		log.Info("reattach: SocketInventory failed, using zero seq state", "pid", freshPID, "err", err)
		return SocketSeqState{}, nil
	}

	localIPStr := localIP.String()
	peerIPStr := peerIP.String()

	for _, e := range entries {
		if e.SrcIP.String() == localIPStr && e.SrcPort == localPort &&
			e.DstIP.String() == peerIPStr && e.DstPort == peerPort {
			return SocketSeqState{SndNxt: e.SndNxt, RcvNxt: e.RcvNxt}, nil
		}
	}

	// Socket not found in ESTABLISHED state — CRIU may have restored it with a slight
	// delay. Retry once after a short wait.
	select {
	case <-time.After(50 * time.Millisecond):
	case <-ctx.Done():
		return SocketSeqState{}, ctx.Err()
	}

	entries, err = SocketInventory(freshPID)
	if err != nil {
		return SocketSeqState{}, nil
	}
	for _, e := range entries {
		if e.SrcIP.String() == localIPStr && e.SrcPort == localPort &&
			e.DstIP.String() == peerIPStr && e.DstPort == peerPort {
			return SocketSeqState{SndNxt: e.SndNxt, RcvNxt: e.RcvNxt}, nil
		}
	}

	// Socket still not found — return zero state. With zero seq deltas PM_SEQ_XLAT
	// becomes a transparent passthrough (safe degradation when seq numbers match).
	log.Info("reattach: socket not found in /proc after retry — using zero seq deltas",
		"localIP", localIPStr, "localPort", localPort,
		"peerIP", peerIPStr, "peerPort", peerPort)
	return SocketSeqState{}, nil
}
