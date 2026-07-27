/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// ADR-0400: the node-scoped PM_BRIDGE_MAP reconciler.
//
// It replaces the per-migration freeze-budget watchdog goroutine (ADR-0155 Decision 7,
// superseded) that deleted live map state on a hardcoded 5.5s wall-clock. A bridge
// map entry (srcIP -> {dstIP, genevePort}) is the live redirect carrying a migrating
// pod's in-flight traffic to the destination during freeze+restore; deleting it on
// elapsed time blackholes exactly the packets the bridge exists to preserve.
//
// This reconciler deletes an entry ONLY on the verified source-of-truth event that
// proves the handoff is over (D1), never on a clock, and — unlike the goroutine —
// survives agent restart, closing the crash-leak ADR-0155 D7 claimed but missed.

// defaultBridgeReconcileInterval is how often the node-scoped reconciler sweeps
// PM_BRIDGE_MAP against the live PodMigration set. A slow tick only lets an orphan
// linger for one interval; it never deletes an entry early (D1 is a positive
// per-key predicate), so the cadence is a liveness knob, not a safety one.
const defaultBridgeReconcileInterval = 5 * time.Second

// bridgeDisposition is the per-key decision of the ADR-0400 D1 predicate.
type bridgeDisposition int

const (
	// bridgeKeep: the CR exists and the handoff is legitimately still in-flight
	// (however slow) — the entry MUST NOT be deleted.
	bridgeKeep bridgeDisposition = iota
	// bridgeDelete: safe to delete — verified cutover (D1a), terminal failure with
	// network rollback owed (D1b), or the CR is genuinely absent (D1c).
	bridgeDelete
)

// bridgeMapOps is the narrow eBPF primitive set the reconciler needs. Satisfied by
// the production EBPFManager and trivially faked in tests. Kept minimal (primitives
// over a wide surface): the reconciler only ever enumerates keys and deletes through
// the existing idempotent DisarmXDPBridge — it never creates or mutates an entry.
type bridgeMapOps interface {
	// ListXDPBridgeKeys enumerates the source-IPv4 keys currently resident in the
	// node-scoped pinned PM_BRIDGE_MAP. Returns (nil, nil) when the bridge is not
	// loaded (XDPBridgeCapable=false) — a benign empty node.
	ListXDPBridgeKeys(ctx context.Context) ([]net.IP, error)
	// DisarmXDPBridge deletes the srcIP entry. Idempotent: a missing key is not an
	// error (ADR-0155 Decision 5).
	DisarmXDPBridge(ctx context.Context, srcIP net.IP) error
}

// BridgeMapReconciler reconciles the node-scoped PM_BRIDGE_MAP against the live
// PodMigration set, deleting an entry only when the owning CR proves the handoff is
// over (ADR-0400 D1/D2).
type BridgeMapReconciler struct {
	// Reader MUST be the agent's UNCACHED APIReader (cluster.GetAPIReader()), never
	// the informer-backed cached client. ADR-0400 D2 review finding B: a direct API
	// read returns either an authoritative complete snapshot or an
	// error — it can never return a cold/unsynced-cache empty/partial set. That is
	// the load-bearing property that makes D1(c) "delete on CR-absent" safe: a key
	// is deleted for absence ONLY when the read was definitively successful.
	Reader client.Reader
	// Ops is the eBPF map primitive set (production: the agent's EBPFManager).
	Ops bridgeMapOps
}

// NewBridgeMapReconciler constructs a reconciler. reader MUST be an uncached
// APIReader (see BridgeMapReconciler.Reader).
func NewBridgeMapReconciler(reader client.Reader, ops bridgeMapOps) *BridgeMapReconciler {
	return &BridgeMapReconciler{Reader: reader, Ops: ops}
}

// decideBridgeEntry applies the ADR-0400 D1 predicate to ONE positively-resolved key.
//
// pm == nil means: an AUTHORITATIVELY-SUCCESSFUL PodMigration snapshot contained no CR
// whose Spec.SourcePodIP equals this key (D1c). Callers MUST pass nil only after a
// successful List — a failed/partial read must never reach this function (fail-closed,
// handled in reconcileOnce). Under that contract, nil is a genuine orphan and is safe
// to delete.
//
// "keep" is the EXACT NEGATION of the delete predicate — CR present AND not terminal
// AND SourceTeardownBlockReason != "" — never an enumerated intermediate-phase
// whitelist (ADR-0400 D2 review finding B).
func decideBridgeEntry(pm *pmv1.PodMigration) bridgeDisposition {
	// D1(c): CR genuinely absent in an authoritative snapshot -> orphan, safe.
	if pm == nil {
		return bridgeDelete
	}
	// D1(b): terminal failure with network rollback owed. Deleting the entry is the
	// network-rollback step; the reconciler is the self-healing backstop if the
	// controller-driven Rollback->Teardown RPC was lost.
	switch pm.Status.Phase {
	case pmv1.MigrationPhaseFailed, pmv1.MigrationPhaseRollingBack:
		return bridgeDelete
	}
	// D1(a): verified cutover. Delegate to the SINGLE canonical stricter-union
	// predicate that already gates source-pod delete and source-EndpointSlice
	// removal (api/v1alpha1/source_teardown.go). Mode-aware BY CONSTRUCTION: in
	// Strict it keys on ServiceContinuityVerified (NOT raw TrafficVerified, which can
	// be a HandoffInstalled false-positive while the destination is unreachable —
	// ADR-0400 review finding A). "" means the source may be safely torn down, so
	// the interception bridge is by definition redundant.
	if pmv1.SourceTeardownBlockReason(pm.Spec.TCPPreservationMode, pm.Status.Conditions) == "" {
		return bridgeDelete
	}
	// CR present, in-flight, not yet safe.
	return bridgeKeep
}

// reconcileOnce runs a single node-scoped reconcile pass. Fail-closed: any error
// reading the authoritative PodMigration snapshot aborts the pass and deletes nothing.
func (r *BridgeMapReconciler) reconcileOnce(ctx context.Context) error {
	log := logf.FromContext(ctx)

	keys, err := r.Ops.ListXDPBridgeKeys(ctx)
	if err != nil {
		return fmt.Errorf("bridge reconcile: enumerate PM_BRIDGE_MAP: %w", err)
	}
	if len(keys) == 0 {
		return nil
	}

	// AUTHORITATIVE snapshot via the uncached APIReader. FAIL CLOSED (ADR-0400 D2
	// review finding B): any List error aborts the pass and deletes nothing,
	// mirroring internal/agent/client/source_rollback_client.go and
	// internal/agent/nri/plugin.go. A failed/partial read must never let a live
	// entry fall into the D1(c) absent-delete branch.
	list := &pmv1.PodMigrationList{}
	if err := r.Reader.List(ctx, list); err != nil {
		return fmt.Errorf("bridge reconcile: list PodMigrations failed — fail-closed, deleting nothing: %w", err)
	}

	// Positive index: sourcePodIP -> owning PodMigration.
	byIP := make(map[string]*pmv1.PodMigration, len(list.Items))
	for i := range list.Items {
		ip := strings.TrimSpace(list.Items[i].Spec.SourcePodIP)
		if ip == "" {
			continue
		}
		byIP[ip] = &list.Items[i]
	}

	var firstErr error
	for _, key := range keys {
		// Positive per-key resolution (nil => absent from a successful snapshot = D1c).
		pm := byIP[normalizeIPKey(key)]
		if decideBridgeEntry(pm) != bridgeDelete {
			continue
		}
		if err := r.Ops.DisarmXDPBridge(ctx, key); err != nil {
			// Best-effort: log and continue the remaining keys; retried next tick.
			log.Error(err, "bridge reconcile: DisarmXDPBridge failed", "srcIP", key.String())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		reason := "orphaned (no owning CR)"
		if pm != nil {
			reason = fmt.Sprintf("phase=%s verified/terminal", pm.Status.Phase)
		}
		log.Info("bridge reconcile: deleted PM_BRIDGE_MAP entry on source-of-truth event",
			"srcIP", key.String(), "reason", reason)
	}
	return firstErr
}

// Run drives reconcileOnce on a ticker until ctx is cancelled. interval <= 0 uses
// defaultBridgeReconcileInterval.
func (r *BridgeMapReconciler) Run(ctx context.Context, interval time.Duration) {
	log := logf.FromContext(ctx)
	if interval <= 0 {
		interval = defaultBridgeReconcileInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Info("PM_BRIDGE_MAP reconciler started (ADR-0400)", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			log.Info("PM_BRIDGE_MAP reconciler stopping")
			return
		case <-ticker.C:
			if err := r.reconcileOnce(ctx); err != nil {
				log.Error(err, "PM_BRIDGE_MAP reconcile pass failed (retried next tick)")
			}
		}
	}
}

// normalizeIPKey renders an IP as the canonical dotted-decimal string used as the
// index key, tolerant of 4-in-16 representations returned by the map iterator.
func normalizeIPKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
