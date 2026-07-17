/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// StorageHandoffReadyRequest carries the ADR-0007/ADR-0344 Decision A.1
// remount-handoff request sent to the source-side agent over the existing
// storage-agent gRPC channel (same transport class as Checkpoint/Restore/Verify;
// no new transport is introduced).
type StorageHandoffReadyRequest struct {
	// MigrationName is the PodMigration CR this handoff belongs to.
	MigrationName string
	// PodNamespace is the namespace of the source pod.
	PodNamespace string
	// PVCName is the Tier0 PVC being remounted read-only on the source.
	PVCName string
}

// StorageHandoffReadyResponse is the source agent's confirmation that the
// requested Tier0 volume has completed its remount-ro sequence.
//
// SourceReadonly corresponds to ADR-0007's mandated `source_readonly: true`
// field: the Restoring phase may only proceed to destination mount creation
// once this is true.
type StorageHandoffReadyResponse struct {
	// SourceReadonly is true once the source has confirmed the volume is
	// remounted read-only (or a fresh unmount, tier-dependent) and safe for a
	// concurrent destination mount.
	SourceReadonly bool
	// Reason carries a short machine-readable explanation when SourceReadonly
	// is false (e.g. "RemountTimeout", "RemountFailed").
	Reason string
}

// StorageHandoffClient issues the StorageHandoffReady RPC against the
// source-side podmotion-agent for a given Tier0 PVC. It is the new RPC added
// to the existing storage-agent service by ADR-0344 Decision A.1.
type StorageHandoffClient interface {
	StorageHandoffReady(ctx context.Context, req *StorageHandoffReadyRequest) (*StorageHandoffReadyResponse, error)
}

// noHandoffClient is the fail-open zero-value StorageHandoffClient used when
// no agent RPC transport has been wired in (e.g. unit tests constructing a
// RWXReattachMigrator directly via NewRWXReattachMigrator). It reports
// SourceReadonly=true immediately, preserving the pre-ADR-0344 no-op Cutover
// behavior for callers that have not opted into the remount-handoff guard.
//
// Production wiring (the operator's AgentPool-backed client) is injected via
// WithHandoffClient and does NOT use this fallback.
type noHandoffClient struct{}

func (noHandoffClient) StorageHandoffReady(_ context.Context, _ *StorageHandoffReadyRequest) (*StorageHandoffReadyResponse, error) {
	return &StorageHandoffReadyResponse{SourceReadonly: true, Reason: "NoHandoffClientConfigured"}, nil
}

// RWXReattachMigrator handles Tier0 (ReadWriteMany) volumes.
//
// For RWX volumes (NFS, CephFS, etc.) no data movement is required:
// the destination pod can mount the same PV directly. The only pre-stage
// work is verifying the PV is reachable from the destination node.
//
// StorageReadyForFreeze is emitted immediately because there is no sync
// phase — compute freeze can begin as soon as this check passes.
//
// Cutover (ADR-0007 amendment, implemented by ADR-0344 Decision A.1) blocks
// on a StorageHandoffReady confirmation from the source agent before
// permitting the destination mount to be created, guarding against the
// concurrent-writer/split-brain hazard described in ADR-0344 Context §2.
type RWXReattachMigrator struct {
	client        client.Client
	handoffClient StorageHandoffClient
}

// NewRWXReattachMigrator returns a Tier0 migrator. Callers that need the
// ADR-0344 Decision A.1 remount-handoff guard enforced against a real agent
// must additionally call WithHandoffClient.
func NewRWXReattachMigrator(c client.Client) *RWXReattachMigrator {
	return &RWXReattachMigrator{client: c, handoffClient: noHandoffClient{}}
}

// WithHandoffClient wires a StorageHandoffClient (the production gRPC-backed
// implementation, or a fake in tests) into the migrator and returns it for
// chaining.
func (m *RWXReattachMigrator) WithHandoffClient(hc StorageHandoffClient) *RWXReattachMigrator {
	m.handoffClient = hc
	return m
}

// Tier returns TierRWX.
func (m *RWXReattachMigrator) Tier() StorageTier { return TierRWX }

// PreStage verifies that each RWX PVC's PV is accessible from the destination
// node and sets syncPct=100 on return — signalling immediate readiness.
//
// "Accessible" for RWX means the PV is Bound and not in a terminating state.
// Network reachability to the NFS/CephFS server is assumed healthy if the PV
// is Bound — a failed mount will surface at CRIU restore time, not here.
func (m *RWXReattachMigrator) PreStage(ctx context.Context, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "RWX")

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierRWX {
			continue
		}

		pvc := &corev1.PersistentVolumeClaim{}
		if err := m.client.Get(ctx, client.ObjectKey{
			Namespace: opts.PodNamespace,
			Name:      clsf.PVCName,
		}, pvc); err != nil {
			return fmt.Errorf("tier0: get pvc %s: %w", clsf.PVCName, err)
		}

		if pvc.Status.Phase != corev1.ClaimBound {
			return fmt.Errorf("tier0: pvc %s is not Bound (phase=%s)", clsf.PVCName, pvc.Status.Phase)
		}

		log.Info("RWX PVC verified — no data movement required",
			"pvc", clsf.PVCName, "pv", pvc.Spec.VolumeName)
	}

	// Tier0 requires no sync — StorageReadyForFreeze can be emitted by the
	// manager immediately after PreStage returns nil.
	return nil
}

// SyncPercent returns 100 for Tier0 — there is nothing to sync.
func (m *RWXReattachMigrator) SyncPercent(_ context.Context, _ MigrationOptions) (int, error) {
	return 100, nil
}

// Cutover implements the ADR-0007-mandated remount-handoff sequence for each
// Tier0 PVC (ADR-0344 Decision A.1): issue the source-side remount-ro request
// over the existing agent gRPC channel via StorageHandoffReady, and only
// return nil once every PVC has confirmed source_readonly=true. A timeout or
// RPC failure — or an explicit SourceReadonly=false — returns an error, which
// the controller maps to a Failed transition BEFORE any destination mount is
// created (no destination-mount side effect occurs on this path).
func (m *RWXReattachMigrator) Cutover(ctx context.Context, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "RWX")

	hc := m.handoffClient
	if hc == nil {
		hc = noHandoffClient{}
	}

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierRWX {
			continue
		}

		resp, err := hc.StorageHandoffReady(ctx, &StorageHandoffReadyRequest{
			MigrationName: opts.MigrationName,
			PodNamespace:  opts.PodNamespace,
			PVCName:       clsf.PVCName,
		})
		if err != nil {
			return fmt.Errorf("tier0: StorageHandoffReady rpc failed for pvc %s: %w", clsf.PVCName, err)
		}
		if resp == nil || !resp.SourceReadonly {
			reason := "unknown"
			if resp != nil {
				reason = resp.Reason
			}
			return fmt.Errorf("tier0: source remount-ro not confirmed for pvc %s (reason=%s) — refusing to permit destination mount", clsf.PVCName, reason)
		}

		log.Info("StorageHandoffReady confirmed source_readonly — destination mount permitted",
			"pvc", clsf.PVCName)
	}

	return nil
}
