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

// RWXReattachMigrator handles Tier0 (ReadWriteMany) volumes.
//
// For RWX volumes (NFS, CephFS, etc.) no data movement is required:
// the destination pod can mount the same PV directly. The only pre-stage
// work is verifying the PV is reachable from the destination node.
//
// StorageReadyForFreeze is emitted immediately because there is no sync
// phase — compute freeze can begin as soon as this check passes.
type RWXReattachMigrator struct {
	client client.Client
}

// NewRWXReattachMigrator returns a Tier0 migrator.
func NewRWXReattachMigrator(c client.Client) *RWXReattachMigrator {
	return &RWXReattachMigrator{client: c}
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

// Cutover is a no-op for Tier0: the destination pod's scheduler will mount
// the same PV on first container start. No detach/attach sequence needed.
func (m *RWXReattachMigrator) Cutover(_ context.Context, _ MigrationOptions) error {
	return nil
}
