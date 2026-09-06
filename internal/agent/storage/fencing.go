/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

const (
	// rwoDetachTimeout is the maximum time allowed for a RWO PVC to detach from the
	// source node after migration completes. If detach stalls beyond this window,
	// the node must be fenced to release the volume lock (ADR-0011, ADR-0014).
	rwoDetachTimeout = 60 * time.Second

	// conditionNodeFencingRequired is the PodMigration condition type emitted when
	// a RWO volume fails to detach from the source node within rwoDetachTimeout.
	conditionNodeFencingRequired = "NodeFencingRequired"

	// eventReasonNodeFencingRequired is the Kubernetes Event reason used when fencing is needed.
	eventReasonNodeFencingRequired = "NodeFencingRequired"

	// fencingPollInterval is the delay between RWO detach-check polls.
	fencingPollInterval = 5 * time.Second
)

// PVCDetachChecker can determine whether a PVC has been successfully detached
// from a given node. The interface is satisfied by a real implementation that
// inspects VolumeAttachment objects, and by a stub for unit tests.
type PVCDetachChecker interface {
	// IsDetached returns true if the PVC identified by pvcName/namespace is no
	// longer attached to nodeName.
	IsDetached(ctx context.Context, namespace, pvcName, nodeName string) (bool, error)
}

// RollbackEnterer decouples internal/agent/storage from internal/controller (avoiding an import
// cycle — internal/controller already imports internal/agent/storage) while still routing every
// Phase=RollingBack write through the controller's one sole-writer implementation (ADR-0423 D4
// decision (b)). Implemented by (*controller.PodMigrationReconciler).EnterRollingBack, an
// exported one-line wrapper around that package's unexported enterRollingBack core — there
// remains exactly one place the phase/marker/condition are actually set.
type RollbackEnterer interface {
	EnterRollingBack(ctx context.Context, pm *pmv1.PodMigration, reason string) error
}

// NodeFencingEmitter monitors RWO PVC detach progress after a migration
// completes. If a RWO PVC fails to detach from the source node within
// rwoDetachTimeout it emits a Kubernetes Event and sets the
// NodeFencingRequired=True condition on the PodMigration CR.
//
// If spec.rollbackOnFailure=true AND the migration has not yet fully completed
// (TrafficVerified=false), the emitter also initiates rollback — preventing the
// source pod from being deleted while its volume is still locked.
type NodeFencingEmitter struct {
	Client        client.Client
	Recorder      record.EventRecorder
	DetachChecker PVCDetachChecker
	// Enterer routes Phase=RollingBack entry through the controller's sole-writer
	// enterRollingBack (ADR-0423 D4 decision (b)). May be nil in tests that never exercise the
	// rollbackOnFailure path (initiateRollback is unreachable without it).
	Enterer RollbackEnterer
}

// NewNodeFencingEmitter returns a production NodeFencingEmitter.
func NewNodeFencingEmitter(c client.Client, recorder record.EventRecorder, checker PVCDetachChecker, enterer RollbackEnterer) *NodeFencingEmitter {
	return &NodeFencingEmitter{
		Client:        c,
		Recorder:      recorder,
		DetachChecker: checker,
		Enterer:       enterer,
	}
}

// MonitorRWODetach starts a blocking watch on all RWO PVCs in opts.Classifications.
// It must be called in a goroutine after the migration restore phase completes.
//
// Returns nil if all RWO PVCs detach within rwoDetachTimeout.
// Returns an error and emits the NodeFencingRequired condition/event if any PVC times out.
func (e *NodeFencingEmitter) MonitorRWODetach(ctx context.Context, pm *pmv1.PodMigration, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", pm.Name)

	rwoPVCs := filterRWOPVCs(opts.Classifications)
	if len(rwoPVCs) == 0 {
		return nil
	}

	deadline := time.Now().Add(rwoDetachTimeout)
	ticker := time.NewTicker(fencingPollInterval)
	defer ticker.Stop()

	remaining := make(map[string]struct{}, len(rwoPVCs))
	for _, pvc := range rwoPVCs {
		remaining[pvc] = struct{}{}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			for pvcName := range remaining {
				detached, err := e.DetachChecker.IsDetached(ctx, opts.PodNamespace, pvcName, opts.SourceNode)
				if err != nil {
					log.Error(err, "checking PVC detach status", "pvc", pvcName)
					continue
				}
				if detached {
					log.Info("RWO PVC detached successfully", "pvc", pvcName, "srcNode", opts.SourceNode)
					delete(remaining, pvcName)
				}
			}

			if len(remaining) == 0 {
				return nil
			}

			if time.Now().After(deadline) {
				stuck := pvcNames(remaining)
				log.Info("RWO PVC detach timeout — emitting NodeFencingRequired",
					"pvcs", stuck, "srcNode", opts.SourceNode)

				if err := e.emitFencingRequired(ctx, pm, opts.SourceNode, stuck); err != nil {
					return fmt.Errorf("emit fencing condition: %w", err)
				}

				// Rollback only makes sense if the destination pod has not yet been
				// verified as live — once TrafficVerified=true the source is already gone.
				if pm.Spec.RollbackOnFailure && !e.isTrafficVerified(pm) {
					log.Info("initiating rollback due to RWO detach timeout with rollbackOnFailure=true")
					if err := e.initiateRollback(ctx, pm); err != nil {
						log.Error(err, "failed to initiate rollback")
					}
				}

				return fmt.Errorf("RWO PVC detach timeout on node %s: %v", opts.SourceNode, stuck)
			}
		}
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

// filterRWOPVCs returns PVC names that are ReadWriteOnce (TierCephRBD, TierSnapshotRsync,
// TierLonghorn — all RWO storage tiers that hold exclusive volume locks).
// TierRWX is excluded because RWX volumes have no exclusive lock.
func filterRWOPVCs(classifications []TierClassification) []string {
	var names []string
	for _, c := range classifications {
		if c.Tier == TierRWX || c.Tier == TierBlocked {
			continue
		}
		if c.PVCName != "" {
			names = append(names, c.PVCName)
		}
	}
	return names
}

func pvcNames(m map[string]struct{}) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	return names
}

func (e *NodeFencingEmitter) emitFencingRequired(ctx context.Context, pm *pmv1.PodMigration, srcNode string, stuck []string) error {
	msg := fmt.Sprintf("RWO PVC(s) %v failed to detach from node %s within %s — manual node fencing required",
		stuck, srcNode, rwoDetachTimeout)

	// Emit Kubernetes Event on the PodMigration object.
	e.Recorder.Event(pm, corev1.EventTypeWarning, eventReasonNodeFencingRequired, msg)

	// Set NodeFencingRequired=True condition on a fresh copy of the CR.
	fresh := &pmv1.PodMigration{}
	if err := e.Client.Get(ctx, client.ObjectKeyFromObject(pm), fresh); err != nil {
		return fmt.Errorf("get PodMigration for fencing patch: %w", err)
	}
	meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
		Type:               conditionNodeFencingRequired,
		Status:             metav1.ConditionTrue,
		Reason:             "RWODetachTimeout",
		Message:            msg,
		LastTransitionTime: metav1.Now(),
	})
	return e.Client.Status().Update(ctx, fresh)
}

func (e *NodeFencingEmitter) isTrafficVerified(pm *pmv1.PodMigration) bool {
	for _, c := range pm.Status.Conditions {
		if c.Type == "TrafficVerified" && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// initiateRollback routes entry into Phase=RollingBack through the controller's sole-writer
// enterRollingBack (ADR-0423 D4 decision (b)) via the injected RollbackEnterer, rather than
// writing Status.Phase directly — internal/agent/storage contains no Status.Phase= assignment of
// any kind after this conversion.
func (e *NodeFencingEmitter) initiateRollback(ctx context.Context, pm *pmv1.PodMigration) error {
	return e.Enterer.EnterRollingBack(ctx, pm, "node fencing detected")
}

// ── VolumeAttachment-based DetachChecker ──────────────────────────────────

// VolumeAttachmentDetachChecker implements PVCDetachChecker using the
// storage.k8s.io/v1 VolumeAttachment API.
type VolumeAttachmentDetachChecker struct {
	Client client.Client
}

// IsDetached returns true if no VolumeAttachment exists that binds the PVC's
// backing PV to nodeName.
func (d *VolumeAttachmentDetachChecker) IsDetached(ctx context.Context, namespace, pvcName, nodeName string) (bool, error) {
	// Resolve PVC → PV name.
	pvc := &corev1.PersistentVolumeClaim{}
	if err := d.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: pvcName}, pvc); err != nil {
		return false, fmt.Errorf("get pvc %s/%s: %w", namespace, pvcName, err)
	}
	pvName := pvc.Spec.VolumeName
	if pvName == "" {
		// PVC not yet bound — no attachment to check.
		return true, nil
	}

	vaList := &storagev1.VolumeAttachmentList{}
	if err := d.Client.List(ctx, vaList); err != nil {
		return false, fmt.Errorf("list VolumeAttachments: %w", err)
	}

	for i := range vaList.Items {
		va := &vaList.Items[i]
		if va.Spec.Source.PersistentVolumeName != nil &&
			*va.Spec.Source.PersistentVolumeName == pvName &&
			va.Spec.NodeName == nodeName &&
			va.Status.Attached {
			return false, nil
		}
	}
	return true, nil
}

// ── Stub ───────────────────────────────────────────────────────────────────

// StubDetachChecker implements PVCDetachChecker for unit tests.
// It returns detached=false until DetachAfter has elapsed, then returns true.
type StubDetachChecker struct {
	// DetachAfter controls how long the stub pretends the volume is still attached.
	// Zero means always detached.
	DetachAfter time.Duration
	startTime   time.Time
	started     bool
}

// IsDetached returns false until DetachAfter elapses, then returns true.
func (s *StubDetachChecker) IsDetached(_ context.Context, _, _, _ string) (bool, error) {
	if !s.started {
		s.startTime = time.Now()
		s.started = true
	}
	if s.DetachAfter == 0 || time.Since(s.startTime) >= s.DetachAfter {
		return true, nil
	}
	return false, nil
}
