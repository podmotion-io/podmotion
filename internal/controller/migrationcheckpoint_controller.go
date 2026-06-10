/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

const (
	checkpointPhaseCapturing = "Capturing"
	checkpointPhaseAvailable = "Available"
	checkpointPhaseConsumed  = "Consumed"
	checkpointPhaseExpired   = "Expired"
	checkpointPhaseFailed    = "Failed"

	// defaultRetentionSeconds matches charts/podmotion/values.yaml checkpoint.retentionSeconds.
	defaultRetentionSeconds = 3600
)

// MigrationCheckpointReconciler manages MigrationCheckpoint lifecycle and GC.
//
// State machine:
//   Capturing → Available  (CRIU agent transitions once dump is complete)
//   Available → Consumed   (PodMigration controller after successful restore)
//   Available → Expired    (this controller when ExpiresAt passes)
//   Expired/Consumed/Failed → deleted (60s grace period)
type MigrationCheckpointReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	RetentionSeconds int
}

// +kubebuilder:rbac:groups=migration.podmotion.io,resources=migrationcheckpoints,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=migrationcheckpoints/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=migrationcheckpoints/finalizers,verbs=update

func (r *MigrationCheckpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	mcp := &pmv1.MigrationCheckpoint{}
	if err := r.Get(ctx, req.NamespacedName, mcp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	switch mcp.Status.Phase {
	case "", checkpointPhaseCapturing:
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	case checkpointPhaseAvailable:
		return r.reconcileAvailable(ctx, mcp)
	case checkpointPhaseConsumed, checkpointPhaseExpired, checkpointPhaseFailed:
		return r.reconcileTerminal(ctx, mcp)
	default:
		log.Info("unknown checkpoint phase", "phase", mcp.Status.Phase)
		return ctrl.Result{}, nil
	}
}

func (r *MigrationCheckpointReconciler) reconcileAvailable(ctx context.Context, mcp *pmv1.MigrationCheckpoint) (ctrl.Result, error) {
	retention := r.RetentionSeconds
	if retention <= 0 {
		retention = defaultRetentionSeconds
	}

	if mcp.Spec.ExpiresAt == nil {
		expiry := metav1.NewTime(mcp.CreationTimestamp.Add(time.Duration(retention) * time.Second))
		mcp.Spec.ExpiresAt = &expiry
		if err := r.Update(ctx, mcp); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
	}

	if time.Now().After(mcp.Spec.ExpiresAt.Time) {
		return r.markExpired(ctx, mcp)
	}

	untilExpiry := time.Until(mcp.Spec.ExpiresAt.Time) + time.Second
	if untilExpiry < 5*time.Second {
		untilExpiry = 5 * time.Second
	}
	return ctrl.Result{RequeueAfter: untilExpiry}, nil
}

func (r *MigrationCheckpointReconciler) markExpired(ctx context.Context, mcp *pmv1.MigrationCheckpoint) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("checkpoint TTL expired", "checkpoint", mcp.Name)

	// TODO(M4): call agent gRPC to delete OCI image when TransferMode==Registry.
	if mcp.Spec.RegistryRef != "" {
		log.Info("stub: would delete OCI image from registry", "ref", mcp.Spec.RegistryRef)
	}

	mcp.Status.Phase = checkpointPhaseExpired
	if err := r.Status().Update(ctx, mcp); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

func (r *MigrationCheckpointReconciler) reconcileTerminal(ctx context.Context, mcp *pmv1.MigrationCheckpoint) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	ref := mcp.Status.CapturedAt
	if ref == nil {
		ref = &mcp.CreationTimestamp
	}
	if time.Since(ref.Time) < 60*time.Second {
		return ctrl.Result{RequeueAfter: 60*time.Second - time.Since(ref.Time)}, nil
	}

	log.Info("deleting terminal checkpoint", "checkpoint", mcp.Name, "phase", mcp.Status.Phase)
	if err := r.Delete(ctx, mcp); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *MigrationCheckpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pmv1.MigrationCheckpoint{}).
		Named("migrationcheckpoint").
		Complete(r)
}
