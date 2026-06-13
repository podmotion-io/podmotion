//go:build chaos_test

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

// Package controller — chaos_test build-tag additions.
//
// This file is NEVER compiled into production binaries. It is included only
// when the chaos_test build tag is set (make build-chaos).
//
// ChaosSyncPoint implements deterministic rendezvous between the reconciler
// and the test harness using PodMigration CR condition watches. No time.Sleep
// is used anywhere in this file (ADR-0097 §3).
package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// ChaosWatchClient is the WithWatch client used by ChaosSyncPoint.
// Must be set before running any chaos scenarios. Injected by the chaos test
// bootstrap code (test/chaos/suite_setup.go) using the same kubeconfig as
// the controller-runtime manager. It is separate from the embedded
// client.Client because client.Client does not expose Watch.
//
// Only compiled with build tag chaos_test; never present in production binaries.
var ChaosWatchClient client.WithWatch

// conditionTypeReached returns "ChaosSyncReached/<name>".
func conditionTypeReached(name string) string { return "ChaosSyncReached/" + name }

// conditionTypeResume returns "ChaosSyncResume/<name>".
func conditionTypeResume(name string) string { return "ChaosSyncResume/" + name }

// ChaosSyncPoint sets a synthetic condition ChaosSyncReached/<name>=True on the
// PodMigration CR to signal the test harness that the reconciler has reached the
// named sync point, then blocks until the test harness sets
// ChaosSyncResume/<name>=True.
//
// Transport: ChaosWatchClient Watch on PodMigration CR conditions.
// No time.Sleep. Timeout governed by ctx deadline (default 60s per sync point
// in the test harness). See ADR-0097 §3.
//
// This function is only compiled with build tag chaos_test and is never
// called in production reconciler paths.
//
// Named sync points wired into the reconciler (see podmigration_controller.go):
//
//	post-socket-inventory    — after SocketInventory, before Validating
//	post-freeze              — after FinalFreezeStateCapture, before OverlayHandoff
//	post-checkpoint-transfer — after overlay transfer, before RestoreSocketReattach
//	post-restore             — after CRIU restore, before DisengageHold
//	post-network-handoff     — after CutoverComplete, before source pod deletion
func (r *PodMigrationReconciler) ChaosSyncPoint(ctx context.Context, pmKey types.NamespacedName, name string) error {
	reachedType := conditionTypeReached(name)
	resumeType := conditionTypeResume(name)

	// Step 1: Patch ChaosSyncReached/<name>=True on the PodMigration CR.
	var pm pmv1.PodMigration
	if err := r.Get(ctx, pmKey, &pm); err != nil {
		return fmt.Errorf("ChaosSyncPoint %s: Get: %w", name, err)
	}
	base := pm.DeepCopy()
	meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
		Type:               reachedType,
		Status:             metav1.ConditionTrue,
		Reason:             "ChaosSyncReached",
		Message:            fmt.Sprintf("reconciler reached sync point %s", name),
		LastTransitionTime: metav1.Now(),
	})
	if err := r.Status().Patch(ctx, &pm, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("ChaosSyncPoint %s: patch reached condition: %w", name, err)
	}

	// Step 2: Watch until ChaosSyncResume/<name>=True is observed.
	// Check immediately first (avoids missing a fast test harness patch).
	var current pmv1.PodMigration
	if err := r.Get(ctx, pmKey, &current); err == nil {
		if meta.IsStatusConditionTrue(current.Status.Conditions, resumeType) {
			return nil
		}
	}

	if ChaosWatchClient == nil {
		return fmt.Errorf("ChaosSyncPoint %s: ChaosWatchClient is nil; must be set before chaos tests run", name)
	}

	watcher, err := ChaosWatchClient.Watch(ctx, &pmv1.PodMigrationList{}, &client.ListOptions{
		Namespace: pmKey.Namespace,
	})
	if err != nil {
		return fmt.Errorf("ChaosSyncPoint %s: watch: %w", name, err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("ChaosSyncPoint %s: timed out waiting for resume condition: %w", name, ctx.Err())
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("ChaosSyncPoint %s: watch channel closed", name)
			}
			if event.Type != watch.Modified && event.Type != watch.Added {
				continue
			}
			obj, ok := event.Object.(*pmv1.PodMigration)
			if !ok || obj.Name != pmKey.Name || obj.Namespace != pmKey.Namespace {
				continue
			}
			if meta.IsStatusConditionTrue(obj.Status.Conditions, resumeType) {
				return nil
			}
		}
	}
}
