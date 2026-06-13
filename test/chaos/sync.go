//go:build chaos_test

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package chaos

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

// conditionType returns the condition type string for a named chaos sync point.
// Reached: "ChaosSyncReached/<name>", Resume: "ChaosSyncResume/<name>".
func conditionTypeReached(name string) string { return "ChaosSyncReached/" + name }
func conditionTypeResume(name string) string  { return "ChaosSyncResume/" + name }

// WaitForSyncPoint blocks until the PodMigration CR carries condition
// ChaosSyncReached/<name>=True, then returns a resume function.
//
// Calling resume() patches ChaosSyncResume/<name>=True on the CR,
// unblocking the reconciler's ChaosSyncPoint call.
//
// Transport: controller-runtime Watch on PodMigration — deterministic,
// no time.Sleep anywhere in this path (ADR-0097 §3).
func WaitForSyncPoint(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName, name string) (resume func(), err error) {
	reachedType := conditionTypeReached(name)

	// First check whether the condition is already set (avoids missing an
	// early signal if the reconciler is fast).
	var pm pmv1.PodMigration
	if err := f.Client.Get(ctx, pmNN, &pm); err != nil {
		return nil, fmt.Errorf("WaitForSyncPoint: initial Get: %w", err)
	}
	if meta.IsStatusConditionTrue(pm.Status.Conditions, reachedType) {
		return buildResumeFn(ctx, f, pmNN, name), nil
	}

	// Watch for condition changes using client.WithWatch (ADR-0097 §3 — no time.Sleep).
	watcher, err := f.Client.Watch(ctx, &pmv1.PodMigrationList{}, &client.ListOptions{
		Namespace: pmNN.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("WaitForSyncPoint: Watch: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("WaitForSyncPoint: context done waiting for %s: %w", reachedType, ctx.Err())
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return nil, fmt.Errorf("WaitForSyncPoint: watch channel closed waiting for %s", reachedType)
			}
			if event.Type != watch.Modified && event.Type != watch.Added {
				continue
			}
			obj, ok := event.Object.(*pmv1.PodMigration)
			if !ok || obj.Name != pmNN.Name || obj.Namespace != pmNN.Namespace {
				continue
			}
			if meta.IsStatusConditionTrue(obj.Status.Conditions, reachedType) {
				return buildResumeFn(ctx, f, pmNN, name), nil
			}
		}
	}
}

// buildResumeFn returns a function that, when called, sets
// ChaosSyncResume/<name>=True on the PodMigration CR via a status patch.
func buildResumeFn(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName, name string) func() {
	return func() {
		resumeType := conditionTypeResume(name)
		var pm pmv1.PodMigration
		// Best-effort: ignore errors; the reconciler will timeout and report.
		if err := f.Client.Get(ctx, pmNN, &pm); err != nil {
			return
		}
		base := pm.DeepCopy()
		meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
			Type:               resumeType,
			Status:             metav1.ConditionTrue,
			Reason:             "ChaosTestResume",
			Message:            fmt.Sprintf("chaos harness resumed sync point %s", name),
			LastTransitionTime: metav1.Now(),
		})
		_ = f.Client.Status().Patch(ctx, &pm, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	}
}

// PatchCRCondition is a convenience helper that patches an arbitrary condition
// on the PodMigration status. Used by chaos scenarios that need to simulate
// operator-set conditions (e.g., StorageCutoverTimeout).
func PatchCRCondition(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName, condType, reason, message string, status metav1.ConditionStatus) error {
	var pm pmv1.PodMigration
	if err := f.Client.Get(ctx, pmNN, &pm); err != nil {
		return fmt.Errorf("PatchCRCondition Get: %w", err)
	}
	base := pm.DeepCopy()
	meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
	return f.Client.Status().Patch(ctx, &pm, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}
