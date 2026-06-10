/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package statefulset

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// LabelStatefulSetPodName is the well-known label attached by the StatefulSet
	// controller to every PVC it creates, mapping it to the owning pod.
	LabelStatefulSetPodName = "statefulset.kubernetes.io/pod-name"
)

// PVCFollowAlong manages PVC discovery and binding verification for a StatefulSet ordinal.
//
// StatefulSet PVCs are bound to a specific pod via the well-known label
// statefulset.kubernetes.io/pod-name. When a pod is migrated, its PVCs must
// follow it to the destination pod; this type handles the lifecycle.
type PVCFollowAlong struct {
	Client client.Client
}

// FindPVCsForPod returns the names of all PVCs labeled for the given pod name.
// The labels are set by the StatefulSet controller on VolumeClaimTemplates.
func (f *PVCFollowAlong) FindPVCsForPod(ctx context.Context, namespace, podName string) ([]string, error) {
	var pvcList corev1.PersistentVolumeClaimList
	if err := f.Client.List(ctx, &pvcList,
		client.InNamespace(namespace),
		client.MatchingLabels{LabelStatefulSetPodName: podName},
	); err != nil {
		return nil, fmt.Errorf("list PVCs for pod %s/%s: %w", namespace, podName, err)
	}
	names := make([]string, 0, len(pvcList.Items))
	for _, pvc := range pvcList.Items {
		names = append(names, pvc.Name)
	}
	return names, nil
}

// VerifyPVCBound checks that all named PVCs in the given namespace are in the Bound phase.
// Called after the destination pod is created to confirm PVC re-attachment.
func (f *PVCFollowAlong) VerifyPVCBound(ctx context.Context, namespace string, pvcNames []string) error {
	log := logf.FromContext(ctx)
	for _, name := range pvcNames {
		pvc := &corev1.PersistentVolumeClaim{}
		if err := f.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pvc); err != nil {
			return fmt.Errorf("get PVC %s/%s: %w", namespace, name, err)
		}
		if pvc.Status.Phase != corev1.ClaimBound {
			return fmt.Errorf("PVC %s/%s is %s, expected Bound", namespace, name, pvc.Status.Phase)
		}
		log.V(1).Info("PVC bound", "pvc", name, "phase", pvc.Status.Phase)
	}
	return nil
}

// RevertPVCLabel restores the statefulset.kubernetes.io/pod-name label to the source
// pod name on all named PVCs. This is called during rollback when the destination
// pod creation fails and the source pod must reclaim its PVCs.
//
// Note: PVC binding in Kubernetes is immutable once Bound — this label update
// signals intent for the StatefulSet controller's next reconcile cycle. It does
// not forcibly re-bind the PVC.
func (f *PVCFollowAlong) RevertPVCLabel(ctx context.Context, namespace, sourcePodName string, pvcNames []string) error {
	log := logf.FromContext(ctx)
	for _, name := range pvcNames {
		pvc := &corev1.PersistentVolumeClaim{}
		if err := f.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pvc); err != nil {
			return fmt.Errorf("get PVC %s/%s for revert: %w", namespace, name, err)
		}
		if pvc.Labels == nil {
			pvc.Labels = map[string]string{}
		}
		pvc.Labels[LabelStatefulSetPodName] = sourcePodName
		if err := f.Client.Update(ctx, pvc); err != nil {
			return fmt.Errorf("revert PVC label %s/%s: %w", namespace, name, err)
		}
		log.Info("reverted PVC label to source pod", "pvc", name, "sourcePod", sourcePodName)
	}
	return nil
}
