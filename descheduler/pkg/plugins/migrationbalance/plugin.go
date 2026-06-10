/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package migrationbalance implements a descheduler Balance plugin that emits
// PodMigration CRs instead of calling the Eviction API.
//
// The design keeps the eviction path out of the hot loop because:
//   - Evictions destroy pod identity; migration preserves it.
//   - The MigrationPolicy maxConcurrentMigrations gate is enforced here to
//     avoid flooding the controller with work it cannot admit.
package migrationbalance

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

const (
	// cpuOverloadThreshold is the CPU utilisation percent above which a node is
	// considered overloaded and eligible for migration-based offload.
	cpuOverloadThreshold = 80

	// LabelDraining mirrors the scheduler label — draining nodes are also eligible sources.
	LabelDraining = "migration.podmotion.io/draining"

	// annotationCreatedBy labels PodMigration CRs created by this plugin.
	annotationCreatedBy = "migration.podmotion.io/created-by"
	createdByValue      = "descheduler-migrationbalance"
)

// NodeMetricsReader abstracts CPU utilisation lookups so tests can inject a stub
// without requiring a live metrics-server.
type NodeMetricsReader interface {
	// CPUUtilisationPercent returns the current CPU utilisation for the named node (0-100).
	CPUUtilisationPercent(ctx context.Context, nodeName string) (int32, error)
}

// MigrationBalance is the descheduler Balance plugin.
type MigrationBalance struct {
	client        client.Client
	metricsReader NodeMetricsReader
}

// New constructs a MigrationBalance plugin.
func New(c client.Client, metricsReader NodeMetricsReader) *MigrationBalance {
	return &MigrationBalance{client: c, metricsReader: metricsReader}
}

// Name satisfies the descheduler plugin interface.
func (b *MigrationBalance) Name() string { return "MigrationBalance" }

// Balance is called by the descheduler on each cycle.
// It finds pods on overloaded/draining nodes and creates PodMigration CRs for them.
func (b *MigrationBalance) Balance(ctx context.Context, nodes []*corev1.Node) error {
	// Collect per-namespace policy limits to avoid creating too many migrations.
	policyMap, err := b.buildPolicyMap(ctx)
	if err != nil {
		return fmt.Errorf("building policy map: %w", err)
	}

	for _, node := range nodes {
		overloaded, err := b.isOverloaded(ctx, node)
		if err != nil {
			// Non-fatal — skip this node and continue balancing.
			continue
		}
		if !overloaded {
			continue
		}

		dest, err := b.findDestination(ctx, node.Name)
		if err != nil || dest == "" {
			continue
		}

		pods, err := b.listPodsOnNode(ctx, node.Name)
		if err != nil {
			continue
		}

		for i := range pods {
			pod := &pods[i]
			if !isMigratable(pod) {
				continue
			}

			ns := pod.Namespace
			policy, ok := policyMap[ns]
			if ok && !b.policyHasCapacity(ctx, policy) {
				continue
			}

			if err := b.createPodMigration(ctx, pod, dest, policy); err != nil {
				// Log but continue — one failure should not block other pods.
				_ = err
			}
		}
	}
	return nil
}

// isOverloaded returns true when the node is labeled draining or its CPU exceeds the threshold.
func (b *MigrationBalance) isOverloaded(ctx context.Context, node *corev1.Node) (bool, error) {
	if node.Labels[LabelDraining] == "true" {
		return true, nil
	}
	cpu, err := b.metricsReader.CPUUtilisationPercent(ctx, node.Name)
	if err != nil {
		return false, err
	}
	return cpu > cpuOverloadThreshold, nil
}

// findDestination picks the first NodeMigrationCapacity that has spare destination slots.
func (b *MigrationBalance) findDestination(ctx context.Context, sourceNodeName string) (string, error) {
	nmcList := &v1alpha1.NodeMigrationCapacityList{}
	if err := b.client.List(ctx, nmcList); err != nil {
		return "", err
	}
	for _, nmc := range nmcList.Items {
		if nmc.Spec.NodeName == sourceNodeName {
			continue
		}
		if !nmc.Status.Ready {
			continue
		}
		if nmc.Spec.CRIUVersion == "" {
			continue
		}
		if nmc.Status.ActiveDestinationMigrations < nmc.Spec.MaxConcurrentMigrationsDestination {
			return nmc.Spec.NodeName, nil
		}
	}
	return "", fmt.Errorf("no eligible destination node found")
}

// listPodsOnNode returns all pods scheduled on the node (excluding system pods).
func (b *MigrationBalance) listPodsOnNode(ctx context.Context, nodeName string) ([]corev1.Pod, error) {
	podList := &corev1.PodList{}
	if err := b.client.List(ctx, podList, client.MatchingFields{"spec.nodeName": nodeName}); err != nil {
		return nil, err
	}
	return podList.Items, nil
}

// buildPolicyMap indexes the first MigrationPolicy per namespace that has a nodeDrain trigger.
func (b *MigrationBalance) buildPolicyMap(ctx context.Context) (map[string]*v1alpha1.MigrationPolicy, error) {
	policies := &v1alpha1.MigrationPolicyList{}
	if err := b.client.List(ctx, policies); err != nil {
		return nil, err
	}
	m := make(map[string]*v1alpha1.MigrationPolicy, len(policies.Items))
	for i := range policies.Items {
		p := &policies.Items[i]
		if _, exists := m[p.Namespace]; !exists {
			m[p.Namespace] = p
		}
	}
	return m, nil
}

// policyHasCapacity returns true when the policy has not reached its maxConcurrentMigrations.
func (b *MigrationBalance) policyHasCapacity(_ context.Context, policy *v1alpha1.MigrationPolicy) bool {
	return policy.Status.ActiveMigrations < policy.Spec.MaxConcurrentMigrations
}

// createPodMigration emits a PodMigration CR targeting the chosen destination node.
func (b *MigrationBalance) createPodMigration(
	ctx context.Context,
	pod *corev1.Pod,
	destNode string,
	policy *v1alpha1.MigrationPolicy,
) error {
	pm := &v1alpha1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-balance-", pod.Name),
			Namespace:    pod.Namespace,
			Annotations: map[string]string{
				annotationCreatedBy: createdByValue,
			},
		},
		Spec: v1alpha1.PodMigrationSpec{
			PodName:        pod.Name,
			PodNamespace:   pod.Namespace,
			SourcePodUID:   string(pod.UID),
			TargetNodeName: destNode,
			Mode:           v1alpha1.MigrationModePreCopy,
			RollbackOnFailure: true,
		},
	}

	if policy != nil {
		pm.Spec.MigrationPolicyRef = &corev1.LocalObjectReference{Name: policy.Name}
		if policy.Spec.MigrationDefaults != nil {
			d := policy.Spec.MigrationDefaults
			if d.Mode != "" {
				pm.Spec.Mode = d.Mode
			}
			if d.BandwidthLimitMbps != 0 {
				pm.Spec.BandwidthLimitMbps = d.BandwidthLimitMbps
			}
		}
	}

	return b.client.Create(ctx, pm)
}

// isMigratable returns false for pods that should never be migrated by the descheduler:
// static pods, mirror pods, pods already terminating, and DaemonSet-owned pods.
func isMigratable(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil {
		return false
	}
	if _, isMirror := pod.Annotations["kubernetes.io/config.mirror"]; isMirror {
		return false
	}
	for _, ref := range pod.OwnerReferences {
		if ref.Kind == "DaemonSet" {
			return false
		}
	}
	if pod.Namespace == "kube-system" {
		return false
	}
	return true
}

// stubNodeMetricsReader is a no-op implementation for use in unit tests and
// environments without a metrics-server.
type stubNodeMetricsReader struct {
	cpuByNode map[string]int32
}

// NewStubNodeMetricsReader returns a metrics reader driven by a static map.
func NewStubNodeMetricsReader(cpuByNode map[string]int32) NodeMetricsReader {
	return &stubNodeMetricsReader{cpuByNode: cpuByNode}
}

func (s *stubNodeMetricsReader) CPUUtilisationPercent(_ context.Context, nodeName string) (int32, error) {
	if v, ok := s.cpuByNode[nodeName]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("node %s not found in stub", nodeName)
}

// Ensure stubNodeMetricsReader is not referenced in stub lookups by accident in production;
// the type is unexported so only NewStubNodeMetricsReader exposes it.
var _ NodeMetricsReader = (*stubNodeMetricsReader)(nil)

// NMCCapacityReader wraps a client.Client to satisfy NMCReader.
type NMCCapacityReader struct {
	client client.Client
}

// NewNMCCapacityReader creates a reader backed by a controller-runtime client.
func NewNMCCapacityReader(c client.Client) *NMCCapacityReader {
	return &NMCCapacityReader{client: c}
}

// Get satisfies the NMCReader interface from the scheduler-plugins package.
func (r *NMCCapacityReader) Get(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
	return r.client.Get(ctx, key, obj, opts...)
}
