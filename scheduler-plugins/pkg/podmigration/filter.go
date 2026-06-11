//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package podmigration implements the MigrationAware scheduler plugin.
package podmigration

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

const (
	// LabelDraining marks a node that the operator is actively draining via migration.
	// Nodes with this label must not receive new migration destinations.
	LabelDraining = "migration.podmotion.io/draining"

	// PluginName is the scheduler framework plugin identifier.
	PluginName = "MigrationAware"
)

// NMCReader is the interface the filter uses to read NodeMigrationCapacity objects.
// The production implementation wraps a controller-runtime cache; tests inject a stub.
type NMCReader interface {
	Get(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error
}

// MigrationAwareFilter implements the scheduler-plugins FilterPlugin interface.
// It gates destination node selection on live migration readiness.
type MigrationAwareFilter struct {
	reader NMCReader
	scheme *runtime.Scheme
}

// NewMigrationAwareFilter constructs a filter backed by the provided cache reader.
func NewMigrationAwareFilter(reader NMCReader, scheme *runtime.Scheme) *MigrationAwareFilter {
	return &MigrationAwareFilter{reader: reader, scheme: scheme}
}

// Name satisfies the scheduler Plugin interface.
func (f *MigrationAwareFilter) Name() string { return PluginName }

// FilterResult is the outcome of a single node filter evaluation.
type FilterResult struct {
	// Allowed is true when the node passes all migration-readiness checks.
	Allowed bool
	// Reason is set when Allowed is false.
	Reason string
}

// Filter evaluates whether nodeName is an acceptable migration destination.
// Called by the custom scheduler for every node in the candidate set.
//
// Migration-labeled replacement pods (carrying podmotion.io/migration-name) bypass
// all standard scoring and are exclusively routed to the pre-designated destination
// node stored in the PodMigration CR spec.destinationNode.
func (f *MigrationAwareFilter) Filter(ctx context.Context, pod *corev1.Pod, node *corev1.Node) FilterResult {
	// Migration-label fast path: if this pod is a PodMotion replacement, only allow
	// the pre-designated destination node. Filter out all others immediately.
	if pmName := pod.Labels["podmotion.io/migration-name"]; pmName != "" {
		return f.filterForMigrationLabel(ctx, pod.Namespace, pmName, node.Name)
	}

	// Drain label check happens before NMC lookup — avoids a cache round-trip for
	// nodes that are mid-drain and should never receive traffic.
	if node.Labels[LabelDraining] == "true" {
		return FilterResult{false, "node is labeled migration.podmotion.io/draining=true"}
	}

	nmc := &v1alpha1.NodeMigrationCapacity{}
	if err := f.reader.Get(ctx, types.NamespacedName{Name: node.Name}, nmc); err != nil {
		// A missing NMC means the agent has not registered; treat as not ready.
		return FilterResult{false, fmt.Sprintf("NodeMigrationCapacity not found: %v", err)}
	}

	if !nmc.Status.Ready {
		return FilterResult{false, "NMC.status.ready=false"}
	}

	if nmc.Spec.CRIUVersion == "" {
		return FilterResult{false, "NMC.spec.criuVersion is empty — no CRIU installed"}
	}

	limit := nmc.Spec.MaxConcurrentMigrationsDestination
	active := nmc.Status.ActiveDestinationMigrations
	if active >= limit {
		return FilterResult{false, fmt.Sprintf("destination capacity full (%d/%d)", active, limit)}
	}

	return FilterResult{Allowed: true}
}

// filterForMigrationLabel enforces exclusive routing for replacement pods.
// Only the pre-designated destination node (from PodMigration spec.destinationNode)
// is allowed; all other nodes are filtered out.
func (f *MigrationAwareFilter) filterForMigrationLabel(ctx context.Context, namespace, pmName, nodeName string) FilterResult {
	pm := &v1alpha1.PodMigration{}
	if err := f.reader.Get(ctx, types.NamespacedName{Name: pmName, Namespace: namespace}, pm); err != nil {
		return FilterResult{false, fmt.Sprintf("PodMigration %s/%s not found: %v", namespace, pmName, err)}
	}
	destNode := pm.Spec.DestinationNode
	if destNode == "" {
		// DestinationNode not yet set — capacity reservation still in progress; reject all nodes.
		return FilterResult{false, "PodMigration.spec.destinationNode not yet assigned — awaiting capacity reservation"}
	}
	if nodeName != destNode {
		return FilterResult{false, fmt.Sprintf("not the pre-designated migration destination (want %s)", destNode)}
	}
	return FilterResult{Allowed: true}
}
