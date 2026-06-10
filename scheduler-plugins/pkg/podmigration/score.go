//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package podmigration

import (
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

const (
	// thermalPenaltyThreshold is the thermal throttle % above which a node is penalised.
	// Chosen at 20% to catch moderate throttling before it impacts migration throughput.
	thermalPenaltyThreshold = 20

	maxScore int64 = 100
)

// ScoreWeights controls the relative contribution of each scoring dimension.
// Exported so tests and the plugin.go wiring can tune them without rebuilding.
type ScoreWeights struct {
	NetworkLocality int64
	Thermal         int64
	MigrationLoad   int64
	MemoryHeadroom  int64
}

// DefaultWeights returns the production weight set.
// Locality is highest — cross-AZ traffic cost dominates migration time.
var DefaultWeights = ScoreWeights{
	NetworkLocality: 40,
	Thermal:         20,
	MigrationLoad:   20,
	MemoryHeadroom:  20,
}

// MigrationAwareScore implements the scheduler-plugins ScorePlugin interface.
type MigrationAwareScore struct {
	reader      NMCReader
	weights     ScoreWeights
	// sourcePodRSSBytes is the RSS of the pod being migrated, populated before scoring.
	sourcePodRSSBytes int64
	// sourceNodeLabels holds topology labels of the source node for locality comparison.
	sourceNodeLabels map[string]string
}

// NewMigrationAwareScore constructs a scorer.
func NewMigrationAwareScore(reader NMCReader, weights ScoreWeights) *MigrationAwareScore {
	return &MigrationAwareScore{reader: reader, weights: weights}
}

// Name satisfies the Plugin interface.
func (s *MigrationAwareScore) Name() string { return PluginName }

// SetSourceContext must be called before Score to provide locality and RSS context.
func (s *MigrationAwareScore) SetSourceContext(sourceNodeLabels map[string]string, rssBytes int64) {
	s.sourceNodeLabels = sourceNodeLabels
	s.sourcePodRSSBytes = rssBytes
}

// Score returns a 0-100 score for the candidate destination node.
// Higher is better. Returns an error only when the NMC cannot be read.
func (s *MigrationAwareScore) Score(ctx context.Context, node *corev1.Node) (int64, error) {
	nmc := &v1alpha1.NodeMigrationCapacity{}
	if err := s.reader.Get(ctx, types.NamespacedName{Name: node.Name}, nmc); err != nil {
		return 0, fmt.Errorf("reading NMC for node %s: %w", node.Name, err)
	}

	localityScore := s.scoreLocality(node)
	thermalScore := s.scoreThermal(nmc)
	loadScore := s.scoreMigrationLoad(nmc)
	memScore := s.scoreMemoryHeadroom(node)

	w := s.weights
	total := w.NetworkLocality + w.Thermal + w.MigrationLoad + w.MemoryHeadroom
	if total == 0 {
		return 0, nil
	}

	weighted := (localityScore*w.NetworkLocality +
		thermalScore*w.Thermal +
		loadScore*w.MigrationLoad +
		memScore*w.MemoryHeadroom) / total

	if weighted > maxScore {
		return maxScore, nil
	}
	return weighted, nil
}

// scoreLocality gives full marks for same-zone, half for same-region, zero for cross-region.
// Zone locality is preferred because it minimises cross-switch bandwidth cost during pre-copy.
func (s *MigrationAwareScore) scoreLocality(node *corev1.Node) int64 {
	destZone := node.Labels["topology.kubernetes.io/zone"]
	destRegion := node.Labels["topology.kubernetes.io/region"]

	srcZone := s.sourceNodeLabels["topology.kubernetes.io/zone"]
	srcRegion := s.sourceNodeLabels["topology.kubernetes.io/region"]

	if srcZone != "" && destZone == srcZone {
		return 100
	}
	if srcRegion != "" && destRegion == srcRegion {
		return 50
	}
	return 0
}

// scoreThermal returns 0 when the node exceeds the penalty threshold, 100 otherwise.
func (s *MigrationAwareScore) scoreThermal(nmc *v1alpha1.NodeMigrationCapacity) int64 {
	if nmc.Status.ThermalThrottlePercent == nil {
		return 100
	}
	if *nmc.Status.ThermalThrottlePercent > thermalPenaltyThreshold {
		return 0
	}
	return 100
}

// scoreMigrationLoad prefers nodes with fewer active destination migrations.
// Uses inverse-proportion so a node at zero load gets 100, at max gets near 0.
func (s *MigrationAwareScore) scoreMigrationLoad(nmc *v1alpha1.NodeMigrationCapacity) int64 {
	max := nmc.Spec.MaxConcurrentMigrationsDestination
	if max <= 0 {
		return 0
	}
	active := nmc.Status.ActiveDestinationMigrations
	if active >= max {
		return 0
	}
	return int64((max-active) * 100 / max)
}

// scoreMemoryHeadroom returns 100 when the node has enough allocatable memory to receive
// the migrating pod's RSS, scaled linearly down to 0 when headroom equals the RSS.
func (s *MigrationAwareScore) scoreMemoryHeadroom(node *corev1.Node) int64 {
	alloc, ok := node.Status.Allocatable[corev1.ResourceMemory]
	if !ok {
		return 0
	}
	headroom := allocatableMemoryBytes(alloc)
	rss := s.sourcePodRSSBytes
	if rss <= 0 || headroom <= 0 {
		return 100
	}
	if headroom <= rss {
		return 0
	}
	// Score proportional to headroom beyond what we need: saturates at 5× RSS.
	ratio := (headroom - rss) * 100 / (5 * rss)
	if ratio > 100 {
		return 100
	}
	return ratio
}

func allocatableMemoryBytes(q resource.Quantity) int64 {
	// resource.Quantity.Value() returns bytes directly.
	return q.Value()
}
