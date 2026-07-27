/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package placement holds the framework-agnostic core of the MigrationAware
// destination-selection logic: NMC-readiness/CRIU-version/capacity filtering
// (Filter) plus locality/thermal/load/memory-headroom scoring (Score).
//
// ADR-0365 packaging resolution: scheduler-plugins/pkg/podmigration's
// filter.go/score.go/plugin.go carried a `//go:build scheduler` tag inherited
// from that package's adapter.go (which genuinely needs the scheduler
// framework, k8s.io/kube-scheduler/framework), even though the filter/score
// decision logic itself imports only client.Reader/corev1/apimachinery — no
// scheduler-framework package at all. That made the decision logic
// unreachable from the controller binary without either (a) pulling in the
// scheduler build tag (and, transitively, risking a future scheduler-
// framework dependency leaking into the operator binary), or (b) duplicating
// the logic (explicitly rejected by ADR-0365 — two independent sources of
// truth for "where is this migration going" is exactly the hazard the ADR
// series exists to avoid).
//
// This package is the extraction: the ONE implementation of Filter/Score
// semantics, carrying no build tag and no scheduler-framework dependency, so
// both scheduler-plugins/pkg/podmigration (which re-exports it for the
// `scheduler`-tagged adapter.go to wire into the real scheduler framework)
// and internal/controller (which calls it directly, synchronously, against
// the live node list — ADR-0365's early-decision step) import the same code.
package placement

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

const (
	// LabelDraining marks a node that the operator is actively draining via migration.
	// Nodes with this label must not receive new migration destinations.
	LabelDraining = "migration.podmotion.io/draining"

	// TaintKeyControlPlane / TaintKeyControlPlaneLegacy are the standard kubeadm
	// role taints/labels a control-plane node carries. A node bearing either (as a
	// taint or a node-role label) is treated as a control plane by IsControlPlaneNode.
	TaintKeyControlPlane       = "node-role.kubernetes.io/control-plane"
	TaintKeyControlPlaneLegacy = "node-role.kubernetes.io/master"

	// thermalPenaltyThreshold is the thermal throttle % above which a node is penalised.
	// Chosen at 20% to catch moderate throttling before it impacts migration throughput.
	thermalPenaltyThreshold = 20

	maxScore int64 = 100
)

// IsControlPlaneNode reports whether node is a Kubernetes control-plane node, by
// either the standard kubeadm role taint (node-role.kubernetes.io/control-plane or
// the legacy .../master) or the equivalent node-role label. The unpinned early
// destination resolver (resolveEarlyDestinationNode, ADR-0365) uses this to keep
// migration workloads off the control plane whenever a worker node is eligible —
// control plane remains selectable only as a last resort when no worker qualifies.
func IsControlPlaneNode(node *corev1.Node) bool {
	if node == nil {
		return false
	}
	for _, taint := range node.Spec.Taints {
		if taint.Key == TaintKeyControlPlane || taint.Key == TaintKeyControlPlaneLegacy {
			return true
		}
	}
	if _, ok := node.Labels[TaintKeyControlPlane]; ok {
		return true
	}
	if _, ok := node.Labels[TaintKeyControlPlaneLegacy]; ok {
		return true
	}
	return false
}

// NMCReader is the interface the filter/score logic uses to read
// NodeMigrationCapacity (and, on the migration-label fast path, PodMigration)
// objects. The production implementation wraps a controller-runtime cache;
// tests inject a stub. client.Client (embedded on the controller's own
// reconciler) satisfies this directly.
type NMCReader interface {
	Get(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error
}

// FilterResult is the outcome of a single node filter evaluation.
type FilterResult struct {
	// Allowed is true when the node passes all migration-readiness checks.
	Allowed bool
	// Reason is set when Allowed is false.
	Reason string
}

// resolveDestinationNode implements the canonical destination-resolution chain every
// other consumer in the codebase already uses — see internal/webhook/pod_webhook.go
// (destNode resolution ahead of the CNI-plugin lookup) and
// internal/controller/podmigration_controller.go's createReplacementPod:
//
//	Status.DestinationNodeName -> Spec.TargetNodeName -> Spec.DestinationNode
//
// Status.DestinationNodeName is the real controller-written destination
// (cacheDestinationNodeFromSpec / resolveEarlyDestinationNode), Spec.TargetNodeName is
// the user-pinned override (set before the controller has cached anything), and
// Spec.DestinationNode is a last-resort fallback with no writers today. Returns "" if
// none of the three are set; callers MUST treat that as fail-closed (reject all nodes)
// — never guess a destination.
func resolveDestinationNode(pm *v1alpha1.PodMigration) string {
	if pm.Status.DestinationNodeName != "" {
		return pm.Status.DestinationNodeName
	}
	if pm.Spec.TargetNodeName != "" {
		return pm.Spec.TargetNodeName
	}
	return pm.Spec.DestinationNode
}

// MigrationAwareFilter gates destination node selection on live migration readiness.
// It is the framework-agnostic core wrapped by scheduler-plugins/pkg/podmigration's
// MigrationAwareFilter (the scheduler FilterPlugin) and called directly by the
// controller's resolveEarlyDestinationNode (ADR-0365).
type MigrationAwareFilter struct {
	reader NMCReader
	scheme *runtime.Scheme
}

// NewMigrationAwareFilter constructs a filter backed by the provided cache reader.
func NewMigrationAwareFilter(reader NMCReader, scheme *runtime.Scheme) *MigrationAwareFilter {
	return &MigrationAwareFilter{reader: reader, scheme: scheme}
}

// Filter evaluates whether node is an acceptable migration destination for pod.
//
// Migration-labeled replacement pods (carrying podmotion.io/migration-name) bypass
// all standard scoring and are exclusively routed to the pre-designated destination
// node resolved via the canonical fallback chain (resolveDestinationNode):
// Status.DestinationNodeName -> Spec.TargetNodeName -> Spec.DestinationNode. Callers
// with no replacement pod yet (e.g. the controller's early decision, ADR-0365) should
// pass a pod with no podmotion.io/migration-name label so this exercises the standard
// NMC-readiness path instead.
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
// Only the pre-designated destination node (resolved via resolveDestinationNode's
// canonical fallback chain) is allowed; all other nodes are filtered out.
func (f *MigrationAwareFilter) filterForMigrationLabel(ctx context.Context, namespace, pmName, nodeName string) FilterResult {
	pm := &v1alpha1.PodMigration{}
	if err := f.reader.Get(ctx, types.NamespacedName{Name: pmName, Namespace: namespace}, pm); err != nil {
		return FilterResult{false, fmt.Sprintf("PodMigration %s/%s not found: %v", namespace, pmName, err)}
	}
	destNode := resolveDestinationNode(pm)
	if destNode == "" {
		// None of Status.DestinationNodeName / Spec.TargetNodeName / Spec.DestinationNode
		// are set yet — capacity reservation still in progress. Fail closed: reject all
		// nodes rather than guess. The pod holds Pending/SchedulingGated and requeues once
		// the controller writes Status.DestinationNodeName.
		return FilterResult{false, "destination node not yet resolved (status.destinationNodeName / spec.targetNodeName / spec.destinationNode all empty) — awaiting capacity reservation"}
	}
	if nodeName != destNode {
		return FilterResult{false, fmt.Sprintf("not the pre-designated migration destination (want %s)", destNode)}
	}
	return FilterResult{Allowed: true}
}

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

// MigrationAwareScore is the framework-agnostic core wrapped by
// scheduler-plugins/pkg/podmigration's MigrationAwareScore (the scheduler ScorePlugin)
// and called directly by the controller's resolveEarlyDestinationNode (ADR-0365).
type MigrationAwareScore struct {
	reader  NMCReader
	weights ScoreWeights
	// sourcePodRSSBytes is the RSS of the pod being migrated, populated before scoring.
	sourcePodRSSBytes int64
	// sourceNodeLabels holds topology labels of the source node for locality comparison.
	sourceNodeLabels map[string]string
}

// NewMigrationAwareScore constructs a scorer.
func NewMigrationAwareScore(reader NMCReader, weights ScoreWeights) *MigrationAwareScore {
	return &MigrationAwareScore{reader: reader, weights: weights}
}

// SetSourceContext must be called before Score to provide locality and RSS context.
func (s *MigrationAwareScore) SetSourceContext(sourceNodeLabels map[string]string, rssBytes int64) {
	s.sourceNodeLabels = sourceNodeLabels
	s.sourcePodRSSBytes = rssBytes
}

// Score returns a 0-100 score for the candidate destination node.
// Higher is better. Returns an error only when the NMC cannot be read.
//
// Migration-labeled replacement pods (carrying podmotion.io/migration-name) bypass
// all multi-factor scoring and return MaxNodeScore only for the pre-designated
// destination node, 0 for all others.
func (s *MigrationAwareScore) Score(ctx context.Context, pod *corev1.Pod, node *corev1.Node) (int64, error) {
	// Migration-label fast path: exclusively score the pre-designated destination.
	if pmName := pod.Labels["podmotion.io/migration-name"]; pmName != "" {
		return s.scoreForMigrationLabel(ctx, pod.Namespace, pmName, node.Name)
	}

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

// scoreForMigrationLabel returns maxScore for the pre-designated destination node
// (resolved via resolveDestinationNode's canonical fallback chain:
// Status.DestinationNodeName -> Spec.TargetNodeName -> Spec.DestinationNode) and 0 for
// every other node, including the case where the chain has not resolved yet — Score is
// never the fail-closed gate (Filter is), but it must never award a guessed node
// maxScore either, so an unresolved destination scores every candidate 0.
func (s *MigrationAwareScore) scoreForMigrationLabel(ctx context.Context, namespace, pmName, nodeName string) (int64, error) {
	pm := &v1alpha1.PodMigration{}
	if err := s.reader.Get(ctx, types.NamespacedName{Name: pmName, Namespace: namespace}, pm); err != nil {
		return 0, fmt.Errorf("scoreForMigrationLabel: PodMigration %s/%s not found: %w", namespace, pmName, err)
	}
	destNode := resolveDestinationNode(pm)
	if destNode != "" && destNode == nodeName {
		return maxScore, nil
	}
	return 0, nil
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
	return int64((max - active) * 100 / max)
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

// Plugin bundles the filter and score components under a single registration point.
type Plugin struct {
	Filter *MigrationAwareFilter
	Score  *MigrationAwareScore
}

// NewPlugin constructs a Plugin from a live cache reader.
func NewPlugin(reader NMCReader, scheme *runtime.Scheme) *Plugin {
	return &Plugin{
		Filter: NewMigrationAwareFilter(reader, scheme),
		Score:  NewMigrationAwareScore(reader, DefaultWeights),
	}
}
