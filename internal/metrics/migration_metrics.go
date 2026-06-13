/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package metrics — M26 per-migration observability metrics.
// See docs/NORTH_STAR_SPRINT_PLAN.md §M26 for metric definitions.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// MigrationSeqDelta is a Gauge tracking the per-migration TCP sequence delta
	// observed at TrafficVerified=True. seq_delta=0 is the North Star target (ADR-0049).
	// Labels: migration_name, namespace, source_node, dest_node, cni_plugin
	MigrationSeqDelta = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "podmotion",
			Name:      "migration_seq_delta",
			Help:      "TCP sequence delta (snd_nxt post-restore minus pre-freeze snd_nxt) observed at TrafficVerified=True. North Star target is 0.",
		},
		[]string{"migration_name", "namespace", "source_node", "dest_node", "cni_plugin"},
	)

	// MigrationFlowLossTotal counts TCP flows lost per migration at terminal phase
	// (Complete or Failed). A non-zero value means at least one TCP connection was
	// RST or dropped during migration.
	// Labels: migration_name, namespace
	MigrationFlowLossTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "podmotion",
			Name:      "migration_flow_loss_total",
			Help:      "Number of TCP flows lost (RST or dropped) per migration. Emitted at terminal phase (Complete or Failed).",
		},
		[]string{"migration_name", "namespace"},
	)

	// MigrationBlackoutDurationSeconds is a Histogram of zero-window hold durations.
	// Emitted when ZeroWindowDisarmed=True is set. Buckets chosen to capture the
	// <100 ms target freeze window as well as degenerate multi-second holds.
	// Labels: migration_name, namespace, preservation_mode
	MigrationBlackoutDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "podmotion",
			Name:      "migration_blackout_duration_seconds",
			Help:      "Duration of the TC-BPF zero-window hold in seconds. Emitted at ZeroWindowDisarmed=True.",
			Buckets:   []float64{0.05, 0.1, 0.2, 0.3, 0.5, 1.0, 2.0},
		},
		[]string{"migration_name", "namespace", "preservation_mode"},
	)

	// ContainerConsistencyTotal counts per-container checkpoint consistency checks.
	// Emitted once per container during the Checkpointing phase.
	// Labels: migration_name, namespace, container_name, result (pass|fail)
	ContainerConsistencyTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "podmotion",
			Name:      "container_consistency_total",
			Help:      "Per-container checkpoint consistency check outcomes. Emitted during Checkpointing phase.",
		},
		[]string{"migration_name", "namespace", "container_name", "result"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		MigrationSeqDelta,
		MigrationFlowLossTotal,
		MigrationBlackoutDurationSeconds,
		ContainerConsistencyTotal,
	)
}
