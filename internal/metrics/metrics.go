/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package metrics registers all PodMotion Prometheus metrics.
// ADR-0030: histograms (not summaries) are used for freeze_duration_ms so that
// percentiles can be aggregated across controller-manager replicas.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// MigrationDuration tracks total wall-clock migration time.
	MigrationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "podmotion",
			Name:      "migration_duration_seconds",
			Help:      "Total wall-clock time for a migration from Pending to terminal phase.",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 12),
		},
		[]string{"mode", "storage_tier", "status"},
	)

	// FreezeDuration tracks the critical freeze window.
	// Histogram chosen over summary so p50/p95/p99 aggregate across replicas (ADR-0030).
	FreezeDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "podmotion",
			Name:      "freeze_duration_ms",
			Help:      "Duration of the CRIU freeze window in milliseconds.",
			Buckets:   []float64{10, 25, 50, 75, 100, 150, 200, 300, 500, 1000},
		},
		[]string{"mode"},
	)

	// PreCopyRounds tracks number of iterative pre-copy rounds before final freeze.
	PreCopyRounds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "podmotion",
			Name:      "precopy_rounds",
			Help:      "Number of pre-copy rounds completed before final freeze.",
			Buckets:   prometheus.LinearBuckets(1, 1, 10),
		},
		[]string{"mode"},
	)

	// CheckpointSize tracks checkpoint artifact size.
	CheckpointSize = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "podmotion",
			Name:      "checkpoint_size_bytes",
			Help:      "Size of the CRIU checkpoint artifact in bytes.",
			Buckets:   prometheus.ExponentialBuckets(1<<20, 2, 12),
		},
	)

	// MigrationsTotal counts completed migrations by mode and terminal status.
	MigrationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "podmotion",
			Name:      "migrations_total",
			Help:      "Total number of migrations that reached a terminal phase.",
		},
		[]string{"mode", "status"},
	)

	// MigrationsFailedTotal counts failures broken down by reason.
	MigrationsFailedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "podmotion",
			Name:      "migrations_failed_total",
			Help:      "Total number of failed migrations broken down by reason.",
		},
		[]string{"reason"},
	)

	// RollbacksTotal counts rollbacks by what triggered them.
	RollbacksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "podmotion",
			Name:      "rollbacks_total",
			Help:      "Total number of rollbacks triggered.",
		},
		[]string{"trigger"},
	)

	// ActiveMigrations tracks in-flight migrations per phase.
	ActiveMigrations = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "podmotion",
			Name:      "active_migrations",
			Help:      "Current number of in-flight migrations per phase.",
		},
		[]string{"phase"},
	)

	// NodesMigrationReady tracks NMC nodes with ready=true.
	NodesMigrationReady = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "podmotion",
			Name:      "nodes_migration_ready",
			Help:      "Number of NodeMigrationCapacity nodes with ready=true.",
		},
	)
)

func init() {
	// Register with controller-runtime's registry so they appear on :8443/metrics.
	metrics.Registry.MustRegister(
		MigrationDuration,
		FreezeDuration,
		PreCopyRounds,
		CheckpointSize,
		MigrationsTotal,
		MigrationsFailedTotal,
		RollbacksTotal,
		ActiveMigrations,
		NodesMigrationReady,
	)
}
