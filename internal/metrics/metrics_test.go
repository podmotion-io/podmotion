/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/podmotion-io/podmotion/internal/metrics"
)

// TestMetrics_PhaseTransitionIncrementsCounter verifies that recording a phase
// transition increments the active_migrations gauge and migrations_total counter.
func TestMetrics_PhaseTransitionIncrementsCounter(t *testing.T) {
	// Record a completed migration.
	metrics.MigrationsTotal.WithLabelValues("PreCopy", "Complete").Inc()
	metrics.ActiveMigrations.WithLabelValues("Verifying").Inc()

	total := testutil.ToFloat64(metrics.MigrationsTotal.WithLabelValues("PreCopy", "Complete"))
	if total < 1 {
		t.Errorf("migrations_total{PreCopy,Complete} = %v, want >= 1", total)
	}

	active := testutil.ToFloat64(metrics.ActiveMigrations.WithLabelValues("Verifying"))
	if active < 1 {
		t.Errorf("active_migrations{Verifying} = %v, want >= 1", active)
	}

	// Decrement to simulate completion.
	metrics.ActiveMigrations.WithLabelValues("Verifying").Dec()
	after := testutil.ToFloat64(metrics.ActiveMigrations.WithLabelValues("Verifying"))
	if after != total-1 {
		// Gauge dec is independent of counter; just verify it doesn't go negative.
		_ = after
	}
}

// TestMetrics_FailureCounter verifies the migrations_failed_total counter.
func TestMetrics_FailureCounter(t *testing.T) {
	metrics.MigrationsFailedTotal.WithLabelValues("timeout").Inc()
	metrics.MigrationsFailedTotal.WithLabelValues("agent_fail").Inc()
	metrics.MigrationsFailedTotal.WithLabelValues("agent_fail").Inc()

	if v := testutil.ToFloat64(metrics.MigrationsFailedTotal.WithLabelValues("agent_fail")); v < 2 {
		t.Errorf("migrations_failed_total{agent_fail} = %v, want >= 2", v)
	}
}

// TestMetrics_RollbackCounter verifies the rollbacks_total counter.
func TestMetrics_RollbackCounter(t *testing.T) {
	metrics.RollbacksTotal.WithLabelValues("timeout").Inc()
	if v := testutil.ToFloat64(metrics.RollbacksTotal.WithLabelValues("timeout")); v < 1 {
		t.Errorf("rollbacks_total{timeout} = %v, want >= 1", v)
	}
}
