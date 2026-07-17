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

	// DatapathCleanupLeakTotal counts VerifyCleanup(CUTOVER_COMPLETE) retry-budget exhaustion
	// events (ADR-0241 item 1 / NR-BLOCK-1). Incremented once per still-present object on the
	// exhausted-retry branch of reconcileVerifying's cni0 cleanup verification, so a leak of
	// only the neigh entry versus only the host route (or both) is distinguishable without
	// parsing the ConditionCni0CleanupVerified message string.
	// Labels: migration_name, namespace, object ("cni0_neigh" | "cni0_host_route")
	DatapathCleanupLeakTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "podmotion",
			Name:      "datapath_cleanup_leak_total",
			Help:      "Per-object cni0 cleanup verification leaks after the ADR-0241 3-attempt retry budget is exhausted.",
		},
		[]string{"migration_name", "namespace", "object"},
	)

	// ZeroWindowHoldRuleReassertTotal counts FORWARD ACCEPT / NOTRACK rule reassertions
	// performed by the agent-side idempotent reconcile loop when it detects an external flush
	// during an active zero-window hold (ADR-0240 D1/D4). Named with the "pm_" prefix (not
	// "podmotion_") per ADR-0240 D4/D4a's literal metric name.
	// Labels: migration ("migration=" per ADR-0240 D1a/D4a), rule ("forward_accept" | "notrack")
	ZeroWindowHoldRuleReassertTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pm",
			Name:      "zero_window_hold_rule_reassert_total",
			Help:      "Count of FORWARD ACCEPT / NOTRACK rule reassertions by the zero-window hold flush-detection loop.",
		},
		[]string{"migration", "rule"},
	)

	// ShmemPagemapGuardFiredTotal counts ADR-0246 fail-closed completeness-guard detections —
	// i.e. Checkpointed=False/ShmemPagemapMissing events, one per Checkpoint RPC failure caused
	// by the CRIU 4.2 anon-shmem dump defect (missing pagemap-shmem-<shmid>.img). Distinct from
	// ContainerConsistencyTotal{result="fail"}, which fires for every Checkpoint RPC error
	// regardless of cause; this counter isolates the specific, currently-unfixable-upstream
	// defect so it is trend-visible without parsing the Checkpointed condition message string.
	// Labels: migration_name, namespace
	ShmemPagemapGuardFiredTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "podmotion",
			Name:      "shmem_pagemap_guard_fired_total",
			Help:      "Count of ADR-0246 fail-closed shmem-pagemap completeness guard detections (CRIU 4.2 anon-shmem dump defect).",
		},
		[]string{"migration_name", "namespace"},
	)

	// ZeroWindowHoldRuleReassertSuppressedTotal counts reassert attempts skipped because the
	// per-migration token-bucket reassert limiter (burst 5, refill 1/2s) was empty (ADR-0240
	// D1a). Detection (the iptables -C probe) is never suppressed — only the reapply write is
	// — so a runaway-flush condition remains observable via this counter even while writes are
	// capped.
	// Labels: migration
	ZeroWindowHoldRuleReassertSuppressedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pm",
			Name:      "zero_window_hold_rule_reassert_suppressed_total",
			Help:      "Count of rule reassert attempts suppressed by the per-migration token-bucket limiter (ADR-0240 D1a).",
		},
		[]string{"migration"},
	)

	// ReplacementEndpointRemovalExhaustedTotal counts ADR-0350 D3/D6 retry-budget exhaustion
	// events on the replacement-endpoint-removal happens-before gate. Incremented once per
	// exhausted reconcile attempt, labeled by the mode-distinguishing reason so a genuinely
	// stuck replacement pod (ReplacementPodUndeletable) is trend-distinguishable from transient
	// EndpointSlice CAS contention (ReplacementEndpointRemovalContended).
	// Labels: migration_name, namespace, reason
	ReplacementEndpointRemovalExhaustedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "podmotion",
			Name:      "replacement_endpoint_removal_exhausted_total",
			Help:      "Count of ADR-0350 replacement-endpoint-removal retry-budget exhaustion events, labeled by failure mode reason.",
		},
		[]string{"migration_name", "namespace", "reason"},
	)

	// CgroupAnchorOutcomeTotal counts ADR-0351 (D3.1a retargeted G10) cgroup-anchor primitive
	// outcomes at the joinNsRestore anchor gate — REPLACES SandboxPausePIDWaitOutcomeTotal, whose
	// producer (sandboxPausePIDWaiting) is deleted in the same diff. No "polls" dimension: the
	// primitive is zero-query (D1.2), so a "polls>1 = race exercised" label has nothing to measure
	// anymore.
	// Labels: outcome ("anchored" | "skipped-no-nri-cgroup-path" | "failed-closed-resolve" | "failed-closed-write")
	CgroupAnchorOutcomeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "podmotion",
			Name:      "cgroup_anchor_outcome_total",
			Help:      "Count of ADR-0351 cgroup-anchor primitive outcomes at the joinNsRestore anchor gate, labeled by outcome.",
		},
		[]string{"outcome"},
	)

	// BrokerExecDeadlineAbortsTotal counts ADR-0354 D7 caller-deadline-enforcement aborts — a
	// restore-path broker exec (funneling Client.do) that was aborted BECAUSE the caller's
	// migration ctx deadline/cancellation fired, not because the broker or CRIU genuinely
	// failed. Incremented ONLY on that specific exit — never on a broker-unreachable/rejected
	// SpawnErr or a non-zero CRIU exit code (those keep their existing
	// MigrationsFailedTotal.WithLabelValues("restore_...") labels) — so post-incident review can
	// tell "the invariant-#8 guardrail fired as designed" from "the broker/CRIU actually failed"
	// without string-matching an error message.
	// Labels: leg ("broker_cmd" | "broker_criu_poll_cgroup" | "broker_criu_poll_pidfile" | "netns_exec")
	BrokerExecDeadlineAbortsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "podmotion",
			Name:      "broker_exec_deadline_aborts_total",
			Help:      "Count of ADR-0354 caller-deadline-enforcement aborts on restore-path broker execs, labeled by the shim/leg that aborted.",
		},
		[]string{"leg"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		MigrationSeqDelta,
		MigrationFlowLossTotal,
		MigrationBlackoutDurationSeconds,
		ContainerConsistencyTotal,
		DatapathCleanupLeakTotal,
		ZeroWindowHoldRuleReassertTotal,
		ZeroWindowHoldRuleReassertSuppressedTotal,
		ShmemPagemapGuardFiredTotal,
		ReplacementEndpointRemovalExhaustedTotal,
		CgroupAnchorOutcomeTotal,
		BrokerExecDeadlineAbortsTotal,
	)
}
