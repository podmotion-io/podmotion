/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package audit provides structured lifecycle event logging for PodMigration CRs.
// Events are emitted both as structured JSON log lines (via zap) and as Kubernetes
// Events on the PodMigration object for kubectl describe visibility.
package audit

import (
	"context"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// AuditEvent is the canonical shape written to the structured log.
type AuditEvent struct {
	Time          string `json:"time"`
	MigrationName string `json:"migrationName"`
	Namespace     string `json:"namespace"`
	Phase         string `json:"phase"`
	Actor         string `json:"actor"`
	Reason        string `json:"reason"`
	SourceNode    string `json:"sourceNode"`
	DestNode      string `json:"destNode"`
}

// Logger writes structured audit events for migration lifecycle transitions.
type Logger struct {
	zap      *zap.Logger
	recorder record.EventRecorder
}

// NewLogger constructs an audit Logger backed by the provided zap logger and
// Kubernetes EventRecorder. Pass nil recorder in unit tests.
func NewLogger(zapLog *zap.Logger, scheme *runtime.Scheme, recorder record.EventRecorder) *Logger {
	return &Logger{
		zap:      zapLog.Named("audit"),
		recorder: recorder,
	}
}

// LogPhaseTransition records a phase change on a PodMigration.
func (l *Logger) LogPhaseTransition(ctx context.Context, pm *pmv1.PodMigration, newPhase, actor, reason string) {
	evt := AuditEvent{
		Time:          time.Now().UTC().Format(time.RFC3339Nano),
		MigrationName: pm.Name,
		Namespace:     pm.Namespace,
		Phase:         newPhase,
		Actor:         actor,
		Reason:        reason,
		SourceNode:    pm.Status.SourceNodeName,
		DestNode:      pm.Status.DestinationNodeName,
	}
	l.zap.Info("phase_transition",
		zap.String("time", evt.Time),
		zap.String("migration", evt.MigrationName),
		zap.String("namespace", evt.Namespace),
		zap.String("phase", evt.Phase),
		zap.String("actor", evt.Actor),
		zap.String("reason", evt.Reason),
		zap.String("sourceNode", evt.SourceNode),
		zap.String("destNode", evt.DestNode),
	)
	if l.recorder != nil {
		l.recorder.Event(pm, corev1.EventTypeNormal, "PhaseTransition",
			"phase="+newPhase+" actor="+actor+" reason="+reason)
	}
}

// LogRollback records a rollback event on a PodMigration.
func (l *Logger) LogRollback(ctx context.Context, pm *pmv1.PodMigration, trigger, reason string) {
	l.zap.Warn("rollback",
		zap.String("time", time.Now().UTC().Format(time.RFC3339Nano)),
		zap.String("migration", pm.Name),
		zap.String("namespace", pm.Namespace),
		zap.String("trigger", trigger),
		zap.String("reason", reason),
		zap.String("sourceNode", pm.Status.SourceNodeName),
		zap.String("destNode", pm.Status.DestinationNodeName),
	)
	if l.recorder != nil {
		l.recorder.Event(pm, corev1.EventTypeWarning, "Rollback",
			"trigger="+trigger+" reason="+reason)
	}
}

// LogCompletion records a terminal completion event with duration.
func (l *Logger) LogCompletion(ctx context.Context, pm *pmv1.PodMigration, durationMs int64) {
	l.zap.Info("completion",
		zap.String("time", time.Now().UTC().Format(time.RFC3339Nano)),
		zap.String("migration", pm.Name),
		zap.String("namespace", pm.Namespace),
		zap.String("phase", string(pm.Status.Phase)),
		zap.Int64("durationMs", durationMs),
		zap.String("sourceNode", pm.Status.SourceNodeName),
		zap.String("destNode", pm.Status.DestinationNodeName),
	)
	if l.recorder != nil {
		l.recorder.Eventf(pm, corev1.EventTypeNormal, "Completed",
			"phase=%s durationMs=%d", pm.Status.Phase, durationMs)
	}
}
