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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	fwk "k8s.io/kube-scheduler/framework"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// ADR-0363 B1: Adapter wires the hand-rolled MigrationAwareFilter/MigrationAwareScore
// (filter.go/score.go — untouched, Part A's business logic) into the real upstream
// scheduler-framework FilterPlugin/PreScorePlugin/ScorePlugin interfaces
// (k8s.io/kube-scheduler/framework, "fwk" below).
//
// Deliberately imports ONLY k8s.io/kube-scheduler/framework — the lightweight, separately
// published staging module that defines the plugin interfaces/Handle/CycleState/Status —
// not the full k8s.io/kubernetes module. The heavy k8s.io/kubernetes dependency (needed only
// for cmd/kube-scheduler/app.NewSchedulerCommand, the actual command bootstrapper) is confined
// to cmd/scheduler/main.go; runtime.PluginFactory there is a type alias over exactly the
// fwk.Handle/fwk.Plugin types used here, so the factory closure in main.go satisfies it without
// this package importing anything from k8s.io/kubernetes.

// sourceContextStateKey is the CycleState key the adapter's PreScore writes and Score reads.
// Using CycleState (framework-provided, per-scheduling-cycle-scoped storage) rather than a
// mutable field on the shared, long-lived MigrationAwareScore instance is deliberate: the
// adapter/plugin is registered once and reused across every scheduling cycle, so storing
// source-pod context directly on that shared instance would let one pod's cycle read another
// pod's stale locality/RSS data. Every Score call below explicitly re-derives the source
// context from THIS cycle's CycleState (defaulting to the zero value if absent) and re-applies
// it via SetSourceContext immediately before delegating — so Score never runs against a stale
// or leftover value from a previous cycle.
const sourceContextStateKey fwk.StateKey = "podmotion.io/migration-source-context"

// sourceContextData is the CycleState payload threaded from PreScore to Score.
type sourceContextData struct {
	nodeLabels map[string]string
	rssBytes   int64
}

// Clone satisfies fwk.StateData. Shallow copy is sufficient: nodeLabels is never mutated
// in place after PreScore writes it.
func (d *sourceContextData) Clone() fwk.StateData {
	return &sourceContextData{nodeLabels: d.nodeLabels, rssBytes: d.rssBytes}
}

// Adapter implements fwk.FilterPlugin, fwk.PreScorePlugin, and fwk.ScorePlugin by translating
// framework-shaped calls into the existing MigrationAwareFilter.Filter / MigrationAwareScore.Score
// calls and mapping their hand-rolled return shapes onto *fwk.Status / (int64, *fwk.Status).
type Adapter struct {
	plugin *Plugin
	reader client.Reader
}

// NewAdapter constructs an Adapter backed by the given cache reader. reader is the same
// controller-runtime client.Reader handed to the wrapped Plugin, constructed by the caller
// (cmd/scheduler) independently of framework.Handle, per ADR-0363 B1 — framework.Handle
// exposes no path to a controller-runtime client.Reader for PodMotion's CRDs.
func NewAdapter(reader client.Reader, scheme *runtime.Scheme) *Adapter {
	return &Adapter{
		plugin: NewPlugin(reader, scheme),
		reader: reader,
	}
}

// Name satisfies fwk.Plugin.
func (a *Adapter) Name() string { return PluginName }

// Filter satisfies fwk.FilterPlugin. Maps FilterResult{Allowed:false, Reason} onto
// framework.NewStatus(fwk.Unschedulable, reason) — an unmapped/degraded path here would
// silently let an ineligible node through, so every non-Allowed result must produce a non-nil,
// non-Success Status; there is no code path that falls through to a bare "return nil"/Success.
func (a *Adapter) Filter(ctx context.Context, _ fwk.CycleState, pod *corev1.Pod, nodeInfo fwk.NodeInfo) *fwk.Status {
	node := nodeInfo.Node()
	if node == nil {
		return fwk.NewStatus(fwk.Error, "MigrationAware Filter: nodeInfo.Node() returned nil")
	}
	result := a.plugin.Filter.Filter(ctx, pod, node)
	if !result.Allowed {
		return fwk.NewStatus(fwk.Unschedulable, result.Reason)
	}
	return fwk.NewStatus(fwk.Success)
}

// PreScore satisfies fwk.PreScorePlugin. For migration-labeled replacement pods it resolves the
// owning PodMigration's source node/RSS context and writes it to CycleState for Score to read.
// For ordinary pods (no podmotion.io/migration-name label) it writes an explicit zero-value
// entry so Score always finds a fresh, cycle-scoped value — never a leftover from elsewhere.
//
// Failure to resolve the PodMigration this pod names is fail-closed (fwk.Error): scoring this
// pod against the wrong/absent source context would violate the exact correctness bar this
// adapter exists to satisfy (QA finding: prove correct data threading, not a stale/zero
// fallback). Failure to resolve the source Node (name known but Get fails) is also fail-closed
// for the same reason — silently scoring with blank locality data is indistinguishable from a
// mapping bug that never threaded the data at all. A MigrationCheckpoint that does not exist
// yet (an expected, ordinary point in the migration lifecycle — checkpointing has not happened
// yet) is NOT an error: RSS simply stays 0, which score.go's own scoreMemoryHeadroom already
// treats as a defined, non-penalizing degenerate (unchanged Part A behavior). Any OTHER
// checkpoint-read error is fail-closed.
func (a *Adapter) PreScore(ctx context.Context, state fwk.CycleState, pod *corev1.Pod, _ []fwk.NodeInfo) *fwk.Status {
	pmName := pod.Labels["podmotion.io/migration-name"]
	if pmName == "" {
		state.Write(sourceContextStateKey, &sourceContextData{})
		return fwk.NewStatus(fwk.Success)
	}

	pm := &v1alpha1.PodMigration{}
	if err := a.reader.Get(ctx, types.NamespacedName{Name: pmName, Namespace: pod.Namespace}, pm); err != nil {
		return fwk.NewStatus(fwk.Error, fmt.Sprintf("MigrationAware PreScore: resolving PodMigration %s/%s: %v", pod.Namespace, pmName, err))
	}

	var sourceNodeLabels map[string]string
	if pm.Status.SourceNodeName != "" {
		node := &corev1.Node{}
		if err := a.reader.Get(ctx, types.NamespacedName{Name: pm.Status.SourceNodeName}, node); err != nil {
			return fwk.NewStatus(fwk.Error, fmt.Sprintf("MigrationAware PreScore: resolving source node %s: %v", pm.Status.SourceNodeName, err))
		}
		sourceNodeLabels = node.Labels
	}

	var rssBytes int64
	mcp := &v1alpha1.MigrationCheckpoint{}
	if err := a.reader.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, mcp); err != nil {
		if !apierrors.IsNotFound(err) {
			return fwk.NewStatus(fwk.Error, fmt.Sprintf("MigrationAware PreScore: resolving MigrationCheckpoint %s/%s: %v", pm.Namespace, pm.Name, err))
		}
		// Not found: checkpoint hasn't been captured yet. rssBytes stays 0 — an
		// already-defined, non-penalizing degenerate in scoreMemoryHeadroom (Part A).
	} else if mcp.Spec.SizeBytes != nil {
		rssBytes = *mcp.Spec.SizeBytes
	}

	state.Write(sourceContextStateKey, &sourceContextData{nodeLabels: sourceNodeLabels, rssBytes: rssBytes})
	return fwk.NewStatus(fwk.Success)
}

// Score satisfies fwk.ScorePlugin. Before every delegated call it re-derives this cycle's
// source context from CycleState (defaulting to the zero value if PreScore did not run or
// wrote nothing) and re-applies it via SetSourceContext immediately before calling
// MigrationAwareScore.Score — so the mapped (int64, error) result is always computed against
// the data this cycle's PreScore actually resolved, never a value threaded (or left behind) by
// an earlier cycle on the shared plugin instance.
func (a *Adapter) Score(ctx context.Context, state fwk.CycleState, pod *corev1.Pod, nodeInfo fwk.NodeInfo) (int64, *fwk.Status) {
	node := nodeInfo.Node()
	if node == nil {
		return 0, fwk.NewStatus(fwk.Error, "MigrationAware Score: nodeInfo.Node() returned nil")
	}

	var ctxData sourceContextData
	if raw, err := state.Read(sourceContextStateKey); err == nil {
		if d, ok := raw.(*sourceContextData); ok {
			ctxData = *d
		}
	}
	a.plugin.Score.SetSourceContext(ctxData.nodeLabels, ctxData.rssBytes)

	score, err := a.plugin.Score.Score(ctx, pod, node)
	if err != nil {
		return 0, fwk.NewStatus(fwk.Error, err.Error())
	}
	return score, fwk.NewStatus(fwk.Success)
}

// ScoreExtensions satisfies fwk.ScorePlugin. MigrationAwareScore.Score already returns an
// absolute 0-100 score independent of other nodes' results (see score.go) — there is nothing
// to normalize, so no ScoreExtensions implementation is needed.
func (a *Adapter) ScoreExtensions() fwk.ScoreExtensions { return nil }

var (
	_ fwk.FilterPlugin   = (*Adapter)(nil)
	_ fwk.PreScorePlugin = (*Adapter)(nil)
	_ fwk.ScorePlugin    = (*Adapter)(nil)
)
