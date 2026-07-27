//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package podmigration implements the MigrationAware scheduler plugin.
package podmigration

import (
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/podmotion-io/podmotion/internal/placement"
)

const (
	// LabelDraining marks a node that the operator is actively draining via migration.
	// Nodes with this label must not receive new migration destinations.
	LabelDraining = placement.LabelDraining

	// PluginName is the scheduler framework plugin identifier.
	PluginName = "MigrationAware"
)

// NMCReader is the interface the filter uses to read NodeMigrationCapacity objects.
// The production implementation wraps a controller-runtime cache; tests inject a stub.
//
// ADR-0365 packaging resolution: this — and MigrationAwareFilter/FilterResult below
// — are thin type aliases onto the framework-agnostic internal/placement package, which
// now carries the actual Filter decision logic build-tag-free. filter.go/score.go used
// to carry the real logic directly under this package's `scheduler` build tag (inherited
// from adapter.go, the one file in this package that genuinely needs the scheduler
// framework); that made the logic unreachable from the controller binary without either
// pulling that tag in (risking a future scheduler-framework dependency leaking into the
// operator binary) or duplicating it (rejected in ADR-0365). Extracting to
// internal/placement gives both this scheduler-tagged package (wired into the real
// scheduler framework by adapter.go) and internal/controller (calling it directly against
// the live node list, ADR-0365's decision) exactly one implementation.
type NMCReader = placement.NMCReader

// MigrationAwareFilter implements the scheduler-plugins FilterPlugin interface.
// It gates destination node selection on live migration readiness.
type MigrationAwareFilter = placement.MigrationAwareFilter

// FilterResult is the outcome of a single node filter evaluation.
type FilterResult = placement.FilterResult

// NewMigrationAwareFilter constructs a filter backed by the provided cache reader.
func NewMigrationAwareFilter(reader NMCReader, scheme *runtime.Scheme) *MigrationAwareFilter {
	return placement.NewMigrationAwareFilter(reader, scheme)
}
