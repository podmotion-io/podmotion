//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package podmigration

import (
	"github.com/podmotion-io/podmotion/internal/placement"
)

// ScoreWeights controls the relative contribution of each scoring dimension.
// Exported so tests and the plugin.go wiring can tune them without rebuilding.
//
// ADR-0365 (packaging resolution): alias onto internal/placement — see filter.go's NMCReader doc comment
// for why the real logic now lives there, build-tag-free.
type ScoreWeights = placement.ScoreWeights

// DefaultWeights returns the production weight set.
// Locality is highest — cross-AZ traffic cost dominates migration time.
var DefaultWeights = placement.DefaultWeights

// MigrationAwareScore implements the scheduler-plugins ScorePlugin interface.
type MigrationAwareScore = placement.MigrationAwareScore

// NewMigrationAwareScore constructs a scorer.
func NewMigrationAwareScore(reader NMCReader, weights ScoreWeights) *MigrationAwareScore {
	return placement.NewMigrationAwareScore(reader, weights)
}
