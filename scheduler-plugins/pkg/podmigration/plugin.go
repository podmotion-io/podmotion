//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package podmigration registers the MigrationAware scheduler plugin.
// Only compiled with the `scheduler` build tag so it does not pollute the
// main operator binary with scheduler-framework dependencies.
package podmigration

import (
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Plugin bundles the filter and score components under a single registration point.
type Plugin struct {
	Filter *MigrationAwareFilter
	Score  *MigrationAwareScore
}

// NewPlugin constructs a Plugin from a live cache reader.
func NewPlugin(reader client.Reader, scheme *runtime.Scheme) *Plugin {
	return &Plugin{
		Filter: NewMigrationAwareFilter(reader, scheme),
		Score:  NewMigrationAwareScore(reader, DefaultWeights),
	}
}
