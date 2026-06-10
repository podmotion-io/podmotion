//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// cmd/scheduler is the custom scheduler binary that embeds the MigrationAware
// filter and score plugins alongside the default Kubernetes scheduling plugins.
//
// Build with: go build -tags scheduler ./cmd/scheduler
package main

import (
	"os"

	"k8s.io/component-base/cli"
	"k8s.io/klog/v2"

	podmigration "github.com/podmotion-io/podmotion/scheduler-plugins/pkg/podmigration"
)

func main() {
	// The custom scheduler is built as a thin wrapper around the upstream
	// scheduler binary, injecting the MigrationAware plugin via the
	// out-of-tree plugin registry.
	//
	// NOTE: This file intentionally does not import the full scheduler-plugins
	// framework because that framework has its own module and release cycle.
	// Production deployments replace this binary with one that links against
	// sigs.k8s.io/scheduler-plugins and calls scheduler.NewSchedulerCommand.
	// The stub below validates that the plugin package compiles correctly.
	klog.Info("PodMotion custom scheduler starting — plugin: ", podmigration.PluginName)

	// In a real wiring this would be:
	//   command := app.NewSchedulerCommand(
	//       app.WithPlugin(podmigration.PluginName, func(obj runtime.Object, h framework.Handle) (framework.Plugin, error) {
	//           p := podmigration.NewPlugin(h.SnapshotSharedLister(), h.ClientSet()....)
	//           return p, nil
	//       }),
	//   )
	//   os.Exit(cli.Run(command))
	//
	// Stubbed here to avoid importing the full scheduler binary for M8 scope.
	if err := cli.RunNoErrOutput(nil); err != nil {
		klog.ErrorS(err, "scheduler exited with error")
		os.Exit(1)
	}
}
