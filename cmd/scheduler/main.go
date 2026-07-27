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
//
// ADR-0363 (B1): this is a real upstream scheduler command
// (k8s.io/kubernetes/cmd/kube-scheduler/app.NewSchedulerCommand), not the prior
// zero-plugin cli.RunNoErrOutput(nil) stub. The MigrationAware plugin is registered via
// app.WithPlugin, backed by a new adapter (scheduler-plugins/pkg/podmigration/adapter.go)
// that translates the framework's FilterPlugin/PreScorePlugin/ScorePlugin calls into the
// existing hand-rolled MigrationAwareFilter/MigrationAwareScore (filter.go/score.go,
// Part A of ADR-0362 — untouched here).
//
// k8s.io/kubernetes is imported ONLY in this file (for app.NewSchedulerCommand/app.WithPlugin,
// the actual command bootstrapper — there is no lighter substitute for that). The adapter
// package itself, and everything it needs to satisfy the plugin interfaces, depends only on
// the lightweight k8s.io/kube-scheduler/framework staging module — see adapter.go's doc
// comment. Both are gated behind the `scheduler` build tag, so `go build ./...` (default,
// no tags) neither compiles this file nor pulls k8s.io/kubernetes into its package graph.
package main

import (
	"context"
	"fmt"
	"os"

	apimachineryruntime "k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/component-base/cli"
	fwk "k8s.io/kube-scheduler/framework"
	app "k8s.io/kubernetes/cmd/kube-scheduler/app"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	migrationv1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/scheduler-plugins/pkg/podmigration"
)

// newMigrationAwarePluginFactory returns the runtime.PluginFactory app.WithPlugin registers
// under podmigration.PluginName. Kubeconfig/client construction happens lazily, INSIDE the
// closure, not at package/command-construction time: the factory only runs when the scheduler
// command actually starts serving (Setup/Run), never during cobra flag parsing or --help — so
// `podmotion-scheduler --help` exits 0 with no kubeconfig/cluster present (§P-VERIFY assertion
// 4), and a missing/invalid kubeconfig fails the running binary loudly at startup rather than
// producing a plugin that silently never gates anything.
func newMigrationAwarePluginFactory() func(ctx context.Context, obj apimachineryruntime.Object, h fwk.Handle) (fwk.Plugin, error) {
	return func(_ context.Context, _ apimachineryruntime.Object, _ fwk.Handle) (fwk.Plugin, error) {
		// In-cluster config, matching how the operator (cmd/main.go, ctrl.GetConfigOrDie)
		// and agent (cmd/agent/main.go, rest.InClusterConfig) resolve their own client
		// config. Constructed independently of framework.Handle: Handle exposes only a
		// plain kubernetes.Interface/SharedInformerFactory, neither of which knows about
		// PodMotion's CRDs (NodeMigrationCapacity, PodMigration, MigrationCheckpoint) that
		// the wrapped plugin's NMCReader needs to read.
		cfg, err := ctrl.GetConfig()
		if err != nil {
			return nil, fmt.Errorf("MigrationAware plugin: resolving kubeconfig: %w", err)
		}

		scheme := apimachineryruntime.NewScheme()
		if err := clientgoscheme.AddToScheme(scheme); err != nil {
			return nil, fmt.Errorf("MigrationAware plugin: registering client-go scheme: %w", err)
		}
		if err := migrationv1alpha1.AddToScheme(scheme); err != nil {
			return nil, fmt.Errorf("MigrationAware plugin: registering podmotion scheme: %w", err)
		}

		cl, err := client.New(cfg, client.Options{Scheme: scheme})
		if err != nil {
			return nil, fmt.Errorf("MigrationAware plugin: constructing client: %w", err)
		}

		return podmigration.NewAdapter(cl, scheme), nil
	}
}

// migrationAwarePluginOption returns the app.Option that registers the MigrationAware plugin
// factory under podmigration.PluginName. Extracted to its own function (rather than inlined in
// main) so main_test.go can exercise this EXACT production wiring — the real app.WithPlugin call
// wrapping the real newMigrationAwarePluginFactory closure — instead of a re-declaration of it.
func migrationAwarePluginOption() app.Option {
	return app.WithPlugin(podmigration.PluginName, newMigrationAwarePluginFactory())
}

func main() {
	command := app.NewSchedulerCommand(migrationAwarePluginOption())
	os.Exit(cli.Run(command))
}
