//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

// ADR-0363 verification assertion 2 ("Registration assertion") — closes a verification gap.
//
// The compile-time block in adapter.go (var _ fwk.FilterPlugin = (*Adapter)(nil), etc.) only
// proves the Adapter TYPE satisfies the framework interfaces. It proves nothing about whether
// THIS FILE's wiring — app.NewSchedulerCommand(app.WithPlugin(podmigration.PluginName,
// newMigrationAwarePluginFactory())) — actually produces a plugin-registry entry under the
// correct name backed by a value satisfying those interfaces. A typo in PluginName, a factory
// that constructs the wrong type, or a WithPlugin call that got dropped during a refactor would
// all pass the compile-time check and still fail this. This test exercises the real
// production call path (migrationAwarePluginOption, used verbatim by main()) end to end.
//
// No live cluster is required: app.WithPlugin's returned Option only needs a
// k8s.io/kubernetes/pkg/scheduler/framework/runtime.Registry to populate — it does not touch a
// kubeconfig or the network. Invoking the resulting factory DOES run
// newMigrationAwarePluginFactory's body (ctrl.GetConfig + client.New), so the test points
// KUBECONFIG at a syntactically valid, throwaway kubeconfig file pointing at a bogus server.
// Per sigs.k8s.io/controller-runtime's client.New (pkg/client/client.go) and
// apiutil.NewDynamicRESTMapper (pkg/client/apiutil/restmapper.go), REST-mapper/client
// construction is lazy discovery — it does not dial the API server until a Get/List/Watch call
// is made, and this test never makes one. That is exactly the design newMigrationAwarePluginFactory
// documents (kubeconfig/client construction happens lazily, only when the scheduler command
// actually starts serving) — this test relies on that same laziness to stay cluster-free.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	fwk "k8s.io/kube-scheduler/framework"
	schedulerruntime "k8s.io/kubernetes/pkg/scheduler/framework/runtime"

	"github.com/podmotion-io/podmotion/scheduler-plugins/pkg/podmigration"
)

// fakeKubeconfig is syntactically valid and self-consistent but points at a server that is
// never dialed (see package doc comment above) — it exists only so ctrl.GetConfig() inside the
// real factory resolves successfully without requiring a live cluster or in-cluster env.
const fakeKubeconfig = `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:16443
    insecure-skip-tls-verify: true
  name: fake
contexts:
- context:
    cluster: fake
    user: fake
  name: fake
current-context: fake
users:
- name: fake
  user:
    token: fake-token
`

// TestMigrationAwarePluginRegistration proves ADR-0363 verification assertion 2: the constructed
// scheduler command's plugin registry contains an entry for podmigration.PluginName
// ("MigrationAware") whose factory produces a plugin satisfying both fwk.FilterPlugin and
// fwk.ScorePlugin — built via the real main.go wiring, not a restatement of adapter.go's
// compile-time interface assertion.
func TestMigrationAwarePluginRegistration(t *testing.T) {
	kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfigPath, []byte(fakeKubeconfig), 0o600); err != nil {
		t.Fatalf("writing throwaway kubeconfig fixture: %v", err)
	}
	t.Setenv("KUBECONFIG", kubeconfigPath)
	t.Setenv("KUBERNETES_SERVICE_HOST", "") // force out-of-cluster resolution path

	// This is the exact Option main() passes to app.NewSchedulerCommand — not a
	// re-implementation of it.
	registry := make(schedulerruntime.Registry)
	if err := migrationAwarePluginOption()(registry); err != nil {
		t.Fatalf("applying the production plugin-registration Option against a fresh registry: %v", err)
	}

	factory, ok := registry[podmigration.PluginName]
	if !ok {
		names := make([]string, 0, len(registry))
		for name := range registry {
			names = append(names, name)
		}
		t.Fatalf("scheduler command's plugin registry has no entry for %q; registered names: %v", podmigration.PluginName, names)
	}

	// ctx/obj/handle are all unused by newMigrationAwarePluginFactory's returned closure (see
	// main.go) — it resolves its own kubeconfig/client independently of framework.Handle — so
	// nil is sufficient here and does not weaken what this test proves about registration.
	plugin, err := factory(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("invoking the registered %q factory: %v", podmigration.PluginName, err)
	}
	if plugin == nil {
		t.Fatalf("registered %q factory returned a nil plugin with a nil error", podmigration.PluginName)
	}

	if got := plugin.Name(); got != podmigration.PluginName {
		t.Fatalf("plugin constructed via the %q registry entry reports Name() = %q, want %q", podmigration.PluginName, got, podmigration.PluginName)
	}

	if _, ok := plugin.(fwk.FilterPlugin); !ok {
		t.Fatalf("plugin registered under %q does not satisfy fwk.FilterPlugin", podmigration.PluginName)
	}
	if _, ok := plugin.(fwk.ScorePlugin); !ok {
		t.Fatalf("plugin registered under %q does not satisfy fwk.ScorePlugin", podmigration.PluginName)
	}
}
