/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package nri implements the NRI (Node Resource Interface) plugin for PodMotion.
// NRI is containerd's plugin hook mechanism — containerd calls registered plugins
// on lifecycle events (Created, Started, Stopping, Stopped, Removed).
//
// PodMotion hooks the Stopping event to trigger CRIU pre-dump before the container
// is fully stopped (M5). In M4 this is a logging stub that establishes the plugin
// registration path without requiring a running containerd.
//
// The plugin binary is installed at /usr/local/lib/nri/podmotion-nri-plugin
// (the NRI plugin discovery path configured in containerd's NRI settings).
package nri

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("nri-plugin")

// PluginName is the NRI plugin identifier registered with containerd.
const PluginName = "podmotion"

// PluginIndex controls the invocation order among NRI plugins (lower = earlier).
// 10 puts us ahead of most plugins but after security enforcement plugins.
const PluginIndex = "10"

// ContainerEvent mirrors the subset of the NRI ContainerAdjustment event we care about.
type ContainerEvent struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Pod       string            `json:"pod"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Plugin is the NRI lifecycle hook handler.
type Plugin struct {
	// OnStopping is called for each Stopping event.
	// Set by the agent main to wire in the pre-dump trigger (M5).
	OnStopping func(ctx context.Context, event ContainerEvent) error
}

// New creates a Plugin. onStopping may be nil (stub mode).
func New(onStopping func(ctx context.Context, event ContainerEvent) error) *Plugin {
	return &Plugin{OnStopping: onStopping}
}

// HandleStopping is called by the NRI runtime bridge when containerd fires the
// Stopping lifecycle hook for a container.
// M4: logs the event. M5: triggers CRIU pre-dump via the checkpointer.
func (p *Plugin) HandleStopping(ctx context.Context, event ContainerEvent) error {
	log.Info("NRI Stopping hook called",
		"container", event.ID,
		"name", event.Name,
		"pod", event.Pod,
		"namespace", event.Namespace,
	)

	if p.OnStopping != nil {
		return p.OnStopping(ctx, event)
	}
	return nil
}

// RunStub reads NRI events from stdin in the simple NRI v2 socket protocol and
// dispatches to HandleStopping. This is the entry point when the binary is
// exec'd by containerd's NRI infrastructure.
//
// In M4 this reads JSON lines from stdin for testability; in M5 it will use
// the nri/pkg/api gRPC socket protocol.
func (p *Plugin) RunStub(ctx context.Context) error {
	log.Info("NRI plugin stub starting", "name", PluginName, "index", PluginIndex)

	dec := json.NewDecoder(os.Stdin)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		var env struct {
			Event string         `json:"event"`
			Data  ContainerEvent `json:"data"`
		}
		if err := dec.Decode(&env); err != nil {
			// EOF means containerd closed the connection — normal shutdown.
			return nil
		}

		if env.Event != "Stopping" {
			continue
		}

		hookCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := p.HandleStopping(hookCtx, env.Data)
		cancel()
		if err != nil {
			// Log but don't propagate — a failed pre-dump hook must not block container stop.
			log.Error(err, "NRI Stopping hook returned error", "container", env.Data.ID)
		}
	}
}

// WriteRegistrationConfig writes the NRI plugin config file to the NRI config dir.
// containerd reads this to discover and exec the plugin.
func WriteRegistrationConfig(configDir string) error {
	cfg := fmt.Sprintf(`# PodMotion NRI plugin — generated at agent startup
[plugin]
  name  = %q
  index = %q
  path  = "/usr/local/lib/nri/podmotion-nri-plugin"
`, PluginName, PluginIndex)

	path := configDir + "/podmotion.conf"
	return os.WriteFile(path, []byte(cfg), 0o644)
}
