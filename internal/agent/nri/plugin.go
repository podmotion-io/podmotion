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
	"fmt"
	"os"
	"regexp"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// validCheckpointRef rejects any ref that is not a plain DNS-label-safe identifier.
// A ref like "../../etc" will never match. This is defense-in-depth — the k8s API
// server already constrains object names, but we validate here since the ref crosses
// the annotation→filesystem boundary.
var validCheckpointRef = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$`)

var log = logf.Log.WithName("nri-plugin")

// PluginName is the NRI plugin identifier registered with containerd.
const PluginName = "podmotion"

// PluginIndex controls the invocation order among NRI plugins (lower = earlier).
// 10 puts us ahead of most plugins but after security enforcement plugins.
const PluginIndex = "10"

// ContainerEvent mirrors the subset of the NRI ContainerAdjustment event we care about.
type ContainerEvent struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Pod         string            `json:"pod"`
	Labels      map[string]string `json:"labels,omitempty"`
	// Annotations carries pod annotations forwarded by the NRI runtime. In real NRI v2,
	// pod annotations appear here. The JSON stub must include them to test the restore path.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Plugin is the NRI lifecycle hook handler.
type Plugin struct {
	// OnStopping is called for each Stopping event.
	// Set by the agent main to wire in the pre-dump trigger (M5).
	OnStopping func(ctx context.Context, event ContainerEvent) error

	// OnStartContainer is called when containerd fires the StartContainer lifecycle
	// hook — after runc has created the container namespaces (PID, net, mnt) but
	// before the container's init process begins executing. This is the correct moment
	// for CRIU restore: namespaces exist, init PID is known, container is paused.
	// The checkpointRef string is the value of the podmotion.io/checkpoint-ref annotation.
	OnStartContainer func(ctx context.Context, event ContainerEvent, checkpointRef string) error

	// k8sClient is used to verify PodMigration CRs before triggering CRIU restore,
	// preventing annotation spoofing attacks. May be nil in unit-test stub mode.
	k8sClient client.Client

	// nodeName is the name of this node, used to validate the migration targets here.
	nodeName string
}

// New creates a Plugin. onStopping and onStartContainer may be nil (stub mode).
// k8sClient and nodeName are used for PodMigration CR verification; pass nil/empty for tests.
func New(
	onStopping func(ctx context.Context, event ContainerEvent) error,
	onStartContainer func(ctx context.Context, event ContainerEvent, checkpointRef string) error,
) *Plugin {
	return &Plugin{
		OnStopping:       onStopping,
		OnStartContainer: onStartContainer,
	}
}

// WithK8sVerification sets the k8s client and node name for PodMigration CR verification.
// Call this after New() when running in a real cluster to prevent annotation spoofing.
func (p *Plugin) WithK8sVerification(c client.Client, nodeName string) *Plugin {
	p.k8sClient = c
	p.nodeName = nodeName
	return p
}

// HandleStartContainer is called by the NRI runtime bridge when containerd fires the
// StartContainer lifecycle hook — after runc builds namespaces, before the container
// command executes. If the container carries podmotion.io/checkpoint-ref, the
// OnStartContainer callback is invoked to trigger CRIU restore into the live namespaces.
func (p *Plugin) HandleStartContainer(ctx context.Context, event ContainerEvent) error {
	// ADR-0119 D2/D3: comma-ok map reads below are nil-safe in Go, so the unconditional
	// log and annotation lookup cannot panic even when Annotations/Labels are nil.

	// ADR-0119 D3: dual-path annotation read. Prefer the pod annotation (the Kubernetes
	// pod spec annotation forwarded by the NRI runtime), then fall back to the
	// container-level/Linux annotations (carried on event.Labels for broad compat with
	// runtimes that surface them there).
	const refKey = "podmotion.io/checkpoint-ref"
	checkpointRef, matchPath := event.Annotations[refKey], "pod-annotation"
	if checkpointRef == "" {
		if v, ok := event.Labels[refKey]; ok {
			checkpointRef, matchPath = v, "container-linux-annotation"
		}
	}
	if checkpointRef == "" {
		matchPath = "none"
	}

	// ADR-0119 D3: unconditional per-pod log for EVERY start event — matching or not —
	// so a "hook never fired" failure is directly observable in the agent journal.
	log.Info("NRI HandleStartContainer called",
		"container", event.ID,
		"name", event.Name,
		"pod", event.Pod,
		"namespace", event.Namespace,
		"checkpointRefPresent", checkpointRef != "",
		"matchPath", matchPath,
	)

	if checkpointRef == "" {
		return nil // not a restore target
	}

	// ADR-0119 D4: record the matched annotation value before invoking the restore path.
	log.Info("NRI HandleStartContainer: checkpoint-ref found — invoking JoinNsRestore",
		"pod", event.Pod,
		"namespace", event.Namespace,
		"checkpointRef", checkpointRef,
		"matchPath", matchPath,
	)

	// Validate before the ref touches the filesystem — reject anything that isn't a
	// plain identifier (no slashes, dots, or path traversal sequences).
	if !validCheckpointRef.MatchString(checkpointRef) {
		log.Error(nil, "NRI StartContainer: rejecting invalid checkpointRef — possible path traversal",
			"checkpointRef", checkpointRef, "container", event.ID)
		return fmt.Errorf("invalid checkpointRef %q: must match [a-z0-9][a-z0-9-]{0,61}[a-z0-9]", checkpointRef)
	}

	// Verify that a PodMigration CR with this checkpointRef actually exists and
	// is in Restoring phase targeting this node. Prevents annotation spoofing.
	if p.k8sClient != nil {
		if err := p.verifyPodMigration(ctx, event.Namespace, checkpointRef); err != nil {
			log.Error(err, "NRI StartContainer: PodMigration verification failed — blocking restore",
				"checkpointRef", checkpointRef, "container", event.ID)
			return fmt.Errorf("PodMigration verification failed: %w", err)
		}
	}

	log.Info("NRI StartContainer: CRIU restore triggered",
		"container", event.ID,
		"checkpointRef", checkpointRef,
	)

	if p.OnStartContainer != nil {
		return p.OnStartContainer(ctx, event, checkpointRef)
	}
	return nil
}

// verifyPodMigration ensures that a PodMigration CR matching the checkpointRef exists,
// is in Restoring phase, and targets this node — blocking restore if not.
func (p *Plugin) verifyPodMigration(ctx context.Context, namespace, checkpointRef string) error {
	// List PodMigrations in the pod's namespace looking for one whose CheckpointRef matches.
	pmList := &pmv1.PodMigrationList{}
	if err := p.k8sClient.List(ctx, pmList, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("list PodMigrations: %w", err)
	}
	for _, pm := range pmList.Items {
		// The annotation value is pm.Name (DNS-label safe identifier). Match on that
		// rather than the full filesystem path stored in pm.Status.CheckpointRef.Name.
		if pm.Name != checkpointRef {
			continue
		}
		if pm.Status.Phase != pmv1.MigrationPhaseRestoring {
			return fmt.Errorf("PodMigration %s/%s phase is %s, expected Restoring",
				namespace, pm.Name, pm.Status.Phase)
		}
		// Prefer status.DestinationNodeName (set by controller after scheduling);
		// fall back to spec.TargetNodeName for early-phase races.
		destNode := pm.Status.DestinationNodeName
		if destNode == "" {
			destNode = pm.Spec.TargetNodeName
		}
		if p.nodeName != "" && destNode != p.nodeName {
			return fmt.Errorf("PodMigration %s/%s destinationNode %s != this node %s",
				namespace, pm.Name, destNode, p.nodeName)
		}
		return nil // found and verified
	}
	// No matching PodMigration found — treat as spoofed annotation.
	return fmt.Errorf("no PodMigration in %s with checkpointRef %q in Restoring phase", namespace, checkpointRef)
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

// nriAdapter wraps Plugin to implement the containerd NRI stub interfaces.
// containerd calls StartContainer and StopContainer on this type via the NRI gRPC socket.
type nriAdapter struct {
	plugin *Plugin
}

// StartContainer implements stub.StartContainerInterface.
// Called after runc creates container namespaces but before the container init executes.
// If the pod carries podmotion.io/checkpoint-ref, CRIU restore is triggered.
//
// Timeout: containerd's plugin_request_timeout governs this context (default 30s).
// M18.5 spike measured actual CRIU restore at ~200–400ms (health-check on ESTAB socket).
// 30s >> 400ms — safe margin. If restore ever exceeds ~10s, containerd config must be
// updated: [plugins."io.containerd.nri.v1.nri"] plugin_request_timeout = "60s".
func (a *nriAdapter) StartContainer(ctx context.Context, pod *nriapi.PodSandbox, container *nriapi.Container) error {
	// ADR-0119 D2: defensive nil guard. The NRI bridge can deliver a start event with a
	// nil or incomplete sandbox/container (the source of the plugin.go panic). Treat it as
	// a clean no-op rather than dereferencing nil.
	if pod == nil || container == nil {
		return nil
	}
	event := ContainerEvent{
		ID:          container.GetId(),
		Name:        container.GetName(),
		Namespace:   pod.GetNamespace(),
		Pod:         pod.GetName(),
		Labels:      container.GetLabels(),
		Annotations: pod.GetAnnotations(),
	}
	// Also merge container-level annotations (containerd may forward them on either).
	if cAnnotations := container.GetAnnotations(); len(cAnnotations) > 0 {
		if event.Annotations == nil {
			event.Annotations = make(map[string]string)
		}
		for k, v := range cAnnotations {
			if _, exists := event.Annotations[k]; !exists {
				event.Annotations[k] = v
			}
		}
	}
	return a.plugin.HandleStartContainer(ctx, event)
}

// StopContainer implements stub.StopContainerInterface.
// Called when a container is stopping; used for pre-dump trigger (M5).
func (a *nriAdapter) StopContainer(ctx context.Context, pod *nriapi.PodSandbox, container *nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
	event := ContainerEvent{
		ID:          container.GetId(),
		Name:        container.GetName(),
		Namespace:   pod.GetNamespace(),
		Pod:         pod.GetName(),
		Labels:      container.GetLabels(),
		Annotations: pod.GetAnnotations(),
	}
	err := a.plugin.HandleStopping(ctx, event)
	return nil, err
}

// nriSocketPath is the containerd NRI socket location.
const nriSocketPath = "/var/run/nri/nri.sock"

// Run connects to containerd's NRI socket via the real NRI v2 gRPC protocol and
// dispatches lifecycle events to Plugin handlers. The agent calls this in a goroutine.
//
// NRI is an enhancement — if the socket is absent (containerd not configured for NRI),
// Run waits and retries with backoff rather than failing. This keeps the core agent
// gRPC server alive on clusters that don't have NRI enabled yet.
func (p *Plugin) Run(ctx context.Context) error {
	backoff := 5 * time.Second
	const maxBackoff = 2 * time.Minute

	for {
		// Check socket before attempting connection to distinguish "not yet configured"
		// (expected, warn-only) from a real handshake failure (unexpected, log error).
		if _, err := os.Stat(nriSocketPath); os.IsNotExist(err) {
			log.Info("NRI socket not found — containerd NRI not enabled; will retry",
				"socket", nriSocketPath, "retryIn", backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
				if backoff < maxBackoff {
					backoff *= 2
				}
				continue
			}
		}

		log.Info("NRI plugin connecting", "name", PluginName, "index", PluginIndex)
		adapter := &nriAdapter{plugin: p}
		s, err := stub.New(adapter,
			stub.WithPluginName(PluginName),
			stub.WithPluginIdx(PluginIndex),
		)
		if err != nil {
			log.Error(err, "NRI stub.New failed — retrying", "retryIn", backoff)
		} else if err = s.Start(ctx); err != nil {
			log.Error(err, "NRI stub.Start failed — retrying", "retryIn", backoff)
		} else {
			// Connected — block until the stub disconnects or ctx is cancelled.
			log.Info("NRI plugin connected", "name", PluginName)
			s.Wait()
			log.Info("NRI plugin disconnected — reconnecting", "name", PluginName)
			backoff = 5 * time.Second // reset on clean disconnect
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
			if backoff < maxBackoff {
				backoff *= 2
			}
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
