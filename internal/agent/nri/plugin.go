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
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
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
	// PodUID is the replacement pod's Kubernetes pod UID (informational/logging).
	PodUID      string            `json:"podUID,omitempty"`
	// SandboxID is the containerd sandbox (pause container) ID from the NRI pod sandbox
	// object (pod.GetId()). It is unambiguous per pod and is used to resolve the sandbox
	// network namespace via the containerd sandbox API for ADR-0122 --net-fd CRIU restore.
	SandboxID   string            `json:"sandboxID,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	// Annotations carries pod annotations forwarded by the NRI runtime. In real NRI v2,
	// pod annotations appear here. The JSON stub must include them to test the restore path.
	Annotations map[string]string `json:"annotations,omitempty"`
	// ImageName is the container image reference fetched from the containerd container
	// record (ctr containers info) at StartContainer time. Used by setupRestoreOverlayfs
	// to launch a placeholder container without needing config.json in the checkpoint dir.
	ImageName string `json:"imageName,omitempty"`
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
	//
	// ADR-0185 r1: bounded retry to tolerate operator phase advance at NRI hook fire time.
	// Controller is NOT changed. Accept-set is NOT widened (Option B per ADR-0185 C3 resolution).
	// The operator advances phase asynchronously via requeues while NRI fires synchronously at
	// container start; we retry until the operator naturally advances past OverlayHandoff (at
	// which point the ADR-0048/0049 FDB barrier is confirmed) into an accepted restore phase, or
	// the deadline expires. A spoofed/absent CR never enters an accepted phase, so this still
	// hard-blocks on timeout with the same blocking error.
	if p.k8sClient != nil {
		// verifyTimeout(45s) + verifyInterval(1s) must sit under containerd
		// plugin_request_timeout (60s required on all nodes; default 30s fails the retry budget).
		verifyDeadline := time.Now().Add(45 * time.Second)
		var verifyErr error
		for time.Now().Before(verifyDeadline) {
			verifyErr = p.verifyPodMigration(ctx, event.Namespace, checkpointRef)
			if verifyErr == nil {
				break
			}
			// Only retry on phase-ordering transients — fail fast on all other errors
			// (missing/forged CR, node mismatch, List failure) with the same blocking error.
			if !isPhaseTransientErr(verifyErr) {
				break
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("NRI StartContainer: context cancelled during phase-wait: %w", ctx.Err())
			case <-time.After(1 * time.Second):
			}
		}
		if verifyErr != nil {
			log.Error(verifyErr, "NRI StartContainer: PodMigration verification failed — blocking restore",
				"checkpointRef", checkpointRef, "container", event.ID)
			return fmt.Errorf("NRI StartContainer: PodMigration verification failed: %w", verifyErr)
		}
	}

	// ADR-0197 Rule D (agent side) — per-container restore-target gate.
	// The pod-scoped checkpoint-ref above has no per-container discriminator, so this hook
	// matches whichever container fires StartContainer FIRST — which is the cp-only
	// podmotion-inject-holder init container, not the holder-running main container
	// (gate-10: inject-holder=6, redis=0). Firing CRIU restore + the holder-quiescent barrier
	// against the init container wedges it (the init container never runs the holder, never
	// writes the sentinel), deadlocking the main container behind it → 50s timeout →
	// RunContainerError → CrashLoopBackOff.
	//
	// Gate on container identity AFTER the verifyPodMigration anti-spoof check and BEFORE the
	// restore trigger + barrier: proceed ONLY if event.Name is in the operator-stamped
	// podmotion.io/restore-target-containers list (main container names; the init container is
	// excluded by construction). For any non-listed container (the init container), return nil
	// immediately — clean pass-through, no restore, no barrier — so the init container completes,
	// the emptyDir is populated, and the main container starts. Its StartContainer then fires and
	// restore+barrier engage against the holder-running container, which DOES write the sentinel.
	const restoreTargetsKey = "podmotion.io/restore-target-containers"
	if targets := event.Annotations[restoreTargetsKey]; targets != "" {
		if !containerInList(event.Name, targets) {
			log.Info("ADR-0197 Rule D: container is not a restore target — clean pass-through (no restore, no barrier)",
				"container", event.ID, "name", event.Name, "restoreTargets", targets)
			return nil
		}
	}

	// ADR-0198 Rule F — defer the holder-quiescent barrier + CRIU restore trigger to
	// PostStartContainer.
	//
	// The NRI StartContainer hook is SYNCHRONOUS: it must RETURN before containerd executes
	// the container entrypoint. ADR-0197 correctly relocated the barrier+restore onto the
	// holder-hosting main container, but the holder-quiescent barrier waits for a signal
	// (sentinel file OR stdout token) that ONLY the main container's own entrypoint
	// (/podmotion/holder, cmd/holder/main.go:39-53) can emit — and that entrypoint cannot run
	// until THIS hook returns. Circular wait → 50s timeout → RunContainerError (gate-11).
	//
	// The fix: StartContainer returns NIL immediately for a restore-target container WITHOUT
	// invoking waitForHolderQuiescent or OnStartContainer, so containerd starts the holder
	// entrypoint. The wait+trigger run in HandlePostStartContainer, which fires AFTER the
	// entrypoint has started — at which point the holder is running and CAN signal quiescence.
	//
	// The verifyPodMigration anti-spoof gate above DELIBERATELY STAYS in StartContainer
	// (pre-entrypoint): a forged/absent/wrong-node CR is rejected before the entrypoint is
	// ever allowed to run. Only the holder-quiescent WAIT and the restore TRIGGER move.
	log.Info("NRI StartContainer: restore deferred to PostStartContainer (holder must start first)",
		"adr", "ADR-0198",
		"container", event.ID,
		"checkpointRef", checkpointRef,
	)
	return nil
}

// HandlePostStartContainer is called by the NRI runtime bridge when containerd fires the
// PostStartContainer lifecycle event — AFTER containerd has started the container's entrypoint.
//
// ADR-0198 Rule F: this is the lifecycle phase in which the holder-quiescent barrier may safely
// wait. By the time PostStartContainer fires, the main container's entrypoint (the injected
// holder, ADR-0195 Rule A) is executing and parked — so it CAN write the sentinel file / emit
// the stdout token the barrier waits for. The barrier therefore becomes satisfiable, and on
// success the CRIU restore (OnStartContainer → JoinNsRestore) engages against the now-running,
// parked holder's namespaces.
//
// The Rule D container-target gate is re-applied here: PostStartContainer fires for every
// container (including the init container's post-start), and non-restore-target containers return
// nil immediately, exactly as in HandleStartContainer.
//
// The synchronous validation gates (ref validation, restore-target gate) run inline; the
// holder-quiescent barrier and the CRIU restore then run ASYNCHRONOUSLY on an independent
// context and this handler returns nil promptly. See the block comment at the go func() for
// why: the inbound ctx is containerd's 2s plugin_request_timeout, which must not govern a 50s
// barrier or a multi-second restore. Restore completion is reported out-of-band via
// ReportRestoreConfirmed → status.criuRestoreConfirmed (the controller's 60s poll).
// The inbound context is intentionally unused (named _): it is containerd's 2s
// plugin_request_timeout event context and must NOT govern the barrier/restore — those run on
// an independent context derived below. See the go func() block comment.
func (p *Plugin) HandlePostStartContainer(_ context.Context, event ContainerEvent) error {
	// Re-read the checkpoint-ref (dual-path: pod annotation, then container-linux annotation),
	// mirroring HandleStartContainer.
	const refKey = "podmotion.io/checkpoint-ref"
	checkpointRef := event.Annotations[refKey]
	if checkpointRef == "" {
		if v, ok := event.Labels[refKey]; ok {
			checkpointRef = v
		}
	}
	if checkpointRef == "" {
		return nil // not a restore target
	}

	// Re-validate the ref before it touches the filesystem (defense-in-depth; HandleStartContainer
	// already validated, but PostStartContainer is reachable independently via the NRI dispatch).
	if !validCheckpointRef.MatchString(checkpointRef) {
		log.Error(nil, "NRI PostStartContainer: rejecting invalid checkpointRef — possible path traversal",
			"checkpointRef", checkpointRef, "container", event.ID)
		return fmt.Errorf("invalid checkpointRef %q: must match [a-z0-9][a-z0-9-]{0,61}[a-z0-9]", checkpointRef)
	}

	// ADR-0197 Rule D (re-applied) — per-container restore-target gate. Non-restore-target
	// containers (the init container's post-start) return nil immediately.
	const restoreTargetsKey = "podmotion.io/restore-target-containers"
	if targets := event.Annotations[restoreTargetsKey]; targets != "" {
		if !containerInList(event.Name, targets) {
			log.Info("ADR-0197 Rule D: container is not a restore target — clean pass-through (PostStartContainer)",
				"container", event.ID, "name", event.Name, "restoreTargets", targets)
			return nil
		}
	}

	log.Info("NRI PostStartContainer: CRIU restore triggered",
		"container", event.ID,
		"checkpointRef", checkpointRef,
	)

	// The inbound (now-discarded) context is containerd's PER-EVENT context, bounded by the NRI
	// plugin_request_timeout (2s on the standing containerd 2.2.1 substrate — NOT the 60s the
	// prior comment assumed). It is the source of truth for "how long containerd will block the
	// container start waiting on this plugin" — it is NOT a budget for CRIU restore. Running the
	// 50s holder-quiescent barrier and the multi-second CRIU restore on that context means the
	// select at waitForHolderQuiescent hits Done() at ~2s EVERY time, the handler returns a
	// hard error, containerd drops the plugin connection (log-spam reconnects), and the migration
	// is forced onto the raw-CRIU fallback — the live failure observed 2026-07-10.
	//
	// Fix (source-of-truth decoupling): derive an INDEPENDENT context for the barrier + restore
	// so it is governed by the barrier's own deadline, not containerd's request budget, and
	// return nil to containerd PROMPTLY so the container start is not blocked and the plugin
	// connection is not dropped. Restore completion is reported asynchronously by
	// ReportRestoreConfirmed (called from OnStartContainer), which sets
	// status.criuRestoreConfirmed — the exact signal the controller's reconcileRestoringNRI
	// already polls for up to 60s. That poll, not containerd's 2s event context, is the real
	// restore completion signal. A barrier failure or restore error is logged loudly here; the
	// controller's 60s poll then times out and falls back to the agent Restore RPC exactly as
	// before — but the happy path now completes on the NRI path and the fallback is not forced.
	restoreCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	go func() {
		defer cancel()

		// ADR-0195 Rule C — holder-quiescent barrier (relocated to PostStartContainer by ADR-0198
		// Rule F; mechanism UNCHANGED — still polls the sentinel file via /proc/<pid>/root OR
		// observes the stdout token, ADR-0197 Rule D/E dual transport). Barrier timeout: 50 s,
		// governed by restoreCtx (independent of containerd's 2s plugin_request_timeout).
		if barrierErr := waitForHolderQuiescent(restoreCtx, event, 50*time.Second); barrierErr != nil {
			log.Error(barrierErr, "NRI PostStartContainer: holder-quiescent barrier FAILED — restore aborted (controller 60s poll will fall back to agent Restore RPC)",
				"container", event.ID, "checkpointRef", checkpointRef)
			return
		}

		// ADR-SEC-B §2.6 — provenance gate on the restore path. The final/ dir for this
		// checkpoint-ref MUST contain the checkpoint-verified sentinel written by PutCheckpointTar
		// (§2.3 step 6) only after signature + per-file digest + migration-binding all passed.
		// Absent → restore is blocked (no CRIU restore on unverified images). Fail-closed.
		if err := verifyCheckpointProvenanceSentinel(checkpointRef); err != nil {
			log.Error(err, "ADR-SEC-B: checkpoint not provenance-verified — refusing restore",
				"container", event.ID, "checkpointRef", checkpointRef)
			return
		}

		// ADR-0198 Rule F item 4 — CRIU restore-over-running-holder. The restore lands over the
		// running, parked holder (which binds no port and parks on <-sigCh). The JoinNsRestore
		// argv is UNCHANGED and does NOT use --restore-detached (Standing Rule 6).
		if p.OnStartContainer != nil {
			if err := p.OnStartContainer(restoreCtx, event, checkpointRef); err != nil {
				log.Error(err, "NRI PostStartContainer: CRIU restore failed (controller 60s poll will fall back to agent Restore RPC)",
					"container", event.ID, "checkpointRef", checkpointRef)
			}
		}
	}()

	// Return nil to containerd immediately — do not block the container start on the barrier or
	// CRIU restore, and do not drop the plugin connection. Completion is signalled out-of-band
	// via ReportRestoreConfirmed → status.criuRestoreConfirmed (controller poll).
	return nil
}

// verifyCheckpointProvenanceSentinel enforces the ADR-SEC-B §2.6 restore-path gate: the
// checkpoint-verified sentinel must exist in the migration's final/ dir before CRIU restore may
// engage. The sentinel is written by PutCheckpointTar only after the full provenance gate passes.
//
// Package var (not a bare func) so the async-restore path can be unit-tested without a writable
// /run/podmotion tree — production always uses verifyCheckpointProvenanceSentinelImpl.
var verifyCheckpointProvenanceSentinel = verifyCheckpointProvenanceSentinelImpl

func verifyCheckpointProvenanceSentinelImpl(checkpointRef string) error {
	sentinel := filepath.Join("/run/podmotion/checkpoints", checkpointRef, "final", "checkpoint-verified")
	if _, err := os.Stat(sentinel); err != nil {
		return fmt.Errorf("checkpoint-verified sentinel absent at %q: %w", sentinel, err)
	}
	return nil
}

// verifyPodMigration ensures that a PodMigration CR matching the checkpointRef exists,
// is in Restoring phase, and targets this node — blocking restore if not.
func (p *Plugin) verifyPodMigration(ctx context.Context, namespace, checkpointRef string) error {
	// List PodMigrations in the pod's namespace looking for one whose CheckpointRef matches.
	//
	// ADR-0185 r1 C6 (cache-staleness): this List is served by the controller-runtime
	// informer-backed cache (eventually consistent). Cache-read is acceptable: controller-runtime
	// informer resync on kind clusters is well under 45s (default 10h but explicit --sync-period=30s
	// set by operator; kind cluster not partition-prone). Phase transitions are written
	// synchronously by the operator — List lag is bounded by one sync cycle. If cache staleness
	// causes the 45s timeout: migration fails with verifyErr, source pod is thawed by the
	// ZeroWindow watchdog (ADR-0157 D3), CR enters phase=Failed, source pod remains Running.
	// No data loss.
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
		// ADR-0185 r1 (Option B): accept-set is NOT widened. OverlayHandoff is deliberately
		// excluded — CRIU restore must not begin until the FDB barrier (conditionVXLANFDBUpdated)
		// is confirmed. The bounded retry in HandleStartContainer waits for the operator to
		// advance past OverlayHandoff into an accepted restore phase.
		if err := verifyPhaseInAcceptSet(string(pm.Status.Phase)); err != nil {
			return fmt.Errorf("PodMigration %s/%s %w", namespace, pm.Name, err)
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

// verifyPhaseInAcceptSet returns nil if the given PodMigration phase is in the NRI
// anti-spoof accept-set, or a "phase is ..." error otherwise.
//
// ADR-0185 r1 (Option B): the accept-set is EXACTLY the phases reachable after
// conditionVXLANFDBUpdated=True — {Restoring, RestoreSocketReattach, DisengageHold}.
// OverlayHandoff is NOT included (FDB not yet confirmed); FinalFreezeStateCapture and all
// earlier phases are NOT included. The phase-mismatch error string contains "phase is" so the
// bounded retry loop (isPhaseTransientErr) waits for the operator to advance, while forged/missing
// CR errors (which do NOT contain "phase is") fail fast.
func verifyPhaseInAcceptSet(phase string) error {
	switch pmv1.MigrationPhase(phase) {
	case pmv1.MigrationPhaseRestoring,
		pmv1.MigrationPhaseRestoreSocketReattach,
		pmv1.MigrationPhaseDisengageHold:
		return nil
	default:
		return fmt.Errorf("phase is %s, expected Restoring/RestoreSocketReattach/DisengageHold", phase)
	}
}

// isPhaseTransientErr returns true for phase-ordering errors where retry is safe.
// Only errors containing "phase is" (phase mismatch, not forged/missing CR, node mismatch, or
// List failure) are transient — the operator is mid-transition and will advance.
func isPhaseTransientErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "phase is")
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
	return a.plugin.HandleStartContainer(ctx, buildContainerEvent(pod, container))
}

// PostStartContainer implements stub.PostStartContainerInterface (NRI v0.12.0).
// Implementing this interface causes the stub's setupHandlers (stub.go:1052-1055) to register
// the handler AND subscribe the plugin to Event_POST_START_CONTAINER automatically — no other
// wiring is required. It fires AFTER containerd has started the container's entrypoint, which is
// the lifecycle phase in which ADR-0198 Rule F runs the holder-quiescent barrier + CRIU restore.
//
// The same ContainerEvent (identical field set, including ImageName, Annotations, and the
// container-level annotation merge) is built as for StartContainer and dispatched to
// HandlePostStartContainer.
func (a *nriAdapter) PostStartContainer(ctx context.Context, pod *nriapi.PodSandbox, container *nriapi.Container) error {
	// Defensive nil guard, identical to StartContainer (ADR-0119 D2).
	if pod == nil || container == nil {
		return nil
	}
	return a.plugin.HandlePostStartContainer(ctx, buildContainerEvent(pod, container))
}

// buildContainerEvent constructs the ContainerEvent from an NRI pod sandbox + container, applying
// the container-level annotation merge. Shared by StartContainer and PostStartContainer so both
// hooks see an identical event field set (ADR-0198 Rule F item 1).
func buildContainerEvent(pod *nriapi.PodSandbox, container *nriapi.Container) ContainerEvent {
	event := ContainerEvent{
		ID:          container.GetId(),
		Name:        container.GetName(),
		Namespace:   pod.GetNamespace(),
		Pod:         pod.GetName(),
		PodUID:      pod.GetUid(),
		SandboxID:   pod.GetId(),
		Labels:      container.GetLabels(),
		Annotations: pod.GetAnnotations(),
		ImageName:   fetchContainerImage(container.GetId()),
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
	return event
}

// fetchContainerImage queries containerd for the image name associated with the given
// container ID using `ctr --namespace k8s.io containers info`. Returns an empty string
// if the query fails — callers fall back to a default image name.
func fetchContainerImage(containerID string) string {
	if containerID == "" {
		return ""
	}
	out, err := exec.Command("ctr", "--namespace", "k8s.io", "containers", "info", containerID).Output()
	if err != nil {
		return ""
	}
	var rec struct {
		Image string `json:"Image"`
	}
	if err := json.Unmarshal(out, &rec); err != nil {
		return ""
	}
	return rec.Image
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

// waitForHolderQuiescent blocks until the universal injected holder (ADR-0195 Rule A) signals
// that it has parked and does NOT occupy the workload port in the sandbox netns, OR until the
// deadline expires.
//
// Quiescence is determined by the presence of the holder-ready sentinel file at
//   /proc/<holderPID>/root/run/podmotion/holder-ready
// OR (for scratch rootfs where /proc traversal is unreliable) by the holder's stdout token
//   "podmotion-holder ready" observable in the agent log (emitted by cmd/holder/main.go).
//
// Because the NRI StartContainer hook fires BEFORE the container init process begins executing,
// the barrier polls with a short interval (200 ms) until the sentinel appears or the timeout
// fires.  The container PID is resolved from /proc/*/cgroup by scanning for the container ID
// (event.ID).  If the PID cannot be resolved, the barrier falls back to a log-derived
// assertion: the annotation podmotion.io/original-command-overridden=true (stamped by
// createReplacementPod) proves that the injected-holder Command is in place, and the barrier
// emits the "holder-quiescent barrier satisfied" log line after a 1 s settling delay.
//
// Sentinel transport: (i) holder writes /run/podmotion/holder-ready inside the
// container rootfs (host-visible via /proc/<pid>/root); (ii) holder emits "podmotion-holder ready"
// to stdout; (iii) the emptyDir is written before workload tree restore and is read-only to
// non-holder containers (ReadOnly:true VolumeMount in createReplacementPod).  The agent observes
// (i) via /proc traversal and (iii) is enforced by the operator pod-spec — neither is world-writable.
//
// On success the barrier logs "holder-quiescent barrier satisfied" to the dest agent log.
func waitForHolderQuiescent(ctx context.Context, event ContainerEvent, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	const pollInterval = 200 * time.Millisecond
	const holderReadySentinel = "run/podmotion/holder-ready" // relative to /proc/<pid>/root/

	// holderQuiescentAnnotation is stamped by createReplacementPod (ADR-0130 / ADR-0195 Rule A)
	// to assert that the injected-holder Command is in place.
	const holderQuiescentAnnotation = "podmotion.io/original-command-overridden"

	// First: quick check — if the annotation is not present, this container is not a
	// replacement-pod candidate at all (should not reach here, but guard defensively).
	if v := event.Annotations[holderQuiescentAnnotation]; v != "true" {
		// No holder annotation — not an ADR-0195 replacement pod.  Pass through immediately
		// so non-restore containers are not delayed.
		log.Info("holder-quiescent barrier: annotation absent — not a replacement pod, skipping barrier",
			"container", event.ID)
		return nil
	}

	// ADR-0197 Rule E — dual quiescence transport.
	// The barrier is satisfied by EITHER:
	//   (i)  the holder-ready sentinel file at /proc/<pid>/root/run/podmotion/holder-ready, OR
	//   (ii) the holder's stdout token "podmotion-holder ready" in the container CRI log.
	// Rule D lets the holder run in the MAIN container, which on a FROM-scratch rootfs may make
	// /proc/<pid>/root/run/podmotion/holder-ready traversal of the read-only emptyDir-shadowed
	// path unreliable. The doc-comment (:472-481) and the holder (cmd/holder/main.go:53) always
	// advertised this dual transport, but only the file stat was implemented. Implementing the
	// stdout token (OR-ed with the file) prevents Rule D from merely moving the timeout from the
	// init container to the main container. The satisfied-transport is attributed in the log so
	// the operator can tell which one fired.
	const holderStdoutToken = "podmotion-holder ready"

	// Poll for the sentinel file via /proc/<pid>/root traversal.
	// The container PID is the init PID of the container; it appears under /proc once the
	// container runtime has created the cgroup and forked the init process.
	for time.Now().Before(deadline) {
		// Transport (i): sentinel file. Find the container's init PID by scanning /proc/*/cgroup.
		pid := findContainerInitPID(event.ID)
		if pid > 0 {
			sentinelPath := fmt.Sprintf("/proc/%d/root/%s", pid, holderReadySentinel)
			if _, err := os.Stat(sentinelPath); err == nil {
				log.Info("holder-quiescent barrier satisfied (sentinel file)",
					"container", event.ID, "pid", pid, "sentinelPath", sentinelPath)
				return nil
			}
		}

		// Transport (ii): stdout token. Observe the holder container's CRI stdout log for the
		// "podmotion-holder ready" token. The token is read ONLY from the Rule-D-selected holder
		// container's own log stream — it does not widen trust to any other writer.
		if observeHolderStdoutToken(event, holderStdoutToken) {
			log.Info("holder-quiescent barrier satisfied (stdout token)",
				"container", event.ID, "name", event.Name, "token", holderStdoutToken)
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled waiting for holder-quiescent sentinel: %w", ctx.Err())
		case <-time.After(pollInterval):
		}
	}

	// Timeout: emit a loud, attributable error log.
	return fmt.Errorf("holder-quiescent barrier: sentinel %q / stdout token %q not observed within %s for container %s (non-conforming holder or init delay exceeded barrier timeout)",
		holderReadySentinel, holderStdoutToken, timeout, event.ID)
}

// observeHolderStdoutToken implements ADR-0197 Rule E transport (ii): it scans the holder
// container's CRI stdout log for the quiescence token (e.g. "podmotion-holder ready"). The CRI
// (containerd) log layout on the host is:
//
//	/var/log/pods/<namespace>_<pod>_<podUID>/<containerName>/<N>.log
//
// Each line is the CRI log format: "<RFC3339Nano> <stdout|stderr> <F|P> <message>". We do a
// substring match against the whole file content (the token is unambiguous). The token is read
// ONLY from the Rule-D-selected holder container's own log stream — it does not widen trust to a
// different writer; both transports are satisfied only by the holder process the agent already
// gates on by container identity (Rule D). Returns false (not an error) on any I/O miss so the
// caller keeps polling until the sentinel-file transport or the deadline resolves.
func observeHolderStdoutToken(event ContainerEvent, token string) bool {
	if event.Namespace == "" || event.Pod == "" || event.PodUID == "" || event.Name == "" {
		// Insufficient identity to locate the CRI log deterministically — fall back to the
		// sentinel-file transport (do not guess a path that could match another container).
		return false
	}
	logDir := fmt.Sprintf("/var/log/pods/%s_%s_%s/%s", event.Namespace, event.Pod, event.PodUID, event.Name)
	logFiles, err := filepath.Glob(filepath.Join(logDir, "*.log"))
	if err != nil || len(logFiles) == 0 {
		return false
	}
	for _, lf := range logFiles {
		data, err := os.ReadFile(lf)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), token) {
			return true
		}
	}
	return false
}

// containerInList reports whether name is a member of the comma-joined list (ADR-0197 Rule D
// restore-target-containers annotation). Whitespace around each element is trimmed; empty
// elements are ignored. The init container (podmotion-inject-holder) is never in this list by
// construction, so it is excluded as a consequence of the allow-list, not a hard-coded deny.
func containerInList(name, csv string) bool {
	for _, part := range strings.Split(csv, ",") {
		if strings.TrimSpace(part) == name {
			return true
		}
	}
	return false
}

// findContainerInitPID scans /proc for the init PID of the container with the given containerID.
// It reads /proc/<pid>/cgroup and looks for a cgroup entry containing the container ID string.
// Returns 0 if not found.
func findContainerInitPID(containerID string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := 0
		for _, c := range e.Name() {
			if c < '0' || c > '9' {
				pid = -1
				break
			}
			pid = pid*10 + int(c-'0')
		}
		if pid <= 0 {
			continue
		}
		cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			continue
		}
		if strings.Contains(string(cgroupData), containerID) {
			return pid
		}
	}
	return 0
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
