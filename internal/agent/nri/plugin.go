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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
	"github.com/podmotion-io/podmotion/internal/metrics"
)

// ValidCheckpointRef rejects any ref that is not a plain DNS-label-safe identifier.
// A ref like "../../etc" will never match. This is defense-in-depth — the k8s API
// server already constrains object names, but we validate here since the ref crosses
// the annotation→filesystem boundary.
var ValidCheckpointRef = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$`)

var log = logf.Log.WithName("nri-plugin")

// nriPluginRequestTimeout is the real containerd NRI plugin_request_timeout, GROUNDED live
// (ADR-0351 G0.3 — `containerd config
// dump` on pm-w1, 2026-07-15) — not assumed. This ONE value pins the three previously
// contradictory in-tree comments this constant replaces ("60s required on all nodes"; "2s on
// the standing containerd 2.2.1 substrate"; "default 30s"). D4.1.
const nriPluginRequestTimeout = 2 * time.Second

// antiSpoofVerifyBudget bounds HandleStartContainer's synchronous PodMigration-CR anti-spoof
// verify loop (ADR-0351 D4.2). HandleStartContainer runs UNDER containerd's synchronous
// nriPluginRequestTimeout — a loop that can still be mid-retry when that budget expires means
// containerd drops the plugin connection entirely, forcing EVERY migration onto the raw-CRIU
// fallback (where the D1 cgroup-anchor primitive never executes at all, not just late). Bounded
// to well under nriPluginRequestTimeout (not merely under it) so the handler can return and
// containerd can still process the plugin's response before its own deadline fires. Do NOT
// widen nriPluginRequestTimeout to make room for a longer loop instead (D5.2/scope [9] — a
// longer timeout fixes nothing about the underlying phase-ordering race this loop tolerates).
const antiSpoofVerifyBudget = 800 * time.Millisecond

// antiSpoofVerifyPollInterval is the re-probe cadence inside antiSpoofVerifyBudget. Short
// enough that at least one retry fits inside the budget above (unlike the retired 1s interval,
// which left room for zero retries inside a 2s containerd deadline).
const antiSpoofVerifyPollInterval = 100 * time.Millisecond

// PluginName is the NRI plugin identifier registered with containerd.
const PluginName = "podmotion"

// PluginIndex controls the invocation order among NRI plugins (lower = earlier).
// 10 puts us ahead of most plugins but after security enforcement plugins.
const PluginIndex = "10"

// ContainerEvent mirrors the subset of the NRI ContainerAdjustment event we care about.
type ContainerEvent struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	// PodUID is the replacement pod's Kubernetes pod UID (informational/logging).
	PodUID string `json:"podUID,omitempty"`
	// SandboxID is the containerd sandbox (pause container) ID from the NRI pod sandbox
	// object (pod.GetId()). It is unambiguous per pod and is used to resolve the sandbox
	// network namespace via the containerd sandbox API for ADR-0122 --net-fd CRIU restore.
	SandboxID string            `json:"sandboxID,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	// Annotations carries pod annotations forwarded by the NRI runtime. In real NRI v2,
	// pod annotations appear here. The JSON stub must include them to test the restore path.
	Annotations map[string]string `json:"annotations,omitempty"`
	// ImageName is the container image reference fetched from the containerd container
	// record (ctr containers info) at StartContainer time. Used by setupRestoreOverlayfs
	// to launch a placeholder container without needing config.json in the checkpoint dir.
	ImageName string `json:"imageName,omitempty"`
	// ContainerCgroupsPath is the migrated container's OWN cgroup path, read directly from
	// container.GetLinux().GetCgroupsPath() (NRI LinuxContainer.CgroupsPath, proto bytes,5).
	// ADR-0351 D1: this is the authoritative restore-path cgroup-anchor target — zero query,
	// zero poll, zero retry. Live-verified populated (G0, BD-0): a systemd cgroup-driver slice
	// token of the form "<slice>.slice:cri-containerd:<containerID>" on this substrate.
	ContainerCgroupsPath string `json:"containerCgroupsPath,omitempty"`
	// PodCgroupParent is the pod's parent slice, read from pod.GetLinux().GetCgroupParent()
	// (NRI LinuxPodSandbox.CgroupParent, proto bytes,3). ADR-0351 D2.3/D2.4: used ONLY as a
	// validation bound (reject an anchor target that equals or escapes it) — NEVER a write
	// target (writing a PID into a non-leaf cgroup with children EBUSYs, cgroup v2).
	PodCgroupParent string `json:"podCgroupParent,omitempty"`
}

// ADR-0412 D2 — sentinel errors for the terminal-phase restore-gate classification. They are
// package-level so both hooks and the unit tests can classify an outcome with errors.Is rather
// than by string-matching a message. None of them contain the substring "phase is", so
// isPhaseTransientErr treats them all as PERMANENT (non-transient): the inner retry loop breaks
// immediately and the outcome is decided in one pass.
var (
	// errRestoreNotApplicableTerminalOwn signals that the pod's OWN migration already reached
	// Complete: the restore already landed during the migration, so a post-completion kubelet
	// restart must cold-start the container WITHOUT re-restoring stale checkpoint memory. This is
	// NOT a rejection — the container starts normally; it only means "no restore here". Distinct
	// from every fail-closed error below.
	errRestoreNotApplicableTerminalOwn = errors.New(
		"restore not applicable: pod's own migration already Complete — start normally")

	// errTerminalNotOwn is a fail-closed rejection: the checkpoint-ref points at a terminal or
	// aborting migration (Complete-but-not-own / Failed / RollingBack / DryRunComplete) that this
	// pod cannot prove ownership of. Cold-starting it risks a second live instance alongside the
	// ADR-0157-thawed source (split-brain), so it is permanently rejected. Wrapped for errors.Is.
	errTerminalNotOwn = errors.New(
		"PodMigration is in a terminal/aborting phase and is not restorable by this pod")

	// errNodeMismatch is a fail-closed rejection: the ref's destination node is not this node.
	// Checked before phase classification so a wrong-node ref fails fast rather than spinning as a
	// transient "phase is ...". Wrapped for errors.Is.
	errNodeMismatch = errors.New("PodMigration destination node is not this node")
)

// restoreDecision is the outcome HandleStartContainer computed for a restore-target container.
// It is threaded to HandlePostStartContainer (ADR-0412 condition #1) so PostStartContainer acts
// on the SAME decision instead of re-deriving it from a second, independent CR read — which a
// phase transition occurring between the two synchronous hook calls could make disagree.
type restoreDecision int

const (
	// restoreDecisionProceed: the anti-spoof + phase gate authorized restore (phase in the
	// {Restoring, RestoreSocketReattach, DisengageHold} accept-set). HandlePostStartContainer runs
	// the holder-quiescent barrier + CRIU restore.
	restoreDecisionProceed restoreDecision = iota
	// restoreDecisionTerminalOwnColdStart: the pod's OWN migration already reached Complete
	// (ADR-0412 D2). HandlePostStartContainer must NOT run the barrier or CRIU restore — the
	// container cold-starts normally.
	restoreDecisionTerminalOwnColdStart
)

// startDecisionTTL bounds how long a recorded StartContainer decision is retained if its paired
// PostStartContainer never fires (e.g. the container failed to start after StartContainer
// returned nil). PostStartContainer normally fires within milliseconds-to-seconds of
// StartContainer, so this is generous; expired entries are swept on the next record.
const startDecisionTTL = 2 * time.Minute

// startDecisionEntry is a recorded decision plus the time it was recorded (for TTL sweeping).
type startDecisionEntry struct {
	decision restoreDecision
	at       time.Time
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

	// startDecisions threads the restore decision HandleStartContainer computed for a
	// restore-target container to HandlePostStartContainer (ADR-0412 condition #1), keyed by
	// container ID (event.ID). Only populated when k8sClient != nil (the verify path runs).
	startDecisionsMu sync.Mutex
	startDecisions   map[string]startDecisionEntry
}

// recordStartDecision stores the decision HandleStartContainer computed for container id, so the
// paired HandlePostStartContainer consumes the SAME outcome (ADR-0412 condition #1). Expired
// entries (see startDecisionTTL) are swept on each record so a container whose PostStart never
// fires cannot leak the map unbounded.
func (p *Plugin) recordStartDecision(id string, d restoreDecision) {
	p.startDecisionsMu.Lock()
	defer p.startDecisionsMu.Unlock()
	if p.startDecisions == nil {
		p.startDecisions = make(map[string]startDecisionEntry)
	}
	now := time.Now()
	for k, e := range p.startDecisions {
		if now.Sub(e.at) > startDecisionTTL {
			delete(p.startDecisions, k)
		}
	}
	p.startDecisions[id] = startDecisionEntry{decision: d, at: now}
}

// takeStartDecision returns and REMOVES the decision recorded for container id. found is false if
// no (unexpired) decision was recorded — e.g. stub mode (k8sClient == nil, nothing recorded) or
// the agent restarted between the two hooks. Callers must fail closed on a missing decision, not
// assume proceed.
func (p *Plugin) takeStartDecision(id string) (restoreDecision, bool) {
	p.startDecisionsMu.Lock()
	defer p.startDecisionsMu.Unlock()
	e, ok := p.startDecisions[id]
	if !ok {
		return 0, false
	}
	delete(p.startDecisions, id)
	if time.Since(e.at) > startDecisionTTL {
		return 0, false
	}
	return e.decision, true
}

// New creates a Plugin. onStopping and onStartContainer may both be nil (stub mode). k8sClient
// and nodeName are used for PodMigration CR verification; pass nil/empty for tests.
// ADR-0351 D3.1: onSandboxPausePID/onSandboxRemoved params retired with the pause-PID
// poll/classify/retry apparatus they fed — the cgroup-anchor primitive (D1) reads the
// container's own cgroup path directly off the event already threaded through
// onStartContainer; there is no side-map to write back or evict.
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
	if !ValidCheckpointRef.MatchString(checkpointRef) {
		log.Error(nil, "NRI StartContainer: rejecting invalid checkpointRef — possible path traversal",
			"checkpointRef", checkpointRef, "container", event.ID)
		return fmt.Errorf("invalid checkpointRef %q: must match [a-z0-9][a-z0-9-]{0,61}[a-z0-9]", checkpointRef)
	}

	// ADR-0197 Rule D (agent side) — per-container restore-target gate.
	// ADR-0412 D1: this exclusion runs BEFORE the verifyPodMigration anti-spoof/phase gate below
	// (it previously ran AFTER it). The pod-scoped checkpoint-ref has no per-container
	// discriminator, so this hook fires for EVERY container in the pod — including the cp-only
	// podmotion-inject-holder init container, which is NOT a restore target (excluded from
	// restore-target-containers by construction). Subjecting that init container to the
	// restore-phase gate is what deadlocked it once the owning migration reached a terminal phase
	// (Complete/Failed): the terminal phase was misclassified as a transient "phase is ..." error
	// and retried forever (kubelet CrashLoopBackOff, the live 114-restart case).
	//
	// The anti-spoof gate exists SOLELY to guard the restore TRIGGER. A container excluded from
	// restore-target-containers returns nil here without ever triggering restore, socket-reattach,
	// or the barrier — the exact outcome it would get with no annotation at all — so there is
	// nothing to spoof on this branch. Every container that IS a restore target still traverses
	// the FULL, unchanged anti-spoof + phase gate below before reaching the trigger. (ADR-0412 D1:
	// coverage over the protected action is byte-identical; only a false-positive deadlock on
	// non-targets is removed.)
	const restoreTargetsKey = "podmotion.io/restore-target-containers"
	if targets := event.Annotations[restoreTargetsKey]; targets != "" {
		if !containerInList(event.Name, targets) {
			log.Info("ADR-0197 Rule D: container is not a restore target — clean pass-through (no restore, no barrier)",
				"container", event.ID, "name", event.Name, "restoreTargets", targets)
			return nil
		}
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
	//
	// ADR-0412 D2: verifyPodMigration now classifies the matched migration into FOUR+ outcomes
	// (accept-set → proceed; terminal-own → clean cold-start; terminal-not-own/Failed/RollingBack
	// → fail-closed reject; wrong-node → fail-closed reject; genuinely mid-flight → transient
	// retry). Only the mid-flight "phase is ..." outcome is transient, so terminal states break
	// the retry loop immediately instead of spinning it to budget exhaustion.
	if p.k8sClient != nil {
		// ADR-0351 D4.2: verifyTimeout(antiSpoofVerifyBudget) + verifyInterval
		// (antiSpoofVerifyPollInterval) are bounded WELL under the GROUNDED real
		// nriPluginRequestTimeout (G0.3 — 2s on this substrate, not the previously-assumed
		// 60s/30s) so this synchronous loop cannot overrun containerd's own deadline and get
		// the plugin connection dropped (which would force the raw-CRIU fallback and skip the
		// D1 cgroup-anchor primitive entirely).
		verifyDeadline := time.Now().Add(antiSpoofVerifyBudget)
		var verifyErr error
		for time.Now().Before(verifyDeadline) {
			verifyErr = p.verifyPodMigration(ctx, event.Namespace, event.Pod, checkpointRef)
			if verifyErr == nil {
				break
			}
			// Only retry on phase-ordering transients — fail fast on all other errors
			// (missing/forged CR, node mismatch, terminal phase, List failure). The terminal
			// sentinels do NOT contain "phase is", so this breaks immediately on them.
			if !isPhaseTransientErr(verifyErr) {
				break
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("NRI StartContainer: context cancelled during phase-wait: %w", ctx.Err())
			case <-time.After(antiSpoofVerifyPollInterval):
			}
		}

		// ADR-0412 D2 — terminal-own clean cold-start. The pod's OWN migration already reached
		// Complete: the restore already landed during the migration, so a post-completion kubelet
		// restart must cold-start the container WITHOUT re-restoring stale checkpoint memory. This
		// is NOT a rejection — the container starts normally, which is what breaks the CrashLoop.
		// Record the decision so HandlePostStartContainer consumes the SAME outcome (ADR-0412
		// condition #1) and does not run the barrier/restore off a second independent read.
		if errors.Is(verifyErr, errRestoreNotApplicableTerminalOwn) {
			metrics.NRIRestoreGateOutcomeTotal.WithLabelValues("terminal_own_coldstart").Inc()
			p.recordStartDecision(event.ID, restoreDecisionTerminalOwnColdStart)
			log.Info("NRI StartContainer: pod's own migration already Complete — clean cold-start, no restore (ADR-0412 D2)",
				"container", event.ID, "pod", event.Pod, "namespace", event.Namespace,
				"checkpointRef", checkpointRef)
			return nil // container starts normally; kubelet CrashLoop is broken
		}

		if verifyErr != nil {
			// Classify the fail-closed outcome for the labeled counter (ADR-0412 condition #3).
			// The detailed reason+phase log is emitted at the reject site inside verifyPodMigration
			// (node-mismatch and terminal-not-own), where the matched phase is in scope.
			switch {
			case errors.Is(verifyErr, errNodeMismatch):
				metrics.NRIRestoreGateOutcomeTotal.WithLabelValues("node_mismatch").Inc()
			case errors.Is(verifyErr, errTerminalNotOwn):
				metrics.NRIRestoreGateOutcomeTotal.WithLabelValues("terminal_reject_not_own").Inc()
			case isPhaseTransientErr(verifyErr):
				// Genuinely mid-flight when the budget expired (e.g. a slow OverlayHandoff). The
				// container will CrashLoop and re-attempt on the next start — unchanged pre-ADR
				// behavior for a real in-flight migration.
				metrics.NRIRestoreGateOutcomeTotal.WithLabelValues("transient_wait").Inc()
			}
			log.Error(verifyErr, "NRI StartContainer: PodMigration verification failed — blocking restore",
				"checkpointRef", checkpointRef, "container", event.ID)
			return fmt.Errorf("NRI StartContainer: PodMigration verification failed: %w", verifyErr)
		}

		// Accept-set phase — restore is authorized. Record the proceed decision so
		// HandlePostStartContainer runs the barrier + restore against the SAME decision.
		metrics.NRIRestoreGateOutcomeTotal.WithLabelValues("proceed").Inc()
		p.recordStartDecision(event.ID, restoreDecisionProceed)
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
	if !ValidCheckpointRef.MatchString(checkpointRef) {
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

	// ADR-0412 D2 / condition #1 — consume the decision HandleStartContainer already computed for
	// this container so PostStartContainer acts on the SAME outcome instead of re-deriving it from
	// a second, independent CR read (which a phase transition between the two synchronous hook
	// calls could make disagree). This block runs ONLY when k8sClient != nil; in stub mode
	// (unit-test / no verification) both hooks behave exactly as before this ADR.
	if p.k8sClient != nil {
		decision, found := p.takeStartDecision(event.ID)
		if !found {
			// The threaded decision is unavailable (e.g. the agent restarted between the two
			// hooks, or PostStartContainer was dispatched independently of a preceding
			// StartContainer decision). Re-derive fail-closed rather than blindly proceeding: run
			// barrier + restore ONLY if the migration is verifiably in the restore accept-set. Any
			// non-nil verify result — terminal-own, terminal-not-own, node-mismatch, mid-flight,
			// missing CR — means "do NOT restore here", so we skip. This preserves the no-fail-open
			// guarantee: a missing decision never authorizes a restore it did not earn.
			if verifyErr := p.verifyPodMigration(context.Background(), event.Namespace, event.Pod, checkpointRef); verifyErr != nil {
				log.Info("NRI PostStartContainer: no threaded StartContainer decision and re-derive is not restore-authorized — skipping barrier + restore (fail-closed)",
					"container", event.ID, "pod", event.Pod, "namespace", event.Namespace,
					"checkpointRef", checkpointRef, "reason", verifyErr.Error())
				return nil
			}
			decision = restoreDecisionProceed
		}
		if decision == restoreDecisionTerminalOwnColdStart {
			log.Info("NRI PostStartContainer: pod's own migration already Complete — skipping barrier + restore, clean cold-start (ADR-0412 D2)",
				"container", event.ID, "pod", event.Pod, "namespace", event.Namespace,
				"checkpointRef", checkpointRef)
			return nil
		}
	}

	log.Info("NRI PostStartContainer: CRIU restore triggered",
		"container", event.ID,
		"checkpointRef", checkpointRef,
	)

	// The inbound (now-discarded) context is containerd's PER-EVENT context, bounded by
	// nriPluginRequestTimeout (ADR-0351 D4.1 — GROUNDED at 2s on this substrate, G0.3; NOT the
	// 60s/30s prior comments elsewhere in this file assumed before being pinned to this one
	// value). It is the source of truth for "how long containerd will block the
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
		// (ADR-SEC-B §2.3 step 6) only after signature + per-file digest + migration-binding all passed.
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

// verifyPodMigration ensures that a PodMigration CR matching the checkpointRef exists and targets
// this node, then classifies its phase into the ADR-0412 D2 outcome model:
//
//   - nil                                  → phase is in the restore accept-set {Restoring,
//     RestoreSocketReattach, DisengageHold}; restore is authorized (UNCHANGED accept-set).
//   - errRestoreNotApplicableTerminalOwn   → the pod's OWN migration is Complete; cold-start
//     normally, do NOT re-restore (D2 own-completed branch).
//   - error wrapping errNodeMismatch       → ref's destination node is not this node (fail-closed).
//   - error wrapping errTerminalNotOwn     → ref points at a terminal/aborting migration this pod
//     does not own (fail-closed; anti-spoof preserved).
//   - "phase is ..." error                 → genuinely mid-flight, pre-FDB phase; transient, retry.
//
// podName is event.Pod (the replacement pod's name) — the "own" discriminator for the terminal
// branch. Correctness of the integrity properties does NOT depend on the name binding: the
// safety-critical action on the terminal branch (never re-trigger restore) holds for ALL terminal
// phases unconditionally; the name match only gates cold-start-vs-block, and a mismatch fails safe
// (a false block, never a false restore).
func (p *Plugin) verifyPodMigration(ctx context.Context, namespace, podName, checkpointRef string) error {
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

		// ADR-0412 D2: node identity is checked FIRST — ahead of phase classification — so a
		// wrong-node ref fails fast as a PERMANENT node-mismatch instead of spinning as a transient
		// "phase is ..." until the budget expires. Prefer status.DestinationNodeName (set by the
		// controller after scheduling); fall back to spec.TargetNodeName for early-phase races.
		destNode := pm.Status.DestinationNodeName
		if destNode == "" {
			destNode = pm.Spec.TargetNodeName
		}
		if p.nodeName != "" && destNode != p.nodeName {
			// ADR-0412 condition #3 — fail-closed reject site (node-mismatch): log with migration
			// ref, phase, and the specific reason.
			log.Error(nil, "NRI StartContainer: fail-closed reject — checkpoint-ref destination node is not this node",
				"reason", "node-mismatch",
				"migrationRef", checkpointRef,
				"namespace", namespace,
				"phase", string(pm.Status.Phase),
				"destinationNode", destNode,
				"thisNode", p.nodeName)
			return fmt.Errorf("PodMigration %s/%s destinationNode %s != this node %s: %w",
				namespace, pm.Name, destNode, p.nodeName, errNodeMismatch)
		}

		switch {
		case isRestoreAcceptPhase(pm.Status.Phase):
			// ADR-0185 r1 (Option B): accept-set is NOT widened. OverlayHandoff and every pre-FDB
			// phase are excluded — CRIU restore must not begin until the FDB barrier
			// (conditionVXLANFDBUpdated) is confirmed. Restore is authorized.
			return nil

		case pmv1.IsTerminalOrRollingBackPhase(pm.Status.Phase):
			// ADR-0412 D2 — terminal/aborting phase. Monotonic: never re-enters the accept-set,
			// so it must NOT be retried as a transient "phase is ..." blip.
			if pm.Status.Phase == pmv1.MigrationPhaseComplete &&
				pm.Status.ReplacementPodName != "" &&
				pm.Status.ReplacementPodName == podName {
				// This pod IS the migration's own destination replacement pod, on this node, and
				// the migration COMPLETED. The restore already landed during the migration; a
				// post-completion kubelet restart must cold-start normally, not re-restore stale
				// checkpoint memory. Distinct, PERMANENT (non-"phase is") sentinel.
				return errRestoreNotApplicableTerminalOwn
			}
			// Complete-but-not-own (stale/forged ref → unrelated completed migration), or Failed /
			// RollingBack / DryRunComplete (aborted / never-restored → cold-starting risks a second
			// live instance alongside the ADR-0157-thawed source: split-brain). Fail-closed,
			// PERMANENT.
			//
			// ADR-0412 condition #3 — fail-closed reject site (terminal-not-own): log with
			// migration ref, phase, and the specific reason (own-mismatch vs Failed/RollingBack).
			// ADR-0412 condition #5 — a pod can land here by LEGITIMATE accident (e.g. a stale
			// Status.ReplacementPodName from an interrupted ADR-0360 self-heal cycle). See
			// docs/runbooks/adr-0412-terminal-not-own-recovery.md for the exact kubectl recipe to
			// un-wedge such a pod.
			log.Error(nil, "NRI StartContainer: fail-closed reject — checkpoint-ref points at a terminal/aborting migration this pod does not own",
				"reason", terminalRejectReason(pm.Status.Phase),
				"migrationRef", checkpointRef,
				"namespace", namespace,
				"phase", string(pm.Status.Phase),
				"replacementPodName", pm.Status.ReplacementPodName,
				"thisPod", podName,
				"runbook", "docs/runbooks/adr-0412-terminal-not-own-recovery.md")
			return fmt.Errorf("PodMigration %s/%s is in terminal phase %s and is not restorable — "+
				"checkpoint-ref is stale or does not belong to this pod: %w",
				namespace, pm.Name, pm.Status.Phase, errTerminalNotOwn)

		default:
			// Genuinely mid-flight, pre-FDB phase (Pending…OverlayHandoff, Verifying, …) that WILL
			// advance. Transient "phase is ..." — the bounded retry loop waits for the operator to
			// advance into an accepted restore phase. UNCHANGED behavior.
			return fmt.Errorf("PodMigration %s/%s phase is %s, expected Restoring/RestoreSocketReattach/DisengageHold",
				namespace, pm.Name, pm.Status.Phase)
		}
	}
	// No matching PodMigration found — treat as spoofed annotation.
	return fmt.Errorf("no PodMigration in %s with checkpointRef %q in Restoring phase", namespace, checkpointRef)
}

// terminalRejectReason names the specific reason a terminal/aborting migration is fail-closed
// rejected (ADR-0412 condition #3 observability): "own-mismatch" when the migration is Complete
// but its ReplacementPodName is not this pod (stale/forged ref), otherwise the aborting phase
// itself (Failed / RollingBack / DryRunComplete).
func terminalRejectReason(phase pmv1.MigrationPhase) string {
	if phase == pmv1.MigrationPhaseComplete {
		return "own-mismatch"
	}
	return string(phase)
}

// isRestoreAcceptPhase reports whether a phase is in the NRI anti-spoof restore accept-set.
//
// ADR-0185 r1 (Option B): the accept-set is EXACTLY the phases reachable after
// conditionVXLANFDBUpdated=True — {Restoring, RestoreSocketReattach, DisengageHold}. OverlayHandoff
// is NOT included (FDB not yet confirmed); FinalFreezeStateCapture and all earlier phases are NOT
// included. ADR-0412 does NOT widen this set — it only carves terminal phases out of the former
// catch-all default into their own branch (see verifyPodMigration).
func isRestoreAcceptPhase(phase pmv1.MigrationPhase) bool {
	switch phase {
	case pmv1.MigrationPhaseRestoring,
		pmv1.MigrationPhaseRestoreSocketReattach,
		pmv1.MigrationPhaseDisengageHold:
		return true
	}
	return false
}

// verifyPhaseInAcceptSet is the error-returning wrapper around isRestoreAcceptPhase, retained so
// the ADR-0185 accept-set contract test (TestVerifyPodMigrationAcceptSet) still anchors the
// UNCHANGED accept-set by string ("phase is ..." → transient for the retry loop).
func verifyPhaseInAcceptSet(phase string) error {
	if isRestoreAcceptPhase(pmv1.MigrationPhase(phase)) {
		return nil
	}
	return fmt.Errorf("phase is %s, expected Restoring/RestoreSocketReattach/DisengageHold", phase)
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
// Timeout: containerd's plugin_request_timeout governs this synchronous context — GROUNDED at
// nriPluginRequestTimeout (2s on this substrate, ADR-0351 G0.3), not the previously-assumed
// 30s/60s. CRIU restore itself does NOT run synchronously here — ADR-0198 Rule F defers the
// holder-quiescent barrier + CRIU restore to PostStartContainer's independent restoreCtx, which
// this 2s budget does not govern (see HandlePostStartContainer doc comment below).
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
	// ADR-0351 D3.1: the D5-c PodSandbox.Pid write-back is retired along with the pause-PID
	// apparatus it fed — the cgroup-anchor primitive (D1) reads container.GetLinux().GetCgroupsPath()
	// directly off buildContainerEvent's own event, so there is nothing to capture here anymore.
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
		// ADR-0351 D1.1: read the container's OWN cgroup path directly off the NRI hook
		// payload already delivered to this callback — zero query, zero poll (G0-verified live
		// on pm-w1/pm-w2, 2026-07-15: both fields populated; see g0-probe-adr0351-transcript.md).
		// Nil-safe: GetLinux() may be nil on either side; the generated getters return "" on a
		// nil receiver, never panic.
		ContainerCgroupsPath: container.GetLinux().GetCgroupsPath(),
		// PodCgroupParent is used ONLY as a D2.3/D2.4 validation bound — never a write target.
		PodCgroupParent: pod.GetLinux().GetCgroupParent(),
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
	// ADR-0351 D3.1: the D5-c eviction call is retired with the map it bounded.
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
//
//	/proc/<holderPID>/root/run/podmotion/holder-ready
//
// OR (for scratch rootfs where /proc traversal is unreliable) by the holder's stdout token
//
//	"podmotion-holder ready" observable in the agent log (emitted by cmd/holder/main.go).
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
		// Transport (i): holder-ready sentinel file, observed via the unconfined
		// netns-broker. Reading the sentinel means dereferencing
		// /proc/<holderPID>/root/run/podmotion/holder-ready inside the restore-target
		// container. Opening another container's /proc/<pid>/root routes through a
		// ptrace_may_access gate that the de-privileged agent's `podmotion-agent`
		// AppArmor profile DENIES against the holder's cri-containerd.apparmor.d peer
		// profile (the exact `apparmor DENIED operation="ptrace" ... requested_mask="read"`
		// signature — CAP_SYS_PTRACE does NOT bypass AppArmor mediation). A direct
		// agent-side os.Stat therefore fails EACCES on EVERY poll, so this transport
		// was silently dead and the barrier always timed out at 50s, forcing the
		// gRPC/raw-CRIU fallback (where the ADR-0351 cgroup anchor is skipped and the
		// restored process is never made pod-visible). Delegate the observation to the
		// unconfined broker — the same ptrace-delegation class as ResolveVeth /
		// signal_pid — which resolves the holder PID and stats the sentinel itself.
		// A transient broker error is non-fatal: log it and fall through to the next
		// transport / poll.
		if ready, berr := netnsbroker.NewClient().HolderSentinelReady(ctx, event.ID); berr != nil {
			log.Info("holder-quiescent barrier: broker sentinel observation errored (will retry next poll)",
				"container", event.ID, "error", berr.Error())
		} else if ready {
			log.Info("holder-quiescent barrier satisfied (sentinel file via netns-broker)",
				"container", event.ID, "name", event.Name)
			return nil
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

// (findContainerInitPID was retired: the holder-ready sentinel is now observed via
// the unconfined netns-broker's holder_sentinel op, which resolves the holder PID
// and stats the sentinel in one unconfined process — the confined agent's direct
// /proc/<pid>/root stat was AppArmor-ptrace-denied on every poll, silently dead.)

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
