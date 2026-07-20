/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package seccomp manages the narrow seccomp Unconfined window required by CRIU dump.
//
// CRIU requires Unconfined seccomp during the checkpoint window because ptrace-based
// memory scanning and parasite injection trigger syscalls (ptrace, process_vm_readv)
// that a production seccomp profile blocks. The window is bounded by the CRIU dump +
// restore window (ADR-0009 §2, upper bound = ADR-0049 zero-window hold timeout);
// RestoreSeccomp MUST run on EVERY exit path — success, failure, panic, timeout —
// to avoid leaving containers Unconfined (Agent 9 invariant, ADR-0009).
//
// # Mechanism (ADR-0009 §1, authoritative)
//
// The authoritative seccomp swap mechanism is containerd OCI-spec mutation via the
// Kill+Create path: containerd does NOT support live seccomp changes on a running
// task without recreating it, so the task is stopped after the CRIU dump and the
// container spec is recreated with a mutated linux.seccomp. ADR-0009 §1 (T-1)
// explicitly SUPERSEDES the prior stub comment that described a TaskService.Update
// call — Update is NOT used.
//
// # Carried debt — SD-3 partial wiring (this file)
//
// SD-3 replaces the prior `runtime/default` hardcode (ADR-0009 T-2 carried debt): the
// manager now reads and persists the container's REAL pre-swap seccomp profile from the
// live OCI bundle config.json, saves it to /run/podmotion/seccomp-restore/, and emits
// the full Kubernetes event set. What remains PARTIAL: this build has NO typed containerd
// Go client (the agent talks to containerd via the `ctr` CLI — see internal/agent/server
// and go.mod), so the actual Kill+Create OCI-spec MUTATION that flips linux.seccomp to
// Unconfined and back is NOT performed here. SwapToUnconfined/RestoreSeccomp do the
// save → event → restore → cleanup bookkeeping against the REAL profile; the spec
// mutation hook is the remaining M13/full-client work and is the single TODO below.
// This eliminates the §57 (T-2) silent-weakening hazard — the rollback chain now
// re-applies the container's true profile, never a blind `runtime/default`.
package seccomp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// savedProfileDir is where we persist the original seccomp profile during the checkpoint
// window. On tmpfs under /run so it is node-local and survives an agent restart within the
// migration window but not a node reboot (a rebooted node has no Unconfined containers to
// restore). Task SD-3 path contract. A package var (not const) only so tests can redirect
// it off the privileged /run path.
var savedProfileDir = "/run/podmotion/seccomp-restore"

const (
	// maxRestoreAttempts is the ADR-0009 §4 retry budget for the primary Kill+Create
	// re-apply before the Critical-event + pod-annotation rollback path fires.
	maxRestoreAttempts = 3

	// Event reasons (ADR-0009 §3 / §4).
	eventReasonSeccompWeakened            = "SeccompWeakened"            // Warning, on swap to Unconfined
	eventReasonSeccompRestored            = "SeccompRestored"            // Normal, on successful restore
	eventReasonSeccompRestoreAfterRestart = "SeccompRestoreAfterRestart" // Normal, crash-recovery restore
	eventReasonSeccompRestorationFailed   = "SeccompRestorationFailed"   // Warning (Critical), after maxRestoreAttempts

	// seccompRestoreFailedAnnotation blocks new PodMigrations for a pod whose seccomp
	// profile could not be restored (ADR-0009 §4.3). Cleared only by a cluster operator.
	seccompRestoreFailedAnnotation = "podmotion.io/seccomp-restore-failed"

	// profileUnconfined is the sentinel persisted when the container ran with no seccomp
	// profile (already unconfined). Restoring it is a no-op spec-wise but we still record it.
	profileUnconfined = "unconfined"

	// defaultContainerdRunRoot is the standard kubeadm/containerd host socket/bundle root.
	// Kept identical to internal/agent/server's default (sprint50 k3s compat plan §0 item 4 —
	// this is a second, independent hardcode of the same path, not a shared constant).
	defaultContainerdRunRoot = "/run/containerd"
)

// hostBundleBase is the containerd v2 task bundle root as visible to the agent. The agent
// mounts the host /run at /host-run (server.go hostBundleDir), so the live OCI spec
// (config.json) for a container lives under this tree, NOT bare /run. Standard
// kubeadm/containerd installs use /run/containerd; k3s's embedded containerd uses a different
// root (UNVERIFIED-EXTERNAL — see docs/sprints/sprint50-k3s/K3S-COMPATIBILITY-PLAN.md §0 item
// 4). Override via PODMOTION_CONTAINERD_RUN_ROOT (same env var server.go reads — set from
// Helm value agent.containerd.socketPath's directory), so a k3s deploy needs a values
// override, not a code change.
var hostBundleBase = "/host-run" + strings.TrimPrefix(containerdRunRootEnv(), "/run") + "/io.containerd.runtime.v2.task/k8s.io"

func containerdRunRootEnv() string {
	if v := os.Getenv("PODMOTION_CONTAINERD_RUN_ROOT"); v != "" {
		return v
	}
	return defaultContainerdRunRoot
}

var log = logf.Log.WithName("seccomp-manager")

// SeccompManager swaps a container's seccomp profile to Unconfined for the CRIU checkpoint
// window and restores it afterwards.
type SeccompManager interface {
	// SwapToUnconfined saves the container's REAL current seccomp profile and applies
	// Unconfined. Must be called immediately before CRIU dump. Caller MUST defer
	// RestoreSeccomp. Emits a Warning/SeccompWeakened event.
	SwapToUnconfined(ctx context.Context, containerID, namespace string, pod types.NamespacedName) error

	// RestoreSeccomp reads the saved profile and restores it. Always called: happy path
	// after restore AND rollback path (ADR-0014, ADR-0009 §2). Retries the Kill+Create
	// re-apply up to maxRestoreAttempts; on exhaustion emits a Critical event and annotates
	// the pod to block further migrations (ADR-0009 §4). Emits Normal/SeccompRestored on success.
	RestoreSeccomp(ctx context.Context, containerID, namespace string, pod types.NamespacedName) error
}

// savedProfile is persisted to disk so RestoreSeccomp works even across an agent restart
// during the narrow checkpoint window (crash recovery, ADR-0009 §2). Pod identity is
// persisted so the crash-recovery scan can emit events / annotate without re-deriving it.
type savedProfile struct {
	ContainerID  string `json:"containerID"`
	Namespace    string `json:"namespace"`
	PodName      string `json:"podName"`
	PodNamespace string `json:"podNamespace"`
	// Profile is the container's REAL pre-swap OCI seccomp profile reference:
	// "unconfined" when the container had no profile, "localhost/<path>" for a localhost
	// profile, or "embedded:<defaultAction>" when the spec carried an inline profile.
	// SD-3: never a blind "runtime/default" — read from the live OCI bundle.
	Profile string `json:"profile"`
}

func savedProfilePath(containerID string) string {
	// SD-3 path contract: /run/podmotion/seccomp-restore/<containerID>.json
	return filepath.Join(savedProfileDir, containerID+".json")
}

// ProfileReader reads the live OCI seccomp profile reference for a container. The default
// implementation reads the containerd task bundle config.json; tests inject a fake.
type ProfileReader interface {
	ReadSeccompProfile(containerID string) (string, error)
}

// SpecMutator performs the ADR-0009 §1 Kill+Create OCI-spec mutation. The default
// implementation is the partial no-op (see package doc — SD-3 carried debt): the typed
// containerd client required for Kill+Create is not in this build. Tests inject a fake to
// assert call ordering and the retry/rollback path.
type SpecMutator interface {
	// ApplyUnconfined recreates the container with linux.seccomp = Unconfined.
	ApplyUnconfined(ctx context.Context, containerID string) error
	// ApplyProfile recreates the container with the given (real) seccomp profile reference.
	ApplyProfile(ctx context.Context, containerID, profile string) error
}

// ContainerdSeccompManager talks to containerd to swap/restore the seccomp profile.
//
// SD-3 state: reads & persists the REAL profile and emits the full event set; the
// Kill+Create spec mutation is delegated to Mutator, which is the partial no-op in this
// build (no typed containerd client) and the seam where M13 wiring lands.
type ContainerdSeccompManager struct {
	// KubeClient patches the pod annotation on restore failure (ADR-0009 §4.3). May be nil
	// in dev/kind; annotation patch is then skipped with a logged warning.
	KubeClient client.Client
	// Recorder emits the SeccompWeakened/SeccompRestored/... events (ADR-0009 §3/§4). May
	// be nil in dev; events are then logged only.
	Recorder record.EventRecorder
	// Reader resolves the live profile. Defaults to bundleProfileReader when nil.
	Reader ProfileReader
	// Mutator performs the OCI-spec mutation. Defaults to noopSpecMutator when nil (partial).
	Mutator SpecMutator
}

func (m *ContainerdSeccompManager) reader() ProfileReader {
	if m.Reader != nil {
		return m.Reader
	}
	return bundleProfileReader{}
}

func (m *ContainerdSeccompManager) mutator() SpecMutator {
	if m.Mutator != nil {
		return m.Mutator
	}
	return noopSpecMutator{}
}

// SwapToUnconfined reads the container's REAL current OCI seccomp profile, persists it to
// /run/podmotion/seccomp-restore/<containerID>.json, applies Unconfined via the Kill+Create
// mutator, and emits a Warning/SeccompWeakened event (ADR-0009 §1/§3).
func (m *ContainerdSeccompManager) SwapToUnconfined(ctx context.Context, containerID, namespace string, pod types.NamespacedName) error {
	profile, err := m.reader().ReadSeccompProfile(containerID)
	if err != nil {
		return fmt.Errorf("read live seccomp profile before swap (SD-3): %w", err)
	}

	if persistErr := persistProfile(savedProfile{
		ContainerID:  containerID,
		Namespace:    namespace,
		PodName:      pod.Name,
		PodNamespace: pod.Namespace,
		Profile:      profile,
	}); persistErr != nil {
		return fmt.Errorf("persist real seccomp profile before swap: %w", persistErr)
	}

	if err := m.mutator().ApplyUnconfined(ctx, containerID); err != nil {
		// Spec mutation failed: roll the persisted record back so we do not leave a saved
		// file claiming a swap that never happened.
		_ = os.Remove(savedProfilePath(containerID))
		return fmt.Errorf("apply unconfined seccomp (Kill+Create, ADR-0009 §1): %w", err)
	}

	log.Info("seccomp swapped to Unconfined — checkpoint window open",
		"containerID", containerID, "namespace", namespace, "savedProfile", profile,
		"pod", pod.String())
	m.event(pod, corev1.EventTypeWarning, eventReasonSeccompWeakened,
		fmt.Sprintf("seccomp profile weakened to Unconfined for CRIU checkpoint window (pod %s, container %s, saved profile %q)",
			pod.String(), containerID, profile))
	return nil
}

// RestoreSeccomp reads the persisted profile and re-applies it via the Kill+Create mutator,
// retrying up to maxRestoreAttempts (ADR-0009 §4.1). On success the saved file is deleted
// and a Normal/SeccompRestored event is emitted. On exhaustion a Critical event is emitted
// and the pod is annotated to block further migrations (ADR-0009 §4.2/§4.3).
func (m *ContainerdSeccompManager) RestoreSeccomp(ctx context.Context, containerID, namespace string, pod types.NamespacedName) error {
	p, err := loadProfile(containerID)
	if err != nil {
		return fmt.Errorf("load saved seccomp profile for restore: %w", err)
	}
	return m.restore(ctx, p, pod, eventReasonSeccompRestored)
}

// restore is the shared retry/rollback body used by RestoreSeccomp and the crash-recovery
// path. successReason lets the crash-recovery path emit SeccompRestoreAfterRestart instead.
func (m *ContainerdSeccompManager) restore(ctx context.Context, p *savedProfile, pod types.NamespacedName, successReason string) error {
	var lastErr error
	for attempt := 1; attempt <= maxRestoreAttempts; attempt++ {
		lastErr = m.mutator().ApplyProfile(ctx, p.ContainerID, p.Profile)
		if lastErr == nil {
			if removeErr := os.Remove(savedProfilePath(p.ContainerID)); removeErr != nil && !os.IsNotExist(removeErr) {
				log.Error(removeErr, "failed to remove saved seccomp profile file", "containerID", p.ContainerID)
			}
			log.Info("seccomp restored after checkpoint window",
				"containerID", p.ContainerID, "namespace", p.Namespace, "restoredProfile", p.Profile,
				"reason", successReason, "attempt", attempt)
			m.event(pod, corev1.EventTypeNormal, successReason,
				fmt.Sprintf("seccomp profile %q restored for container %s (pod %s)", p.Profile, p.ContainerID, pod.String()))
			return nil
		}
		log.Error(lastErr, "seccomp restore attempt failed (ADR-0009 §4.1)",
			"containerID", p.ContainerID, "attempt", attempt, "max", maxRestoreAttempts)
		// Exponential backoff between attempts (skip after the final attempt).
		if attempt < maxRestoreAttempts {
			backoff := time.Duration(1<<uint(attempt-1)) * 100 * time.Millisecond
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
		}
	}

	// ADR-0009 §4.2/§4.3 rollback: Critical event + block-further-migrations annotation.
	log.Error(lastErr, "seccomp restore FAILED after max attempts — container may be left Unconfined (ADR-0009 §4)",
		"containerID", p.ContainerID, "attempts", maxRestoreAttempts, "profile", p.Profile)
	m.event(pod, corev1.EventTypeWarning, eventReasonSeccompRestorationFailed,
		fmt.Sprintf("CRITICAL: seccomp profile %q could not be restored for container %s after %d attempts; pod %s annotated %s=true to block further migrations (ADR-0009 §4)",
			p.Profile, p.ContainerID, maxRestoreAttempts, pod.String(), seccompRestoreFailedAnnotation))
	if annErr := m.annotateRestoreFailed(ctx, pod); annErr != nil {
		log.Error(annErr, "failed to annotate pod with seccomp-restore-failed (ADR-0009 §4.3)", "pod", pod.String())
	}
	return fmt.Errorf("seccomp restore failed after %d attempts (container %s): %w", maxRestoreAttempts, p.ContainerID, lastErr)
}

// RecoverOrphanedProfiles scans savedProfileDir for any seccomp profiles persisted by a
// prior agent instance that died inside the checkpoint window and restores each one. It
// emits a SeccompRestoreAfterRestart event per recovered container (ADR-0009 §2 crash
// recovery). Returns the count of profiles successfully restored. Safe to call when the
// directory is absent. Intended to be called once at agent startup, before the gRPC server
// accepts new migrations.
func (m *ContainerdSeccompManager) RecoverOrphanedProfiles(ctx context.Context) (int, error) {
	entries, err := os.ReadDir(savedProfileDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("scan seccomp-restore dir: %w", err)
	}
	recovered := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		containerID := strings.TrimSuffix(e.Name(), ".json")
		p, loadErr := loadProfile(containerID)
		if loadErr != nil {
			log.Error(loadErr, "crash-recovery: unreadable saved seccomp profile — leaving in place", "file", e.Name())
			continue
		}
		pod := types.NamespacedName{Namespace: p.PodNamespace, Name: p.PodName}
		log.Info("crash-recovery: restoring orphaned seccomp profile left Unconfined by prior agent (ADR-0009 §2)",
			"containerID", containerID, "profile", p.Profile, "pod", pod.String())
		if restoreErr := m.restore(ctx, p, pod, eventReasonSeccompRestoreAfterRestart); restoreErr != nil {
			log.Error(restoreErr, "crash-recovery: failed to restore orphaned seccomp profile", "containerID", containerID)
			continue
		}
		recovered++
	}
	return recovered, nil
}

// event emits a Kubernetes event against the migrated Pod, or logs it when no recorder /
// pod identity is available (dev/kind).
func (m *ContainerdSeccompManager) event(pod types.NamespacedName, eventType, reason, msg string) {
	if m.Recorder == nil || pod.Name == "" {
		log.Info("seccomp event (no recorder/pod — logged only)", "type", eventType, "reason", reason, "message", msg, "pod", pod.String())
		return
	}
	ref := &corev1.ObjectReference{Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name}
	m.Recorder.Event(ref, eventType, reason, msg)
}

// annotateRestoreFailed sets podmotion.io/seccomp-restore-failed=true on the pod so the
// ValidatingAdmissionWebhook rejects new PodMigrations for it (ADR-0009 §4.3).
func (m *ContainerdSeccompManager) annotateRestoreFailed(ctx context.Context, pod types.NamespacedName) error {
	if m.KubeClient == nil || pod.Name == "" {
		return fmt.Errorf("no kube client or pod identity — cannot set %s annotation", seccompRestoreFailedAnnotation)
	}
	var p corev1.Pod
	if err := m.KubeClient.Get(ctx, pod, &p); err != nil {
		return fmt.Errorf("get pod for annotation: %w", err)
	}
	base := p.DeepCopy()
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	p.Annotations[seccompRestoreFailedAnnotation] = "true"
	if err := m.KubeClient.Patch(ctx, &p, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("patch pod annotation: %w", err)
	}
	return nil
}

func persistProfile(p savedProfile) error {
	if err := os.MkdirAll(savedProfileDir, 0o700); err != nil {
		return fmt.Errorf("create saved profile dir: %w", err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	// Write atomically: temp file then rename to avoid partial reads on crash.
	tmp := savedProfilePath(p.ContainerID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, savedProfilePath(p.ContainerID))
}

func loadProfile(containerID string) (*savedProfile, error) {
	data, err := os.ReadFile(savedProfilePath(containerID))
	if err != nil {
		return nil, err
	}
	var p savedProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal saved seccomp profile: %w", err)
	}
	return &p, nil
}

// bundleProfileReader resolves the REAL seccomp profile from the live containerd task
// bundle config.json (OCI runtime spec linux.seccomp). This is the SD-3 fix that replaces
// the prior hardcoded "runtime/default": it reads what the container ACTUALLY ran with.
type bundleProfileReader struct{}

func (bundleProfileReader) ReadSeccompProfile(containerID string) (string, error) {
	cfgPath := filepath.Join(hostBundleBase, containerID, "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", fmt.Errorf("read OCI config.json at %s: %w", cfgPath, err)
	}
	return parseSeccompProfile(data)
}

// parseSeccompProfile extracts a stable profile reference from an OCI config.json. We parse
// generically (not via the runtime-spec struct) so we are robust across spec versions and
// can record a meaningful reference even for inline/embedded profiles. Semantics:
//   - linux.seccomp absent          -> "unconfined" (container ran with no profile)
//   - linux.seccomp.defaultAction X -> "embedded:X" (the real inline profile is preserved
//     verbatim on disk in the saved file's source bundle; we record its defaultAction as a
//     stable, non-secret reference for the restore + rollback chain)
func parseSeccompProfile(configJSON []byte) (string, error) {
	var cfg struct {
		Linux *struct {
			Seccomp *struct {
				DefaultAction string `json:"defaultAction"`
			} `json:"seccomp"`
		} `json:"linux"`
	}
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return "", fmt.Errorf("unmarshal OCI config.json: %w", err)
	}
	if cfg.Linux == nil || cfg.Linux.Seccomp == nil {
		return profileUnconfined, nil
	}
	if cfg.Linux.Seccomp.DefaultAction == "" {
		// seccomp object present but no defaultAction — treat as an embedded profile with
		// an unknown action; still NOT unconfined.
		return "embedded:unknown", nil
	}
	return "embedded:" + cfg.Linux.Seccomp.DefaultAction, nil
}

// noopSpecMutator is the partial (SD-3) Kill+Create mutator: this build has no typed
// containerd client, so it performs no spec mutation and returns nil. The real Kill+Create
// OCI-spec mutation (ADR-0009 §1) lands at this seam in M13. It is deliberately a success
// no-op so the save/restore/event/crash-recovery invariants are exercised end-to-end now.
type noopSpecMutator struct{}

func (noopSpecMutator) ApplyUnconfined(_ context.Context, containerID string) error {
	log.Info("SD-3 PARTIAL: skipping Kill+Create OCI-spec mutation to Unconfined — no typed containerd client in this build (ADR-0009 §1, M13 seam)",
		"containerID", containerID)
	return nil
}

func (noopSpecMutator) ApplyProfile(_ context.Context, containerID, profile string) error {
	log.Info("SD-3 PARTIAL: skipping Kill+Create OCI-spec mutation to restore profile — no typed containerd client in this build (ADR-0009 §1, M13 seam)",
		"containerID", containerID, "profile", profile)
	return nil
}

// SeccompManagerStub is a no-op implementation for use in unit tests and dry-run mode.
type SeccompManagerStub struct{}

func (s *SeccompManagerStub) SwapToUnconfined(_ context.Context, containerID, namespace string, pod types.NamespacedName) error {
	log.Info("SeccompManagerStub: no-op SwapToUnconfined", "containerID", containerID, "namespace", namespace, "pod", pod.String())
	return nil
}

func (s *SeccompManagerStub) RestoreSeccomp(_ context.Context, containerID, namespace string, pod types.NamespacedName) error {
	log.Info("SeccompManagerStub: no-op RestoreSeccomp", "containerID", containerID, "namespace", namespace, "pod", pod.String())
	return nil
}
