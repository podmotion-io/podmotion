/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// longhornReadyThreshold is the replica sync percentage that triggers
	// StorageReadyForFreeze (ADR-0011: must be ≥95% before compute freeze).
	longhornReadyThreshold = 95

	// longhornPollInterval is the delay between replica health polls.
	longhornPollInterval = 3 * time.Second

	// longhornSingleOwnerTimeout bounds how long AwaitSingleOwner polls for
	// Longhorn to collapse a volume's dual-engine live-migration state back
	// down to a single RW replica on the destination node. Longhorn's own
	// migration-confirm/handoff step normally completes within a few polling
	// intervals of Cutover's attach call returning; a long stall here means
	// something is genuinely stuck (e.g. the source engine failed to detach),
	// so this must fail closed rather than poll forever.
	longhornSingleOwnerTimeout = 2 * time.Minute
)

// LonghornMigrator implements Tier1 dual-engine live migration via the
// Longhorn Manager HTTP API.
//
// Dual-engine migration sequence:
//  1. GET  /v1/volumes/{name}                      — verify volume exists
//  2. POST /v1/volumes/{name}?action=updateReplicaCount — add replica on dest node
//  3. Poll replica list until dest replica reaches RW + ≥95% sync
//  4. Emit StorageReadyForFreeze
//  5. Cutover: detach from source, attach to destination
//
// We use plain HTTP (not the Longhorn Go SDK) to avoid importing Longhorn as
// a module dependency and to keep the coupling surface small.
type LonghornMigrator struct {
	// ManagerURL is the base URL of the Longhorn Manager, e.g. http://longhorn-frontend.longhorn-system:80
	ManagerURL string
	HTTPClient *http.Client
	// client is used to resolve each PVC's bound PersistentVolume name — the
	// actual Longhorn volume name — rather than assuming it equals the PVC's
	// own name (only true for statically-provisioned volumes; dynamically
	// provisioned PVCs are bound to a PV named e.g. "pvc-d39ce436-...", which
	// is what the Longhorn Manager API actually keys volumes by).
	client client.Client
}

// NewLonghornMigrator returns a production Longhorn migrator. c is used to
// resolve each PVC's bound PersistentVolume name (see resolveVolumeName).
func NewLonghornMigrator(managerURL string, c client.Client) *LonghornMigrator {
	return &LonghornMigrator{
		ManagerURL: strings.TrimRight(managerURL, "/"),
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		client:     c,
	}
}

// resolveVolumeName returns the Longhorn volume name for a PVC — the name of
// the PersistentVolume it is bound to (spec.volumeName), NOT the PVC's own
// name. Longhorn volumes are keyed by PV name; for dynamically-provisioned
// PVCs (the common case) the PV name is generated (e.g.
// "pvc-d39ce436-...") and differs from the PVC name, so using the PVC name
// directly causes the Longhorn Manager API to 404 on an otherwise-healthy
// volume.
func (m *LonghornMigrator) resolveVolumeName(ctx context.Context, namespace, pvcName string) (string, error) {
	pvc := &corev1.PersistentVolumeClaim{}
	if err := m.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: pvcName}, pvc); err != nil {
		return "", fmt.Errorf("get pvc %s: %w", pvcName, err)
	}
	if pvc.Spec.VolumeName == "" {
		return "", fmt.Errorf("pvc %s has no bound PersistentVolume (spec.volumeName empty, phase=%s)",
			pvcName, pvc.Status.Phase)
	}
	return pvc.Spec.VolumeName, nil
}

// Tier returns TierLonghorn.
func (m *LonghornMigrator) Tier() StorageTier { return TierLonghorn }

// PreStage adds a replica on the destination node for each Tier1 PVC and polls
// until the replica is healthy enough to allow compute freeze (≥95% synced).
func (m *LonghornMigrator) PreStage(ctx context.Context, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "Longhorn")

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierLonghorn {
			continue
		}

		volumeName, err := m.resolveVolumeName(ctx, opts.PodNamespace, clsf.PVCName)
		if err != nil {
			return fmt.Errorf("tier1: resolve volume name for pvc %s: %w", clsf.PVCName, err)
		}

		if err := m.verifyVolume(ctx, volumeName); err != nil {
			return fmt.Errorf("tier1: volume verify %s: %w", volumeName, err)
		}

		log.Info("adding replica on destination node", "volume", volumeName, "destNode", opts.DestinationNode)
		if err := m.addDestReplica(ctx, volumeName, opts.DestinationNode); err != nil {
			return fmt.Errorf("tier1: add replica %s: %w", volumeName, err)
		}

		log.Info("polling until replica ≥95%% synced", "volume", volumeName)
		if err := m.pollUntilReady(ctx, volumeName, opts.DestinationNode); err != nil {
			return fmt.Errorf("tier1: poll replica %s: %w", volumeName, err)
		}

		log.Info("Longhorn replica ready for freeze", "volume", volumeName)
	}

	return nil
}

// SyncPercent polls the Longhorn API and returns the lowest replica sync
// percentage across all Tier1 volumes. Returns 0 if no Tier1 volumes.
func (m *LonghornMigrator) SyncPercent(ctx context.Context, opts MigrationOptions) (int, error) {
	lowest := 100
	found := false

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierLonghorn {
			continue
		}
		found = true
		volumeName, err := m.resolveVolumeName(ctx, opts.PodNamespace, clsf.PVCName)
		if err != nil {
			return 0, fmt.Errorf("tier1: resolve volume name for pvc %s: %w", clsf.PVCName, err)
		}
		pct, err := m.replicaSyncPercent(ctx, volumeName, opts.DestinationNode)
		if err != nil {
			return 0, err
		}
		if pct < lowest {
			lowest = pct
		}
	}

	if !found {
		return 100, nil
	}
	return lowest, nil
}

// Cutover detaches the volume from the source node and attaches it to the
// destination. Called after the CRIU restore completes on the destination.
func (m *LonghornMigrator) Cutover(ctx context.Context, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "Longhorn")

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierLonghorn {
			continue
		}

		volumeName, err := m.resolveVolumeName(ctx, opts.PodNamespace, clsf.PVCName)
		if err != nil {
			return fmt.Errorf("tier1: resolve volume name for pvc %s: %w", clsf.PVCName, err)
		}

		log.Info("detaching volume from source node", "volume", volumeName, "src", opts.SourceNode)
		if err := m.detachFromNode(ctx, volumeName, opts.SourceNode); err != nil {
			return fmt.Errorf("tier1: detach %s from %s: %w", volumeName, opts.SourceNode, err)
		}

		log.Info("attaching volume to destination node", "volume", volumeName, "dest", opts.DestinationNode)
		if err := m.attachToNode(ctx, volumeName, opts.DestinationNode); err != nil {
			return fmt.Errorf("tier1: attach %s to %s: %w", volumeName, opts.DestinationNode, err)
		}
	}

	return nil
}

// AwaitSingleOwner polls the Longhorn Manager API until each Tier1 volume's
// replica list has collapsed to exactly one RW/running replica, and that
// replica sits on opts.DestinationNode — i.e. the dual-engine live-migration
// pair Cutover's attach left in place has been torn down on the source side
// by Longhorn's own migration-confirm/handoff step, and the CSI driver will
// therefore see a single controller when the destination pod's NodeStageVolume
// call lands (this is the general fix for the "invalid controller count 2"
// class of error, expressed via Longhorn's real replica-state signal — never
// a string match on the CSI error itself).
func (m *LonghornMigrator) AwaitSingleOwner(ctx context.Context, opts MigrationOptions) error {
	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "Longhorn")

	deadlineCtx, cancel := context.WithTimeout(ctx, longhornSingleOwnerTimeout)
	defer cancel()

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierLonghorn {
			continue
		}

		volumeName, err := m.resolveVolumeName(ctx, opts.PodNamespace, clsf.PVCName)
		if err != nil {
			return fmt.Errorf("tier1: resolve volume name for pvc %s: %w", clsf.PVCName, err)
		}

		log.Info("awaiting single-owner (collapsed dual-engine) state", "volume", volumeName, "destNode", opts.DestinationNode)
		if err := m.pollUntilSingleOwner(deadlineCtx, volumeName, opts.DestinationNode); err != nil {
			return fmt.Errorf("tier1: await single owner %s: %w", volumeName, err)
		}
		log.Info("volume collapsed to single owner", "volume", volumeName, "destNode", opts.DestinationNode)
	}

	return nil
}

// pollUntilSingleOwner polls fetchVolume until exactly one non-failed
// RW/running replica exists and it is on destNode, or ctx is done (a timeout
// or cancellation is returned as an error — fail closed, never requeue
// forever).
func (m *LonghornMigrator) pollUntilSingleOwner(ctx context.Context, volumeName, destNode string) error {
	for {
		vol, err := m.fetchVolume(ctx, volumeName)
		if err == nil {
			owners := 0
			destIsSingleOwner := false
			for _, r := range vol.Replicas {
				if r.FailedAt != "" || r.Mode != "RW" || !r.Running {
					continue
				}
				owners++
				if r.NodeID == destNode {
					destIsSingleOwner = true
				}
			}
			if owners == 1 && destIsSingleOwner {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for volume %s to collapse to a single RW replica on %s: %w",
				volumeName, destNode, ctx.Err())
		case <-time.After(longhornPollInterval):
		}
	}
}

// ── Longhorn HTTP helpers ───────────────────────────────────────────────────

// longhornVolume is the subset of the Longhorn volume API response we care about.
type longhornVolume struct {
	Name       string            `json:"name"`
	State      string            `json:"state"`
	Robustness string            `json:"robustness"`
	Replicas   []longhornReplica `json:"replicas"`
}

type longhornReplica struct {
	Name string `json:"name"`
	// Longhorn's actual /v1/volumes/{name} response field is "hostId", not
	// "nodeID" — confirmed live 2026-07-17 against a running v1.9.1 manager.
	// The mismatched tag silently zero-valued NodeID on every decode, so
	// every "does the destination already have a replica" check here and in
	// replicaSyncPercent below always fell through (empty string never equals
	// a real node name), causing addDestReplica to unconditionally grow the
	// replica set by 1 on every reconcile forever — impossible to satisfy
	// once replica count already equals node count — and pollUntilReady to
	// never see a synced replica, since it uses the same broken match.
	NodeID  string `json:"hostId"`
	Mode    string `json:"mode"` // "RW", "WO", "ERR"
	Running bool   `json:"running"`
	// SnapshotSizeUsage is used to estimate sync progress.
	// Longhorn does not expose a direct sync% — we approximate from
	// mode=WO (write-only / syncing) vs mode=RW (fully synced).
	FailedAt string `json:"failedAt"`
}

func (m *LonghornMigrator) verifyVolume(ctx context.Context, volumeName string) error {
	url := fmt.Sprintf("%s/v1/volumes/%s", m.ManagerURL, volumeName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("longhorn volume %q not found", volumeName)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("longhorn GET volume %q: HTTP %d", volumeName, resp.StatusCode)
	}
	return nil
}

// fetchVolume GETs and decodes the current state of a Longhorn volume,
// including its replica list.
func (m *LonghornMigrator) fetchVolume(ctx context.Context, volumeName string) (*longhornVolume, error) {
	url := fmt.Sprintf("%s/v1/volumes/%s", m.ManagerURL, volumeName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("longhorn GET volume %q: HTTP %d", volumeName, resp.StatusCode)
	}

	var vol longhornVolume
	if err := json.NewDecoder(resp.Body).Decode(&vol); err != nil {
		return nil, err
	}
	return &vol, nil
}

// addDestReplica calls the Longhorn updateReplicaCount action to add one
// replica on the destination node. Longhorn's scheduler will place the new
// replica on the specified node if a node selector is set via the request body.
//
// Before calling, it fetches the volume's current replica set and skips the
// call entirely if the destination node already has a non-failed replica.
// Sprint48 bug: this used to call updateReplicaCount unconditionally with a
// hardcoded replicaCount:2 on every PreStage, regardless of the volume's
// actual current replica count or placement. For a volume that already had
// 3 replicas (one already on the destination node), this silently told
// Longhorn to SHRINK the replica set from 3 to 2 — the opposite of what
// PreStage needs — right as the migration needed the replica set stable.
func (m *LonghornMigrator) addDestReplica(ctx context.Context, volumeName, destNode string) error {
	log := logf.FromContext(ctx).WithValues("volume", volumeName, "destNode", destNode)

	vol, err := m.fetchVolume(ctx, volumeName)
	if err != nil {
		return fmt.Errorf("fetch volume before replica-count check: %w", err)
	}

	for _, r := range vol.Replicas {
		if r.NodeID != destNode {
			continue
		}
		if r.FailedAt != "" {
			// Replica exists on the destination but is failed — fall through
			// and let the updateReplicaCount call below trigger rescheduling.
			break
		}
		log.Info("skipping addDestReplica: destination node already has a replica",
			"replica", r.Name, "mode", r.Mode)
		return nil
	}

	// No healthy/syncing replica on the destination yet — grow the replica
	// set by one, preserving whatever count the volume already has instead
	// of hardcoding it.
	desiredCount := len(vol.Replicas) + 1

	url := fmt.Sprintf("%s/v1/volumes/%s?action=updateReplicaCount", m.ManagerURL, volumeName)
	body := fmt.Sprintf(`{"replicaCount":%d,"nodeSelector":[%q]}`, desiredCount, destNode)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("addDestReplica HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (m *LonghornMigrator) pollUntilReady(ctx context.Context, volumeName, destNode string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(longhornPollInterval):
		}

		pct, err := m.replicaSyncPercent(ctx, volumeName, destNode)
		if err != nil {
			// Transient API error — log and continue polling.
			continue
		}
		if pct >= longhornReadyThreshold {
			return nil
		}
	}
}

// replicaSyncPercent returns 0–100 for the dest node replica.
// Longhorn does not expose a raw sync% — we use mode as a proxy:
//
//	mode=RW  → 100% (fully synced)
//	mode=WO  → 50% (still syncing — mid-point estimate; improves with Longhorn v1.7+ API)
//	mode=ERR → 0%
//	absent   → 0% (replica not yet scheduled)
func (m *LonghornMigrator) replicaSyncPercent(ctx context.Context, volumeName, destNode string) (int, error) {
	vol, err := m.fetchVolume(ctx, volumeName)
	if err != nil {
		return 0, err
	}

	for _, r := range vol.Replicas {
		if r.NodeID != destNode {
			continue
		}
		if r.FailedAt != "" {
			return 0, nil
		}
		switch r.Mode {
		case "RW":
			return 100, nil
		case "WO":
			// Write-only = still syncing; treat as 50% to avoid premature freeze.
			return 50, nil
		default:
			return 0, nil
		}
	}
	return 0, nil // replica not yet present
}

func (m *LonghornMigrator) detachFromNode(ctx context.Context, volumeName, nodeName string) error {
	url := fmt.Sprintf("%s/v1/volumes/%s?action=detach", m.ManagerURL, volumeName)
	body := fmt.Sprintf(`{"hostId":%q}`, nodeName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("detach HTTP %d", resp.StatusCode)
	}
	return nil
}

func (m *LonghornMigrator) attachToNode(ctx context.Context, volumeName, nodeName string) error {
	url := fmt.Sprintf("%s/v1/volumes/%s?action=attach", m.ManagerURL, volumeName)
	body := fmt.Sprintf(`{"hostId":%q,"disableFrontend":false}`, nodeName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("attach HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Stub ───────────────────────────────────────────────────────────────────

// LonghornStubMigrator is used in unit tests and environments without Longhorn.
// It emits StorageReadyForFreeze immediately by returning 100% sync on first poll.
type LonghornStubMigrator struct {
	// InjectPreStageError causes PreStage to return this error.
	InjectPreStageError error
	// PreStageCalled is incremented each time PreStage is called.
	PreStageCalled int
	// CutoverCalled records whether Cutover was called.
	CutoverCalled bool
	// AwaitSingleOwnerCalled records whether AwaitSingleOwner was called.
	AwaitSingleOwnerCalled bool
	// InjectAwaitSingleOwnerError causes AwaitSingleOwner to return this error.
	InjectAwaitSingleOwnerError error
}

// Tier returns TierLonghorn.
func (s *LonghornStubMigrator) Tier() StorageTier { return TierLonghorn }

// PreStage records the call and returns the injected error (nil by default).
func (s *LonghornStubMigrator) PreStage(_ context.Context, _ MigrationOptions) error {
	s.PreStageCalled++
	return s.InjectPreStageError
}

// SyncPercent returns 100 immediately — the stub is always "ready".
func (s *LonghornStubMigrator) SyncPercent(_ context.Context, _ MigrationOptions) (int, error) {
	return 100, nil
}

// Cutover records the call without performing any real work.
func (s *LonghornStubMigrator) Cutover(_ context.Context, _ MigrationOptions) error {
	s.CutoverCalled = true
	return nil
}

// AwaitSingleOwner records the call and returns the injected error (nil by default).
func (s *LonghornStubMigrator) AwaitSingleOwner(_ context.Context, _ MigrationOptions) error {
	s.AwaitSingleOwnerCalled = true
	return s.InjectAwaitSingleOwnerError
}
