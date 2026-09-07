/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// errEmptyDestinationNode is returned by PreStage/addDestReplica when opts.DestinationNode (or
// the destNode argument, respectively) is empty (ADR-0365 Decision §2 item 3 — fail-closed
// hardening #3). Before this guard, an empty DestinationNode was silently accepted and forwarded
// into a Longhorn updateReplicaCount call as nodeSelector:[""], depending on Longhorn's own
// (unverified, not fail-fast) handling of that input. This guard is a backstop independent of
// ADR-0365's other hardenings (the early destination decision in reconcileValidating, the hoisted
// destNode-required gate in reconcileDestinationPrewarm) — even if a future code path reaches
// PreStage with an empty destination through some route none of those anticipated, it fails at
// this boundary instead of silently proceeding. RunPreStage's existing error-handling path
// surfaces this the same way it already surfaces ClassifyFailed/BlockedVolume/PreStageFailed, via
// a distinct "EmptyDestinationNode" condition reason.
var errEmptyDestinationNode = errors.New("empty destination node: refusing to issue a Longhorn " +
	"nodeSelector call with no destination (ADR-0365 fail-closed guard)")

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
	if opts.DestinationNode == "" {
		// ADR-0365 Decision §2 item 3: fail closed rather than proceeding with an empty
		// destination — see errEmptyDestinationNode's doc comment.
		return errEmptyDestinationNode
	}

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
// destination. Called by the controller from reconcileOverlayHandoff, after
// the scheduling gate has already been removed (so the destination pod has
// had a chance to schedule and kubelet has had a chance to mount the
// volume — the real trigger for Longhorn's dual-engine collapse below) but
// strictly before CRIU restore is permitted to run on the destination.
//
// NOTE (sprint49 root-cause finding, CORRECTED post-ADR-0368 live outage — see
// docs/adr/0368-storage-rollback-undo-migrator-releasedestination.md §1): Longhorn's real
// dual-engine live migration is driven entirely by the CSI attachment tickets on
// volumeattachments.longhorn.io (spec.attachmentTickets, keyed by the
// csi-attacher ticket type) — a second pod referencing the PVC on a
// different node is what makes longhorn-manager populate
// spec.migrationNodeID and start the second engine; that is a GET-only,
// observable signal with no REST POST involved. The detachFromNode/attachToNode calls below
// issue the legacy `?action=detach`/`?action=attach` REST calls, which operate on a DIFFERENT
// ticket type and do NOT drive that CSI-attacher dual-engine collapse signal — AwaitSingleOwner
// below correctly does not depend on them, and that narrow claim stands.
//
// The broader claim this comment used to make — "no observed effect… harmless (dead weight, not
// wrong)" — was FALSE and directly caused a live production outage (ADR-0368 §1, 2026-07-23):
// the `?action=attach` call sets real, load-bearing Longhorn manager state
// (spec.nodeID/status.currentNodeID) that Longhorn's CSI driver reads and enforces a strict
// single-attach constraint against on every subsequent AttachVolume call, for ANY future
// claimant of that volume — a different migration's destination, or the original source pod
// trying to reattach after a rollback that never issued the symmetric detach. It is NOT dead
// weight: it is a real reservation that MUST be released on rollback. ReleaseDestination
// (below) is that symmetric undo — see its doc comment for the fix.
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
// controller (engine) list has collapsed to exactly one running controller,
// and that controller sits on opts.DestinationNode — i.e. the dual-engine
// live-migration pair Cutover's attach left in place has been torn down on
// the source side by Longhorn's own migration-confirm/handoff step, so the
// CSI driver will see a single controller when the destination pod's
// NodeStageVolume call lands (this is the general fix for the "invalid
// controller count 2" class of error, expressed via Longhorn's real
// controller-collapse signal — never a string match on the CSI error itself).
//
// sprint49 root-cause finding (live cluster verification, 2026-07-18):
// this MUST poll the volume's "controllers" (engine) list, NOT its
// "replicas" list. Longhorn's dual-engine live migration adds a SECOND
// ENGINE on the destination node and later tears down the source engine —
// it does not, and for an HA volume (numberOfReplicas>1, the normal case:
// confirmed live against the longhorn-migratable StorageClass, which sets
// numberOfReplicas=3) never does, change the underlying REPLICA count.
// A healthy 3-replica volume keeps all 3 replicas RW/running on their 3
// nodes for the volume's entire lifetime, migration included (confirmed
// live: replicas on pm-cp1/pm-w1/pm-w2 all mode=RW running=true both before
// and after a completed cutover) — polling for "replica count == 1" can
// never be satisfied and times out every longhornSingleOwnerTimeout forever.
// The real GET-only signal for "has the dual-engine pair collapsed back to
// one" is the volume's controllers array (JSON field the live Longhorn
// v1.9.1 Manager API actually returns, confirmed via GET
// /v1/volumes/{name}): exactly one entry, running=true, hostId==destNode.
//
// This method's AwaitSingleOwnerTimeout reason is relied on by CutoverSideEffectOccurred
// (ADR-0368) and, as of ADR-0428 D1c, by the storage-cutover guard's Cutover-skip decision, as
// evidence that the tier's Cutover already ran. That is a SEQUENCE invariant, not a confirmed
// fact: it holds only because the sole non-test caller reaches this method only after Cutover
// returned nil. A future caller that invokes this without a preceding successful Cutover breaks
// both consumers — after D1c, in the skip direction. See the Cutover doc comment above for why
// the collapse this polls for is CSI-attacher-driven and does not depend on Cutover's REST calls
// (ADR-0428 D1c.0.2).
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

// pollUntilSingleOwner polls fetchVolume until exactly one running
// controller (engine) exists and it is on destNode, or ctx is done (a
// timeout or cancellation is returned as an error — fail closed, never
// requeue forever). See the AwaitSingleOwner doc comment above for why this
// checks the controller list rather than the replica list.
func (m *LonghornMigrator) pollUntilSingleOwner(ctx context.Context, volumeName, destNode string) error {
	for {
		vol, err := m.fetchVolume(ctx, volumeName)
		if err == nil {
			owners := 0
			destIsSingleOwner := false
			for _, c := range vol.Controllers {
				if !c.Running {
					continue
				}
				owners++
				if c.NodeID == destNode {
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

// ErrTier1DetachReleaseTimedOut is returned by ReleaseDestination when detachFromNode's HTTP call
// succeeded (2xx) but the destination attach reservation was not confirmed released within
// longhornDetachTimeout. This is a real, distinct, non-nil error — never nil — per ADR-0368
// CONDITION 3 (KVM Expert FINDING 2): a 2xx response only proves the detach was REQUESTED, not
// that it COMPLETED, exactly the class of bug (trusting a request-sent signal as a confirmed-done
// signal) that caused the live outage this ADR fixes. Retriable via the normal rollback requeue —
// this is an operational timeout, not a structural ErrRollbackPointOfNoReturn/
// ErrRollbackNotImplemented case.
var ErrTier1DetachReleaseTimedOut = errors.New(
	"tier1: detach requested but not confirmed released from the destination node within the timeout")

// longhornDetachTimeout bounds how long ReleaseDestination polls to confirm a rollback detach
// has actually taken effect, mirroring longhornSingleOwnerTimeout's bounded-poll shape (never an
// unbounded/forever wait).
const longhornDetachTimeout = 2 * time.Minute

// ReleaseDestination undoes Cutover's attachToNode call by issuing the symmetric detachFromNode
// request against opts.DestinationNode, then polling (bounded by longhornDetachTimeout) until the
// volume is CONFIRMED actually released — not merely requested — before returning nil (ADR-0368
// §5.2/CONDITION 3). detachFromNode's own HTTP call only proves Longhorn ACCEPTED the detach
// request (a 2xx response); it does not prove the destination-node engine was actually torn down.
// Trusting the 2xx alone as "released" is exactly the class of bug (a request-sent signal
// mistaken for a confirmed-done signal) that produced the live outage this ADR fixes — and is the
// same class of bug the emergency recovery this session had to work around by polling the volume's
// real attachment state instead of trusting the original attach call's own 2xx response.
//
// No opts.CutoverComplete gate is needed here (unlike Tier2/Tier3 — see CONDITION 2): Longhorn's
// `?action=detach` on an already-detached (or never-attached) volume is a safe, idempotent
// no-op server-side (the same idempotency assumption Cutover's own attachToNode call already
// relies on across reconciles — ADR-0368 §5.2). So calling detachFromNode unconditionally is
// itself the correct behavior for "if cutover never happened, there's nothing to release": the
// detach call and its poll simply confirm-and-return immediately with no state change.
//
// A detach HTTP failure (detachFromNode itself erroring) returns a plain wrapped error — a real,
// retriable, operational failure, not a point-of-no-return; so does a confirmed-release-timeout
// (ErrTier1DetachReleaseTimedOut). Neither is nil, per the interface's fail-loud contract.
func (m *LonghornMigrator) ReleaseDestination(ctx context.Context, opts MigrationOptions) error {
	if opts.DestinationNode == "" {
		// Mirrors PreStage/addDestReplica's identical fail-closed guard — see
		// errEmptyDestinationNode's doc comment. Refuse to issue a detach against an
		// unspecified node rather than letting Longhorn interpret an empty hostId.
		return errEmptyDestinationNode
	}

	log := logf.FromContext(ctx).WithValues("migration", opts.MigrationName, "tier", "Longhorn")

	for _, clsf := range opts.Classifications {
		if clsf.Tier != TierLonghorn {
			continue
		}

		volumeName, err := m.resolveVolumeName(ctx, opts.PodNamespace, clsf.PVCName)
		if err != nil {
			return fmt.Errorf("tier1: resolve volume name for pvc %s: %w", clsf.PVCName, err)
		}

		log.Info("releasing destination attach reservation (rollback)", "volume", volumeName, "destNode", opts.DestinationNode)
		if err := m.detachFromNode(ctx, volumeName, opts.DestinationNode); err != nil {
			return fmt.Errorf("tier1: rollback detach %s from %s: %w", volumeName, opts.DestinationNode, err)
		}

		deadlineCtx, cancel := context.WithTimeout(ctx, longhornDetachTimeout)
		pollErr := m.pollUntilDetached(deadlineCtx, volumeName, opts.DestinationNode)
		cancel()
		if pollErr != nil {
			return fmt.Errorf("tier1: %w: volume %s on %s: %v", ErrTier1DetachReleaseTimedOut, volumeName, opts.DestinationNode, pollErr)
		}
		log.Info("destination attach reservation confirmed released", "volume", volumeName, "destNode", opts.DestinationNode)
	}

	return nil
}

// pollUntilDetached polls fetchVolume until no running controller (engine) remains on destNode,
// or ctx is done (a timeout/cancellation is returned as an error — fail closed, never assume
// release from an unconfirmed request). Reuses the same Controllers[].NodeID/Running signal
// pollUntilSingleOwner already trusts as the real, GET-only attachment-state primitive — not a
// new signal invented for this method.
func (m *LonghornMigrator) pollUntilDetached(ctx context.Context, volumeName, destNode string) error {
	for {
		vol, err := m.fetchVolume(ctx, volumeName)
		if err == nil {
			stillAttached := false
			for _, c := range vol.Controllers {
				if c.Running && c.NodeID == destNode {
					stillAttached = true
					break
				}
			}
			if !stillAttached {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for volume %s to actually release from %s: %w",
				volumeName, destNode, ctx.Err())
		case <-time.After(longhornPollInterval):
		}
	}
}

// ── Longhorn HTTP helpers ───────────────────────────────────────────────────

// longhornVolume is the subset of the Longhorn volume API response we care about.
type longhornVolume struct {
	Name       string             `json:"name"`
	State      string             `json:"state"`
	Robustness string             `json:"robustness"`
	Replicas   []longhornReplica  `json:"replicas"`
	// Controllers is Longhorn's engine list — during dual-engine live
	// migration this holds one entry per active engine (source + dest);
	// once the source engine is torn down (migration confirmed) it
	// collapses to exactly one entry. This is the real single-owner
	// signal AwaitSingleOwner polls for — see pollUntilSingleOwner.
	Controllers []longhornController `json:"controllers"`
}

type longhornController struct {
	Name string `json:"name"`
	// NodeID: Longhorn's real /v1/volumes/{name} response field for a
	// controller's node is "hostId" (same field name as on replicas —
	// see longhornReplica.NodeID for why the tag matters).
	NodeID  string `json:"hostId"`
	Running bool   `json:"running"`
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
	if destNode == "" {
		// ADR-0365 Decision §2 item 3: independent backstop guard — see PreStage's identical
		// guard and errEmptyDestinationNode's doc comment. PreStage already rejects an empty
		// opts.DestinationNode before ever reaching this call in the normal path; this catches
		// any future caller that reaches addDestReplica some other way.
		return errEmptyDestinationNode
	}
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
	// ReleaseDestinationCalled records whether ReleaseDestination was called.
	ReleaseDestinationCalled bool
	// InjectReleaseDestinationError, if non-nil, is returned verbatim by ReleaseDestination
	// instead of the default ErrRollbackNotImplemented — lets tests exercise the plain
	// operational-error return path distinct from the sentinel.
	InjectReleaseDestinationError error
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

// ReleaseDestination records the call and, when cutover actually happened for this migration
// (opts.CutoverComplete), returns a wrapped ErrRollbackNotImplemented — NEVER a bare nil
// (ADR-0368 CONDITION 1). This stub has no real Longhorn backend to talk to, so unlike the
// production LonghornMigrator (which performs and verifies a real detach) it cannot honestly
// claim to have confirmed a release; "not implemented" is the truthful answer for a fake that
// never touches any backend. If cutover never happened there is nothing to release, matching
// every other tier's "no cutover, no reservation" case — returns nil.
// InjectReleaseDestinationError overrides the default for tests that need a plain operational
// error instead of the sentinel.
func (s *LonghornStubMigrator) ReleaseDestination(_ context.Context, opts MigrationOptions) error {
	s.ReleaseDestinationCalled = true
	if s.InjectReleaseDestinationError != nil {
		return s.InjectReleaseDestinationError
	}
	if !opts.CutoverComplete {
		return nil
	}
	return fmt.Errorf("tier1 stub: %w", ErrRollbackNotImplemented)
}
