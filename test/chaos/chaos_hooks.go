//go:build chaos_test

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package chaos

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// ─── G8: Storage cutover timeout and quiescence hook failure ──────────────────
//
// Scenarios covered:
//   FS-003  FinalFreezeStateCapture — agent loss during freeze; rollback + unquiesce
//   FS-009  FinalFreezeStateCapture — network partition during freeze; rollback + unquiesce
//   FS-016  OverlayHandoff — RWX re-attach hangs (tc netem storage lag)
//   FS-017  OverlayHandoff — Longhorn dual-engine failure
//   FS-018  OverlayHandoff — Ceph RBD map failure
//   FS-019a OverlayHandoff — rollback triggered during active handoff (source node)
//   FS-019b CutoverComplete — rollback after cutover complete; verify PV claimRef flip

// RunFS003 exercises FS-003: agent loss during FinalFreezeStateCapture.
//
// The scenario:
//  1. Wait for the reconciler to reach the post-freeze sync point.
//  2. Simulate agent loss by patching the PodMigration with a synthetic
//     AgentLost=True condition before resuming.
//  3. Assert migration transitions to Failed/RollingBack.
//  4. If app-consistent quiescence was configured, assert the unquiesce hook
//     was called (ADR-0084 §5 + ADR-0097 §Group A).
func RunFS003(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName, unquiesceRecorder *UnquiesceCallRecorder) error {
	resume, err := WaitForSyncPoint(ctx, f, pmNN, "post-freeze")
	if err != nil {
		return fmt.Errorf("FS-003 WaitForSyncPoint: %w", err)
	}

	// Inject agent loss condition before allowing the reconciler to continue.
	if patchErr := PatchCRCondition(ctx, f, pmNN,
		"AgentLost", "SimulatedAgentLoss",
		"chaos: FS-003 agent loss injected during FinalFreezeStateCapture",
		metav1.ConditionTrue,
	); patchErr != nil {
		return fmt.Errorf("FS-003 inject agent loss: %w", patchErr)
	}
	resume()

	// Assert migration reaches a terminal failure state.
	if err := waitForTerminalFailure(ctx, f, pmNN); err != nil {
		return fmt.Errorf("FS-003 failure assertion: %w", err)
	}

	// Assert unquiesce hook is called when app-consistent mode is active.
	if unquiesceRecorder != nil {
		if err := AssertUnquiesceHookCalled(ctx, unquiesceRecorder); err != nil {
			return fmt.Errorf("FS-003 unquiesce assertion: %w", err)
		}
	}
	return nil
}

// RunFS009 exercises FS-009: network partition during FinalFreezeStateCapture.
//
// This is the CRITICAL scenario: the source pod is frozen but the network
// partition prevents checkpoint transfer. Rollback must immediately unfreeze
// the source pod (ADR-0097 §Group B).
func RunFS009(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName, sourceNode string, unquiesceRecorder *UnquiesceCallRecorder) error {
	resume, err := WaitForSyncPoint(ctx, f, pmNN, "post-freeze")
	if err != nil {
		return fmt.Errorf("FS-009 WaitForSyncPoint: %w", err)
	}

	// Inject full network partition on the source node.
	restoreNet, netErr := InjectNetworkPartition(ctx, f, sourceNode, "")
	if netErr != nil {
		resume() // unblock reconciler before returning
		return fmt.Errorf("FS-009 inject partition: %w", netErr)
	}
	defer restoreNet()

	resume()

	if err := waitForTerminalFailure(ctx, f, pmNN); err != nil {
		return fmt.Errorf("FS-009 failure assertion: %w", err)
	}

	if unquiesceRecorder != nil {
		if err := AssertUnquiesceHookCalled(ctx, unquiesceRecorder); err != nil {
			return fmt.Errorf("FS-009 unquiesce assertion: %w", err)
		}
	}
	return nil
}

// RunFS016 exercises FS-016: RWX re-attach hangs during OverlayHandoff.
//
// tc netem delay is applied to the source node's network interface to simulate
// RWX volume re-attach latency exceeding StorageCutoverTimeout.
func RunFS016(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName, sourceNode string, delayMs int) error {
	// Inject storage lag before the handoff sync point.
	restoreLag, lagErr := InjectStorageLag(ctx, f, sourceNode, delayMs)
	if lagErr != nil {
		return fmt.Errorf("FS-016 inject lag: %w", lagErr)
	}
	defer restoreLag()

	resume, err := WaitForSyncPoint(ctx, f, pmNN, "post-checkpoint-transfer")
	if err != nil {
		return fmt.Errorf("FS-016 WaitForSyncPoint: %w", err)
	}
	resume()

	return AssertPhaseReached(ctx, f, pmNN, pmv1.MigrationPhaseOverlayHandoff)
}

// RunFS017 exercises FS-017: Longhorn dual-engine failure during OverlayHandoff.
//
// The scenario simulates a dual-engine failure by injecting a StorageCutoverTimeout
// condition on the CR while the reconciler is in OverlayHandoff phase.
func RunFS017(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName) error {
	resume, err := WaitForSyncPoint(ctx, f, pmNN, "post-checkpoint-transfer")
	if err != nil {
		return fmt.Errorf("FS-017 WaitForSyncPoint: %w", err)
	}

	if patchErr := PatchCRCondition(ctx, f, pmNN,
		"StorageCutoverTimeout", "LonghornDualEngineFault",
		"chaos: FS-017 Longhorn dual-engine failure injected",
		metav1.ConditionTrue,
	); patchErr != nil {
		resume()
		return fmt.Errorf("FS-017 inject timeout: %w", patchErr)
	}
	resume()

	return waitForTerminalFailure(ctx, f, pmNN)
}

// RunFS018 exercises FS-018: Ceph RBD map failure during OverlayHandoff.
//
// Analogous to FS-017 but represents the Ceph RBD map error path.
func RunFS018(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName) error {
	resume, err := WaitForSyncPoint(ctx, f, pmNN, "post-checkpoint-transfer")
	if err != nil {
		return fmt.Errorf("FS-018 WaitForSyncPoint: %w", err)
	}

	if patchErr := PatchCRCondition(ctx, f, pmNN,
		"StorageCutoverTimeout", "CephRBDMapFault",
		"chaos: FS-018 Ceph RBD map failure injected",
		metav1.ConditionTrue,
	); patchErr != nil {
		resume()
		return fmt.Errorf("FS-018 inject timeout: %w", patchErr)
	}
	resume()

	return waitForTerminalFailure(ctx, f, pmNN)
}

// RunFS019a exercises FS-019a: rollback triggered during active OverlayHandoff
// (source node path).
//
// Recovery class: PanicSafe. The rollback fires before CutoverComplete so the
// storage pipeline has not fully committed on the destination. The cheaper
// abort path is taken. See ADR-0097 §Group D.
func RunFS019a(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName) error {
	resume, err := WaitForSyncPoint(ctx, f, pmNN, "post-checkpoint-transfer")
	if err != nil {
		return fmt.Errorf("FS-019a WaitForSyncPoint: %w", err)
	}

	// Inject a source-node-side failure before handoff commits.
	if patchErr := PatchCRCondition(ctx, f, pmNN,
		"SourceNodeFault", "SourceNodeLossDuringHandoff",
		"chaos: FS-019a source node failure during OverlayHandoff",
		metav1.ConditionTrue,
	); patchErr != nil {
		resume()
		return fmt.Errorf("FS-019a inject fault: %w", patchErr)
	}
	resume()

	// Expect rollback to succeed and reach terminal state.
	return waitForTerminalFailure(ctx, f, pmNN)
}

// RunFS019b exercises FS-019b: rollback after CutoverComplete (destination node
// path). This is the EXPENSIVE rollback: the storage pipeline has committed on
// the destination; StoragePipeline.Rollback() must re-flip PV.spec.claimRef
// back to source. See ADR-0097 §Group D and ADR-0014.
//
// pvName is the PersistentVolume name. sourceNS/sourcePVCName are the original
// claim coordinates. After rollback, AssertPVClaimRefFlippedToSource verifies
// the flip.
func RunFS019b(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName, pvName, sourceNS, sourcePVCName string) error {
	resume, err := WaitForSyncPoint(ctx, f, pmNN, "post-network-handoff")
	if err != nil {
		return fmt.Errorf("FS-019b WaitForSyncPoint: %w", err)
	}

	// Inject a destination-node failure after CutoverComplete.
	if patchErr := PatchCRCondition(ctx, f, pmNN,
		"DestinationNodeFault", "DestinationNodeLossPostCutover",
		"chaos: FS-019b destination node failure after CutoverComplete",
		metav1.ConditionTrue,
	); patchErr != nil {
		resume()
		return fmt.Errorf("FS-019b inject fault: %w", patchErr)
	}
	resume()

	if err := waitForTerminalFailure(ctx, f, pmNN); err != nil {
		return fmt.Errorf("FS-019b failure assertion: %w", err)
	}

	// Verify that the expensive StoragePipeline.Rollback() re-flipped claimRef.
	return AssertPVClaimRefFlippedToSource(ctx, f, pvName, sourceNS, sourcePVCName)
}

// ─── G10: Overlay/network fault injection ─────────────────────────────────────
//
// Scenarios:
//   FS-010 OverlayHandoff — transfer fails; source unfrozen after dump
//   FS-012 CutoverComplete — post-handoff partition; HumanRequired
//   Overlay fault during OverlayHandoff (generic tc netem on overlay iface)

// RunFS010 exercises FS-010: checkpoint transfer failure after OverlayHandoff
// due to network fault. The source pod must be unfrozen (SIGCONT issued by
// rollback) even though the dump completed. See ADR-0097 §Group B.
func RunFS010(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName, destNode, overlayIface string) error {
	// Wait for checkpoint transfer sync point.
	resume, err := WaitForSyncPoint(ctx, f, pmNN, "post-checkpoint-transfer")
	if err != nil {
		return fmt.Errorf("FS-010 WaitForSyncPoint: %w", err)
	}

	// Inject overlay fault (100% packet loss) on the destination node's overlay
	// interface to simulate transfer failure.
	restoreFault, faultErr := InjectOverlayFault(ctx, f, destNode, overlayIface, 100, 0)
	if faultErr != nil {
		resume()
		return fmt.Errorf("FS-010 inject overlay fault: %w", faultErr)
	}
	defer restoreFault()

	resume()

	// Expect migration to fail; source pod must be intact (unfrozen after rollback).
	if err := waitForTerminalFailure(ctx, f, pmNN); err != nil {
		return fmt.Errorf("FS-010 failure assertion: %w", err)
	}
	return AssertSourcePodIntact(ctx, f, pmNN)
}

// RunFS012 exercises FS-012: post-handoff network partition after CutoverComplete.
// The source pod has been deleted; this is a HumanRequired scenario because there
// is no safe automated recovery path. See ADR-0097 §Group B.
func RunFS012(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName, destNode string) error {
	resume, err := WaitForSyncPoint(ctx, f, pmNN, "post-network-handoff")
	if err != nil {
		return fmt.Errorf("FS-012 WaitForSyncPoint: %w", err)
	}

	// Inject full network partition on destination node.
	restoreNet, netErr := InjectNetworkPartition(ctx, f, destNode, "")
	if netErr != nil {
		resume()
		return fmt.Errorf("FS-012 inject partition: %w", netErr)
	}
	defer restoreNet()

	resume()

	// Expect HumanRequired condition to be set.
	return waitForHumanRequired(ctx, f, pmNN)
}

// RunOverlayFaultDuringHandoff exercises a generic overlay network fault scenario
// during OverlayHandoff using tc netem on the overlay interface. This covers the
// G10 requirement: overlay/network fault injection during the handoff phase.
//
// overlayIface is the overlay interface name on sourceNode (e.g. "flannel.1",
// "calico-vxlan", "cilium_vxlan"). lossPercent and delayMs are the tc netem
// parameters; typical values: lossPercent=50, delayMs=200.
func RunOverlayFaultDuringHandoff(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName, sourceNode, overlayIface string, lossPercent, delayMs int) error {
	resume, err := WaitForSyncPoint(ctx, f, pmNN, "post-freeze")
	if err != nil {
		return fmt.Errorf("RunOverlayFaultDuringHandoff WaitForSyncPoint: %w", err)
	}

	restoreFault, faultErr := InjectOverlayFault(ctx, f, sourceNode, overlayIface, lossPercent, delayMs)
	if faultErr != nil {
		resume()
		return fmt.Errorf("RunOverlayFaultDuringHandoff inject: %w", faultErr)
	}
	defer restoreFault()

	resume()

	// The migration should either succeed (if fault is transient and within
	// retry budget) or fail gracefully. Either outcome is valid; the invariant
	// checked is that no TCP RST events were emitted (North Star).
	_ = waitForAnyTerminal(ctx, f, pmNN)
	return AssertNorthStarInvariant(ctx, f)
}

// ─── internal helpers ──────────────────────────────────────────────────────────

const terminalPollInterval = 200 * time.Millisecond

// waitForTerminalFailure blocks until the PodMigration reaches Failed or
// RollingBack. Returns an error if ctx expires or the phase is unexpected.
func waitForTerminalFailure(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName) error {
	for {
		var pm pmv1.PodMigration
		if err := f.Client.Get(ctx, pmNN, &pm); err != nil {
			return fmt.Errorf("waitForTerminalFailure Get: %w", err)
		}
		switch pm.Status.Phase {
		case pmv1.MigrationPhaseFailed, pmv1.MigrationPhaseRollingBack:
			return nil
		case pmv1.MigrationPhaseComplete, pmv1.MigrationPhaseDryRunComplete:
			return fmt.Errorf("waitForTerminalFailure: migration completed successfully (unexpected for failure scenario); phase=%s", pm.Status.Phase)
		}
		select {
		case <-ctx.Done():
			var last pmv1.PodMigration
			_ = f.Client.Get(context.Background(), pmNN, &last)
			return fmt.Errorf("waitForTerminalFailure: timed out; last phase=%s", last.Status.Phase)
		case <-time.After(terminalPollInterval):
		}
	}
}

// waitForHumanRequired blocks until the PodMigration carries a HumanRequired
// condition (True), indicating an unrecoverable failure requiring manual intervention.
func waitForHumanRequired(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName) error {
	for {
		var pm pmv1.PodMigration
		if err := f.Client.Get(ctx, pmNN, &pm); err != nil {
			return fmt.Errorf("waitForHumanRequired Get: %w", err)
		}
		// HumanRequired may be set as a condition or reflected in phase=Failed with reason.
		if isHumanRequired(&pm) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waitForHumanRequired: timed out; phase=%s", pm.Status.Phase)
		case <-time.After(terminalPollInterval):
		}
	}
}

// isHumanRequired returns true when the PodMigration has a HumanRequired=True
// condition or a Failed condition with Reason containing "HumanRequired".
func isHumanRequired(pm *pmv1.PodMigration) bool {
	for _, c := range pm.Status.Conditions {
		if c.Type == "HumanRequired" && c.Status == metav1.ConditionTrue {
			return true
		}
		if c.Status == metav1.ConditionTrue && contains(c.Reason, "HumanRequired") {
			return true
		}
	}
	return false
}

// waitForAnyTerminal blocks until the migration reaches any terminal phase
// (Complete, Failed, RollingBack). It does not return an error — callers
// that need specific phases should use AssertPhaseReached instead.
func waitForAnyTerminal(ctx context.Context, f *FaultFixture, pmNN types.NamespacedName) error {
	for {
		var pm pmv1.PodMigration
		if err := f.Client.Get(ctx, pmNN, &pm); err != nil {
			return err
		}
		switch pm.Status.Phase {
		case pmv1.MigrationPhaseComplete, pmv1.MigrationPhaseFailed,
			pmv1.MigrationPhaseRollingBack, pmv1.MigrationPhaseDryRunComplete:
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(terminalPollInterval):
		}
	}
}
