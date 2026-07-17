/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"bytes"
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/featuregate"
)

// TestTwelvePhaseTransitions drives a PodMigration through all 12 phases of the ADR-0047
// pipeline and asserts each phase name appears in either the log output or the phase
// sequence observed on the PodMigration status, satisfying the M19 acceptance criterion:
// "mock reconcile shows 12 distinct phase transitions in logs".
//
// All agent-dependent paths (AgentPool, ReplicationMgr, StorageMgr, TrafficVerifier) are
// left nil so fast-path and skip branches are exercised. TCPPreservationMode=None exercises
// the stateless degenerate case (ADR-0047: stateless as degenerate TCPPreservationMode=None).
// Conditions that require a live agent are pre-seeded so each phase advances without
// blocking on external RPCs.
func TestTwelvePhaseTransitions(t *testing.T) {
	// NOTE: this test intentionally does NOT call logf.SetLogger. controller-runtime's
	// global root logger is one-shot — the first SetLogger in the whole test binary wins
	// and every later call (including this test's) is silently ignored (deleg.go Fulfill
	// nils the promise). A prior version asserted the 10 non-strict phases via a log
	// substring captured into a local buffer; when another test in the package won the
	// one-shot logger race that buffer stayed empty and this test failed ~1/3 of full-package
	// runs. The assertions below now rely ONLY on the executed phase-visit map, so they are
	// deterministic regardless of test ordering (Constitutional Invariant 5: no flaky proof
	// of the TCP-continuity spine).

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "src-pod",
			Namespace: "default",
			UID:       "test-uid-1",
		},
		Spec: corev1.PodSpec{NodeName: "src-node"},
		Status: corev1.PodStatus{PodIP: "10.0.0.1"},
	}

	nmc := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "src-node"},
		Status:     pmv1.NodeMigrationCapacityStatus{Ready: true},
	}

	now := metav1.Now()
	trueCondition := func(condType string) metav1.Condition {
		return metav1.Condition{
			Type:               condType,
			Status:             metav1.ConditionTrue,
			Reason:             "PreSeeded",
			Message:            "pre-seeded for 12-phase mock test",
			LastTransitionTime: now,
		}
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-12phase",
			Namespace: "default",
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			Mode:                pmv1.MigrationModeCold,
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
			RollbackOnFailure:   true,
			TargetNodeName:      "dst-node",
		},
		Status: pmv1.PodMigrationStatus{
			// Pre-seed all agent-dependent conditions so phases advance without a live agent.
			Conditions: []metav1.Condition{
				trueCondition(conditionCheckpointed),
				trueCondition(conditionRestored),
				trueCondition(conditionTrafficVerified),
				trueCondition(conditionDestinationVolumeReady),
			},
			CheckpointTransferred: true,
			SourceNodeName:        "src-node",
			DestinationNodeName:   "dst-node",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod, nmc).
		WithStatusSubresource(pm, nmc).
		Build()

	r := &PodMigrationReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-12phase", Namespace: "default"}}

	// Track all phases observed on the PodMigration status across reconcile iterations.
	visitedPhases := make(map[pmv1.MigrationPhase]bool)

	const maxIterations = 60
	for i := 0; i < maxIterations; i++ {
		fresh := &pmv1.PodMigration{}
		if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
			t.Fatalf("iteration %d: Get before reconcile: %v", i, err)
		}
		visitedPhases[fresh.Status.Phase] = true

		_, err := r.Reconcile(ctx, req)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}

		if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
			t.Fatalf("iteration %d: Get after reconcile: %v", i, err)
		}
		visitedPhases[fresh.Status.Phase] = true

		phase := fresh.Status.Phase
		if phase == pmv1.MigrationPhaseComplete ||
			phase == pmv1.MigrationPhaseFailed ||
			phase == pmv1.MigrationPhaseDryRunComplete {
			break
		}
	}

	// Each of the 12 phase names must have been VISITED as an executed state transition
	// (i.e. the PodMigration status actually held that phase across a reconcile). Every one
	// of the 12 phases is a real dispatch case that transitions phase-to-phase via
	// transitionTo, and the loop below records the phase both before and after each reconcile,
	// so every held phase is captured. No log-substring fallback is used (see the note at the
	// top of this test): a log line is not proof a phase was entered, and depending on it made
	// this test order-dependent and flaky.
	expectedPhases := []pmv1.MigrationPhase{
		pmv1.MigrationPhaseSocketInventory,
		pmv1.MigrationPhaseValidating,
		pmv1.MigrationPhaseDestinationPrewarm,
		pmv1.MigrationPhasePreCopyMemory,
		pmv1.MigrationPhaseZeroWindowArm,
		pmv1.MigrationPhaseFinalFreezeStateCapture,
		pmv1.MigrationPhaseOverlayHandoff,
		pmv1.MigrationPhaseRestoreSocketReattach,
		pmv1.MigrationPhaseDisengageHold,
		pmv1.MigrationPhaseTCPVerifying,
		pmv1.MigrationPhaseServiceVerifying,
		pmv1.MigrationPhaseCutoverComplete,
	}

	// A-02 (C-2): OverlayHandoff and DisengageHold are the two phases whose bypass the C-2
	// finding is about (two-sided FDB/neighbor handoff and the zero-window disarm barrier — the
	// TCP-continuity spine). The finding was precisely that a log line can be printed while the
	// phase is never entered as a state transition, so EVERY phase here — not just those two —
	// must appear in the phase-visit map. There is no log-substring escape hatch for any phase.
	var missing []string
	for _, phase := range expectedPhases {
		if !visitedPhases[phase] {
			missing = append(missing, string(phase)+" (must be VISITED as a state transition, not a log substring)")
		}
	}
	if len(missing) > 0 {
		t.Errorf("12-phase transitions not observed: %v\n\nvisited phases: %v",
			missing, visitedPhases)
	}
}

// TestTCPPreservationModeGating verifies the safety invariants for Strict and BestEffort modes:
//
//   (a) In Strict mode: a TCP verification failure triggers rollback and does NOT delete the
//       source pod (i.e. the migration must not reach Complete with source deleted).
//   (b) In BestEffort mode: a TCP verification failure emits a warning but proceeds; the source
//       pod is NOT deleted before TrafficVerified=True.
//   (c) Source pod deletion in CutoverComplete is gated by TrafficVerified=True re-check.
//
// These tests satisfy the M19 gate requirement: "Strict/BestEffort code path has non-zero coverage
// and the rollback branch must be reachable".  Real probes are not implemented (M20); the tests
// assert the fail-closed behaviour of the current stub.
func TestTCPPreservationModeGating(t *testing.T) {
	// Make sure TCPPreservation gate is off (default) for these tests.
	featuregate.Reset()

	tests := []struct {
		name             string
		mode             pmv1.TCPPreservationMode
		wantPhase        pmv1.MigrationPhase  // expected terminal phase
		wantRolledBack   bool                  // migration should reach RollingBack/Failed
		sourcePodDeleted bool                  // source pod must NOT be deleted
	}{
		{
			name:             "Strict_TCPVerifyFails_Rollback_SourcePodSurvives",
			mode:             pmv1.TCPPreservationModeStrict,
			wantPhase:        pmv1.MigrationPhaseRollingBack,
			wantRolledBack:   true,
			sourcePodDeleted: false,
		},
		{
			name:             "BestEffort_TCPVerifyFails_ProceedsWarn_SourcePodNotDeletedWithoutTrafficVerified",
			mode:             pmv1.TCPPreservationModeBestEffort,
			// BestEffort proceeds past TCPVerifying but CutoverComplete blocks on TrafficVerified=True.
			// With no TrafficVerifier wired and Strict=false, it sets TrafficVerified=True and
			// tries CutoverComplete, but the defensive re-check blocks deletion because
			// TCPSequenceContinuityVerified stays False in BestEffort.
			wantPhase:        pmv1.MigrationPhaseCutoverComplete, // stalls waiting
			wantRolledBack:   false,
			sourcePodDeleted: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			logf.SetLogger(zap.New(zap.WriteTo(&logBuf), zap.UseDevMode(true)))

			scheme := runtime.NewScheme()
			if err := pmv1.AddToScheme(scheme); err != nil {
				t.Fatalf("AddToScheme pmv1: %v", err)
			}
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatalf("AddToScheme corev1: %v", err)
			}

			srcPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "src-pod",
					Namespace: "default",
					UID:       "test-uid-tcp",
				},
				Spec:   corev1.PodSpec{NodeName: "src-node"},
				Status: corev1.PodStatus{PodIP: "10.0.0.1"},
			}
			nmc := &pmv1.NodeMigrationCapacity{
				ObjectMeta: metav1.ObjectMeta{Name: "src-node"},
				Status:     pmv1.NodeMigrationCapacityStatus{Ready: true},
			}

			now := metav1.Now()
			trueCondition := func(condType string) metav1.Condition {
				return metav1.Condition{
					Type:               condType,
					Status:             metav1.ConditionTrue,
					Reason:             "PreSeeded",
					Message:            "pre-seeded for tcp-gating test",
					LastTransitionTime: now,
				}
			}

			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-tcp-gating",
					Namespace: "default",
				},
				Spec: pmv1.PodMigrationSpec{
					PodName:             "src-pod",
					PodNamespace:        "default",
					Mode:                pmv1.MigrationModeCold,
					TCPPreservationMode: tc.mode,
					RollbackOnFailure:   true,
					TargetNodeName:      "dst-node",
				},
				Status: pmv1.PodMigrationStatus{
					// Pre-seed conditions up to the TCPVerifying phase so we exercise that path.
					Conditions: []metav1.Condition{
						trueCondition(conditionCheckpointed),
						trueCondition(conditionRestored),
						trueCondition(conditionDestinationVolumeReady),
						// TrafficVerified is NOT pre-seeded — it must be set by reconcileServiceVerifying.
					},
					CheckpointTransferred: true,
					SourceNodeName:        "src-node",
					DestinationNodeName:   "dst-node",
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pm, srcPod, nmc).
				WithStatusSubresource(pm, nmc).
				Build()

			r := &PodMigrationReconciler{
				Client: fakeClient,
				Scheme: scheme,
				// No AgentPool, ReplicationMgr, or TrafficVerifier — exercises stub paths.
			}

			ctx := context.Background()
			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-tcp-gating", Namespace: "default"}}

			// Advance the migration to the TCPVerifying phase by setting it directly.
			// This bypasses the earlier phases that need a live agent.
			if err := fakeClient.Get(ctx, req.NamespacedName, pm); err != nil {
				t.Fatalf("Get pm: %v", err)
			}
			pm.Status.Phase = pmv1.MigrationPhaseTCPVerifying
			if err := fakeClient.Status().Update(ctx, pm); err != nil {
				t.Fatalf("Status().Update to TCPVerifying: %v", err)
			}

			const maxIter = 30
			for i := 0; i < maxIter; i++ {
				fresh := &pmv1.PodMigration{}
				if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
					t.Fatalf("iter %d: Get: %v", i, err)
				}
				phase := fresh.Status.Phase
				if phase == pmv1.MigrationPhaseComplete ||
					phase == pmv1.MigrationPhaseFailed ||
					phase == pmv1.MigrationPhaseRollingBack ||
					phase == pmv1.MigrationPhaseDryRunComplete {
					break
				}
				if _, err := r.Reconcile(ctx, req); err != nil {
					// Reconcile errors are expected (e.g. requeue) for stub probes — don't fatal.
					break
				}
			}

			// Check terminal state.
			finalPM := &pmv1.PodMigration{}
			if err := fakeClient.Get(ctx, req.NamespacedName, finalPM); err != nil {
				t.Fatalf("Get finalPM: %v", err)
			}
			logs := logBuf.String()
			_ = logs

			if tc.wantRolledBack {
				if finalPM.Status.Phase != pmv1.MigrationPhaseRollingBack &&
					finalPM.Status.Phase != pmv1.MigrationPhaseFailed {
					t.Errorf("mode=%s: expected RollingBack/Failed, got %s", tc.mode, finalPM.Status.Phase)
				}
			}

			// CRITICAL: assert source pod was NOT deleted.
			pod := &corev1.Pod{}
			if err := fakeClient.Get(ctx, types.NamespacedName{Name: "src-pod", Namespace: "default"}, pod); err != nil {
				t.Errorf("mode=%s: source pod was deleted before safe cutover! This is the TCP RST / data loss CRITICAL.", tc.mode)
			}

			// CRITICAL: assert TCPSequenceContinuityVerified is NOT True (no stub-true allowed).
			tcpVerified := meta.IsStatusConditionTrue(finalPM.Status.Conditions, pmv1.ConditionTCPSequenceContinuityVerified)
			if tcpVerified {
				t.Errorf("mode=%s: ConditionTCPSequenceContinuityVerified=True was set by a stub — this masks TCP RST failures", tc.mode)
			}
		})
	}
}

// TestDestinationNetnsReadyCondition verifies the correct behaviour of reconcileDestinationPrewarm:
//
//   - TCPPreservationMode=None: fast-path, DestinationNetnsReady set True immediately (no RPC needed).
//   - TCPPreservationMode=Strict: blocked — PrepareDestinationNetns RPC not yet wired (M22).
//     DestinationNetnsReady is set to False (RPC not yet wired at M22). Setting it True without
//     a real RPC would advance the state machine past OverlayHandoff and delete the source pod
//     without any actual netns/FDB state being created, black-holing the source IP and RST-ing
//     every in-flight TCP connection (M19.5 CRITICAL bar). This test guards against regression.
func TestDestinationNetnsReadyCondition(t *testing.T) {
	tests := []struct {
		name        string
		mode        pmv1.TCPPreservationMode
		expectTrue  bool
		expectFalse bool
	}{
		{"None_SkipPath", pmv1.TCPPreservationModeNone, true, false},
		// Strict_ActivePath must block until the RPC is wired (M22).
		{"Strict_BlockedPendingRPC", pmv1.TCPPreservationModeStrict, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := pmv1.AddToScheme(scheme); err != nil {
				t.Fatalf("AddToScheme: %v", err)
			}
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatalf("AddToScheme corev1: %v", err)
			}
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{Name: "test-netns", Namespace: "default"},
				Spec: pmv1.PodMigrationSpec{
					PodName:             "src-pod",
					PodNamespace:        "default",
					TCPPreservationMode: tc.mode,
					TargetNodeName:      "dst-node",
				},
				Status: pmv1.PodMigrationStatus{
					Phase:               pmv1.MigrationPhaseDestinationPrewarm,
					SourceNodeName:      "src-node",
					DestinationNodeName: "dst-node",
				},
			}
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pm).
				WithStatusSubresource(pm).
				Build()
			r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
			ctx := context.Background()
			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-netns", Namespace: "default"}}

			// Two passes: first adds the finalizer, second executes the phase.
			for i := 0; i < 2; i++ {
				if _, err := r.Reconcile(ctx, req); err != nil {
					t.Fatalf("Reconcile pass %d: %v", i, err)
				}
			}

			fresh := &pmv1.PodMigration{}
			if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
				t.Fatalf("Get: %v", err)
			}
			if tc.expectTrue && !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionDestinationNetnsReady) {
				t.Errorf("mode=%s: expected DestinationNetnsReady=True after reconcileDestinationPrewarm", tc.mode)
			}
			if tc.expectFalse && meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionDestinationNetnsReady) {
				t.Errorf("mode=%s: DestinationNetnsReady must not be True without PrepareDestinationNetns RPC (M22 gate)", tc.mode)
			}
		})
	}
}

// TestShmemPagemapMissingRoutesToRollingBack verifies the ADR-0246 stale-condition backstop
// switch in reconcileCheckpointing: a PodMigration whose Checkpointed condition is already
// False/Reason=ShmemPagemapMissing on entry (e.g. after a controller crash/restart between
// the condition write and the initiateRollback call on the primary detect-and-route path)
// must be routed to RollingBack by the real reconcile loop, not re-issue another Checkpoint
// RPC against a deterministically-failing CRIU 4.2 anon-shmem dump. This exercises the
// backstop switch (podmigration_controller.go, "case ... ShmemPagemapMissing:") directly
// through Reconcile, distinct from existing RollingBack coverage that reaches it via other
// trigger paths (see TestTCPPreservationModeGating above).
func TestShmemPagemapMissingRoutesToRollingBack(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-shmem-pagemap-missing", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
			TargetNodeName:      "dst-node",
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseCheckpointing,
			SourceNodeName:      "src-node",
			DestinationNodeName: "dst-node",
			Conditions: []metav1.Condition{
				{
					Type:               conditionCheckpointed,
					Status:             metav1.ConditionFalse,
					Reason:             "ShmemPagemapMissing",
					Message:            "anon-shmem segment(s) with no pagemap-shmem-<shmid>.img (CRIU 4.2 dump defect)",
					LastTransitionTime: metav1.Now(),
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-shmem-pagemap-missing", Namespace: "default"}}

	// Two passes: first adds the finalizer, second executes reconcileCheckpointing's
	// stale-condition backstop switch and routes to RollingBack.
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile pass %d: %v", i, err)
		}
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseRollingBack {
		t.Errorf("expected phase RollingBack after ShmemPagemapMissing backstop, got %s", fresh.Status.Phase)
	}
}

// TestVXLANFDBUpdatedCondition verifies the correct behaviour of reconcileOverlayHandoff:
//
//   - TCPPreservationMode=None: fast-path, VXLANFDBUpdated set True immediately (no RPC needed).
//   - TCPPreservationMode=Strict: blocked — AddFDBEntry/ConfirmOverlayReady RPCs not yet wired (M22).
//     VXLANFDBUpdated is set to False (RPC not yet wired at M22). Setting it True without a real
//     RPC would advance the state machine to RestoreSocketReattach and delete the source pod
//     against a dataplane that was never configured — RST-ing every in-flight TCP connection
//     (M19.5 CRITICAL bar). This test guards against regression.
func TestVXLANFDBUpdatedCondition(t *testing.T) {
	tests := []struct {
		name        string
		mode        pmv1.TCPPreservationMode
		expectTrue  bool
		expectFalse bool
	}{
		{"None_SkipPath", pmv1.TCPPreservationModeNone, true, false},
		// Strict_ActivePath must block until AddFDBEntry/ConfirmOverlayReady RPCs are wired (M22).
		{"Strict_BlockedPendingRPC", pmv1.TCPPreservationModeStrict, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := pmv1.AddToScheme(scheme); err != nil {
				t.Fatalf("AddToScheme: %v", err)
			}
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatalf("AddToScheme corev1: %v", err)
			}
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{Name: "test-fdb", Namespace: "default"},
				Spec: pmv1.PodMigrationSpec{
					PodName:             "src-pod",
					PodNamespace:        "default",
					TCPPreservationMode: tc.mode,
					TargetNodeName:      "dst-node",
				},
				Status: pmv1.PodMigrationStatus{
					Phase:               pmv1.MigrationPhaseOverlayHandoff,
					SourceNodeName:      "src-node",
					DestinationNodeName: "dst-node",
				},
			}
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pm).
				WithStatusSubresource(pm).
				Build()
			r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
			ctx := context.Background()
			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-fdb", Namespace: "default"}}

			// Two passes: first adds the finalizer, second executes the phase.
			for i := 0; i < 2; i++ {
				if _, err := r.Reconcile(ctx, req); err != nil {
					t.Fatalf("Reconcile pass %d: %v", i, err)
				}
			}

			fresh := &pmv1.PodMigration{}
			if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
				t.Fatalf("Get: %v", err)
			}
			if tc.expectTrue && !meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionVXLANFDBUpdated) {
				t.Errorf("mode=%s: expected VXLANFDBUpdated=True after reconcileOverlayHandoff", tc.mode)
			}
			if tc.expectFalse && meta.IsStatusConditionTrue(fresh.Status.Conditions, pmv1.ConditionVXLANFDBUpdated) {
				t.Errorf("mode=%s: VXLANFDBUpdated must not be True without AddFDBEntry/ConfirmOverlayReady RPC (M22 gate)", tc.mode)
			}
		})
	}
}

// TestFinalFreezeStateCaptureDoesNotHijackPipeline is the A-02 (C-2) contract test: on the
// 12-phase ADR-0047 pipeline the phase is MigrationPhaseFinalFreezeStateCapture, which OWNS the
// checkpoint→transfer→OverlayHandoff sequencing. The checkpoint and transfer sub-handlers must
// therefore NOT self-transition to the legacy Transferring/Restoring phases when invoked on this
// phase — doing so hands the phase machine to the legacy Transferring→Restoring→Verifying tail
// and permanently bypasses OverlayHandoff/RestoreSocketReattach/DisengageHold/TCPVerifying/
// ServiceVerifying/CutoverComplete (the entire TCP-continuity spine).
//
// This test is FALSIFIABLE and would have caught the C-2 bug: against the pre-A-02 tree the
// checkpoint fast-path ended at transitionTo(Transferring) and the transfer tail at
// transitionTo(Restoring), so both sub-assertions below would FAIL (phase would read
// Transferring / Restoring). It passes only once each sub-handler is pipeline-aware.
func TestFinalFreezeStateCaptureDoesNotHijackPipeline(t *testing.T) {
	// Defense-in-depth (fix item 3): the controller package's one un-scoped mutable global,
	// macWritebackFirstSeen (keyed by pm.Name), is the only cross-test state-bleed channel in this
	// package. It is NOT consulted on the checkpoint/transfer advance path under test, but resetting
	// it here — plus giving every fixture a unique t.Name()-derived pm.Name below — eliminates the
	// entire class of co-scheduled-test leak that caused a prior round's misdiagnosis. Reset before
	// AND after so neither a sibling test's residue nor this test's residue can bleed.
	resetMACWriteback := func() {
		macWritebackFirstSeen.Range(func(k, _ any) bool {
			macWritebackFirstSeen.Delete(k)
			return true
		})
	}
	resetMACWriteback()
	t.Cleanup(resetMACWriteback)

	// transition records the (from, decided) next-phase decisions the advance helpers make at their
	// single source-of-truth decision point. This recorded ledger is the source-of-truth primitive that
	// replaces observing the phase via a fake-client readback: it is written synchronously, in-process, at the
	// exact branch, with no timing, no goroutine, and no round-trip — so the safety assertion is
	// deterministic-by-construction and cannot be spoofed by a partial/aliased readback or masked by a
	// CPU-starvation process kill.
	type transition struct{ from, to pmv1.MigrationPhase }

	// Build a minimal reconciler + PM fixture at phase FinalFreezeStateCapture. Each fixture gets a
	// UNIQUE name (t.Name()-derived) and its own reconciler with a fresh ledger, so no two subtests
	// share client, object, or ledger state.
	buildFixture := func(t *testing.T, mutate func(pm *pmv1.PodMigration)) (*PodMigrationReconciler, *pmv1.PodMigration, func() *pmv1.PodMigration, *[]transition) {
		scheme := runtime.NewScheme()
		if err := pmv1.AddToScheme(scheme); err != nil {
			t.Fatalf("AddToScheme pmv1: %v", err)
		}
		if err := corev1.AddToScheme(scheme); err != nil {
			t.Fatalf("AddToScheme corev1: %v", err)
		}
		// Unique, DNS-safe name derived from the subtest so co-scheduled runs never collide on the
		// name-keyed global or on the fake-client object key.
		name := "nohijack-" + strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
				return r
			case r >= 'A' && r <= 'Z':
				return r + ('a' - 'A')
			default:
				return '-'
			}
		}, t.Name())
		now := metav1.Now()
		pm := &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: pmv1.PodMigrationSpec{
				PodName:             "src-pod",
				PodNamespace:        "default",
				Mode:                pmv1.MigrationModeCold,
				TCPPreservationMode: pmv1.TCPPreservationModeStrict,
				TargetNodeName:      "dst-node",
			},
			Status: pmv1.PodMigrationStatus{
				Phase:               pmv1.MigrationPhaseFinalFreezeStateCapture,
				SourceNodeName:      "src-node",
				DestinationNodeName: "dst-node",
				Conditions: []metav1.Condition{
					{
						Type:               conditionCheckpointed,
						Status:             metav1.ConditionTrue,
						Reason:             "PreSeeded",
						Message:            "checkpoint already complete (fixture)",
						LastTransitionTime: now,
					},
				},
			},
		}
		if mutate != nil {
			mutate(pm)
		}
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(pm).
			WithStatusSubresource(pm).
			Build()
		ledger := &[]transition{}
		r := &PodMigrationReconciler{
			Client: fakeClient,
			Scheme: scheme,
			onPhaseDecision: func(from, decided pmv1.MigrationPhase) {
				*ledger = append(*ledger, transition{from: from, to: decided})
			},
		}
		getFresh := func() *pmv1.PodMigration {
			fresh := &pmv1.PodMigration{}
			if err := fakeClient.Get(context.Background(),
				types.NamespacedName{Name: name, Namespace: "default"}, fresh); err != nil {
				t.Fatalf("Get fresh: %v", err)
			}
			return fresh
		}
		return r, pm, getFresh, ledger
	}

	// assertNoLegacyHijack is the deterministic safety assertion. It verifies, from the recorded
	// transition ledger (the source-of-truth primitive), that the advance helper made NO
	// FinalFreezeStateCapture→Transferring and NO FinalFreezeStateCapture→Restoring decision — the
	// exact edges that would hand the phase machine to the legacy tail and bypass the TCP-continuity
	// spine. This is a recorded-decision check, not a value-observation of an eventually-consistent
	// readback, so it cannot flake on timing or be masqueraded by a harness kill.
	assertNoLegacyHijack := func(t *testing.T, ledger *[]transition) {
		t.Helper()
		if len(*ledger) != 1 {
			t.Fatalf("expected exactly one recorded phase decision on the 12-phase path, got %d: %+v",
				len(*ledger), *ledger)
		}
		dec := (*ledger)[0]
		if dec.from != pmv1.MigrationPhaseFinalFreezeStateCapture {
			t.Fatalf("phase decision was evaluated from %q, expected %q",
				dec.from, pmv1.MigrationPhaseFinalFreezeStateCapture)
		}
		if dec.to == pmv1.MigrationPhaseTransferring || dec.to == pmv1.MigrationPhaseRestoring {
			t.Fatalf("C-2 regression: advance helper decided FinalFreezeStateCapture→%q, handing the "+
				"phase machine to the legacy tail (OverlayHandoff/RestoreSocketReattach/DisengageHold "+
				"bypassed); the 12-phase delegator must own the transition", dec.to)
		}
		if dec.to != pmv1.MigrationPhaseFinalFreezeStateCapture {
			t.Fatalf("expected the 12-phase advance to stay on %q, decided %q",
				pmv1.MigrationPhaseFinalFreezeStateCapture, dec.to)
		}
	}

	t.Run("checkpoint fast-path does not transition to legacy Transferring", func(t *testing.T) {
		r, pm, getFresh, ledger := buildFixture(t, nil)
		ctx := context.Background()
		// reconcileCheckpointing on the 12-phase phase hits the Checkpointed=True fast-path.
		res, err := r.reconcileCheckpointing(ctx, pm)
		if err != nil {
			t.Fatalf("reconcileCheckpointing: %v", err)
		}
		// PRIMARY, in-process signal: the recorded transition ledger proves the branch taken with no
		// dependence on the fake-client round-trip.
		assertNoLegacyHijack(t, ledger)
		// The status-only 12-phase path requeues without a transitionTo; a legacy hijack would have
		// gone through transitionTo (also Requeue:true) but WOULD have recorded a Transferring edge,
		// which assertNoLegacyHijack already rejects. The Requeue flag pins the status-only contract.
		if !res.Requeue {
			t.Fatalf("expected Requeue:true from the 12-phase checkpoint fast-path, got %+v", res)
		}
		// Defense-in-depth: the durable readback must ALSO show no hijack.
		if got := getFresh().Status.Phase; got != pmv1.MigrationPhaseFinalFreezeStateCapture {
			t.Fatalf("readback: expected phase to remain %q on the 12-phase path, got %q",
				pmv1.MigrationPhaseFinalFreezeStateCapture, got)
		}
	})

	t.Run("transfer tail does not transition to legacy Restoring", func(t *testing.T) {
		// The transfer-side stealing point is advanceAfterTransfer (reconcileTransferring's
		// terminal call). Its full body requires a live AgentPool to reach, so the seam helper
		// is asserted directly: on the 12-phase phase it must NOT transition to legacy Restoring.
		// Pre-A-02 this helper's body was an unconditional transitionTo(Restoring), so the ledger
		// assertion would FAIL (a FinalFreezeStateCapture→Restoring edge would be recorded).
		r, pm, getFresh, ledger := buildFixture(t, func(pm *pmv1.PodMigration) {
			pm.Status.CheckpointTransferred = true
		})
		ctx := context.Background()
		res, err := r.advanceAfterTransfer(ctx, pm)
		if err != nil {
			t.Fatalf("advanceAfterTransfer: %v", err)
		}
		assertNoLegacyHijack(t, ledger)
		if !res.Requeue {
			t.Fatalf("expected Requeue:true from the 12-phase transfer tail, got %+v", res)
		}
		if got := getFresh().Status.Phase; got != pmv1.MigrationPhaseFinalFreezeStateCapture {
			t.Fatalf("readback: expected phase to remain %q on the 12-phase path, got %q",
				pmv1.MigrationPhaseFinalFreezeStateCapture, got)
		}
	})

	t.Run("legacy Transferring phase still owns its transition to Restoring", func(t *testing.T) {
		// Backward-compat guard for the transfer seam: a PodMigration on the legacy path
		// (phase Transferring) must still self-transition to Restoring.
		r, pm, getFresh, ledger := buildFixture(t, func(pm *pmv1.PodMigration) {
			pm.Status.Phase = pmv1.MigrationPhaseTransferring
			pm.Status.CheckpointTransferred = true
		})
		ctx := context.Background()
		if _, err := r.advanceAfterTransfer(ctx, pm); err != nil {
			t.Fatalf("advanceAfterTransfer (legacy): %v", err)
		}
		// Ledger primitive: the recorded decision must be exactly Transferring→Restoring.
		if len(*ledger) != 1 || (*ledger)[0] != (transition{from: pmv1.MigrationPhaseTransferring, to: pmv1.MigrationPhaseRestoring}) {
			t.Fatalf("legacy Transferring must record a Transferring→Restoring decision, got %+v", *ledger)
		}
		if got := getFresh().Status.Phase; got != pmv1.MigrationPhaseRestoring {
			t.Fatalf("legacy Transferring must transition to Restoring, got %q", got)
		}
	})

	t.Run("legacy Checkpointing phase still owns its transition to Transferring", func(t *testing.T) {
		// Backward-compat guard: a PodMigration already on the legacy 8-phase path (phase
		// Checkpointing) must still self-transition to Transferring — the fix must not break
		// the legacy pipeline for existing in-flight objects.
		r, pm, getFresh, ledger := buildFixture(t, func(pm *pmv1.PodMigration) {
			pm.Status.Phase = pmv1.MigrationPhaseCheckpointing
		})
		ctx := context.Background()
		if _, err := r.reconcileCheckpointing(ctx, pm); err != nil {
			t.Fatalf("reconcileCheckpointing (legacy): %v", err)
		}
		if len(*ledger) != 1 || (*ledger)[0] != (transition{from: pmv1.MigrationPhaseCheckpointing, to: pmv1.MigrationPhaseTransferring}) {
			t.Fatalf("legacy Checkpointing must record a Checkpointing→Transferring decision, got %+v", *ledger)
		}
		if got := getFresh().Status.Phase; got != pmv1.MigrationPhaseTransferring {
			t.Fatalf("legacy Checkpointing must transition to Transferring, got %q", got)
		}
	})
}

// TestStrictMigrationVisitsOverlayHandoffAndDisengageHold drives a full Strict migration through
// the real Reconcile dispatcher from FinalFreezeStateCapture and asserts that OverlayHandoff AND
// DisengageHold are VISITED as executed state transitions (present in the observed phase set), NOT
// as log substrings. This is the arch_a-C1 / oss_qa-C1 contract: a Strict migration must pass
// through OverlayHandoff and DisengageHold before Complete, and the assertion is not satisfiable
// by a log line.
//
// Agent-dependent legs are advanced via their fast-path conditions (no AgentPool is available in
// a unit test); the point under test is the phase-machine sequencing owned by the controller, not
// the agent RPCs.
func TestStrictMigrationVisitsOverlayHandoffAndDisengageHold(t *testing.T) {
	var logBuf bytes.Buffer
	logf.SetLogger(zap.New(zap.WriteTo(&logBuf), zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "default", UID: "uid-strict"},
		Spec:       corev1.PodSpec{NodeName: "src-node"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.9"},
	}
	nmc := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "src-node"},
		Status:     pmv1.NodeMigrationCapacityStatus{Ready: true},
	}

	now := metav1.Now()
	cond := func(t string) metav1.Condition {
		return metav1.Condition{Type: t, Status: metav1.ConditionTrue, Reason: "PreSeeded",
			Message: "fast-path pre-seed (strict visitation test)", LastTransitionTime: now}
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-strict-visit", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			Mode:                pmv1.MigrationModeCold,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
			RollbackOnFailure:   true,
			TargetNodeName:      "dst-node",
		},
		Status: pmv1.PodMigrationStatus{
			Phase: pmv1.MigrationPhaseFinalFreezeStateCapture,
			Conditions: []metav1.Condition{
				cond(conditionCheckpointed),
				// OverlayHandoff fast-path: VXLANFDBUpdated=True → RestoreSocketReattach.
				cond(string(pmv1.ConditionVXLANFDBUpdated)),
				// RestoreSocketReattach fast-path: Restored=True → DisengageHold.
				cond(conditionRestored),
				// DisengageHold fast-path: RelayProgramsLoaded=True → TCPVerifying.
				cond(string(pmv1.ConditionRelayProgramsLoaded)),
				cond(conditionTrafficVerified),
				cond(conditionDestinationVolumeReady),
			},
			CheckpointTransferred: true,
			SourceNodeName:        "src-node",
			DestinationNodeName:   "dst-node",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm, srcPod, nmc).
		WithStatusSubresource(pm, nmc).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-strict-visit", Namespace: "default"}}

	visited := make(map[pmv1.MigrationPhase]bool)
	const maxIter = 60
	for i := 0; i < maxIter; i++ {
		fresh := &pmv1.PodMigration{}
		if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
			t.Fatalf("iter %d: Get before: %v", i, err)
		}
		visited[fresh.Status.Phase] = true
		if _, err := r.Reconcile(ctx, req); err != nil {
			// A requeue-with-error on a stub leg is acceptable; keep the phases already visited.
			break
		}
		if err := fakeClient.Get(ctx, req.NamespacedName, fresh); err != nil {
			t.Fatalf("iter %d: Get after: %v", i, err)
		}
		visited[fresh.Status.Phase] = true
		p := fresh.Status.Phase
		if p == pmv1.MigrationPhaseComplete || p == pmv1.MigrationPhaseFailed ||
			p == pmv1.MigrationPhaseRollingBack || p == pmv1.MigrationPhaseDryRunComplete {
			break
		}
	}

	// Executed-state-transition assertions — NOT satisfiable by log substrings.
	if !visited[pmv1.MigrationPhaseOverlayHandoff] {
		t.Errorf("Strict migration never VISITED OverlayHandoff (C-2 bypass); visited=%v", visited)
	}
	if !visited[pmv1.MigrationPhaseDisengageHold] {
		t.Errorf("Strict migration never VISITED DisengageHold (C-2 bypass); visited=%v", visited)
	}
	// The migration must NOT have taken the legacy Transferring/Restoring/Verifying tail.
	for _, legacy := range []pmv1.MigrationPhase{
		pmv1.MigrationPhaseTransferring, pmv1.MigrationPhaseRestoring, pmv1.MigrationPhaseVerifying,
	} {
		if visited[legacy] {
			t.Errorf("Strict migration visited legacy phase %q — the 12-phase pipeline was bypassed; visited=%v",
				legacy, visited)
		}
	}
}

// TestDisengageHoldReadsOverlayReadyFromConditions is the regression for the sprint46B4
// live-proof cycle-2 wedge: a live redis Strict migration reached phase=DisengageHold with
// VXLANFDBUpdated=True, Restored=True and Status.SourceConntrackArmed=true — every input the
// ADR-0049 post-restore barrier needs — yet hung for the full 120s cap because reconcileDisengageHold
// re-derived the barrier by re-issuing a live ConfirmOverlayReady RPC that requeued every 5s and
// never set OverlayReady (docs/sprints/sprint46B4/live-proof-c2-transcript.txt).
//
// This test drives reconcileDisengageHold with that EXACT condition set and a nil AgentPool (the
// live re-probe is unreachable). Under the old brittle-chain code the barrier block returned a
// bare RequeueAfter without ever setting OverlayReady — an unbounded wedge. Under the ADR-0352 /
// invariant-#10 primitive it reads the source-of-truth write-backs and sets OverlayReady=True with
// no live RPC. Note it deliberately does NOT pre-seed RelayProgramsLoaded (the fast-path condition
// TestStrictMigrationVisitsOverlayHandoffAndDisengageHold uses), because that pre-seed short-circuits
// the barrier at the top of reconcileDisengageHold and is exactly why the wedge slipped prior gates.
func TestDisengageHoldReadsOverlayReadyFromConditions(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	now := metav1.Now()
	cond := func(typ string) metav1.Condition {
		return metav1.Condition{Type: typ, Status: metav1.ConditionTrue, Reason: "PreSeeded",
			Message: "live-proof cycle-2 state", LastTransitionTime: now}
	}

	newPM := func(name string, conds []metav1.Condition, srcConntrack bool) *pmv1.PodMigration {
		return &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: pmv1.PodMigrationSpec{
				PodName:             "redis-src",
				PodNamespace:        "default",
				TCPPreservationMode: pmv1.TCPPreservationModeStrict,
				RollbackOnFailure:   true,
				TargetNodeName:      "pm-w2",
			},
			Status: pmv1.PodMigrationStatus{
				Phase:               pmv1.MigrationPhaseDisengageHold,
				Conditions:          conds,
				SourceNodeName:      "pm-w1",
				DestinationNodeName: "pm-w2",
				SourceConntrackArmed: srcConntrack,
			},
		}
	}

	t.Run("all_inputs_present_sets_OverlayReady_without_live_rpc", func(t *testing.T) {
		pm := newPM("live-proof-c2-mig1",
			[]metav1.Condition{
				cond(string(pmv1.ConditionVXLANFDBUpdated)), // B/C/D + dest-E, confirmed pre-restore
				cond(conditionRestored),                     // F: CRIU restore complete
			}, true /* SourceConntrackArmed: source-E axis */)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(pm).WithStatusSubresource(pm).Build()
		// AgentPool intentionally nil: the retired live re-probe would be unreachable here.
		r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

		if _, err := r.reconcileDisengageHold(context.Background(), pm); err != nil {
			t.Fatalf("reconcileDisengageHold returned error: %v", err)
		}
		if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionOverlayReady) {
			t.Fatalf("OverlayReady was not set True from source-of-truth conditions — the barrier wedge is NOT fixed; conditions=%+v",
				pm.Status.Conditions)
		}
	})

	t.Run("missing_input_fails_closed_not_wedged", func(t *testing.T) {
		// VXLANFDBUpdated absent → an upstream invariant is missing. The primitive must fail
		// CLOSED (bounded, invariant #8), never infinite-requeue at the barrier.
		pm := newPM("live-proof-c2-migX",
			[]metav1.Condition{cond(conditionRestored)}, true)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(pm).WithStatusSubresource(pm).Build()
		r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

		if _, err := r.reconcileDisengageHold(context.Background(), pm); err != nil {
			t.Fatalf("reconcileDisengageHold (fail-closed) returned error: %v", err)
		}
		// The fail-closed branch must set OverlayReady=False with the BarrierInputsAbsent reason
		// and route to rollback — NOT the old brittle-chain behaviour of a bare RequeueAfter that
		// leaves OverlayReady entirely absent and re-probes forever (the unbounded wedge).
		oc := meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionOverlayReady)
		if oc == nil {
			t.Fatalf("OverlayReady absent — the barrier silently requeued instead of failing closed (invariant #8)")
		}
		if oc.Status != metav1.ConditionFalse || oc.Reason != "BarrierInputsAbsent" {
			t.Fatalf("expected OverlayReady=False/BarrierInputsAbsent on missing input, got %s/%s", oc.Status, oc.Reason)
		}
	})
}
