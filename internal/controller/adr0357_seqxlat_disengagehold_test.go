/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// getFresh re-fetches pm from the fake client — transitionTo/initiateRollback patch a freshly
// re-Get'd copy internally (retry.RetryOnConflict), not the caller's in-memory pm, so phase
// assertions must read back from the client rather than the local pm variable.
func getFreshPM(t *testing.T, c client.Client, pm *pmv1.PodMigration) *pmv1.PodMigration {
	t.Helper()
	fresh := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pm), fresh); err != nil {
		t.Fatalf("get fresh PodMigration: %v", err)
	}
	return fresh
}

// adr0357_seqxlat_disengagehold_test.go — ADR-0357 D1.3 / AC5 regression coverage.
//
// reconcileDisengageHold previously set ConditionRelayProgramsLoaded=True unconditionally
// (an M20 placeholder — "PM_SEQ_XLAT relay wiring is M22... marking RelayProgramsLoaded" —
// stale dead code left in place after M22 shipped as ADR-0093/ADR-0357). This is the fault-
// injection regression AC5 requires: when TCPSeqSnapshots is non-empty but the destination
// agent's verified write-back (Status.SeqXlatSeeded) was never confirmed, the migration MUST
// fail closed to RollingBack (source pod preserved per invariant #1) — never silently report
// RelayProgramsLoaded=True on unverified/absent seq translation.
func TestDisengageHold_SeqXlatSeeded_D13(t *testing.T) {
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
			Message: "ADR-0357 D1.3 test fixture", LastTransitionTime: now}
	}

	// Every barrier input reconcileDisengageHold needs BEFORE it ever reaches the D1.3 gate:
	// OverlayReady's prerequisites (VXLANFDBUpdated, Restored, SourceConntrackArmed) and
	// ZeroWindowDisarmed (so the AgentPool-requiring disarm block is skipped — AgentPool is
	// left nil, matching the established pattern in TestDisengageHoldReadsOverlayReadyFromConditions).
	baseConditions := []metav1.Condition{
		cond(string(pmv1.ConditionVXLANFDBUpdated)),
		cond(conditionRestored),
		cond(string(pmv1.ConditionZeroWindowDisarmed)),
	}

	newPM := func(name string, snaps []pmv1.TCPSeqSnapshot, seeded bool) *pmv1.PodMigration {
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
				Phase:                pmv1.MigrationPhaseDisengageHold,
				Conditions:           append([]metav1.Condition{}, baseConditions...),
				SourceNodeName:       "pm-w1",
				DestinationNodeName:  "pm-w2",
				SourceConntrackArmed: true,
				TCPSeqSnapshots:      snaps,
				SeqXlatSeeded:        seeded,
			},
		}
	}

	oneSnapshot := []pmv1.TCPSeqSnapshot{
		{SrcIP: "10.0.0.9", SrcPort: 6379, DstIP: "10.0.0.1", DstPort: 40000, SndNxt: 100, RcvNxt: 200},
	}

	t.Run("non-empty snapshots, SeqXlatSeeded absent -> fails closed to RollingBack", func(t *testing.T) {
		pm := newPM("d13-block", oneSnapshot, false)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(pm).WithStatusSubresource(pm).Build()
		r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

		if _, err := r.reconcileDisengageHold(context.Background(), pm); err != nil {
			t.Fatalf("reconcileDisengageHold returned unexpected error: %v", err)
		}

		rc := meta.FindStatusCondition(pm.Status.Conditions, string(pmv1.ConditionRelayProgramsLoaded))
		if rc == nil || rc.Status != metav1.ConditionFalse || rc.Reason != "SeqXlatNotSeeded" {
			t.Fatalf("expected RelayProgramsLoaded=False/SeqXlatNotSeeded, got %+v", rc)
		}
		if got := getFreshPM(t, fakeClient, pm).Status.Phase; got != pmv1.MigrationPhaseRollingBack {
			t.Fatalf("expected fail-closed rollback (invariant #1: source pod preserved), got phase=%s", got)
		}
	})

	t.Run("non-empty snapshots, SeqXlatSeeded=true -> RelayProgramsLoaded=True, advances to TCPVerifying", func(t *testing.T) {
		pm := newPM("d13-verified", oneSnapshot, true)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(pm).WithStatusSubresource(pm).Build()
		r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

		if _, err := r.reconcileDisengageHold(context.Background(), pm); err != nil {
			t.Fatalf("reconcileDisengageHold returned unexpected error: %v", err)
		}

		rc := meta.FindStatusCondition(pm.Status.Conditions, string(pmv1.ConditionRelayProgramsLoaded))
		if rc == nil || rc.Status != metav1.ConditionTrue || rc.Reason != "SeqXlatVerified" {
			t.Fatalf("expected RelayProgramsLoaded=True/SeqXlatVerified, got %+v", rc)
		}
		if got := getFreshPM(t, fakeClient, pm).Status.Phase; got != pmv1.MigrationPhaseTCPVerifying {
			t.Fatalf("expected advance to TCPVerifying, got phase=%s", got)
		}
	})

	t.Run("empty snapshots (D1.4 vacuous pass), SeqXlatSeeded absent -> still advances", func(t *testing.T) {
		pm := newPM("d13-vacuous", nil, false)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(pm).WithStatusSubresource(pm).Build()
		r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

		if _, err := r.reconcileDisengageHold(context.Background(), pm); err != nil {
			t.Fatalf("reconcileDisengageHold returned unexpected error: %v", err)
		}

		rc := meta.FindStatusCondition(pm.Status.Conditions, string(pmv1.ConditionRelayProgramsLoaded))
		if rc == nil || rc.Status != metav1.ConditionTrue {
			t.Fatalf("expected RelayProgramsLoaded=True (D1.4 vacuous pass — no TCP connections to translate), got %+v", rc)
		}
		if got := getFreshPM(t, fakeClient, pm).Status.Phase; got != pmv1.MigrationPhaseTCPVerifying {
			t.Fatalf("expected advance to TCPVerifying, got phase=%s", got)
		}
	})
}
