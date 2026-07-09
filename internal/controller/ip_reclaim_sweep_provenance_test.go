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

// TestIPReclaimSweepProvenance is the Sprint 42 FS-048 regression guard.
//
// The defect: reconcileIPReclaimSweep short-circuited to
// IPReclaimComplete/Verified=True (NothingToReclaim) whenever conditionIPHandoffInjected
// was absent. But IPHandoffInjected is DROPPED (never persisted) when
// verifyDataplaneReachability returns done=false — i.e. whenever the OLD pod IP does not
// converge cross-node (a legitimate, sometimes-permanent outcome on kind/Flannel and on
// cross-subnet/cross-AZ AWS VPC CNI). The reclaim datapath objects were nonetheless
// physically installed on the wire (InjectIPHandoff confirmed resp.Injected before the
// probe), so the short-circuit silently orphaned real objects — no VerifyCleanup, no
// DatapathCleanupLeak event/metric — the exact inverse of the FS-048 invariant.
//
// The fix keys the short-circuit (and ipReclaimEligible R2) off the durable
// ConditionReclaimObjectsInstalled provenance, set the moment resp.Injected is confirmed
// and never dropped by a reachability requeue.
//
// Assertions:
//   - objects installed + IPHandoffInjected absent (reachability never converged) ⇒ the
//     sweep MUST NOT declare NothingToReclaim; it proceeds toward VerifyCleanup.
//   - no objects ever installed ⇒ the sweep MAY legitimately declare NothingToReclaim.
func TestIPReclaimSweepProvenance(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	now := metav1.Now()
	cond := func(t string, s metav1.ConditionStatus) metav1.Condition {
		return metav1.Condition{Type: t, Status: s, Reason: "Test", LastTransitionTime: now}
	}

	tests := []struct {
		name string
		// conditions present on the terminal CR at sweep time
		conditions []metav1.Condition
		// true  => the sweep short-circuited to NothingToReclaim (skipped VerifyCleanup)
		// false => the sweep proceeded (did NOT declare NothingToReclaim)
		wantNothingToReclaim bool
	}{
		{
			// THE BUG: reclaim objects were physically installed, but the cross-node
			// reachability probe never converged so IPHandoffInjected was dropped. The sweep
			// MUST still run — it must NOT short-circuit to NothingToReclaim.
			name: "objects installed, reachability not converged (IPHandoffInjected dropped)",
			conditions: []metav1.Condition{
				cond(pmv1.ConditionReclaimObjectsInstalled, metav1.ConditionTrue),
				// IPHandoffInjected intentionally ABSENT — this is the dropped-condition state.
				cond(conditionDataplaneReachabilityVerified, metav1.ConditionFalse),
			},
			wantNothingToReclaim: false,
		},
		{
			// QA Gap 2 — PARTIAL / SOURCE-ONLY install. The destination InjectIPHandoff RPC
			// confirmed resp.Injected (so ConditionReclaimObjectsInstalled is set and dest objects
			// are on the wire), but the best-effort source VXLAN redirect (InjectSourceRedirect,
			// warn-only) did NOT install — there is no per-side install condition, and this is the
			// exact state a source-side failure produces. The sweep MUST NOT short-circuit to
			// NothingToReclaim: it must proceed so VerifyCleanup (which is presence-based and probes
			// BOTH dest and source objects) can surface/clean any source-side leak. Reachability is
			// also not converged here to stack the failure the way FS-048 observed it.
			name: "dest objects installed, source redirect not installed (partial), reachability not converged",
			conditions: []metav1.Condition{
				cond(pmv1.ConditionReclaimObjectsInstalled, metav1.ConditionTrue),
				cond(conditionDataplaneReachabilityVerified, metav1.ConditionFalse),
			},
			wantNothingToReclaim: false,
		},
		{
			// LEGIT NothingToReclaim: no reclaim objects were ever installed (e.g. rolled back
			// before InjectIPHandoff, or TCPPreservationMode=None). Short-circuit is correct.
			name:                 "no objects ever installed",
			conditions:           []metav1.Condition{},
			wantNothingToReclaim: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{Name: "fs048-" + tc.name[:3], Namespace: "default"},
				Spec: pmv1.PodMigrationSpec{
					PodName:             "src-pod",
					PodNamespace:        "default",
					TCPPreservationMode: pmv1.TCPPreservationModeStrict,
					SourcePodIP:         "10.0.0.1",
				},
				Status: pmv1.PodMigrationStatus{
					// Terminal, so the sweep runs its real body (not an early return).
					Phase:          pmv1.MigrationPhaseComplete,
					SourceNodeName: "src-node",
					Conditions:     tc.conditions,
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pm).
				WithStatusSubresource(pm).
				Build()

			// AgentPool left nil: the "objects installed" case will pass the short-circuit and
			// R2, then defer at a later eligibility conjunct or the VerifyCleanup nil-AgentPool
			// guard — either way it does NOT declare NothingToReclaim, which is the invariant
			// under test. The "no objects" case never reaches any agent path.
			r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

			if _, err := r.reconcileIPReclaimSweep(context.Background(), pm); err != nil {
				t.Fatalf("reconcileIPReclaimSweep returned error: %v", err)
			}

			// Re-read from the fake client to observe persisted status.
			got := &pmv1.PodMigration{}
			if err := fakeClient.Get(context.Background(),
				client.ObjectKeyFromObject(pm), got); err != nil {
				t.Fatalf("get after sweep: %v", err)
			}

			verifiedCond := meta.FindStatusCondition(got.Status.Conditions, pmv1.ConditionIPReclaimVerified)
			isNothingToReclaim := verifiedCond != nil &&
				verifiedCond.Status == metav1.ConditionTrue &&
				verifiedCond.Reason == "NothingToReclaim"

			if isNothingToReclaim != tc.wantNothingToReclaim {
				t.Fatalf("NothingToReclaim short-circuit: got=%v want=%v (IPReclaimVerified=%+v)",
					isNothingToReclaim, tc.wantNothingToReclaim, verifiedCond)
			}

			// Extra guard on the bug case: the objects-installed CR must NOT have its
			// IPReclaimComplete falsely marked NothingToReclaim either.
			if !tc.wantNothingToReclaim {
				completeCond := meta.FindStatusCondition(got.Status.Conditions, pmv1.ConditionIPReclaimComplete)
				if completeCond != nil && completeCond.Reason == "NothingToReclaim" {
					t.Fatalf("objects were installed but sweep marked IPReclaimComplete=NothingToReclaim — orphan leak silently skipped (the FS-048 defect)")
				}
			}
		})
	}
}
