/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/multicluster"
)

// TestHandle_LifecycleUpdatesBypassCreateTimeGates is the round-2 rewrite of the former
// TestIsLifecycleOnlyRequest. Round 1 (rejected, Finding 1, brittle-chain BLOCKING) added a
// dedicated isLifecycleOnlyRequest short-circuit keyed on DeletionTimestamp/terminal-phase.
// That function has been removed entirely (see docs/adr — Round-2 Verifying-phase wedge fix):
// the fix is now structural — every CREATE-time premigration gate in validate() (Rule 1 pod
// existence chief among them) is scoped behind isCreate, which is derived from req.Operation.
// So this test exercises Handle() end-to-end (not a deleted internal helper) and asserts the
// exact real-world scenarios the round-1 test covered, now passing for a different, more
// durable reason: Rule 1 (and friends) never run on any UPDATE, regardless of DeletionTimestamp
// or phase, because there is no live pod fetch on UPDATE at all any more.
func TestHandle_LifecycleUpdatesBypassCreateTimeGates(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}

	now := metav1.Now()

	mk := func(phase pmv1.MigrationPhase, deleting bool) *pmv1.PodMigration {
		pm := &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{Name: "pm-test", Namespace: "default"},
			Spec: pmv1.PodMigrationSpec{
				// Deliberately points at a pod that does NOT exist in the fake client — this
				// is exactly the real wedge: the source pod has already been legitimately
				// deleted (ADR-0012) by the time this UPDATE is issued. Rule 1 must not run.
				PodName:      "already-deleted-source-pod",
				PodNamespace: "default",
				// Rule 10 (range validations) stays unconditional by design (pure pm.Spec
				// self-check) — give it valid values so these cases isolate Rule 1's behavior.
				PreCopyMaxRounds:         5,
				PreCopyDirtyThresholdMB:  64,
				CompletionTimeoutSeconds: 600,
			},
		}
		pm.Status.Phase = phase
		if deleting {
			pm.DeletionTimestamp = &now
			pm.Finalizers = []string{"podmotion.io/finalizer"}
		}
		return pm
	}

	newValidator := func(t *testing.T) *PodMigrationValidator {
		t.Helper()
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()
		dec := admission.NewDecoder(scheme)
		return &PodMigrationValidator{
			client:    cl,
			decoder:   dec,
			Federator: &multicluster.StubClusterFederator{},
		}
	}

	buildReq := func(t *testing.T, op admissionv1.Operation, pm *pmv1.PodMigration) admission.Request {
		t.Helper()
		raw, err := json.Marshal(pm)
		if err != nil {
			t.Fatalf("marshal pm: %v", err)
		}
		return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
			UID:       "test-uid",
			Operation: op,
			Object:    runtime.RawExtension{Raw: raw},
		}}
	}

	tests := []struct {
		name        string
		op          admissionv1.Operation
		pm          *pmv1.PodMigration
		wantAllowed bool
	}{
		// The exact gate-8 deadlock: finalizer-removal UPDATE on a deleting Complete CR, source
		// pod already legitimately gone. Must be Allowed — Rule 1 must not run on UPDATE.
		{"delete-path UPDATE on Complete (gate-8 deadlock)", admissionv1.Update, mk(pmv1.MigrationPhaseComplete, true), true},
		{"delete-path UPDATE on running CR", admissionv1.Update, mk(pmv1.MigrationPhaseRestoring, true), true},

		// Terminal-phase UPDATEs (no deletionTimestamp) — status/metadata churn, spec immutable,
		// source pod may legitimately be gone.
		{"UPDATE on Complete", admissionv1.Update, mk(pmv1.MigrationPhaseComplete, false), true},
		{"UPDATE on Failed", admissionv1.Update, mk(pmv1.MigrationPhaseFailed, false), true},
		{"UPDATE on RollingBack", admissionv1.Update, mk(pmv1.MigrationPhaseRollingBack, false), true},
		{"UPDATE on DryRunComplete", admissionv1.Update, mk(pmv1.MigrationPhaseDryRunComplete, false), true},

		// The exact round-2 target scenario: a non-terminal (Verifying) UPDATE issued AFTER the
		// source pod was legitimately deleted mid-Verifying (e.g. the cni0-cleanup-verify retry
		// bump). This is the case round 1's isLifecycleOnlyRequest did NOT cover (phase is not
		// terminal, no DeletionTimestamp) and which caused the real wedge. Must now be Allowed
		// because Rule 1 never runs on UPDATE at all, not because of any phase/deletion special-case.
		{"non-terminal UPDATE after legitimate mid-Verifying source deletion", admissionv1.Update, mk(pmv1.MigrationPhaseVerifying, false), true},
		{"UPDATE on empty phase", admissionv1.Update, mk(pmv1.MigrationPhase(""), false), true},

		// CREATE must still be fully validated — the missing pod must deny it.
		{"CREATE against missing pod is denied", admissionv1.Create, mk(pmv1.MigrationPhasePending, false), false},
		{"CREATE even on terminal phase is still fully validated", admissionv1.Create, mk(pmv1.MigrationPhaseComplete, false), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newValidator(t)
			resp := v.Handle(context.Background(), buildReq(t, tt.op, tt.pm))
			if resp.Allowed != tt.wantAllowed {
				t.Errorf("Handle(%s, phase=%q, deleting=%v).Allowed = %v (result=%q), want %v",
					tt.op, tt.pm.Status.Phase, tt.pm.DeletionTimestamp != nil, resp.Allowed, resp.Result, tt.wantAllowed)
			}
		})
	}
}

// TestValidate_UpdateNeverFetchesLivePod is a focused regression test for Finding 1: after the
// round-2 fix, validate() must never deny an UPDATE via any live-data rule (pod/NMC/federator),
// only via Rule 3 (mode enum) or Rule 10 (range validations) — both pure pm.Spec self-checks.
// This directly guards against a future change accidentally re-introducing a live pod fetch (or
// any other live-data gate) outside the isCreate block.
func TestValidate_UpdateNeverFetchesLivePod(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	v := &PodMigrationValidator{client: cl, Federator: &multicluster.StubClusterFederator{}}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-test", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  "does-not-exist",
			PodNamespace:             "default",
			Mode:                     pmv1.MigrationModePreCopy,
			PreCopyMaxRounds:         5,
			PreCopyDirtyThresholdMB:  64,
			CompletionTimeoutSeconds: 600,
		},
	}
	pm.Status.Phase = pmv1.MigrationPhaseVerifying

	errs := v.validate(context.Background(), pm, false /* isCreate */)
	if len(errs) != 0 {
		t.Errorf("validate() on UPDATE with valid spec and nonexistent pod = %v errors, want 0: %v", len(errs), errs)
	}
}
