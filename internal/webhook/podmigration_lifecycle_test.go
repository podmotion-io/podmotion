/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestIsLifecycleOnlyRequest covers the ADR-0212 finalizer/webhook deadlock guard.
//
// The validating webhook must ALLOW (skip CREATE-time spec admission rules) on:
//   - any request whose object carries a deletionTimestamp (the finalizer-removal UPDATE), and
//   - any UPDATE on a terminal-phase CR (source pod legitimately gone per ADR-0012).
//
// It must NEVER treat a CREATE as lifecycle-only, and must NOT bypass a non-terminal UPDATE.
func TestIsLifecycleOnlyRequest(t *testing.T) {
	now := metav1.Now()

	mk := func(phase pmv1.MigrationPhase, deleting bool) *pmv1.PodMigration {
		pm := &pmv1.PodMigration{}
		pm.Status.Phase = phase
		if deleting {
			pm.DeletionTimestamp = &now
		}
		return pm
	}

	req := func(op admissionv1.Operation) admission.Request {
		return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: op}}
	}

	tests := []struct {
		name string
		op   admissionv1.Operation
		pm   *pmv1.PodMigration
		want bool
	}{
		// The exact gate-8 deadlock: finalizer-removal UPDATE on a deleting Complete CR.
		{"delete-path UPDATE on Complete (gate-8 deadlock)", admissionv1.Update, mk(pmv1.MigrationPhaseComplete, true), true},
		{"delete-path UPDATE on running CR", admissionv1.Update, mk(pmv1.MigrationPhaseRestoring, true), true},
		{"delete-path DELETE", admissionv1.Delete, mk(pmv1.MigrationPhaseComplete, true), true},

		// Terminal-phase UPDATEs (no deletionTimestamp) — status/metadata churn, spec immutable.
		{"UPDATE on Complete", admissionv1.Update, mk(pmv1.MigrationPhaseComplete, false), true},
		{"UPDATE on Failed", admissionv1.Update, mk(pmv1.MigrationPhaseFailed, false), true},
		{"UPDATE on RollingBack", admissionv1.Update, mk(pmv1.MigrationPhaseRollingBack, false), true},
		{"UPDATE on DryRunComplete", admissionv1.Update, mk(pmv1.MigrationPhaseDryRunComplete, false), true},

		// Must still fully validate.
		{"CREATE never lifecycle-only", admissionv1.Create, mk(pmv1.MigrationPhasePending, false), false},
		{"CREATE even on terminal phase", admissionv1.Create, mk(pmv1.MigrationPhaseComplete, false), false},
		{"UPDATE on non-terminal phase", admissionv1.Update, mk(pmv1.MigrationPhaseVerifying, false), false},
		{"UPDATE on empty phase", admissionv1.Update, mk(pmv1.MigrationPhase(""), false), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLifecycleOnlyRequest(req(tt.op), tt.pm)
			if got != tt.want {
				t.Errorf("isLifecycleOnlyRequest(%s, phase=%q, deleting=%v) = %v, want %v",
					tt.op, tt.pm.Status.Phase, tt.pm.DeletionTimestamp != nil, got, tt.want)
			}
		})
	}
}
