/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0352_b8_restoring_nri_test.go — ADR-0352 sprint46B8 B8-DR-3(a) coverage:
//
//   - TestReconcileRestoringNRI_Strict_TransitionsToTCPVerifying: the load-bearing regression
//     gate for B8-D1/B8-D2 — a Strict NRI restore-tail exit routes onto the authoritative
//     DisengageHold -> TCPVerifying -> ServiceVerifying spine instead of the legacy 8-phase
//     Verifying tail; BestEffort/None stay byte-unchanged on the legacy MigrationPhaseVerifying
//     exit (B8-DR-7). Round-2 correction: the terminal transition targets
//     MigrationPhaseDisengageHold (not MigrationPhaseTCPVerifying directly) so this population
//     always traverses the phase that disarms the source zero-window hold — see the production
//     comment at podmigration_controller.go's reconcileRestoringNRI terminal statement.
//
// Named distinctly from the pre-existing podmigration_controller_test.go (a Ginkgo/envtest
// scaffold requiring the suite_test.go TestControllers entrypoint) to avoid colliding with it —
// this is a plain *testing.T unit test against the fake client, no envtest required.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

func TestReconcileRestoringNRI_Strict_TransitionsToTCPVerifying(t *testing.T) {
	scheme := adr0210Scheme(t) // reuse the existing scheme-builder helper (adr0210_dataplane_gate_test.go)
	ns := "default"

	newFixture := func(mode pmv1.TCPPreservationMode, name string) (*pmv1.PodMigration, *corev1.Pod) {
		confirmed := true
		replacement := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name + "-dst", Namespace: ns},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{Name: "app", Ready: true},
				},
			},
		}
		pm := &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: pmv1.PodMigrationSpec{
				PodName:             name + "-src",
				PodNamespace:        ns,
				TCPPreservationMode: mode,
			},
			Status: pmv1.PodMigrationStatus{
				DestinationNodeName:  "node-b",
				ReplacementPodName:   replacement.Name,
				CRIURestoreConfirmed: &confirmed,
			},
		}
		return pm, replacement
	}

	t.Run("Strict routes to DisengageHold", func(t *testing.T) {
		pm, replacement := newFixture(pmv1.TCPPreservationModeStrict, "pm-nri-strict")
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, replacement).WithStatusSubresource(pm).Build()
		r := &PodMigrationReconciler{Client: c, Scheme: scheme}

		if _, err := r.reconcileRestoringNRI(context.Background(), pm); err != nil {
			t.Fatalf("reconcileRestoringNRI: %v", err)
		}
		fresh := &pmv1.PodMigration{}
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(pm), fresh); err != nil {
			t.Fatalf("re-Get: %v", err)
		}
		// ADR-0352 B8-D1 round-2 correction: targeting DisengageHold (not TCPVerifying
		// directly) converges the override-fires and override-skipped(crash) cases on the
		// zero-window disarm barrier — see the production comment on this transition.
		if fresh.Status.Phase != pmv1.MigrationPhaseDisengageHold {
			t.Fatalf("ADR-0352 B8-D1: Strict NRI restore must transition to DisengageHold, got %q", fresh.Status.Phase)
		}
	})

	for _, mode := range []pmv1.TCPPreservationMode{pmv1.TCPPreservationModeBestEffort, pmv1.TCPPreservationModeNone} {
		mode := mode
		t.Run(string(mode)+" stays on Verifying (byte-unchanged, B8-DR-7)", func(t *testing.T) {
			pm, replacement := newFixture(mode, "pm-nri-"+string(mode))
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, replacement).WithStatusSubresource(pm).Build()
			r := &PodMigrationReconciler{Client: c, Scheme: scheme}

			if _, err := r.reconcileRestoringNRI(context.Background(), pm); err != nil {
				t.Fatalf("reconcileRestoringNRI: %v", err)
			}
			fresh := &pmv1.PodMigration{}
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(pm), fresh); err != nil {
				t.Fatalf("re-Get: %v", err)
			}
			if fresh.Status.Phase != pmv1.MigrationPhaseVerifying {
				t.Fatalf("ADR-0352 B8-DR-7: %s NRI restore must stay on legacy Verifying, got %q", mode, fresh.Status.Phase)
			}
		})
	}
}
