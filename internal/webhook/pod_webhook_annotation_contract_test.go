/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/podmotion-io/podmotion/internal/agent/nri"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestPodMutatingWebhookAnnotationSatisfiesNRIContract is the §P-VERIFY integration
// test required by ADR-0369. It closes the six-week detection gap the ADR documents:
// the webhook side and the NRI plugin side were each covered only by isolated unit
// tests that independently assumed different, disagreeing shapes for the same
// podmotion.io/checkpoint-ref value — a webhook test asserting "full path" and a
// plugin test asserting "bare identifier" could both pass forever without ever
// proving the two components agree with each other.
//
// This test invokes the real PodMutatingWebhook.Handle to produce a real admission
// patch, extracts the real annotation value from that real patch output, and feeds it
// through the real nri.ValidCheckpointRef regex (imported directly from the NRI
// plugin package, not restated here) — proving the webhook's construction side and
// the plugin's validation side actually agree, rather than each being merely
// self-consistent with its own separately-assumed input shape.
func TestPodMutatingWebhookAnnotationSatisfiesNRIContract(t *testing.T) {
	const ns = "default"
	const migName = "mig-contract-4"

	scheme := newPodWebhookScheme(t)

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "source-pod",
			PodNamespace: ns,
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()

	// Seed CheckpointRef the same way the controller does at admission time
	// (reconcileCheckpointing sets it to the full filesystem path) — this is exactly
	// the field the webhook must NOT copy verbatim into the annotation.
	pm.Status.CheckpointRef = &corev1.LocalObjectReference{
		Name: "/run/podmotion/checkpoints/" + migName + "/final",
	}
	if err := c.Status().Update(context.Background(), pm); err != nil {
		t.Fatalf("seed status: %v", err)
	}

	w := NewPodMutatingWebhook(c, scheme)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replacement-pod",
			Namespace: ns,
			Labels:    map[string]string{LabelMigrationName: migName},
		},
	}
	req := buildAdmissionRequest(t, pod, ns)

	resp := w.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected admission allowed, got denied: %+v", resp.Result)
	}

	gotAnn, err := findAnnotationInPatches(resp.Patches, AnnotationCheckpointRef)
	if err != nil {
		t.Fatalf("looking for %s annotation patch: %v", AnnotationCheckpointRef, err)
	}

	// The actual contract check: the webhook's real output must satisfy the NRI
	// plugin's real path-traversal-defense regex. Using nri.ValidCheckpointRef
	// directly (not a restated copy) means a future drift in either component is
	// caught here, regardless of whether each side's own isolated unit tests still
	// pass in isolation.
	if !nri.ValidCheckpointRef.MatchString(gotAnn) {
		t.Fatalf("webhook produced checkpoint-ref annotation %q which the real NRI "+
			"plugin regex (nri.ValidCheckpointRef) rejects — webhook construction and "+
			"plugin validation have drifted out of agreement", gotAnn)
	}

	// Also confirm it is in fact the bare identifier convention, not the path, so a
	// regression that made the regex accidentally match something else entirely
	// (e.g. an empty string, if MatchString semantics ever changed) cannot slip by.
	if gotAnn != migName {
		t.Fatalf("annotation %s = %q, want %q (pm.Name)", AnnotationCheckpointRef, gotAnn, migName)
	}
}
