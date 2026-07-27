/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	jsonpatch "gomodules.xyz/jsonpatch/v2"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

var (
	errPatchNotFound = errors.New("json patch operation not found")
	errNotAString    = errors.New("json patch value is not a string")
)

func newPodWebhookScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	return scheme
}

// buildAdmissionRequest packages a replacement pod object into an admission.Request
// carrying the migration-name label, mirroring what the API server sends for a real
// pod CREATE once the chart's MutatingWebhookConfiguration objectSelector routes it here.
func buildAdmissionRequest(t *testing.T, pod *corev1.Pod, ns string) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:       "test-uid",
		Namespace: ns,
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: raw},
	}}
}

// TestPodMutatingWebhookDestNodeFallbackChain covers the sprint52 diagnosis Bug B fix:
// the webhook must resolve the destination node (and therefore the destination NMC's
// CNI plugin, and therefore whether the CNI IPAM pin annotation is written) via the same
// fallback chain the rest of the codebase uses — Status.DestinationNodeName ->
// Spec.TargetNodeName -> Spec.DestinationNode — not TargetNodeName alone. Before the fix,
// any scheduler-selected (unpinned) migration — the normal case, where only
// Status.DestinationNodeName is populated — silently fell back to the write-never
// pm.Status.CNIProvider field and never wrote ipam.cilium.io/ip.
func TestPodMutatingWebhookDestNodeFallbackChain(t *testing.T) {
	const ns = "default"

	cases := []struct {
		name       string
		pmSpec     pmv1.PodMigrationSpec
		pmStatus   pmv1.PodMigrationStatus
		wantAnnKey string
		wantAnnVal string
	}{
		{
			// The normal, scheduler-selected case: TargetNodeName is empty (scheduler
			// picks), and the controller has populated Status.DestinationNodeName. This
			// is exactly the case Bug B missed.
			name: "falls through to Status.DestinationNodeName when TargetNodeName is empty",
			pmSpec: pmv1.PodMigrationSpec{
				PodName:      "source-pod",
				PodNamespace: ns,
				SourcePodIP:  "10.244.1.5",
			},
			pmStatus: pmv1.PodMigrationStatus{
				DestinationNodeName: "node-b",
			},
			wantAnnKey: "ipam.cilium.io/ip",
			wantAnnVal: "10.244.1.5",
		},
		{
			// Explicit pin still works (this was the only case Bug B covered).
			name: "uses Spec.TargetNodeName when set",
			pmSpec: pmv1.PodMigrationSpec{
				PodName:        "source-pod",
				PodNamespace:   ns,
				SourcePodIP:    "10.244.1.6",
				TargetNodeName: "node-b",
			},
			wantAnnKey: "ipam.cilium.io/ip",
			wantAnnVal: "10.244.1.6",
		},
		{
			// Status.DestinationNodeName takes priority over Spec.TargetNodeName,
			// matching createReplacementPod's own resolution order.
			name: "Status.DestinationNodeName takes priority over Spec.TargetNodeName",
			pmSpec: pmv1.PodMigrationSpec{
				PodName:        "source-pod",
				PodNamespace:   ns,
				SourcePodIP:    "10.244.1.7",
				TargetNodeName: "node-wrong",
			},
			pmStatus: pmv1.PodMigrationStatus{
				DestinationNodeName: "node-b",
			},
			wantAnnKey: "ipam.cilium.io/ip",
			wantAnnVal: "10.244.1.7",
		},
		{
			// Final fallback: Spec.DestinationNode, when neither of the other two is set.
			name: "falls through to Spec.DestinationNode as last resort",
			pmSpec: pmv1.PodMigrationSpec{
				PodName:         "source-pod",
				PodNamespace:    ns,
				SourcePodIP:     "10.244.1.8",
				DestinationNode: "node-b",
			},
			wantAnnKey: "ipam.cilium.io/ip",
			wantAnnVal: "10.244.1.8",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newPodWebhookScheme(t)

			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{Name: "mig-1", Namespace: ns},
				Spec:       tc.pmSpec,
			}
			nmc := &pmv1.NodeMigrationCapacity{
				ObjectMeta: metav1.ObjectMeta{Name: "node-b"},
				Spec: pmv1.NodeMigrationCapacitySpec{
					NetworkCapability: pmv1.NetworkCapability{CNIPlugin: "cilium"},
				},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pm, nmc).
				WithStatusSubresource(pm).
				Build()

			// WithObjects seeds .Status as zero-value even when set on the object passed
			// in (fake client historically only honors spec on create) — set Status via
			// a follow-up Status().Update to make sure it's actually persisted for Get.
			if tc.pmStatus.DestinationNodeName != "" {
				pm.Status.DestinationNodeName = tc.pmStatus.DestinationNodeName
				if err := c.Status().Update(context.Background(), pm); err != nil {
					t.Fatalf("seed status: %v", err)
				}
			}

			w := NewPodMutatingWebhook(c, scheme)

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "replacement-pod",
					Namespace: ns,
					Labels:    map[string]string{LabelMigrationName: "mig-1"},
				},
			}
			req := buildAdmissionRequest(t, pod, ns)

			resp := w.Handle(context.Background(), req)
			if !resp.Allowed {
				t.Fatalf("expected admission allowed, got denied: %+v", resp.Result)
			}

			gotVal, err := findAnnotationInPatches(resp.Patches, tc.wantAnnKey)
			if err != nil {
				t.Fatalf("looking for annotation patch: %v", err)
			}
			if gotVal != tc.wantAnnVal {
				t.Fatalf("annotation %s = %q, want %q (patches: %+v)", tc.wantAnnKey, gotVal, tc.wantAnnVal, resp.Patches)
			}
		})
	}
}

// TestPodMutatingWebhookNoDestNodeResolvedFallsThroughToNoAnnotation covers the case
// where none of Status.DestinationNodeName, Spec.TargetNodeName, or Spec.DestinationNode
// are set: the webhook must not error, and must not write a CNI annotation (P-VERIFY-C
// catches the unpinned case downstream, not the webhook).
func TestPodMutatingWebhookNoDestNodeResolvedFallsThroughToNoAnnotation(t *testing.T) {
	const ns = "default"
	scheme := newPodWebhookScheme(t)

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-2", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "source-pod",
			PodNamespace: ns,
			SourcePodIP:  "10.244.1.9",
			// No TargetNodeName, no DestinationNode, no Status.DestinationNodeName.
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).Build()
	w := NewPodMutatingWebhook(c, scheme)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replacement-pod",
			Namespace: ns,
			Labels:    map[string]string{LabelMigrationName: "mig-2"},
		},
	}
	req := buildAdmissionRequest(t, pod, ns)

	resp := w.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected admission allowed, got denied: %+v", resp.Result)
	}
	if _, err := findAnnotationInPatches(resp.Patches, "ipam.cilium.io/ip"); err == nil {
		t.Fatalf("expected no ipam.cilium.io/ip annotation patch, but found one: %+v", resp.Patches)
	}
}

// TestPodMutatingWebhookCheckpointRefLabelIsLegal covers the sprint51 bug where the
// webhook stamped pod.Labels[AnnotationCheckpointRef] with pm.Status.CheckpointRef.Name
// verbatim. CheckpointRef.Name is a filesystem path (e.g.
// /run/podmotion/checkpoints/<migration>/final) and is NOT a legal Kubernetes label
// value (labels only allow alphanumeric, '-', '_', '.') — every replacement pod CREATE
// was rejected by the API server with "a valid label must be an empty string or
// consist of alphanumeric characters, '-', '_' or '.'", making live migration fail
// 100% of the time. Per ADR-0369, both the annotation and the label must carry
// pm.Name (the bare migration identifier, not the checkpoint path) — matching the
// controller's own convention in createReplacementPod
// (replacementPodMigrationNameLabel = pm.Name) and what every other reader of this
// annotation (NRI plugin regex, path-joiner, anti-spoof comparator) already assumes.
func TestPodMutatingWebhookCheckpointRefLabelIsLegal(t *testing.T) {
	const ns = "default"
	const migName = "mig-3"
	const checkpointPath = "/run/podmotion/checkpoints/mig-3/final"

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

	pm.Status.CheckpointRef = &corev1.LocalObjectReference{Name: checkpointPath}
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
	if gotAnn != migName {
		t.Fatalf("annotation %s = %q, want %q (pm.Name, not the checkpoint path)", AnnotationCheckpointRef, gotAnn, migName)
	}

	gotLabel, err := findLabelInPatches(resp.Patches, AnnotationCheckpointRef)
	if err != nil {
		t.Fatalf("looking for %s label patch: %v", AnnotationCheckpointRef, err)
	}
	if gotLabel != migName {
		t.Fatalf("label %s = %q, want %q (pm.Name, not the checkpoint path)", AnnotationCheckpointRef, gotLabel, migName)
	}
	if errs := validation.IsValidLabelValue(gotLabel); len(errs) != 0 {
		t.Fatalf("label %s value %q is not a legal Kubernetes label value: %v", AnnotationCheckpointRef, gotLabel, errs)
	}
	// Guard against a regression that "fixes" this by making the label illegal in a
	// different way (e.g. reusing the path with slashes stripped) — it must contain
	// no '/' at all, which the real bug's value definitely did.
	if strings.Contains(gotLabel, "/") {
		t.Fatalf("label %s value %q still contains '/', not label-legal", AnnotationCheckpointRef, gotLabel)
	}
}

// findLabelInPatches returns the string value of the given label key from the
// admission response's JSON patches, handling both the per-key and whole-map patch
// shapes (see findAnnotationInPatches).
func findLabelInPatches(patches []jsonpatch.JsonPatchOperation, key string) (string, error) {
	perKeyPath := "/metadata/labels/" + jsonPatchEscape(key)
	for _, p := range patches {
		if p.Operation != "add" && p.Operation != "replace" {
			continue
		}
		if p.Path == perKeyPath {
			s, ok := p.Value.(string)
			if !ok {
				return "", errNotAString
			}
			return s, nil
		}
		if p.Path == "/metadata/labels" {
			m, ok := p.Value.(map[string]interface{})
			if !ok {
				return "", errNotAString
			}
			if v, present := m[key]; present {
				s, ok := v.(string)
				if !ok {
					return "", errNotAString
				}
				return s, nil
			}
		}
	}
	return "", errPatchNotFound
}

// findAnnotationInPatches returns the string value of the given annotation key from
// the admission response's JSON patches. The webhook may emit either a per-key patch
// (/metadata/annotations/<key>, when the pod already had some annotations) or a
// whole-map patch (/metadata/annotations, when the pod started with none) — handle
// both shapes rather than assuming one.
func findAnnotationInPatches(patches []jsonpatch.JsonPatchOperation, key string) (string, error) {
	perKeyPath := "/metadata/annotations/" + jsonPatchEscape(key)
	for _, p := range patches {
		if (p.Operation != "add" && p.Operation != "replace") {
			continue
		}
		if p.Path == perKeyPath {
			s, ok := p.Value.(string)
			if !ok {
				return "", errNotAString
			}
			return s, nil
		}
		if p.Path == "/metadata/annotations" {
			m, ok := p.Value.(map[string]interface{})
			if !ok {
				return "", errNotAString
			}
			if v, present := m[key]; present {
				s, ok := v.(string)
				if !ok {
					return "", errNotAString
				}
				return s, nil
			}
		}
	}
	return "", errPatchNotFound
}

func jsonPatchEscape(s string) string {
	// JSON Pointer escaping: ~ -> ~0, / -> ~1.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '~':
			out = append(out, '~', '0')
		case '/':
			out = append(out, '~', '1')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
