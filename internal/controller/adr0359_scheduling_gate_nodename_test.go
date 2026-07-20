/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package controller

// adr0359_scheduling_gate_nodename_test.go — ADR-0359 regression test.
//
// Prior behavior (the bug): createReplacementPod cleared spec.SchedulerName/
// spec.SchedulingGates (deferring to the mutating webhook to re-inject them at
// admission) and then, later in the same function, unconditionally set
// spec.NodeName = <resolved destination node>. A pod created with spec.NodeName
// already populated is bound to that node at admission time — kubelet on that node
// picks it up directly via its pod-watch, regardless of spec.SchedulingGates. So the
// webhook's re-injected podmotion.io/awaiting-checkpoint gate was admitted onto the
// object but inert: it never actually held the pod off the destination node, and the
// gate's entire purpose (block scheduling until CheckpointTransferred) was defeated.
//
// The fix (ADR-0359, Option A): delete the controller's direct spec.NodeName pin
// entirely. The webhook's scheduling-gate injection + the podmotion-scheduler custom
// scheduler become the SOLE, exclusive mechanism binding a replacement pod to its
// destination node. This controller-level test cannot exercise the webhook (it runs
// at admission, outside this package), so it pins the controller's half of the
// contract: createReplacementPod must never populate spec.NodeName on the pod object
// it builds, under any of the ways a destination node can be resolved — including the
// specific dormant sub-bug every panelist flagged as mandatory to close in the same
// change: a live source pod's own spec.NodeName (the SOURCE node) must not leak
// through the deep copy and re-pin the replacement pod, which would reproduce the
// identical gate-bypass aimed at the node the source workload is still live on
// (ADR-0012: source not deleted until TrafficVerified=True).
//
// It also pins the decoupled-but-retained half of the ADR-0359 removal-symmetry audit:
// NodeSelector / NodeAffinity clearing must survive independent of the removed
// NodeName assignment, or a source pod pinned via nodeSelector to its own node would
// leave the replacement pod Unschedulable at the destination — trading the gate-bypass
// race for a stuck-Pending regression.
//
// Finally it pins that the taint-toleration logic (retained, unchanged) still works
// from pm.Status.DestinationNodeName directly, since it never depended on
// spec.NodeName being set.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// buildAndFetchReplacementPod runs createReplacementPod against pm/srcPod (plus any
// extra objects, e.g. a destination Node for the taint-toleration path) and returns
// the created replacement pod.
func buildAndFetchReplacementPod(
	t *testing.T,
	pm *pmv1.PodMigration,
	srcPod *corev1.Pod,
	extraObjs ...client.Object,
) corev1.Pod {
	t.Helper()
	t.Setenv("AGENT_IMAGE", "podmotion-agent:test")

	scheme := adr0331Scheme(t)

	objs := []client.Object{pm, srcPod}
	objs = append(objs, extraObjs...)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(pm).
		Build()

	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()

	if err := r.createReplacementPod(ctx, pm, srcPod); err != nil {
		t.Fatalf("createReplacementPod: %v", err)
	}

	list := &corev1.PodList{}
	if err := fakeClient.List(ctx, list, client.InNamespace(pm.Spec.PodNamespace),
		client.MatchingLabels{replacementPodMigrationNameLabel: pm.Name}); err != nil {
		t.Fatalf("list replacement pod: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected exactly 1 replacement pod, got %d", len(list.Items))
	}
	return list.Items[0]
}

// scheme reuse note: adr0331Scheme (defined in adr0331_selector_label_preservation_test.go,
// same package) already registers pmv1/corev1/appsv1 — reused here rather than duplicated.

func newADR0359TestPM(destNodeName, targetNodeName string) *pmv1.PodMigration {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "adr0359-pm", Namespace: "pm-ns", UID: "adr0359-uid"},
		Spec: pmv1.PodMigrationSpec{
			PodName:        "src-pod",
			PodNamespace:   "pm-ns",
			TargetNodeName: targetNodeName,
		},
	}
	if destNodeName != "" {
		pm.Status.DestinationNodeName = destNodeName
	}
	return pm
}

// TestCreateReplacementPod_NeverSetsNodeName_WhenDestinationResolvedFromStatus is the
// core ADR-0359 regression: before the fix, this exact scenario (a normal migration
// where the scheduler has already resolved Status.DestinationNodeName before checkpoint
// staging completes) produced spec.NodeName = "node-b" on the replacement pod object
// — the gate-bypass conflict. After the fix, spec.NodeName must be empty; only the
// webhook + custom scheduler are permitted to bind the pod to a node.
func TestCreateReplacementPod_NeverSetsNodeName_WhenDestinationResolvedFromStatus(t *testing.T) {
	pm := newADR0359TestPM("node-b", "")
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "pm-ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "redis:7-alpine"}},
		},
	}

	got := buildAndFetchReplacementPod(t, pm, srcPod)

	if got.Spec.NodeName != "" {
		t.Errorf("replacement pod spec.NodeName = %q, want empty — the controller must never "+
			"pin NodeName directly (ADR-0359); the webhook scheduling gate + podmotion-scheduler "+
			"are the sole binding authority", got.Spec.NodeName)
	}
}

// TestCreateReplacementPod_NeverSetsNodeName_WhenDestinationResolvedFromSpecTargetNode
// covers the Spec.TargetNodeName fallback path (Status.DestinationNodeName empty), the
// second of the three resolution branches in createReplacementPod.
func TestCreateReplacementPod_NeverSetsNodeName_WhenDestinationResolvedFromSpecTargetNode(t *testing.T) {
	pm := newADR0359TestPM("", "node-b")
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "pm-ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "redis:7-alpine"}},
		},
	}

	got := buildAndFetchReplacementPod(t, pm, srcPod)

	if got.Spec.NodeName != "" {
		t.Errorf("replacement pod spec.NodeName = %q, want empty (Spec.TargetNodeName fallback path)", got.Spec.NodeName)
	}
}

// TestCreateReplacementPod_SourceNodeNameDoesNotLeakIntoReplacement is the mandatory
// closing condition every panelist (Arch-A, Arch-B, Security Reviewer, QA Lead) flagged
// as load-bearing: a LIVE source pod's spec.NodeName (the node it is currently running
// on) is present on sourcePod.Spec.DeepCopy(). Without an explicit zero, removing only
// the destination-NodeName pin would leave the replacement pod's spec.NodeName pinned
// to the SOURCE node instead — reproducing the identical gate-bypass, now aimed at the
// node the source workload is still live on (ADR-0012).
func TestCreateReplacementPod_SourceNodeNameDoesNotLeakIntoReplacement(t *testing.T) {
	pm := newADR0359TestPM("node-b", "")
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "pm-ns"},
		Spec: corev1.PodSpec{
			NodeName:   "node-a", // the live source pod is scheduled on node-a
			Containers: []corev1.Container{{Name: "app", Image: "redis:7-alpine"}},
		},
	}

	got := buildAndFetchReplacementPod(t, pm, srcPod)

	if got.Spec.NodeName != "" {
		t.Errorf("replacement pod spec.NodeName = %q, want empty — the source pod's own "+
			"NodeName (%q) must not leak through the deep copy and re-pin the replacement pod",
			got.Spec.NodeName, srcPod.Spec.NodeName)
	}
}

// TestCreateReplacementPod_ClearsStaleNodeSelectorAndAffinity_Unconditionally is the
// retained half of the ADR-0359 removal-symmetry audit: a source pod pinned to its own
// node via nodeSelector (or hard nodeAffinity) must still have that constraint cleared
// on the replacement pod, decoupled from the now-removed NodeName assignment it used to
// be bundled with — otherwise the replacement pod becomes Unschedulable at the
// destination (a different regression, not the one this ADR targets, but one the ADR's
// own audit requires not be introduced).
func TestCreateReplacementPod_ClearsStaleNodeSelectorAndAffinity_Unconditionally(t *testing.T) {
	pm := newADR0359TestPM("node-b", "")
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "pm-ns"},
		Spec: corev1.PodSpec{
			NodeSelector: map[string]string{"kubernetes.io/hostname": "node-a"},
			Affinity: &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{"node-a"},
							}},
						}},
					},
				},
			},
			Containers: []corev1.Container{{Name: "app", Image: "redis:7-alpine"}},
		},
	}

	got := buildAndFetchReplacementPod(t, pm, srcPod)

	if got.Spec.NodeSelector != nil {
		t.Errorf("replacement pod spec.NodeSelector = %v, want nil — a stale source-node "+
			"selector must not survive and strand the replacement pod as Unschedulable at the "+
			"destination", got.Spec.NodeSelector)
	}
	if got.Spec.Affinity != nil && got.Spec.Affinity.NodeAffinity != nil &&
		got.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
		t.Errorf("replacement pod spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = %v, want nil",
			got.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution)
	}
}

// TestCreateReplacementPod_TaintTolerationStillWorks_WithoutNodeNamePin proves the
// retained taint-toleration logic is unaffected by removing the NodeName pin: it reads
// destNode.Spec.Taints directly (via pm.Status.DestinationNodeName), never spec.NodeName,
// so a replacement pod destined for a tainted control-plane node still gets the
// matching toleration even though it is no longer bound there via NodeName.
func TestCreateReplacementPod_TaintTolerationStillWorks_WithoutNodeNamePin(t *testing.T) {
	pm := newADR0359TestPM("cp-node", "")
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "src-pod", Namespace: "pm-ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "redis:7-alpine"}},
		},
	}
	destNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "cp-node"},
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{{
				Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule,
			}},
		},
	}

	got := buildAndFetchReplacementPod(t, pm, srcPod, destNode)

	if got.Spec.NodeName != "" {
		t.Errorf("replacement pod spec.NodeName = %q, want empty even for a tainted destination node", got.Spec.NodeName)
	}
	found := false
	for _, tol := range got.Spec.Tolerations {
		if tol.Key == "node-role.kubernetes.io/control-plane" && tol.Effect == corev1.TaintEffectNoSchedule {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("replacement pod missing toleration for destination node's control-plane taint; tolerations = %+v", got.Spec.Tolerations)
	}
}
