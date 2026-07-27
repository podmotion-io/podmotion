/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0352_servicecontinuity_test.go — ADR-0352 D5.4 coverage:
//
//   - TestMarkDestinationReadyIfConverged_FiresWhenBothConvergenceSignalsTrue: with
//     WorkloadLivenessVerified=True and CRIURestoreConfirmed present-and-true, the D0.1
//     write-back actually flips the destination endpoint's Ready bit.
//   - TestMarkDestinationReadyIfConverged_DoesNotFireWithoutCRIURestoreConfirmed: the
//     Stop-here safety #1 regression guard (Architect B) — CRIURestoreConfirmed nil/false
//     must NOT let the write-back fire even if WorkloadLivenessVerified is somehow True,
//     because that would flip Ready=true on a restored-but-not-liveness-proven pod.
//   - TestEstablishServiceContinuity_HeadlessService_FailsClosed: ADR-0352 D0.2 option (b)
//     — a headless Service (clusterIP: None) gets an explicit fail-closed
//     ServiceContinuityVerified=False/HeadlessServiceUnsupported, never an unwired poll.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

func destSliceReadyFalse(ns, name, destIP string) *discoveryv1.EndpointSlice {
	notReady := false
	return &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: name, Namespace: ns},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{destIP}, Conditions: discoveryv1.EndpointConditions{Ready: &notReady}},
		},
	}
}

func isReady(t *testing.T, c client.Client, ns, sliceName, ip string) bool {
	t.Helper()
	fresh := &discoveryv1.EndpointSlice{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: sliceName}, fresh); err != nil {
		t.Fatalf("re-Get EndpointSlice: %v", err)
	}
	for _, ep := range fresh.Endpoints {
		for _, addr := range ep.Addresses {
			if addr == ip {
				return ep.Conditions.Ready != nil && *ep.Conditions.Ready
			}
		}
	}
	return false
}

func TestMarkDestinationReadyIfConverged_FiresWhenBothConvergenceSignalsTrue(t *testing.T) {
	scheme := adr0210Scheme(t)
	ns := "default"
	destIP := "10.244.1.7"
	slice := destSliceReadyFalse(ns, "slice-dest", destIP)

	confirmed := true
	node, replPod := "pm-w2", "dest-repl"
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-d01-pos", Namespace: ns},
		Spec:       pmv1.PodMigrationSpec{PodName: "src", PodNamespace: ns},
		Status: pmv1.PodMigrationStatus{
			DestinationNodeName:  node,
			ReplacementPodName:   replPod,
			CRIURestoreConfirmed: &confirmed,
			Conditions: []metav1.Condition{
				{Type: pmv1.ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue, Reason: "ExplicitProbePassed"},
			},
		},
	}

	// ADR-0405: the write-back now also requires the destination CNI's own confirmation that the
	// replacement endpoint is programmed and advertises destIP. Wire a ready CiliumEndpoint so the
	// full three-signal gate is satisfied (the two-signal-only case is covered by the ADR-0405 held
	// tests in adr0405_ready_gate_test.go). Helpers ciliumNMC/fakeCiliumEndpointObj/
	// testCiliumEndpointGVR come from dataplane_cilium_authoritative_test.go.
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(slice, pm, ciliumNMC(node, "cilium")).WithStatusSubresource(pm).Build()
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{testCiliumEndpointGVR: "CiliumEndpointList"},
		fakeCiliumEndpointObj(ns, replPod, "ready", 4242, node, destIP),
	)
	r := &PodMigrationReconciler{Client: c, Scheme: scheme, DynamicClient: dc}

	r.markDestinationReadyIfConverged(context.Background(), pm, destIP)

	if !isReady(t, c, ns, "slice-dest", destIP) {
		t.Fatalf("expected destination endpoint Ready=true: liveness + CRIURestoreConfirmed + CNI-programmed destIP should fire the write-back")
	}
}

func TestMarkDestinationReadyIfConverged_DoesNotFireWithoutCRIURestoreConfirmed(t *testing.T) {
	// Stop-here safety #1 regression guard (Architect B): liveness alone (or restore-confirm
	// alone) must never be sufficient — both signals are required, controller-side.
	scheme := adr0210Scheme(t)
	ns := "default"
	destIP := "10.244.1.8"
	slice := destSliceReadyFalse(ns, "slice-dest-2", destIP)

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-d01-neg", Namespace: ns},
		Spec:       pmv1.PodMigrationSpec{PodName: "src", PodNamespace: ns},
		Status: pmv1.PodMigrationStatus{
			// CRIURestoreConfirmed deliberately nil (agent has not yet confirmed restore —
			// e.g. NRI/AC5 path, ADR-0123 D2 step 5).
			Conditions: []metav1.Condition{
				{Type: pmv1.ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue, Reason: "ExplicitProbePassed"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(slice, pm).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	r.markDestinationReadyIfConverged(context.Background(), pm, destIP)

	if isReady(t, c, ns, "slice-dest-2", destIP) {
		t.Fatalf("expected destination endpoint to remain Ready=false: CRIURestoreConfirmed nil must block the D0.1 write-back (premature-enrollment guard)")
	}
}

func TestEstablishServiceContinuity_HeadlessService_FailsClosed(t *testing.T) {
	scheme := adr0210Scheme(t)
	ns := "default"
	destIP := "10.244.1.9"

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "headless-svc", Namespace: ns},
		Spec:       corev1.ServiceSpec{ClusterIP: "None"},
	}
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: "slice-headless", Namespace: ns, Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{destIP}}},
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-headless", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src",
			PodNamespace:        ns,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc, slice, pm).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	_, err, done := r.establishServiceContinuity(context.Background(), pm, destIP)
	if err != nil {
		t.Fatalf("establishServiceContinuity: %v", err)
	}
	if !done {
		t.Fatalf("expected done=true (explicit fail-closed disposition, not an unwired poll)")
	}
	cond := findCondition(pm.Status.Conditions, pmv1.ConditionServiceContinuityVerified)
	if cond == nil {
		t.Fatalf("expected ConditionServiceContinuityVerified to be set")
	}
	if cond.Status != metav1.ConditionFalse || cond.Reason != "HeadlessServiceUnsupported" {
		t.Fatalf("expected ServiceContinuityVerified=False/HeadlessServiceUnsupported, got status=%s reason=%s", cond.Status, cond.Reason)
	}
}

// TestReconcileVerifying_Strict_NeverInvokesRetiredProducers is the ADR-0352 D3 scope-gap
// regression (DR-4 is path-agnostic — it does not carve out the legacy reconcileVerifying
// phase). Under Strict mode, reconcileVerifying must divert to establishServiceContinuity
// (the D1 primitive) instead of injectIPHandoff, so it can NEVER set
// DataplaneReachabilityVerified=False (the retired producers' only write). No Service/
// EndpointSlice fixture is wired, so ServiceContinuityVerified cannot converge either —
// the migration must simply HOLD (requeue), never crash, never fall through to the retired
// producers, and never advance past TrafficVerified alone.
func TestReconcileVerifying_Strict_NeverInvokesRetiredProducers(t *testing.T) {
	scheme := adr0210Scheme(t)
	ns := "default"

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-dst", Namespace: ns},
		Spec:       corev1.PodSpec{NodeName: "node-b"},
		Status:     corev1.PodStatus{PodIP: "10.244.3.1"},
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-legacy-strict", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "legacy-src",
			PodNamespace:        ns,
			SourcePodIP:         "10.244.1.1",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseVerifying,
			SourceNodeName:      "node-a",
			DestinationNodeName: "node-b",
			ReplacementPodName:  "legacy-dst",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, destPod).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	res, err := r.reconcileVerifying(context.Background(), pm)
	if err != nil {
		t.Fatalf("reconcileVerifying: %v", err)
	}
	if res.RequeueAfter <= 0 && !res.Requeue {
		t.Fatalf("expected a bounded requeue (hold) with no Service fixture wired, got %+v", res)
	}
	if cond := findCondition(pm.Status.Conditions, pmv1.ConditionDataplaneReachabilityVerified); cond != nil {
		t.Fatalf("DR-4 regression: reconcileVerifying under Strict must NEVER set DataplaneReachabilityVerified (the retired producers' only write); got %+v", cond)
	}
	if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionTrafficVerified) {
		t.Fatalf("Strict must not advance past TrafficVerified alone — ServiceContinuityVerified never converged")
	}
	fresh := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pm), fresh); err != nil {
		t.Fatalf("re-Get PodMigration: %v", err)
	}
	// ADR-0352 B8-D3 round-2 correction: hand off to DisengageHold (not TCPVerifying
	// directly) so a CR entering via this legacy tail also traverses the zero-window
	// disarm barrier before ever reaching TCPVerifying — see the production comment on
	// this hand-off.
	if fresh.Status.Phase != pmv1.MigrationPhaseDisengageHold {
		t.Fatalf("ADR-0352 B8-D3: Strict reconcileVerifying must hand off to DisengageHold, got phase=%q", fresh.Status.Phase)
	}
}

// TestEstablishServiceContinuity_NoServiceSelectsPod_TriviallySatisfied is the ADR-0390
// regression test for §P-MECHANISM's stuck-ServiceVerifying finding: a pod that no Service in
// its namespace ever selects (e.g. a standalone pod with no owning Service — the live
// podmotion-demo-6vf5f/default/nginx case) must NOT requeue establishServiceContinuity
// indefinitely waiting for an EndpointSlice that will never exist. Because no EndpointSlice will
// ever carry destPodIP with a Service label, resolveTargetService always returns
// errNoEndpointSliceServiceLabelYet; anyServiceSelectsPod must recognize — from the real source
// of truth (Service selectors vs. the pod's own labels), not from EndpointSlice population — that
// this is permanent, not transient, and set ServiceContinuityVerified=True immediately (vacuous
// pass: nothing routes to this pod via a Service, so Strict's Service-continuity guarantee is
// trivially satisfied over an empty set — mirrors ADR-0388's zero-TCP-connection disposition).
func TestEstablishServiceContinuity_NoServiceSelectsPod_TriviallySatisfied(t *testing.T) {
	scheme := adr0210Scheme(t)
	ns := "default"
	destIP := "10.42.2.117"

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-m-117e6b9f", Namespace: ns,
			Labels: map[string]string{"run": "nginx"}},
		Status: corev1.PodStatus{PodIP: destIP},
	}
	// Deliberately NO EndpointSlice and NO Service selecting {"run": "nginx"} anywhere in the
	// namespace — the exact live condition (verified via kubectl: no Service anywhere selects
	// this pod's labels).
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-no-service", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "nginx",
			PodNamespace:        ns,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			ReplacementPodName: "nginx-m-117e6b9f",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(destPod, pm).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	res, err, done := r.establishServiceContinuity(context.Background(), pm, destIP)
	if err != nil {
		t.Fatalf("establishServiceContinuity: %v", err)
	}
	if !done {
		t.Fatalf("expected done=true (permanent disposition recognized immediately), got requeue %+v — this is the exact indefinite-requeue-until-deadline-backstop bug ADR-0390 fixes", res)
	}
	cond := findCondition(pm.Status.Conditions, pmv1.ConditionServiceContinuityVerified)
	if cond == nil {
		t.Fatalf("expected ConditionServiceContinuityVerified to be set")
	}
	if cond.Status != metav1.ConditionTrue || cond.Reason != "NoServiceSelectsPod" {
		t.Fatalf("expected ServiceContinuityVerified=True/NoServiceSelectsPod, got status=%s reason=%s", cond.Status, cond.Reason)
	}
}

// TestEstablishServiceContinuity_ServiceSelectsPodButSliceNotConverged_StillHolds is the negative
// control for the ADR-0390 fix: when a real Service DOES select the pod's labels but its
// EndpointSlice simply has not caught up yet, establishServiceContinuity must keep requeuing
// (transient), never mistake this for the permanent no-Service case above.
func TestEstablishServiceContinuity_ServiceSelectsPodButSliceNotConverged_StillHolds(t *testing.T) {
	scheme := adr0210Scheme(t)
	ns := "default"
	destIP := "10.42.2.200"

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-m-2", Namespace: ns,
			Labels: map[string]string{"run": "nginx"}},
		Status: corev1.PodStatus{PodIP: destIP},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-svc", Namespace: ns},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"run": "nginx"}, ClusterIP: "10.96.5.5"},
	}
	// Deliberately no EndpointSlice at all yet — the EndpointSlice controller hasn't converged.
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-service-pending", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "nginx",
			PodNamespace:        ns,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			ReplacementPodName: "nginx-m-2",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(destPod, svc, pm).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme}

	_, err, done := r.establishServiceContinuity(context.Background(), pm, destIP)
	if err != nil {
		t.Fatalf("establishServiceContinuity: %v", err)
	}
	if done {
		t.Fatalf("expected done=false (transient — a Service selects this pod, must keep waiting for its EndpointSlice), got done=true")
	}
	if cond := findCondition(pm.Status.Conditions, pmv1.ConditionServiceContinuityVerified); cond != nil {
		t.Fatalf("ServiceContinuityVerified must remain unset while transient, got %+v", cond)
	}
}

func findCondition(conds []metav1.Condition, t string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

// TestReconcileVerifying_Strict_FullPredicateSet_ReachesCompleteThroughGate — ADR-0352
// B8-DR-3(c). Because B8-D3 makes Strict bypass reconcileVerifying's completion logic
// entirely (hand-off at the top of the function), this is a non-Strict (None-mode) exercise
// of the pre-existing legacy completion path — confirming it still reaches Complete and
// actually deletes the source pod through deleteSourcePodIfSafe, unaffected by the Strict
// hand-off (B8-DR-7). Mode=None sets conditionTrafficVerified=True directly (no TrafficVerifier
// needed) on the first reconcile pass but that pass always returns before reaching the
// deletion gates (the `if !trafficVerified {...}` block returns unconditionally at its end) —
// so this test drives two passes: pass 1 sets TrafficVerified=True and persists it, pass 2
// (against the re-fetched object) proceeds through DestinationVolumeReady/PDB/ResourceQuota/
// WorkloadLivenessVerified and deleteSourcePodIfSafe to MigrationPhaseComplete.
func TestReconcileVerifying_Strict_FullPredicateSet_ReachesCompleteThroughGate(t *testing.T) {
	scheme := adr0210Scheme(t)
	ns := "default"

	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-src", Namespace: ns},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{PodIP: ""},
	}
	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-dst2", Namespace: ns},
		Spec:       corev1.PodSpec{NodeName: "node-b"},
		Status:     corev1.PodStatus{PodIP: "10.244.3.2"},
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-legacy-none", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "legacy-src",
			PodNamespace:        ns,
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
			// SourcePodIP deliberately empty: gates the EndpointSlice/agent-cleanup
			// side paths off (unrelated to this test's B8-D3 completion-path assertion).
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseVerifying,
			SourceNodeName:      "node-a",
			DestinationNodeName: "node-b",
			ReplacementPodName:  "legacy-dst2",
			Conditions: []metav1.Condition{
				{Type: pmv1.ConditionServiceContinuityVerified, Status: metav1.ConditionTrue, Reason: "Converged", LastTransitionTime: metav1.Now()},
				{Type: pmv1.ConditionTCPSequenceContinuityVerified, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: metav1.Now()},
				{Type: pmv1.ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue, Reason: "NoKnownProtocol", LastTransitionTime: metav1.Now()},
				{Type: conditionDestinationVolumeReady, Status: metav1.ConditionTrue, Reason: "VolumeAttached", LastTransitionTime: metav1.Now()},
				{Type: conditionDataplaneReachabilityVerified, Status: metav1.ConditionTrue, Reason: "Legacy", LastTransitionTime: metav1.Now()},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, srcPod, destPod).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme} // r.TrafficVerifier left nil deliberately

	// Pass 1: trafficVerified starts false -> None-mode branch sets
	// IPHandoffInjected+TrafficVerified=True and returns (Requeue: true) before reaching the
	// deletion gates below in the same call.
	if _, err := r.reconcileVerifying(context.Background(), pm); err != nil {
		t.Fatalf("reconcileVerifying pass 1: %v", err)
	}
	afterPass1 := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pm), afterPass1); err != nil {
		t.Fatalf("re-Get after pass 1: %v", err)
	}
	if !meta.IsStatusConditionTrue(afterPass1.Status.Conditions, conditionTrafficVerified) {
		t.Fatalf("ADR-0352 B8-DR-3(c)(a): pass 1 must set TrafficVerified=True (None mode), got conditions=%+v", afterPass1.Status.Conditions)
	}

	// Pass 2: trafficVerified now true on the re-fetched object -> proceeds through the
	// deletion gates to deleteSourcePodIfSafe and on to MigrationPhaseComplete.
	if _, err := r.reconcileVerifying(context.Background(), afterPass1); err != nil {
		t.Fatalf("reconcileVerifying pass 2: %v", err)
	}

	fresh := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pm), fresh); err != nil {
		t.Fatalf("re-Get after pass 2: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseComplete {
		t.Fatalf("ADR-0352 B8-DR-3(c)(b): expected MigrationPhaseComplete, got %q", fresh.Status.Phase)
	}
	freshSrcPod := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "legacy-src"}, freshSrcPod); !errors.IsNotFound(err) {
		t.Fatalf("ADR-0352 B8-DR-3(c)(b): expected source pod legacy-src to be deleted (NotFound), got err=%v", err)
	}
}
