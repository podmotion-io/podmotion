/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0405_ready_gate_test.go — ADR-0405 coverage: markDestinationReadyIfConverged must gate the
// EndpointSlice Ready flip fail-closed on the destination CNI's own source-of-truth write-back that
// the replacement endpoint is programmed and advertises destPodIP (the exact IP being enrolled as a
// Ready Service backend). WorkloadLivenessVerified+CRIURestoreConfirmed are necessary but NOT
// sufficient: flipping Ready — the bit Cilium consumes to select a VIP-DNAT backend — before the CNI
// has made the backend cluster-routable is the §5.3a fail-open that produced the ServiceVerifying
// EHOSTUNREACH hang. These tests prove the third precondition holds the flip until the CiliumEndpoint
// confirms.
//
// Reuses helpers from dataplane_cilium_authoritative_test.go: ciliumNMC, fakeCiliumEndpointObj,
// testCiliumEndpointGVR.

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// readyGateReconciler builds a reconciler holding the EndpointSlice + PodMigration + NMC in the
// controller-runtime fake client, and the given CiliumEndpoint objects in a fake dynamic client.
func readyGateReconciler(t *testing.T, pm *pmv1.PodMigration, nmc *pmv1.NodeMigrationCapacity, slice client.Object, ce ...runtime.Object) *PodMigrationReconciler {
	t.Helper()
	scheme := adr0210Scheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, nmc, slice).WithStatusSubresource(pm).Build()
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{testCiliumEndpointGVR: "CiliumEndpointList"},
		ce...,
	)
	return &PodMigrationReconciler{Client: c, Scheme: scheme, DynamicClient: dc}
}

func readyGatePM(name, ns, node, replPod string) *pmv1.PodMigration {
	confirmed := true
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
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
}

// TestMarkDestinationReady_HeldUntilCiliumEndpointProgrammed: liveness + restore true, but the
// CiliumEndpoint is still regenerating (not ready). Ready must NOT flip — fail-closed hold.
func TestMarkDestinationReady_HeldUntilCiliumEndpointProgrammed(t *testing.T) {
	ns, destIP, node, replPod := "default", "10.244.2.55", "pm-w2", "postgres-repl-m-abc"
	slice := destSliceReadyFalse(ns, "slice-held", destIP)
	pm := readyGatePM("pm-0405-held", ns, node, replPod)
	r := readyGateReconciler(t, pm, ciliumNMC(node, "cilium"), slice,
		fakeCiliumEndpointObj(ns, replPod, "regenerating", 4242, node, destIP))

	r.markDestinationReadyIfConverged(context.Background(), pm, destIP)

	if isReady(t, r.Client, ns, "slice-held", destIP) {
		t.Fatalf("Ready must stay false while the CiliumEndpoint is not yet programmed (fail-closed hold)")
	}
}

// TestMarkDestinationReady_FiresOnceCiliumEndpointAdvertisesDestIP: the full three-signal gate —
// liveness + restore + CiliumEndpoint ready advertising destPodIP — flips Ready. Keying on the
// replacement's actually-assigned destIP (not the retired SourcePodIP pin) is exactly why this
// latches under cluster-pool IPAM.
func TestMarkDestinationReady_FiresOnceCiliumEndpointAdvertisesDestIP(t *testing.T) {
	ns, destIP, node, replPod := "default", "10.244.2.55", "pm-w2", "postgres-repl-m-abc"
	slice := destSliceReadyFalse(ns, "slice-fires", destIP)
	pm := readyGatePM("pm-0405-fires", ns, node, replPod)
	r := readyGateReconciler(t, pm, ciliumNMC(node, "cilium"), slice,
		fakeCiliumEndpointObj(ns, replPod, "ready", 4242, node, destIP))

	r.markDestinationReadyIfConverged(context.Background(), pm, destIP)

	if !isReady(t, r.Client, ns, "slice-fires", destIP) {
		t.Fatalf("Ready must flip once all three signals hold (liveness + restore + CNI-programmed destIP)")
	}
}

// TestMarkDestinationReady_HeldOnWrongIPDecidedNegative: the CiliumEndpoint is ready but advertises a
// DIFFERENT IP (decided fail-closed negative). Ready must NOT flip — the endpoint the LB would route
// to does not own destIP.
func TestMarkDestinationReady_HeldOnWrongIPDecidedNegative(t *testing.T) {
	ns, destIP, node, replPod := "default", "10.244.2.55", "pm-w2", "postgres-repl-m-abc"
	slice := destSliceReadyFalse(ns, "slice-wrongip", destIP)
	pm := readyGatePM("pm-0405-wrongip", ns, node, replPod)
	r := readyGateReconciler(t, pm, ciliumNMC(node, "cilium"), slice,
		fakeCiliumEndpointObj(ns, replPod, "ready", 4242, node, "10.244.2.99"))

	r.markDestinationReadyIfConverged(context.Background(), pm, destIP)

	if isReady(t, r.Client, ns, "slice-wrongip", destIP) {
		t.Fatalf("Ready must stay false when the ready CiliumEndpoint advertises a different IP (decided fail-closed)")
	}
}

// TestConfirmEndpointReadyAdvertisesIP_NoProducerCNI_PreservesBehavior: on a CNI with no
// authoritative endpoint-programming producer (flannel), the primitive returns (true,nil) so the
// pre-ADR-0405 flip-on-liveness behavior is preserved rather than adding a gate we cannot honor.
func TestConfirmEndpointReadyAdvertisesIP_NoProducerCNI_PreservesBehavior(t *testing.T) {
	ns, destIP, node, replPod := "default", "10.244.2.55", "pm-w2", "postgres-repl-m-abc"
	pm := readyGatePM("pm-0405-noproducer", ns, node, replPod)
	r := readyGateReconciler(t, pm, ciliumNMC(node, "flannel"), destSliceReadyFalse(ns, "slice-np", destIP))

	ok, err := r.confirmEndpointReadyAdvertisesIP(context.Background(), pm, destIP)
	if err != nil {
		t.Fatalf("no-producer CNI must not error; got: %v", err)
	}
	if !ok {
		t.Fatalf("no-producer CNI must return ok=true (preserve pre-ADR-0405 behavior, no gate we cannot honor)")
	}
}
