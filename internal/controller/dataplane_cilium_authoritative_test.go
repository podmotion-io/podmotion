/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// dataplane_cilium_authoritative_test.go — sprint46B2 substrate fix regression tests.
//
// The live redis Strict pm-w1->pm-w2 migration wedged at phase=CutoverComplete forever because
// DataplaneReachabilityVerified never resolved: its ADR-0210 producer drives a nonce round-trip
// dialed FROM the source-node agent, but ADR-0012 holds the source pod alive on the source node
// with the preserved IP, so the source node delivers that IP to its own local held pod and the
// round-trip can never match (structurally, on any substrate — see
// tryEstablishDataplaneReachability, renamed from the original Cilium-only
// tryEstablishCiliumDataplaneReachability when it was generalized to dispatch via
// CNIMobilitySelector). The fix reads cilium-agent's authoritative CiliumEndpoint
// status instead and retires the source-node probe on the Cilium cross-node path.
//
// These tests drive the CONTROLLER producer directly with AgentPool == nil — proving the condition
// is established WITHOUT any nonce round-trip — and pin the fail-closed reasons. They FAIL on the
// pre-fix baseline (which had no CiliumEndpoint-owns-IP producer and required the never-converging
// probe).

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

var testCiliumEndpointGVR = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumendpoints"}

// fakeCiliumEndpointObj mirrors cilium-agent's CiliumEndpoint status write-back for the
// replacement pod. ipv4 is the address cilium-agent recorded ("" -> no addressing entry).
func fakeCiliumEndpointObj(namespace, name, state string, identityID int64, node, ipv4 string) *unstructured.Unstructured {
	networking := map[string]interface{}{"node": node}
	if ipv4 != "" {
		networking["addressing"] = []interface{}{map[string]interface{}{"ipv4": ipv4}}
	}
	ce := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumEndpoint",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		"status": map[string]interface{}{
			"state":      state,
			"identity":   map[string]interface{}{"id": identityID},
			"networking": networking,
		},
	}}
	ce.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumEndpoint"})
	return ce
}

func ciliumNMC(node, cniPlugin string) *pmv1.NodeMigrationCapacity {
	return &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: node},
		Spec: pmv1.NodeMigrationCapacitySpec{
			NetworkCapability: pmv1.NetworkCapability{CNIPlugin: cniPlugin},
		},
	}
}

// strictCrossNodePM mirrors the live-proof-cycle2 CR: redis Strict, preserved IP 10.244.1.178,
// src=pm-w1, dest=pm-w2, replacement pod already restored on pm-w2.
func strictCrossNodePM(name, preservedIP, replPod string) *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "pm-live-proof-c2"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "redis-src",
			PodNamespace:        "pm-live-proof-c2",
			SourcePodIP:         preservedIP,
			TargetNodeName:      "pm-w2",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseServiceVerifying,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  replPod,
		},
	}
}

// reconcilerForDataplane builds a PodMigrationReconciler wired with a controller-runtime fake client
// (holding pm + nmc) and a fake dynamic client (holding the CiliumEndpoint objects). AgentPool is
// deliberately left nil — the authoritative read must NOT depend on any agent RPC.
func reconcilerForDataplane(t *testing.T, pm *pmv1.PodMigration, nmc *pmv1.NodeMigrationCapacity, ce ...runtime.Object) *PodMigrationReconciler {
	t.Helper()
	scheme := adr0210Scheme(t)
	cb := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm)
	if nmc != nil {
		cb = cb.WithObjects(nmc)
	}
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{testCiliumEndpointGVR: "CiliumEndpointList"},
		ce...,
	)
	return &PodMigrationReconciler{Client: cb.Build(), Scheme: scheme, DynamicClient: dc /* AgentPool: nil */}
}

// TestTryEstablish_Cilium_CrossNode_ConfirmsFromAuthoritativeRead: the load-bearing positive case.
// With a Cilium NMC and a CiliumEndpoint that is ready and owns the preserved IP, the producer sets
// DataplaneReachabilityVerified=True (reason CiliumDataplaneProgrammed), handled=true, done=true —
// with AgentPool nil, proving NO source-node nonce round-trip was used.
func TestTryEstablish_Cilium_CrossNode_ConfirmsFromAuthoritativeRead(t *testing.T) {
	const preservedIP = "10.244.1.178"
	const replPod = "redis-src-m-5604a0fb"
	pm := strictCrossNodePM("live-proof-c2-mig1", preservedIP, replPod)
	r := reconcilerForDataplane(t, pm, ciliumNMC("pm-w2", "cilium"),
		fakeCiliumEndpointObj("pm-live-proof-c2", replPod, "ready", 12345, "203.0.113.243", preservedIP))

	res, err, done, handled := r.tryEstablishDataplaneReachability(context.Background(), pm, "pm-w2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handled {
		t.Fatalf("Cilium cross-node destination must be handled by the authoritative read, not fall through")
	}
	if !done {
		t.Fatalf("authoritative read of a ready endpoint owning the preserved IP must confirm (done=true); res=%+v", res)
	}
	c := meta.FindStatusCondition(pm.Status.Conditions, string(pmv1.ConditionDataplaneReachabilityVerified))
	if c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("DataplaneReachabilityVerified must be True; got %+v", c)
	}
	if c.Reason != pmv1.ReasonCiliumDataplaneProgrammed {
		t.Fatalf("reason must be %q (authoritative Cilium read), got %q", pmv1.ReasonCiliumDataplaneProgrammed, c.Reason)
	}
}

// TestTryEstablish_Cilium_WrongIP_FailsClosed: ADR-0324 verification check C. A ready endpoint that received a
// DIFFERENT IP (pin not honored) must fail closed (done=false, condition False,
// PreservedIPNotOnCiliumEndpoint) — never falsely credit a dataplane that did not move the IP.
func TestTryEstablish_Cilium_WrongIP_FailsClosed(t *testing.T) {
	const preservedIP = "10.244.1.178"
	const replPod = "redis-src-m-5604a0fb"
	pm := strictCrossNodePM("live-proof-c2-mig1", preservedIP, replPod)
	r := reconcilerForDataplane(t, pm, ciliumNMC("pm-w2", "cilium"),
		fakeCiliumEndpointObj("pm-live-proof-c2", replPod, "ready", 12345, "203.0.113.243", "10.244.2.99"))

	_, _, done, handled := r.tryEstablishDataplaneReachability(context.Background(), pm, "pm-w2")
	if !handled {
		t.Fatalf("Cilium cross-node destination must be handled")
	}
	if done {
		t.Fatalf("must NOT confirm when the ready endpoint advertises a different IP than the preserved one")
	}
	c := meta.FindStatusCondition(pm.Status.Conditions, string(pmv1.ConditionDataplaneReachabilityVerified))
	if c == nil || c.Status != metav1.ConditionFalse {
		t.Fatalf("DataplaneReachabilityVerified must be False (fail-closed); got %+v", c)
	}
	if c.Reason != pmv1.ReasonPreservedIPNotOnEndpoint {
		t.Fatalf("reason must be %q; got %q", pmv1.ReasonPreservedIPNotOnEndpoint, c.Reason)
	}
}

// TestTryEstablish_NoAuthoritativeProducer_FallsThrough: a destination CNI with no authoritative
// producer wired (Flannel — no IPHandoffStrategy readiness signal today) is not handled here — the
// caller falls back to the ADR-0210 producer. No condition is set by this function.
func TestTryEstablish_NoAuthoritativeProducer_FallsThrough(t *testing.T) {
	pm := strictCrossNodePM("live-proof-c2-mig1", "10.244.1.178", "redis-src-m-5604a0fb")
	r := reconcilerForDataplane(t, pm, ciliumNMC("pm-w2", "flannel"))

	_, _, _, handled := r.tryEstablishDataplaneReachability(context.Background(), pm, "pm-w2")
	if handled {
		t.Fatalf("a CNI with no authoritative producer wired must fall through (handled=false) to verifyDataplaneReachability")
	}
	if c := meta.FindStatusCondition(pm.Status.Conditions, string(pmv1.ConditionDataplaneReachabilityVerified)); c != nil {
		t.Fatalf("fall-through must not set the condition here; got %+v", c)
	}
}

// TestTryEstablish_SameNode_FallsThrough: a same-node migration falls through to the ADR-0237
// vacuous path, not the cross-node authoritative read.
func TestTryEstablish_SameNode_FallsThrough(t *testing.T) {
	pm := strictCrossNodePM("live-proof-c2-mig1", "10.244.1.178", "redis-src-m-5604a0fb")
	pm.Status.SourceNodeName = "pm-w2" // src == dest -> same node
	r := reconcilerForDataplane(t, pm, ciliumNMC("pm-w2", "cilium"))

	_, _, _, handled := r.tryEstablishDataplaneReachability(context.Background(), pm, "pm-w2")
	if handled {
		t.Fatalf("same-node migration must fall through (handled=false) to the ADR-0237 vacuous path")
	}
}
