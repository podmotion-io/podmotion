/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// dataplane_calico_authoritative_test.go — generalization regression tests (CALICO-COMPATIBILITY
// sprint). tryEstablishDataplaneReachability previously hardcoded a Cilium-only string check
// (strings.Contains(cniPlugin, "cilium")) and directly constructed iphandoff.CiliumHandoff{},
// bypassing CNIMobilitySelector and the already-written CalicoHandoff entirely — a cross-node
// Calico migration would fall through to the ADR-0210 nonce round-trip, which is structurally
// blind to cross-node reachability while the source pod is held (see the
// tryEstablishDataplaneReachability doc comment).
//
// These tests drive the CONTROLLER producer directly with AgentPool == nil on a Calico
// destination, proving the generalized selector-dispatch establishes the condition from
// CalicoHandoff.WaitForWorkloadEndpointReady — the authoritative "Felix programmed the
// dataplane" read — instead of the never-converging source-node probe.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// reconcilerForCalicoDataplane builds a PodMigrationReconciler wired with a controller-runtime
// fake client (holding pm + nmc) and a typed fake clientset (holding the replacement pod).
// AgentPool is deliberately left nil — the authoritative read must NOT depend on any agent RPC.
func reconcilerForCalicoDataplane(t *testing.T, pm *pmv1.PodMigration, nmc *pmv1.NodeMigrationCapacity, pods ...*corev1.Pod) *PodMigrationReconciler {
	t.Helper()
	scheme := adr0210Scheme(t)
	cb := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm)
	if nmc != nil {
		cb = cb.WithObjects(nmc)
	}
	kubeObjs := make([]runtime.Object, 0, len(pods))
	for _, p := range pods {
		kubeObjs = append(kubeObjs, p)
	}
	kc := kubefake.NewSimpleClientset(kubeObjs...)
	return &PodMigrationReconciler{Client: cb.Build(), Scheme: scheme, KubeClient: kc /* AgentPool: nil */}
}

// TestTryEstablish_Calico_CrossNode_ConfirmsFromAuthoritativeRead: the load-bearing positive case.
// With a Calico NMC and a replacement pod that already has an IP assigned (Felix has processed
// it), the generalized producer dispatches via CNIMobilitySelector to CalicoHandoff and sets
// DataplaneReachabilityVerified=True (reason CalicoDataplaneProgrammed), handled=true, done=true —
// with AgentPool nil, proving NO source-node nonce round-trip was used.
func TestTryEstablish_Calico_CrossNode_ConfirmsFromAuthoritativeRead(t *testing.T) {
	const preservedIP = "10.244.1.178"
	const replPod = "nginx-src-m-5604a0fb"
	pm := strictCrossNodePM("live-proof-calico-mig1", preservedIP, replPod)
	pm.Spec.PodNamespace = "pm-live-proof-calico"
	pm.Namespace = "pm-live-proof-calico"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: replPod, Namespace: "pm-live-proof-calico"},
		Status:     corev1.PodStatus{PodIP: preservedIP},
	}
	r := reconcilerForCalicoDataplane(t, pm, ciliumNMC("pm-w2", "calico"), pod)

	res, err, done, handled := r.tryEstablishDataplaneReachability(context.Background(), pm, "pm-w2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handled {
		t.Fatalf("Calico cross-node destination must be handled by the authoritative read, not fall through")
	}
	if !done {
		t.Fatalf("authoritative read of an active Calico WorkloadEndpoint must confirm (done=true); res=%+v", res)
	}
	c := meta.FindStatusCondition(pm.Status.Conditions, string(pmv1.ConditionDataplaneReachabilityVerified))
	if c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("DataplaneReachabilityVerified must be True; got %+v", c)
	}
	if c.Reason != pmv1.ReasonCalicoDataplaneProgrammed {
		t.Fatalf("reason must be %q (authoritative Calico read), got %q", pmv1.ReasonCalicoDataplaneProgrammed, c.Reason)
	}
}
