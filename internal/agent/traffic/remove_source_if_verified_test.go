/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package traffic

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("pmv1.AddToScheme: %v", err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatalf("discoveryv1.AddToScheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}
	return scheme
}

func newSliceWithIP(namespace, name, ip string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{ip}},
		},
	}
}

func trafficVerifiedTrueConditions() []metav1.Condition {
	return []metav1.Condition{
		{Type: "TrafficVerified", Status: metav1.ConditionTrue, Reason: "ServiceVerified"},
		{Type: pmv1.ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue, Reason: "NoKnownProtocol"},
	}
}

// TestRemoveSourceIfVerified_HappyPathMutatesIdenticallyToRemoveSource asserts the no-op
// contract: when the canonical predicate permits removal, RemoveSourceIfVerified removes the
// source IP from the EndpointSlice exactly as bare RemoveSource would.
func TestRemoveSourceIfVerified_HappyPathMutatesIdenticallyToRemoveSource(t *testing.T) {
	scheme := newTestScheme(t)
	ns := "default"
	sourceIP := "10.0.0.1"

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-1", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
			SourcePodIP:         sourceIP,
		},
		Status: pmv1.PodMigrationStatus{
			Conditions: trafficVerifiedTrueConditions(),
		},
	}
	slice := newSliceWithIP(ns, "slice-1", sourceIP)

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, slice).WithStatusSubresource(pm).Build()
	m := NewEndpointSliceManager(c)

	// Pre-call: confirm presence so the assertion below is non-vacuous.
	present, err := m.HasEndpointForIP(context.Background(), ns, sourceIP)
	if err != nil || !present {
		t.Fatalf("precondition: expected source IP present pre-call, present=%v err=%v", present, err)
	}

	removed, err := m.RemoveSourceIfVerified(context.Background(), pm, ns, sourceIP)
	if err != nil {
		t.Fatalf("RemoveSourceIfVerified returned unexpected error: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 slice updated, got %d", removed)
	}

	present, err = m.HasEndpointForIP(context.Background(), ns, sourceIP)
	if err != nil {
		t.Fatalf("HasEndpointForIP: %v", err)
	}
	if present {
		t.Fatalf("expected source IP removed, but still present")
	}
}

// TestRemoveSourceIfVerified_BlocksAndDoesNotMutateWhenUnverified asserts the safety property:
// when the canonical predicate blocks removal (no TrafficVerified/WorkloadLivenessVerified),
// RemoveSourceIfVerified returns errSourceEndpointRemovalBlocked and mutates nothing.
func TestRemoveSourceIfVerified_BlocksAndDoesNotMutateWhenUnverified(t *testing.T) {
	scheme := newTestScheme(t)
	ns := "default"
	sourceIP := "10.0.0.2"

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-2", Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
			SourcePodIP:         sourceIP,
		},
		Status: pmv1.PodMigrationStatus{
			// No conditions set at all: TrafficVerified/WorkloadLivenessVerified both absent.
			Conditions: nil,
		},
	}
	slice := newSliceWithIP(ns, "slice-2", sourceIP)

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, slice).WithStatusSubresource(pm).Build()
	m := NewEndpointSliceManager(c)

	// Pre-call: confirm presence so "unmutated" below is a real observation, not vacuous.
	present, err := m.HasEndpointForIP(context.Background(), ns, sourceIP)
	if err != nil || !present {
		t.Fatalf("precondition: expected source IP present pre-call, present=%v err=%v", present, err)
	}

	removed, err := m.RemoveSourceIfVerified(context.Background(), pm, ns, sourceIP)
	if !errors.Is(err, errSourceEndpointRemovalBlocked) {
		t.Fatalf("expected errSourceEndpointRemovalBlocked, got removed=%d err=%v", removed, err)
	}
	if removed != 0 {
		t.Fatalf("expected 0 slices touched on block, got %d", removed)
	}

	present, err = m.HasEndpointForIP(context.Background(), ns, sourceIP)
	if err != nil {
		t.Fatalf("HasEndpointForIP: %v", err)
	}
	if !present {
		t.Fatalf("expected source IP to remain present after a blocked removal")
	}
}
