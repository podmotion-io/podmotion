/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package traffic

import (
	"context"
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// mark_destination_ready_test.go — ADR-0352 D5.4 fake-client coverage for the D0.1
// write-back primitive: MarkDestinationReady (endpoints.go:113) was dead code since
// introduction (zero call sites) — this pins its actual behavior now that
// internal/controller wires it (servicecontinuity.go: markDestinationReadyIfConverged).

// TestMarkDestinationReady_FlipsReadyAndUnblocksVerify asserts the full D0.1/D1.1 chain
// in the traffic package alone: a destination endpoint seeded with Ready=false (matching
// AddDestination's landed destReady=false insert) has its Ready bit flipped by
// MarkDestinationReady, and EndpointSliceVerifierImpl.Verify — the same Ready-gate D1.1
// reads — then returns nil (the gate the write-back was meant to unblock).
func TestMarkDestinationReady_FlipsReadyAndUnblocksVerify(t *testing.T) {
	scheme := newTestScheme(t)
	ns := "default"
	destIP := "10.244.1.7"
	notReady := false

	slice := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: "slice-dest", Namespace: ns},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{destIP}, Conditions: discoveryv1.EndpointConditions{Ready: &notReady}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(slice).Build()
	m := NewEndpointSliceManager(c)
	ctx := context.Background()

	// Precondition: Verify must fail (fast, bounded) while Ready=false — non-vacuous check.
	preErr := (&EndpointSliceVerifierImpl{Manager: m}).Verify(ctx, VerifyRequest{
		Namespace: ns, DestPodIP: destIP, TimeoutSeconds: 1, PollIntervalSeconds: 1,
	})
	if preErr == nil {
		t.Fatalf("precondition: expected Verify to fail while Ready=false, got nil")
	}

	if err := m.MarkDestinationReady(ctx, ns, destIP); err != nil {
		t.Fatalf("MarkDestinationReady: %v", err)
	}

	fresh := &discoveryv1.EndpointSlice{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(slice), fresh); err != nil {
		t.Fatalf("re-Get EndpointSlice: %v", err)
	}
	found := false
	for _, ep := range fresh.Endpoints {
		for _, addr := range ep.Addresses {
			if addr == destIP {
				found = true
				if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
					t.Fatalf("expected destination endpoint Ready=true after MarkDestinationReady, got %v", ep.Conditions.Ready)
				}
			}
		}
	}
	if !found {
		t.Fatalf("destination endpoint %s not found in EndpointSlice after MarkDestinationReady", destIP)
	}

	// The gate D0.1 was built to unblock: Verify must now return nil.
	postErr := (&EndpointSliceVerifierImpl{Manager: m}).Verify(ctx, VerifyRequest{
		Namespace: ns, DestPodIP: destIP, TimeoutSeconds: 1, PollIntervalSeconds: 1,
	})
	if postErr != nil {
		t.Fatalf("expected Verify to succeed after MarkDestinationReady, got: %v", postErr)
	}
}
