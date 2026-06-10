/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package traffic

import (
	"context"
	"fmt"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EndpointSliceManager handles the EndpointSlice transition during migration cutover.
//
// Protocol (ADR-0015 overlap-then-delete):
//  1. AddDestination: add new pod IP to all EndpointSlices that currently list source pod.
//     Both IPs are now registered — traffic can flow to either.
//  2. (External): Traffic verification runs (TrafficVerified gate).
//  3. RemoveSource: remove old pod IP from EndpointSlices only AFTER TrafficVerified=true.
//
// This ensures there is never a gap in endpoint registration.
type EndpointSliceManager struct {
	client client.Client
}

// NewEndpointSliceManager creates an EndpointSliceManager backed by the given client.
func NewEndpointSliceManager(c client.Client) *EndpointSliceManager {
	return &EndpointSliceManager{client: c}
}

// AddDestination adds destPodIP to every EndpointSlice in namespace that currently
// contains sourcePodIP. Returns the number of EndpointSlices updated.
func (m *EndpointSliceManager) AddDestination(ctx context.Context, namespace, sourcePodIP, destPodIP string, destReady bool) (int, error) {
	slices, err := m.findSlicesWithIP(ctx, namespace, sourcePodIP)
	if err != nil {
		return 0, fmt.Errorf("listing EndpointSlices: %w", err)
	}

	updated := 0
	for i := range slices {
		sl := &slices[i]
		if endpointExists(sl, destPodIP) {
			continue
		}
		sl.Endpoints = append(sl.Endpoints, makeEndpoint(destPodIP, destReady))
		if err := m.client.Update(ctx, sl); err != nil {
			return updated, fmt.Errorf("updating EndpointSlice %s: %w", sl.Name, err)
		}
		updated++
	}
	return updated, nil
}

// RemoveSource removes sourcePodIP from all EndpointSlices in namespace.
// Must only be called after TrafficVerified=true.
func (m *EndpointSliceManager) RemoveSource(ctx context.Context, namespace, sourcePodIP string) (int, error) {
	slices, err := m.findSlicesWithIP(ctx, namespace, sourcePodIP)
	if err != nil {
		return 0, fmt.Errorf("listing EndpointSlices: %w", err)
	}

	removed := 0
	for i := range slices {
		sl := &slices[i]
		before := len(sl.Endpoints)
		sl.Endpoints = filterEndpoints(sl.Endpoints, sourcePodIP)
		if len(sl.Endpoints) == before {
			continue
		}
		if err := m.client.Update(ctx, sl); err != nil {
			return removed, fmt.Errorf("updating EndpointSlice %s: %w", sl.Name, err)
		}
		removed++
	}
	return removed, nil
}

// MarkDestinationReady sets the destination endpoint's Ready condition to true
// in all EndpointSlices that contain it. Called once the restored pod passes readiness.
func (m *EndpointSliceManager) MarkDestinationReady(ctx context.Context, namespace, destPodIP string) error {
	slices, err := m.findSlicesWithIP(ctx, namespace, destPodIP)
	if err != nil {
		return err
	}
	for i := range slices {
		sl := &slices[i]
		changed := false
		for j := range sl.Endpoints {
			for _, addr := range sl.Endpoints[j].Addresses {
				if addr == destPodIP {
					ready := true
					sl.Endpoints[j].Conditions.Ready = &ready
					changed = true
				}
			}
		}
		if changed {
			if err := m.client.Update(ctx, sl); err != nil {
				return fmt.Errorf("updating EndpointSlice %s: %w", sl.Name, err)
			}
		}
	}
	return nil
}

func (m *EndpointSliceManager) findSlicesWithIP(ctx context.Context, namespace, ip string) ([]discoveryv1.EndpointSlice, error) {
	list := &discoveryv1.EndpointSliceList{}
	if err := m.client.List(ctx, list,
		client.InNamespace(namespace),
		client.MatchingLabelsSelector{Selector: labels.Everything()},
	); err != nil {
		return nil, err
	}

	var matching []discoveryv1.EndpointSlice
	for _, sl := range list.Items {
		if sliceContainsIP(sl, ip) {
			matching = append(matching, sl)
		}
	}
	return matching, nil
}

func sliceContainsIP(sl discoveryv1.EndpointSlice, ip string) bool {
	for _, ep := range sl.Endpoints {
		for _, addr := range ep.Addresses {
			if addr == ip {
				return true
			}
		}
	}
	return false
}

func endpointExists(sl *discoveryv1.EndpointSlice, ip string) bool {
	return sliceContainsIP(*sl, ip)
}

func filterEndpoints(eps []discoveryv1.Endpoint, removeIP string) []discoveryv1.Endpoint {
	out := eps[:0]
	for _, ep := range eps {
		keep := true
		for _, addr := range ep.Addresses {
			if addr == removeIP {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, ep)
		}
	}
	return out
}

func makeEndpoint(ip string, ready bool) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses:  []string{ip},
		Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		NodeName:   nil, // will be set by the controller once destination node is known
	}
}

// DrainSource stops new connections flowing to sourcePodIP by marking it NotReady,
// then waits up to drainSeconds for in-flight connections to complete.
func (m *EndpointSliceManager) DrainSource(ctx context.Context, namespace, sourcePodIP string, drainSeconds int) error {
	// Mark not-ready first so the kube-proxy stops sending new connections.
	slices, err := m.findSlicesWithIP(ctx, namespace, sourcePodIP)
	if err != nil {
		return err
	}
	for i := range slices {
		sl := &slices[i]
		changed := false
		for j := range sl.Endpoints {
			for _, addr := range sl.Endpoints[j].Addresses {
				if addr == sourcePodIP {
					notReady := false
					sl.Endpoints[j].Conditions.Ready = &notReady
					terminating := true
					sl.Endpoints[j].Conditions.Terminating = &terminating
					changed = true
				}
			}
		}
		if changed {
			if err := m.client.Update(ctx, sl); err != nil {
				return fmt.Errorf("marking source not-ready in EndpointSlice %s: %w", sl.Name, err)
			}
		}
	}

	// Wait for drain period.
	if drainSeconds > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(drainSeconds) * time.Second):
		}
	}
	return nil
}

// NodeName sets the NodeName on the destination endpoint across all slices.
func (m *EndpointSliceManager) SetDestinationNode(ctx context.Context, namespace, destPodIP, nodeName string) error {
	slices, err := m.findSlicesWithIP(ctx, namespace, destPodIP)
	if err != nil {
		return err
	}
	for i := range slices {
		sl := &slices[i]
		changed := false
		for j := range sl.Endpoints {
			for _, addr := range sl.Endpoints[j].Addresses {
				if addr == destPodIP {
					n := nodeName
					sl.Endpoints[j].NodeName = &n
					// Also set TargetRef if possible.
					if sl.Endpoints[j].TargetRef == nil {
						sl.Endpoints[j].TargetRef = &corev1.ObjectReference{
							Kind: "Pod",
							Name: destPodIP, // placeholder — real name set by caller
						}
					}
					changed = true
				}
			}
		}
		if changed {
			if err := m.client.Update(ctx, sl); err != nil {
				return err
			}
		}
	}
	return nil
}
