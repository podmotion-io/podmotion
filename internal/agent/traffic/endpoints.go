/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package traffic

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// errSourceEndpointRemovalBlocked is returned by RemoveSourceIfVerified when
// pmv1.SourceTeardownBlockReason reports a non-empty block reason — i.e. the
// canonical ADR-0341 predicate does not yet permit removing the source IP
// from EndpointSlices. Callers should treat this as "not yet safe to
// remove," not a transport/API failure.
var errSourceEndpointRemovalBlocked = errors.New("traffic: source EndpointSlice removal blocked by SourceTeardownBlockReason")

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

// RemoveSourceIfVerified is the canonical, ADR-0341/ADR-0344-aligned gate for
// source-EndpointSlice removal: it delegates to pmv1.SourceTeardownBlockReason
// (the single predicate also used by the controller's source-pod-deletion
// gate) and only calls RemoveSource when that predicate reports no block
// reason. On block, it returns errSourceEndpointRemovalBlocked and mutates
// nothing. Returns the number of EndpointSlices updated on success.
func (m *EndpointSliceManager) RemoveSourceIfVerified(ctx context.Context, pm *pmv1.PodMigration, namespace, sourcePodIP string) (int, error) {
	if reason := pmv1.SourceTeardownBlockReason(pm.Spec.TCPPreservationMode, pm.Status.Conditions); reason != "" {
		return 0, fmt.Errorf("%w: %s", errSourceEndpointRemovalBlocked, reason)
	}
	return m.RemoveSource(ctx, namespace, sourcePodIP)
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

// HasEndpointForIP reports whether any EndpointSlice in namespace contains ip.
// Used by the controller for post-flight verification that RemoveSource actually cleaned up.
func (m *EndpointSliceManager) HasEndpointForIP(ctx context.Context, namespace, ip string) (bool, error) {
	slices, err := m.findSlicesWithIP(ctx, namespace, ip)
	if err != nil {
		return false, err
	}
	return len(slices) > 0, nil
}

// ServiceNameForIP (ADR-0352 D1.2) returns the owning Service name for the EndpointSlice
// containing ip, read via the standard discoveryv1.LabelServiceName label — the only
// Service-linkage mechanism this codebase has (PodMigrationSpec carries no ServiceName
// field, VERIFIED against api/v1alpha1/podmigration_types.go). Returns "" (not an error)
// when no EndpointSlice with ip carries the label yet — the caller (controller) treats
// that as "not yet resolvable" and requeues, exactly like any other convergent primitive.
func (m *EndpointSliceManager) ServiceNameForIP(ctx context.Context, namespace, ip string) (string, error) {
	slices, err := m.findSlicesWithIP(ctx, namespace, ip)
	if err != nil {
		return "", err
	}
	for _, sl := range slices {
		if name := sl.Labels[discoveryv1.LabelServiceName]; name != "" {
			return name, nil
		}
	}
	return "", nil
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

// RemoveByTargetRefUIDs removes, from every EndpointSlice in namespace, any endpoint whose
// TargetRef.UID is in uids (ADR-0350 D1: the reaped replacement pods' UIDs, source of truth,
// handed out of deleteReplacementPod's return value — never re-resolved here). UID-keyed, not
// IP- or name-keyed: a same-named or same-IP successor pod must never be matched.
//
// Each per-slice write is a bounded compare-and-set: retry.RetryOnConflict(retry.DefaultRetry, …)
// re-fetches and reapplies the filter on 409 (ADR-0350 D3). On retry-budget exhaustion for any
// slice, this returns immediately with that slice's error — the caller (ensureReplacementEndpoints
// Removed) is responsible for the D6 fail-closed signal and for withholding RolledBack=True; this
// method does not itself fall back to any inferred/async mechanism (invariant #10).
//
// Idempotent: a UID already absent from a slice is a no-op for that slice (no write issued).
func (m *EndpointSliceManager) RemoveByTargetRefUIDs(ctx context.Context, namespace string, uids map[types.UID]bool) (int, error) {
	if len(uids) == 0 {
		return 0, nil
	}
	list := &discoveryv1.EndpointSliceList{}
	if err := m.client.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return 0, fmt.Errorf("listing EndpointSlices: %w", err)
	}

	updated := 0
	for i := range list.Items {
		name := list.Items[i].Name
		if !sliceHasAnyTargetRefUID(&list.Items[i], uids) {
			continue // cheap pre-check on the already-fetched list; avoids a wasted Get+CAS
		}
		wrote := false
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			fresh := &discoveryv1.EndpointSlice{}
			if err := m.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, fresh); err != nil {
				return err
			}
			before := len(fresh.Endpoints)
			fresh.Endpoints = filterEndpointsByTargetRefUID(fresh.Endpoints, uids)
			if len(fresh.Endpoints) == before {
				return nil // already absent by the time we re-fetched — idempotent no-op
			}
			wrote = true
			return m.client.Update(ctx, fresh)
		}); err != nil {
			return updated, fmt.Errorf("removing reaped replacement UIDs from EndpointSlice %s: %w", name, err)
		}
		if wrote {
			updated++
		}
	}
	return updated, nil
}

// HasAnyTargetRefUID reports whether any EndpointSlice in namespace still carries an endpoint
// whose TargetRef.UID is in uids (ADR-0350 D1.3 confirm-absence read — the write-then-verify
// step, categorically different from inferring a peer controller's convergence).
func (m *EndpointSliceManager) HasAnyTargetRefUID(ctx context.Context, namespace string, uids map[types.UID]bool) (bool, error) {
	if len(uids) == 0 {
		return false, nil
	}
	list := &discoveryv1.EndpointSliceList{}
	if err := m.client.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return false, fmt.Errorf("listing EndpointSlices: %w", err)
	}
	for i := range list.Items {
		if sliceHasAnyTargetRefUID(&list.Items[i], uids) {
			return true, nil
		}
	}
	return false, nil
}

func sliceHasAnyTargetRefUID(sl *discoveryv1.EndpointSlice, uids map[types.UID]bool) bool {
	for _, ep := range sl.Endpoints {
		if ep.TargetRef != nil && uids[ep.TargetRef.UID] {
			return true
		}
	}
	return false
}

func filterEndpointsByTargetRefUID(eps []discoveryv1.Endpoint, uids map[types.UID]bool) []discoveryv1.Endpoint {
	out := eps[:0]
	for _, ep := range eps {
		if ep.TargetRef != nil && uids[ep.TargetRef.UID] {
			continue
		}
		out = append(out, ep)
	}
	return out
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
