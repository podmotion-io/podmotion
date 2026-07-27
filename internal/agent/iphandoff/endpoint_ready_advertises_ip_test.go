/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// endpoint_ready_advertises_ip_test.go — drives the ADR-0405 SINGLE-SHOT core
// EndpointReadyAdvertisesIP directly. The single-shot core must return exactly once with no
// internal poll loop so the Ready-gate call site can compose it with controller-runtime's own
// requeue cadence instead of blocking a reconcile worker for the full readyTimeout. These tests
// pin the tri-state contract the wrapper and the new Service-backend gate both depend on:
//   - programmed        -> (node, true, nil)
//   - not-yet (missing/not-ready) -> ("", false, nil)   [transient, caller requeues]
//   - decided negative (wrong IP / nil client / empty wantIP) -> ("", false, err) [fail-closed]
package iphandoff

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// TestEndpointReadyAdvertisesIP_Programmed: ready endpoint with identity advertising wantIP -> ok.
func TestEndpointReadyAdvertisesIP_Programmed(t *testing.T) {
	const (
		ns     = "migration-demo"
		pod    = "postgres-repl-m-abc123"
		wantIP = "10.244.2.55" // the replacement's actually-assigned dest IP (cluster-pool /24 on pm-w2)
		node   = "192.168.122.243"
	)
	ch := fakeCiliumHandoff(ciliumEndpoint(ns, pod, "ready", 4242, node, wantIP))

	gotNode, ok, err := ch.EndpointReadyAdvertisesIP(context.Background(), ns, pod, wantIP)
	if err != nil {
		t.Fatalf("single-shot core must not error for a programmed endpoint; got: %v", err)
	}
	if !ok {
		t.Fatalf("single-shot core must report ok=true for a ready endpoint owning wantIP")
	}
	if gotNode != node {
		t.Fatalf("expected node %q, got %q", node, gotNode)
	}
}

// TestEndpointReadyAdvertisesIP_NotYet_NotFound: no CiliumEndpoint object yet -> transient
// (false,nil), NOT an error — the caller requeues rather than failing the migration.
func TestEndpointReadyAdvertisesIP_NotYet_NotFound(t *testing.T) {
	ch := fakeCiliumHandoff() // no objects
	node, ok, err := ch.EndpointReadyAdvertisesIP(context.Background(), "migration-demo", "missing-pod", "10.244.2.55")
	if err != nil {
		t.Fatalf("missing endpoint object must be transient (nil err), not a decided error; got: %v", err)
	}
	if ok {
		t.Fatalf("missing endpoint object must be ok=false")
	}
	if node != "" {
		t.Fatalf("missing endpoint must return empty node, got %q", node)
	}
}

// TestEndpointReadyAdvertisesIP_NotYet_NotReady: object exists but state!=ready -> transient
// (false,nil). Readiness alone gates; the caller requeues.
func TestEndpointReadyAdvertisesIP_NotYet_NotReady(t *testing.T) {
	const (
		ns     = "migration-demo"
		pod    = "postgres-repl-m-abc123"
		wantIP = "10.244.2.55"
		node   = "192.168.122.243"
	)
	ch := fakeCiliumHandoff(ciliumEndpoint(ns, pod, "regenerating", 4242, node, wantIP))
	_, ok, err := ch.EndpointReadyAdvertisesIP(context.Background(), ns, pod, wantIP)
	if err != nil {
		t.Fatalf("not-ready endpoint must be transient (nil err); got: %v", err)
	}
	if ok {
		t.Fatalf("not-ready endpoint must be ok=false")
	}
}

// TestEndpointReadyAdvertisesIP_Decided_WrongIP: ready endpoint advertising a DIFFERENT IP is a
// decided negative (fail-closed err with the classifiable token) — never a transient that could be
// retried into a false-ready. This is the load-bearing anti-fail-open guarantee.
func TestEndpointReadyAdvertisesIP_Decided_WrongIP(t *testing.T) {
	const (
		ns     = "migration-demo"
		pod    = "postgres-repl-m-abc123"
		wantIP = "10.244.2.55"
		gotIP  = "10.244.2.99"
		node   = "192.168.122.243"
	)
	ch := fakeCiliumHandoff(ciliumEndpoint(ns, pod, "ready", 4242, node, gotIP))
	_, ok, err := ch.EndpointReadyAdvertisesIP(context.Background(), ns, pod, wantIP)
	if ok || err == nil {
		t.Fatalf("ready-but-wrong-IP must be a decided fail-closed error, got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(err.Error(), "does not advertise preserved IP") {
		t.Fatalf("wrong-IP error must carry the classifiable token; got: %v", err)
	}
}

// TestEndpointReadyAdvertisesIP_Decided_NilClient / _EmptyWantIP: both guard conditions are decided
// errors (fail-closed), never a false-ready.
func TestEndpointReadyAdvertisesIP_Decided_NilClient(t *testing.T) {
	ch := &CiliumHandoff{} // DynamicClient nil
	if _, ok, err := ch.EndpointReadyAdvertisesIP(context.Background(), "ns", "pod", "10.0.0.1"); ok || err == nil {
		t.Fatalf("nil DynamicClient must fail closed, got ok=%v err=%v", ok, err)
	}
}

func TestEndpointReadyAdvertisesIP_Decided_EmptyWantIP(t *testing.T) {
	ch := fakeCiliumHandoff()
	if _, ok, err := ch.EndpointReadyAdvertisesIP(context.Background(), "ns", "pod", ""); ok || err == nil {
		t.Fatalf("empty wantIP must fail closed, got ok=%v err=%v", ok, err)
	}
}

// TestEndpointReadyAdvertisesIP_IsSingleShot: the core must NOT poll. An endpoint that never
// becomes ready must return immediately, well under the package poll interval, proving there is no
// internal loop that would block a reconcile worker.
func TestEndpointReadyAdvertisesIP_IsSingleShot(t *testing.T) {
	const (
		ns   = "migration-demo"
		pod  = "postgres-repl-m-abc123"
		node = "192.168.122.243"
	)
	ch := fakeCiliumHandoff(ciliumEndpoint(ns, pod, "regenerating", 4242, node, "10.244.2.55"))
	// Force a large poll bound: if the core (wrongly) looped, it would sleep on this.
	ch.PollInterval = 5 * time.Second
	ch.ReadyTimeout = 5 * time.Second

	start := time.Now()
	_, ok, err := ch.EndpointReadyAdvertisesIP(context.Background(), ns, pod, "10.244.2.55")
	elapsed := time.Since(start)
	if ok || err != nil {
		t.Fatalf("expected transient not-ready (false,nil), got ok=%v err=%v", ok, err)
	}
	if elapsed > time.Second {
		t.Fatalf("single-shot core must return immediately (no poll loop); took %v", elapsed)
	}
}

// TestConfirmEndpointOwnsPreservedIP_StillPollsViaCore: the blocking wrapper must still converge
// through the refactored core — a positive control that the extraction preserved wrapper behavior.
func TestConfirmEndpointOwnsPreservedIP_StillPollsViaCore(t *testing.T) {
	const (
		ns     = "migration-demo"
		pod    = "postgres-repl-m-abc123"
		wantIP = "10.244.1.178"
		node   = "192.168.122.243"
	)
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{ciliumEndpointGVR: "CiliumEndpointList"}
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind,
		ciliumEndpoint(ns, pod, "ready", 999, node, wantIP))
	ch := &CiliumHandoff{DynamicClient: dc, ReadyTimeout: 200 * time.Millisecond, PollInterval: 10 * time.Millisecond}

	gotNode, err := ch.ConfirmEndpointOwnsPreservedIP(context.Background(), ns, pod, wantIP)
	if err != nil {
		t.Fatalf("wrapper must still converge through the extracted core; got: %v", err)
	}
	if gotNode != node {
		t.Fatalf("expected node %q, got %q", node, gotNode)
	}
}
