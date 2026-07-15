/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// confirm_endpoint_owns_ip_test.go — drives the sprint46B2 substrate primitive
// ConfirmEndpointOwnsPreservedIP against a fake dynamic client whose CiliumEndpoint object
// carries the EXACT status shape cilium-agent writes (status.state / status.identity.id /
// status.networking.addressing[].ipv4). This is the "real converging producer" proof: unlike the
// retired ADR-0210 nonce round-trip (structurally blind from the source-node vantage while ADR-0012
// holds the source pod alive with the preserved IP — see tryEstablishCiliumDataplaneReachability),
// the authoritative CiliumEndpoint read genuinely CONVERGES to a confirmation on a correctly
// migrated IP, and FAILS CLOSED (never false-credits) when the ipam.cilium.io/ip pin was not
// honored (ADR-0324 P-VERIFY-C) or the endpoint is not ready.
package iphandoff

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// ciliumEndpoint builds an *unstructured.Unstructured mirroring cilium-agent's CiliumEndpoint
// status write-back. ipv4 is the address cilium-agent recorded for the endpoint ("" -> no
// addressing entry); state/identityID model the readiness predicates.
func ciliumEndpoint(namespace, name, state string, identityID int64, node, ipv4 string) *unstructured.Unstructured {
	networking := map[string]interface{}{"node": node}
	if ipv4 != "" {
		networking["addressing"] = []interface{}{
			map[string]interface{}{"ipv4": ipv4},
		}
	}
	ce := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumEndpoint",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"status": map[string]interface{}{
			"state":      state,
			"identity":   map[string]interface{}{"id": identityID},
			"networking": networking,
		},
	}}
	ce.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumEndpoint"})
	return ce
}

func fakeCiliumHandoff(objs ...runtime.Object) *CiliumHandoff {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		ciliumEndpointGVR: "CiliumEndpointList",
	}
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, objs...)
	return &CiliumHandoff{
		DynamicClient: dc,
		// Short bounds so the not-ready hold path returns fast and deterministically.
		ReadyTimeout: 200 * time.Millisecond,
		PollInterval: 10 * time.Millisecond,
	}
}

// TestConfirmEndpointOwnsPreservedIP_Converges is the POSITIVE control: cilium-agent reports the
// replacement endpoint ready with an identity AND advertising the preserved IP. The authoritative
// read must confirm (return the endpoint's node, nil err) — this is the datapath gate producer
// actually converging, without any source-node probe.
func TestConfirmEndpointOwnsPreservedIP_Converges(t *testing.T) {
	const (
		ns     = "pm-live-proof-c2"
		pod    = "redis-src-m-5604a0fb"
		wantIP = "10.244.1.178"
		node   = "192.168.122.243"
	)
	ch := fakeCiliumHandoff(ciliumEndpoint(ns, pod, "ready", 12345, node, wantIP))

	gotNode, err := ch.ConfirmEndpointOwnsPreservedIP(context.Background(), ns, pod, wantIP)
	if err != nil {
		t.Fatalf("authoritative read must converge for a ready endpoint owning the preserved IP; got err: %v", err)
	}
	if gotNode != node {
		t.Fatalf("expected endpoint node %q, got %q", node, gotNode)
	}
}

// TestConfirmEndpointOwnsPreservedIP_FailClosed_WrongIP is the load-bearing negative control for
// ADR-0324 P-VERIFY-C: the endpoint is ready with an identity, but cilium-agent assigned a
// DIFFERENT IP (the ipam.cilium.io/ip pin was not honored under cluster-pool per-node blocks). The
// read MUST fail closed — never credit a dataplane that did not actually move the preserved IP —
// with a specific, classifiable reason token.
func TestConfirmEndpointOwnsPreservedIP_FailClosed_WrongIP(t *testing.T) {
	const (
		ns     = "pm-live-proof-c2"
		pod    = "redis-src-m-5604a0fb"
		wantIP = "10.244.1.178"
		gotIP  = "10.244.2.99" // pm-w2's own /24 — pin rejected, endpoint got a native IP
		node   = "192.168.122.243"
	)
	ch := fakeCiliumHandoff(ciliumEndpoint(ns, pod, "ready", 12345, node, gotIP))

	if _, err := ch.ConfirmEndpointOwnsPreservedIP(context.Background(), ns, pod, wantIP); err == nil {
		t.Fatalf("read MUST fail closed when the ready endpoint advertises a different IP than the preserved one")
	} else if !strings.Contains(err.Error(), "does not advertise preserved IP") {
		t.Fatalf("wrong-IP error must carry the classifiable token 'does not advertise preserved IP'; got: %v", err)
	}
}

// TestConfirmEndpointOwnsPreservedIP_FailClosed_NotReady: an endpoint stuck regenerating (never
// state=="ready") must hold (fail closed) rather than confirm.
func TestConfirmEndpointOwnsPreservedIP_FailClosed_NotReady(t *testing.T) {
	const (
		ns     = "pm-live-proof-c2"
		pod    = "redis-src-m-5604a0fb"
		wantIP = "10.244.1.178"
		node   = "192.168.122.243"
	)
	// state=regenerating with the preserved IP already present: readiness alone must gate.
	ch := fakeCiliumHandoff(ciliumEndpoint(ns, pod, "regenerating", 12345, node, wantIP))

	if _, err := ch.ConfirmEndpointOwnsPreservedIP(context.Background(), ns, pod, wantIP); err == nil {
		t.Fatalf("read MUST fail closed for an endpoint that never reaches state=ready")
	} else if !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("not-ready error must carry the 'not ready' token; got: %v", err)
	}
}

// TestConfirmEndpointOwnsPreservedIP_FailClosed_ZeroIdentity: state=ready but identity.id==0 means
// cilium-agent has NOT allocated a security identity / published the ipcache — must not confirm.
func TestConfirmEndpointOwnsPreservedIP_FailClosed_ZeroIdentity(t *testing.T) {
	const (
		ns     = "pm-live-proof-c2"
		pod    = "redis-src-m-5604a0fb"
		wantIP = "10.244.1.178"
		node   = "192.168.122.243"
	)
	ch := fakeCiliumHandoff(ciliumEndpoint(ns, pod, "ready", 0, node, wantIP))

	if _, err := ch.ConfirmEndpointOwnsPreservedIP(context.Background(), ns, pod, wantIP); err == nil {
		t.Fatalf("read MUST fail closed when status.identity.id==0 (ipcache not published)")
	}
}
