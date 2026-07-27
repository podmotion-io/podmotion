/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0410_snapshot_readback_apireader_test.go — ADR-0410 coverage: the ADR-0393 capture read-back must
// be served by the UNCACHED APIReader (mgr.GetAPIReader) when one is wired, so the fail-closed
// "refuse source kill" gate observes authoritative server truth immediately after the direct
// Status().Patch, instead of a not-read-after-write-consistent informer cache.
//
// These unit tests are NECESSARY BUT NOT SUFFICIENT (ADR-0410 §7 P-VERIFY-2): a fake client is
// read-after-write consistent and CANNOT reproduce informer cache-lag, so they prove the wiring,
// the nil-fallback, and that the gate still fails closed — NOT that the live cold-start transient is
// gone. That is the OWED live §P-VERIFY-3 proof.
//
// Proves:
//   - the read-back Get is dispatched through r.APIReader (not r.Client) when APIReader is set;
//   - with APIReader nil (unit default), the read-back falls back to r.Client and behaves as before;
//   - a genuinely-nil snapshot observed through the APIReader still fails closed (gate preserved);
//   - a bad HMAC observed through the APIReader still fails closed (ADR-0396 verify preserved).

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// adr0410Pod builds a source pod whose UID matches adr0393BarePM's Spec.SourcePodUID so the captured
// snapshot round-trips the read-back verify.
func adr0410Pod() *corev1.Pod {
	pod := srcPodOnNode("node-src")
	pod.UID = types.UID("src-uid-1")
	pod.Spec.Containers = []corev1.Container{{Name: "app", Image: "redis:7"}}
	return pod
}

// TestADR0410_ReadBackUsesAPIReaderWhenSet — the core wiring proof. With a distinct APIReader wired,
// the capture read-back Get must be served by the APIReader, and never by the cached Client. Both
// readers wrap the same backing store (so the read-back still observes the persisted snapshot), and
// each is instrumented to count the Gets it serves. The read-back is the ONLY Get that flows through
// the APIReader; the field-scoped patch's own re-Get flows through the Client — so an APIReader Get
// count of exactly 1 proves the read-back was re-homed onto the uncached reader.
func TestADR0410_ReadBackUsesAPIReaderWhenSet(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-0410")
	pm.Namespace = "default"
	pod := adr0410Pod()

	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()

	var clientGets, apiReaderGets int
	cachedClient := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*pmv1.PodMigration); ok {
				clientGets++
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	uncachedReader := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*pmv1.PodMigration); ok {
				apiReaderGets++
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})

	r := &PodMigrationReconciler{
		Client:                  cachedClient,
		APIReader:               uncachedReader,
		Scheme:                  scheme,
		testOnlySnapshotHMACKey: adr0393TestKey(),
	}

	if err := r.captureSourcePodSpecSnapshot(context.Background(), pm, pod); err != nil {
		t.Fatalf("capture failed with APIReader wired: %v", err)
	}
	if apiReaderGets != 1 {
		t.Fatalf("read-back should be served by the UNCACHED APIReader exactly once, got %d APIReader Get(s)", apiReaderGets)
	}
	if clientGets < 1 {
		t.Fatalf("the field-scoped patch's own re-Get should still flow through the cached Client, got %d", clientGets)
	}
}

// TestADR0410_ReadBackFallsBackToClientWhenAPIReaderNil — with APIReader unset (the unit-test default),
// readBackReader() must return r.Client and capture must behave exactly as before (the fake client is
// read-after-write consistent, so there is no cache-lag to defend against). This guards the fallback
// that keeps every existing unit test valid.
func TestADR0410_ReadBackFallsBackToClientWhenAPIReaderNil(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-0410")
	pm.Namespace = "default"
	pod := adr0410Pod()

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, testOnlySnapshotHMACKey: adr0393TestKey()}

	if r.APIReader != nil {
		t.Fatal("precondition: APIReader should be nil in this unit default")
	}
	if r.readBackReader() != client.Reader(fakeClient) {
		t.Fatal("readBackReader() must fall back to r.Client when APIReader is nil")
	}
	if err := r.captureSourcePodSpecSnapshot(context.Background(), pm, pod); err != nil {
		t.Fatalf("capture failed on the nil-APIReader fallback path: %v", err)
	}
}

// TestADR0410_ReadBackNilStillFailsClosed — the gate must NOT be defeated by the reader swap. When the
// APIReader observes a genuinely-absent snapshot (the real "did not persist" case), the read-back must
// still return the fail-closed "refusing source kill" error. Here the APIReader strips the snapshot from
// the object it returns, simulating an authoritative read that finds no persisted snapshot.
func TestADR0410_ReadBackNilStillFailsClosed(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-0410")
	pm.Namespace = "default"
	pod := adr0410Pod()

	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	stripReader := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := cl.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if pmObj, ok := obj.(*pmv1.PodMigration); ok {
				pmObj.Status.SourcePodSpecSnapshot = nil // authoritative read finds no snapshot
			}
			return nil
		},
	})
	r := &PodMigrationReconciler{
		Client:                  base, // write path persists the snapshot to the server
		APIReader:               stripReader,
		Scheme:                  scheme,
		testOnlySnapshotHMACKey: adr0393TestKey(),
	}

	err := r.captureSourcePodSpecSnapshot(context.Background(), pm, pod)
	if err == nil {
		t.Fatal("read-back-nil observed through APIReader must fail closed (refuse source kill), got nil error")
	}
	if !containsAll(err.Error(), "read-back nil", "refusing source kill") {
		t.Fatalf("expected the fail-closed read-back-nil error, got: %v", err)
	}
}

// TestADR0410_ReadBackHMACVerifyPreserved — the ADR-0396 HMAC verify still runs on the object the
// APIReader returns. When the APIReader observes a snapshot whose integrity HMAC is corrupted, the
// read-back must fail closed on verification, not silently accept it.
func TestADR0410_ReadBackHMACVerifyPreserved(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("pm-0410")
	pm.Namespace = "default"
	pod := adr0410Pod()

	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	tamperReader := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := cl.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if pmObj, ok := obj.(*pmv1.PodMigration); ok && pmObj.Status.SourcePodSpecSnapshot != nil {
				pmObj.Status.SourcePodSpecSnapshot.IntegrityHMAC = "deadbeefdeadbeef" // forged signature
			}
			return nil
		},
	})
	r := &PodMigrationReconciler{
		Client:                  base,
		APIReader:               tamperReader,
		Scheme:                  scheme,
		testOnlySnapshotHMACKey: adr0393TestKey(),
	}

	err := r.captureSourcePodSpecSnapshot(context.Background(), pm, pod)
	if err == nil {
		t.Fatal("a bad HMAC observed through APIReader must fail closed, got nil error")
	}
	if !containsAll(err.Error(), "failed verification", "refusing source kill") {
		t.Fatalf("expected the fail-closed HMAC-verify error, got: %v", err)
	}
}
