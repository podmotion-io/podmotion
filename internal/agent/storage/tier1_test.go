/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

// makeBoundPVC builds a PVC whose spec.volumeName is a dynamically-provisioned
// PV name distinct from the PVC's own name — the common real-world case that
// the "volume name == PVC name by convention" assumption gets wrong.
func makeBoundPVC(namespace, pvcName, pvName string) *corev1.PersistentVolumeClaim {
	sc := "longhorn"
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: pvcName, Namespace: namespace},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: &sc,
			VolumeName:       pvName,
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase: corev1.ClaimBound,
		},
	}
}

// pathRecorder is a thread-safe log of request paths hit against the fake
// Longhorn Manager server, used to assert which volume name (PVC name vs.
// bound PV name) each call actually used.
type pathRecorder struct {
	mu    sync.Mutex
	paths []string
}

func (r *pathRecorder) record(p string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, p)
}

func (r *pathRecorder) contains(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.paths {
		if p == sub {
			return true
		}
	}
	return false
}

// TestLonghornMigrator_Cutover_ResolvesBoundPVName is the regression test for
// the wrong volume-name-resolution bug: tier1.go used to assume
// "Longhorn volume name == PVC name," which 404s against the Longhorn
// Manager API for any dynamically-provisioned PVC. Cutover (detach+attach,
// no polling) is used here to keep the test fast while still exercising the
// resolution path shared by PreStage/SyncPercent/Cutover.
func TestLonghornMigrator_Cutover_ResolvesBoundPVName(t *testing.T) {
	const (
		namespace = "default"
		pvcName   = "postgres-pgdata"
		pvName    = "pvc-d39ce436-1234-5678-9abc-def012345678"
	)

	rec := &pathRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r.URL.Path)
		// The PVC name must never be dialed — it does not exist as a Longhorn
		// volume for a dynamically-provisioned PVC.
		if r.URL.Path == "/v1/volumes/"+pvcName {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/v1/volumes/"+pvName {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	pvc := makeBoundPVC(namespace, pvcName, pvName)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pvc).Build()

	mig := storage.NewLonghornMigrator(srv.URL, c)

	opts := storage.MigrationOptions{
		MigrationName:   "mig-1",
		PodNamespace:    namespace,
		SourceNode:      "node-a",
		DestinationNode: "node-b",
		Classifications: []storage.TierClassification{
			{Tier: storage.TierLonghorn, PVCName: pvcName},
		},
	}

	if err := mig.Cutover(context.Background(), opts); err != nil {
		t.Fatalf("Cutover returned error: %v", err)
	}

	if rec.contains("/v1/volumes/" + pvcName) {
		t.Errorf("Cutover dialed the Longhorn API using the PVC name %q — must resolve and use the bound PV name %q instead", pvcName, pvName)
	}
	if !rec.contains("/v1/volumes/" + pvName) {
		t.Errorf("Cutover never dialed the resolved PV name %q; recorded paths: %v", pvName, rec.paths)
	}
}

// TestLonghornMigrator_PreStage_PVCNotBound_FailsFastWithoutDialingLonghorn
// proves resolveVolumeName fails closed (no Longhorn API call at all) when
// the PVC has no bound PV yet, rather than silently falling back to the PVC
// name and letting a stale/wrong 404 surface later.
func TestLonghornMigrator_PreStage_PVCNotBound_FailsFastWithoutDialingLonghorn(t *testing.T) {
	const (
		namespace = "default"
		pvcName   = "postgres-pgdata"
	)

	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dialed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	// Unbound PVC — spec.volumeName is empty.
	sc := "longhorn"
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: pvcName, Namespace: namespace},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: &sc,
		},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pvc).Build()

	mig := storage.NewLonghornMigrator(srv.URL, c)

	opts := storage.MigrationOptions{
		MigrationName:   "mig-2",
		PodNamespace:    namespace,
		DestinationNode: "node-b",
		Classifications: []storage.TierClassification{
			{Tier: storage.TierLonghorn, PVCName: pvcName},
		},
	}

	err := mig.PreStage(context.Background(), opts)
	if err == nil {
		t.Fatalf("expected PreStage to fail for an unbound PVC, got nil")
	}
	if dialed {
		t.Errorf("PreStage dialed the Longhorn Manager API for a PVC with no bound PV — should fail fast on volume-name resolution instead")
	}
}

// TestLonghornMigrator_PreStage_FullResolutionAndSync exercises the full
// PreStage path (verify + addDestReplica + poll) end-to-end against a fake
// Longhorn Manager server keyed by the resolved PV name, proving
// SyncPercent's resolution path also uses the bound PV name.
func TestLonghornMigrator_PreStage_FullResolutionAndSync(t *testing.T) {
	const (
		namespace = "default"
		pvcName   = "postgres-pgdata"
		pvName    = "pvc-d39ce436-full"
		destNode  = "node-b"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/volumes/"+pvName {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"name":%q,"state":"attached","robustness":"healthy","replicas":[{"name":"r1","hostId":%q,"mode":"RW","running":true}]}`, pvName, destNode)
		case http.MethodPost:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	pvc := makeBoundPVC(namespace, pvcName, pvName)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pvc).Build()

	mig := storage.NewLonghornMigrator(srv.URL, c)

	opts := storage.MigrationOptions{
		MigrationName:   "mig-3",
		PodNamespace:    namespace,
		DestinationNode: destNode,
		Classifications: []storage.TierClassification{
			{Tier: storage.TierLonghorn, PVCName: pvcName},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := mig.PreStage(ctx, opts); err != nil {
		t.Fatalf("PreStage returned error: %v", err)
	}

	pct, err := mig.SyncPercent(context.Background(), opts)
	if err != nil {
		t.Fatalf("SyncPercent returned error: %v", err)
	}
	if pct != 100 {
		t.Errorf("expected 100%% sync once replica mode=RW, got %d", pct)
	}
}

// TestLonghornMigrator_PreStage_SkipsAddReplicaWhenDestAlreadyHealthy is the
// regression test for the sprint48 addDestReplica bug: the destination node
// already has a healthy replica (volume has 3 replicas total, spread across
// 3 nodes), so PreStage must NOT call updateReplicaCount at all — the old
// code called it unconditionally with a hardcoded replicaCount:2, which
// shrank an already-correct 3-replica volume down to 2.
func TestLonghornMigrator_PreStage_SkipsAddReplicaWhenDestAlreadyHealthy(t *testing.T) {
	const (
		namespace = "default"
		pvcName   = "postgres-pgdata"
		pvName    = "pvc-d39ce436-401d-4f20-ad4b-c64a736bde20"
		destNode  = "pm-w2"
	)

	var postCalls int32
	var mu sync.Mutex
	var postBodies []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/volumes/"+pvName {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			// Volume already has 3 healthy replicas, one on each node,
			// including the migration destination.
			fmt.Fprintf(w, `{"name":%q,"state":"attached","robustness":"healthy","replicas":[`+
				`{"name":"r1","hostId":"pm-cp1","mode":"RW","running":true},`+
				`{"name":"r2","hostId":"pm-w1","mode":"RW","running":true},`+
				`{"name":"r3","hostId":%q,"mode":"RW","running":true}`+
				`]}`, pvName, destNode)
		case http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			postCalls++
			postBodies = append(postBodies, string(b))
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	pvc := makeBoundPVC(namespace, pvcName, pvName)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pvc).Build()

	mig := storage.NewLonghornMigrator(srv.URL, c)

	opts := storage.MigrationOptions{
		MigrationName:   "mig-4",
		PodNamespace:    namespace,
		DestinationNode: destNode,
		Classifications: []storage.TierClassification{
			{Tier: storage.TierLonghorn, PVCName: pvcName},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := mig.PreStage(ctx, opts); err != nil {
		t.Fatalf("PreStage returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if postCalls != 0 {
		t.Errorf("expected PreStage to skip updateReplicaCount when destination already has a healthy replica, got %d POST call(s) with bodies %v", postCalls, postBodies)
	}
}
