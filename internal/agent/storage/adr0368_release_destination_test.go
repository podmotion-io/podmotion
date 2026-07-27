/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

// adr0368_release_destination_test.go covers ADR-0368's Migrator.ReleaseDestination contract
// across all four tiers plus their stub counterparts:
//
//   - CONDITION 1: the three stub types (LonghornStubMigrator/CephRBDStubMigrator/
//     SnapshotRsyncStubMigrator) must return the same loud sentinel errors as their production
//     counterparts — NEVER nil — once cutover has actually happened.
//   - CONDITION 2: Tier2/Tier3 (both real and stub) must gate the sentinel on
//     opts.CutoverComplete, not tier identity alone — nil when cutover never ran.
//   - CONDITION 3: Tier1's ReleaseDestination must poll-until-actually-detached, not trust a
//     bare 2xx, and fail loud (a distinct error) on a confirm timeout.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

// ── Tier0 ────────────────────────────────────────────────────────────────────

func TestRWXReattachMigrator_ReleaseDestination_AlwaysNilNoOp(t *testing.T) {
	m := storage.NewRWXReattachMigrator(nil)
	for _, cutoverComplete := range []bool{false, true} {
		err := m.ReleaseDestination(context.Background(), storage.MigrationOptions{CutoverComplete: cutoverComplete})
		if err != nil {
			t.Errorf("Tier0 ReleaseDestination must always return nil (CutoverComplete=%v), got: %v", cutoverComplete, err)
		}
	}
}

// ── Tier1 (real LonghornMigrator) ───────────────────────────────────────────

// TestLonghornMigrator_ReleaseDestination_DetachConfirmed_ReturnsNil is the CONDITION 3 happy
// path: detach POST returns 2xx, and the subsequent poll GET shows no running controller left on
// destNode — ReleaseDestination must confirm release before returning nil, not trust the 2xx
// alone.
func TestLonghornMigrator_ReleaseDestination_DetachConfirmed_ReturnsNil(t *testing.T) {
	const (
		namespace = "default"
		pvcName   = "postgres-pgdata"
		pvName    = "pvc-fc436e39-release"
		destNode  = "pm-w2"
	)

	var detachCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/volumes/"+pvName && r.URL.Query().Get("action") == "detach":
			detachCalled = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/volumes/"+pvName:
			w.Header().Set("Content-Type", "application/json")
			// No running controller anywhere — the detach has actually taken effect.
			fmt.Fprintf(w, `{"name":%q,"state":"detached","robustness":"healthy","replicas":[],"controllers":[]}`, pvName)
		default:
			w.WriteHeader(http.StatusNotFound)
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
		MigrationName:   "mig-release-1",
		PodNamespace:    namespace,
		DestinationNode: destNode,
		Classifications: []storage.TierClassification{
			{Tier: storage.TierLonghorn, PVCName: pvcName},
		},
	}

	if err := mig.ReleaseDestination(context.Background(), opts); err != nil {
		t.Fatalf("expected nil once detach is confirmed released, got: %v", err)
	}
	if !detachCalled {
		t.Errorf("ReleaseDestination never issued the detach POST")
	}
}

// TestLonghornMigrator_ReleaseDestination_DetachAcceptedButStillAttached_TimesOut is the
// CONDITION 3 regression test: a 2xx from the detach POST must NOT be trusted as "released" —
// if the poll keeps observing a running controller on destNode, ReleaseDestination must return a
// distinct, non-nil timeout error (never nil) once its bounded poll deadline expires.
func TestLonghornMigrator_ReleaseDestination_DetachAcceptedButStillAttached_TimesOut(t *testing.T) {
	const (
		namespace = "default"
		pvcName   = "postgres-pgdata"
		pvName    = "pvc-fc436e39-stuck"
		destNode  = "pm-w2"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Query().Get("action") == "detach":
			// Longhorn Manager accepts the request (2xx) but the engine never actually tears
			// down — exactly the class of bug (request-sent mistaken for confirmed-done) this
			// ADR fixes.
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"name":%q,"state":"attached","robustness":"healthy",`+
				`"replicas":[{"name":"r1","hostId":%q,"mode":"RW","running":true}],`+
				`"controllers":[{"name":"e1","hostId":%q,"running":true}]}`, pvName, destNode, destNode)
		default:
			w.WriteHeader(http.StatusNotFound)
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
		MigrationName:   "mig-release-2",
		PodNamespace:    namespace,
		DestinationNode: destNode,
		Classifications: []storage.TierClassification{
			{Tier: storage.TierLonghorn, PVCName: pvcName},
		},
	}

	// Bound well under longhornDetachTimeout so the test itself stays fast — ReleaseDestination's
	// internal context.WithTimeout(ctx, longhornDetachTimeout) takes the earlier of the two
	// deadlines, exactly like AwaitSingleOwner's own tests rely on
	// (TestLonghornMigrator_AwaitSingleOwner_StillDualEngine_TimesOut).
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := mig.ReleaseDestination(ctx, opts)
	if err == nil {
		t.Fatalf("expected a non-nil error when the destination attach is never actually confirmed released, got nil")
	}
	if !errors.Is(err, storage.ErrTier1DetachReleaseTimedOut) {
		t.Errorf("expected errors.Is(err, storage.ErrTier1DetachReleaseTimedOut), got: %v", err)
	}
}

// TestLonghornMigrator_ReleaseDestination_DetachHTTPFailure_ReturnsPlainWrappedError proves an
// outright detach HTTP failure is a plain, retriable, non-sentinel error — distinct from the
// confirm-timeout case above.
func TestLonghornMigrator_ReleaseDestination_DetachHTTPFailure_ReturnsPlainWrappedError(t *testing.T) {
	const (
		namespace = "default"
		pvcName   = "postgres-pgdata"
		pvName    = "pvc-fc436e39-httpfail"
		destNode  = "pm-w2"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
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
		MigrationName:   "mig-release-3",
		PodNamespace:    namespace,
		DestinationNode: destNode,
		Classifications: []storage.TierClassification{
			{Tier: storage.TierLonghorn, PVCName: pvcName},
		},
	}

	err := mig.ReleaseDestination(context.Background(), opts)
	if err == nil {
		t.Fatalf("expected a non-nil error on detach HTTP failure")
	}
	if errors.Is(err, storage.ErrTier1DetachReleaseTimedOut) {
		t.Errorf("an outright HTTP failure must not be reported as the confirm-timeout sentinel")
	}
	if errors.Is(err, storage.ErrRollbackPointOfNoReturn) || errors.Is(err, storage.ErrRollbackNotImplemented) {
		t.Errorf("a plain HTTP failure must never be one of the two ADR-0368 structural sentinels")
	}
}

// ── Tier1 stub ───────────────────────────────────────────────────────────────

func TestLonghornStubMigrator_ReleaseDestination_CutoverComplete_ReturnsNotImplementedNeverNil(t *testing.T) {
	s := &storage.LonghornStubMigrator{}
	err := s.ReleaseDestination(context.Background(), storage.MigrationOptions{CutoverComplete: true})
	if err == nil {
		t.Fatalf("CONDITION 1: stub must never return nil once cutover happened")
	}
	if !errors.Is(err, storage.ErrRollbackNotImplemented) {
		t.Errorf("expected errors.Is(err, storage.ErrRollbackNotImplemented), got: %v", err)
	}
	if !s.ReleaseDestinationCalled {
		t.Errorf("expected ReleaseDestinationCalled to be recorded")
	}
}

func TestLonghornStubMigrator_ReleaseDestination_NoCutover_ReturnsNil(t *testing.T) {
	s := &storage.LonghornStubMigrator{}
	err := s.ReleaseDestination(context.Background(), storage.MigrationOptions{CutoverComplete: false})
	if err != nil {
		t.Errorf("expected nil when cutover never happened, got: %v", err)
	}
}

// ── Tier2 (real CephRBDMigrator) ────────────────────────────────────────────

func recordingExecCommand(calls *[]string) func(name string, args ...string) *exec.Cmd {
	return func(name string, args ...string) *exec.Cmd {
		*calls = append(*calls, name+" "+strings.Join(args, " "))
		return exec.Command("true")
	}
}

func TestCephRBDMigrator_ReleaseDestination_CutoverComplete_PointOfNoReturn_NoRBDExec(t *testing.T) {
	var calls []string
	m := storage.NewCephRBDMigrator("rbd")
	m.ExecCommand = recordingExecCommand(&calls)

	opts := storage.MigrationOptions{
		CutoverComplete: true,
		Classifications: []storage.TierClassification{
			{Tier: storage.TierCephRBD, PVCName: "pgdata"},
		},
		DestinationNode: "pm-w2",
	}

	err := m.ReleaseDestination(context.Background(), opts)
	if err == nil {
		t.Fatalf("CONDITION 2: expected ErrRollbackPointOfNoReturn once cutover (rbd migration commit) has run")
	}
	if !errors.Is(err, storage.ErrRollbackPointOfNoReturn) {
		t.Errorf("expected errors.Is(err, storage.ErrRollbackPointOfNoReturn), got: %v", err)
	}
	if len(calls) != 0 {
		t.Errorf("expected ZERO rbd subprocess invocations (commit already ran and cannot be undone), got: %v", calls)
	}
}

func TestCephRBDMigrator_ReleaseDestination_NoCutover_ReturnsNil_NoRBDExec(t *testing.T) {
	var calls []string
	m := storage.NewCephRBDMigrator("rbd")
	m.ExecCommand = recordingExecCommand(&calls)

	opts := storage.MigrationOptions{
		CutoverComplete: false, // e.g. a rollback triggered during Checkpointing/Transferring —
		// the common case KVM Expert FINDING 1 (CONDITION 2) targets.
		Classifications: []storage.TierClassification{
			{Tier: storage.TierCephRBD, PVCName: "pgdata"},
		},
		DestinationNode: "pm-w2",
	}

	err := m.ReleaseDestination(context.Background(), opts)
	if err != nil {
		t.Errorf("CONDITION 2: expected nil when cutover never ran — nothing destination-side to release, got: %v", err)
	}
	if len(calls) != 0 {
		t.Errorf("expected zero rbd subprocess invocations, got: %v", calls)
	}
}

// ── Tier2 stub ───────────────────────────────────────────────────────────────

func TestCephRBDStubMigrator_ReleaseDestination_Gating(t *testing.T) {
	t.Run("cutover complete: never nil", func(t *testing.T) {
		s := &storage.CephRBDStubMigrator{}
		err := s.ReleaseDestination(context.Background(), storage.MigrationOptions{CutoverComplete: true})
		if err == nil {
			t.Fatalf("CONDITION 1: stub must never return nil once cutover happened")
		}
		if !errors.Is(err, storage.ErrRollbackPointOfNoReturn) {
			t.Errorf("expected errors.Is(err, storage.ErrRollbackPointOfNoReturn), got: %v", err)
		}
	})
	t.Run("no cutover: nil", func(t *testing.T) {
		s := &storage.CephRBDStubMigrator{}
		err := s.ReleaseDestination(context.Background(), storage.MigrationOptions{CutoverComplete: false})
		if err != nil {
			t.Errorf("expected nil when cutover never happened, got: %v", err)
		}
	})
}

// ── Tier3 (real SnapshotRsyncMigrator) ──────────────────────────────────────

func TestSnapshotRsyncMigrator_ReleaseDestination_Gating(t *testing.T) {
	t.Run("cutover complete: never nil", func(t *testing.T) {
		// Client deliberately nil: ReleaseDestination must never touch the Kubernetes API
		// (no snapshot/PVC mutation), so a nil client proves it by construction — any Get/
		// Create/etc. call would nil-panic.
		m := storage.NewSnapshotRsyncMigrator(nil)
		err := m.ReleaseDestination(context.Background(), storage.MigrationOptions{CutoverComplete: true})
		if err == nil {
			t.Fatalf("CONDITION 1: must never return nil once cutover happened")
		}
		if !errors.Is(err, storage.ErrRollbackNotImplemented) {
			t.Errorf("expected errors.Is(err, storage.ErrRollbackNotImplemented), got: %v", err)
		}
	})
	t.Run("no cutover: nil", func(t *testing.T) {
		m := storage.NewSnapshotRsyncMigrator(nil)
		err := m.ReleaseDestination(context.Background(), storage.MigrationOptions{CutoverComplete: false})
		if err != nil {
			t.Errorf("expected nil when cutover never happened, got: %v", err)
		}
	})
}

// ── Tier3 stub ───────────────────────────────────────────────────────────────

func TestSnapshotRsyncStubMigrator_ReleaseDestination_Gating(t *testing.T) {
	t.Run("cutover complete: never nil", func(t *testing.T) {
		s := &storage.SnapshotRsyncStubMigrator{}
		err := s.ReleaseDestination(context.Background(), storage.MigrationOptions{CutoverComplete: true})
		if err == nil {
			t.Fatalf("CONDITION 1: stub must never return nil once cutover happened")
		}
		if !errors.Is(err, storage.ErrRollbackNotImplemented) {
			t.Errorf("expected errors.Is(err, storage.ErrRollbackNotImplemented), got: %v", err)
		}
	})
	t.Run("no cutover: nil", func(t *testing.T) {
		s := &storage.SnapshotRsyncStubMigrator{}
		err := s.ReleaseDestination(context.Background(), storage.MigrationOptions{CutoverComplete: false})
		if err != nil {
			t.Errorf("expected nil when cutover never happened, got: %v", err)
		}
	})
}
