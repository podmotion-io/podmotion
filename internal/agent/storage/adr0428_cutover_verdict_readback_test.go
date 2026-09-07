/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

// adr0428_cutover_verdict_readback_test.go — ADR-0428 §P-VERIFY assertion 7 (D7):
// buildMigrationOptionsFromCache's condition read must go through the uncached APIReader, so
// the ADR-0368 irreversibility verdict (CutoverSideEffectOccurred, fed via MigrationOptions.
// CutoverComplete) is computed from authoritative server state, not a lagging informer cache.
//
// This is a storage-package test and does not involve the controller at all.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

func adr0428ManagerScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	if err := pmv1.AddToScheme(s); err != nil {
		t.Fatalf("add pmv1: %v", err)
	}
	return s
}

// adr0428ReleasePM builds a PodMigration carrying the F5 classification-cache seed for the given
// tier, ready for a ReleaseDestination call.
func adr0428ReleasePM(name string, tier storage.StorageTier) *pmv1.PodMigration {
	tv := int32(tier)
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "pg-0", PodNamespace: "default"},
		Status: pmv1.PodMigrationStatus{
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			StorageTier:         &tv,
			ClassifiedVolumes: []pmv1.PVCTierClassification{{
				Tier:         tv,
				PVCName:      "data",
				StorageClass: "irrelevant-for-this-test",
			}},
		},
	}
}

func setStorageCutoverCondition(pm *pmv1.PodMigration, status metav1.ConditionStatus, reason string) {
	meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
		Type:               pmv1.ConditionStorageCutoverComplete,
		Status:             status,
		Reason:             reason,
		Message:            "test-seeded",
		LastTransitionTime: metav1.Now(),
	})
}

type adr0428StubMigrator struct {
	tier                    storage.StorageTier
	ReleaseDestinationCalls int
	lastOpts                storage.MigrationOptions
}

func (s *adr0428StubMigrator) Tier() storage.StorageTier { return s.tier }
func (s *adr0428StubMigrator) PreStage(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}
func (s *adr0428StubMigrator) SyncPercent(_ context.Context, _ storage.MigrationOptions) (int, error) {
	return 100, nil
}
func (s *adr0428StubMigrator) Cutover(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}
func (s *adr0428StubMigrator) AwaitSingleOwner(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}
func (s *adr0428StubMigrator) ReleaseDestination(_ context.Context, opts storage.MigrationOptions) error {
	s.ReleaseDestinationCalls++
	s.lastOpts = opts
	return nil
}

// TestADR0428_CutoverVerdictUsesUncachedReader is the primary D7 proof: with a real cutover on
// F1 and a frozen (pre-cutover) client wired as Client, the verdict computed by
// ReleaseDestination must still be CutoverComplete==true when APIReader is wired to F1.
func TestADR0428_CutoverVerdictUsesUncachedReader(t *testing.T) {
	scheme := adr0428ManagerScheme(t)
	pm := adr0428ReleasePM("pm-0428-d7-1", storage.TierLonghorn)
	setStorageCutoverCondition(pm, metav1.ConditionTrue, "CutoverComplete")
	frozen := pm.DeepCopy()
	frozen.Status.Conditions = nil // frozen: pre-cutover, condition absent

	f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	frozenClient := interceptor.NewClient(f1, interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			if pmObj, ok := obj.(*pmv1.PodMigration); ok {
				frozen.DeepCopyInto(pmObj)
				return nil
			}
			return nil
		},
	})

	fakeMigrator := &adr0428StubMigrator{tier: storage.TierLonghorn}

	mgr := &storage.StorageMigrationManager{
		Client:     frozenClient,
		APIReader:  f1,
		Classifier: storage.NewStorageClassifier(f1),
		Migrators:  map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: fakeMigrator},
	}

	if err := mgr.ReleaseDestination(context.Background(), pm); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fakeMigrator.ReleaseDestinationCalls != 1 {
		t.Fatalf("expected ReleaseDestination dispatched exactly once, got %d", fakeMigrator.ReleaseDestinationCalls)
	}
	if !fakeMigrator.lastOpts.CutoverComplete {
		t.Fatal("with APIReader wired, CutoverComplete must be computed from the API SERVER (true), not the lagging cache")
	}
}

// NEGATIVE CONTROL — the same A/B discipline as controller assertion 2: with APIReader nil,
// readBackReader() falls back to the frozen Client, and the verdict is the fabricated-success
// input (CutoverComplete==false for a cutover that provably ran).
func TestADR0428_CutoverVerdictNegativeControl_NilAPIReaderFabricatesFalse(t *testing.T) {
	// This proves the READER, not a Tier-1 consequence: the real LonghornMigrator does not
	// consult opts.CutoverComplete. See ADR-0428 D7.0.
	scheme := adr0428ManagerScheme(t)
	pm := adr0428ReleasePM("pm-0428-d7-2", storage.TierLonghorn)
	setStorageCutoverCondition(pm, metav1.ConditionTrue, "CutoverComplete")
	frozen := pm.DeepCopy()
	frozen.Status.Conditions = nil

	f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	frozenClient := interceptor.NewClient(f1, interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			if pmObj, ok := obj.(*pmv1.PodMigration); ok {
				frozen.DeepCopyInto(pmObj)
				return nil
			}
			return nil
		},
	})

	fakeMigrator := &adr0428StubMigrator{tier: storage.TierLonghorn}
	mgr := &storage.StorageMigrationManager{
		Client:     frozenClient,
		APIReader:  nil, // falls back to Client
		Classifier: storage.NewStorageClassifier(f1),
		Migrators:  map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: fakeMigrator},
	}

	if err := mgr.ReleaseDestination(context.Background(), pm); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fakeMigrator.ReleaseDestinationCalls != 1 {
		t.Fatalf("expected ReleaseDestination dispatched exactly once, got %d — otherwise the CutoverComplete==false check below is non-vacuous only by accident", fakeMigrator.ReleaseDestinationCalls)
	}
	if fakeMigrator.lastOpts.CutoverComplete {
		t.Fatal("FAILED VERIFICATION: with APIReader nil over a frozen client, this must fabricate CutoverComplete==false — it did not, so this control does not demonstrate D7's fix")
	}
}

// ROUND-3 ADDITION — 7b, THE CONSEQUENCE CONTROL, on branches that actually consult the flag
// in the shipped configuration: CephRBDStubMigrator (Tier2) and SnapshotRsyncStubMigrator
// (Tier3), both real, unmodified, ACTUALLY deployed by NewStorageMigrationManager.
func TestADR0428_ConsequenceControl_Tier2Stub_FixedVsUnfixed(t *testing.T) {
	scheme := adr0428ManagerScheme(t)
	pm := adr0428ReleasePM("pm-0428-d7-7b-t2", storage.TierCephRBD)
	setStorageCutoverCondition(pm, metav1.ConditionTrue, "CutoverComplete")
	frozen := pm.DeepCopy()
	frozen.Status.Conditions = nil

	buildMgr := func(apiReaderWired bool) (*storage.StorageMigrationManager, *storage.CephRBDStubMigrator) {
		f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm.DeepCopy()).Build()
		frozenClient := interceptor.NewClient(f1, interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if pmObj, ok := obj.(*pmv1.PodMigration); ok {
					frozen.DeepCopyInto(pmObj)
					return nil
				}
				return nil
			},
		})
		var apiReader client.Reader
		if apiReaderWired {
			apiReader = f1
		}
		migrator := &storage.CephRBDStubMigrator{}
		return &storage.StorageMigrationManager{
			Client:     frozenClient,
			APIReader:  apiReader,
			Classifier: storage.NewStorageClassifier(f1),
			Migrators:  map[storage.StorageTier]storage.Migrator{storage.TierCephRBD: migrator},
		}, migrator
	}

	// Fixed: APIReader wired — must return the loud sentinel.
	fixedMgr, fixedMigrator := buildMgr(true)
	fixedErr := fixedMgr.ReleaseDestination(context.Background(), pm)
	if fixedErr == nil || !errors.Is(fixedErr, storage.ErrRollbackPointOfNoReturn) {
		t.Fatalf("fixed (APIReader wired): expected wrapped ErrRollbackPointOfNoReturn, got: %v", fixedErr)
	}
	if !fixedMigrator.ReleaseDestinationCalled {
		t.Fatal("expected ReleaseDestination dispatched on the fixed variant — otherwise the error assertion above is non-vacuous only by accident")
	}

	// Unfixed: APIReader nil over frozen client — fabricates bare nil "nothing to release."
	unfixedMgr, unfixedMigrator := buildMgr(false)
	unfixedErr := unfixedMgr.ReleaseDestination(context.Background(), pm)
	if unfixedErr != nil {
		t.Fatalf("FAILED VERIFICATION: expected the unfixed (nil APIReader) variant to fabricate a bare nil, got: %v — both variants agree, this control demonstrates nothing", unfixedErr)
	}
	if !unfixedMigrator.ReleaseDestinationCalled {
		t.Fatal("expected ReleaseDestination dispatched on the unfixed variant too — otherwise the nil-error assertion above is non-vacuous only by accident")
	}
}

func TestADR0428_ConsequenceControl_Tier3Stub_FixedVsUnfixed(t *testing.T) {
	scheme := adr0428ManagerScheme(t)
	pm := adr0428ReleasePM("pm-0428-d7-7b-t3", storage.TierSnapshotRsync)
	setStorageCutoverCondition(pm, metav1.ConditionTrue, "CutoverComplete")
	frozen := pm.DeepCopy()
	frozen.Status.Conditions = nil

	buildMgr := func(apiReaderWired bool) (*storage.StorageMigrationManager, *storage.SnapshotRsyncStubMigrator) {
		f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm.DeepCopy()).Build()
		frozenClient := interceptor.NewClient(f1, interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if pmObj, ok := obj.(*pmv1.PodMigration); ok {
					frozen.DeepCopyInto(pmObj)
					return nil
				}
				return nil
			},
		})
		var apiReader client.Reader
		if apiReaderWired {
			apiReader = f1
		}
		migrator := &storage.SnapshotRsyncStubMigrator{}
		return &storage.StorageMigrationManager{
			Client:     frozenClient,
			APIReader:  apiReader,
			Classifier: storage.NewStorageClassifier(f1),
			Migrators:  map[storage.StorageTier]storage.Migrator{storage.TierSnapshotRsync: migrator},
		}, migrator
	}

	fixedMgr, fixedMigrator := buildMgr(true)
	fixedErr := fixedMgr.ReleaseDestination(context.Background(), pm)
	if fixedErr == nil || !errors.Is(fixedErr, storage.ErrRollbackNotImplemented) {
		t.Fatalf("fixed (APIReader wired): expected wrapped ErrRollbackNotImplemented, got: %v", fixedErr)
	}
	if !fixedMigrator.ReleaseDestinationCalled {
		t.Fatal("expected ReleaseDestination dispatched on the fixed variant — otherwise the error assertion above is non-vacuous only by accident")
	}

	unfixedMgr, unfixedMigrator := buildMgr(false)
	unfixedErr := unfixedMgr.ReleaseDestination(context.Background(), pm)
	if unfixedErr != nil {
		t.Fatalf("FAILED VERIFICATION: expected the unfixed (nil APIReader) variant to fabricate a bare nil, got: %v", unfixedErr)
	}
	if !unfixedMigrator.ReleaseDestinationCalled {
		t.Fatal("expected ReleaseDestination dispatched on the unfixed variant too — otherwise the nil-error assertion above is non-vacuous only by accident")
	}
}

// Tier-1 NEGATIVE RESULT, recorded deliberately: the real LonghornMigrator does not read
// opts.CutoverComplete at all (tier1.go:351-356, :361-396), so the fixed/unfixed A/B must show
// NO behavioral difference. ROUND-4 REWRITE (implementation-review panel finding): driven against the REAL
// storage.NewLonghornMigrator (tier1.go:83) talking to an httptest stub Longhorn HTTP endpoint —
// not the adr0428StubMigrator fake, which trivially ignores opts.CutoverComplete by construction
// and so could never fail even if LonghornMigrator.ReleaseDestination grew a CutoverComplete gate.
// Follows the same httptest-driven LonghornMigrator pattern as tier1_test.go /
// adr0368_release_destination_test.go / tier1_internal_test.go. Asserts the A/B (APIReader wired
// vs nil) produces an IDENTICAL detach request sequence against the real migrator.
func TestADR0428_Tier1NegativeResult_NoBehavioralDifference(t *testing.T) {
	scheme := adr0428ManagerScheme(t)
	pm := adr0428ReleasePM("pm-0428-d7-7b-t1", storage.TierLonghorn)
	setStorageCutoverCondition(pm, metav1.ConditionTrue, "CutoverComplete")
	frozen := pm.DeepCopy()
	frozen.Status.Conditions = nil

	const (
		namespace = "default"
		pvcName   = "data" // matches adr0428ReleasePM's ClassifiedVolumes[0].PVCName
		pvName    = "pvc-adr0428-d7-t1-longhorn"
		destNode  = "pm-w2" // matches adr0428ReleasePM's Status.DestinationNodeName
	)

	run := func(apiReaderWired bool) (seq []string, calls int, cutoverComplete bool, err error) {
		var mu sync.Mutex
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seq = append(seq, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
			calls++
			mu.Unlock()
			switch {
			case r.Method == http.MethodPost && r.URL.Query().Get("action") == "detach":
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodGet:
				// No controller running on destNode — models an already-released volume so
				// pollUntilDetached returns on the very first poll (keeps the test fast and
				// deterministic; the point of this test is the REQUEST SEQUENCE, not timing).
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"name":"` + pvName + `","controllers":[]}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		pvc := makeBoundPVC(namespace, pvcName, pvName)
		f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).
			WithObjects(pm.DeepCopy(), pvc).Build()
		frozenClient := interceptor.NewClient(f1, interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if pmObj, ok := obj.(*pmv1.PodMigration); ok {
					frozen.DeepCopyInto(pmObj)
					return nil
				}
				return nil
			},
		})
		var apiReader client.Reader
		if apiReaderWired {
			apiReader = f1
		}
		// The real, production LonghornMigrator (tier1.go:83) — NOT a fake. Its own k8s client
		// (used only to resolve the PVC's bound PV name) is the unfrozen f1, independent of
		// mgr.Client/mgr.APIReader, matching production wiring where the migrator resolves
		// volume names off the live cluster regardless of the ADR-0428 D7 reader in question.
		realLonghorn := storage.NewLonghornMigrator(srv.URL, f1)
		mgr := &storage.StorageMigrationManager{
			Client:     frozenClient,
			APIReader:  apiReader,
			Classifier: storage.NewStorageClassifier(f1),
			Migrators:  map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: realLonghorn},
		}
		err = mgr.ReleaseDestination(context.Background(), pm)
		return seq, calls, false, err // CutoverComplete is not observable through the real migrator (D7.0's point)
	}

	fixedSeq, fixedCalls, _, fixedErr := run(true)
	unfixedSeq, unfixedCalls, _, unfixedErr := run(false)

	if fixedErr != nil || unfixedErr != nil {
		t.Fatalf("Tier-1 ReleaseDestination must never error here: fixed=%v unfixed=%v", fixedErr, unfixedErr)
	}
	if fixedCalls == 0 || unfixedCalls == 0 {
		t.Fatalf("expected at least one Longhorn HTTP call in each variant (a detach POST plus a poll GET), got fixed=%d unfixed=%d", fixedCalls, unfixedCalls)
	}
	// THE ASSERTION THAT MAKES THIS TEST ABLE TO FAIL: if LonghornMigrator.ReleaseDestination
	// ever grows an opts.CutoverComplete gate (the Tier-2/Tier-3 shape), the fixed variant
	// (CutoverComplete computed true) and the unfixed variant (fabricated false) would diverge —
	// e.g. the unfixed run would skip the detach POST entirely. Asserting the two REAL request
	// sequences are byte-for-byte identical is the regression guard the fake could never provide.
	if len(fixedSeq) != len(unfixedSeq) {
		t.Fatalf("fixed and unfixed request sequences differ in length — LonghornMigrator.ReleaseDestination may now consult opts.CutoverComplete: fixed=%v unfixed=%v", fixedSeq, unfixedSeq)
	}
	for i := range fixedSeq {
		if fixedSeq[i] != unfixedSeq[i] {
			t.Fatalf("fixed and unfixed request sequences diverge at index %d — LonghornMigrator.ReleaseDestination may now consult opts.CutoverComplete: fixed=%v unfixed=%v", i, fixedSeq, unfixedSeq)
		}
	}
	sawDetach := false
	for _, req := range fixedSeq {
		if strings.Contains(req, "action=detach") {
			sawDetach = true
		}
	}
	if !sawDetach {
		t.Fatalf("expected a detach POST in the request sequence, got: %v", fixedSeq)
	}
}

// ASSERT (fail-loud preserved): an unreadable API server must never be reported as "nothing to
// release."
func TestADR0428_ReleaseDestination_APIReaderErrorFailsLoud(t *testing.T) {
	scheme := adr0428ManagerScheme(t)
	pm := adr0428ReleasePM("pm-0428-d7-failloud", storage.TierLonghorn)

	f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	errReader := interceptor.NewClient(f1, interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			if _, ok := obj.(*pmv1.PodMigration); ok {
				return errors.New("simulated apiserver error")
			}
			return nil
		},
	})
	mgr := &storage.StorageMigrationManager{
		Client:     f1,
		APIReader:  errReader,
		Classifier: storage.NewStorageClassifier(f1),
		Migrators:  map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: &adr0428StubMigrator{tier: storage.TierLonghorn}},
	}

	err := mgr.ReleaseDestination(context.Background(), pm)
	if err == nil {
		t.Fatal("an unreadable API server must return a non-nil error, never a fabricated nil")
	}
}

// ASSERT (no regression to the classification path): with StorageTier nil, ReleaseDestination
// still returns nil via the errNoCachedClassification branch — D7 changes which reader answers,
// not the ADR-0368 contract.
func TestADR0428_ReleaseDestination_NoCachedClassification_StillReturnsNil(t *testing.T) {
	scheme := adr0428ManagerScheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "pm-0428-d7-noclass", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "pg-0", PodNamespace: "default"},
	}
	f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	mgr := &storage.StorageMigrationManager{
		Client:     f1,
		APIReader:  f1,
		Classifier: storage.NewStorageClassifier(f1),
		Migrators:  map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: &adr0428StubMigrator{tier: storage.TierLonghorn}},
	}
	if err := mgr.ReleaseDestination(context.Background(), pm); err != nil {
		t.Fatalf("expected nil (no cached classification is a recoverable no-op), got: %v", err)
	}
}
