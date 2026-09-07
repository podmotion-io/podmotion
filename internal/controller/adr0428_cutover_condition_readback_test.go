/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0428_cutover_condition_readback_test.go — ADR-0428 §P-VERIFY coverage for D1a/D1b/D1c:
// gateStorageCutoverBeforeRestore's post-cutover re-fetch (D1a) and pre-cutover idempotency
// short-circuit (D1b) must go through the uncached APIReader, and the guard's Cutover-skip
// decision must ask storage.CutoverSideEffectOccurred rather than a bare IsStatusConditionTrue
// (D1c) — never the cache-backed r.Client, which is not read-after-write consistent with
// StorageMigrationManager.patchStorageCutover's direct Status().Update landed earlier in the
// same reconcile pass.
//
// Fixture (§P-VERIFY.0): F1 is the live store (fake client modelling the API server). F2 is a
// frozen-cache interceptor over F1 that always (or, in bounded-lag mode, for the first K
// PodMigration Gets) returns a deep copy captured BEFORE the cutover — modelling an informer
// that has not yet delivered the watch event. F3 is a counting stub Migrator. F4 is a REAL
// StorageMigrationManager built by literal (not the constructor, which would overwrite
// Migrators). F5/F6: the classification cache (StorageTier + ClassifiedVolumes) is seeded on
// BOTH the live object and the frozen copy, so the guard's dispatch to buildMigrationOptionsFromCache
// never short-circuits into errNoCachedClassification — a precondition miss that would make the
// test pass while exercising nothing (this is the false-green trap the ADR names explicitly).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// ── F1-F7 fixture helpers ───────────────────────────────────────────────────

func adr0428Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := pmv1.AddToScheme(s); err != nil {
		t.Fatalf("add pmv1: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	return s
}

// adr0428PM builds a PodMigration carrying the F5 classification-cache seed: BOTH StorageTier
// (non-nil, passes buildMigrationOptionsFromCache's :384 guard) and a non-empty ClassifiedVolumes
// entry (what HighestTier reduces to select the migrator — an empty slice would dispatch to
// TierRWX instead, a second, distinct false-green trap the ADR names).
func adr0428PM(name string) *pmv1.PodMigration {
	tier := int32(storage.TierLonghorn)
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "pg-0",
			PodNamespace: "default",
		},
		Status: pmv1.PodMigrationStatus{
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			StorageTier:         &tier,
			ClassifiedVolumes: []pmv1.PVCTierClassification{{
				Tier:         int32(storage.TierLonghorn),
				PVCName:      "data",
				StorageClass: "longhorn-migratable",
				Reason:       "longhorn RWX dual-engine migratable",
			}},
		},
	}
}

// countingReader wraps a client and counts the *pmv1.PodMigration Gets it serves.
func countingReader(base client.WithWatch, counter *int) client.WithWatch {
	return interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*pmv1.PodMigration); ok {
				*counter++
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
}

// frozenCacheReader (F2) always returns a deep copy of frozen for *pmv1.PodMigration Gets when
// k < 0, or serves the frozen copy for the first k PodMigration Gets and the live store
// thereafter (assertion 6's bounded-lag mode) — counter-based, fully deterministic, no sleeps.
func frozenCacheReader(base client.WithWatch, frozen *pmv1.PodMigration, k int, getCount *int) client.WithWatch {
	return interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			pmObj, ok := obj.(*pmv1.PodMigration)
			if !ok {
				return cl.Get(ctx, key, obj, opts...)
			}
			*getCount++
			if k < 0 || *getCount <= k {
				frozen.DeepCopyInto(pmObj)
				return nil
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
}

// fakeCutoverMigrator (F3) is a counting stub Migrator implementing the full storage.Migrator
// interface. All call counting happens here, never at the manager, which is real. cutoverErr and
// awaitErr are returned by every call (queues are not needed — each §P-VERIFY assertion builds a
// fresh fixture) unless awaitAlwaysFails is set, which forces AwaitSingleOwner to fail forever
// (assertion 5g's non-converging arm).
type fakeCutoverMigrator struct {
	tier                    storage.StorageTier
	cutoverErr              error
	awaitErr                error
	awaitAlwaysFails        bool
	CutoverCalls            int
	AwaitSingleOwnerCalls   int
	ReleaseDestinationCalls int
}

func (f *fakeCutoverMigrator) Tier() storage.StorageTier { return f.tier }
func (f *fakeCutoverMigrator) PreStage(_ context.Context, _ storage.MigrationOptions) error {
	return nil
}
func (f *fakeCutoverMigrator) SyncPercent(_ context.Context, _ storage.MigrationOptions) (int, error) {
	return 100, nil
}
func (f *fakeCutoverMigrator) Cutover(_ context.Context, _ storage.MigrationOptions) error {
	f.CutoverCalls++
	return f.cutoverErr
}
func (f *fakeCutoverMigrator) AwaitSingleOwner(_ context.Context, _ storage.MigrationOptions) error {
	f.AwaitSingleOwnerCalls++
	if f.awaitAlwaysFails {
		return errors.New("fake: single-owner collapse never confirmed")
	}
	return f.awaitErr
}
func (f *fakeCutoverMigrator) ReleaseDestination(_ context.Context, _ storage.MigrationOptions) error {
	f.ReleaseDestinationCalls++
	return nil
}

// adr0428Fixture bundles F1 (live store), the fake migrator (F3), and a reconciler wired per the
// caller's chosen client/APIReader combination (F4 constructed by literal). base is the plain
// fake client over F1 that the caller wires directly where a read-after-write-consistent view of
// the live store is wanted (e.g. as StorageMgr.Client / StorageMgr.APIReader, which must always
// see real writes — only the CONTROLLER's r.Client is ever the frozen one under test).
type adr0428Fixture struct {
	f1         client.WithWatch
	migrator   *fakeCutoverMigrator
	storageMgr *storage.StorageMigrationManager
}

func newADR0428Fixture(t *testing.T, scheme *runtime.Scheme, pm *pmv1.PodMigration, migrator *fakeCutoverMigrator) *adr0428Fixture {
	t.Helper()
	f1 := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	storageMgr := &storage.StorageMigrationManager{
		Client:     f1,
		APIReader:  f1,
		Classifier: storage.NewStorageClassifier(f1),
		Migrators:  map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: migrator},
	}
	return &adr0428Fixture{f1: f1, migrator: migrator, storageMgr: storageMgr}
}

func adr0428GetPM(t *testing.T, c client.Client, name string) *pmv1.PodMigration {
	t.Helper()
	got := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, got); err != nil {
		t.Fatalf("get PodMigration %s: %v", name, err)
	}
	return got
}

func hasTrueCutoverComplete(conds []metav1.Condition) bool {
	c := meta.FindStatusCondition(conds, pmv1.ConditionStorageCutoverComplete)
	return c != nil && c.Status == metav1.ConditionTrue && c.Reason == "CutoverComplete"
}

// ── Assertion 1: DETERMINISTIC RACE REPRODUCTION — the primary proof for D1a ────────────────

func TestADR0428_GuardSurvivesStaleCache(t *testing.T) {
	scheme := adr0428Scheme(t)
	pm := adr0428PM("pm-0428-1")
	frozen := pm.DeepCopy() // captured BEFORE cutover

	migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
	fx := newADR0428Fixture(t, scheme, pm, migrator)

	var clientGets, apiReaderGets int
	cachedClient := frozenCacheReader(fx.f1, frozen, -1, &clientGets)
	uncachedReader := countingReader(fx.f1, &apiReaderGets)

	r := &PodMigrationReconciler{Client: cachedClient, APIReader: uncachedReader, Scheme: scheme, StorageMgr: fx.storageMgr}

	res, ready, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// F7 self-check.
	if migrator.CutoverCalls != 1 || migrator.AwaitSingleOwnerCalls != 1 {
		t.Fatalf("F7 self-check failed: CutoverCalls=%d AwaitSingleOwnerCalls=%d, want 1/1",
			migrator.CutoverCalls, migrator.AwaitSingleOwnerCalls)
	}

	live := adr0428GetPM(t, fx.f1, pm.Name)
	if !hasTrueCutoverComplete(live.Status.Conditions) {
		t.Fatalf("real patchStorageCutover should have landed StorageCutoverComplete=True on F1, got: %+v", live.Status.Conditions)
	}
	if hasTrueCutoverComplete(frozen.Status.Conditions) {
		t.Fatalf("frozen pre-cutover copy must NOT show the condition — fixture is not modelling staleness")
	}

	if !ready {
		t.Fatalf("guard must return ready=true, got ready=false (res=%+v)", res)
	}
	if !hasTrueCutoverComplete(pm.Status.Conditions) {
		t.Fatalf("pm.Status.Conditions must contain StorageCutoverComplete=True after the call — this is the property that failed live, got: %+v", pm.Status.Conditions)
	}
	for _, frozenCond := range frozen.Status.Conditions {
		found := meta.FindStatusCondition(pm.Status.Conditions, frozenCond.Type)
		if found == nil {
			t.Errorf("condition %s present on the frozen pre-cutover copy was dropped by the guard", frozenCond.Type)
		}
	}
	if apiReaderGets != 2 {
		t.Fatalf("expected exactly 2 uncached PodMigration Gets (D1b pre-cutover re-check + D1a post-cutover re-fetch), got %d", apiReaderGets)
	}
	if clientGets != 0 {
		t.Fatalf("expected ZERO PodMigration Gets served by the frozen cached client from inside the guard, got %d", clientGets)
	}
}

// ── Assertion 2: TRUE NEGATIVE CONTROL — the unmodified production function loses the
// condition when both reads are cached (APIReader nil, r.Client frozen) ─────────────────────

func TestADR0428_StaleCacheClobbersCondition_CachedReaderFallback(t *testing.T) {
	scheme := adr0428Scheme(t)
	pm := adr0428PM("pm-0428-2")
	frozen := pm.DeepCopy()

	migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
	fx := newADR0428Fixture(t, scheme, pm, migrator)

	var clientGets int
	cachedClient := frozenCacheReader(fx.f1, frozen, -1, &clientGets)

	// APIReader left nil: readBackReader() falls back to r.Client, the documented,
	// in-tree, production nil-fallback, exercised as-is.
	r := &PodMigrationReconciler{Client: cachedClient, Scheme: scheme, StorageMgr: fx.storageMgr}

	_, _, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	live := adr0428GetPM(t, fx.f1, pm.Name)
	if !hasTrueCutoverComplete(live.Status.Conditions) {
		t.Fatalf("F7 check: the real patchStorageCutover must still have landed on F1, got: %+v", live.Status.Conditions)
	}
	if hasTrueCutoverComplete(pm.Status.Conditions) {
		t.Fatal("FAILED VERIFICATION: with both reads cached-and-frozen, the condition must be LOST from pm.Status.Conditions — it was not, meaning this control does not model the race and assertion 1 proves nothing")
	}
}

// ── Assertion 3: WIRING / FALLBACK on a CONSISTENT store ────────────────────────────────────

func TestADR0428_FallsBackToClientWhenAPIReaderNil(t *testing.T) {
	scheme := adr0428Scheme(t)
	pm := adr0428PM("pm-0428-3")

	migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
	fx := newADR0428Fixture(t, scheme, pm, migrator)

	// r.Client wired to a plain read-after-write-consistent fake over F1 — NOT the frozen
	// interceptor. Deliberately a distinct fixture from assertion 2's.
	r := &PodMigrationReconciler{Client: fx.f1, Scheme: scheme, StorageMgr: fx.storageMgr}
	if r.readBackReader() != client.Reader(fx.f1) {
		t.Fatal("readBackReader() must return r.Client when APIReader is nil")
	}

	_, ready, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ready {
		t.Fatal("expected ready=true")
	}
	if !hasTrueCutoverComplete(pm.Status.Conditions) {
		t.Fatalf("expected StorageCutoverComplete=True present, got: %+v", pm.Status.Conditions)
	}
}

// ── Assertion 4: ERROR DISPOSITION PRESERVED — both uncached reads fail closed ──────────────

func TestADR0428_UncachedReadErrorBlocksTransition_PostCutover(t *testing.T) {
	scheme := adr0428Scheme(t)
	pm := adr0428PM("pm-0428-4a")

	migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
	fx := newADR0428Fixture(t, scheme, pm, migrator)

	// The FIRST PodMigration Get (D1b's pre-cutover authoritative re-check) must succeed so the
	// guard proceeds to dispatch the real Cutover/AwaitSingleOwner; the SECOND (D1a's
	// post-cutover re-fetch) is the one under test here and must error.
	var pmGets int
	errReader := interceptor.NewClient(fx.f1, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*pmv1.PodMigration); ok {
				pmGets++
				if pmGets >= 2 {
					return fmt.Errorf("simulated apiserver error")
				}
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})

	r := &PodMigrationReconciler{Client: fx.f1, APIReader: errReader, Scheme: scheme, StorageMgr: fx.storageMgr}
	_, ready, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm)
	if ready {
		t.Fatal("ready must be false on an uncached read error")
	}
	if err == nil || !containsAll(err.Error(), "re-fetch PodMigration after storage cutover") {
		t.Fatalf("expected the post-cutover re-fetch error, got: %v", err)
	}
}

func TestADR0428_UncachedReadErrorBlocksTransition_PreCutover(t *testing.T) {
	scheme := adr0428Scheme(t)
	pm := adr0428PM("pm-0428-4b")

	migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
	fx := newADR0428Fixture(t, scheme, pm, migrator)

	// First Get (the D1b pre-cutover re-check) errors; nothing else is reached.
	errReader := interceptor.NewClient(fx.f1, interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			if _, ok := obj.(*pmv1.PodMigration); ok {
				return fmt.Errorf("simulated apiserver error")
			}
			return nil
		},
	})

	r := &PodMigrationReconciler{Client: fx.f1, APIReader: errReader, Scheme: scheme, StorageMgr: fx.storageMgr}
	_, ready, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm)
	if ready {
		t.Fatal("ready must be false on an uncached read error")
	}
	if err == nil || !containsAll(err.Error(), "authoritative re-check of storage-cutover condition before cutover") {
		t.Fatalf("expected the pre-cutover authoritative re-check error, got: %v", err)
	}
	if migrator.CutoverCalls != 0 {
		t.Fatalf("a failed authoritative read must REFUSE, never fall through into a real cutover; got CutoverCalls=%d", migrator.CutoverCalls)
	}
}

// ── Assertion 5: IDEMPOTENCY SHORT-CIRCUIT ───────────────────────────────────────────────────

func TestADR0428_ShortCircuit_CachedTrue_CheapPathIntact(t *testing.T) {
	// 5a
	scheme := adr0428Scheme(t)
	pm := adr0428PM("pm-0428-5a")
	setCondition(pm, pmv1.ConditionStorageCutoverComplete, metav1.ConditionTrue, "CutoverComplete", "already true in-memory")

	migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
	fx := newADR0428Fixture(t, scheme, pm, migrator)

	var clientGets, apiReaderGets int
	cachedClient := countingReader(fx.f1, &clientGets)
	uncachedReader := countingReader(fx.f1, &apiReaderGets)
	r := &PodMigrationReconciler{Client: cachedClient, APIReader: uncachedReader, Scheme: scheme, StorageMgr: fx.storageMgr}

	_, ready, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm)
	if err != nil || !ready {
		t.Fatalf("expected ready=true, err=nil; got ready=%v err=%v", ready, err)
	}
	if migrator.CutoverCalls != 0 || migrator.AwaitSingleOwnerCalls != 0 {
		t.Fatalf("cheap path must not dispatch to the migrator: CutoverCalls=%d AwaitSingleOwnerCalls=%d", migrator.CutoverCalls, migrator.AwaitSingleOwnerCalls)
	}
	if clientGets != 0 || apiReaderGets != 0 {
		t.Fatalf("cached True must short-circuit with ZERO reads through either reader; got clientGets=%d apiReaderGets=%d", clientGets, apiReaderGets)
	}
}

func TestADR0428_ShortCircuit_CachedFalseServerTrue_D1bProof(t *testing.T) {
	// 5b — the exact state produced by the interleaving in Blast-factor 2.
	scheme := adr0428Scheme(t)
	pm := adr0428PM("pm-0428-5b") // in-memory: condition absent

	live := pm.DeepCopy()
	setCondition(live, pmv1.ConditionStorageCutoverComplete, metav1.ConditionTrue, "CutoverComplete", "landed in a prior pass")

	migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
	f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(live).Build()
	storageMgr := &storage.StorageMigrationManager{
		Client: f1, APIReader: f1, Classifier: storage.NewStorageClassifier(f1),
		Migrators: map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: migrator},
	}

	var apiReaderGets int
	uncachedReader := countingReader(f1, &apiReaderGets)
	r := &PodMigrationReconciler{Client: f1, APIReader: uncachedReader, Scheme: scheme, StorageMgr: storageMgr}

	_, ready, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm)
	if err != nil || !ready {
		t.Fatalf("expected ready=true, err=nil; got ready=%v err=%v", ready, err)
	}
	if migrator.CutoverCalls != 0 || migrator.AwaitSingleOwnerCalls != 0 {
		t.Fatalf("D1b must prevent the redundant, disruptive Longhorn detach/attach; got CutoverCalls=%d AwaitSingleOwnerCalls=%d (round-1 diff fails this with CutoverCalls==1)", migrator.CutoverCalls, migrator.AwaitSingleOwnerCalls)
	}
	if apiReaderGets != 1 {
		t.Fatalf("expected exactly 1 uncached Get (the D1b authoritative re-check), got %d", apiReaderGets)
	}
	if !hasTrueCutoverComplete(pm.Status.Conditions) {
		t.Fatalf("the authoritative list must be installed onto pm so the caller's blob write cannot re-clobber it, got: %+v", pm.Status.Conditions)
	}
}

func TestADR0428_ShortCircuit_BothReadsFalse_MustNotOverSuppress(t *testing.T) {
	// 5c
	scheme := adr0428Scheme(t)
	pm := adr0428PM("pm-0428-5c")

	migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
	fx := newADR0428Fixture(t, scheme, pm, migrator)
	r := &PodMigrationReconciler{Client: fx.f1, APIReader: fx.f1, Scheme: scheme, StorageMgr: fx.storageMgr}

	_, ready, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm)
	if err != nil || !ready {
		t.Fatalf("expected ready=true, err=nil; got ready=%v err=%v", ready, err)
	}
	if migrator.CutoverCalls != 1 || migrator.AwaitSingleOwnerCalls != 1 {
		t.Fatalf("both reads false must run exactly one real cutover; got CutoverCalls=%d AwaitSingleOwnerCalls=%d", migrator.CutoverCalls, migrator.AwaitSingleOwnerCalls)
	}
}

func TestADR0428_ShortCircuit_AwaitSingleOwnerTimeout_D1cProof(t *testing.T) {
	// 5d — the only sub-case with direct live evidence (podmotion-demo-dpr8n).
	scheme := adr0428Scheme(t)
	pm := adr0428PM("pm-0428-5d")
	setCondition(pm, pmv1.ConditionStorageCutoverComplete, metav1.ConditionFalse, "AwaitSingleOwnerTimeout", "collapse poll timed out in a prior pass")

	live := pm.DeepCopy() // both copies agree — no cache staleness needed for this sub-case

	migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
	f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(live).Build()
	storageMgr := &storage.StorageMigrationManager{
		Client: f1, APIReader: f1, Classifier: storage.NewStorageClassifier(f1),
		Migrators: map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: migrator},
	}
	r := &PodMigrationReconciler{Client: f1, APIReader: f1, Scheme: scheme, StorageMgr: storageMgr}

	_, ready, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm)
	if err != nil || !ready {
		t.Fatalf("expected ready=true, err=nil (D1c leaves the recovery path intact); got ready=%v err=%v", ready, err)
	}
	if migrator.CutoverCalls != 0 {
		t.Fatalf("the destination-side action already ran in a prior pass; Cutover must NOT be re-issued. Got CutoverCalls=%d (round-2 diff fails this with 1)", migrator.CutoverCalls)
	}
	if migrator.AwaitSingleOwnerCalls != 1 {
		t.Fatalf("the collapse poll is the step that did not finish and MUST still be retried; got AwaitSingleOwnerCalls=%d", migrator.AwaitSingleOwnerCalls)
	}
	if !hasTrueCutoverComplete(pm.Status.Conditions) {
		t.Fatalf("with AwaitSingleOwner now succeeding, patchStorageCutover must land True/CutoverComplete, got: %+v", pm.Status.Conditions)
	}
}

func TestADR0428_ShortCircuit_OtherFalseReasons_MustStillCutover(t *testing.T) {
	// 5e
	for _, reason := range []string{"CutoverFailed", "ClassifyFailed"} {
		t.Run(reason, func(t *testing.T) {
			scheme := adr0428Scheme(t)
			pm := adr0428PM("pm-0428-5e-" + reason)
			setCondition(pm, pmv1.ConditionStorageCutoverComplete, metav1.ConditionFalse, reason, "cutover genuinely never completed")
			live := pm.DeepCopy()

			migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
			f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(live).Build()
			storageMgr := &storage.StorageMigrationManager{
				Client: f1, APIReader: f1, Classifier: storage.NewStorageClassifier(f1),
				Migrators: map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: migrator},
			}
			r := &PodMigrationReconciler{Client: f1, APIReader: f1, Scheme: scheme, StorageMgr: storageMgr}

			_, _, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if migrator.CutoverCalls != 1 {
				t.Fatalf("reason=%s: Cutover must still run — CutoverSideEffectOccurred is false for this reason; got CutoverCalls=%d", reason, migrator.CutoverCalls)
			}
		})
	}
}

func TestADR0428_PredicateParity_5f(t *testing.T) {
	// 5f — the guard's Cutover-skip decision and storage.CutoverSideEffectOccurred must agree
	// for every input shape.
	cases := []struct {
		name     string
		seed     func(pm *pmv1.PodMigration)
		wantSkip bool
	}{
		{"absent", func(pm *pmv1.PodMigration) {}, false},
		{"True/CutoverComplete", func(pm *pmv1.PodMigration) {
			setCondition(pm, pmv1.ConditionStorageCutoverComplete, metav1.ConditionTrue, "CutoverComplete", "")
		}, true},
		{"False/AwaitSingleOwnerTimeout", func(pm *pmv1.PodMigration) {
			setCondition(pm, pmv1.ConditionStorageCutoverComplete, metav1.ConditionFalse, "AwaitSingleOwnerTimeout", "")
		}, true},
		{"False/CutoverFailed", func(pm *pmv1.PodMigration) {
			setCondition(pm, pmv1.ConditionStorageCutoverComplete, metav1.ConditionFalse, "CutoverFailed", "")
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := adr0428Scheme(t)
			pm := adr0428PM("pm-0428-5f-" + tc.name)
			tc.seed(pm)
			live := pm.DeepCopy()

			migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
			f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(live).Build()
			storageMgr := &storage.StorageMigrationManager{
				Client: f1, APIReader: f1, Classifier: storage.NewStorageClassifier(f1),
				Migrators: map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: migrator},
			}
			r := &PodMigrationReconciler{Client: f1, APIReader: f1, Scheme: scheme, StorageMgr: storageMgr}

			if _, _, err := r.gateStorageCutoverBeforeRestore(context.Background(), pm); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			skipped := migrator.CutoverCalls == 0
			if skipped != tc.wantSkip {
				t.Fatalf("guard skip=%v, storage.CutoverSideEffectOccurred implies skip=%v — DIVERGENT PREDICATES", skipped, tc.wantSkip)
			}
			predicateVerdict := storage.CutoverSideEffectOccurred(live.Status.Conditions)
			if predicateVerdict != tc.wantSkip {
				t.Fatalf("test precondition inconsistent with storage.CutoverSideEffectOccurred: got %v want %v", predicateVerdict, tc.wantSkip)
			}
		})
	}
}

func TestADR0428_NonConvergingArm_KeepsRetryingFailsClosed_5g(t *testing.T) {
	scheme := adr0428Scheme(t)
	pm := adr0428PM("pm-0428-5g")
	setCondition(pm, pmv1.ConditionStorageCutoverComplete, metav1.ConditionFalse, "AwaitSingleOwnerTimeout", "collapse poll timed out")
	live := pm.DeepCopy()

	migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn, awaitAlwaysFails: true}
	f1 := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(live).Build()
	storageMgr := &storage.StorageMigrationManager{
		Client: f1, APIReader: f1, Classifier: storage.NewStorageClassifier(f1),
		Migrators: map[storage.StorageTier]storage.Migrator{storage.TierLonghorn: migrator},
	}
	r := &PodMigrationReconciler{Client: f1, APIReader: f1, Scheme: scheme, StorageMgr: storageMgr}

	for pass := 1; pass <= 3; pass++ {
		wantAwaitCalls := pass
		// Re-read the CR fresh each pass, mirroring a real reconcile re-entry.
		fresh := adr0428GetPM(t, f1, pm.Name)
		_, ready, err := r.gateStorageCutoverBeforeRestore(context.Background(), fresh)
		if err != nil {
			t.Fatalf("pass %d: gate must never hard-error on a bounded AwaitSingleOwner failure, got: %v", pass, err)
		}
		if ready {
			t.Fatalf("pass %d: no phase transition may ever occur while the collapse never confirms", pass)
		}
		if migrator.CutoverCalls != 0 {
			t.Fatalf("pass %d: the skip must hold — Cutover must never be re-issued, got CutoverCalls=%d", pass, migrator.CutoverCalls)
		}
		if migrator.AwaitSingleOwnerCalls != wantAwaitCalls {
			t.Fatalf("pass %d: AwaitSingleOwnerCalls must increment by exactly one per pass, got %d want %d", pass, migrator.AwaitSingleOwnerCalls, wantAwaitCalls)
		}
	}
	final := adr0428GetPM(t, f1, pm.Name)
	cond := meta.FindStatusCondition(final.Status.Conditions, pmv1.ConditionStorageCutoverComplete)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "AwaitSingleOwnerTimeout" {
		t.Fatalf("condition must remain False/AwaitSingleOwnerTimeout on F1 (loud, recorded, fail-closed), got: %+v", cond)
	}
}

// ── Assertion 6: COMPOSED PATH, BOUNDED LAG ──────────────────────────────────────────────────

func TestADR0428_ConditionSurvivesGuardThenTransition(t *testing.T) {
	for _, k := range []int{0, 1, 2, 5, 20} {
		t.Run(fmt.Sprintf("K=%d", k), func(t *testing.T) {
			scheme := adr0428Scheme(t)
			pm := adr0428PM(fmt.Sprintf("pm-0428-6-k%d", k))
			// VXLANFDBUpdated must be True so reconcileOverlayHandoff dispatches to the gate.
			setCondition(pm, pmv1.ConditionVXLANFDBUpdated, metav1.ConditionTrue, "Done", "")
			pm.Status.Phase = pmv1.MigrationPhaseOverlayHandoff
			frozen := pm.DeepCopy()

			migrator := &fakeCutoverMigrator{tier: storage.TierLonghorn}
			fx := newADR0428Fixture(t, scheme, pm, migrator)

			var getCount int
			laggedClient := frozenCacheReader(fx.f1, frozen, k, &getCount)
			r := &PodMigrationReconciler{Client: laggedClient, APIReader: fx.f1, Scheme: scheme, StorageMgr: fx.storageMgr}

			ctx := context.Background()
			// Drive re-entries the way controller-runtime's requeue-on-error/requeue-on-Result
			// loop would: transitionTo's own cached re-Get (D2, deliberately left cached) can
			// 409 while the lag persists, which surfaces as an error here — that is a real
			// reconcile requeue, not a test failure, so long as it eventually converges once
			// getCount exceeds K.
			for attempt := 0; attempt < 40; attempt++ {
				result, err := r.reconcileOverlayHandoff(ctx, pm)
				if err != nil {
					// Conflict-driven requeue: re-fetch pm the way the next real Reconcile's
					// top-of-loop r.Get would, and try again.
					pm = adr0428GetPM(t, laggedClient, pm.Name)
					continue
				}
				live := adr0428GetPM(t, fx.f1, pm.Name)
				if live.Status.Phase == pmv1.MigrationPhaseRestoreSocketReattach {
					break
				}
				if result.RequeueAfter == 0 && !result.Requeue {
					t.Fatalf("K=%d attempt=%d: gate returned a terminal non-requeue result without reaching RestoreSocketReattach", k, attempt)
				}
				pm = adr0428GetPM(t, laggedClient, pm.Name)
				if attempt == 39 {
					t.Fatalf("K=%d: did not converge to RestoreSocketReattach within 40 attempts", k)
				}
			}

			live := adr0428GetPM(t, fx.f1, pm.Name)
			if !hasTrueCutoverComplete(live.Status.Conditions) {
				t.Fatalf("K=%d: F1 must hold StorageCutoverComplete=True after reconcileOverlayHandoff, got: %+v", k, live.Status.Conditions)
			}
			if live.Status.Phase != pmv1.MigrationPhaseRestoreSocketReattach {
				t.Fatalf("K=%d: phase must have advanced to RestoreSocketReattach, got %s", k, live.Status.Phase)
			}
			if migrator.CutoverCalls != 1 || migrator.AwaitSingleOwnerCalls != 1 {
				t.Fatalf("K=%d: expected exactly one real cutover across all re-entries, got CutoverCalls=%d AwaitSingleOwnerCalls=%d (round-1 diff drives these to 2 for large K)", k, migrator.CutoverCalls, migrator.AwaitSingleOwnerCalls)
			}
		})
	}
}

// ── Assertion 10: STATIC — the semantic regression guard ────────────────────────────────────

// TestADR0428_StaticGuard_PrimitiveStaysWired (10c) pins that both readBackReader() wiring
// lines exist in cmd/main.go, so a refactor that drops either one does not silently return
// production to the cached path while the unit suite stays green.
func TestADR0428_StaticGuard_PrimitiveStaysWired(t *testing.T) {
	t.Helper()
	// This is a same-repo source-text check (not a live build), matching the discipline of
	// the ADR's own §5.8 grounding greps. Kept minimal and explicit rather than a general
	// AST walk, since the two literal wiring lines are exactly what §Residual risk 6 names.
	src := mustReadFile(t, "../../cmd/main.go")
	gotAPIReaderRefs := strings.Count(src, "mgr.GetAPIReader()")
	if gotAPIReaderRefs < 2 {
		t.Errorf("cmd/main.go must wire mgr.GetAPIReader() at least twice — PodMigrationReconciler.APIReader (ADR-0410) and StorageMigrationManager.APIReader (ADR-0428 D7); found %d", gotAPIReaderRefs)
	}
	if !containsAll(src, "storageMgr.APIReader = mgr.GetAPIReader()") {
		t.Error("cmd/main.go must wire StorageMigrationManager.APIReader = mgr.GetAPIReader() (ADR-0428 D7)")
	}
}

// TestADR0428_StaticGuard_SoleDocumentedCachedReadException (10a) pins
// podmigration_controller.go:4293 — the checkpoint-slot claim's "re-fetch pm after checkpoint
// claim" read — as the ONE known, documented-as-open cached (non-readBackReader) whole-object
// re-read of pm anywhere in the tree (ADR-0428 D3a: a real instance of the D1a/D1b/D7 defect's
// literal shape, investigated and EXPLICITLY SCOPED OUT with a stated, materially-lower severity
// argument and a named follow-up — not silently missed). A NEW such call site — a cached read
// whose target is the bare "pm" identifier, i.e. shaped like `r.Get(ctx,
// client.ObjectKeyFromObject(pm), pm)` — outside this allowlist would be a silent, unreviewed
// instance of the same class this ADR closes, so this test fails loud rather than let one slip
// in. Matches the ADR's own D3 investigation discipline: a textual `Status.Conditions = ` grep is
// structurally blind to this whole-object shape, so this test greps for the SHAPE instead.
func TestADR0428_StaticGuard_SoleDocumentedCachedReadException(t *testing.T) {
	t.Helper()

	// allowlist: base filename -> set of allowed 1-indexed line numbers for a cached (non-
	// readBackReader) `.Get(ctx, <key-expr>, pm)` call — target is the bare identifier "pm".
	//
	// Do NOT add a second entry here without first updating ADR-0428 D3a (or a superseding ADR)
	// to record the new exception the same way D3a records this one.
	allowlist := map[string]map[int]bool{
		"podmigration_controller.go": {4293: true},
	}
	// excludeEntryPoints: Reconcile's own top-of-loop fetch (`r.Get(ctx, req.NamespacedName,
	// pm)`, podmigration_controller.go:348) is not a competing re-read of an already-fresher
	// write within the same pass — it is the ORIGIN read every other read in the reconcile
	// (including the guard's own D1a/D1b authoritative re-checks) is compared against, and it
	// precedes any ConditionStorageCutoverComplete write in this reconcile pass by construction.
	// Excluded by exact call site, not by a broad carve-out.
	excludeEntryPoints := map[string]map[int]bool{
		"podmigration_controller.go": {348: true},
	}

	dirs := []string{".", "../agent/storage"} // relative to this test file's package dir
	re := regexp.MustCompile(`\.Get\(ctx,\s*[^,]+,\s*pm\)`)

	found := map[string]map[int]bool{}
	var violations []string
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		for _, path := range matches {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			base := filepath.Base(path)
			src := mustReadFile(t, path)
			for i, line := range strings.Split(src, "\n") {
				lineNo := i + 1
				if !re.MatchString(line) {
					continue
				}
				if strings.Contains(line, "readBackReader()") {
					// D1a/D1b/ADR-0423's uncached read-back primitive — not the cached shape.
					continue
				}
				if excludeEntryPoints[base][lineNo] {
					continue
				}
				if allowlist[base][lineNo] {
					if found[base] == nil {
						found[base] = map[int]bool{}
					}
					found[base][lineNo] = true
					continue
				}
				violations = append(violations, fmt.Sprintf("%s:%d: %s", base, lineNo, strings.TrimSpace(line)))
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("found cached (non-readBackReader) whole-object Get(...,pm) call site(s) not in the ADR-0428 D3a allowlist — a NEW, unreviewed instance of the cached-condition-clobber defect class:\n%s", strings.Join(violations, "\n"))
	}
	for base, lines := range allowlist {
		for lineNo := range lines {
			if !found[base][lineNo] {
				t.Fatalf("allowlisted exception %s:%d (ADR-0428 D3a) no longer matches the expected shape — the code may have shifted; re-verify against source and re-pin this test's allowlist (and, if the shift is substantive, ADR-0428 D3a itself)", base, lineNo)
			}
		}
	}
}

// TestADR0428_StaticGuard_SoleCutoverSideEffectPredicate (10d) is the direct regression guard for
// the D1c defect class: a SECOND, independently hand-rolled predicate answering "has the
// destination-side storage action already executed?" silently drifting from
// storage.CutoverSideEffectOccurred — exactly what the guard's own bare IsStatusConditionTrue was
// before D1c. The semantically load-bearing line of that predicate is the AwaitSingleOwnerTimeout
// special case (manager.go's `cond.Reason == "AwaitSingleOwnerTimeout"`) — the ONE place in the
// tree that correctly answers "the condition is False but the destination-side action nonetheless
// already executed." A second occurrence of that same comparison anywhere else in non-test source
// is, by construction, a second hand-rolled predicate for the identical question.
func TestADR0428_StaticGuard_SoleCutoverSideEffectPredicate(t *testing.T) {
	t.Helper()

	re := regexp.MustCompile(`==\s*"AwaitSingleOwnerTimeout"`)
	allowlist := map[string]map[int]bool{
		"manager.go": {488: true}, // storage.CutoverSideEffectOccurred's own comparison
	}

	dirs := []string{".", "../agent/storage", "../rollback"}
	found := map[string]map[int]bool{}
	var violations []string
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		for _, path := range matches {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			base := filepath.Base(path)
			src := mustReadFile(t, path)
			for i, line := range strings.Split(src, "\n") {
				lineNo := i + 1
				if !re.MatchString(line) {
					continue
				}
				if allowlist[base][lineNo] {
					if found[base] == nil {
						found[base] = map[int]bool{}
					}
					found[base][lineNo] = true
					continue
				}
				violations = append(violations, fmt.Sprintf("%s:%d: %s", base, lineNo, strings.TrimSpace(line)))
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("found a SECOND hand-rolled predicate testing Reason == \"AwaitSingleOwnerTimeout\" outside storage.CutoverSideEffectOccurred (manager.go:488) — this is exactly the D1c divergent-predicate defect class reintroduced:\n%s", strings.Join(violations, "\n"))
	}
	for base, lines := range allowlist {
		for lineNo := range lines {
			if !found[base][lineNo] {
				t.Fatalf("allowlisted predicate line %s:%d no longer matches — storage.CutoverSideEffectOccurred may have moved or changed shape; re-verify against source and re-pin this test", base, lineNo)
			}
		}
	}

	// Belt-and-suspenders: confirm the guard's actual Cutover-skip decision calls
	// storage.CutoverSideEffectOccurred directly on the line that dispatches migrator.Cutover,
	// never a re-derived IsStatusConditionTrue.
	guardSrc := mustReadFile(t, "podmigration_controller.go")
	if !containsAll(guardSrc, "if !storage.CutoverSideEffectOccurred(authoritative.Status.Conditions) {") {
		t.Fatal("gateStorageCutoverBeforeRestore's Cutover-skip decision must call storage.CutoverSideEffectOccurred directly — found a different (possibly divergent) expression")
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
