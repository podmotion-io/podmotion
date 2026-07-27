/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"errors"
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// ADR-0400 verification assertions. The reconciler deletes a PM_BRIDGE_MAP entry
// only on the verified source-of-truth event, never on a clock, and fails closed on
// any non-definitive read.

// --- test doubles ---

type fakeBridgeOps struct {
	keys      []net.IP
	listErr   error
	disarmErr error
	disarmed  []string
}

func (f *fakeBridgeOps) ListXDPBridgeKeys(_ context.Context) ([]net.IP, error) {
	return f.keys, f.listErr
}

func (f *fakeBridgeOps) DisarmXDPBridge(_ context.Context, srcIP net.IP) error {
	if f.disarmErr != nil {
		return f.disarmErr
	}
	f.disarmed = append(f.disarmed, srcIP.String())
	return nil
}

// errListReader is a client.Reader whose List always errors — models a transient
// control-plane read failure / non-definitive snapshot (review finding B).
type errListReader struct{ err error }

func (e errListReader) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return e.err
}
func (e errListReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return e.err
}

func newTestReader(t *testing.T, pms ...*pmv1.PodMigration) client.Reader {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	b := fake.NewClientBuilder().WithScheme(scheme)
	for _, pm := range pms {
		b = b.WithObjects(pm)
	}
	return b.Build()
}

func trueCond(t string) metav1.Condition {
	return metav1.Condition{Type: t, Status: metav1.ConditionTrue, Reason: "Test", LastTransitionTime: metav1.Now()}
}

func newPM(name, srcIP string, mode pmv1.TCPPreservationMode, phase pmv1.MigrationPhase, conds ...metav1.Condition) *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{SourcePodIP: srcIP, TCPPreservationMode: mode},
		Status:     pmv1.PodMigrationStatus{Phase: phase, Conditions: conds},
	}
}

// verifiedBestEffortConds is a fully-safe-to-tear-down BestEffort condition set
// (SourceTeardownBlockReason == "").
func verifiedBestEffortConds() []metav1.Condition {
	return []metav1.Condition{
		trueCond("TrafficVerified"),
		trueCond(pmv1.ConditionTCPSequenceContinuityVerified),
		trueCond(pmv1.ConditionWorkloadLivenessVerified),
	}
}

// verifiedStrictConds is a fully-safe-to-tear-down Strict condition set.
func verifiedStrictConds() []metav1.Condition {
	return []metav1.Condition{
		trueCond(pmv1.ConditionServiceContinuityVerified),
		trueCond(pmv1.ConditionTCPSequenceContinuityVerified),
		trueCond(pmv1.ConditionWorkloadLivenessVerified),
	}
}

func runOnce(t *testing.T, reader client.Reader, ops *fakeBridgeOps) error {
	t.Helper()
	r := NewBridgeMapReconciler(reader, ops)
	return r.reconcileOnce(context.Background())
}

// --- decideBridgeEntry unit table (D1 predicate core) ---

func TestADR0400_decideBridgeEntry(t *testing.T) {
	cases := []struct {
		name string
		pm   *pmv1.PodMigration
		want bridgeDisposition
	}{
		{"absent CR -> delete (D1c)", nil, bridgeDelete},
		{"terminal Failed -> delete (D1b)", newPM("m", "10.0.0.1", pmv1.TCPPreservationModeStrict, pmv1.MigrationPhaseFailed), bridgeDelete},
		{"terminal RollingBack -> delete (D1b)", newPM("m", "10.0.0.1", pmv1.TCPPreservationModeBestEffort, pmv1.MigrationPhaseRollingBack), bridgeDelete},
		{"BestEffort verified -> delete (D1a)", newPM("m", "10.0.0.1", pmv1.TCPPreservationModeBestEffort, pmv1.MigrationPhaseVerifying, verifiedBestEffortConds()...), bridgeDelete},
		{"Strict verified -> delete (D1a)", newPM("m", "10.0.0.1", pmv1.TCPPreservationModeStrict, pmv1.MigrationPhaseVerifying, verifiedStrictConds()...), bridgeDelete},
		{"Strict TrafficVerified-only -> KEEP (review finding A)", newPM("m", "10.0.0.1", pmv1.TCPPreservationModeStrict, pmv1.MigrationPhaseVerifying, trueCond("TrafficVerified")), bridgeKeep},
		{"in-flight intermediate -> KEEP", newPM("m", "10.0.0.1", pmv1.TCPPreservationModeStrict, pmv1.MigrationPhaseRestoring), bridgeKeep},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideBridgeEntry(tc.pm); got != tc.want {
				t.Fatalf("decideBridgeEntry = %v, want %v", got, tc.want)
			}
		})
	}
}

// Assertion 3: delete fires when the source-of-truth predicate is satisfied.
func TestADR0400_BridgeTornDownWhenVerified(t *testing.T) {
	pm := newPM("m1", "10.244.0.5", pmv1.TCPPreservationModeBestEffort, pmv1.MigrationPhaseVerifying, verifiedBestEffortConds()...)
	ops := &fakeBridgeOps{keys: []net.IP{net.ParseIP("10.244.0.5")}}
	if err := runOnce(t, newTestReader(t, pm), ops); err != nil {
		t.Fatalf("reconcileOnce: %v", err)
	}
	if len(ops.disarmed) != 1 || ops.disarmed[0] != "10.244.0.5" {
		t.Fatalf("expected disarm of 10.244.0.5, got %v", ops.disarmed)
	}
}

// Assertion 4: terminal failure tears the entry down.
func TestADR0400_BridgeTornDownOnTerminal(t *testing.T) {
	pm := newPM("m2", "10.244.0.6", pmv1.TCPPreservationModeStrict, pmv1.MigrationPhaseFailed)
	ops := &fakeBridgeOps{keys: []net.IP{net.ParseIP("10.244.0.6")}}
	if err := runOnce(t, newTestReader(t, pm), ops); err != nil {
		t.Fatalf("reconcileOnce: %v", err)
	}
	if len(ops.disarmed) != 1 {
		t.Fatalf("expected 1 disarm on terminal phase, got %v", ops.disarmed)
	}
}

// Assertion 5: crash-leak self-heal — an orphan key (no owning CR in an
// authoritatively-successful snapshot) is reclaimed.
func TestADR0400_ReconcilerReclaimsOrphanEntry(t *testing.T) {
	// Reader has NO PodMigrations at all; the map key is a leaked pin.
	ops := &fakeBridgeOps{keys: []net.IP{net.ParseIP("10.244.0.7")}}
	if err := runOnce(t, newTestReader(t), ops); err != nil {
		t.Fatalf("reconcileOnce: %v", err)
	}
	if len(ops.disarmed) != 1 || ops.disarmed[0] != "10.244.0.7" {
		t.Fatalf("expected orphan 10.244.0.7 reclaimed, got %v", ops.disarmed)
	}
}

// Assertion 6 (review finding A): Strict is NOT torn down on raw TrafficVerified; it IS torn
// down once the mode-correct SourceTeardownBlockReason clears.
func TestADR0400_StrictNotTornDownOnTrafficVerifiedAlone(t *testing.T) {
	key := net.ParseIP("10.244.0.8")

	// Phase 1: Strict, TrafficVerified=True but ServiceContinuityVerified unset
	// (the HandoffInstalled split-brain window) -> MUST survive.
	pm := newPM("m3", "10.244.0.8", pmv1.TCPPreservationModeStrict, pmv1.MigrationPhaseVerifying, trueCond("TrafficVerified"))
	ops := &fakeBridgeOps{keys: []net.IP{key}}
	if err := runOnce(t, newTestReader(t, pm), ops); err != nil {
		t.Fatalf("phase1 reconcileOnce: %v", err)
	}
	if len(ops.disarmed) != 0 {
		t.Fatalf("review finding A regression: Strict bridge deleted on raw TrafficVerified; disarmed=%v", ops.disarmed)
	}

	// Phase 2: the Strict source-of-truth actually clears -> delete.
	pm2 := newPM("m3", "10.244.0.8", pmv1.TCPPreservationModeStrict, pmv1.MigrationPhaseVerifying, verifiedStrictConds()...)
	ops2 := &fakeBridgeOps{keys: []net.IP{key}}
	if err := runOnce(t, newTestReader(t, pm2), ops2); err != nil {
		t.Fatalf("phase2 reconcileOnce: %v", err)
	}
	if len(ops2.disarmed) != 1 {
		t.Fatalf("expected delete once ServiceContinuityVerified set, got %v", ops2.disarmed)
	}
}

// Assertion 7 (review finding B): a non-definitive read (List error) deletes nothing and
// surfaces the error. This is the datapath-protecting fail-closed guard.
func TestADR0400_ListErrorDeletesNothing(t *testing.T) {
	ops := &fakeBridgeOps{keys: []net.IP{net.ParseIP("10.244.0.9")}}
	reader := errListReader{err: errors.New("apiserver unavailable")}
	err := runOnce(t, reader, ops)
	if err == nil {
		t.Fatalf("expected reconcileOnce to return the List error (fail-closed)")
	}
	if len(ops.disarmed) != 0 {
		t.Fatalf("review finding B regression: deleted a live entry on a failed read; disarmed=%v", ops.disarmed)
	}
}

// Assertion 8 (review finding B companion): a migration parked in an early bridge-live
// phase (block reason != "") survives repeated passes — "keep" is the exact negation,
// never an intermediate-phase whitelist.
func TestADR0400_InFlightIntermediatePhaseSurvivesRepeatedPasses(t *testing.T) {
	pm := newPM("m4", "10.244.0.10", pmv1.TCPPreservationModeStrict, pmv1.MigrationPhaseRestoring)
	reader := newTestReader(t, pm)
	ops := &fakeBridgeOps{keys: []net.IP{net.ParseIP("10.244.0.10")}}
	r := NewBridgeMapReconciler(reader, ops)
	for i := 0; i < 5; i++ {
		if err := r.reconcileOnce(context.Background()); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	if len(ops.disarmed) != 0 {
		t.Fatalf("in-flight bridge deleted during repeated passes; disarmed=%v", ops.disarmed)
	}
}

// A no-key pass does not even read the CR set (cheap, and no spurious deletes).
func TestADR0400_EmptyMapIsNoop(t *testing.T) {
	ops := &fakeBridgeOps{keys: nil}
	// A reader that would ERROR if List were called — proves we short-circuit.
	if err := runOnce(t, errListReader{err: errors.New("must not be called")}, ops); err != nil {
		t.Fatalf("empty-map pass should be a no-op, got %v", err)
	}
	if len(ops.disarmed) != 0 {
		t.Fatalf("no deletes expected, got %v", ops.disarmed)
	}
}
