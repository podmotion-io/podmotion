/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0423_p_verify_test.go implements ADR-0423's §P-VERIFY acceptance suite (V1-V14), the
// falsifiable assertions that discharge the ADR once implemented. See docs/adr/0423-*.md
// §P-VERIFY for the authoritative text each test below cites. V2a/V5b (the structural
// sole-writer scans) live separately in adr0423_sole_writer_structural_test.go. V11 (the live
// KVM-cluster re-run) is NOT implemented here — it requires the standing KVM cluster and is out
// of reach of a unit-test package; it is called out explicitly, not silently skipped, per
// §P-VERIFY discipline (no overclaiming).

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
	pmmetrics "github.com/podmotion-io/podmotion/internal/metrics"
	"github.com/podmotion-io/podmotion/internal/podlineage"
	"github.com/podmotion-io/podmotion/internal/rollback"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// ── shared helpers ───────────────────────────────────────────────────────────────────────────

// pVerifyRollbacker is a configurable Rollbacker spy for the §P-VERIFY suite: it can be made to
// fail (V2 row (i)/(ii)) or succeed (every other row), and records whether/how many times it ran.
type pVerifyRollbacker struct {
	err   error
	calls int
}

func (s *pVerifyRollbacker) Rollback(_ context.Context, _ *pmv1.PodMigration) error {
	s.calls++
	return s.err
}

var _ rollback.Rollbacker = (*pVerifyRollbacker)(nil)

// pVerifyAgentSpy is a real MigrationAgentServiceServer implementing ONLY ReleaseCheckpoint and
// Abort (spy), call-tracking both — the ADR-0423 V3 requirement ("AgentPool must be a real mock,
// never nil... a bufconn mock with call-tracking ReleaseCheckpoint/Abort overrides").
type pVerifyAgentSpy struct {
	agentpb.UnimplementedMigrationAgentServiceServer
	mu           sync.Mutex
	releaseCalls int
	abortCalls   int
}

func (s *pVerifyAgentSpy) ReleaseCheckpoint(_ context.Context, _ *agentpb.ReleaseCheckpointRequest) (*agentpb.ReleaseCheckpointResponse, error) {
	s.mu.Lock()
	s.releaseCalls++
	s.mu.Unlock()
	return &agentpb.ReleaseCheckpointResponse{Success: true}, nil
}

func (s *pVerifyAgentSpy) Abort(_ context.Context, _ *agentpb.AbortRequest) (*agentpb.AbortResponse, error) {
	s.mu.Lock()
	s.abortCalls++
	s.mu.Unlock()
	return &agentpb.AbortResponse{Success: true}, nil
}

func (s *pVerifyAgentSpy) released() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releaseCalls > 0
}

func (s *pVerifyAgentSpy) aborted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.abortCalls > 0
}

// pVerifyAgentHarness stands up a real gRPC listener + pVerifyAgentSpy, mirroring the
// established adr0351/adr0356 pattern in this package (real bufconn-equivalent TCP listener, a
// self-signed TLS cert, and a real *agentclient.AgentClientPool dialing it) — never a nil
// AgentPool (ADR-0423 V3).
type pVerifyAgentHarness struct {
	spy  *pVerifyAgentSpy
	pool *agentclient.AgentClientPool
	stop func()
}

// newPVerifyAgentHarness starts the spy agent server and returns a pool that resolves the given
// destNode to it. c must already (or will, via WithObjects below) carry a Running agent pod on
// destNode at the loopback address the harness listens on — callers must include the returned
// agentPod object in their fake client's WithObjects/WithIndex setup.
func newPVerifyAgentHarness(t *testing.T, c client.Client) (*pVerifyAgentHarness, *corev1.Pod) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	serverCert := adr0351SelfSignedServerCert(t)
	spy := &pVerifyAgentSpy{}
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{serverCert}})))
	agentpb.RegisterMigrationAgentServiceServer(grpcSrv, spy)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(func() { grpcSrv.Stop(); _ = lis.Close() })

	port := lis.Addr().(*net.TCPAddr).Port
	// #nosec G402 -- test-only pool; this suite does not exercise the SPIFFE peer-identity
	// verifier (covered separately in internal/agent/tls).
	pool := agentclient.NewAgentClientPool(c, strconv.Itoa(port), &tls.Config{InsecureSkipVerify: true})

	agentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podmotion-agent-dst",
			Namespace: "podmotion-system",
			Labels:    map[string]string{"app": "podmotion-agent"},
		},
		Spec:   corev1.PodSpec{NodeName: "node-dst"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}
	return &pVerifyAgentHarness{spy: spy, pool: pool}, agentPod
}

// driveReconcileUntil repeatedly calls Reconcile for req until pred(fresh) is true or maxIters
// is exhausted, re-fetching the object from c between calls (mirroring how a real controller
// work-queue re-drives a CR whose Reconcile returned Requeue:true). Returns the final fetch.
func driveReconcileUntil(t *testing.T, r *PodMigrationReconciler, c client.Client, req ctrl.Request, maxIters int, pred func(*pmv1.PodMigration) bool) *pmv1.PodMigration {
	t.Helper()
	fresh := &pmv1.PodMigration{}
	for i := 0; i < maxIters; i++ {
		if _, err := r.Reconcile(context.Background(), req); err != nil {
			t.Fatalf("Reconcile iteration %d returned unexpected error: %v", i, err)
		}
		if err := c.Get(context.Background(), req.NamespacedName, fresh); err != nil {
			t.Fatalf("get pm after reconcile iteration %d: %v", i, err)
		}
		if pred(fresh) {
			return fresh
		}
	}
	return fresh
}

func isTerminalPhase(pm *pmv1.PodMigration) bool {
	return pm.Status.Phase == pmv1.MigrationPhaseFailed || pm.Status.Phase == pmv1.MigrationPhaseComplete
}

// ── V1 — the H5 repro reaches Failed, never Complete, via RollingBack ──────────────────────────

func TestADR0423_V1_H5Repro_ReachesFailedViaRollingBack(t *testing.T) {
	scheme := adr0356Scheme(t)
	tier := int32(storage.TierLonghorn)
	now := metav1.Now()

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "v1-h5-repro",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-999 * time.Second)), // budget long expired
			Finalizers:        []string{finalizerName},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  "src-pod",
			PodNamespace:             "default",
			TargetNodeName:           "node-dst",
			TCPPreservationMode:      pmv1.TCPPreservationModeNone,
			CompletionTimeoutSeconds: 120,
		},
		Status: pmv1.PodMigrationStatus{
			// Matches the live incident: stuck pre-restore, source already gone via the
			// ADR-0356 early-release path, nothing verified.
			Phase:               pmv1.MigrationPhaseOverlayHandoff,
			SourceNodeName:      "node-src",
			DestinationNodeName: "node-dst",
			StorageTier:         &tier,
			Conditions: []metav1.Condition{
				{Type: conditionSourcePodDeleted, Status: metav1.ConditionTrue, Reason: "Tier1LonghornEarlyRelease", LastTransitionTime: now},
				{Type: pmv1.ConditionTier1EarlySourceRelease, Status: metav1.ConditionTrue, Reason: "Tier1LonghornEarlyRelease", LastTransitionTime: now},
				// Restored/TCPSequenceContinuityVerified/ServiceContinuityVerified/TrafficVerified/
				// WorkloadLivenessVerified are all deliberately absent — nothing was verified.
			},
			// A present-but-unverifiable snapshot: verifySnapshotIntegrity fails closed
			// (no signing key wired below), so reconcileTier1ColdRecreateFromSnapshot is
			// genuinely ATTEMPTED and degrades honestly to coldRecreateBlockedInvalid,
			// exercising the branch V1 requires without needing a live-Running pod.
			SourcePodSpecSnapshot: &pmv1.SourcePodSpecSnapshot{
				PodSpecJSON:   []byte(`{"containers":[{"name":"app","image":"postgres:16"}]}`),
				BaseName:      "src-pod",
				Namespace:     "default",
				IntegrityHMAC: "not-a-real-hmac",
			},
		},
	}
	// src-pod is genuinely gone (deliberately not seeded) — corroborates conditionSourcePodDeleted.

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(pm).WithObjects(pm).Build()

	spyRB := &pVerifyRollbacker{}
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: spyRB, TestOnlyAllowNilAgentPoolFailOpen: true}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}

	fresh := driveReconcileUntil(t, r, fakeClient, req, 5, isTerminalPhase)

	if fresh.Status.Phase != pmv1.MigrationPhaseFailed {
		t.Fatalf("expected terminal Phase=Failed, got %s", fresh.Status.Phase)
	}
	rbReason := meta.FindStatusCondition(fresh.Status.Conditions, "RollbackReason")
	if rbReason == nil || rbReason.Status != metav1.ConditionTrue || rbReason.Reason != "Initiating" {
		t.Fatalf("expected RollbackReason=True/Initiating (Failed reached via RollingBack), got %+v", rbReason)
	}
	// The Tier1EarlySourceRelease branch ran and attempted reconcileTier1ColdRecreateFromSnapshot:
	// it left a trace (RollbackRecreatePending=False/RollbackRecreateBlockedInvalidSnapshot) that
	// only that function sets, and the honest no-owning-controller narration.
	pending := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionRollbackRecreatePending)
	if pending == nil || pending.Reason != "RollbackRecreateBlockedInvalidSnapshot" {
		t.Fatalf("expected reconcileTier1ColdRecreateFromSnapshot to have been attempted (RollbackRecreateBlockedInvalidSnapshot), got %+v", pending)
	}
	rolledBack := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionRolledBack)
	if rolledBack == nil || rolledBack.Reason != "RollbackCompleteNoOwningController" {
		t.Fatalf("expected honest RollbackCompleteNoOwningController narration, got %+v", rolledBack)
	}
}

// ── V1a — the :738 Strict clsact pre-check conversion ──────────────────────────────────────────

func TestADR0423_V1a_StrictClsactPrecheck_RoutesThroughFinalizeFailed(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "v1a-clsact", Namespace: "default", Finalizers: []string{finalizerName}},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod",
			PodNamespace:        "default",
			TargetNodeName:      "node-dst",
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseDestinationPrewarm,
			DestinationNodeName: "node-dst",
		},
	}
	destNMC := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "node-dst"},
		Status:     pmv1.NodeMigrationCapacityStatus{Ready: true}, // TCClsactSupported left false
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(pm).WithObjects(pm, destNMC).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}); err != nil {
		t.Fatalf("Reconcile returned unexpected error: %v", err)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseFailed {
		t.Fatalf("expected Phase=Failed via finalizeFailed, got %s", fresh.Status.Phase)
	}
	if fresh.Status.CompletionTime == nil {
		t.Fatal("expected CompletionTime set by finalizeFailed")
	}
	capCond := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionStrictCapabilitySatisfied)
	if capCond == nil || capCond.Status != metav1.ConditionFalse || capCond.Reason != "ClsactUnsupportedOnResolvedNode" {
		t.Fatalf("expected ConditionStrictCapabilitySatisfied=False/ClsactUnsupportedOnResolvedNode unchanged, got %+v", capCond)
	}
	failedCond := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionFailed)
	if failedCond == nil || failedCond.Status != metav1.ConditionTrue {
		t.Fatalf("expected ConditionFailed=True (finalizeFailed's own write), got %+v", failedCond)
	}
}

// ── V2 / V3 — the exit-path matrix, with a real (never-nil) AgentPool ──────────────────────────

// v2Fixture builds a RollingBack PodMigration with GC-9/GC-10-relevant state (CheckpointTransferred,
// a CheckpointRef pointing at a real MigrationCheckpoint CR, a replacement pod, and
// ConditionZeroWindowArmed=True per V4) common to every V2 row, plus D7's regression row
// (CheckpointTransferred=true, ConditionDestinationNetnsReady absent) via destNetnsReady.
func v2Fixture(name string, destNetnsReady bool) (*pmv1.PodMigration, *pmv1.MigrationCheckpoint, *corev1.Pod) {
	now := metav1.Now()
	conditions := []metav1.Condition{
		// V4: ConditionZeroWindowArmed must be True — the "never armed" vacuous disjunct is removed.
		{Type: pmv1.ConditionZeroWindowArmed, Status: metav1.ConditionTrue, Reason: "Armed", LastTransitionTime: now},
	}
	if destNetnsReady {
		conditions = append(conditions, metav1.Condition{
			Type: pmv1.ConditionDestinationNetnsReady, Status: metav1.ConditionTrue, Reason: "Staged", LastTransitionTime: now,
		})
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Finalizers: []string{finalizerName}},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "src-pod-" + name,
			PodNamespace:        "default",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:                 pmv1.MigrationPhaseRollingBack,
			SourceNodeName:        "node-src",
			DestinationNodeName:   "node-dst",
			ReplacementPodName:    "replacement-" + name,
			CheckpointTransferred: true,
			CheckpointRef:         &corev1.LocalObjectReference{Name: name},
			RollbackAttempted:     true,
			RollbackStartTime:     &now,
			Conditions:            conditions,
			// Non-empty so step 8's MigrationFlowLossTotal.Add(len(...)) produces an observable,
			// non-zero delta — a zero-length slice would make "the guard always skipped the
			// increment" (the FIX 1 regression) and "the increment fired once with nothing to
			// count" indistinguishable in the metric assertion below.
			TCPSeqSnapshots: []pmv1.TCPSeqSnapshot{
				{SrcIP: "10.0.0.1", SrcPort: 5432, DstIP: "10.0.0.2", DstPort: 54321, SndNxt: 1, RcvNxt: 1},
				{SrcIP: "10.0.0.1", SrcPort: 5433, DstIP: "10.0.0.2", DstPort: 54322, SndNxt: 1, RcvNxt: 1},
			},
		},
	}
	mcp := &pmv1.MigrationCheckpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Status:     pmv1.MigrationCheckpointStatus{Phase: "Transferred"},
	}
	replacementPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replacement-" + name,
			Namespace: "default",
			Labels:    map[string]string{replacementPodMigrationNameLabel: name},
		},
	}
	return pm, mcp, replacementPod
}

// TestADR0423_V2_ExitPathMatrix drives reconcileRollingBack's negative branch once per row and
// asserts, on every row: ReleaseCheckpoint was called, Abort was called (D7: even when
// ConditionDestinationNetnsReady is absent, so long as CheckpointTransferred is true), the
// zero-window was disarmed, the replacement pod was reaped, the MigrationCheckpoint CR's
// Status.Phase=="Failed", an honest ConditionRolledBack/ConditionFailed reason was set, and the
// terminal Phase==Failed.
func TestADR0423_V2_ExitPathMatrix(t *testing.T) {
	rows := []struct {
		name           string
		rollbackErr    error
		destNetnsReady bool
	}{
		{name: "v2-i-point-of-no-return", rollbackErr: storage.ErrRollbackPointOfNoReturn, destNetnsReady: true},
		{name: "v2-ii-not-implemented", rollbackErr: storage.ErrRollbackNotImplemented, destNetnsReady: true},
		{name: "v2-v-clean", rollbackErr: nil, destNetnsReady: true},
		// D7 regression row: CheckpointTransferred=true but ConditionDestinationNetnsReady absent
		// — GC-9 must still fire (V3's D7 row).
		{name: "v2-d7-netns-not-ready", rollbackErr: nil, destNetnsReady: false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			scheme := adr0356Scheme(t)
			if err := discoveryv1.AddToScheme(scheme); err != nil {
				t.Fatalf("AddToScheme discoveryv1: %v", err)
			}
			pm, mcp, replacementPod := v2Fixture(row.name, row.destNetnsReady)

			fakeClient := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(pm, mcp).
				WithIndex(&corev1.Pod{}, "spec.nodeName", adr0351PodNodeNameIndexer).
				WithObjects(pm, mcp, replacementPod).Build()

			harness, agentPod := newPVerifyAgentHarness(t, fakeClient)
			if err := fakeClient.Create(context.Background(), agentPod); err != nil {
				t.Fatalf("seed agent pod: %v", err)
			}

			spyRB := &pVerifyRollbacker{err: row.rollbackErr}
			r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: spyRB, AgentPool: harness.pool}
			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}

			// §P-VERIFY V2 (flow-loss metric): capture the counter before Reconcile so the
			// post-Reconcile delta isolates exactly what this single reconcile call did to it —
			// FIX 1's regression (three independent reviewers, ADR-0423/0424 implementation
			// review) is that ensureMigrationTerminalCleanup's step 8 always saw
			// ConditionRolledBack already True on THIS row's exit (reconcileRollingBack's tail
			// sets it on the same in-memory pm, in the same reconcile call, moments before
			// calling finalizeFailed) and so skipped the increment on every single invocation of
			// this exit path.
			before := testutil.ToFloat64(pmmetrics.MigrationFlowLossTotal.WithLabelValues(pm.Name, pm.Namespace))

			if _, err := r.Reconcile(context.Background(), req); err != nil {
				t.Fatalf("Reconcile returned unexpected error: %v", err)
			}

			after := testutil.ToFloat64(pmmetrics.MigrationFlowLossTotal.WithLabelValues(pm.Name, pm.Namespace))
			wantDelta := float64(len(pm.Status.TCPSeqSnapshots))
			if gotDelta := after - before; gotDelta != wantDelta {
				t.Errorf("MigrationFlowLossTotal delta = %v, want exactly %v (incremented exactly once for this migration's terminal exit, ADR-0423 D2/§P-VERIFY V2) — a delta of 0 reproduces the reviewer-confirmed regression where ensureMigrationTerminalCleanup's step 8 always sees ConditionRolledBack already True on this same in-memory pm and skips the increment",
					gotDelta, wantDelta)
			}

			fresh := &pmv1.PodMigration{}
			if err := fakeClient.Get(context.Background(), req.NamespacedName, fresh); err != nil {
				t.Fatalf("get pm: %v", err)
			}
			if fresh.Status.Phase != pmv1.MigrationPhaseFailed {
				t.Fatalf("expected terminal Phase=Failed, got %s", fresh.Status.Phase)
			}
			if !harness.spy.released() {
				t.Error("expected ReleaseCheckpoint (GC-9) to have been called")
			}
			// D7: GC-10 (Abort) is gated independently on ConditionDestinationNetnsReady, NOT on
			// CheckpointTransferred — the d7-netns-not-ready row deliberately omits that
			// condition, so Abort must NOT fire on that row while GC-9 still does (the direct
			// regression assertion for the destStaged coupling bug D7 fixes).
			if row.destNetnsReady {
				if !harness.spy.aborted() {
					t.Error("expected Abort (GC-10) to have been called")
				}
			} else if harness.spy.aborted() {
				t.Error("expected Abort (GC-10) NOT to have been called when ConditionDestinationNetnsReady is absent")
			}
			disarmed := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionZeroWindowDisarmed)
			if disarmed == nil || disarmed.Status != metav1.ConditionTrue {
				t.Errorf("expected zero-window disarmed, got %+v", disarmed)
			}
			gotReplacement := &corev1.Pod{}
			getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: replacementPod.Name, Namespace: "default"}, gotReplacement)
			if !apierrors.IsNotFound(getErr) {
				t.Errorf("expected replacement pod reaped, got err=%v", getErr)
			}
			freshMCP := &pmv1.MigrationCheckpoint{}
			if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: mcp.Name, Namespace: "default"}, freshMCP); err != nil {
				t.Fatalf("get mcp: %v", err)
			}
			if freshMCP.Status.Phase != "Failed" {
				t.Errorf("expected MigrationCheckpoint Status.Phase=Failed, got %q", freshMCP.Status.Phase)
			}
			failedCond := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionFailed)
			if failedCond == nil || failedCond.Status != metav1.ConditionTrue {
				t.Errorf("expected ConditionFailed=True, got %+v", failedCond)
			}
			if row.rollbackErr != nil {
				var wantCond string
				switch {
				case errors.Is(row.rollbackErr, storage.ErrRollbackPointOfNoReturn):
					wantCond = pmv1.ConditionStorageRollbackImpossible
				case errors.Is(row.rollbackErr, storage.ErrRollbackNotImplemented):
					wantCond = pmv1.ConditionStorageRollbackNotSupported
				}
				if c := meta.FindStatusCondition(fresh.Status.Conditions, wantCond); c == nil || c.Status != metav1.ConditionTrue {
					t.Errorf("expected distinguishing condition %s=True, got %+v", wantCond, c)
				}
			} else {
				rolledBack := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionRolledBack)
				if rolledBack == nil || rolledBack.Status != metav1.ConditionTrue {
					t.Errorf("expected ConditionRolledBack=True on the clean row, got %+v", rolledBack)
				}
			}
		})
	}
}

// ── V2b — Gap 3 regression: step 6 must not run from :738's or D4a's path ──────────────────────

func TestADR0423_V2b_EnsureReplacementEndpointsRemoved_ExcludedFromTerminalCleanup(t *testing.T) {
	// ensureMigrationTerminalCleanup itself performs steps 1,2,3,4,5,7,8 only — step 6
	// (ensureReplacementEndpointsRemoved) is never called from it. Assert this directly: a
	// migration reaching Failed via the D4a wall-clock-forced path (enforceRollbackBudget ->
	// finalizeFailed) must not touch ConditionReplacementEndpointsRemoved at all — that condition
	// is only ever set inline inside reconcileRollingBack's own gate, which D4a's forced path
	// never reaches.
	scheme := adr0356Scheme(t)
	now := metav1.Now()
	past := metav1.NewTime(time.Now().Add(-999 * time.Second))
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "v2b-d4a", Namespace: "default", Finalizers: []string{finalizerName}},
		Spec:       pmv1.PodMigrationSpec{PodName: "src-pod", PodNamespace: "default"},
		Status: pmv1.PodMigrationStatus{
			Phase:             pmv1.MigrationPhaseRollingBack,
			RollbackAttempted: true,
			RollbackStartTime: &past,
			Conditions: []metav1.Condition{
				{Type: "RollbackReason", Status: metav1.ConditionTrue, Reason: "Initiating", LastTransitionTime: now},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}); err != nil {
		t.Fatalf("Reconcile returned unexpected error: %v", err)
	}
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseFailed {
		t.Fatalf("expected D4a to force terminal Phase=Failed, got %s", fresh.Status.Phase)
	}
	if c := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionReplacementEndpointsRemoved); c != nil {
		t.Errorf("expected NO ConditionReplacementEndpointsRemoved on the D4a-forced path (step 6 excluded), got %+v", c)
	}
}

// ── V5 / V5a — the rollback wall-clock bound ───────────────────────────────────────────────────

func TestADR0423_V5_RollbackBudgetForcesFailedWhenAttempted(t *testing.T) {
	scheme := adr0356Scheme(t)
	past := metav1.NewTime(time.Now().Add(-999 * time.Second))
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "v5-budget", Namespace: "default", Finalizers: []string{finalizerName}},
		Spec:       pmv1.PodMigrationSpec{PodName: "src-pod", PodNamespace: "default"},
		Status: pmv1.PodMigrationStatus{
			Phase:             pmv1.MigrationPhaseRollingBack,
			RollbackAttempted: true,
			RollbackStartTime: &past, // far past rollbackBudget
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}); err != nil {
		t.Fatalf("Reconcile returned unexpected error: %v", err)
	}
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseFailed {
		t.Fatalf("expected the rollback budget to force terminal Phase=Failed, got %s", fresh.Status.Phase)
	}
}

// TestADR0423_V5a_EnforceRollbackBudget_UnitLevel is the direct, unambiguous falsification target
// for D4a's gate: called on a RollingBack migration whose RollbackStartTime is already more than
// rollbackBudget in the past but whose RollbackAttempted is still false, enforceRollbackBudget
// itself must return terminal=false (never force Failed) — before D4a existed, this exact input
// would have force-failed the migration sight-unseen, preempting the one rollback/thaw attempt
// Rollbacker.Rollback is required to make. Once RollbackAttempted becomes true, the identical
// RollbackStartTime is free to fire.
func TestADR0423_V5a_EnforceRollbackBudget_UnitLevel(t *testing.T) {
	scheme := adr0356Scheme(t)
	past := metav1.NewTime(time.Now().Add(-999 * time.Second))
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "v5a-unit", Namespace: "default"},
		Status: pmv1.PodMigrationStatus{
			Phase:             pmv1.MigrationPhaseRollingBack,
			RollbackStartTime: &past,
			RollbackAttempted: false,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	if _, _, terminal := r.enforceRollbackBudget(context.Background(), pm); terminal {
		t.Fatal("D4a violated: enforceRollbackBudget forced Failed before RollbackAttempted was ever set true")
	}

	pm.Status.RollbackAttempted = true
	if err := fakeClient.Status().Update(context.Background(), pm); err != nil {
		t.Fatalf("update pm: %v", err)
	}
	if _, _, terminal := r.enforceRollbackBudget(context.Background(), pm); !terminal {
		t.Fatal("expected the identical expired RollbackStartTime to fire once RollbackAttempted=true")
	}
}

// TestADR0423_V5a_Integration_AttemptRunsBeforeAnyTerminalForcing is the integration-level
// companion: a full Reconcile on the same input must actually let reconcileRollingBack run and
// attempt Rollbacker.Rollback — not merely return without forcing Failed. Before D4a existed, the
// watchdog would have force-failed the migration without ever calling Rollback at all
// (spyRB.calls would stay 0).
func TestADR0423_V5a_Integration_AttemptRunsBeforeAnyTerminalForcing(t *testing.T) {
	scheme := adr0356Scheme(t)
	past := metav1.NewTime(time.Now().Add(-999 * time.Second))
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "v5a-integration", Namespace: "default", Finalizers: []string{finalizerName}},
		Spec:       pmv1.PodMigrationSpec{PodName: "src-pod", PodNamespace: "default"},
		Status: pmv1.PodMigrationStatus{
			Phase:             pmv1.MigrationPhaseRollingBack,
			RollbackStartTime: &past,
			RollbackAttempted: false,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(pm).Build()
	spyRB := &pVerifyRollbacker{}
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: spyRB, TestOnlyAllowNilAgentPoolFailOpen: true}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile returned unexpected error: %v", err)
	}
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), req.NamespacedName, fresh); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	if spyRB.calls == 0 {
		t.Fatal("D4a violated: Rollbacker.Rollback was never attempted — the watchdog preempted reconcileRollingBack entirely")
	}
	if !fresh.Status.RollbackAttempted {
		t.Fatal("expected RollbackAttempted=true to have been set")
	}
	// Reaching Failed on this same pass is fine and expected: reconcileRollingBack genuinely ran
	// to completion (nothing in this minimal fixture blocks it) — the property under test is that
	// the ATTEMPT happened at all, not that the migration is somehow kept non-terminal forever.
}

// ── V6 — second-generation descope (D6b) ───────────────────────────────────────────────────────

func TestADR0423_V6_SecondGenerationDescope_SkipsColdRecreate(t *testing.T) {
	scheme := adr0356Scheme(t)
	now := metav1.Now()
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "v6-secondgen", Namespace: "default", Finalizers: []string{finalizerName}},
		Spec:       pmv1.PodMigrationSpec{PodName: "src-pod-m-aaaaaaaa", PodNamespace: "default", TCPPreservationMode: pmv1.TCPPreservationModeNone},
		Status: pmv1.PodMigrationStatus{
			Phase:             pmv1.MigrationPhaseRollingBack,
			RollbackAttempted: true,
			RollbackStartTime: &now,
			Conditions: []metav1.Condition{
				{Type: pmv1.ConditionTier1EarlySourceRelease, Status: metav1.ConditionTrue, Reason: "Tier1LonghornEarlyRelease", LastTransitionTime: now},
			},
			SourcePodSpecSnapshot: &pmv1.SourcePodSpecSnapshot{
				PodSpecJSON: []byte(`{}`),
				BaseName:    "src-pod-m-aaaaaaaa",
				Namespace:   "default",
				Annotations: map[string]string{
					"podmotion.io/original-command-overridden": "true",
					"podmotion.io/checkpoint-ref":              "some-prior-migration",
				},
				Labels: map[string]string{"podmotion.io/lineage-generation": "1"},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(pm).Build()
	spyRB := &pVerifyRollbacker{}
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: spyRB, TestOnlyAllowNilAgentPoolFailOpen: true}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile returned unexpected error: %v", err)
	}
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), req.NamespacedName, fresh); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	// No cold-recreate pod may exist.
	list := &corev1.PodList{}
	if err := fakeClient.List(context.Background(), list, client.MatchingLabels{rollbackRecreateMigrationUIDLabel: string(pm.UID)}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Fatalf("expected NO cold-recreate pod for a second-generation source, got %d", len(list.Items))
	}
	rolledBack := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionRolledBack)
	if rolledBack == nil || rolledBack.Reason != "RollbackCompleteNoOwningController" {
		t.Fatalf("expected RollbackCompleteNoOwningController, got %+v", rolledBack)
	}
	if rolledBack != nil && !strings.Contains(rolledBack.Message, "second-generation, no durable original spec") {
		t.Errorf("expected message to state second-generation reason, got %q", rolledBack.Message)
	}
}

// ── V10 — the ADR-0356-then-genuinely-completed case still closes out Complete ────────────────

func TestADR0423_V10_EarlyReleaseThenGenuinelyVerified_StillClosesOutComplete(t *testing.T) {
	scheme := adr0356Scheme(t)
	now := metav1.Now()
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "v10-early-then-verified",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-999 * time.Second)),
			Finalizers:        []string{finalizerName},
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  "src-pod",
			PodNamespace:             "default",
			TCPPreservationMode:      pmv1.TCPPreservationModeNone,
			CompletionTimeoutSeconds: 120,
		},
		Status: pmv1.PodMigrationStatus{
			Phase: pmv1.MigrationPhaseVerifying,
			Conditions: []metav1.Condition{
				{Type: conditionSourcePodDeleted, Status: metav1.ConditionTrue, Reason: "Tier1LonghornEarlyRelease", LastTransitionTime: now},
				{Type: pmv1.ConditionTier1EarlySourceRelease, Status: metav1.ConditionTrue, Reason: "Tier1LonghornEarlyRelease", LastTransitionTime: now},
				{Type: conditionTrafficVerified, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: now},
				{Type: pmv1.ConditionWorkloadLivenessVerified, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: now},
				{Type: conditionRestored, Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: now},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}); err != nil {
		t.Fatalf("Reconcile returned unexpected error: %v", err)
	}
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseComplete {
		t.Fatalf("expected Phase=Complete (genuinely verified despite early release), got %s", fresh.Status.Phase)
	}
}

// ── V13 — D4b's bounds check ────────────────────────────────────────────────────────────────────

func TestADR0423_V13_D4b_BoundsCheck(t *testing.T) {
	rows := []struct {
		name string
		// Exactly one of these is set per row.
		futureBad        time.Time     // absolute far-future timestamp
		beforeCreationBy time.Duration // bad = CreationTimestamp - this (zero => unused)
	}{
		{name: "future", futureBad: time.Now().Add(999 * time.Hour)},
		// Round 8 design review tightened D4b's bound to exactly pm.CreationTimestamp (Runtime
		// Architect finding, §P-VERIFY V13). Round 7's looser bound instead treated anything
		// within rollbackBudget BEFORE CreationTimestamp as plausible. This row sits inside that
		// old, round-7-plausible window (CreationTimestamp - rollbackBudget/2) — a real,
		// physically-impossible value (the migration object did not exist yet) that the final
		// round-8 bound must still correctly reject. Without this row, a future regression back
		// to the looser round-7 bound would pass V13 silently.
		{name: "before-creation-within-old-round7-window", beforeCreationBy: rollbackBudget / 2},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			scheme := adr0356Scheme(t)
			creation := metav1.NewTime(time.Now().Add(-time.Hour))
			var badTime metav1.Time
			if row.beforeCreationBy > 0 {
				badTime = metav1.NewTime(creation.Time.Add(-row.beforeCreationBy))
			} else {
				badTime = metav1.NewTime(row.futureBad)
			}
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{Name: "v13-" + row.name, Namespace: "default", Finalizers: []string{finalizerName}, CreationTimestamp: creation},
				Spec:       pmv1.PodMigrationSpec{PodName: "src-pod", PodNamespace: "default"},
				Status: pmv1.PodMigrationStatus{
					Phase:             pmv1.MigrationPhaseRollingBack,
					RollbackAttempted: true,
					RollbackStartTime: &badTime,
				},
			}
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(pm).Build()
			recorder := record.NewFakeRecorder(10)
			r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Recorder: recorder, TestOnlyAllowNilAgentPoolFailOpen: true, Rollbacker: &pVerifyRollbacker{}}

			// Unit-level: enforceRollbackBudget itself must treat the implausible value as a
			// bounds-check hit (terminal=false — it does not gate the fall-through), not as an
			// already-expired budget that fires D4 immediately.
			if _, _, terminal := r.enforceRollbackBudget(context.Background(), pm); terminal {
				t.Fatal("expected D4b's bounds check to correct the implausible value (terminal=false), not fire the budget directly from it")
			}

			fresh := &pmv1.PodMigration{}
			if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
				t.Fatalf("get pm: %v", err)
			}
			if fresh.Status.RollbackStartTime == nil || fresh.Status.RollbackStartTime.Equal(&badTime) {
				t.Fatalf("expected RollbackStartTime to be corrected away from the implausible value, got %v", fresh.Status.RollbackStartTime)
			}
			if fresh.Status.RollbackStartTime.After(time.Now()) || fresh.Status.RollbackStartTime.Before(&creation) {
				t.Fatalf("expected the corrected RollbackStartTime to be plausible, got %v (creation=%v)", fresh.Status.RollbackStartTime, creation)
			}
			select {
			case ev := <-recorder.Events:
				if !strings.Contains(ev, "RollbackStartTimeImplausible") {
					t.Errorf("expected a RollbackStartTimeImplausible event, got %q", ev)
				}
			default:
				t.Error("expected a Warning event to be recorded for the implausible value")
			}
		})
	}
}

// ── V14 — enterRollingBack's patch call is fail-safe ───────────────────────────────────────────

func TestADR0423_V14_EnterRollingBack_FailSafeOnPersistentPatchError(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "v14-failsafe", Namespace: "default", Finalizers: []string{finalizerName}},
		Spec:       pmv1.PodMigrationSpec{PodName: "src-pod", PodNamespace: "default"},
		Status:     pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhaseOverlayHandoff},
	}
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(pm).Build()
	// Force every Status().Patch to fail, simulating a persistent patchRollbackProgress error.
	failingClient := &patchFailingClient{Client: baseClient}
	spyRB := &pVerifyRollbacker{}
	r := &PodMigrationReconciler{Client: failingClient, Scheme: scheme, Rollbacker: spyRB, TestOnlyAllowNilAgentPoolFailOpen: true}

	if _, err := r.enterRollingBack(context.Background(), pm, "test-forced-entry"); err != nil {
		t.Fatalf("enterRollingBack returned unexpected error (it must be fail-safe re: the patch, not the transitionTo write): %v", err)
	}
	// transitionTo persists Phase via its own freshly-fetched copy, not by mutating the caller's
	// in-memory pm — read back through the (unaffected-by-the-Patch-override) base client.
	fresh := &pmv1.PodMigration{}
	if err := baseClient.Get(context.Background(), types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	if fresh.Status.Phase != pmv1.MigrationPhaseRollingBack {
		t.Fatalf("expected Phase=RollingBack to be reached despite the forced patchRollbackProgress error, got %s", fresh.Status.Phase)
	}

	// Next reconcile pass (Phase now RollingBack): Rollbacker.Rollback must still run — the thaw
	// is not permanently foreclosed by the persistent patch error.
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}); err != nil {
		t.Fatalf("Reconcile returned unexpected error: %v", err)
	}
	if spyRB.calls == 0 {
		t.Fatal("expected r.Rollbacker.Rollback to have been invoked despite the persistent patch error")
	}
}

// patchFailingClient wraps a client.Client and forces every Status().Patch call to fail,
// simulating a persistent patchRollbackProgress error (e.g. an unapplied CRD schema or a
// permission failure) for V14.
type patchFailingClient struct {
	client.Client
}

func (p *patchFailingClient) Status() client.SubResourceWriter {
	return &patchFailingStatusWriter{SubResourceWriter: p.Client.Status()}
}

type patchFailingStatusWriter struct {
	client.SubResourceWriter
}

func (w *patchFailingStatusWriter) Patch(_ context.Context, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
	return errors.New("v14: injected persistent patch failure")
}

// ── V7 — first-generation happy path (D5 + D6a) ────────────────────────────────────────────────

func TestADR0423_V7_FirstGeneration_ColdRecreate_NoHolderArtifacts_OnlyAfterRunning(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := adr0393BarePM("v7-firstgen")
	// A genuinely first-generation snapshot: no holder artifacts, generation 0.
	snap := adr0393MakeSnapshot(t, adr0393TestKey(), pm, adr0393SimpleSpec(), "src-pod", "default")
	pm.Status.SourcePodSpecSnapshot = snap
	if !snapshotIsFirstGeneration(snap) {
		t.Fatal("test setup: fixture snapshot must be first-generation")
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, testOnlySnapshotHMACKey: adr0393TestKey()}
	ctx := context.Background()

	// D5: the built pod carries no holder artifacts at all — the strip is a true no-op for a
	// first-generation source (nothing to strip), and the shared helper does not accidentally
	// introduce or leave anything behind.
	pod, err := buildColdRecreatePod(pm)
	if err != nil {
		t.Fatalf("buildColdRecreatePod: %v", err)
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == "podmotion-holder-bin" {
			t.Fatal("D5 regression: cold-recreate pod carries the holder volume")
		}
	}
	for _, c := range pod.Spec.InitContainers {
		if c.Name == "podmotion-inject-holder" {
			t.Fatal("D5 regression: cold-recreate pod carries the holder init container")
		}
	}
	for _, key := range []string{"podmotion.io/checkpoint-ref", "podmotion.io/migration-namespace",
		"podmotion.io/original-command-overridden", "podmotion.io/restore-target-containers"} {
		if _, bad := pod.Annotations[key]; bad {
			t.Fatalf("D5 regression: cold-recreate pod carries annotation %q", key)
		}
	}

	// D6a: a fixture that stops at Status.Phase==Pending must assert coldRecreatePending, not
	// success.
	outcome, _, err := r.reconcileTier1ColdRecreateFromSnapshot(ctx, pm)
	if err != nil {
		t.Fatalf("recreate errored: %v", err)
	}
	if outcome != coldRecreatePending {
		t.Fatalf("expected coldRecreatePending before the pod is observed Running, got %v", outcome)
	}

	want := pod.Name
	adr0393MarkRecreatePodRunning(t, fakeClient, "default", want, 0, metav1.Now())
	// First observation (no-probe two-read fallback) — still pending.
	if outcome, _, err = r.reconcileTier1ColdRecreateFromSnapshot(ctx, pm); err != nil {
		t.Fatalf("recreate errored: %v", err)
	} else if outcome != coldRecreatePending {
		t.Fatalf("expected coldRecreatePending on the first Running observation, got %v", outcome)
	}
	// Second, agreeing observation — confirmed.
	if outcome, _, err = r.reconcileTier1ColdRecreateFromSnapshot(ctx, pm); err != nil {
		t.Fatalf("recreate errored: %v", err)
	} else if outcome != coldRecreateSucceeded {
		t.Fatalf("expected coldRecreateSucceeded only once Running is confirmed, got %v", outcome)
	}
}

// ── V8 — re-entry (D2's finding (a) fix) ────────────────────────────────────────────────────────

func TestADR0423_V8_ReEntry_ReportsColdRecreatedNotUnrecoveredOutage(t *testing.T) {
	scheme := adr0356Scheme(t)
	now := metav1.Now()
	pm := adr0393BarePM("v8-reentry")
	pm.Namespace = "default"
	pm.Finalizers = []string{finalizerName}
	pm.Status.Phase = pmv1.MigrationPhaseRollingBack
	pm.Status.RollbackAttempted = true
	pm.Status.RollbackStartTime = &now
	setCondition(pm, pmv1.ConditionTier1EarlySourceRelease, metav1.ConditionTrue, "Tier1LonghornEarlyRelease", "")

	// Simulate: a PRIOR reconcile already cold-recreated successfully and durably cleared the
	// snapshot (clearSourcePodSpecSnapshot's own independent field-scoped patch already landed),
	// but its own terminal blob write conflicted/errored, so Phase never advanced past
	// RollingBack. pm.Status.SourcePodSpecSnapshot is therefore nil on THIS re-entrant pass — the
	// ADR-0393 gate's own SourcePodSpecSnapshot!=nil conjunct now fails, exactly the re-entry
	// hazard D2 finding (a) exists to fix.
	pm.Status.SourcePodSpecSnapshot = nil

	base := podlineage.CanonicalBaseName(pm.Spec.PodName)
	recreateName := podlineage.DeterministicIncarnationName(base, podlineage.RecreateNameTag, string(pm.UID))
	recreatePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recreateName,
			Namespace: "default",
			Labels:    map[string]string{rollbackRecreateMigrationUIDLabel: string(pm.UID)},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(pm).WithObjects(pm, recreatePod).Build()
	recorder := record.NewFakeRecorder(10)
	spyRB := &pVerifyRollbacker{}
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, Rollbacker: spyRB, Recorder: recorder, TestOnlyAllowNilAgentPoolFailOpen: true}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile returned unexpected error: %v", err)
	}
	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), req.NamespacedName, fresh); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	rolledBack := meta.FindStatusCondition(fresh.Status.Conditions, pmv1.ConditionRolledBack)
	if rolledBack == nil || rolledBack.Reason != "RollbackCompleteColdRecreatedFromSnapshot" {
		t.Fatalf("expected re-entry to still report RollbackCompleteColdRecreatedFromSnapshot (fresh read of the deterministic recreate pod), got %+v", rolledBack)
	}
	select {
	case ev := <-recorder.Events:
		if strings.Contains(ev, "Tier1EarlyReleaseUnrecoveredOutage") {
			t.Fatalf("expected NO Tier1EarlyReleaseUnrecoveredOutage event on re-entry, got %q", ev)
		}
	default:
	}
}

// ── V12 Row 2/3 — patchRollbackProgress's CAS guard (Row 1 is envtest-only; see
// adr0423_v12_envtest_test.go) ─────────────────────────────────────────────────────────────────

// TestADR0423_V12_Row2_CASConvergesOnOneWinner: two independent in-memory callers, each starting
// from a fresh Get of the same object and both observing RollbackStartTime==nil, attempt to stamp
// distinct values t1<t2. Asserts a single, consistent winner: both calls succeed, a fresh Get
// shows one value, and both callers' own in-memory pm agree with it and each other.
func TestADR0423_V12_Row2_CASConvergesOnOneWinner(t *testing.T) {
	scheme := adr0356Scheme(t)
	seed := &pmv1.PodMigration{ObjectMeta: metav1.ObjectMeta{Name: "v12-row2", Namespace: "default"}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(seed).WithObjects(seed).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()
	key := types.NamespacedName{Name: "v12-row2", Namespace: "default"}

	caller1 := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, key, caller1); err != nil {
		t.Fatalf("get caller1: %v", err)
	}
	caller2 := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, key, caller2); err != nil {
		t.Fatalf("get caller2: %v", err)
	}

	t1 := metav1.NewTime(time.Now())
	t2 := metav1.NewTime(time.Now().Add(5 * time.Second))

	stamped1, err1 := r.patchRollbackProgress(ctx, caller1, &t1, nil)
	if err1 != nil || !stamped1 {
		t.Fatalf("caller1 patch: stamped=%v err=%v", stamped1, err1)
	}
	// caller2's retry re-Gets and observes the field already set by caller1 — a no-op, not a
	// conflict — and still returns success (stamped=true, synced from the server).
	stamped2, err2 := r.patchRollbackProgress(ctx, caller2, &t2, nil)
	if err2 != nil || !stamped2 {
		t.Fatalf("caller2 patch: stamped=%v err=%v", stamped2, err2)
	}

	fresh := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, key, fresh); err != nil {
		t.Fatalf("get fresh: %v", err)
	}
	if fresh.Status.RollbackStartTime == nil {
		t.Fatal("expected a single persisted RollbackStartTime")
	}
	if !caller1.Status.RollbackStartTime.Equal(fresh.Status.RollbackStartTime) ||
		!caller2.Status.RollbackStartTime.Equal(fresh.Status.RollbackStartTime) {
		t.Fatalf("expected both callers to agree with the persisted winner: caller1=%v caller2=%v fresh=%v",
			caller1.Status.RollbackStartTime, caller2.Status.RollbackStartTime, fresh.Status.RollbackStartTime)
	}
	// The fake client round-trips metav1.Time at second precision, so compare truncated to the
	// second rather than requiring nanosecond-exact equality — the property under test is WHICH
	// caller won (t1, not t2), not sub-second fidelity of the stored timestamp.
	if !caller1.Status.RollbackStartTime.Time.Truncate(time.Second).Equal(t1.Time.Truncate(time.Second)) {
		t.Fatalf("expected caller1 (whose Patch landed first) to be the winner, got %v (t1=%v, t2=%v)",
			caller1.Status.RollbackStartTime, t1, t2)
	}
}

// TestADR0423_V12_Row3_SelfHealingOnRegression: a concurrent whole-status overwrite (simulating a
// stale-in-memory transitionTo/statusUpdate call) lands after patchRollbackProgress and regresses
// RollbackStartTime to nil on the persisted object. Asserts the self-healing property: the very
// next enforceRollbackBudget pass (D4(c)'s adopt-and-stamp) observes the regressed value and
// re-stamps it, never firing the budget as a result of the regression, and the clock is only ever
// reset forward (a later stamp), never backward.
func TestADR0423_V12_Row3_SelfHealingOnRegression(t *testing.T) {
	scheme := adr0356Scheme(t)
	pm := &pmv1.PodMigration{ObjectMeta: metav1.ObjectMeta{Name: "v12-row3", Namespace: "default"}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pm).WithObjects(pm).Build()
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme}
	ctx := context.Background()
	key := types.NamespacedName{Name: "v12-row3", Namespace: "default"}

	original := metav1.Now()
	if stamped, err := r.patchRollbackProgress(ctx, pm, &original, nil); err != nil || !stamped {
		t.Fatalf("initial stamp: stamped=%v err=%v", stamped, err)
	}

	// Simulate a stale concurrent blob overwrite regressing the field to nil on the server.
	regressed := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, key, regressed); err != nil {
		t.Fatalf("get: %v", err)
	}
	regressed.Status.RollbackStartTime = nil
	if err := fakeClient.Status().Update(ctx, regressed); err != nil {
		t.Fatalf("simulate regression: %v", err)
	}
	confirmRegressed := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, key, confirmRegressed); err != nil {
		t.Fatalf("get: %v", err)
	}
	if confirmRegressed.Status.RollbackStartTime != nil {
		t.Fatal("test setup: regression did not land")
	}

	// The next pass observes nil again and re-stamps, without firing the budget on this account.
	if _, _, terminal := r.enforceRollbackBudget(ctx, confirmRegressed); terminal {
		t.Fatal("expected the nil regression to be re-stamped (adopt-and-stamp), not treated as a fired budget")
	}
	healed := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, key, healed); err != nil {
		t.Fatalf("get: %v", err)
	}
	if healed.Status.RollbackStartTime == nil {
		t.Fatal("expected RollbackStartTime to be re-stamped after the regression (self-healing)")
	}
	// Second-precision round-trip tolerance (fake client), matching Row 2's comparison above.
	if healed.Status.RollbackStartTime.Time.Truncate(time.Second).Before(original.Time.Truncate(time.Second)) {
		t.Fatalf("expected the re-stamp to move the clock forward (more time given, never less), got %v (original %v)",
			healed.Status.RollbackStartTime, original)
	}
}
