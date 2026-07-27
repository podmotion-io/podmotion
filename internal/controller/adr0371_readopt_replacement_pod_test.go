/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0371_readopt_replacement_pod_test.go — regression tests for ADR-0371 (Re-Adopt the
// Replacement Pod Into Its Owning ReplicaSet Before Early Source-Pod Delete). Covers the
// scenarios the ADR's Decision is built around:
//
//  1. TestReadopt_SuccessfulReadoptConfirmDeleteSequence — the positive path: re-adopt lands,
//     is confirmed via a real re-read BEFORE the source pod is deleted, and the source delete
//     only proceeds after that confirmation.
//  2. TestReadopt_ConfirmTimeout_FailsClosed_SourceNotDeleted — re-adoption failing to be
//     observed within the bounded confirm poll: fails CLOSED (source pod NOT deleted,
//     replacement pod re-stripped back to its original CR-owned/label-stripped state).
//  3. TestReadopt_RollbackReStripsAfterIncompleteReadopt — rollback symmetry: a re-adopt that
//     WAS confirmed, but where the migration then fails to complete before the source pod is
//     actually deleted (KillFrozenSource RPC failure), re-strips the replacement pod back to
//     CR-owned/label-stripped rather than leaving it stranded RS-owned.
//  4. TestReadopt_LateRaceAfterKillFrozenSource_FailsClosed_SourceNotDeleted — the
//     review-identified TOCTOU gap this ADR was amended to close: the replacement pod is
//     confirmed RS-owned by the INITIAL bounded poll (so readoptReplacementPodIntoOwningReplicaSet
//     itself returns success), then is deleted "by the ReplicaSet" (simulated externally,
//     out from under the code under test) in the window that opens during the KillFrozenSource
//     RPC — i.e. AFTER the initial confirm, but BEFORE the source pod delete call. Proves the
//     final pre-delete re-check catches this and the source pod is NOT deleted, even though
//     KillFrozenSource has already unconditionally run.

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

const (
	adr0371RSName          = "demo-rs"
	adr0371ReplacementName = "src-pod-m-abcd1234"
	adr0371PodTemplateHash = "7c9f6d5b8"
)

func adr0371Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme appsv1: %v", err)
	}
	return scheme
}

// adr0371ReplicaSet builds the owning ReplicaSet the source/replacement pods reference,
// carrying a selector this ADR's re-adopt step must resolve via getRSSelector.
func adr0371ReplicaSet() *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: adr0371RSName, Namespace: "default", UID: "rs-uid-1"},
		Spec: appsv1.ReplicaSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}},
		},
	}
}

// adr0371SourcePod builds the source pod, RS-owned, carrying both its own selector label
// ("app": "demo") and the RS-generated pod-template-hash — exactly what createReplacementPod
// strips when building the replacement pod, and exactly what the re-adopt step must restore
// verbatim from this object.
func adr0371SourcePod(rs *appsv1.ReplicaSet, node string) *corev1.Pod {
	isController := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "src-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "demo", "pod-template-hash": adr0371PodTemplateHash},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       rs.Name,
					UID:        rs.UID,
					Controller: &isController,
				},
			},
		},
		Spec: corev1.PodSpec{NodeName: node},
	}
}

// adr0371ReplacementPod builds the replacement pod exactly as createReplacementPod leaves it:
// CR-owned (PodMigration controller ref), selector labels ("app", "pod-template-hash")
// stripped, only the migration-name label present.
func adr0371ReplacementPod(t *testing.T, scheme *runtime.Scheme, pm *pmv1.PodMigration) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      adr0371ReplacementName,
			Namespace: "default",
			Labels:    map[string]string{replacementPodMigrationNameLabel: pm.Name},
		},
	}
	if err := controllerutil.SetControllerReference(pm, pod, scheme); err != nil {
		t.Fatalf("SetControllerReference on replacement pod fixture: %v", err)
	}
	return pod
}

func adr0371PM(name string, checkpointTransferred bool) *pmv1.PodMigration {
	tier := int32(storage.TierLonghorn)
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: types.UID(name + "-uid")},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "src-pod",
			PodNamespace: "default",
		},
		Status: pmv1.PodMigrationStatus{
			SourceNodeName:        "node-src",
			DestinationNodeName:   "node-dst",
			StorageTier:           &tier,
			CheckpointTransferred: checkpointTransferred,
			ReplacementPodName:    adr0371ReplacementName,
		},
	}
}

// TestReadopt_SuccessfulReadoptConfirmDeleteSequence proves the full positive sequence:
// re-adopt patch lands, the bounded confirm poll observes it intact on the FIRST read,
// ConditionReplacementPodReadopted=True/ReadoptConfirmed is persisted BEFORE the source pod
// is deleted (verified via a Delete-time interceptor snapshot, not just final state), and the
// source pod is deleted only after that. The replacement pod ends up RS-owned with its
// selector labels restored.
func TestReadopt_SuccessfulReadoptConfirmDeleteSequence(t *testing.T) {
	scheme := adr0371Scheme(t)
	rs := adr0371ReplicaSet()
	pm := adr0371PM("pm-success", true)
	sourcePod := adr0371SourcePod(rs, "node-src")
	replacementPod := adr0371ReplacementPod(t, scheme, pm)
	srcAgentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "podmotion-agent-src", Namespace: "podmotion-system", Labels: map[string]string{"app": "podmotion-agent"}},
		Spec:       corev1.PodSpec{NodeName: "node-src"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}

	baseClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithIndex(&corev1.Pod{}, "spec.nodeName", adr0351PodNodeNameIndexer).
		WithObjects(sourcePod, replacementPod, pm, readyNMC("node-dst"), rs, srcAgentPod).Build()

	// Captured the instant r.Delete(sourcePod) fires, to prove ordering (ADR-0371
	// verification assertion 2): the readopt condition must already be True by then.
	var conditionTrueBeforeDelete atomic.Bool
	var deleteCalled atomic.Bool
	fakeClient := interceptor.NewClient(baseClient, interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if p, ok := obj.(*corev1.Pod); ok && p.Name == "src-pod" {
				deleteCalled.Store(true)
				conditionTrueBeforeDelete.Store(meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionReplacementPodReadopted))
			}
			return c.Delete(ctx, obj, opts...)
		},
	})

	killResp := &agentpb.KillFrozenSourceResponse{Success: true, Killed: true}
	pool := agentClientPoolForTest(t, fakeClient, killResp)
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, AgentPool: pool}

	if err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if !deleteCalled.Load() {
		t.Fatal("expected source pod Delete to have been called")
	}
	if !conditionTrueBeforeDelete.Load() {
		t.Fatal("expected ConditionReplacementPodReadopted=True to already be set at the moment source pod Delete fired")
	}

	// Source pod actually gone.
	getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, &corev1.Pod{})
	if !apierrors.IsNotFound(getErr) {
		t.Fatalf("expected source pod deleted (NotFound), got err=%v", getErr)
	}

	// Final condition state.
	cond := meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionReplacementPodReadopted)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "ReadoptConfirmed" {
		t.Fatalf("expected ConditionReplacementPodReadopted=True/ReadoptConfirmed, got %+v", cond)
	}

	// Replacement pod is now RS-owned with selector labels restored.
	gotRepl := &corev1.Pod{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: adr0371ReplacementName, Namespace: "default"}, gotRepl); err != nil {
		t.Fatalf("get replacement pod: %v", err)
	}
	if len(gotRepl.OwnerReferences) != 1 || gotRepl.OwnerReferences[0].Kind != "ReplicaSet" || gotRepl.OwnerReferences[0].Name != rs.Name {
		t.Fatalf("expected replacement pod OwnerReferences to be swapped to the RS, got %+v", gotRepl.OwnerReferences)
	}
	if gotRepl.Labels["app"] != "demo" {
		t.Fatalf("expected selector label 'app'='demo' restored, got %q", gotRepl.Labels["app"])
	}
	if gotRepl.Labels["pod-template-hash"] != adr0371PodTemplateHash {
		t.Fatalf("expected pod-template-hash restored, got %q", gotRepl.Labels["pod-template-hash"])
	}
}

// agentClientPoolForTest starts a real gRPC listener implementing only KillFrozenSource with
// the given canned response, and returns an AgentClientPool bound to the given fake client so
// AgentPool.ForNode(...).KillFrozenSource(...) resolves to it — mirroring the harness the
// existing ADR-0356 tests use in this package.
func agentClientPoolForTest(t *testing.T, fakeClient client.Client, resp *agentpb.KillFrozenSourceResponse) *agentclient.AgentClientPool {
	t.Helper()
	return agentClientPoolForTestWithHook(t, fakeClient, resp, nil)
}

// agentClientPoolForTestWithHook is agentClientPoolForTest plus onCall, invoked synchronously
// inside the KillFrozenSource RPC handler before it returns — used to simulate an external
// event (the owning ReplicaSet deleting the replacement pod) landing during the RPC's real,
// uncontrolled-latency round trip. See spyKillFrozenSourceAgentServer.onCall.
func agentClientPoolForTestWithHook(t *testing.T, fakeClient client.Client, resp *agentpb.KillFrozenSourceResponse, onCall func()) *agentclient.AgentClientPool {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverCert := adr0351SelfSignedServerCert(t)
	spy := &spyKillFrozenSourceAgentServer{resp: resp, onCall: onCall}
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{serverCert}})))
	agentpb.RegisterMigrationAgentServiceServer(grpcSrv, spy)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(func() {
		grpcSrv.Stop()
		_ = lis.Close()
	})
	port := lis.Addr().(*net.TCPAddr).Port
	clientTLSCfg := &tls.Config{InsecureSkipVerify: true}
	return agentclient.NewAgentClientPool(fakeClient, strconv.Itoa(port), clientTLSCfg)
}

// TestReadopt_ConfirmTimeout_FailsClosed_SourceNotDeleted proves ADR-0371's fail-closed
// requirement (§3): if the bounded confirm poll never observes a definitive read (a test
// double that delays the confirm read, per verification assertion 3, here simulated by an
// interceptor that returns a STALE pre-patch snapshot of the replacement pod on every read
// after the initial patch's own Get), the source pod is NOT deleted and the replacement pod
// is re-stripped back to its CR-owned/label-stripped state.
func TestReadopt_ConfirmTimeout_FailsClosed_SourceNotDeleted(t *testing.T) {
	scheme := adr0371Scheme(t)
	rs := adr0371ReplicaSet()
	pm := adr0371PM("pm-timeout", true)
	sourcePod := adr0371SourcePod(rs, "node-src")
	replacementPod := adr0371ReplacementPod(t, scheme, pm)
	staleSnapshot := replacementPod.DeepCopy() // pre-patch: CR-owned, labels stripped

	baseClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithIndex(&corev1.Pod{}, "spec.nodeName", adr0351PodNodeNameIndexer).
		WithObjects(sourcePod, replacementPod, pm, readyNMC("node-dst"), rs).Build()

	var getCount int32
	fakeClient := interceptor.NewClient(baseClient, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			pod, ok := obj.(*corev1.Pod)
			if !ok || key.Name != adr0371ReplacementName || key.Namespace != "default" {
				return c.Get(ctx, key, obj, opts...)
			}
			n := atomic.AddInt32(&getCount, 1)
			if n == 1 {
				// The re-adopt patch's own retry.RetryOnConflict Get: must see the REAL,
				// current object so the subsequent Update has a valid resourceVersion.
				return c.Get(ctx, key, obj, opts...)
			}
			// Every confirm-loop read after that: return the stale, pre-patch snapshot —
			// simulates a confirm read that never catches up to the just-applied patch.
			staleSnapshot.DeepCopyInto(pod)
			return nil
		},
	})

	r := &PodMigrationReconciler{
		Client:                         fakeClient,
		Scheme:                         scheme,
		readoptConfirmIntervalOverride: time.Millisecond, // keep the bounded poll fast in-test
	}

	err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm)
	if err == nil {
		t.Fatal("expected an error — re-adopt confirm must fail closed on an inconclusive read")
	}

	// Source pod must NOT have been deleted.
	getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, &corev1.Pod{})
	if getErr != nil {
		t.Fatalf("source pod should NOT have been deleted on confirm timeout: %v", getErr)
	}

	cond := meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionReplacementPodReadopted)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "ReadoptConfirmTimeout" {
		t.Fatalf("expected ConditionReplacementPodReadopted=False/ReadoptConfirmTimeout, got %+v", cond)
	}
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
		t.Fatal("ConditionTier1EarlySourceRelease must not be set — the function returned before reaching that point")
	}

	// Replacement pod must be re-stripped: CR-owned again, selector labels removed.
	gotRepl := &corev1.Pod{}
	if err := baseClient.Get(context.Background(), types.NamespacedName{Name: adr0371ReplacementName, Namespace: "default"}, gotRepl); err != nil {
		t.Fatalf("get replacement pod: %v", err)
	}
	if len(gotRepl.OwnerReferences) != 1 || gotRepl.OwnerReferences[0].Kind != "PodMigration" {
		t.Fatalf("expected replacement pod re-stripped to CR-owned, got OwnerReferences=%+v", gotRepl.OwnerReferences)
	}
	if _, present := gotRepl.Labels["app"]; present {
		t.Fatalf("expected selector label 'app' removed after re-strip, got %+v", gotRepl.Labels)
	}
	if _, present := gotRepl.Labels["pod-template-hash"]; present {
		t.Fatalf("expected pod-template-hash removed after re-strip, got %+v", gotRepl.Labels)
	}
}

// TestReadopt_RollbackReStripsAfterIncompleteReadopt proves the rollback-symmetry
// requirement (ADR-0371 §2 step 4 / §3): a re-adopt that WAS confirmed, but where
// KillFrozenSource then fails (an existing, already-handled ADR-0356 error path) before the
// source pod is actually deleted, re-strips the replacement pod back to CR-owned/
// label-stripped rather than leaving it stranded RS-owned with the source pod still alive.
func TestReadopt_RollbackReStripsAfterIncompleteReadopt(t *testing.T) {
	scheme := adr0371Scheme(t)
	rs := adr0371ReplicaSet()
	pm := adr0371PM("pm-restrip", true)
	sourcePod := adr0371SourcePod(rs, "node-src")
	replacementPod := adr0371ReplacementPod(t, scheme, pm)

	baseClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithIndex(&corev1.Pod{}, "spec.nodeName", adr0351PodNodeNameIndexer).
		WithObjects(sourcePod, replacementPod, pm, readyNMC("node-dst"), rs).Build()

	// KillFrozenSource fails — the re-adopt itself succeeds and is confirmed first.
	failResp := &agentpb.KillFrozenSourceResponse{Success: false, Error: "broker SIGKILL failed"}
	pool := agentClientPoolForTest(t, baseClient, failResp)

	// The spy agent needs a Running agent pod on node-src to resolve — add it via a second
	// client build so AgentPool.ForNode finds it (mirrors adr0356 test pattern).
	srcAgentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "podmotion-agent-src", Namespace: "podmotion-system", Labels: map[string]string{"app": "podmotion-agent"}},
		Spec:       corev1.PodSpec{NodeName: "node-src"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}
	if err := baseClient.Create(context.Background(), srcAgentPod); err != nil {
		t.Fatalf("create source agent pod: %v", err)
	}

	r := &PodMigrationReconciler{Client: baseClient, Scheme: scheme, AgentPool: pool}

	err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm)
	if err == nil {
		t.Fatal("expected an error — KillFrozenSource failure must not fall through to source delete")
	}

	// Source pod must NOT have been deleted.
	getErr := baseClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, &corev1.Pod{})
	if getErr != nil {
		t.Fatalf("source pod should NOT have been deleted: %v", getErr)
	}

	// Replacement pod must have been re-stripped back to CR-owned/label-stripped — NOT left
	// stranded RS-owned, even though the re-adopt itself was briefly confirmed.
	gotRepl := &corev1.Pod{}
	if err := baseClient.Get(context.Background(), types.NamespacedName{Name: adr0371ReplacementName, Namespace: "default"}, gotRepl); err != nil {
		t.Fatalf("get replacement pod: %v", err)
	}
	if len(gotRepl.OwnerReferences) != 1 || gotRepl.OwnerReferences[0].Kind != "PodMigration" {
		t.Fatalf("expected replacement pod re-stripped back to CR-owned after post-readopt failure, got OwnerReferences=%+v", gotRepl.OwnerReferences)
	}
	if _, present := gotRepl.Labels["app"]; present {
		t.Fatalf("expected selector label 'app' removed after rollback re-strip, got %+v", gotRepl.Labels)
	}
	if _, present := gotRepl.Labels["pod-template-hash"]; present {
		t.Fatalf("expected pod-template-hash removed after rollback re-strip, got %+v", gotRepl.Labels)
	}

	cond := meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionReplacementPodReadopted)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "ReadoptRestrippedAfterFailure" {
		t.Fatalf("expected ConditionReplacementPodReadopted=False/ReadoptRestrippedAfterFailure, got %+v", cond)
	}
}

// TestReadopt_LateRaceAfterKillFrozenSource_FailsClosed_SourceNotDeleted is the regression
// test for the review-identified TOCTOU gap this ADR was amended to close: "confirm
// before delete" only detects a race already lost by the time of the confirming read, not one
// that lands afterward — specifically in the window opened by the KillFrozenSource RPC's real,
// uncontrolled latency between the initial confirm and the source pod delete.
//
// This test lets the INITIAL bounded confirm poll inside
// readoptReplacementPodIntoOwningReplicaSet succeed normally (the replacement pod is genuinely
// RS-owned at that point — ConditionReplacementPodReadopted is observed True, exactly as the
// positive-path test proves). It then simulates the owning ReplicaSet's surplus-deletion
// reconcile deleting the replacement pod DURING the KillFrozenSource RPC itself (via the spy
// agent server's onCall hook, which runs synchronously inside the RPC handler before the
// response is returned) — i.e. strictly AFTER the confirm succeeded, not before it. Per the
// original (pre-amendment) design this window was unguarded: KillFrozenSource would have
// already unconditionally killed the frozen source process, and the source pod delete would
// have proceeded anyway on the strength of the now-stale earlier confirm, leaving both pods
// gone with no path back. This test asserts the amended design's final pre-delete re-check
// catches it instead: the source pod object is NOT deleted, and the migration fails closed via
// failReleaseAfterReadopt (re-stripped condition), even though KillFrozenSource itself did run
// (its irreversible kill cannot be undone — only the source pod OBJECT delete is prevented).
func TestReadopt_LateRaceAfterKillFrozenSource_FailsClosed_SourceNotDeleted(t *testing.T) {
	scheme := adr0371Scheme(t)
	rs := adr0371ReplicaSet()
	pm := adr0371PM("pm-late-race", true)
	sourcePod := adr0371SourcePod(rs, "node-src")
	replacementPod := adr0371ReplacementPod(t, scheme, pm)
	srcAgentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "podmotion-agent-src", Namespace: "podmotion-system", Labels: map[string]string{"app": "podmotion-agent"}},
		Spec:       corev1.PodSpec{NodeName: "node-src"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}

	baseClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&pmv1.PodMigration{}).
		WithIndex(&corev1.Pod{}, "spec.nodeName", adr0351PodNodeNameIndexer).
		WithObjects(sourcePod, replacementPod, pm, readyNMC("node-dst"), rs, srcAgentPod).Build()

	killResp := &agentpb.KillFrozenSourceResponse{Success: true, Killed: true}
	// onCall fires synchronously inside the KillFrozenSource RPC handler — i.e. strictly AFTER
	// readoptReplacementPodIntoOwningReplicaSet's own confirm poll has already returned success
	// (that poll runs entirely before the RPC is ever dialed), simulating the RS's
	// surplus-deletion reconcile winning the race in the RPC's latency window.
	pool := agentClientPoolForTestWithHook(t, baseClient, killResp, func() {
		if err := baseClient.Delete(context.Background(), replacementPod.DeepCopy()); err != nil {
			t.Errorf("onCall: failed to delete replacement pod mid-RPC to simulate the late race: %v", err)
		}
	})
	r := &PodMigrationReconciler{Client: baseClient, Scheme: scheme, AgentPool: pool}

	err := r.earlyReleaseSourceForTier1Longhorn(context.Background(), pm)
	if err == nil {
		t.Fatal("expected an error — the late race (replacement pod deleted after the initial confirm, during KillFrozenSource) must fail closed")
	}

	// The load-bearing assertion: the source pod OBJECT must NOT have been deleted, even
	// though KillFrozenSource already ran (its kill is irreversible, but the object delete
	// must still be prevented — this is what leaves a path back for recovery).
	getErr := baseClient.Get(context.Background(), types.NamespacedName{Name: "src-pod", Namespace: "default"}, &corev1.Pod{})
	if getErr != nil {
		t.Fatalf("source pod object should NOT have been deleted after the late race: %v", getErr)
	}

	// The replacement pod is gone (the RS "won" it in this scenario) — nothing left to
	// re-strip; failReleaseAfterReadopt's reStripReplacementPodOwnership treats NotFound as a
	// no-op success, so the condition set is the plain post-readopt-failure one.
	replGetErr := baseClient.Get(context.Background(), types.NamespacedName{Name: adr0371ReplacementName, Namespace: "default"}, &corev1.Pod{})
	if !apierrors.IsNotFound(replGetErr) {
		t.Fatalf("expected replacement pod to be gone (simulated RS deletion), got err=%v", replGetErr)
	}

	cond := meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionReplacementPodReadopted)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "ReadoptRestrippedAfterFailure" {
		t.Fatalf("expected ConditionReplacementPodReadopted=False/ReadoptRestrippedAfterFailure, got %+v", cond)
	}

	// Tier1EarlySourceRelease must never have been set True — the function returned before
	// reaching that point.
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
		t.Fatal("ConditionTier1EarlySourceRelease must not be set — the late race must stop the migration before this condition is reached")
	}
}
