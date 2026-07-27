/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0409_socketinventory_predatapath_abort_test.go is the falsifiable regression proof for
// ADR-0409 (docs/adr/0409-socketinventory-predatapath-source-unresolved-clean-abort-not-budget-rollback.md).
//
// Defect corrected: reconcileSocketInventory (the FIRST pipeline phase) resolved the source pod by
// the mutable spec.podName and treated ANY getPod error — including a deterministic NotFound on a
// migrate-then-renamed reference (ADR-0012) — as a transient 5s requeue with no phase-local
// terminal bound. That rode the shared 600s completion budget (invariant #8) and then failed into a
// rollback whose source-agent Abort RPC resolves the node by Status.SourceNodeName, which this
// pre-resolution path never populates (set only AFTER getPod succeeds) — dying Failed ~600s later
// via a rollback-of-nothing.
//
// ADR-0409 splits the error branch on apierrors.IsNotFound:
//   - a NotFound source pod at first-touch is a fast, attributed CLEAN-ABORT via failMigration
//     (nothing was mutated, no agent contacted, so nothing to roll back) — but only after ONE
//     confirmatory uncached live read rules out informer cache lag;
//   - a genuinely-transient (non-NotFound) error keeps the bounded requeue -> budget -> rollback
//     path (a retry can succeed and populate SourceNodeName).
//
// These tests are necessary-but-not-sufficient per the ADR: the load-bearing acceptance is the
// §7.2 live cluster proof. A refactor that reintroduces the slow-opaque wedge, that routes a
// NotFound into RollingBack, or that fast-fails a cache-lag miss, goes red here.

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	"github.com/podmotion-io/podmotion/internal/podlineage"
)

func adr0409Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	return scheme
}

// adr0409PM builds a PodMigration parked in the SocketInventory phase in Strict mode (so the
// getPod source-resolution gate is exercised, not the None-mode skip).
func adr0409PM(name, ns, podName string) *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: pmv1.PodMigrationSpec{
			PodName:             podName,
			PodNamespace:        ns,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhaseSocketInventory},
	}
}

// adr0409Pool returns a non-nil AgentPool so reconcileSocketInventory passes the AgentPool-nil
// gate and reaches the getPod source-resolution branch under test. It is never actually dialed on
// the NotFound/transient paths (they terminate/requeue before ForNode).
func adr0409Pool(c client.Client) *agentclient.AgentClientPool {
	// #nosec G402 -- test-only pool, never dialed on the paths under test.
	return agentclient.NewAgentClientPool(c, "1", &tls.Config{InsecureSkipVerify: true})
}

// TestADR0409_SocketInventoryNotFoundSourceIsCleanAbortNotRollback: a cached NotFound on the source
// pod (with no live pod to rescue it) drives terminal Failed via failMigration with an attributed
// reason, and NEVER transitions to RollingBack.
func TestADR0409_SocketInventoryNotFoundSourceIsCleanAbortNotRollback(t *testing.T) {
	scheme := adr0409Scheme(t)
	const ns, migName, podName = "default", "pm-notfound", "migration-demo-redis"

	// Source pod is ABSENT from the cached client -> getPod NotFound. A live successor that records
	// this source as its predecessor (via the lineage label — no longer via a name suffix) exists,
	// so the attribution hint should fire.
	successor := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName + "-m-f31c5423",
			Namespace: ns,
			Labels:    map[string]string{podlineage.PredecessorPodNameLabel: podName},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	pm := adr0409PM(migName, ns, podName)

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(pm, successor).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme, AgentPool: adr0409Pool(c)}
	// KubeClient left nil: sourcePodPresentLive degrades to "not present" -> clean-abort proceeds.

	if _, err := r.reconcileSocketInventory(context.Background(), pm); err != nil {
		t.Fatalf("reconcileSocketInventory returned error: %v", err)
	}

	got := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: migName}, got); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	if got.Status.Phase != pmv1.MigrationPhaseFailed {
		t.Fatalf("phase = %q, want %q (clean-abort terminal)", got.Status.Phase, pmv1.MigrationPhaseFailed)
	}
	if got.Status.Phase == pmv1.MigrationPhaseRollingBack {
		t.Fatalf("phase reached RollingBack — a pre-datapath NotFound must NEVER enter rollback")
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, pmv1.ConditionFailed)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("ConditionFailed = %+v, want True with an attributed reason", cond)
	}
	if !strings.Contains(cond.Message, podName) {
		t.Errorf("failure reason %q does not name the missing pod %q", cond.Message, podName)
	}
	if !strings.Contains(cond.Message, successor.Name) {
		t.Errorf("failure reason %q does not surface the live successor hint %q", cond.Message, successor.Name)
	}
}

// TestADR0409_SocketInventoryTransientErrorStillRequeues: a non-NotFound getPod error keeps the
// bounded requeue (fail-closed budget path), never a terminal transition.
func TestADR0409_SocketInventoryTransientErrorStillRequeues(t *testing.T) {
	scheme := adr0409Scheme(t)
	const ns, migName, podName = "default", "pm-transient", "migration-demo-redis"
	pm := adr0409PM(migName, ns, podName)

	transient := apierrors.NewServerTimeout(schema.GroupResource{Resource: "pods"}, "get", 1)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(pm).WithStatusSubresource(pm).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Pod); ok && key.Name == podName {
					return transient
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme, AgentPool: adr0409Pool(c)}

	res, err := r.reconcileSocketInventory(context.Background(), pm)
	if err != nil {
		t.Fatalf("reconcileSocketInventory returned error: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("transient error must return a bounded RequeueAfter, got %+v", res)
	}

	got := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: migName}, got); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	if got.Status.Phase == pmv1.MigrationPhaseFailed || got.Status.Phase == pmv1.MigrationPhaseRollingBack {
		t.Fatalf("transient error terminated the migration (phase=%q) — must only requeue", got.Status.Phase)
	}
}

// TestADR0409_CacheLagNotFoundIsRescuedByLiveRead: a cached NotFound whose pod IS present on the
// uncached live read is informer cache lag — must requeue, NOT clean-abort.
func TestADR0409_CacheLagNotFoundIsRescuedByLiveRead(t *testing.T) {
	scheme := adr0409Scheme(t)
	const ns, migName, podName = "default", "pm-cachelag", "freshly-created-pod"
	pm := adr0409PM(migName, ns, podName)

	// Cached client does NOT have the source pod (cache lag); the uncached KubeClient DOES.
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()
	live := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: ns},
		Spec:       corev1.PodSpec{NodeName: "pm-w1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	r := &PodMigrationReconciler{
		Client:     c,
		Scheme:     scheme,
		AgentPool:  adr0409Pool(c),
		KubeClient: kubefake.NewSimpleClientset(live),
	}

	res, err := r.reconcileSocketInventory(context.Background(), pm)
	if err != nil {
		t.Fatalf("reconcileSocketInventory returned error: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("cache-lag NotFound must requeue, got %+v", res)
	}
	got := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: migName}, got); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	if got.Status.Phase == pmv1.MigrationPhaseFailed {
		t.Fatalf("cache-lag NotFound was fast-failed — a valid migration whose source is momentarily cache-absent must NOT terminate")
	}
}

// TestADR0409_SourceNodeNameNeverSetOnUnresolvedPath: the clean-abort path never writes
// Status.SourceNodeName, so the removed rollback path's precondition is provably never satisfiable.
func TestADR0409_SourceNodeNameNeverSetOnUnresolvedPath(t *testing.T) {
	scheme := adr0409Scheme(t)
	const ns, migName, podName = "default", "pm-nonode", "migration-demo-redis"
	pm := adr0409PM(migName, ns, podName)

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme, AgentPool: adr0409Pool(c)}

	if _, err := r.reconcileSocketInventory(context.Background(), pm); err != nil {
		t.Fatalf("reconcileSocketInventory returned error: %v", err)
	}
	if pm.Status.SourceNodeName != "" {
		t.Fatalf("Status.SourceNodeName = %q, want empty on the unresolved clean-abort path", pm.Status.SourceNodeName)
	}
	got := &pmv1.PodMigration{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: migName}, got); err != nil {
		t.Fatalf("get pm: %v", err)
	}
	if got.Status.SourceNodeName != "" {
		t.Fatalf("persisted Status.SourceNodeName = %q, want empty", got.Status.SourceNodeName)
	}
}

// TestADR0409_SuccessorHintDegradesGracefully: the attribution helper returns a helpful string only
// in the unambiguous single-successor case and "" for zero, multiple, or a List error, and never
// affects control flow (it is a pure string builder here).
func TestADR0409_SuccessorHintDegradesGracefully(t *testing.T) {
	scheme := adr0409Scheme(t)
	const ns, podName = "default", "migration-demo-redis"

	// mkSuccessor stamps the lineage predecessor label the hint now matches on (rather than encoding
	// the predecessor in the pod name). mkUnrelated makes a pod with no such label.
	mkSuccessor := func(name, predecessor string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{podlineage.PredecessorPodNameLabel: predecessor},
		}}
	}
	mkUnrelated := func(name string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	}

	t.Run("single_successor_yields_hint", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(mkSuccessor(podName+"-m-f31c5423", podName)).Build()
		r := &PodMigrationReconciler{Client: c, Scheme: scheme}
		hint := r.describeLiveSuccessorHint(context.Background(), adr0409PM("pm", ns, podName))
		if !strings.Contains(hint, podName+"-m-f31c5423") {
			t.Fatalf("hint = %q, want it to name the single successor", hint)
		}
	})

	t.Run("zero_candidates_empty", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mkUnrelated("unrelated")).Build()
		r := &PodMigrationReconciler{Client: c, Scheme: scheme}
		if hint := r.describeLiveSuccessorHint(context.Background(), adr0409PM("pm", ns, podName)); hint != "" {
			t.Fatalf("hint = %q, want empty with no successor", hint)
		}
	})

	t.Run("multiple_candidates_ambiguous_empty", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(mkSuccessor(podName+"-m-aaaaaaaa", podName), mkSuccessor(podName+"-m-bbbbbbbb", podName)).Build()
		r := &PodMigrationReconciler{Client: c, Scheme: scheme}
		if hint := r.describeLiveSuccessorHint(context.Background(), adr0409PM("pm", ns, podName)); hint != "" {
			t.Fatalf("hint = %q, want empty when ambiguous", hint)
		}
	})

	t.Run("list_error_empty", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).
			WithInterceptorFuncs(interceptor.Funcs{
				List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					return errors.New("simulated list failure")
				},
			}).Build()
		r := &PodMigrationReconciler{Client: c, Scheme: scheme}
		if hint := r.describeLiveSuccessorHint(context.Background(), adr0409PM("pm", ns, podName)); hint != "" {
			t.Fatalf("hint = %q, want empty on List error", hint)
		}
	})
}

// TestADR0409_ResolvableSourceUnchanged: a live source pod still resolves and sets
// Status.SourceNodeName, and does NOT clean-abort (no regression to the success path). The agent is
// unreachable so the phase requeues downstream of the getPod gate — the point is it is NOT Failed
// and SourceNodeName IS populated.
func TestADR0409_ResolvableSourceUnchanged(t *testing.T) {
	scheme := adr0409Scheme(t)
	const ns, migName, podName, srcNode = "default", "pm-resolvable", "migration-demo-redis", "pm-w2"
	pm := adr0409PM(migName, ns, podName)
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: ns, UID: "uid-src"},
		Spec:       corev1.PodSpec{NodeName: srcNode},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.9"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(pm, srcPod).WithStatusSubresource(pm).Build()
	r := &PodMigrationReconciler{Client: c, Scheme: scheme, AgentPool: adr0409Pool(c)}

	if _, err := r.reconcileSocketInventory(context.Background(), pm); err != nil {
		t.Fatalf("reconcileSocketInventory returned error: %v", err)
	}
	if pm.Status.SourceNodeName != srcNode {
		t.Fatalf("Status.SourceNodeName = %q, want %q (resolvable source path must set it)", pm.Status.SourceNodeName, srcNode)
	}
	if pm.Status.Phase == pmv1.MigrationPhaseFailed || pm.Status.Phase == pmv1.MigrationPhaseRollingBack {
		t.Fatalf("resolvable source pod was terminated (phase=%q) — the success path must be unchanged", pm.Status.Phase)
	}
}
