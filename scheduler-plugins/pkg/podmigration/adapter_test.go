//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package podmigration_test

// ADR-0363 B1 verification follow-up: these tests exercise the
// adapter's OWN translation code (adapter.go) — the framework<->hand-rolled-type mapping —
// not just filter.go/score.go's pre-existing business logic (already covered by
// filter_test.go/score_test.go/filter_cpu_test.go, untouched here). Specifically:
//   - FilterResult{Allowed:false, Reason} must map to framework.NewStatus(Unschedulable,
//     reason), never silently degrade to a Success status on a mapping bug.
//   - (int64, error) from MigrationAwareScore.Score must map to (int64, *framework.Status)
//     with the SAME int64 value and a non-nil Status whose code reflects the error.
//   - PreScore -> CycleState -> Score must actually thread the resolved source context through
//     to the delegated Score call (not a stale/zero-valued field left over from construction or
//     an earlier cycle).

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	fwk "k8s.io/kube-scheduler/framework"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/scheduler-plugins/pkg/podmigration"
)

// fakeCycleState is a minimal fwk.CycleState implementation used only by adapter_test.go.
// Deliberately hand-rolled instead of pulling in k8s.io/kubernetes/pkg/scheduler/framework's
// concrete CycleState — the whole point of adapter.go depending only on the lightweight
// k8s.io/kube-scheduler/framework staging module is that its tests shouldn't need the heavy
// module either. Only Read/Write/Delete are exercised by the adapter; the Skip*/metrics methods
// are unused no-ops required to satisfy the interface.
type fakeCycleState struct {
	data map[fwk.StateKey]fwk.StateData
}

func newState() fwk.CycleState { return &fakeCycleState{data: map[fwk.StateKey]fwk.StateData{}} }

func (s *fakeCycleState) ShouldRecordPluginMetrics() bool         { return false }
func (s *fakeCycleState) GetSkipFilterPlugins() sets.Set[string]  { return nil }
func (s *fakeCycleState) SetSkipFilterPlugins(sets.Set[string])   {}
func (s *fakeCycleState) GetSkipScorePlugins() sets.Set[string]   { return nil }
func (s *fakeCycleState) SetSkipScorePlugins(sets.Set[string])    {}
func (s *fakeCycleState) GetSkipPreBindPlugins() sets.Set[string] { return nil }
func (s *fakeCycleState) SetSkipPreBindPlugins(sets.Set[string])  {}
func (s *fakeCycleState) Read(key fwk.StateKey) (fwk.StateData, error) {
	if v, ok := s.data[key]; ok {
		return v, nil
	}
	return nil, fwk.ErrNotFound
}
func (s *fakeCycleState) Write(key fwk.StateKey, val fwk.StateData) { s.data[key] = val }
func (s *fakeCycleState) Delete(key fwk.StateKey)                   { delete(s.data, key) }
func (s *fakeCycleState) Clone() fwk.CycleState {
	clone := &fakeCycleState{data: map[fwk.StateKey]fwk.StateData{}}
	for k, v := range s.data {
		clone.data[k] = v.Clone()
	}
	return clone
}

// adapterFakeReader is a general-purpose client.Reader test double keyed by GroupResource+name,
// used only by adapter_test.go. Unlike filter_test.go's stubNMCReader (which returns a bespoke
// non-apierrors error), missing entries here return a real *apierrors.StatusError via
// apierrors.NewNotFound, so the adapter's apierrors.IsNotFound(...) branch (the
// MigrationCheckpoint-not-yet-captured degenerate) is exercised against the same error shape a
// real API server produces — not merely assumed to work.
type adapterFakeReader struct {
	nmcs  map[string]*v1alpha1.NodeMigrationCapacity
	pms   map[string]*v1alpha1.PodMigration
	nodes map[string]*corev1.Node
	mcps  map[string]*v1alpha1.MigrationCheckpoint
}

func (r *adapterFakeReader) Get(_ context.Context, key types.NamespacedName, obj client.Object, _ ...client.GetOption) error {
	switch target := obj.(type) {
	case *v1alpha1.NodeMigrationCapacity:
		nmc, ok := r.nmcs[key.Name]
		if !ok {
			return apierrors.NewNotFound(schema.GroupResource{Group: "migration.podmotion.io", Resource: "nodemigrationcapacities"}, key.Name)
		}
		*target = *nmc
		return nil
	case *v1alpha1.PodMigration:
		pm, ok := r.pms[key.Namespace+"/"+key.Name]
		if !ok {
			return apierrors.NewNotFound(schema.GroupResource{Group: "migration.podmotion.io", Resource: "podmigrations"}, key.Name)
		}
		*target = *pm
		return nil
	case *corev1.Node:
		node, ok := r.nodes[key.Name]
		if !ok {
			return apierrors.NewNotFound(schema.GroupResource{Resource: "nodes"}, key.Name)
		}
		*target = *node
		return nil
	case *v1alpha1.MigrationCheckpoint:
		mcp, ok := r.mcps[key.Namespace+"/"+key.Name]
		if !ok {
			return apierrors.NewNotFound(schema.GroupResource{Group: "migration.podmotion.io", Resource: "migrationcheckpoints"}, key.Name)
		}
		*target = *mcp
		return nil
	default:
		return apierrors.NewNotFound(schema.GroupResource{}, key.Name)
	}
}

func (r *adapterFakeReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return nil
}

// fakeNodeInfo is a minimal fwk.NodeInfo whose only behavior the adapter uses is Node().
type fakeNodeInfo struct {
	fwk.NodeInfo
	node *corev1.Node
}

func (f *fakeNodeInfo) Node() *corev1.Node { return f.node }

func nodeInfoFor(node *corev1.Node) fwk.NodeInfo { return &fakeNodeInfo{node: node} }

func destNMC(name string, active, max int32) *v1alpha1.NodeMigrationCapacity {
	return &v1alpha1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.NodeMigrationCapacitySpec{
			NodeName:                           name,
			CRIUVersion:                        "4.2",
			MaxConcurrentMigrationsDestination: max,
		},
		Status: v1alpha1.NodeMigrationCapacityStatus{
			Ready:                       true,
			ActiveDestinationMigrations: active,
		},
	}
}

// --- Filter mapping ---------------------------------------------------------------------

func TestAdapter_Filter_AllowedMapsToSuccess(t *testing.T) {
	reader := &adapterFakeReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{
		"node-a": destNMC("node-a", 0, 2),
	}}
	a := podmigration.NewAdapter(reader, runtime.NewScheme())
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "default"}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}

	status := a.Filter(context.Background(), newState(), pod, nodeInfoFor(node))
	if status.Code() != fwk.Success {
		t.Fatalf("expected Success, got code=%v reasons=%v", status.Code(), status.Reasons())
	}
}

// TestAdapter_Filter_DisallowedMapsToUnschedulableWithReason asserts:
// FilterResult{Allowed:false, Reason} must map onto framework.NewStatus(Unschedulable, reason)
// — and must NOT silently degrade to Success. A mapping bug that drops the Allowed check (e.g.
// always returning fwk.NewStatus(fwk.Success)) would pass every OTHER adapter test in this file
// but fails this one specifically because it asserts both the failing Code AND that the
// business-logic Reason string survives the translation verbatim.
func TestAdapter_Filter_DisallowedMapsToUnschedulableWithReason(t *testing.T) {
	reader := &adapterFakeReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{
		// active == max => at-capacity => FilterResult{Allowed:false, Reason: "destination capacity full (2/2)"}
		"node-b": destNMC("node-b", 2, 2),
	}}
	a := podmigration.NewAdapter(reader, runtime.NewScheme())
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "default"}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b"}}

	status := a.Filter(context.Background(), newState(), pod, nodeInfoFor(node))
	if status.Code() != fwk.Unschedulable {
		t.Fatalf("expected Unschedulable, got code=%v (this is the fail-open regression this test guards against)", status.Code())
	}
	if status.Message() == "" {
		t.Fatalf("expected the FilterResult.Reason to survive translation into the Status, got empty message")
	}
	want := "destination capacity full (2/2)"
	if status.Message() != want {
		t.Fatalf("Reason not translated verbatim: got %q, want %q", status.Message(), want)
	}
}

// --- Score mapping ------------------------------------------------------------------------

func TestAdapter_Score_SuccessMapsInt64AndStatus(t *testing.T) {
	reader := &adapterFakeReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{
		"node-a": destNMC("node-a", 0, 4),
	}}
	a := podmigration.NewAdapter(reader, runtime.NewScheme())
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "default"}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}

	state := newState()
	if s := a.PreScore(context.Background(), state, pod, nil); s.Code() != fwk.Success {
		t.Fatalf("PreScore failed: %v", s.Message())
	}

	score, status := a.Score(context.Background(), state, pod, nodeInfoFor(node))
	if status.Code() != fwk.Success {
		t.Fatalf("expected Success status, got code=%v msg=%v", status.Code(), status.Message())
	}
	// No source context (no migration label): locality=0 (no source labels), thermal=100 (no
	// throttle data), load=100 (0 active of 4), memHeadroom=0 (node has no Allocatable memory
	// set in this fixture). Weighted per DefaultWeights (40/20/20/20):
	// (0*40 + 100*20 + 100*20 + 0*20) / 100 = 40.
	if score != 40 {
		t.Fatalf("adapter did not pass through MigrationAwareScore.Score's int64 unchanged: got %d, want 40", score)
	}
}

// TestAdapter_Score_ErrorMapsToNonNilErrorStatus asserts: the (int64, error)
// return of MigrationAwareScore.Score must map onto (int64, *framework.Status) with a non-nil,
// non-Success Status when the plugin returns an error — never (score, nil)/(score, Success),
// which would be scheduler-fatal (a nil *Status is treated as Success by the framework: see
// fwk.Status.Code()'s nil receiver case).
func TestAdapter_Score_ErrorMapsToNonNilErrorStatus(t *testing.T) {
	// No NMC registered for "missing-node" => MigrationAwareScore.Score returns (0, error).
	reader := &adapterFakeReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{}}
	a := podmigration.NewAdapter(reader, runtime.NewScheme())
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "default"}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "missing-node"}}

	state := newState()
	if s := a.PreScore(context.Background(), state, pod, nil); s.Code() != fwk.Success {
		t.Fatalf("PreScore failed: %v", s.Message())
	}

	score, status := a.Score(context.Background(), state, pod, nodeInfoFor(node))
	if status == nil {
		t.Fatalf("expected a non-nil Status on Score error — a nil Status is Success to the framework, which would silently schedule against a node whose NMC read failed")
	}
	if status.Code() == fwk.Success {
		t.Fatalf("expected a non-Success code when MigrationAwareScore.Score returns an error, got Success (fail-open regression)")
	}
	if score != 0 {
		t.Fatalf("expected score 0 on error path, got %d", score)
	}
}

// --- PreScore -> CycleState -> Score threading -------------------------------------------
//
// score.go's OWN business logic (Part A, untouched) gives migration-labeled pods an EXCLUSIVE
// destination-routing fast path (scoreForMigrationLabel: maxScore for the one pre-designated
// node, 0 for every other node) that never consults SetSourceContext's locality/RSS data at
// all — and filter.go's twin fast path only ever lets ONE node reach Score for such a pod in
// the first place. So a same-zone-vs-different-zone score DIFFERENTIAL is structurally
// unobservable through a migration-labeled pod, regardless of whether PreScore->Score threading
// is correct or broken; that is an accepted, unrelated fact about the wrapped black box, not
// something this adapter should route around. The tests below instead prove threading directly,
// at the boundary the adapter actually owns:
//   - adapter_internal_test.go (package podmigration, same directory) verifies PreScore writes
//     the exact resolved sourceContextData into CycleState, and that Score reads exactly what
//     was written and forwards it to SetSourceContext — both checked with precise expected
//     values, not merely "non-zero".
//   - The test below verifies the observable, cross-package-boundary consequence of that:
//     Score results are cycle-scoped and never bleed a REAL, non-empty context resolved in one
//     PreScore/Score cycle into a later cycle that starts its own, separate CycleState — which
//     is the concrete "stale/zero-valued struct field" failure mode this guards against, and is fully
//     observable without needing score.go's weighted path to differentiate on locality.

// TestAdapter_Score_NoBleedThroughAcrossCycles proves a real, non-empty source context resolved
// and threaded in one scheduling cycle does not leak into a later, independent cycle that never
// wrote one. Cycle 1 uses a migration-labeled pod (a real PreScore resolution, writing non-empty
// sourceContextData to its own CycleState). Cycle 2 uses an ordinary pod on a FRESH CycleState,
// exercising score.go's weighted path. If Score read a leftover value from the shared,
// long-lived MigrationAwareScore instance instead of THIS cycle's own CycleState, cycle 2's
// weighted computation would be corrupted by cycle 1's resolved data; it is not, because Score
// always resets via SetSourceContext from cycle 2's own (absent-key) CycleState first.
func TestAdapter_Score_NoBleedThroughAcrossCycles(t *testing.T) {
	destNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "dest"}}
	srcNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "src",
			Labels: map[string]string{"topology.kubernetes.io/zone": "us-east-1a"},
		},
	}
	sizeBytes := int64(512 * 1024 * 1024)

	reader := &adapterFakeReader{
		nmcs: map[string]*v1alpha1.NodeMigrationCapacity{"dest": destNMC("dest", 0, 4)},
		pms: map[string]*v1alpha1.PodMigration{
			"default/mig-a": {
				ObjectMeta: metav1.ObjectMeta{Name: "mig-a", Namespace: "default"},
				Status:     v1alpha1.PodMigrationStatus{SourceNodeName: "src"},
			},
		},
		nodes: map[string]*corev1.Node{"src": srcNode},
		mcps: map[string]*v1alpha1.MigrationCheckpoint{
			"default/mig-a": {
				ObjectMeta: metav1.ObjectMeta{Name: "mig-a", Namespace: "default"},
				Spec:       v1alpha1.MigrationCheckpointSpec{SizeBytes: &sizeBytes},
			},
		},
	}
	a := podmigration.NewAdapter(reader, runtime.NewScheme())

	labeledPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "replacement", Namespace: "default",
		Labels: map[string]string{"podmotion.io/migration-name": "mig-a"},
	}}

	// Cycle 1: real, non-empty source context resolved and written (verified precisely by
	// adapter_internal_test.go). Its Score result is irrelevant here (score.go's exclusive
	// path ignores it) — only that PreScore actually ran and populated cycle 1's CycleState.
	state1 := newState()
	if s := a.PreScore(context.Background(), state1, labeledPod, nil); s.Code() != fwk.Success {
		t.Fatalf("PreScore (cycle 1, labeled) failed: %v", s.Message())
	}
	if _, status := a.Score(context.Background(), state1, labeledPod, nodeInfoFor(destNode)); status.Code() != fwk.Success {
		t.Fatalf("Score (cycle 1, labeled) failed: %v", status.Message())
	}

	// Baseline: what an ordinary pod scores on a CycleState that NEVER saw a real source
	// context (established independently by TestAdapter_Score_SuccessMapsInt64AndStatus == 40
	// for this exact NMC shape, since destNode here also has no Allocatable memory set).
	plainPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "default"}}
	baselineState := newState()
	if s := a.PreScore(context.Background(), baselineState, plainPod, nil); s.Code() != fwk.Success {
		t.Fatalf("PreScore (baseline) failed: %v", s.Message())
	}
	baselineScore, baselineStatus := a.Score(context.Background(), baselineState, plainPod, nodeInfoFor(destNode))
	if baselineStatus.Code() != fwk.Success {
		t.Fatalf("Score (baseline) failed: %v", baselineStatus.Message())
	}

	// Cycle 2: the SAME ordinary pod, same adapter/plugin instance, on its OWN fresh
	// CycleState — run AFTER cycle 1 resolved a real, non-empty context. If Score bled through
	// cycle 1's leftover state (a stale-field bug), this would differ from baselineScore.
	state2 := newState()
	if s := a.PreScore(context.Background(), state2, plainPod, nil); s.Code() != fwk.Success {
		t.Fatalf("PreScore (cycle 2) failed: %v", s.Message())
	}
	score2, status2 := a.Score(context.Background(), state2, plainPod, nodeInfoFor(destNode))
	if status2.Code() != fwk.Success {
		t.Fatalf("Score (cycle 2) failed: %v", status2.Message())
	}

	if score2 != baselineScore {
		t.Fatalf("cross-cycle bleed-through detected: cycle 2 scored %d, want the isolated baseline %d "+
			"(cycle 1's real, non-empty source context leaked into a later, unrelated cycle)", score2, baselineScore)
	}
}

// TestAdapter_PreScore_MissingPodMigrationFailsClosed proves the identity-resolution failure
// path is fail-closed (fwk.Error), not a silent Success with an empty/default source context —
// per the project's zero-fail-open standing rule, a pod that names a PodMigration the adapter
// cannot resolve must not be scored as if it were an ordinary, non-migration pod.
func TestAdapter_PreScore_MissingPodMigrationFailsClosed(t *testing.T) {
	reader := &adapterFakeReader{}
	a := podmigration.NewAdapter(reader, runtime.NewScheme())
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "replacement", Namespace: "default",
		Labels: map[string]string{"podmotion.io/migration-name": "does-not-exist"},
	}}

	status := a.PreScore(context.Background(), newState(), pod, nil)
	if status.Code() != fwk.Error {
		t.Fatalf("expected fwk.Error on unresolvable PodMigration, got code=%v (fail-open regression)", status.Code())
	}
}

// TestAdapter_PreScore_MissingCheckpointIsNotAnError proves the checkpoint-not-yet-captured
// degenerate (a genuinely ordinary point in the migration lifecycle) does NOT fail the cycle —
// distinguishing this from the fail-closed cases above is itself part of the correctness bar:
// treating every Get miss as fatal would be over-broad; treating every Get miss as tolerable
// would be fail-open. Only this specific, well-understood miss is tolerated.
func TestAdapter_PreScore_MissingCheckpointIsNotAnError(t *testing.T) {
	reader := &adapterFakeReader{
		pms: map[string]*v1alpha1.PodMigration{
			"default/mig-x": {ObjectMeta: metav1.ObjectMeta{Name: "mig-x", Namespace: "default"}},
		},
		mcps: map[string]*v1alpha1.MigrationCheckpoint{}, // deliberately empty
	}
	a := podmigration.NewAdapter(reader, runtime.NewScheme())
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "replacement", Namespace: "default",
		Labels: map[string]string{"podmotion.io/migration-name": "mig-x"},
	}}

	status := a.PreScore(context.Background(), newState(), pod, nil)
	if status.Code() != fwk.Success {
		t.Fatalf("expected Success when the MigrationCheckpoint simply doesn't exist yet, got code=%v msg=%v", status.Code(), status.Message())
	}
}
