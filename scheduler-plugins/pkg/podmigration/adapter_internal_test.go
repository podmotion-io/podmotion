//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package podmigration

// Internal (white-box) tests for the PreScore -> CycleState -> Score threading path. These
// complement adapter_test.go's black-box tests by reaching the unexported sourceContextStateKey
// / sourceContextData directly, so the assertions here check EXACT resolved values (not merely
// "differs from zero") and isolate Score's CycleState-read/SetSourceContext-forward step from
// PreScore's resolution step — see adapter_test.go's threading-test doc comment for why the two
// must be verified separately given score.go's own migration-label fast path.

import (
	"context"
	"reflect"
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
)

// --- minimal local test doubles (duplicated, not imported, from adapter_test.go: that file is
// package podmigration_test, an external package this internal test file cannot import from
// without creating an import cycle) ---

type internalFakeCycleState struct {
	data map[fwk.StateKey]fwk.StateData
}

func newInternalState() *internalFakeCycleState {
	return &internalFakeCycleState{data: map[fwk.StateKey]fwk.StateData{}}
}
func (s *internalFakeCycleState) ShouldRecordPluginMetrics() bool         { return false }
func (s *internalFakeCycleState) GetSkipFilterPlugins() sets.Set[string]  { return nil }
func (s *internalFakeCycleState) SetSkipFilterPlugins(sets.Set[string])   {}
func (s *internalFakeCycleState) GetSkipScorePlugins() sets.Set[string]   { return nil }
func (s *internalFakeCycleState) SetSkipScorePlugins(sets.Set[string])    {}
func (s *internalFakeCycleState) GetSkipPreBindPlugins() sets.Set[string] { return nil }
func (s *internalFakeCycleState) SetSkipPreBindPlugins(sets.Set[string])  {}
func (s *internalFakeCycleState) Read(key fwk.StateKey) (fwk.StateData, error) {
	if v, ok := s.data[key]; ok {
		return v, nil
	}
	return nil, fwk.ErrNotFound
}
func (s *internalFakeCycleState) Write(key fwk.StateKey, val fwk.StateData) { s.data[key] = val }
func (s *internalFakeCycleState) Delete(key fwk.StateKey)                   { delete(s.data, key) }
func (s *internalFakeCycleState) Clone() fwk.CycleState {
	clone := newInternalState()
	for k, v := range s.data {
		clone.data[k] = v.Clone()
	}
	return clone
}

type internalFakeReader struct {
	pms   map[string]*v1alpha1.PodMigration
	nodes map[string]*corev1.Node
	mcps  map[string]*v1alpha1.MigrationCheckpoint
}

func (r *internalFakeReader) Get(_ context.Context, key types.NamespacedName, obj client.Object, _ ...client.GetOption) error {
	switch target := obj.(type) {
	case *v1alpha1.PodMigration:
		pm, ok := r.pms[key.Namespace+"/"+key.Name]
		if !ok {
			return apierrors.NewNotFound(schema.GroupResource{Resource: "podmigrations"}, key.Name)
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
			return apierrors.NewNotFound(schema.GroupResource{Resource: "migrationcheckpoints"}, key.Name)
		}
		*target = *mcp
		return nil
	default:
		return apierrors.NewNotFound(schema.GroupResource{}, key.Name)
	}
}
func (r *internalFakeReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return nil
}

// TestAdapter_PreScore_WritesExactResolvedContext verifies PreScore's CycleState write is the
// EXACT resolved source-node labels and RSS bytes from the fixture — not a zero/default value,
// not a partial/wrong-key write. This is the precise "not a stale/zero-valued struct field"
// check QA asked for, applied at the exact point the adapter owns (the CycleState write itself),
// independent of whatever score.go's business logic later does with it.
func TestAdapter_PreScore_WritesExactResolvedContext(t *testing.T) {
	sizeBytes := int64(777 * 1024 * 1024)
	reader := &internalFakeReader{
		pms: map[string]*v1alpha1.PodMigration{
			"default/mig-a": {
				ObjectMeta: metav1.ObjectMeta{Name: "mig-a", Namespace: "default"},
				Status:     v1alpha1.PodMigrationStatus{SourceNodeName: "src-node"},
			},
		},
		nodes: map[string]*corev1.Node{
			"src-node": {
				ObjectMeta: metav1.ObjectMeta{
					Name: "src-node",
					Labels: map[string]string{
						"topology.kubernetes.io/zone":   "us-east-1a",
						"topology.kubernetes.io/region": "us-east-1",
					},
				},
			},
		},
		mcps: map[string]*v1alpha1.MigrationCheckpoint{
			"default/mig-a": {
				ObjectMeta: metav1.ObjectMeta{Name: "mig-a", Namespace: "default"},
				Spec:       v1alpha1.MigrationCheckpointSpec{SizeBytes: &sizeBytes},
			},
		},
	}
	a := NewAdapter(reader, runtime.NewScheme())
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "replacement", Namespace: "default",
		Labels: map[string]string{"podmotion.io/migration-name": "mig-a"},
	}}

	state := newInternalState()
	if s := a.PreScore(context.Background(), state, pod, nil); s.Code() != fwk.Success {
		t.Fatalf("PreScore failed: %v", s.Message())
	}

	raw, err := state.Read(sourceContextStateKey)
	if err != nil {
		t.Fatalf("expected PreScore to have written %s, got Read error: %v", sourceContextStateKey, err)
	}
	got, ok := raw.(*sourceContextData)
	if !ok {
		t.Fatalf("CycleState entry is not *sourceContextData: %T", raw)
	}

	wantLabels := map[string]string{
		"topology.kubernetes.io/zone":   "us-east-1a",
		"topology.kubernetes.io/region": "us-east-1",
	}
	if !reflect.DeepEqual(got.nodeLabels, wantLabels) {
		t.Fatalf("resolved nodeLabels mismatch: got %v, want %v (stale/zero-valued write regression)", got.nodeLabels, wantLabels)
	}
	if got.rssBytes != sizeBytes {
		t.Fatalf("resolved rssBytes mismatch: got %d, want %d (stale/zero-valued write regression)", got.rssBytes, sizeBytes)
	}
}

// TestAdapter_PreScore_NoLabelWritesExplicitZeroValue verifies the "no migration label" branch
// writes an EXPLICIT zero-value entry (not simply skipping the write and leaving Score to
// silently fall back to whatever Read returns for a missing key). This matters because a plugin
// instance IS reused across concurrent/adjacent cycles; PreScore must positively reset state for
// non-migration pods each cycle, not rely on the key merely being absent.
func TestAdapter_PreScore_NoLabelWritesExplicitZeroValue(t *testing.T) {
	a := NewAdapter(&internalFakeReader{}, runtime.NewScheme())
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "default"}}

	state := newInternalState()
	if s := a.PreScore(context.Background(), state, pod, nil); s.Code() != fwk.Success {
		t.Fatalf("PreScore failed: %v", s.Message())
	}

	raw, err := state.Read(sourceContextStateKey)
	if err != nil {
		t.Fatalf("expected an explicit zero-value write, got Read error: %v", err)
	}
	got, ok := raw.(*sourceContextData)
	if !ok {
		t.Fatalf("CycleState entry is not *sourceContextData: %T", raw)
	}
	if got.nodeLabels != nil || got.rssBytes != 0 {
		t.Fatalf("expected explicit zero-value sourceContextData, got %+v", got)
	}
}

// TestAdapter_Score_ForwardsExactCycleStateValueToSetSourceContext verifies the Score-side half
// of the threading path in isolation: given a CycleState pre-populated with a KNOWN
// sourceContextData (as PreScore would have written it), Score must apply that EXACT data via
// SetSourceContext before delegating — proven observably through score.go's own (unmodified)
// weighted locality computation, which only MigrationAwareScore.SetSourceContext can influence.
// Writing the fixture directly (bypassing PreScore) isolates this from PreScore's own resolution
// logic, already covered above, and from score.go's migration-label fast path, which does not
// consume SetSourceContext at all (see adapter_test.go's threading doc comment).
func TestAdapter_Score_ForwardsExactCycleStateValueToSetSourceContext(t *testing.T) {
	a := NewAdapter(&fakeNMCReaderForInternal{
		nmcs: map[string]*v1alpha1.NodeMigrationCapacity{
			"dest": {
				ObjectMeta: metav1.ObjectMeta{Name: "dest"},
				Spec: v1alpha1.NodeMigrationCapacitySpec{
					NodeName:                           "dest",
					CRIUVersion:                        "4.2",
					MaxConcurrentMigrationsDestination: 4,
				},
				Status: v1alpha1.NodeMigrationCapacityStatus{Ready: true, ActiveDestinationMigrations: 0},
			},
		},
	}, runtime.NewScheme())

	destNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "dest",
			Labels: map[string]string{"topology.kubernetes.io/zone": "us-east-1a"},
		},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "default"}}

	// Same-zone fixture, written directly (simulating what PreScore resolved).
	sameZoneState := newInternalState()
	sameZoneState.Write(sourceContextStateKey, &sourceContextData{
		nodeLabels: map[string]string{"topology.kubernetes.io/zone": "us-east-1a"},
		rssBytes:   0,
	})
	sameZoneScore, status := a.Score(context.Background(), sameZoneState, pod, testNodeInfo{node: destNode})
	if status.Code() != fwk.Success {
		t.Fatalf("Score (same-zone fixture) failed: %v", status.Message())
	}

	// Different-zone fixture, same destination node.
	otherZoneState := newInternalState()
	otherZoneState.Write(sourceContextStateKey, &sourceContextData{
		nodeLabels: map[string]string{"topology.kubernetes.io/zone": "us-west-2b"},
		rssBytes:   0,
	})
	otherZoneScore, status2 := a.Score(context.Background(), otherZoneState, pod, testNodeInfo{node: destNode})
	if status2.Code() != fwk.Success {
		t.Fatalf("Score (other-zone fixture) failed: %v", status2.Message())
	}

	if sameZoneScore <= otherZoneScore {
		t.Fatalf("Score did not forward CycleState's exact value to SetSourceContext: "+
			"same-zone fixture scored %d, other-zone fixture scored %d (expected same-zone strictly higher — "+
			"proves the CycleState value, not a stale/zero field, drove the weighted computation)",
			sameZoneScore, otherZoneScore)
	}
}

// fakeNMCReaderForInternal is a minimal client.Reader serving only NodeMigrationCapacity, used
// by TestAdapter_Score_ForwardsExactCycleStateValueToSetSourceContext.
type fakeNMCReaderForInternal struct {
	nmcs map[string]*v1alpha1.NodeMigrationCapacity
}

func (r *fakeNMCReaderForInternal) Get(_ context.Context, key types.NamespacedName, obj client.Object, _ ...client.GetOption) error {
	nmc, ok := r.nmcs[key.Name]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "nodemigrationcapacities"}, key.Name)
	}
	if target, ok := obj.(*v1alpha1.NodeMigrationCapacity); ok {
		*target = *nmc
	}
	return nil
}
func (r *fakeNMCReaderForInternal) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return nil
}

// testNodeInfo is a minimal fwk.NodeInfo whose only behavior used by the adapter is Node().
type testNodeInfo struct {
	fwk.NodeInfo
	node *corev1.Node
}

func (n testNodeInfo) Node() *corev1.Node { return n.node }
