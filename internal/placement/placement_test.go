/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package placement_test

// placement_test.go is a direct smoke test for the ADR-0365 packaging extraction: proves
// internal/placement's Filter/Score preserve the exact semantics filter.go/score.go had before
// being moved out from behind the `scheduler` build tag — this package has no build tag, so it
// is the one place both the controller (ADR-0365's early-decision step) and the scheduler-plugins wrapper
// import from, and it must not silently diverge from either caller's expectations.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/placement"
)

func placementScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := pmv1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	return s
}

func TestFilter_UnlabeledPod_RejectsNotReadyAndDrainedNodes_AllowsHealthy(t *testing.T) {
	scheme := placementScheme(t)
	readyNMC := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "node-healthy"},
		Spec:       pmv1.NodeMigrationCapacitySpec{CRIUVersion: "4.2", MaxConcurrentMigrationsDestination: 3},
		Status:     pmv1.NodeMigrationCapacityStatus{Ready: true, ActiveDestinationMigrations: 0},
	}
	notReadyNMC := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "node-notready"},
		Spec:       pmv1.NodeMigrationCapacitySpec{CRIUVersion: "4.2", MaxConcurrentMigrationsDestination: 3},
		Status:     pmv1.NodeMigrationCapacityStatus{Ready: false},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(readyNMC, notReadyNMC).Build()

	f := placement.NewMigrationAwareFilter(c, scheme)
	pod := &corev1.Pod{} // unlabeled — standard NMC-readiness path, not the migration-label fast path

	healthyNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-healthy"}}
	if res := f.Filter(context.Background(), pod, healthyNode); !res.Allowed {
		t.Errorf("expected node-healthy to be Allowed, got rejected: %s", res.Reason)
	}

	notReadyNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-notready"}}
	if res := f.Filter(context.Background(), pod, notReadyNode); res.Allowed {
		t.Errorf("expected node-notready to be rejected (NMC.status.ready=false)")
	}

	drainedNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-healthy", Labels: map[string]string{placement.LabelDraining: "true"}},
	}
	if res := f.Filter(context.Background(), pod, drainedNode); res.Allowed {
		t.Errorf("expected a drain-labeled node to be rejected even with a Ready NMC")
	}
}

func TestScore_LocalityAndCapacity_PreferSameZoneAndLessLoaded(t *testing.T) {
	scheme := placementScheme(t)
	lightNMC := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "node-light"},
		Spec:       pmv1.NodeMigrationCapacitySpec{MaxConcurrentMigrationsDestination: 10},
		Status:     pmv1.NodeMigrationCapacityStatus{ActiveDestinationMigrations: 0},
	}
	heavyNMC := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "node-heavy"},
		Spec:       pmv1.NodeMigrationCapacitySpec{MaxConcurrentMigrationsDestination: 10},
		Status:     pmv1.NodeMigrationCapacityStatus{ActiveDestinationMigrations: 9},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lightNMC, heavyNMC).Build()

	s := placement.NewMigrationAwareScore(c, placement.DefaultWeights)
	s.SetSourceContext(map[string]string{"topology.kubernetes.io/zone": "zone-a"}, 0)
	pod := &corev1.Pod{}

	lightNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-light", Labels: map[string]string{"topology.kubernetes.io/zone": "zone-a"}}}
	heavyNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-heavy", Labels: map[string]string{"topology.kubernetes.io/zone": "zone-b"}}}

	lightScore, err := s.Score(context.Background(), pod, lightNode)
	if err != nil {
		t.Fatalf("Score(node-light): %v", err)
	}
	heavyScore, err := s.Score(context.Background(), pod, heavyNode)
	if err != nil {
		t.Fatalf("Score(node-heavy): %v", err)
	}
	if lightScore <= heavyScore {
		t.Fatalf("expected the same-zone, lightly-loaded node to outscore the cross-zone, heavily-loaded one: light=%d heavy=%d",
			lightScore, heavyScore)
	}
}

func TestFilter_MigrationLabelFastPath_OnlyAllowsPreDesignatedDestination(t *testing.T) {
	scheme := placementScheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-1", Namespace: "default"},
		Status:     pmv1.PodMigrationStatus{DestinationNodeName: "node-b"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).Build()
	f := placement.NewMigrationAwareFilter(c, scheme)

	replPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Labels: map[string]string{"podmotion.io/migration-name": "mig-1"}},
	}

	nodeB := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b"}}
	if res := f.Filter(context.Background(), replPod, nodeB); !res.Allowed {
		t.Errorf("expected the pre-designated destination node-b to be Allowed, got: %s", res.Reason)
	}

	nodeC := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-c"}}
	if res := f.Filter(context.Background(), replPod, nodeC); res.Allowed {
		t.Errorf("expected a non-pre-designated node to be rejected on the migration-label fast path")
	}
}
