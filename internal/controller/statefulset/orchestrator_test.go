/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package statefulset

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func int32Ptr(i int32) *int32 { return &i }

func makeSTS(name string, replicas int32) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: int32Ptr(replicas),
		},
	}
}

// TestBuildMigrationPlan_QuorumSafety verifies that a 3-replica StatefulSet
// always plans a single migration at a time to preserve quorum.
func TestBuildMigrationPlan_QuorumSafety(t *testing.T) {
	sts := makeSTS("myapp", 3)
	// activeCount=3: quorumFloor=2, maxAllowed=1
	plan := BuildMigrationPlan(sts, 3)
	if plan.SafeParallelism != 1 {
		t.Errorf("expected SafeParallelism=1 for 3-replica set, got %d", plan.SafeParallelism)
	}
	if len(plan.Ordinals) != 3 {
		t.Errorf("expected 3 ordinals, got %d", len(plan.Ordinals))
	}
}

// TestBuildMigrationPlan_QuorumSafety_LargeSet verifies that a 5-replica set
// allows up to 2 non-adjacent migrations when enough members are active.
func TestBuildMigrationPlan_QuorumSafety_LargeSet(t *testing.T) {
	sts := makeSTS("myapp", 5)
	// activeCount=5: quorumFloor=3, maxAllowed=2
	// Ordinals in highest-first order: [4,3,2,1,0]
	// Non-adjacent selection: 4 (skip 3), 2 (skip 1) → selected=2
	plan := BuildMigrationPlan(sts, 5)
	if plan.SafeParallelism < 2 {
		t.Errorf("expected SafeParallelism>=2 for 5-replica set with 5 active, got %d", plan.SafeParallelism)
	}
}

// TestBuildMigrationPlan_AdjacentOrdinalPrevention verifies that adjacent ordinals
// are never selected together in the same batch.
func TestBuildMigrationPlan_AdjacentOrdinalPrevention(t *testing.T) {
	sts := makeSTS("myapp", 4)
	// activeCount=4: quorumFloor=3, maxAllowed=1
	plan := BuildMigrationPlan(sts, 4)

	// Verify no two selected ordinals in the first SafeParallelism slots are adjacent.
	selected := plan.Ordinals[:plan.SafeParallelism]
	for i := 0; i < len(selected); i++ {
		for j := i + 1; j < len(selected); j++ {
			diff := selected[i] - selected[j]
			if diff < 0 {
				diff = -diff
			}
			if diff == 1 {
				t.Errorf("adjacent ordinals %d and %d selected in same batch", selected[i], selected[j])
			}
		}
	}
}

// TestBuildMigrationPlan_HighestFirst verifies that the default order is highest ordinal first.
func TestBuildMigrationPlan_HighestFirst(t *testing.T) {
	sts := makeSTS("myapp", 3)
	plan := BuildMigrationPlan(sts, 3)
	if plan.Ordinals[0] != 2 {
		t.Errorf("expected first ordinal=2 (highest-first), got %d", plan.Ordinals[0])
	}
}

// TestBuildMigrationPlan_LowestFirstAnnotation verifies the operator override via annotation.
func TestBuildMigrationPlan_LowestFirstAnnotation(t *testing.T) {
	sts := makeSTS("myapp", 3)
	sts.Annotations = map[string]string{
		AnnotationOrdinalOrder: ordinalOrderLowestFirst,
	}
	plan := BuildMigrationPlan(sts, 3)
	if plan.Ordinals[0] != 0 {
		t.Errorf("expected first ordinal=0 (lowest-first), got %d", plan.Ordinals[0])
	}
}

// TestOrdinalFromPodName verifies parsing of StatefulSet pod names.
func TestOrdinalFromPodName(t *testing.T) {
	cases := []struct {
		name    string
		wantOrd int
		wantErr bool
	}{
		{"myapp-0", 0, false},
		{"myapp-5", 5, false},
		{"complex-name-with-dashes-12", 12, false},
		{"nohyphen", 0, true},
	}
	for _, tc := range cases {
		ord, err := OrdinalFromPodName(tc.name)
		if tc.wantErr {
			if err == nil {
				t.Errorf("OrdinalFromPodName(%q): expected error, got nil", tc.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("OrdinalFromPodName(%q): unexpected error: %v", tc.name, err)
			continue
		}
		if ord != tc.wantOrd {
			t.Errorf("OrdinalFromPodName(%q): got %d, want %d", tc.name, ord, tc.wantOrd)
		}
	}
}
