/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestSourcePodDeletionBlockReasonDelegatesToSourceTeardownBlockReason is a drift-guard test
// (sign-off finding §C2 on ADR-0344): sourcePodDeletionBlockReason (this package) and
// pmv1.SourceTeardownBlockReason (api/v1alpha1/source_teardown.go) MUST be exactly one
// predicate. sourcePodDeletionBlockReason now delegates directly, so this test is a structural
// belt-and-suspenders guard against a future regression that re-inlines the predicate here and
// lets the two copies drift apart again — it exercises the full condition-set/mode combinatorics
// and asserts byte-for-byte identical results from both entry points.
func TestSourcePodDeletionBlockReasonDelegatesToSourceTeardownBlockReason(t *testing.T) {
	allConditions := []string{
		conditionDataplaneReachabilityVerified,
		conditionTrafficVerified,
		string(pmv1.ConditionTCPSequenceContinuityVerified),
		string(pmv1.ConditionWorkloadLivenessVerified),
	}
	modes := []pmv1.TCPPreservationMode{
		pmv1.TCPPreservationModeStrict,
		pmv1.TCPPreservationModeBestEffort,
		pmv1.TCPPreservationModeNone,
	}

	// Enumerate every subset of the 4 relevant conditions being True (16 combinations) x 3 modes.
	for mask := 0; mask < (1 << len(allConditions)); mask++ {
		var conditions []metav1.Condition
		for i, name := range allConditions {
			status := metav1.ConditionFalse
			if mask&(1<<i) != 0 {
				status = metav1.ConditionTrue
			}
			conditions = append(conditions, metav1.Condition{
				Type:   name,
				Status: status,
			})
		}

		for _, mode := range modes {
			got := sourcePodDeletionBlockReason(mode, conditions)
			want := pmv1.SourceTeardownBlockReason(mode, conditions)
			if got != want {
				t.Fatalf("mode=%v mask=%b: sourcePodDeletionBlockReason() = %q, pmv1.SourceTeardownBlockReason() = %q — predicates have drifted apart",
					mode, mask, got, want)
			}
		}
	}
}
