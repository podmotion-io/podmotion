/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/meta"
)

// conditionTrafficVerified mirrors the controller-package-local constant of the same name
// (podmigration_controller.go). Duplicated here as a literal because it is not otherwise
// exported from this package; kept in lockstep by the parity relationship documented on
// SourceTeardownBlockReason.
const conditionTrafficVerified = "TrafficVerified"

// SourceTeardownBlockReason is the SINGLE canonical STRICTER-union safety predicate that gates
// BOTH source-pod deletion (controller.deleteSourcePodIfSafe, via sourcePodDeletionBlockReason)
// and source-EndpointSlice removal (traffic.EndpointSliceManager.RemoveSourceIfVerified).
//
// Defined in this leaf package (imports only metav1 + apimachinery meta, no internal package)
// so that both controller and traffic — which must not import each other — can depend on it
// without an import cycle. Both call sites delegating to this one function is what makes their
// parity true BY CONSTRUCTION, rather than by hand-kept duplication.
//
// Semantics (locked to controller.go:1705-1723), across three groups:
//   - Strict:                DataplaneReachabilityVerified=True (ADR-0210 cross-node gate),
//     NOT TrafficVerified.
//   - BestEffort/None:       TrafficVerified=True (ADR-0012).
//   - Strict OR BestEffort:  additionally TCPSequenceContinuityVerified=True (ADR-0012).
//   - ALL modes (incl None): additionally WorkloadLivenessVerified=True (ADR-0325).
//
// Returns "" when the source pod/endpoint may be safely torn down, or a non-empty human-readable
// block reason otherwise.
func SourceTeardownBlockReason(mode TCPPreservationMode, conditions []metav1.Condition) string {
	// Reachability / traffic predicate (mode-dependent necessary predicate).
	if mode == TCPPreservationModeStrict {
		if !meta.IsStatusConditionTrue(conditions, ConditionDataplaneReachabilityVerified) {
			return "DataplaneReachabilityVerified is not True (ADR-0210 cross-node gate)"
		}
	} else if !meta.IsStatusConditionTrue(conditions, conditionTrafficVerified) {
		return "TrafficVerified is not True (ADR-0012)"
	}
	// TCP sequence-continuity predicate — REQUIRED for both Strict and BestEffort.
	if mode == TCPPreservationModeStrict || mode == TCPPreservationModeBestEffort {
		if !meta.IsStatusConditionTrue(conditions, ConditionTCPSequenceContinuityVerified) {
			return "TCPSequenceContinuityVerified is not True in Strict/BestEffort mode (ADR-0012)"
		}
	}
	// ADR-0325: additive predicate for ALL THREE modes, including None.
	if !meta.IsStatusConditionTrue(conditions, ConditionWorkloadLivenessVerified) {
		return "WorkloadLivenessVerified is not True (ADR-0325 real-liveness gate)"
	}
	return ""
}
