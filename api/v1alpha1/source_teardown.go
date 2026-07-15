/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
//   - Strict:                ServiceContinuityVerified=True (ADR-0352 Service-continuity gate),
//     NOT TrafficVerified.
//   - BestEffort/None:       TrafficVerified=True (ADR-0012).
//   - Strict OR BestEffort:  additionally TCPSequenceContinuityVerified=True (ADR-0012).
//   - ALL modes (incl None): additionally WorkloadLivenessVerified=True (ADR-0325).
//   - ANY mode, if armed:    additionally ZeroWindowDisarmed=True whenever ZeroWindowArmed=True —
//     the source zero-window hold must be confirmed disarmed before teardown, so a still-frozen
//     source socket cannot be deleted on a vacuous seq_delta==0 completion (ADR-0049/ADR-0157,
//     invariant #1). Vacuously satisfied when the hold was never armed.
//
// Returns "" when the source pod/endpoint may be safely torn down, or a non-empty human-readable
// block reason otherwise.
func SourceTeardownBlockReason(mode TCPPreservationMode, conditions []metav1.Condition) string {
	// SECURITY — split-brain fail-closed veto (Security Reviewer, sprint46B3 live-proof cycle-2
	// finding; re-keyed ADR-0352 D2.2/D2.2a). DataplaneReachabilityVerified was the AUTHORITATIVE
	// cross-node "the destination actually answers on the preserved IP" truth (controller-issued
	// nonce round-trip / CiliumEndpoint read) — pod-IP-preservation reachability. ADR-0352 supersedes
	// that as the Strict-path truth (see the Strict branch below, now keyed on ServiceContinuityVerified
	// — EndpointSlice-Ready enrollment + a real Service ClusterIP round-trip, NOT preserved-IP
	// reachability): a replacement with a DIFFERENT IP/MAC is fully Service-continuous the instant it
	// is a Ready EndpointSlice member and the ClusterIP load-balances to it (Kubernetes Service
	// semantics), so pod-IP preservation is no longer the correctness signal for Strict.
	//
	// This veto itself is RETAINED VERBATIM (ADR-0352 D2.2 option b) as the split-brain guard for
	// BestEffort/None only: DataplaneReachabilityVerified's two producers (tryEstablishCiliumData-
	// planeReachability, verifyDataplaneReachability) are retired from the Strict completion path
	// (ADR-0352 D3) but remain live for BestEffort/None (reconcileVerifying), where TrafficVerified
	// (below) can still be a false positive on mere IP-handoff INSTALL (reason=HandoffInstalled) while
	// the destination is affirmatively unreachable — the original live-proof c2 split-brain this veto
	// was authored against. Keyed on present-and-explicitly-False, NOT !True: an ABSENT or Unknown
	// condition does not veto (a not-yet-run probe must not block BestEffort/None).
	if c := meta.FindStatusCondition(conditions, ConditionDataplaneReachabilityVerified); c != nil && c.Status == metav1.ConditionFalse {
		return "DataplaneReachabilityVerified is explicitly False — destination affirmatively unreachable; source teardown blocked (non-Strict split-brain guard, ADR-0210/ADR-0012/ADR-0352, invariant #1)"
	}
	// ADR-0352 D2.2 option (b): a SEPARATE Strict-only veto, mirroring the shape of the veto above,
	// keyed on the NEW authoritative condition. ServiceContinuityVerified is Strict-only-produced
	// (ADR-0352 D1), so it cannot simply replace the cross-mode veto above without silently dropping
	// the split-brain guard for BestEffort/None (ADR-0352 D2.2b) — hence two live vetoes, one per
	// condition family, until a future ADR unifies BestEffort/None onto ServiceContinuityVerified too.
	if mode == TCPPreservationModeStrict {
		if c := meta.FindStatusCondition(conditions, ConditionServiceContinuityVerified); c != nil && c.Status == metav1.ConditionFalse {
			return "ServiceContinuityVerified is explicitly False — replacement affirmatively not Service-continuous; source teardown blocked to prevent split-brain (ADR-0352, invariant #1)"
		}
	}
	// SECURITY — fail-closed zero-window disarm predicate (Security Reviewer; ADR-0352 Strict
	// teardown re-key). Authoritative primitive replacing a control-flow-reachability defense:
	// the controller routes Strict onto the DisengageHold spine so the source zero-window hold
	// is disarmed (DisarmZeroWindow) before TCP verification, but a process exit that persists
	// phase=TCPVerifying can dispatch straight to reconcileTCPVerifying and BYPASS
	// reconcileDisengageHold — the only phase that disarms the hold. VerifyTCP then measures a
	// still-FROZEN source socket, seq_delta==0 satisfies the Strict TCP-continuity gate
	// VACUOUSLY, and the source pod is deleted with the hold never disarmed: a live connection
	// silently severed while we report continuity (invariant #1 / ADR-0012). Routing alone keys
	// safety on control-flow reachability, which a crash-persisted phase can evade. The
	// authoritative truth already exists as status write-backs: ConditionZeroWindowArmed is set
	// on every arm, and ConditionZeroWindowDisarmed on EVERY disarm path — success
	// (reconcileDisengageHold) AND failure (disarmZeroWindowOnFailurePath), including the
	// watchdog backstop (reason=WatchdogFired). Reading them here makes teardown fail CLOSED
	// regardless of routing: if the hold was ever armed it MUST be confirmed disarmed before the
	// source may be torn down. Keyed on ZeroWindowArmed==True as the antecedent (NOT on mode) so
	// a workload/mode that never arms the hold (None, or a migration that failed before
	// ZeroWindowArm) leaves the antecedent False and is never false-blocked — the same
	// armed-implies-must-disarm invariant disarmZeroWindowOnFailurePath already enforces, lifted
	// into the single canonical teardown gate so it also holds on the success path.
	if meta.IsStatusConditionTrue(conditions, ConditionZeroWindowArmed) &&
		!meta.IsStatusConditionTrue(conditions, ConditionZeroWindowDisarmed) {
		return "ZeroWindowArmed=True but ZeroWindowDisarmed is not True — source zero-window hold not confirmed disarmed; source teardown blocked to prevent deleting a still-frozen source socket on a vacuous seq_delta==0 completion (ADR-0049/ADR-0157/ADR-0352, invariant #1)"
	}
	// Reachability / traffic predicate (mode-dependent necessary predicate).
	if mode == TCPPreservationModeStrict {
		if !meta.IsStatusConditionTrue(conditions, ConditionServiceContinuityVerified) {
			return "ServiceContinuityVerified is not True (ADR-0352 Service-continuity gate)"
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
