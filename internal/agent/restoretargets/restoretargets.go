// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

// Package restoretargets holds the ADR-0197 Rule D restore-target-container membership semantics.
//
// WHY THIS PACKAGE EXISTS (ADR-0421 D2c). The predicate used to live in internal/agent/nri as an
// unexported containerInList. ADR-0421 gives it a SECOND consumer — the gRPC destination-mount
// lookup in internal/agent/server — and a second copy of it is unacceptable: divergence between
// the NRI gate and the gRPC gate is the exact class of defect ADR-0421 D2 exists to close, since
// the two paths disagreeing about which container the restore targets IS the defect.
//
// Exporting it from internal/agent/nri would have worked mechanically and added no dependency
// edge, but it would put a TRANSPORT-NEUTRAL domain predicate in a package named for ONE specific
// transport, and make the gRPC fallback depend on the NRI plugin package for a semantic neither
// path owns. It also stops typechecking cleanly once the two inputs diverge in shape: after
// ADR-0421 D2a re-sourced the gRPC selector to replPod.Spec.Containers[].Name, the NRI side holds
// a csv ANNOTATION VALUE while the gRPC side holds a []string off the POD SPEC, so "reuse the csv
// predicate" would force the gRPC path to strings.Join a csv it already holds structurally —
// reconstructing a serialized form purely to fit a helper.
//
// This package therefore imports nothing from nri or server, so no cycle is possible and the
// semantic carries no transport in its name.
package restoretargets

import "strings"

// FromCSV parses an ADR-0197 Rule D restore-target-containers annotation value into a normalized
// name set: comma-split, whitespace-trimmed, and EMPTY ELEMENTS DROPPED.
//
// The "empty elements dropped" claim is load-bearing and is the reason this is a MOVE and not a
// rename. The predicate this replaces carried a doc comment claiming empty elements were ignored
// and it did NOT ignore them: containerInList("", "a,,b") returned true, because an empty csv
// element compares equal to an empty name. That was unreachable on the NRI path (an empty
// annotation short-circuits before the call, and joining DNS-1123 container names cannot produce
// an empty element), so it was a comment defect rather than a live bug. ADR-0421 makes the
// predicate load-bearing on a second path whose name source may be ABSENT on some substrate —
// which produces exactly the empty string — so the claim is made TRUE here rather than carried
// forward as a false comment.
func FromCSV(csv string) []string {
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Contains reports whether name is a member of targets. An empty name is never a member —
// an unnameable container is not evidence that it is the right one.
//
// That empty-name rejection is the SECOND guard, not the first. ADR-0421 D2b requires the caller
// to establish that a name is DETERMINABLE before calling this predicate at all, so an empty name
// should never reach here. Both exist deliberately: the caller's ordering rule is the control, and
// this check is the backstop that keeps the control from being the ONLY thing standing between a
// missing name source and a false membership match.
//
// The init container (podmotion-inject-holder) is excluded as a CONSEQUENCE of the allow-list,
// never by a hardcoded deny. That principle is ADR-0197's and is unchanged.
func Contains(name string, targets []string) bool {
	if name == "" {
		return false
	}
	for _, t := range targets {
		if t == name {
			return true
		}
	}
	return false
}
