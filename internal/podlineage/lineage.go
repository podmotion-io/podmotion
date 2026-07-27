/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package podlineage centralizes how PodMotion names successor pods (the
// checkpoint-restore replacement pod and the cold-recreate rollback pod) and
// how it records the migration lineage of those pods.
//
// The single invariant this package exists to enforce: a successor pod name is
// ALWAYS derived from the STABLE ORIGINAL (root) pod name of the workload —
// never from whatever the immediate predecessor happened to be called. Before
// this package, both name-generation sites appended a per-migration suffix to
// the CURRENT source pod name, so migrating an already-migrated pod chained a
// second suffix onto the first ("redis-m-aaaa" -> "redis-m-aaaa-m-bbbb" -> ...),
// growing without bound across repeated cycles until the 63-char DNS-label clamp
// began lopping the ORIGINAL prefix off the LEFT. Deriving every incarnation's
// name from the root instead makes the name a fixed-width function of
// (rootName, migrationUID): repeated cycles produce "redis-m-aaaa", then
// "redis-m-bbbb", then "redis-m-cccc" — same length every time, never chaining.
//
// Lineage that USED to be readable only by parsing the accreted name string
// (which migration produced this incarnation, what it replaced, how deep in the
// chain it is) now lives in labels stamped by StampLabels, so no consumer ever
// has to parse a pod name to recover it.
package podlineage

import (
	"fmt"
	"regexp"
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

const (
	// OriginalPodNameLabel carries the STABLE original (root) pod name across an
	// entire migration/recreate chain. Every successor copies it verbatim from
	// its predecessor; the first successor of a never-migrated pod seeds it from
	// the canonicalized source pod name. Deterministic successor names are always
	// derived from THIS value, so they are bounded and never chain.
	OriginalPodNameLabel = "podmotion.io/original-pod-name"

	// GenerationLabel counts how many migration/recreate cycles deep an
	// incarnation is. The original pod is generation 0 (and carries no label);
	// the first successor is 1, and each subsequent successor is predecessor+1.
	GenerationLabel = "podmotion.io/lineage-generation"

	// PredecessorPodNameLabel is the name of the immediate pod this incarnation
	// replaced. Consumers that need to find "the pod that superseded X" match on
	// this label instead of parsing successor names.
	PredecessorPodNameLabel = "podmotion.io/predecessor-pod-name"

	// PredecessorUIDLabel is the UID of the immediate pod this incarnation
	// replaced (empty-string predecessor UIDs are not stamped).
	PredecessorUIDLabel = "podmotion.io/predecessor-uid"
)

const (
	// MigrateNameTag is the fixed separator for a checkpoint-restore replacement
	// pod name: <root>-m-<shortUID>. Historically documented as the "-m-" suffix.
	MigrateNameTag = "-m-"

	// RecreateNameTag is the fixed separator for a cold-recreate rollback pod
	// name: <root>-r-<shortUID>. Deliberately distinct from MigrateNameTag so the
	// two pod classes never collide on a name. Historically the "-r-" suffix.
	RecreateNameTag = "-r-"
)

// shortUIDLen is how many leading characters of a migration UID form the
// name/label discriminator. A Kubernetes UID is a RFC-4122 UUID whose first 8
// characters are always lowercase hex (the time-low field, before the first
// hyphen), which is what chainedSuffixRe keys on.
const shortUIDLen = 8

// chainedSuffixRe matches ONE trailing PodMotion successor suffix: a "-m-" or
// "-r-" tag followed by exactly the 8 lowercase-hex characters a shortened
// migration UID contributes. Requiring exactly 8 hex chars (not any token) keeps
// CanonicalBaseName from mis-stripping an organic name segment that merely
// happens to contain "-m-" (e.g. "my-m-service" — "service" is neither 8 chars
// nor hex, so it is preserved).
var chainedSuffixRe = regexp.MustCompile(`(-m-|-r-)[0-9a-f]{8}$`)

// CanonicalBaseName recovers the root workload name from a pod name that may
// already carry one or more accreted PodMotion successor suffixes, stripping
// them right-to-left until none remain. It is the FALLBACK root source used only
// when a pod does not carry OriginalPodNameLabel (a legacy pod created before
// lineage labels existed, whose name is the only surviving record of its
// chain); pods stamped by StampLabels carry the root explicitly and never need
// it. For a never-migrated pod the name is returned unchanged.
func CanonicalBaseName(name string) string {
	for {
		trimmed := chainedSuffixRe.ReplaceAllString(name, "")
		if trimmed == name {
			return name
		}
		name = trimmed
	}
}

// OriginalNameFromLabels returns the stable root name for a workload given a
// predecessor's label set and current name: the explicitly-propagated
// OriginalPodNameLabel when present, otherwise the canonicalized current name
// (first-migration seed / legacy fallback).
func OriginalNameFromLabels(labels map[string]string, currentName string) string {
	if labels != nil {
		if v := labels[OriginalPodNameLabel]; v != "" {
			return v
		}
	}
	return CanonicalBaseName(currentName)
}

// OriginalPodName is OriginalNameFromLabels applied to a live pod object.
func OriginalPodName(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	return OriginalNameFromLabels(pod.Labels, pod.Name)
}

// GenerationFromLabels returns the lineage generation recorded in a predecessor's
// label set, or 0 when absent/unpariseable (the original pod is generation 0).
func GenerationFromLabels(labels map[string]string) int {
	if labels != nil {
		if v := labels[GenerationLabel]; v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				return n
			}
		}
	}
	return 0
}

// PodGeneration is GenerationFromLabels applied to a live pod object.
func PodGeneration(pod *corev1.Pod) int {
	if pod == nil {
		return 0
	}
	return GenerationFromLabels(pod.Labels)
}

// DeterministicIncarnationName builds a successor pod name as
// <base><tag><shortUID>, clamping base from the LEFT only as far as needed to
// keep the whole name within the 63-char DNS-label limit. Because base is the
// STABLE root (not the predecessor's already-suffixed name) and the suffix is
// fixed-width, the result is the same length on every cycle and never chains.
// tag must be MigrateNameTag or RecreateNameTag; uid is a full migration UID (it
// is shortened here).
func DeterministicIncarnationName(base, tag, uid string) string {
	if len(uid) > shortUIDLen {
		uid = uid[:shortUIDLen]
	}
	suffix := tag + uid
	if maxBase := 63 - len(suffix); len(base) > maxBase {
		base = base[:maxBase]
	}
	return base + suffix
}

// StampLabels writes the lineage labels onto a successor pod's label map. It
// fails CLOSED: a nil map or an empty original name — either of which would
// leave the successor without a reconstructable root/lineage — is a real error,
// never a silent skip, so the caller aborts rather than create an unrooted pod.
// predecessorName/predecessorUID are stamped only when non-empty (a live
// predecessor always has both; a snapshot-sourced recreate may omit the UID).
func StampLabels(labels map[string]string, originalName, predecessorName, predecessorUID string, generation int) error {
	if labels == nil {
		return fmt.Errorf("podlineage: nil label map — cannot stamp lineage")
	}
	if originalName == "" {
		return fmt.Errorf("podlineage: empty original pod name — refusing to create an unrooted incarnation")
	}
	labels[OriginalPodNameLabel] = originalName
	labels[GenerationLabel] = strconv.Itoa(generation)
	if predecessorName != "" {
		labels[PredecessorPodNameLabel] = predecessorName
	}
	if predecessorUID != "" {
		labels[PredecessorUIDLabel] = predecessorUID
	}
	return nil
}
