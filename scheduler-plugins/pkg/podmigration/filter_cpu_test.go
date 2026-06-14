//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package podmigration_test

// filter_cpu_test.go is the §14b exit-criterion test for ADR-0153
// (CPU Feature Migration Compatibility Gate).
//
// It encodes the compatibility predicate defined in ADR-0153 §2:
//
//   1. Tier check (necessary): tierRank(dest.Baseline) >= tierRank(source.Baseline).
//   2. Exact-set check: identical fingerprint passes; otherwise every source flag
//      must be present on the destination (source.Flags ⊆ dest.Flags).
//   3. Fail-closed: an unknown (empty) source or destination profile is rejected.
//
// The canonical failure this test pins down: a Skylake-sourced pod (x86-64-v4,
// advertising avx512f) targeting a Haswell node (x86-64-v3, no avx512f) MUST be
// rejected — restoring such a checkpoint risks SIGILL on the first AVX-512
// instruction. Skylake is modeled at v4 (Skylake-SP/Server class with AVX-512);
// Haswell tops out at AVX2 (v3).
//
// When Sprint 32 lands the production cpuFeatureCompatible predicate on the
// scheduler filter, the local helper below is replaced by a call into that
// implementation; the assertions are the normative contract and must not change.

import (
	"sort"
	"testing"
)

// cpuProfile mirrors the ADR-0153 CPUFeature advertisement (NMC spec field +
// node labels): a named psABI baseline tier plus the canonical sorted flag set
// and its fingerprint.
type cpuProfile struct {
	baseline    string // "x86-64-v1".."x86-64-v4"; "" = unknown
	fingerprint string // sha256 of sorted flags (modeled here as a sentinel)
	flags       []string
}

// tierRank ranks the x86-64 psABI micro-architecture levels. Unknown ("") ranks
// below v1 so it can never satisfy any real source tier (fail-closed input).
func tierRank(baseline string) int {
	switch baseline {
	case "x86-64-v1":
		return 1
	case "x86-64-v2":
		return 2
	case "x86-64-v3":
		return 3
	case "x86-64-v4":
		return 4
	default:
		return 0
	}
}

func flagSet(flags []string) map[string]struct{} {
	m := make(map[string]struct{}, len(flags))
	for _, f := range flags {
		m[f] = struct{}{}
	}
	return m
}

// cpuFeatureCompatible implements ADR-0153 §2. Returns false (reject) when the
// destination cannot prove it can safely run a checkpoint taken on the source.
func cpuFeatureCompatible(source, dest cpuProfile) bool {
	// (3) Fail-closed: unknown provenance on either side is never auto-approved.
	if source.baseline == "" || dest.baseline == "" {
		return false
	}
	// (1) Tier check (necessary).
	if tierRank(dest.baseline) < tierRank(source.baseline) {
		return false
	}
	// (2) Exact-set short-circuit, else subset containment.
	if source.fingerprint != "" && source.fingerprint == dest.fingerprint {
		return true
	}
	destFlags := flagSet(dest.flags)
	for _, sf := range source.flags {
		if _, ok := destFlags[sf]; !ok {
			return false
		}
	}
	return true
}

func skylakeProfile() cpuProfile {
	flags := []string{
		"sse4_2", "popcnt", "avx", "avx2", "bmi1", "bmi2", "fma",
		"avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl",
		"aes", "sha_ni",
	}
	sort.Strings(flags)
	return cpuProfile{baseline: "x86-64-v4", fingerprint: "sha256-skylake0001", flags: flags}
}

func haswellProfile() cpuProfile {
	flags := []string{
		"sse4_2", "popcnt", "avx", "avx2", "bmi1", "bmi2", "fma", "aes",
		// NOTE: no avx512*, no sha_ni — Haswell tops out at AVX2 (x86-64-v3).
	}
	sort.Strings(flags)
	return cpuProfile{baseline: "x86-64-v3", fingerprint: "sha256-haswell0001", flags: flags}
}

// TestCPUCompat_SkylakeSourceToHaswellDest_Rejected is the headline §14b assertion.
func TestCPUCompat_SkylakeSourceToHaswellDest_Rejected(t *testing.T) {
	source := skylakeProfile()
	dest := haswellProfile()
	if cpuFeatureCompatible(source, dest) {
		t.Fatalf("ADR-0153 violation: Skylake (x86-64-v4, avx512f) source restored on "+
			"Haswell (x86-64-v3, no avx512f) destination must be REJECTED to prevent SIGILL; "+
			"got allowed. source=%v dest=%v", source, dest)
	}
}

// TestCPUCompat_SafeWideningAllowed: source narrower than (subset of) destination passes.
func TestCPUCompat_SafeWideningAllowed(t *testing.T) {
	source := haswellProfile() // v3
	dest := skylakeProfile()   // v4, superset of Haswell flags
	if !cpuFeatureCompatible(source, dest) {
		t.Fatalf("expected safe widening Haswell->Skylake to be ALLOWED; got rejected")
	}
}

// TestCPUCompat_IdenticalFingerprintAllowed: same silicon always passes.
func TestCPUCompat_IdenticalFingerprintAllowed(t *testing.T) {
	source := skylakeProfile()
	dest := skylakeProfile()
	if !cpuFeatureCompatible(source, dest) {
		t.Fatalf("expected identical CPU profile to be ALLOWED; got rejected")
	}
}

// TestCPUCompat_UnknownProfileFailsClosed: missing provenance is never auto-approved.
func TestCPUCompat_UnknownProfileFailsClosed(t *testing.T) {
	known := skylakeProfile()
	unknown := cpuProfile{} // empty baseline = unknown
	if cpuFeatureCompatible(known, unknown) {
		t.Fatalf("expected unknown DESTINATION profile to fail closed; got allowed")
	}
	if cpuFeatureCompatible(unknown, known) {
		t.Fatalf("expected unknown SOURCE profile to fail closed; got allowed")
	}
}

// TestCPUCompat_SameTierMissingSubFlagRejected: equal psABI tier is not sufficient
// when a sub-tier extension (e.g. sha_ni) present on source is absent on dest.
func TestCPUCompat_SameTierMissingSubFlagRejected(t *testing.T) {
	source := cpuProfile{
		baseline:    "x86-64-v3",
		fingerprint: "sha256-src-shani",
		flags:       []string{"sse4_2", "avx2", "bmi2", "fma", "sha_ni"},
	}
	dest := cpuProfile{
		baseline:    "x86-64-v3",
		fingerprint: "sha256-dst-noshani",
		flags:       []string{"sse4_2", "avx2", "bmi2", "fma"}, // no sha_ni
	}
	if cpuFeatureCompatible(source, dest) {
		t.Fatalf("ADR-0153 §2: same tier but missing sha_ni on destination must be REJECTED; got allowed")
	}
}
