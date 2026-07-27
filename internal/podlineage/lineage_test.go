/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package podlineage

import (
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCanonicalBaseName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"never-migrated unchanged", "migration-demo-redis", "migration-demo-redis"},
		{"one migrate suffix stripped", "migration-demo-redis-m-f31c5423", "migration-demo-redis"},
		{"one recreate suffix stripped", "migration-demo-redis-r-f31c5423", "migration-demo-redis"},
		{"chained m then m fully stripped", "redis-m-aaaaaaaa-m-bbbbbbbb", "redis"},
		{"chained m then r fully stripped", "redis-m-aaaaaaaa-r-bbbbbbbb", "redis"},
		{"deep chain fully stripped", "redis-m-aaaaaaaa-r-bbbbbbbb-m-cccccccc", "redis"},
		// Organic name segments that merely resemble a tag are preserved: the trailing token is
		// neither 8 chars nor pure hex, so the heuristic does not over-strip.
		{"organic -m- not stripped (non-hex, wrong len)", "my-m-service", "my-m-service"},
		{"organic -r- not stripped (non-hex)", "web-r-frontend", "web-r-frontend"},
		{"hex but wrong length not stripped", "app-m-abc", "app-m-abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanonicalBaseName(tc.in); got != tc.want {
				t.Fatalf("CanonicalBaseName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDeterministicIncarnationName_NeverChains is the core regression: re-deriving a name from an
// ALREADY-suffixed predecessor name (as the old code did) would chain; deriving from the stable root
// (as callers now do) does not. It also proves fixed width and the 63-char clamp.
func TestDeterministicIncarnationName_NeverChains(t *testing.T) {
	root := "migration-demo-redis"

	gen1 := DeterministicIncarnationName(root, MigrateNameTag, "aaaaaaaa-1111-2222-3333-444444444444")
	if gen1 != root+"-m-aaaaaaaa" {
		t.Fatalf("gen1 = %q, want %q", gen1, root+"-m-aaaaaaaa")
	}

	// Second migration: the caller re-derives from the SAME root (recovered from the label), NOT
	// from gen1's name. A different migration UID -> a different, same-length name — never a chain.
	gen2 := DeterministicIncarnationName(root, MigrateNameTag, "bbbbbbbb-1111-2222-3333-444444444444")
	if gen2 != root+"-m-bbbbbbbb" {
		t.Fatalf("gen2 = %q, want %q", gen2, root+"-m-bbbbbbbb")
	}
	if len(gen1) != len(gen2) {
		t.Fatalf("names must be fixed-width across cycles: len(gen1)=%d len(gen2)=%d", len(gen1), len(gen2))
	}
	if strings.Count(gen2, "-m-") != 1 {
		t.Fatalf("gen2 %q chained a second -m- suffix", gen2)
	}

	// Contrast: had the caller (wrongly) fed the predecessor's already-suffixed name back in, it
	// WOULD chain — this asserts the root-derivation is what prevents it.
	chained := DeterministicIncarnationName(gen1, MigrateNameTag, "bbbbbbbb")
	if strings.Count(chained, "-m-") != 2 {
		t.Fatalf("sanity: feeding a suffixed name back in should chain, got %q", chained)
	}
	if CanonicalBaseName(chained) != root {
		t.Fatalf("CanonicalBaseName must recover root from a chained name, got %q", CanonicalBaseName(chained))
	}
}

func TestDeterministicIncarnationName_ClampsTo63(t *testing.T) {
	longRoot := strings.Repeat("a", 100)
	name := DeterministicIncarnationName(longRoot, RecreateNameTag, "f31c5423cafebabe")
	if len(name) != 63 {
		t.Fatalf("clamped name len = %d, want 63", len(name))
	}
	if !strings.HasSuffix(name, "-r-f31c5423") {
		t.Fatalf("clamp must preserve the full fixed-width suffix, got %q", name)
	}
}

func TestOriginalNameFromLabels(t *testing.T) {
	// Explicit label wins (root propagated forward).
	got := OriginalNameFromLabels(map[string]string{OriginalPodNameLabel: "redis"}, "redis-m-aaaaaaaa")
	if got != "redis" {
		t.Fatalf("label root = %q, want redis", got)
	}
	// No label -> canonicalize the current name (first-migration seed / legacy fallback).
	got = OriginalNameFromLabels(nil, "redis-m-aaaaaaaa")
	if got != "redis" {
		t.Fatalf("fallback root = %q, want redis", got)
	}
	got = OriginalNameFromLabels(map[string]string{}, "web-frontend")
	if got != "web-frontend" {
		t.Fatalf("never-migrated root = %q, want web-frontend", got)
	}
}

func TestGenerationFromLabels(t *testing.T) {
	if g := GenerationFromLabels(nil); g != 0 {
		t.Fatalf("nil labels gen = %d, want 0", g)
	}
	if g := GenerationFromLabels(map[string]string{GenerationLabel: "3"}); g != 3 {
		t.Fatalf("gen = %d, want 3", g)
	}
	if g := GenerationFromLabels(map[string]string{GenerationLabel: "garbage"}); g != 0 {
		t.Fatalf("unparseable gen = %d, want 0", g)
	}
	if g := GenerationFromLabels(map[string]string{GenerationLabel: "-2"}); g != 0 {
		t.Fatalf("negative gen = %d, want 0 (rejected)", g)
	}
}

func TestPodHelpers(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "redis-m-aaaaaaaa",
			Labels: map[string]string{
				OriginalPodNameLabel: "redis",
				GenerationLabel:      "2",
			},
		},
	}
	if got := OriginalPodName(pod); got != "redis" {
		t.Fatalf("OriginalPodName = %q, want redis", got)
	}
	if got := PodGeneration(pod); got != 2 {
		t.Fatalf("PodGeneration = %d, want 2", got)
	}
	if OriginalPodName(nil) != "" || PodGeneration(nil) != 0 {
		t.Fatalf("nil pod helpers must return zero values")
	}
}

func TestStampLabels_HappyPath(t *testing.T) {
	labels := map[string]string{}
	if err := StampLabels(labels, "redis", "redis-m-aaaaaaaa", "uid-123", 2); err != nil {
		t.Fatalf("StampLabels: %v", err)
	}
	if labels[OriginalPodNameLabel] != "redis" {
		t.Fatalf("original = %q", labels[OriginalPodNameLabel])
	}
	if labels[GenerationLabel] != strconv.Itoa(2) {
		t.Fatalf("generation = %q, want 2", labels[GenerationLabel])
	}
	if labels[PredecessorPodNameLabel] != "redis-m-aaaaaaaa" {
		t.Fatalf("predecessor name = %q", labels[PredecessorPodNameLabel])
	}
	if labels[PredecessorUIDLabel] != "uid-123" {
		t.Fatalf("predecessor uid = %q", labels[PredecessorUIDLabel])
	}
}

// TestStampLabels_FailsClosed proves lineage is never silently dropped: a nil map or an empty root
// is a real error the caller must propagate (abort the create), not a no-op.
func TestStampLabels_FailsClosed(t *testing.T) {
	if err := StampLabels(nil, "redis", "redis", "uid", 1); err == nil {
		t.Fatal("StampLabels(nil map) must error, not silently skip")
	}
	if err := StampLabels(map[string]string{}, "", "redis", "uid", 1); err == nil {
		t.Fatal("StampLabels(empty original) must error, not create an unrooted incarnation")
	}
}

// TestStampLabels_OmitsEmptyPredecessorFields: a snapshot-sourced recreate may lack a predecessor
// UID; it must not stamp an empty-valued label.
func TestStampLabels_OmitsEmptyPredecessorFields(t *testing.T) {
	labels := map[string]string{}
	if err := StampLabels(labels, "redis", "", "", 1); err != nil {
		t.Fatalf("StampLabels: %v", err)
	}
	if _, ok := labels[PredecessorPodNameLabel]; ok {
		t.Fatal("empty predecessor name must not be stamped")
	}
	if _, ok := labels[PredecessorUIDLabel]; ok {
		t.Fatal("empty predecessor uid must not be stamped")
	}
}
