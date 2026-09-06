/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0425_scratch_script_test.go — ADR-0425 §P-VERIFY assertion 1: the concurrent-invocation
// collision test.
//
// Round 3's fix (createScratchScript, os.CreateTemp under /dev/shm) takes no caller-supplied
// uniqueness argument at all, so the correct, harder test holds every input identical across all
// N concurrent goroutines per call site — this is what actually exercises the "same migration,
// same name, same everything, still concurrent" shape from round 2 finding (b). A test that varied
// a migrationName-equivalent per goroutine would not cover that shape.
//
// One sync.Map per call-site pattern, keyed by the returned scriptPath, LoadOrStore-checked for a
// second writer landing on a path already claimed by another goroutine in the same run.

import (
	"os"
	"sync"
	"testing"
)

// TestCreateScratchScript_ConcurrentInvocations_NoPathCollision is ADR-0425 §P-VERIFY assertion 1.
//
// It exercises createScratchScript directly (rather than the three higher-level functions, which
// require python3/pycriu and real checkpoint image fixtures) with each of the three real patterns
// those functions pass in production — "pm-patch-ckpt-*.py", "pm-devshm-scan-*.py", and
// "pm-scan-mounts-*.py" — since createScratchScript is exactly where §Scope factored the fix, and
// this is the seam the ADR names as an acceptable substitute for the real function when python3 is
// unavailable in the test environment.
func TestCreateScratchScript_ConcurrentInvocations_NoPathCollision(t *testing.T) {
	const n = 200 // >= the ADR's N >= 50 floor

	patterns := []string{
		"pm-patch-ckpt-*.py",
		"pm-devshm-scan-*.py",
		"pm-scan-mounts-*.py",
	}

	for _, pattern := range patterns {
		pattern := pattern
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()

			var seen sync.Map // scriptPath -> struct{}
			var wg sync.WaitGroup
			errs := make([]error, n)
			paths := make([]string, n)

			// Every goroutine calls createScratchScript with IDENTICAL arguments — same pattern,
			// same content string, nothing varied — per the ADR's corrected assertion 1: holding
			// every argument identical across all N goroutines is the harder, correct test, since
			// round 3's fix derives uniqueness from os.CreateTemp alone, never from any
			// caller-supplied identifier.
			const content = "# identical content for every concurrent invocation\n"

			for i := 0; i < n; i++ {
				i := i
				wg.Add(1)
				go func() {
					defer wg.Done()
					path, err := createScratchScript(pattern, content)
					paths[i] = path
					errs[i] = err
				}()
			}
			wg.Wait()

			// Clean up every successfully created scratch file regardless of test outcome.
			defer func() {
				for _, p := range paths {
					if p != "" {
						_ = os.Remove(p)
					}
				}
			}()

			for i, err := range errs {
				if err != nil {
					t.Fatalf("goroutine %d: createScratchScript(%q) returned error: %v", i, pattern, err)
				}
			}

			for i, p := range paths {
				if p == "" {
					t.Fatalf("goroutine %d: createScratchScript(%q) returned empty path with nil error", i, pattern)
				}
				if _, loaded := seen.LoadOrStore(p, struct{}{}); loaded {
					t.Fatalf("pattern %q: goroutine %d landed on scriptPath %q already claimed by another concurrent invocation — collision", pattern, i, p)
				}
			}
		})
	}
}
