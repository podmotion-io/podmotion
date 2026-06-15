/*
Copyright YEAR.

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

package ci

// flakedb.go — Flake database types and measurement functions.
// Canonical specification: ADR-0093 (formerly ADR-0079), §2.
//
// Run results are stored as append-only NDJSON in ci/flake-db/<cell-id>.ndjson.
// The DB is committed to the repo so flake history is visible in git log.
//
// Bootstrap gap policy: cells with fewer than ClearanceWindowSize (30) recorded
// runs return status "data-pending" and block ReadyForPromotion. This prevents
// a falsely-green gate on a newly-added cell that happens to have 0 failures.

import (
	"time"
)

// RunResult records one test result for one matrix cell.
// Serialised to ci/flake-db/<cell-id>.ndjson as NDJSON (one JSON object per line).
type RunResult struct {
	RunID      string    `json:"run_id"`
	CellID     string    `json:"cell_id"`    // "<kernel>/<cni>/<storage>/<k8s>"
	TestName   string    `json:"test_name"`  // Ginkgo full path
	Passed     bool      `json:"passed"`
	Timestamp  time.Time `json:"timestamp"`
	CommitSHA  string    `json:"commit_sha"`
	SeqDelta   int64     `json:"seq_delta,omitempty"`   // 0 = North Star satisfied
	DurationMs int64     `json:"duration_ms,omitempty"` // freeze window duration
}

// CellRunStatus indicates the data availability state for a cell.
type CellRunStatus string

const (
	// CellRunStatusDataPending is returned when fewer than ClearanceWindowSize
	// runs have been recorded. Per ADR-0093 bootstrap gap policy, this state
	// blocks ReadyForPromotion — insufficient data is treated as a blocking
	// condition, not as "OK so far."
	CellRunStatusDataPending CellRunStatus = "data-pending"

	// CellRunStatusOK is returned when at least ClearanceWindowSize runs exist
	// and the flake rate is within budget.
	CellRunStatusOK CellRunStatus = "ok"

	// CellRunStatusOverBudget is returned when flake_rate > 0.02 in the window.
	CellRunStatusOverBudget CellRunStatus = "over-budget"
)

// FlakeRate returns the flake rate for testName in cellID over the last windowSize runs.
//
// A flake is a run where the test passed on run N-1 and failed on run N (and
// is not a deterministic failure — i.e., it passes on re-run). Returns 0 when
// fewer than windowSize runs are recorded (insufficient data); callers should
// check CellStatus to distinguish "no data" from "clean."
//
// Per ADR-0093 §2.2:
//
//	flake_rate(T, C) = flaky_runs(T, C, window=windowSize) / windowSize
func FlakeRate(db []RunResult, cellID, testName string, windowSize int) float64 {
	// Filter to this cell and test, ordered chronologically (assumes db is
	// already time-ordered; append-only NDJSON guarantees this).
	var filtered []RunResult
	for _, r := range db {
		if r.CellID == cellID && r.TestName == testName {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) < windowSize {
		// Insufficient data — return 0 per spec; caller should check CellStatus.
		return 0
	}
	window := filtered[len(filtered)-windowSize:]

	flaky := 0
	for i := 1; i < len(window); i++ {
		prev := window[i-1]
		curr := window[i]
		// Flake: passed then failed (not two consecutive failures, which is a bug).
		if prev.Passed && !curr.Passed {
			// Check it's not deterministic: if the next run also failed, it's a bug.
			if i+1 < len(window) && !window[i+1].Passed {
				// Deterministic failure — not counted as a flake.
				continue
			}
			flaky++
		}
	}
	return float64(flaky) / float64(windowSize)
}

// CellStatus returns the data availability and budget status for a given cell
// and test name over the last windowSize runs in db.
func CellStatus(db []RunResult, cellID, testName string, windowSize int) CellRunStatus {
	var count int
	for _, r := range db {
		if r.CellID == cellID && r.TestName == testName {
			count++
		}
	}
	if count < windowSize {
		return CellRunStatusDataPending
	}
	rate := FlakeRate(db, cellID, testName, windowSize)
	if rate > 0.02 {
		return CellRunStatusOverBudget
	}
	return CellRunStatusOK
}

// ConsecutiveGreenStreak returns the length of the current consecutive green
// streak for a given cell across all test names. A run is green if every test
// in that run passed (or was quarantined). runIDs must be the ordered list of
// run IDs for this cell (oldest first).
//
// Returns -1 when the cell has fewer than RequiredConsecutiveGreenRuns recorded
// runs total (bootstrap gap policy → "data-pending").
func ConsecutiveGreenStreak(db []RunResult, cellID string, quarantined map[string]bool) int {
	// Collect distinct run IDs for this cell, in time order.
	runOrder := make([]string, 0)
	seen := make(map[string]bool)
	for _, r := range db {
		if r.CellID != cellID {
			continue
		}
		if !seen[r.RunID] {
			seen[r.RunID] = true
			runOrder = append(runOrder, r.RunID)
		}
	}
	if len(runOrder) < RequiredConsecutiveGreenRuns {
		return -1 // data-pending
	}

	// Build a map: runID → all results for that run in this cell.
	runResults := make(map[string][]RunResult)
	for _, r := range db {
		if r.CellID == cellID {
			runResults[r.RunID] = append(runResults[r.RunID], r)
		}
	}

	// Walk backwards from the most recent run, counting consecutive green runs.
	streak := 0
	for i := len(runOrder) - 1; i >= 0; i-- {
		runID := runOrder[i]
		green := true
		for _, r := range runResults[runID] {
			if !r.Passed && !quarantined[r.TestName] {
				green = false
				break
			}
		}
		if !green {
			break
		}
		streak++
	}
	return streak
}
