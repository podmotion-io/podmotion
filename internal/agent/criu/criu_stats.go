/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package criu

// criu_stats.go — fail-closed phase-gate remediation (item 1a/1b), redesigned per
// ADR-Redesign (Real Dirty-Page Measurement for Pre-Copy Convergence, CRIU 4.2).
//
// CRIU 4.2's pre-dump/dump write a `stats-dump` protobuf image into the images directory
// UNCONDITIONALLY, on every invocation — no --stats/-S flag exists on this CRIU version (the
// prior --stats-based design was verified live to abort pre-dump outright: `criu: unrecognized
// option '--stats'`). pages_written in that image is the exact count of memory pages CRIU wrote
// for the round (byte-exact against the round's pages-N.img size; verified live against the KVM
// cluster's real CRIU 4.2 binary across two chained pre-dump rounds).
//
// This file decodes stats-dump via github.com/checkpoint-restore/go-criu/v7/stats
// (CriuGetDumpStats), an already-pinned dependency, IN-PROCESS — not a python3/pycriu
// subprocess. The node's system Python does not have pycriu importable (verified live: `python3
// -c "import pycriu"` -> ModuleNotFoundError on the cluster), so the previous subprocess-shellout
// design was a second, separate way this silently failed in production; the vendored pycriu tree
// remains only as an acceptance-test cross-check tool (internal/agent/server pycriu-based tests),
// never as production gate input.
//
// Fail-closed contract (unchanged, verbatim): decodeCRIUStats returns an error (never a
// fabricated 0) whenever the stats-dump image is missing, its magics don't match, or the
// protobuf fails to unmarshal — a genuine "0 dirty pages" measurement and "couldn't measure" are
// not the same fact, and the caller (PreDump) must be able to tell them apart.

import (
	"fmt"
	"os"

	"github.com/checkpoint-restore/go-criu/v7/stats"
)

// statsPageSizeBytes is the page size CRIU's dump_stats counts are reported in. CRIU always
// counts in the host's actual page size; 4096 is the universal default on the x86_64/arm64
// kernels this project targets (verified: no huge-page-backed workload path exists in this
// codebase today). If that ever changes, this constant is the single place to update.
const statsPageSizeBytes = 4096

// decodeCRIUStats reads the stats-dump image written into imagesDir by a just-completed
// pre-dump/dump round and returns the real dirty-page count in MB, decoded in-process via
// go-criu's stats.CriuGetDumpStats. It NEVER returns (0, nil) as a substitute for "couldn't
// measure" — any decode failure (missing file, magic mismatch, protobuf unmarshal error) is a
// returned error, so a caller cannot mistake "no signal" for "genuinely zero dirty pages"
// (fail-closed phase-gate).
func decodeCRIUStats(imagesDir string) (dirtyPagesMB int64, err error) {
	dir, openErr := os.Open(imagesDir)
	if openErr != nil {
		return 0, fmt.Errorf("decodeCRIUStats: open images dir %s: %w", imagesDir, openErr)
	}
	defer dir.Close()

	dumpStats, statsErr := stats.CriuGetDumpStats(dir)
	if statsErr != nil {
		return 0, fmt.Errorf("decodeCRIUStats: CriuGetDumpStats(%s): %w", imagesDir, statsErr)
	}
	if dumpStats == nil {
		// go-criu's StatsEntry carries dump_stats as an optional oneof-style field
		// (GetDump()); a stats-dump image that decodes but does not carry a dump_stats
		// payload (e.g. a stats-restore-only image misidentified) is exactly the
		// "couldn't measure" case, not a real zero.
		return 0, fmt.Errorf("decodeCRIUStats: %s: stats-dump image has no dump_stats payload", imagesDir)
	}

	pagesWritten := dumpStats.GetPagesWritten()
	bytesWritten := int64(pagesWritten) * statsPageSizeBytes
	return bytesWritten / (1024 * 1024), nil
}
