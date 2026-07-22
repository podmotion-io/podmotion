/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package criu

// criu_stats.go — fail-closed phase-gate remediation (item 1a/1b). PreDump previously always returned
// DirtyPagesMB: 0 unconditionally ("stats file parsing not yet implemented"), which made
// EstimateCheckpoint's "success" branch just as fabricated as its error-fallback branch (both
// synthesized numbers from nothing real). CRIU's own --stats output (a stats-dump image written
// into ImagesDir on a successful pre-dump/dump) already carries the real dirty-page accounting;
// this file decodes it via the same vendored-pycriu subprocess pattern already proven in this
// codebase (internal/agent/server/shmem_pagemap_guard.go, patch_checkpoint_script.go) rather than
// inventing a new CRIU-image parsing mechanism.
//
// Fail-closed contract: decodeCRIUStats returns an error (never a fabricated 0) whenever the
// stats image is missing, unreadable, or does not carry the expected dump_stats fields — a
// genuine "0 dirty pages" measurement and "couldn't measure" are not the same fact, and the
// caller (PreDump) must be able to tell them apart.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// pycriuPythonPath is the PYTHONPATH entry used to import the vendored pycriu package. Mirrors
// the identically-named var in internal/agent/server/shmem_pagemap_guard.go — kept as a separate
// package-local var (not shared) to avoid an inter-package coupling for what is otherwise an
// independent decode; tests in this package point it at the in-repo pycriu/ tree.
var pycriuPythonPath = "/usr/lib/python3/dist-packages"

// statsPageSizeBytes is the page size CRIU's dump_stats counts are reported in. CRIU always
// counts in the host's actual page size; 4096 is the universal default on the x86_64/arm64
// kernels this project targets (verified: no huge-page-backed workload path exists in this
// codebase today). If that ever changes, this constant is the single place to update.
const statsPageSizeBytes = 4096

// criuStatsScanScript decodes CRIU's stats-dump (or stats-restore) protobuf image via pycriu and
// emits the JSON-encoded pages_written count (the real number of dirty/written pages CRIU
// recorded for this dump/pre-dump round). CRIU's stats.proto dump_stats message field names are
// stable across the 3.x/4.x series (pages_scanned, pages_skipped_parent, pages_written,
// pages_wrote). pages_written is the count of pages actually written into this round's page
// images — i.e. the real "dirty since last round" measurement EstimateCheckpoint needs.
const criuStatsScanScript = `
import pycriu, glob, json, sys

candidates = glob.glob(sys.argv[1] + '/stats-dump') + glob.glob(sys.argv[1] + '/stats-restore')
if not candidates:
    print(json.dumps({"error": "no stats image found"}))
    sys.exit(0)

with open(candidates[0], 'rb') as f:
    data = pycriu.images.load(f)

pages_written = None
for entry in data.get('entries', []):
    d = entry.get('dump', {})
    if 'pages_written' in d:
        pages_written = d['pages_written']
        break

if pages_written is None:
    print(json.dumps({"error": "pages_written field not present in stats image"}))
    sys.exit(0)

print(json.dumps({"pages_written": pages_written}))
`

// criuStatsResult mirrors the JSON emitted by criuStatsScanScript.
type criuStatsResult struct {
	PagesWritten *int64 `json:"pages_written"`
	Error        string `json:"error"`
}

// decodeCRIUStats reads the CRIU --stats image written into imagesDir by a just-completed
// pre-dump/dump round and returns the real dirty-page count in MB. It NEVER returns (0, nil) as
// a substitute for "couldn't measure" — any decode failure is a returned error, so a caller
// cannot mistake "no signal" for "genuinely zero dirty pages" (fail-closed phase-gate).
func decodeCRIUStats(imagesDir string) (dirtyPagesMB int64, err error) {
	scriptPath := filepath.Join(imagesDir, ".pm-scan-stats.py")
	if writeErr := os.WriteFile(scriptPath, []byte(criuStatsScanScript), 0o600); writeErr != nil {
		return 0, fmt.Errorf("decodeCRIUStats: write scan script: %w", writeErr)
	}
	defer func() {
		// Same zeroize-then-remove treatment as every other transient artifact this codebase
		// places on tmpfs imagesDir (shmem_pagemap_guard.go), even though this script itself
		// carries no tenant memory content.
		if info, statErr := os.Stat(scriptPath); statErr == nil {
			zeros := make([]byte, info.Size())
			_ = os.WriteFile(scriptPath, zeros, 0o600)
		}
		_ = os.Remove(scriptPath)
	}()

	cmd := exec.Command("python3", scriptPath, imagesDir)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pycriuPythonPath)
	out, runErr := cmd.Output()
	if runErr != nil {
		return 0, fmt.Errorf("decodeCRIUStats: stats scan script failed: %w\n%s", runErr, out)
	}

	var res criuStatsResult
	if jsonErr := json.Unmarshal(out, &res); jsonErr != nil {
		return 0, fmt.Errorf("decodeCRIUStats: parse scan output: %w\n%s", jsonErr, out)
	}
	if res.Error != "" {
		return 0, fmt.Errorf("decodeCRIUStats: %s", res.Error)
	}
	if res.PagesWritten == nil {
		return 0, fmt.Errorf("decodeCRIUStats: scan script returned neither pages_written nor error")
	}

	bytesWritten := *res.PagesWritten * statsPageSizeBytes
	return bytesWritten / (1024 * 1024), nil
}
