/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// shmem_pagemap_guard.go — ADR-0246 D1/D3: post-checkpoint, pre-transfer completeness guard.
//
// CRIU 4.2 has a confirmed (§P-PREMISE-decoded, docs/sprints/SPRINT40C-SHMEM-PREMISE-EVIDENCE.md)
// dump-time defect where an anon-shmem vma is recorded in mm-<pid>.img (with a non-zero shmid)
// but the corresponding pagemap-shmem-<shmid>.img is never written. Restoring such a checkpoint
// dies partway through with "criu/shmem.c:534: Can't restore shmem content". This guard detects
// that reference-without-data pattern BEFORE transfer so a non-restorable checkpoint never ships
// (ADR-0246 D1) — a pure detector, no retry, no repair.
//
// D3 (non-negotiable): this decode step is a least-privileged, host-mount-namespace-free,
// in-process reader over the agent container's own tmpfs imagesDir. It follows the exact
// call pattern already established (and already gate-proven) by buildMaskedPathExtMountArgs
// (server.go, ADR-0121/ADR-0124): a small python3 subprocess invoking the already-vendored
// pycriu.images generic image reader, with PYTHONPATH pointed at the vendored
// /usr/lib/python3/dist-packages/pycriu tree. It is explicitly NOT invoked via nsenterCmd and
// does not touch the host mount namespace, hostPID, hostNetwork, or containerd.sock — it only
// opens files already local to the agent container's own filesystem view (imagesDir itself).
//
// Any transient artifact this step produces (the scan script) is written into imagesDir itself
// (the already-governed tmpfs dir, mode 0700, Standing Rule 7) and is explicitly zeroized and
// removed before this function returns on every exit path — it is never written to a separate
// or persistent path, and is additionally covered by the caller's existing zeroizeDir sweep of
// imagesDir on abort paths as defense in depth.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// pycriuPythonPath is the PYTHONPATH entry used to import the vendored pycriu package. It is a
// var (not a const) purely so tests can point it at the in-repo pycriu/ tree
// (resolveRepoPycriuPath in pycriu_corpus_test.go) on a dev machine that lacks the production
// agent-image path — production always uses the default below, matching the other pycriu call
// sites in server.go (buildMaskedPathExtMountArgs, patchCheckpointImages).
var pycriuPythonPath = "/usr/lib/python3/dist-packages"

// ErrIncompleteShmemPagemap is the distinguishable sentinel error for ADR-0246's completeness
// guard. It wraps the list of shmids that were referenced by an anon-shmem vma in mm-*.img but
// have no corresponding non-empty pagemap-shmem-<shmid>.img in the same imagesDir. The
// controller-side error-branching logic (podmigration_controller.go, following the ADR-0245 D1
// pattern) matches on this via errors.Is and sets CheckpointFailed/ShmemPagemapMissing.
var ErrIncompleteShmemPagemap = errors.New("checkpoint incomplete: CRIU dump referenced anon-shmem segment(s) with no pagemap-shmem-<shmid>.img (CRIU 4.2 anon-shmem dump defect; see docs/known-issues/CRIU-4.2-ANON-SHMEM-DUMP-DEFECT.md)")

// ShmemPagemapMissingDetail is the typed detail carried alongside ErrIncompleteShmemPagemap
// (ADR-0246 typed-status redesign). It exists so the gRPC
// boundary (newShmemPagemapMissingStatus in server.go) can build a structured
// codes.FailedPrecondition status with an errdetails.ErrorInfo{Reason: ShmemPagemapMissingReason}
// payload instead of the controller string-matching prose in ErrIncompleteShmemPagemap's Error().
// Error() below reproduces the exact original message text so in-process callers (tests,
// log lines) are unaffected; Unwrap() preserves errors.Is(err, ErrIncompleteShmemPagemap)
// compatibility for any existing in-process check.
type ShmemPagemapMissingDetail struct {
	Missing   []int64
	ImagesDir string
}

func (d *ShmemPagemapMissingDetail) Error() string {
	return fmt.Sprintf("%v: shmid(s) %v referenced by mm-*.img with no non-empty pagemap-shmem-<shmid>.img in %s",
		ErrIncompleteShmemPagemap, d.Missing, d.ImagesDir)
}

func (d *ShmemPagemapMissingDetail) Unwrap() error { return ErrIncompleteShmemPagemap }

// ShmemPagemapMissingReason is the stable, machine-readable errdetails.ErrorInfo.Reason value
// (ADR-0246) carried on the codes.FailedPrecondition gRPC status returned by the Checkpoint RPC
// when verifyShmemPagemapCompleteness fails. It replaces the former error-string substring match
// (see podmigration_controller.go). This constant is the ONE thing that must agree between the
// agent (server.go, sets it) and the controller (podmigration_controller.go, reads it via
// errdetails.ErrorInfo rather than any error-message prose) — a stable reason code on a
// standard gRPC status-details payload, not free text kept in sync by a unit test.
const ShmemPagemapMissingReason = "SHMEM_PAGEMAP_MISSING"

// ShmemPagemapMissingReasonDomain is the errdetails.ErrorInfo.Domain paired with
// ShmemPagemapMissingReason.
const ShmemPagemapMissingReasonDomain = "podmotion.io"

// shmemScanScript is the embedded python3/pycriu script that decodes every mm-*.img in the
// target directory (argv[1]) and prints the JSON-encoded sorted list of distinct non-zero
// shmids referenced by any vma entry across all of them. It performs no filesystem writes and
// touches nothing outside argv[1] — it is a pure read.
//
// Kept in lockstep with the mirrored copy in shmem_pagemap_guard_test.go (buildShmemScanScript);
// any divergence there is a test gap (same pattern as buildScanScript/buildPatchScript in
// pycriu_corpus_test.go).
const shmemScanScript = `
import pycriu, glob, json, sys

shmids = set()
for img in glob.glob(sys.argv[1] + '/mm-*.img'):
    with open(img, 'rb') as f:
        data = pycriu.images.load(f)
    for entry in data.get('entries', []):
        for vma in entry.get('vmas', []):
            shmid = vma.get('shmid', 0)
            if shmid:
                shmids.add(shmid)
print(json.dumps(sorted(shmids)))
`

// verifyShmemPagemapCompleteness implements ADR-0246 D1/D3. It must be called after the final
// checkpoint image set is produced (both the ctr-native and raw-CRIU fallback paths — the
// defect is CRIU-internal, not caller-specific) and before that image set is considered ready
// for GetCheckpointTar/transfer.
//
// It decodes every mm-*.img in imagesDir to collect every referenced anon-shmem shmid, then
// confirms a non-empty pagemap-shmem-<shmid>.img exists in imagesDir for each one. Returns
// ErrIncompleteShmemPagemap (wrapped with the missing shmid list) if any is absent or empty.
//
// D3: runs as a plain in-process reader over imagesDir — no nsenterCmd, no host mount
// namespace, no hostPID/hostNetwork/containerd.sock reach. Mirrors buildMaskedPathExtMountArgs.
func verifyShmemPagemapCompleteness(imagesDir string) error {
	// No mm-*.img files at all is not an error here — e.g. synthetic/test checkpoints, or a
	// workload with no address-space image for some reason. Absence of evidence is not
	// evidence of the defect; the decode below simply yields an empty shmid set in that case.
	scriptPath := filepath.Join(imagesDir, ".pm-scan-shmem.py")
	if err := os.WriteFile(scriptPath, []byte(shmemScanScript), 0o600); err != nil {
		return fmt.Errorf("verifyShmemPagemapCompleteness: write scan script: %w", err)
	}
	defer func() {
		// §P-VERIFY: zeroize the transient script before removal, identically to how
		// checkpoint images themselves are zeroized on exit paths (zeroizeDir), even though
		// the script itself carries no tenant memory content — treat every artifact this
		// guard places on tmpfs imagesDir the same way, no exceptions.
		if data, statErr := os.Stat(scriptPath); statErr == nil {
			zeros := make([]byte, data.Size())
			_ = os.WriteFile(scriptPath, zeros, 0o600)
		}
		_ = os.Remove(scriptPath)
	}()

	cmd := exec.Command("python3", scriptPath, imagesDir)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pycriuPythonPath)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("verifyShmemPagemapCompleteness: mm-image scan script failed: %w\n%s", err, out)
	}

	var shmids []int64
	if err := json.Unmarshal(out, &shmids); err != nil {
		return fmt.Errorf("verifyShmemPagemapCompleteness: parse scan output: %w\n%s", err, out)
	}
	if len(shmids) == 0 {
		return nil
	}

	var missing []int64
	for _, shmid := range shmids {
		pagemapPath := filepath.Join(imagesDir, fmt.Sprintf("pagemap-shmem-%d.img", shmid))
		info, statErr := os.Stat(pagemapPath)
		if statErr != nil || info.Size() == 0 {
			missing = append(missing, shmid)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
	return &ShmemPagemapMissingDetail{Missing: missing, ImagesDir: imagesDir}
}

// newShmemPagemapMissingStatus wraps a verifyShmemPagemapCompleteness failure as a typed
// codes.FailedPrecondition gRPC status carrying an errdetails.ErrorInfo{Reason:
// ShmemPagemapMissingReason} payload (ADR-0246 typed-status redesign). Follows the EXACT sibling
// pattern already established for ErrCRIUCapability (server.go: status.Errorf(codes.
// FailedPrecondition, ...) on errors.Is match) — same code, same "do not string-match at the
// controller" intent — but additionally attaches a structured details payload (missing shmid
// list + imagesDir) since, unlike ErrCRIUCapability, the controller needs a second axis to
// distinguish THIS FailedPrecondition cause from the CRIU-capability one sharing the same code.
func newShmemPagemapMissingStatus(err error) error {
	st := status.New(codes.FailedPrecondition, fmt.Sprintf("checkpoint failed: %v", err))

	info := &errdetails.ErrorInfo{
		Reason: ShmemPagemapMissingReason,
		Domain: ShmemPagemapMissingReasonDomain,
	}
	var detail *ShmemPagemapMissingDetail
	if errors.As(err, &detail) {
		info.Metadata = map[string]string{
			"imagesDir": detail.ImagesDir,
			"missing":   fmt.Sprint(detail.Missing),
		}
	}

	if withDetails, wdErr := st.WithDetails(info); wdErr == nil {
		return withDetails.Err()
	}
	// WithDetails can only fail if info is not a proto.Message, which it always is here;
	// fall back to the plain typed status (code alone) rather than losing the RPC error.
	return st.Err()
}
