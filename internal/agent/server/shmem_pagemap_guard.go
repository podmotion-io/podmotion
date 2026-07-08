/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// shmem_pagemap_guard.go — ADR-0246 D1/D3: post-checkpoint, pre-transfer completeness guard.
//
// CRIU 4.2 has a confirmed (§P-PREMISE-decoded, docs/sprints/SPRINT40C-SHMEM-PREMISE-EVIDENCE.md)
// dump-time defect where a genuine anon-shmem vma (VMA_ANON_SHARED) is recorded in mm-<pid>.img
// but the corresponding pagemap-shmem-<shmid>.img is never written. Restoring such a checkpoint
// dies partway through with "criu/shmem.c:534: Can't restore shmem content". This guard detects
// that reference-without-data pattern BEFORE transfer so a non-restorable checkpoint never ships
// (ADR-0246 D1) — a pure detector, no retry, no repair.
//
// SPRINT41 NR-BLOCK-2 bugfix (docs/sprints/SPRINT41-NR-BLOCK-2-MECHANISM-INVESTIGATION.md,
// panel-verified by two independent architect reviews): the original scan logic treated ANY
// non-zero vma_entry.shmid field as an anon-shmem pagemap obligation. CRIU's mm-*.img overloads
// that field as a generic per-checkpoint object index for multiple unrelated vma classes, which
// produced a false positive on every checkpoint (the exact fixed small-integer signature
// [1 2 3] seen across four failed gate attempts). The scan now classifies each vma by its
// status bitmask (CRIU's mmap.status flags) before deciding whether a pagemap check applies:
//   - VMA_FILE_PRIVATE (file-backed private mappings, e.g. ELF text/data): excluded entirely —
//     backed by pages-*.img via file/pgoff, no pagemap-shmem-*.img is ever produced or needed.
//   - VMA_ANON_SHARED (genuine shm_open/anon MAP_SHARED segments): checked exactly as before,
//     directly by vma.shmid — this is the guard's original, load-bearing protection against the
//     real historical defect (shmid 22685/11423).
//   - VMA_AREA_MEMFD (memfd-backed MAP_SHARED, including CRIU's own CRIUMFD parasite-injection
//     regions): NOT excluded — still checked, but the real pagemap key is resolved via
//     memfd.img's memfd_inode_entry list (vma.shmid matches an entry's inode_id; that entry's
//     own shmid field is the real, correctly-written pagemap-shmem-<shmid>.img key), since a
//     memfd vma's own shmid field is a small sequential index, not the real kernel identifier.
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
// target directory (argv[1]) and prints the JSON-encoded sorted list of distinct real
// pagemap-shmem keys that must have a matching pagemap-shmem-<key>.img.
//
// CRIU's mm-*.img vma_entry.shmid field is a generic, overloaded per-checkpoint object index —
// NOT always a real anon-shmem/pagemap key (see docs/sprints/SPRINT41-NR-BLOCK-2-MECHANISM-
// INVESTIGATION.md and ADR-0246's follow-up bugfix note). The vma_entry.status bitmask
// (CRIU's mmap.status flags, pycriu/images/pb2dict.py mmap_status_map) distinguishes three
// cases this scan must treat differently:
//
//   - VMA_FILE_PRIVATE (bit 6, 1<<6): a private file-backed mapping (e.g. ELF text/data). Its
//     content is recovered from pages-*.img via file/pgoff, never from a pagemap-shmem-*.img.
//     The vma's shmid field here is just a generic index, not a pagemap key — EXCLUDE entirely.
//   - VMA_ANON_SHARED (bit 8, 1<<8): a genuine anon-shmem (shm_open/MAP_SHARED anon) mapping.
//     This is the ONLY class the original ADR-0246 defect (shmid 22685/11423) applies to. Its
//     vma.shmid IS the real pagemap key — KEEP the existing direct check unchanged.
//   - VMA_AREA_MEMFD (bit 14, 1<<14): a memfd-backed MAP_SHARED mapping (including CRIU's own
//     CRIUMFD parasite-injection regions). This DOES have a real on-disk pagemap — but keyed by
//     the memfd's real kernel inode/shmid recorded in memfd.img, not by the vma's own (small,
//     sequential, overloaded) shmid field. On a REAL CRIU 4.2 dump (verified live against the
//     go-tcp-echo workload, docs/sprints/SPRINT41-NR-BLOCK-2-MECHANISM-INVESTIGATION.md), the
//     vma's shmid field is actually a files.img file-object id, NOT memfd.img's inode_id
//     directly — the correct resolution is a two-hop join: vma.shmid -> files.img entry (type
//     MEMFD) with matching id -> that entry's memfd.inode_id -> memfd.img's
//     memfd_inode_entry with matching inode_id -> that entry's own .shmid field, which is the
//     real pagemap-shmem-<key>.img key to check. If either hop fails to resolve, fall back to
//     the vma's own shmid (fail closed rather than silently skip — an unresolvable memfd
//     reference is itself suspicious).
//
// Emits a JSON list of the real pagemap-shmem keys that must have a matching
// pagemap-shmem-<key>.img.
//
// Kept in lockstep with the mirrored copy in shmem_pagemap_guard_test.go (buildShmemScanScript);
// any divergence there is a test gap (same pattern as buildScanScript/buildPatchScript in
// pycriu_corpus_test.go).
const shmemScanScript = `
import pycriu, glob, json, sys

VMA_FILE_PRIVATE = 1 << 6
VMA_ANON_SHARED = 1 << 8
VMA_AREA_MEMFD = 1 << 14

# Hop 1: files.img file-object id -> memfd.inode_id, for every FILES entry of type MEMFD. A
# VMA_AREA_MEMFD vma's own shmid field is actually this files.img "id", not memfd.img's inode_id
# directly (verified against a real CRIU 4.2 dump, not just the synthetic pycriu round-trip).
memfd_inode_id_by_file_id = {}
for img in glob.glob(sys.argv[1] + '/files.img'):
    with open(img, 'rb') as f:
        data = pycriu.images.load(f)
    for entry in data.get('entries', []):
        if entry.get('type') == 'MEMFD':
            memfd = entry.get('memfd', {})
            file_id = entry.get('id')
            inode_id = memfd.get('inode_id')
            if file_id is not None and inode_id is not None:
                memfd_inode_id_by_file_id[file_id] = inode_id

# Hop 2: memfd.img's memfd_inode_entry.inode_id -> that entry's own real shmid (the actual
# kernel-assigned identifier pagemap-shmem-<shmid>.img is keyed by).
real_shmid_by_inode_id = {}
for img in glob.glob(sys.argv[1] + '/memfd.img') + glob.glob(sys.argv[1] + '/memfd-*.img'):
    with open(img, 'rb') as f:
        data = pycriu.images.load(f)
    for entry in data.get('entries', []):
        inode_id = entry.get('inode_id')
        real_shmid = entry.get('shmid')
        if inode_id is not None and real_shmid is not None:
            real_shmid_by_inode_id[inode_id] = real_shmid

def resolve_memfd_key(vma_shmid):
    inode_id = memfd_inode_id_by_file_id.get(vma_shmid)
    if inode_id is None:
        return vma_shmid
    return real_shmid_by_inode_id.get(inode_id, vma_shmid)

keys = set()
for img in glob.glob(sys.argv[1] + '/mm-*.img'):
    with open(img, 'rb') as f:
        data = pycriu.images.load(f)
    for entry in data.get('entries', []):
        for vma in entry.get('vmas', []):
            shmid = vma.get('shmid', 0)
            if not shmid:
                continue
            status = vma.get('status', 0)
            if isinstance(status, str):
                # pretty/dict-mode may render flags as a "|"-joined name string; only the raw
                # int form is relied upon in production (pycriu.images.load default), but guard
                # defensively rather than crash on an unexpected representation.
                status_int = 0
                if 'VMA_FILE_PRIVATE' in status:
                    status_int |= VMA_FILE_PRIVATE
                if 'VMA_ANON_SHARED' in status:
                    status_int |= VMA_ANON_SHARED
                if 'VMA_AREA_MEMFD' in status:
                    status_int |= VMA_AREA_MEMFD
                status = status_int

            if status & VMA_FILE_PRIVATE:
                # File-backed private mapping: never needs a pagemap-shmem check, regardless of
                # any other bit also set. Exclude entirely.
                continue

            if status & VMA_AREA_MEMFD:
                keys.add(resolve_memfd_key(shmid))
                continue

            if status & VMA_ANON_SHARED:
                keys.add(shmid)
                continue

            # Any other status combination (e.g. VMA_ANON_PRIVATE, VMA_AREA_SYSVIPC, etc.) does
            # not carry a pagemap-shmem-<shmid>.img obligation under this convention — only
            # VMA_ANON_SHARED and VMA_AREA_MEMFD do. Not flagged.

print(json.dumps(sorted(keys)))
`

// verifyShmemPagemapCompleteness implements ADR-0246 D1/D3. It must be called after the final
// checkpoint image set is produced (both the ctr-native and raw-CRIU fallback paths — the
// defect is CRIU-internal, not caller-specific) and before that image set is considered ready
// for GetCheckpointTar/transfer.
//
// It decodes every mm-*.img in imagesDir to collect every real pagemap-shmem key referenced by
// a VMA_ANON_SHARED or VMA_AREA_MEMFD vma (resolving the latter's real key via memfd.img;
// VMA_FILE_PRIVATE vmas are excluded entirely — see the classification note above), then
// confirms a non-empty pagemap-shmem-<key>.img exists in imagesDir for each one. Returns
// ErrIncompleteShmemPagemap (wrapped with the missing key list) if any is absent or empty.
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
