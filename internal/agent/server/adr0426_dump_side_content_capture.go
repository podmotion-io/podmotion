/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0426_dump_side_content_capture.go — ADR-0426: capture the content of every content-absent mount
// whose backing source the agent can reach, on EVERY dump path, and fail the checkpoint closed when a
// capture is impossible and the mount's recorded OCI source is not affirmatively
// destination-reconstructable.
//
// This generalizes ADR-0414/ADR-0415's /dev/shm-literal captureCtrDevShmContent (which this file
// deletes, D1e) into a class-level primitive wired to BOTH the ctr fast path and the raw-CRIU
// fallback path (D2) — the wiring asymmetry (F1) that let a raw-path /dev/shm migration reach CRIU's
// files-reg.c:2353 with no content ever captured for it.
//
// THE DISPOSITION IS TWO-STAGE (D1d), and each stage reads a DIFFERENT fact:
//
//	Stage 1 (capture, D1a-CAP) reads ONLY reachability. It does not read a demand count and it does
//	not read any property of the resolved source directory, including whether it is empty — an empty
//	source yields an empty image, and F8a proves that empty image is what makes the restore side
//	internalize the mount rather than destination-rebind it.
//
//	Stage 2 (disposition when capture was impossible, D1a-FC) reads the mount's recorded OCI SOURCE
//	TYPE (D1b-2) — a positive fact from a source of truth — never a demand count. A benign skip
//	requires the source to be AFFIRMATIVELY identified as destination-reconstructable
//	(kubernetes.io~projected today); everything else, including a source that could not be classified
//	at all, fails closed.
//
// Neither stage reads a demand count. Demand remains load-bearing ONLY on the restore side (D4),
// which asks a different question — "does THIS checkpoint tell CRIU to open a name it cannot supply?"
// — that only files.img's own recorded content can answer.
import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/podmotion-io/podmotion/internal/metrics"
)

// createScratchScript creates a per-invocation-unique /dev/shm scratch script for a CRIU patch/scan
// python3 helper, writes content to it, and returns its path. Uniqueness comes from os.CreateTemp's
// own kernel-guaranteed collision-free creation — never from any caller-supplied identifier — so
// concurrent invocations (including retry-driven concurrent invocations sharing every other argument,
// e.g. the Checkpoint RPC's un-guarded retry path) never share a scratch-file path (ADR-0425 round 3).
// Precondition: callers must still `defer os.Remove(path)` themselves immediately after exec, exactly
// as today — this helper only creates and writes the file, it does not own its cleanup.
//
// (Relocated here, unchanged, from the deleted readDevShmMountInfo's neighborhood — D1e deletes that
// /dev/shm-literal function, not this shared scratch-file primitive, which several other decoders in
// this package still use.)
func createScratchScript(pattern, content string) (path string, err error) {
	f, err := os.CreateTemp("/dev/shm", pattern)
	if err != nil {
		return "", fmt.Errorf("create scratch script %s: %w", pattern, err)
	}
	path = f.Name()
	if _, werr := f.WriteString(content); werr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write scratch script %s: %w", pattern, werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close scratch script %s: %w", path, cerr)
	}
	return path, nil
}

// contentCaptureDemandScanPy is D1a's scanner. mountContentAxisPy is prepended verbatim (never
// restated — D1a, ADR-0420 D1c's whole argument extended to this THIRD consumer); see V5.
//
// For every EXTERNAL mountpoints entry the shared axis classifies INTERNALIZE_CONTENT_ABSENT, it
// emits the mountpoint, mnt_id, root_dev, the raw (unnormalized, un-interpreted) mountpoints `source`
// field, and the two files.img demand counts (regular / directory, split by the SAME S_IFMT/S_IFDIR
// mask the shipped classifiers use — never a private fourth spelling; V5). Round 4 adds `source` to
// the emit list: it feeds BOTH the reachability fallback (D1b-3) and the classifier fallback
// (D1b-2 rule 2). The counts are DIAGNOSTIC ONLY on the dump side (D1d) — logged and exported as
// metric-label exemplars; no dump-side branch reads them (V8b). A files.img read/parse failure is
// tolerated as zero counts (diagnostic-only), but a MOUNTPOINTS scan failure or unparseable output is
// a hard stop at the Go call site (D1a-SCAN) — "no entries" and "could not look" are different facts
// and this scanner exits non-zero (via the interpreter's own uncaught-exception path) on the latter,
// never silently emitting an empty list for it.
const contentCaptureDemandScanPy = `
import pycriu, glob, json, sys, os

_S_IFMT = 0o170000
_S_IFDIR = 0o040000


def _reg_counts(ckpt, mnt_id):
    """files.img REG-entry counts under mnt_id, split by the shipped S_IFMT/S_IFDIR mask.
    Diagnostic-only on the dump side (D1d) — a missing or unreadable files.img yields (0, 0)
    rather than failing the scan; the mountpoints image is this scanner's load-bearing input."""
    regular = 0
    directory = 0
    files_path = os.path.join(ckpt, 'files.img')
    if not os.path.exists(files_path):
        return regular, directory
    try:
        with open(files_path, 'rb') as f:
            files_img = pycriu.images.load(f)
    except Exception:
        return regular, directory
    for entry in files_img.get('entries', []):
        if entry.get('type') != 'REG':
            continue
        reg = entry.get('reg', {}) or {}
        if reg.get('mnt_id') != mnt_id:
            continue
        if (reg.get('mode', 0) & _S_IFMT) == _S_IFDIR:
            directory += 1
        else:
            regular += 1
    return regular, directory


ckpt = sys.argv[1]
out = []
for img in sorted(glob.glob(os.path.join(ckpt, 'mountpoints-*.img'))):
    if not img.endswith('.img'):
        continue
    with open(img, 'rb') as f:
        data = pycriu.images.load(f)
    for e in data.get('entries', []):
        ext_key = e.get('ext_key')
        mnt_id = e.get('mnt_id')
        mp = e.get('mountpoint')
        if not ext_key or mnt_id is None or not mp:
            continue
        if internalization_outcome(ckpt, e) != INTERNALIZE_CONTENT_ABSENT:
            continue
        demanded_regular, demanded_dir = _reg_counts(ckpt, mnt_id)
        src = e.get('source')
        out.append({
            'mountpoint': mp,
            'mnt_id': mnt_id,
            'root_dev': e.get('root_dev', 0) or 0,
            'source': src if isinstance(src, str) else '',
            'demanded_regular': demanded_regular,
            'demanded_dir': demanded_dir,
        })
print(json.dumps(out))
`

// contentCaptureScanEntry is one D1a scan result: an EXTERNAL mount the shared content axis
// classifies INTERNALIZE_CONTENT_ABSENT.
type contentCaptureScanEntry struct {
	Mountpoint      string `json:"mountpoint"`
	MntID           int64  `json:"mnt_id"`
	RootDev         int64  `json:"root_dev"`
	Source          string `json:"source"`
	DemandedRegular int    `json:"demanded_regular"`
	DemandedDir     int    `json:"demanded_dir"`
}

// contentCaptureDemandScan runs D1a's scanner and returns its content-absent entries.
//
// D1a-SCAN: a scan failure — the subprocess exits non-zero, or its output does not parse — is
// reported to the caller as an error, never as an empty/zero-entry result. The caller
// (captureContentAbsentMounts) treats that error as a hard stop (scan_failed), restoring
// `captureCtrDevShmContent:5424-5426`'s pre-ADR-0426 behavior verbatim: "no entries" (a successful
// scan finding nothing to capture) and "could not look" (a failed scan) are never collapsed into the
// same outcome.
func contentCaptureDemandScan(ctx context.Context, imagesDir string) ([]contentCaptureScanEntry, error) {
	scriptPath, err := createScratchScript("pm-capture-scan-*.py", mountContentAxisPy+contentCaptureDemandScanPy)
	if err != nil {
		return nil, fmt.Errorf("write content-capture scan script: %w", err)
	}
	defer os.Remove(scriptPath)

	cmd := exec.CommandContext(ctx, "python3", scriptPath, imagesDir)
	cmd.Env = append(os.Environ(), "PYTHONPATH=/usr/lib/python3/dist-packages")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("content-capture scan script failed: %w\n%s", err, out)
	}
	var entries []contentCaptureScanEntry
	if uerr := json.Unmarshal(out, &entries); uerr != nil {
		return nil, fmt.Errorf("parse content-capture scan output: %w\n%s", uerr, out)
	}
	return entries, nil
}

// hostRunRoot is the agent-visible filesystem root that a "/run/..." OCI/mountpoints source is
// re-rooted onto by runHostDir (F5: the daemonset bind-mounts host /run at /host-run;
// charts/podmotion/templates/daemonset.yaml). It is a package-level VARIABLE, not an inline literal,
// for exactly one reason: it is the injectable test seam that ADR-0426's own review round found
// missing — without it, exercising a real successful capture required writing into the actual host
// filesystem at /host-run, which only works as root with the real daemonset mount present, so the one
// test that tried (the round-4 capture fixture) silently t.Skipf()'d everywhere else, including CI.
// Production code MUST NEVER assign to this outside of the initializer above — the only permitted
// mutation site is withHostRunRootForTest (adr0426_test_seam_test.go), which points it at a
// t.TempDir() for the lifetime of one test and restores the production default on cleanup.
var hostRunRoot = "/host-run"

// runHostDir applies the SINGLE /run/-prefix + hostRunRoot re-rooting reachability test (F5), shared
// by both the config.json leg and the mountpoints-source fallback leg of mountHostSourceDir (D1b-3
// rule 3) — one test, not a second copy for the fallback (V6f: "a duplicated boundary test is how the
// two legs drift apart later").
func runHostDir(candidate string) (string, bool) {
	if !strings.HasPrefix(candidate, "/run/") {
		return "", false
	}
	return hostRunRoot + strings.TrimPrefix(candidate, "/run"), true
}

// dumpedFromDevice reports whether dir — the agent-visible host directory resolved for a
// content-absent mount — actually lives on the SAME filesystem CRIU dumped that mount from.
// ADR-0427 D6.
//
// recordedRootDev is the mountpoints image's own root_dev for this entry: CRIU's mi->s_dev, the
// device of the superblock the mount was on at dump time. It is the SOURCE OF TRUTH for "which
// filesystem object did CRIU dump here", which is why nothing about the path has to be inferred —
// no mountpoint test, no parent comparison, no /proc/self/mountinfo parse, no tiers.
//
// ENCODING — VERIFIED EMPIRICALLY (ADR-0427 round 4); THE TWO NUMBERS ARE NOT INTERCHANGEABLE:
//   - CRIU root_dev is the kernel-internal form, major<<20|minor — the same composition
//     /proc/<pid>/mountinfo prints as "maj:min".
//   - syscall.Stat_t.Dev is what stat(2) returns, packed by the kernel's new_encode_dev() as
//     (minor&0xff) | (major<<8) | ((minor&~0xff)<<12).
//
// They agree ONLY when major==0 && minor<256. Real /dev/shm root_dev values on the reference
// cluster fall on BOTH sides of that boundary, so a raw == would accept some captures and wrongly
// refuse others depending on which anonymous minor the kernel allocated. Both values are therefore
// decomposed to (major, minor) and compared componentwise. Do not "simplify" this back to ==.
func dumpedFromDevice(dir string, recordedRootDev int64) (bool, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return false, err
	}
	live := uint64(st.Dev)
	rec := uint64(recordedRootDev)
	return unix.Major(live) == uint32(rec>>20) && unix.Minor(live) == uint32(rec&0xFFFFF), nil
}

// dumpedFromDeviceCheck is the D6 test seam (ADR-0427): a package-level function variable whose
// only permitted mutation site is a test helper, mirroring the hostRunRoot discipline above
// (:200-203). Production code MUST NEVER assign to this outside of the initializer.
var dumpedFromDeviceCheck = dumpedFromDevice

// mountHostSourceDir resolves the agent-visible host source directory for mountpoint, and the
// OCI-recorded source string used by mountSourceReconstructability, per ADR-0426 D1b / D1b-1 / D1b-3.
// It generalizes the deleted devShmHostSourceDir (D1e) from a /dev/shm literal to any mountpoint.
//
// Resolution order (D1b-3 — the whole of the round-4 fix):
//  1. config.json is PREFERRED when present, parses, and carries an entry whose normalized
//     Destination matches the normalized mountpoint (D1b-1: /var/run -> /run, both sides). A MATCH
//     terminates resolution — even when that entry's Source is outside /run, `ok` is false and the
//     mountpoints source is NOT consulted (D1b-3: "matched but outside /run is not no entry").
//  2. Otherwise (config.json absent, unreadable, unparseable, or no matching entry under either
//     spelling) the mountpoints-*.img `source` field is the FALLBACK, and only when it is an absolute
//     path. CRIU sometimes records an external source with a doubled leading slash
//     ("//<abspath>" instead of "/<abspath>") — normalized to a single leading slash here before the
//     /run/ test, the same normalization discipline patch_checkpoint_script.go's `_lead` leading-
//     slash-count pattern already applies elsewhere in this codebase, so a double-slash-recorded path
//     is not wrongly treated as unreachable (ADR-0426 round-4, Arch-A's round-4 CONDITIONAL_SIGN_OFF
//     finding on D1b-3 rule 2).
//  3. The reachability test itself (runHostDir) is IDENTICAL for both candidates and is not relaxed.
//
// ociSource is populated from config.json ONLY (it is D1b-2 rule 1's sole source of truth) and is
// returned whether or not ok is true — the unreachable case is precisely where stage 2 needs it.
//
// sourceOrigin names which source of truth produced (hostDir, ok): "config.json", "mountpoints", or
// "none" (neither yielded a path-shaped candidate at all) — the D5 round-4 telemetry field that lets
// a raw-path `captured{sourceOrigin=mountpoints}` be distinguished from "we did not look" (F8d).
func mountHostSourceDir(imagesDir, mountpoint, mountpointsSource string) (hostDir, ociSource string, ok bool, sourceOrigin string) {
	if data, err := os.ReadFile(filepath.Join(imagesDir, "config.json")); err == nil {
		var cfg struct {
			Mounts []struct {
				Destination string `json:"destination"`
				Source      string `json:"source"`
			} `json:"mounts"`
		}
		if json.Unmarshal(data, &cfg) == nil {
			normalizedMountpoint := normalizeContainerMountPath(mountpoint)
			for _, m := range cfg.Mounts {
				if normalizeContainerMountPath(m.Destination) != normalizedMountpoint {
					continue
				}
				ociSource = m.Source
				if hd, rok := runHostDir(m.Source); rok {
					return hd, ociSource, true, "config.json"
				}
				return "", ociSource, false, "config.json"
			}
		}
	}

	// config.json absent, unreadable, unparseable, or carried no matching entry: fall back to the
	// mountpoints-*.img source field (D1b-3 rule 2), only when it is an absolute path.
	candidate := mountpointsSource
	for strings.HasPrefix(candidate, "//") {
		candidate = candidate[1:] // normalize a CRIU-recorded doubled leading slash (round-4 fix)
	}
	if !strings.HasPrefix(candidate, "/") {
		return "", ociSource, false, "none"
	}
	if hd, rok := runHostDir(candidate); rok {
		return hd, ociSource, true, "mountpoints"
	}
	return "", ociSource, false, "mountpoints"
}

// sourceClass is mountSourceReconstructability's result vocabulary (D1b-2).
type sourceClass string

const (
	// sourceClassReconstructable — the destination independently produces equivalent content for
	// this mount, so shipping without its bytes loses nothing.
	sourceClassReconstructable sourceClass = "RECONSTRUCTABLE"
	// sourceClassWorkloadState — the source is (or may be) the workload's own data; shipping
	// without its bytes is data loss. There is no third value and no default-permissive branch.
	sourceClassWorkloadState sourceClass = "WORKLOAD_STATE"
)

// projectedVolumeMarker is the ONE evidenced RECONSTRUCTABLE shape today (R12): kubelet regenerates
// a projected volume at the destination with its own projection and expiry (ADR-0420 D1's settled
// credential outcome). The allowlist is deliberately a closed, single-member set.
const projectedVolumeMarker = "/volumes/kubernetes.io~projected/"

// mountSourceReconstructability classifies a content-absent mount's recorded backing source (D1b-2).
// Three rules, in order, each grounded in F8c:
//
//  1. ociSource (from config.json) is the authority. If it contains projectedVolumeMarker, the mount
//     is RECONSTRUCTABLE.
//  2. mountpointsSource is a FALLBACK, and ONLY when ociSource is unavailable (config.json absent,
//     unreadable, unparseable, or no matching entry — the resolver returns ociSource == "" in every
//     such case) AND mountpointsSource is an absolute host path. A non-path source (the ctr path's
//     bare "shm"/"tmpfs", F8c fact 1) is never a candidate and is ignored entirely.
//  3. Everything else is WORKLOAD_STATE — explicitly including kubernetes.io~empty-dir,  a containerd
//     sandbox shm directory that is genuinely unreachable, any /var/lib/kubelet source that is not a
//     projected volume, and any case where no source could be determined at all.
func mountSourceReconstructability(ociSource, mountpointsSource string) sourceClass {
	if ociSource != "" {
		if strings.Contains(ociSource, projectedVolumeMarker) {
			return sourceClassReconstructable
		}
		return sourceClassWorkloadState
	}
	if strings.HasPrefix(mountpointsSource, "/") && strings.Contains(mountpointsSource, projectedVolumeMarker) {
		return sourceClassReconstructable
	}
	return sourceClassWorkloadState
}

// tmpfsContentImageName is the CRIU tmpfs-content image basename for a tmpfs whose recorded root_dev
// is rootDev (renamed from devShmContentImageName, D1c — the naming contract is unchanged and is now
// shared by every content-absent tmpfs, not only /dev/shm).
func tmpfsContentImageName(rootDev int64) string {
	return fmt.Sprintf("tmpfs-dev-%d.tar.gz.img", rootDev)
}

// writeTmpfsContentImage tar-serializes the live host source directory (srcDir) into the CRIU-native
// content image at outPath, matching CRIU's own dump_tmpfs invocation (gzip tar, sparse, numeric
// owner, ./-relative from the mount dir) so restore_tmpfs extracts it unchanged. On failure it removes
// any partial image so the checkpoint never carries a torn content layer. Renamed from
// writeDevShmContentImage (D1c) — body unchanged; it was already path-agnostic.
func writeTmpfsContentImage(ctx context.Context, srcDir, outPath string) error {
	tarCmd := exec.CommandContext(ctx, "tar", "--create", "--gzip", "--sparse", "--numeric-owner",
		"--file", outPath, "-C", srcDir, ".")
	if tout, err := tarCmd.CombinedOutput(); err != nil {
		_ = os.Remove(outPath)
		return fmt.Errorf("tar mount content: %w\n%s", err, strings.TrimSpace(string(tout)))
	}
	return nil
}

// tarMemberCount returns the number of members in a gzip tarball, best-effort (0 on any read error) —
// used only for the diagnostic "members" log field (V11 assertion 3), never for a gating decision.
func tarMemberCount(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0
	}
	defer gz.Close()
	n := 0
	tr := tar.NewReader(gz)
	for {
		if _, terr := tr.Next(); terr != nil {
			break
		}
		n++
	}
	return n
}

// capturedMount is one D1d "captured" outcome, returned for the caller's diagnostic log line.
type capturedMount struct {
	Mountpoint   string
	Image        string
	Members      int
	RegFiles     int
	SourceOrigin string
}

// captureOutcome summarizes what captureContentAbsentMounts did. It is diagnostic only: every gating
// decision (capture vs. fail-closed vs. skip) is already final — via the returned error or via the
// D5 metric — by the time this is returned; captureOutcome exists so a caller can log a summary line
// without re-deriving it.
type captureOutcome struct {
	Captured                   []capturedMount
	AlreadyPresent             []string
	DestinationReconstructable []string
}

// ContentAbsentRegFileDemandError is ADR-0426 D4's restore-side hard stop: the checkpoint classifies
// Mountpoint content-absent (so the destination's own empty mount is used) while recording
// RegFileCount regular file(s) inside it that CRIU will be told to open. Restoring would abort at
// criu/files-reg.c:2353. This rides the EXISTING MountContentAvailabilityOutcomeTotal counter (a new
// "inconsistent_reg_file_demand" label value) — no new metric family, no new condition, no new Event
// type; the existing RestoreFailed/rollback machinery handles the disposition unchanged.
type ContentAbsentRegFileDemandError struct {
	Mountpoint   string
	RegFileCount int
}

func (e *ContentAbsentRegFileDemandError) Error() string {
	return fmt.Sprintf("checkpoint is internally inconsistent: it classifies %q content-absent (so the destination's own empty mount is used) while recording %d regular file(s) inside it that CRIU will be told to open — restoring would abort at criu/files-reg.c:2353 (ADR-0426 D4)",
		e.Mountpoint, e.RegFileCount)
}

// captureContentAbsentMounts is the dump-side half of ADR-0420's content axis. It captures every
// INTERNALIZE_CONTENT_ABSENT mount whose host source is agent-reachable — empty or not, demanded or
// not — and fails the checkpoint closed when a capture is impossible on a mount whose recorded OCI
// source is not affirmatively destination-reconstructable. It consults no demand count and no
// property of the source directory other than its reachability (ADR-0426 D1d).
//
// Called from BOTH dump paths (D2): the ctr fast path's success branch, and the raw-CRIU fallback
// path. The two paths leave the source in DIFFERENT states, and the distinction matters (ADR-0427):
//
//   - raw-CRIU path: the capture runs after that path's LeaveStopped dump and registerFrozenSource
//     (D3), so the source is additionally FROZEN and thawable via the frozen-source machinery.
//   - ctr fast path: ctrCheckpoint passes no exit/stop flag, so the source is never frozen at all —
//     it KEEPS RUNNING normally across the capture window. This is the common case in practice.
//
// A fail-closed return here never releases or tears down the source on EITHER path. That property
// comes from the fail-closed return itself — the checkpoint images are zeroized and a typed failure
// is returned to the caller, which aborts the migration around an intact source — and NOT from the
// source's freeze state (D3-THAW, F6), which only one of the two paths establishes.
func captureContentAbsentMounts(ctx context.Context, imagesDir string) (captureOutcome, error) {
	var out captureOutcome

	entries, scanErr := contentCaptureDemandScan(ctx, imagesDir)
	if scanErr != nil {
		metrics.MountContentCaptureOutcomeTotal.WithLabelValues("scan_failed", "", "").Inc()
		return out, &MountContentCaptureFailedDetail{
			Mountpoint: "",
			Cause:      fmt.Sprintf("mountpoints/files scan failed: %v", scanErr),
		}
	}

	for _, e := range entries {
		fail := func(cause string) error {
			return &MountContentCaptureFailedDetail{Mountpoint: e.Mountpoint, Cause: cause}
		}

		outPath := filepath.Join(imagesDir, tmpfsContentImageName(e.RootDev))
		if _, statErr := os.Stat(outPath); statErr == nil {
			out.AlreadyPresent = append(out.AlreadyPresent, e.Mountpoint)
			metrics.MountContentCaptureOutcomeTotal.WithLabelValues("already_present", "", "").Inc()
			continue
		}

		hostDir, ociSource, ok, origin := mountHostSourceDir(imagesDir, e.Mountpoint, e.Source)

		// Stage 1 — capture. Demand-blind AND emptiness-blind (D1a-CAP): attempted for every
		// INTERNALIZE_CONTENT_ABSENT entry whose host source resolves, full stop.
		if e.RootDev != 0 && ok {
			// ADR-0427 D6: verify, before any tar, that hostDir actually lives on the filesystem
			// CRIU recorded dumping this mount from — not merely that the path resolves lexically.
			// A stale, unpropagated /host-run view resolves fine and stats fine while pointing at
			// the empty directory a later host mount is layered over; this is the check that
			// catches that case at the source of truth (RootDev) instead of inferring it.
			matched, devErr := dumpedFromDeviceCheck(hostDir, e.RootDev)
			if devErr != nil {
				metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "root_dev_check_failed", origin).Inc()
				return out, fail(fmt.Sprintf("could not verify resolved host source %q against recorded root_dev %d: %v", hostDir, e.RootDev, devErr))
			}
			if !matched {
				var live syscall.Stat_t
				liveMajMin := "unknown"
				if statErr := syscall.Stat(hostDir, &live); statErr == nil {
					liveMajMin = fmt.Sprintf("%d:%d", unix.Major(uint64(live.Dev)), unix.Minor(uint64(live.Dev)))
				}
				recMajMin := fmt.Sprintf("%d:%d", uint32(uint64(e.RootDev)>>20), uint32(uint64(e.RootDev)&0xFFFFF))
				metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "root_dev_mismatch", origin).Inc()
				return out, fail(fmt.Sprintf("resolved host source %q is not the filesystem CRIU dumped this mount from: live device %s != recorded root_dev %s (ADR-0427 D6 — mount propagation is the overwhelmingly likely cause)", hostDir, liveMajMin, recMajMin))
			}

			if tarErr := writeTmpfsContentImage(ctx, hostDir, outPath); tarErr != nil {
				metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "tar_failed", origin).Inc()
				return out, fail(fmt.Sprintf("tar of resolved host source %q failed: %v", hostDir, tarErr))
			}
			members := tarMemberCount(outPath)
			log.Info("Checkpoint: captured content-absent mount content (ADR-0426 D1d — reachability-keyed, no demand test, no emptiness test)",
				"mountpoint", e.Mountpoint, "image", tmpfsContentImageName(e.RootDev), "outcome", "captured",
				"sourceOrigin", origin, "regFiles", e.DemandedRegular, "members", members)
			out.Captured = append(out.Captured, capturedMount{
				Mountpoint: e.Mountpoint, Image: tmpfsContentImageName(e.RootDev),
				Members: members, RegFiles: e.DemandedRegular, SourceOrigin: origin,
			})
			metrics.MountContentCaptureOutcomeTotal.WithLabelValues("captured", "", origin).Inc()
			continue
		}

		// Stage 2 — disposition when stage 1 could not capture. Reads the OCI SOURCE TYPE; reads NO
		// demand count.
		if e.RootDev == 0 {
			metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "no_root_dev", origin).Inc()
			return out, fail("content-absent mount has no root_dev in the mountpoints image — cannot name the CRIU tmpfs content image")
		}

		class := mountSourceReconstructability(ociSource, e.Source)
		if class == sourceClassReconstructable {
			log.Info("Checkpoint: content-absent mount's source is not agent-reachable but is affirmatively destination-reconstructable — skipping capture (ADR-0426 D1d stage 2)",
				"mountpoint", e.Mountpoint, "ociSource", ociSource, "mountpointsSource", e.Source)
			out.DestinationReconstructable = append(out.DestinationReconstructable, e.Mountpoint)
			metrics.MountContentCaptureOutcomeTotal.WithLabelValues("destination_reconstructable", "", origin).Inc()
			continue
		}

		metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "unreachable_workload_state", origin).Inc()
		return out, fail("no agent-visible host source for this content-absent mount, and its recorded OCI source is not affirmatively destination-reconstructable — cannot capture and cannot prove it is safe to skip")
	}

	return out, nil
}
