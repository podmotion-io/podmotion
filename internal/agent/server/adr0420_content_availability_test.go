/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0420_content_availability_test.go — ADR-0420 D4's replaced D1 case list, plus the D1b, D1c and
// D1d assertions and the §P-VERIFY guards that are mechanically checkable in a unit-test process.
//
// TWO LEVELS, DELIBERATELY, because they falsify different things:
//
//  1. The PREDICATE, driven through the production Python in --content-selftest mode. This is the
//     only way to cover the fail-closed cases (absent / non-integer / bool root_dev and mnt_id) that
//     a protobuf-typed mountpoints image structurally cannot express, and it runs the code that
//     ships rather than a Go re-implementation of it (see patch_classify_test.go for why a Go mirror
//     is the anti-pattern here).
//  2. The END-TO-END classification, driven through the real patchCheckpointImages against real
//     pycriu-written mountpoints images. This is what proves the predicate is actually WIRED — a
//     correct predicate nobody calls would pass level 1 and change nothing.
//
// D4's seven D1 cases map onto these as: (a) and (d) internalization with content, (b) and (c) the
// content-absent fall-through resolved and unresolved, (e) the kernel-regenerated fstypes, (f) the
// untouched non-recreatable class, (g) the fail-closed identifier cases.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/podmotion-io/podmotion/internal/agent/nri"
	"github.com/podmotion-io/podmotion/internal/metrics"
)

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

// stageTmpfsContentImage writes a tmpfs content image into a checkpoint directory.
//
// The BYTES ARE IRRELEVANT and that is the point: D1's predicate is os.path.exists over the
// directory CRIU's tmpfs_restore will look in, mirroring that function's own two-name lookup order.
// It never opens, parses, validates or creates a content image — see
// TestADR0420_PVERIFY4_D1NeverFabricatesContent, which is the guard against the single worst way
// this decision could be implemented.
func stageTmpfsContentImage(t *testing.T, ckptDir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(ckptDir, name), []byte("not-a-real-tar"), 0o600); err != nil {
		t.Fatalf("stage content image %s: %v", name, err)
	}
}

// adr0420CorpusGenPy writes a mountpoints image with an overlay root plus ONE external entry
// carrying a caller-chosen fstype, mnt_id and root_dev — the three fields the ADR-0420 content axis
// reads. It is parameterized on root_dev/mnt_id (which adr0417FstypeCorpusGenPy pins) because the
// whole point of case (d) is that tmpfs_restore's SECOND lookup name is keyed on mnt_id, not
// root_dev, and a corpus that cannot vary them cannot tell the two lookups apart.
const adr0420CorpusGenPy = `
import sys, os
import pycriu
d = sys.argv[1]
fstype, mnt_id, root_dev = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
mountpoint = sys.argv[5]
mnts = [
    {'fstype': 17, 'mnt_id': 1, 'root_dev': 0, 'parent_mnt_id': 0, 'flags': 0,
     'root': '/', 'mountpoint': '/', 'source': 'overlay', 'options': '', 'sb_flags': 0},
    {'fstype': fstype, 'mnt_id': mnt_id, 'root_dev': root_dev, 'parent_mnt_id': 1, 'flags': 0,
     'root': '/src/node/only', 'mountpoint': mountpoint, 'source': '/src/node/only',
     'options': '', 'sb_flags': 0, 'ext_key': mountpoint},
]
with open(os.path.join(d, 'mountpoints-13.img'), 'wb') as f:
    pycriu.images.dump({'magic': 'MNTS', 'entries': mnts}, f)
print('CORPUS_OK')
`

// adr0420ServiceAccountPath is the live-decoded in-container mountpoint of the pod
// serviceaccount-token tmpfs — the member of the previously-unexamined "internalized without
// captured content" set that exists on every pod in the cluster, and the mount that failed 7/7 live
// restores. It is used as fixture DATA only: nothing in the production predicate matches on it, and
// TestADR0420_D1_PredicateNamesNoPathOrWorkload asserts that.
const adr0420ServiceAccountPath = "/run/secrets/kubernetes.io/serviceaccount"

func writeADR0420Corpus(t *testing.T, pypath string, extraEnv []string, ckptDir string, fstype, mntID, rootDev int, mountpoint string) {
	t.Helper()
	genPath := filepath.Join(t.TempDir(), "adr0420-gen.py")
	if err := os.WriteFile(genPath, []byte(adr0420CorpusGenPy), 0o600); err != nil {
		t.Fatalf("write corpus generator: %v", err)
	}
	cmd := exec.Command("python3", genPath, ckptDir,
		strconv.Itoa(fstype), strconv.Itoa(mntID), strconv.Itoa(rootDev), mountpoint)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "CORPUS_OK") {
		t.Fatalf("generate corpus (fstype=%d mnt_id=%d root_dev=%d): %v\noutput: %s", fstype, mntID, rootDev, err, out)
	}
}

// contentSelftestResult mirrors one element of mountContentAxisPy's --content-selftest output.
type contentSelftestResult struct {
	Outcome        string `json:"outcome"`
	Recreatable    bool   `json:"recreatable"`
	ContentBearing bool   `json:"content_bearing"`
	HasContent     bool   `json:"has_content"`
}

// runContentSelftest runs the PRODUCTION content-axis predicate over the given checkpoint dir and
// entries. It writes only mountContentAxisPy — the exact constant both production decoders prepend.
func runContentSelftest(t *testing.T, ckpt string, entries []map[string]any) []contentSelftestResult {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available — skipping real-predicate selftest")
	}
	scriptPath := filepath.Join(t.TempDir(), "pm-content-axis.py")
	if err := os.WriteFile(scriptPath, []byte(mountContentAxisPy), 0o600); err != nil {
		t.Fatalf("write content-axis script: %v", err)
	}
	payload, err := json.Marshal(map[string]any{"ckpt": ckpt, "entries": entries})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	cmd := exec.Command("python3", scriptPath, "--content-selftest")
	cmd.Stdin = strings.NewReader(string(payload))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("content-axis selftest failed: %v\nstderr: %s", err, stderr.String())
	}
	var results []contentSelftestResult
	if uerr := json.Unmarshal(out, &results); uerr != nil {
		t.Fatalf("parse selftest output: %v\noutput: %s", uerr, out)
	}
	if len(results) != len(entries) {
		t.Fatalf("selftest returned %d results for %d entries", len(results), len(entries))
	}
	return results
}

// ---------------------------------------------------------------------------------------------
// D4 cases (a), (d), (e), (f), (g) — the predicate itself, through the production Python.
// ---------------------------------------------------------------------------------------------

// TestADR0420_D1_ContentAxisPredicate covers the full D1 decision matrix at the predicate level,
// including the cases a protobuf-typed image cannot express.
func TestADR0420_D1_ContentAxisPredicate(t *testing.T) {
	ckpt := t.TempDir()
	// The /dev/shm shape: content present under tmpfs_restore's FIRST lookup name.
	stageTmpfsContentImage(t, ckpt, "tmpfs-dev-144.tar.gz.img")
	// The fallback shape: content present ONLY under tmpfs_restore's SECOND lookup name.
	stageTmpfsContentImage(t, ckpt, "tmpfs-4242.tar.gz.img")

	cases := []struct {
		name        string
		entry       map[string]any
		wantOutcome string
		why         string
	}{
		{
			name:        "a_tmpfs_with_root_dev_content_internalizes",
			entry:       map[string]any{"fstype": 5, "mnt_id": 1889, "root_dev": 144},
			wantOutcome: "internalize",
			why:         "D4(a), the /dev/shm REGRESSION GUARD: a content-bearing recreatable mount whose content IS in the checkpoint must be internalized exactly as before ADR-0420. This is the one internalization that works today, and D1 changes the predicate that decides it.",
		},
		{
			name:        "d_tmpfs_with_mnt_id_fallback_content_internalizes",
			entry:       map[string]any{"fstype": 5, "mnt_id": 4242, "root_dev": 999},
			wantOutcome: "internalize",
			why:         "D4(d): the lookup must mirror tmpfs_restore's OWN two-step order (tmpfs-dev-<root_dev>, THEN tmpfs-<mnt_id>), not just its first step. Checking only the first name would re-externalize a mount that restores fine.",
		},
		{
			name:        "b_c_tmpfs_without_content_is_content_absent",
			entry:       map[string]any{"fstype": 5, "mnt_id": 1890, "root_dev": 69},
			wantOutcome: "content_absent",
			why:         "The decoded live failure: the serviceaccount-token tmpfs, external at dump time so CRIU dumped no content for it. Internalizing it makes tmpfs_restore fail SILENTLY.",
		},
		{
			name:        "devtmpfs_without_content_is_content_absent_failclosed",
			entry:       map[string]any{"fstype": 3, "mnt_id": 7, "root_dev": 8},
			wantOutcome: "content_absent",
			why:         "DEVTMPFS is included in the content-bearing set FAIL-CLOSED without its fstypes[] row being decoded. A wrongly-demanded content image routes to DESTINATION-REBIND, which resolves or hard-stops LOUDLY; a wrongly-skipped check reproduces the silent failure.",
		},
		{
			name:        "e_proc_without_content_still_internalizes",
			entry:       map[string]any{"fstype": 1, "mnt_id": 10, "root_dev": 11},
			wantOutcome: "internalize",
			why:         "D4(e): PROC is kernel-regenerated. CRIU stores no content image for it and demanding one would hard-stop every migration on a mount that restores correctly.",
		},
		{
			name:        "e_sysfs_without_content_still_internalizes",
			entry:       map[string]any{"fstype": 2, "mnt_id": 12, "root_dev": 13},
			wantOutcome: "internalize",
			why:         "D4(e): SYSFS is kernel-regenerated.",
		},
		{
			name:        "e_binfmt_misc_without_content_still_internalizes",
			entry:       map[string]any{"fstype": 4, "mnt_id": 14, "root_dev": 15},
			wantOutcome: "internalize",
			why:         "D4(e): BINFMT_MISC registrations restore from binfmt-misc images, not from a tmpfs content image.",
		},
		{
			name:        "e_devpts_without_content_still_internalizes",
			entry:       map[string]any{"fstype": 6, "mnt_id": 16, "root_dev": 17},
			wantOutcome: "internalize",
			why:         "D4(e): DEVPTS is constructed by devpts_restore.",
		},
		{
			name:        "e_mqueue_without_content_still_internalizes",
			entry:       map[string]any{"fstype": 14, "mnt_id": 18, "root_dev": 19},
			wantOutcome: "internalize",
			why:         "D4(e): CRIU asserts MQUEUE is empty at dump (dump_empty_fs).",
		},
		{
			name:        "f_unsupported_fstype_untouched_by_the_content_axis",
			entry:       map[string]any{"fstype": 0, "mnt_id": 20, "root_dev": 144},
			wantOutcome: "not_recreatable",
			why:         "D4(f): a non-recreatable external is ADR-0417's existing class. It must report not_recreatable even though a matching content image happens to be present — D1 adds no new branch for it, and mislabelling it would corrupt D1b's counter.",
		},
		{
			name:        "f_absent_fstype_untouched_by_the_content_axis",
			entry:       map[string]any{"mnt_id": 21, "root_dev": 144},
			wantOutcome: "not_recreatable",
			why:         "D4(f): an absent fstype is FSTYPE_UNSUPPORTED and falls through fail-closed, unchanged.",
		},
		{
			name:        "g_missing_root_dev_and_mnt_id_is_content_absent",
			entry:       map[string]any{"fstype": 5},
			wantOutcome: "content_absent",
			why:         "D4(g): an entry whose identifiers cannot be read is treated as content ABSENT, never as content present. Fail-closed is the direction that matters.",
		},
		{
			name:        "g_string_root_dev_and_mnt_id_is_content_absent",
			entry:       map[string]any{"fstype": 5, "mnt_id": "144", "root_dev": "144"},
			wantOutcome: "content_absent",
			why:         "D4(g): a malformed or hostile image writing a string where an integer belongs must not be able to name a content image.",
		},
		{
			name:        "g_bool_root_dev_is_content_absent",
			entry:       map[string]any{"fstype": 5, "mnt_id": true, "root_dev": true},
			wantOutcome: "content_absent",
			why:         "D4(g): bool is a subclass of int in Python; without the explicit exclusion True would format as image name 1 and could match an unrelated file.",
		},
	}

	entries := make([]map[string]any, 0, len(cases))
	for _, c := range cases {
		entries = append(entries, c.entry)
	}
	got := runContentSelftest(t, ckpt, entries)

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got[i].Outcome != c.wantOutcome {
				t.Errorf("outcome = %q, want %q\nentry: %v\nwhy this matters: %s", got[i].Outcome, c.wantOutcome, c.entry, c.why)
			}
		})
	}
}

// TestADR0420_D1_PredicateNamesNoPathOrWorkload is the substrate-primitive assertion, made
// mechanically rather than by review.
//
// The shapes ADR-0420 rejects BY NAME are all string-matching shapes: a serviceaccount skip list, a
// SERVICEACCOUNT_MOUNT_PATHS constant, extending the dump-side capture's literal /dev/shm match to
// a second literal path. Every one of them would leave a path literal in this predicate. There is
// none, and there must never be one — the predicate is keyed on a fact about the checkpoint on disk,
// which is why it covers a projected-volume tmpfs, a CSI ephemeral tmpfs and a future
// sidecar-injected credential mount with no new code.
func TestADR0420_D1_PredicateNamesNoPathOrWorkload(t *testing.T) {
	forbidden := []struct {
		token string
		why   string
	}{
		{"serviceaccount", "the predicate must not name the mount that surfaced the defect"},
		{"/dev/shm", "the predicate must not name the one mount a dump-side carve-out was built for"},
		{"secrets", "no per-path allowlist or skip list"},
		{"kubernetes.io", "no runtime-specific path literal"},
		{"postgres", "no workload literal"},
		{"nginx", "no workload literal"},
	}
	lowered := strings.ToLower(mountContentAxisPy)
	for _, f := range forbidden {
		// Comments are part of the shipped string, so this is a genuine constraint on the whole
		// constant, prose included — a path that shows up "only in a comment" is a path someone is
		// reasoning about per-mount.
		if strings.Contains(lowered, f.token) {
			t.Errorf("ADR-0420 D1 is a substrate primitive: %q must not appear in mountContentAxisPy — %s", f.token, f.why)
		}
	}
}

// TestADR0420_PVERIFY4_D1NeverFabricatesContent asserts §P-VERIFY #4 by source inspection.
//
// Fabricating an empty or zero-filled content image to satisfy the check would turn a LOUD failure
// into SILENT DATA LOSS, and is named in the ADR as the single worst way this decision could be
// implemented specifically so a reviewer can look for it. D1's only effects are (i) routing an entry
// to the existing DESTINATION-REBIND branch and (ii) the existing EXTERNAL_MOUNT_UNRESOLVED hard
// stop. This mirrors the dump-side gate's own rule — adr0415_mount_capture_gate.go never fabricates
// zero-filled shared memory either.
func TestADR0420_PVERIFY4_D1NeverFabricatesContent(t *testing.T) {
	writeTokens := []string{"open(", "makedirs", "mkdir", "shutil.copy", "tarfile", "truncate", "write("}
	for _, tok := range writeTokens {
		if strings.Contains(mountContentAxisPy, tok) {
			t.Errorf("§P-VERIFY #4: mountContentAxisPy must be a PURE READ over the checkpoint directory — it contains %q, which is a write/creation primitive. D1 reclassifies; it never fabricates content.", tok)
		}
	}
	if !strings.Contains(mountContentAxisPy, "os.path.exists") {
		t.Error("§P-VERIFY #4: the content check must be an existence test against the checkpoint directory the script already reads (no new argv, no subprocess, no cluster call)")
	}
}

// TestADR0420_PVERIFY5_WithdrawnMarkerIsAbsent asserts §P-VERIFY #5: the withdrawn Revision-2
// ownership-inversion decision left NOTHING behind in code, tests or metrics. Its premise was
// refuted before anything was implemented, and a guard whose closure is empty by construction on the
// substrate's real mount shape must not silently reappear.
func TestADR0420_PVERIFY5_WithdrawnMarkerIsAbsent(t *testing.T) {
	root := repoRootForADR0420(t)
	withdrawn := []string{
		"MOUNT_OWNERSHIP_INVERSION",
		"MountOwnershipInversionError",
		"emitMountOwnershipInversionEvent",
		"MountForestInversionOutcomeTotal",
	}
	var hits []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "adr0420_content_availability_test.go") {
			return nil // this assertion contains the literals it searches for
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, w := range withdrawn {
			if strings.Contains(string(b), w) {
				hits = append(hits, path+": "+w)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("the withdrawn ADR-0420 Revision-2 D1 must exist nowhere in code: %v", hits)
	}
}

// repoRootForADR0420 resolves the repository root from this package's location.
func repoRootForADR0420(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

// ---------------------------------------------------------------------------------------------
// D1c — the lockstep dependency, and the test that would have caught it.
// ---------------------------------------------------------------------------------------------

// TestADR0420_D1c_ContentAxisIsTheSingleDefinitionInBothDecoders is the mechanical form of D1c.
//
// Two decoders ask the internalization question — the patch script's classification loop and the
// Go-side destination-rebind demand scanner. If they diverge, the patch script routes a contentless
// tmpfs to DESTINATION-REBIND while the demand scanner never demands its target, so the target is
// never resolved and the script hard-stops on a mount the destination could have supplied: a FALSE
// STOP ON EVERY MIGRATION. Before ADR-0420 the two carried duplicate RECREATABLE_FSTYPES literals,
// which D1 would have made load-bearing in a second place. They are now one constant rendered into
// both, and this asserts that rather than trusting it.
func TestADR0420_D1c_ContentAxisIsTheSingleDefinitionInBothDecoders(t *testing.T) {
	assembled := assemblePatchScript()
	if !strings.Contains(assembled, mountContentAxisPy) {
		t.Error("the assembled patch script must embed mountContentAxisPy VERBATIM — a paraphrase is a second definition")
	}

	// The demand scanner is assembled at its call site (destinationRebindDemandSet writes
	// mountContentAxisPy + destinationRebindDemandScanPy). Assert both halves of that contract.
	if !strings.Contains(readDemandScanAssemblySource(t), "mountContentAxisPy + destinationRebindDemandScanPy") {
		t.Error("destinationRebindDemandSet must prepend mountContentAxisPy to its scan script, exactly as assemblePatchScript does")
	}

	// Neither decoder may re-declare the predicate. This is the assertion that fails if someone
	// "helpfully" restores a local copy of the frozenset for readability.
	for _, tc := range []struct {
		name string
		body string
	}{
		{"patchCheckpointScriptBody", patchCheckpointScriptBody},
		{"destinationRebindDemandScanPy", destinationRebindDemandScanPy},
	} {
		for _, redecl := range []string{
			"RECREATABLE_FSTYPES = frozenset",
			"CONTENT_BEARING_FSTYPES = frozenset",
			"def _is_recreatable_fstype",
			"def _has_captured_content",
			"def internalization_outcome",
		} {
			if strings.Contains(tc.body, redecl) {
				t.Errorf("%s re-declares %q — there must be exactly ONE definition (mountContentAxisPy), or the two decoders can drift and every migration false-stops", tc.name, redecl)
			}
		}
	}

	// Both decoders must actually CALL the shared decision. A shared definition nobody calls is a
	// shared definition that proves nothing.
	if !strings.Contains(patchCheckpointScriptBody, "internalization_outcome(ckpt, e)") {
		t.Error("the patch script must classify via internalization_outcome — the shared decision, not a local re-derivation")
	}
	if !strings.Contains(destinationRebindDemandScanPy, "internalization_outcome(ckpt, e)") {
		t.Error("the demand scanner must classify via internalization_outcome — the shared decision, not a local re-derivation")
	}
}

// readDemandScanAssemblySource returns adr0419_destination_mounts.go's source, so the assembly
// contract (which is a Go expression, not a string constant) can be asserted.
func readDemandScanAssemblySource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRootForADR0420(t), "internal", "agent", "server", "adr0419_destination_mounts.go"))
	if err != nil {
		t.Fatalf("read adr0419_destination_mounts.go: %v", err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------------------------
// D4 cases (a), (b), (c), (f) END TO END — through the real patch script and real pycriu images.
// ---------------------------------------------------------------------------------------------

// TestADR0420_D1_EndToEndClassification proves the predicate is WIRED, not merely correct: it runs
// production patchCheckpointImages over real mountpoints images and reads back what landed in the
// patched image.
func TestADR0420_D1_EndToEndClassification(t *testing.T) {
	const dst = "/var/lib/kubelet/pods/DESTUID/volumes/kubernetes.io~projected/kube-api-access-xyz"

	t.Run("a_content_present_is_internalized", func(t *testing.T) {
		pypath, extraEnv := pycriuEnv(t)
		ckpt := t.TempDir()
		writeADR0420Corpus(t, pypath, extraEnv, ckpt, 5, 1889, 144, "/dev/shm")
		stageTmpfsContentImage(t, ckpt, "tmpfs-dev-144.tar.gz.img")
		if _, _, err := patchCheckpointImages(ckpt, nil, nil, nil, nil); err != nil {
			t.Fatalf("a content-bearing mount WITH its content must internalize with no destination target: %v", err)
		}
		e := findMountEntry(readMountpointsEntries(t, pypath, extraEnv, ckpt), "/dev/shm")
		if e == nil {
			t.Fatal("/dev/shm missing from the patched image")
		}
		if k, ok := e["ext_key"]; ok && k != nil && k != "" {
			t.Errorf("internalized mount must have ext_key cleared; got %v", k)
		}
		if root, _ := e["root"].(string); root != "/" {
			t.Errorf("internalized mount must have root rewritten to \"/\"; got %q", root)
		}
	})

	t.Run("d_fallback_image_name_is_internalized", func(t *testing.T) {
		pypath, extraEnv := pycriuEnv(t)
		ckpt := t.TempDir()
		writeADR0420Corpus(t, pypath, extraEnv, ckpt, 5, 3527, 172, "/mnt/probe")
		stageTmpfsContentImage(t, ckpt, "tmpfs-3527.tar.gz.img") // ONLY the mnt_id-keyed name
		if _, _, err := patchCheckpointImages(ckpt, nil, nil, nil, nil); err != nil {
			t.Fatalf("content present under tmpfs_restore's SECOND lookup name must still internalize: %v", err)
		}
		e := findMountEntry(readMountpointsEntries(t, pypath, extraEnv, ckpt), "/mnt/probe")
		if e == nil {
			t.Fatal("/mnt/probe missing from the patched image")
		}
		if k, ok := e["ext_key"]; ok && k != nil && k != "" {
			t.Errorf("internalized mount must have ext_key cleared; got %v", k)
		}
	})

	t.Run("b_content_absent_with_target_is_destination_rebind", func(t *testing.T) {
		pypath, extraEnv := pycriuEnv(t)
		ckpt := t.TempDir()
		writeADR0420Corpus(t, pypath, extraEnv, ckpt, 5, 3527, 172, adr0420ServiceAccountPath)
		// No content image staged: this is the live serviceaccount-token shape.
		if _, _, err := patchCheckpointImages(ckpt, nil, nil,
			map[string]string{adr0420ServiceAccountPath: dst}, nil); err != nil {
			t.Fatalf("a contentless recreatable mount with a resolvable destination target must patch cleanly (no hard stop): %v", err)
		}
		e := findMountEntry(readMountpointsEntries(t, pypath, extraEnv, ckpt), adr0420ServiceAccountPath)
		if e == nil {
			t.Fatal("the serviceaccount mount is missing from the patched image")
		}
		if k, _ := e["ext_key"].(string); k != adr0420ServiceAccountPath {
			t.Errorf("DESTINATION-REBIND must PRESERVE ext_key; got %q", k)
		}
		if root, _ := e["root"].(string); root != dst {
			t.Errorf("root must be rewritten to the destination target; got %q", root)
		}
		if src, _ := e["source"].(string); strings.Contains(src, "/src/node/only") {
			t.Errorf("the SOURCE-node path must not survive; got source=%q", src)
		}
	})

	t.Run("c_content_absent_without_target_hard_stops_with_the_new_reason", func(t *testing.T) {
		pypath, extraEnv := pycriuEnv(t)
		ckpt := t.TempDir()
		writeADR0420Corpus(t, pypath, extraEnv, ckpt, 5, 3527, 172, adr0420ServiceAccountPath)
		_, _, err := patchCheckpointImages(ckpt, nil, nil, nil, nil)
		if err == nil {
			t.Fatal("a contentless recreatable mount with NO destination target must hard-stop before CRIU is invoked, never internalize into a silent tmpfs_restore failure")
		}
		var unresolved *ExternalMountUnresolvedError
		if !errors.As(err, &unresolved) {
			t.Fatalf("want ExternalMountUnresolvedError (the EXISTING typed error — D1 adds none); got %T: %v", err, err)
		}
		if unresolved.Reason != "internalize_without_captured_content_and_no_destination_target" {
			t.Errorf("D1a: the reason must distinguish this origin from an ordinary destination-rebind miss so an operator can tell \"the destination never offered this mount\" from \"the checkpoint never captured this mount's content AND the destination did not offer it either\"; got %q", unresolved.Reason)
		}
		// §P-VERIFY #6: the reason must survive into the CR Event message, which is built from
		// Error(). An Event that says only "external mount unresolved" cannot distinguish this cause
		// from a missing PVC target and is a FAIL.
		if !strings.Contains(unresolved.Error(), "internalize_without_captured_content_and_no_destination_target") {
			t.Errorf("§P-VERIFY #6: the reason must reach the Event message (emitExternalMountUnresolvedEvent uses Error()); got %q", unresolved.Error())
		}
	})

	t.Run("f_non_recreatable_keeps_the_pre_existing_reason", func(t *testing.T) {
		pypath, extraEnv := pycriuEnv(t)
		ckpt := t.TempDir()
		writeADR0420Corpus(t, pypath, extraEnv, ckpt, 0, 1780, 66, "/dev/termination-log")
		_, _, err := patchCheckpointImages(ckpt, nil, nil, nil, nil)
		var unresolved *ExternalMountUnresolvedError
		if !errors.As(err, &unresolved) || unresolved.Reason != "destination_rebind_target_unresolved" {
			t.Fatalf("D4(f): a non-recreatable external is ADR-0417's existing class and must keep its existing reason — D1 adds no new branch for it; got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------------------------
// D1b — the outcome must be countable, on all three paths.
// ---------------------------------------------------------------------------------------------

// TestADR0420_D1b_OutcomeIsCountableOnAllThreePaths asserts §P-VERIFY #7.
//
// Today the transition "internalized a mount with no content" is not merely unattributed, it is
// UNCOUNTED. rebound_content_absent is the label that matters: it is the population that was
// silently mis-handled before this ADR, and a zero on a real migration means D1 is not doing
// anything.
func TestADR0420_D1b_OutcomeIsCountableOnAllThreePaths(t *testing.T) {
	const absent = adr0420ServiceAccountPath
	const hostSrc = "/var/lib/kubelet/pods/DESTUID/volumes/kubernetes.io~projected/kube-api-access-xyz"

	withDemand := func(d destinationRebindDemand) func() {
		orig := destinationRebindDemandSetFn
		destinationRebindDemandSetFn = func(context.Context, string, string) (destinationRebindDemand, error) {
			return d, nil
		}
		return func() { destinationRebindDemandSetFn = orig }
	}

	t.Run("internalized_with_content", func(t *testing.T) {
		before := testutil.ToFloat64(metrics.MountContentAvailabilityOutcomeTotal.WithLabelValues("internalized_with_content"))
		defer withDemand(destinationRebindDemand{InternalizedWithContent: 2})()
		var outcome string
		var attempts int
		defer withObserve(t, &outcome, &attempts)()
		s := newADR0417Server(t)
		if _, err := s.appendDestinationRebindReattachMounts(
			context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID, nil, nil); err != nil {
			t.Fatalf("a checkpoint that demands nothing must resolve cleanly: %v", err)
		}
		after := testutil.ToFloat64(metrics.MountContentAvailabilityOutcomeTotal.WithLabelValues("internalized_with_content"))
		if after-before != 2 {
			t.Errorf("internalized_with_content must be counted once per content-bearing recreatable external that KEPT its content, so the denominator is real; delta = %v, want 2", after-before)
		}
	})

	t.Run("rebound_content_absent", func(t *testing.T) {
		before := testutil.ToFloat64(metrics.MountContentAvailabilityOutcomeTotal.WithLabelValues("rebound_content_absent"))
		defer withDemand(destinationRebindDemand{Paths: []string{absent}, ContentAbsent: []string{absent}})()
		var outcome string
		var attempts int
		defer withObserve(t, &outcome, &attempts)()
		s := newADR0417Server(t)
		got, err := s.appendDestinationRebindReattachMounts(
			context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID,
			[]nri.ContainerMount{{Destination: absent, Type: "bind", Source: hostSrc}}, nil)
		if err != nil {
			t.Fatalf("a content-absent mount the destination DOES offer must resolve, not hard-stop: %v", err)
		}
		if len(got) != 1 || got[0].HostTarget != hostSrc {
			t.Fatalf("the destination's own mount must be the resolved target; got %+v", got)
		}
		after := testutil.ToFloat64(metrics.MountContentAvailabilityOutcomeTotal.WithLabelValues("rebound_content_absent"))
		if after-before != 1 {
			t.Errorf("rebound_content_absent is THE counter that matters — it is the population silently mis-handled before ADR-0420; delta = %v, want 1", after-before)
		}
	})

	t.Run("unresolved_content_absent", func(t *testing.T) {
		before := testutil.ToFloat64(metrics.MountContentAvailabilityOutcomeTotal.WithLabelValues("unresolved_content_absent"))
		defer withDemand(destinationRebindDemand{Paths: []string{absent}, ContentAbsent: []string{absent}})()
		var outcome string
		var attempts int
		defer withObserve(t, &outcome, &attempts)()
		s := newADR0417Server(t)
		// The runtime supplies a DIFFERENT mount, so the demanded one is genuinely absent.
		_, err := s.appendDestinationRebindReattachMounts(
			context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID,
			[]nri.ContainerMount{{Destination: "/etc/hosts", Type: "bind", Source: "/somewhere/hosts"}}, nil)
		var absentErr *DestinationRuntimeMountAbsentError
		if !errors.As(err, &absentErr) {
			t.Fatalf("a content-absent mount the destination does NOT offer must fail closed with the named terminal; got %v", err)
		}
		after := testutil.ToFloat64(metrics.MountContentAvailabilityOutcomeTotal.WithLabelValues("unresolved_content_absent"))
		if after-before != 1 {
			t.Errorf("unresolved_content_absent must be distinguishable from an ordinary destination-rebind miss; delta = %v, want 1", after-before)
		}
	})
}

// ---------------------------------------------------------------------------------------------
// D1d — /run vs /var/run: the named, pre-identified blocker on D1's fallback.
// ---------------------------------------------------------------------------------------------

// TestADR0420_D1d_RunAndVarRunAreTheSameMount is the assertion that keeps D1 from converting a
// SILENT restore failure into a DestinationRuntimeMountAbsent hard stop on every migration.
//
// The checkpoint records what the kernel's mount table says (/run/secrets/...); a pod spec's
// serviceaccount mountPath is /var/run/secrets/..., and /var/run is a symlink to /run in essentially
// every base image. ADR-0419's lookup matches by exact string equality and was correct for every
// path it shipped against, none of which traverses a symlinked parent. D1 routes a new member
// through the same lookup, and this is the pre-identified risk stated as blocking rather than as a
// footnote.
func TestADR0420_D1d_RunAndVarRunAreTheSameMount(t *testing.T) {
	t.Run("normalization_is_narrow_and_anchored", func(t *testing.T) {
		cases := map[string]string{
			"/var/run": "/run",
			"/var/run/secrets/kubernetes.io/serviceaccount": "/run/secrets/kubernetes.io/serviceaccount",
			"/run/secrets/kubernetes.io/serviceaccount":     "/run/secrets/kubernetes.io/serviceaccount",
			"/var/runtime/data":                             "/var/runtime/data", // component boundary, not a prefix match
			"/var/runsomething":                             "/var/runsomething",
			"/etc/hosts":                                    "/etc/hosts",
			"/data/var/run/x":                               "/data/var/run/x", // anchored at the start only
			"":                                              "",
		}
		for in, want := range cases {
			if got := normalizeContainerMountPath(in); got != want {
				t.Errorf("normalizeContainerMountPath(%q) = %q, want %q", in, got, want)
			}
		}
	})

	t.Run("demanded_run_resolves_against_runtime_var_run", func(t *testing.T) {
		const hostSrc = "/var/lib/kubelet/pods/DESTUID/volumes/kubernetes.io~projected/kube-api-access-xyz"
		got, err := resolveDestinationRebindTargets(
			[]string{adr0420ServiceAccountPath},
			[]nri.ContainerMount{{Destination: "/var/run/secrets/kubernetes.io/serviceaccount", Source: hostSrc}},
			adr0417Migration, adr0417SandboxID, "test")
		if err != nil {
			t.Fatalf("D1d: /run/... demanded and /var/run/... supplied denote the SAME mount; an exact-equality miss here hard-stops every migration: %v", err)
		}
		if len(got) != 1 || got[0].HostTarget != hostSrc {
			t.Fatalf("want the runtime's Source as the host target; got %+v", got)
		}
		// The resolved ContainerPath must remain the CHECKPOINT's literal spelling: it is the key
		// the patch script looks its host target up by (reattach_host_targets.get(mp)). Normalizing
		// it here would silently unresolve the mount one layer down.
		if got[0].ContainerPath != adr0420ServiceAccountPath {
			t.Errorf("ContainerPath must stay the checkpoint's own literal mountpoint (the patch script's lookup key); got %q", got[0].ContainerPath)
		}
	})

	t.Run("normalization_does_not_invent_a_mount", func(t *testing.T) {
		_, err := resolveDestinationRebindTargets(
			[]string{adr0420ServiceAccountPath},
			[]nri.ContainerMount{{Destination: "/etc/hosts", Source: "/somewhere/hosts"}},
			adr0417Migration, adr0417SandboxID, "test")
		var absentErr *DestinationRuntimeMountAbsentError
		if !errors.As(err, &absentErr) {
			t.Fatalf("normalization must not weaken the fail-closed leg — a mount the runtime genuinely did not supply must still be a named terminal; got %v", err)
		}
	})
}
