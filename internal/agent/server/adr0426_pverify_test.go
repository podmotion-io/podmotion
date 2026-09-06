/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0426_pverify_test.go — the ADR-0426 §P-VERIFY assertions the two-reviewer round found NOT YET
// IMPLEMENTED: V1, V2, V2b, V2c, V4, V5 (third-consumer extension), V6b, V6c. Every fixture here
// routes real bytes through the shipped production primitives (captureContentAbsentMounts,
// mountHostSourceDir, the mountContentAxisPy --content-selftest entry point) — never a Go
// re-implementation of the decision — and uses withHostRunRootForTest (adr0426_test_seam_test.go) so
// every test that needs a real, reachable source directory runs unconditionally, on any machine.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// readTarGzSizes returns a map of member name -> byte size for a gzip tarball, so a captured
// content image's exact byte count can be asserted (readTarGz only checks membership).
func readTarGzSizes(t *testing.T, path string) map[string]int64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("output is not a valid gzip stream: %v", err)
	}
	defer gz.Close()
	sizes := map[string]int64{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		sizes[h.Name] = h.Size
	}
	return sizes
}

// pverifyMountSpec is one mountpoints-*.img entry for pverifyWriteCorpus.
type pverifyMountSpec struct {
	FSType     int    `json:"fstype"`
	MntID      int    `json:"mnt_id"`
	RootDev    int    `json:"root_dev"`
	Mountpoint string `json:"mountpoint"`
	Source     string `json:"source"`
	ExtKey     string `json:"ext_key"`
}

// pverifyRegSpec is one files.img REG entry for pverifyWriteCorpus.
type pverifyRegSpec struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	MntID int    `json:"mnt_id"`
	Mode  int    `json:"mode"`
}

// pverifyWriteCorpus writes an overlay-root + caller-supplied mounts mountpoints-10.img, and,
// when regs is non-nil (even if empty), a files.img carrying exactly those REG entries. A nil regs
// means "write no files.img at all" (the zero-demand shape most ADR-0426 fixtures need).
func pverifyWriteCorpus(t *testing.T, imagesDir string, mounts []pverifyMountSpec, regs []pverifyRegSpec) {
	t.Helper()
	pypath, extraEnv := pycriuEnv(t)
	const genPy = `
import sys, os, json
import pycriu
d = sys.argv[1]
spec = json.loads(sys.argv[2])
mnts = [
    {'fstype': 17, 'mnt_id': 1, 'root_dev': 0, 'parent_mnt_id': 0, 'flags': 0,
     'root': '/', 'mountpoint': '/', 'source': 'overlay', 'options': '', 'sb_flags': 0},
]
for m in spec['mounts']:
    e = {'fstype': m['fstype'], 'mnt_id': m['mnt_id'], 'root_dev': m['root_dev'],
         'parent_mnt_id': 1, 'flags': 0, 'root': '/', 'mountpoint': m['mountpoint'],
         'source': m['source'], 'options': '', 'sb_flags': 0}
    if m.get('ext_key'):
        e['ext_key'] = m['ext_key']
    mnts.append(e)
with open(os.path.join(d, 'mountpoints-10.img'), 'wb') as f:
    pycriu.images.dump({'magic': 'MNTS', 'entries': mnts}, f)

if spec.get('regs') is not None:
    _FOWN = {'uid': 0, 'euid': 0, 'signum': 0, 'pid_type': 0, 'pid': 0}
    entries = []
    for r in spec['regs']:
        entries.append({'type': 'REG', 'id': r['id'],
            'reg': {'id': r['id'], 'flags': 2, 'pos': 0, 'fown': _FOWN,
                    'name': r['name'], 'mnt_id': r['mnt_id'], 'mode': r['mode'], 'ext': False}})
    with open(os.path.join(d, 'files.img'), 'wb') as f:
        pycriu.images.dump({'magic': 'FILES', 'entries': entries}, f)
print('CORPUS_OK')
`
	genPath := filepath.Join(t.TempDir(), "adr0426-pverify-gen.py")
	if err := os.WriteFile(genPath, []byte(genPy), 0o600); err != nil {
		t.Fatalf("write corpus gen: %v", err)
	}
	specMap := map[string]any{"mounts": mounts}
	if regs != nil {
		specMap["regs"] = regs
	}
	spec, err := json.Marshal(specMap)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	cmd := exec.Command("python3", genPath, imagesDir, string(spec))
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "CORPUS_OK") {
		t.Fatalf("generate pverify corpus: %v\n%s", err, out)
	}
}

// pverifyWriteConfigJSON writes a minimal OCI config.json binding mountpoint -> source.
func pverifyWriteConfigJSON(t *testing.T, imagesDir, mountpoint, source string) {
	t.Helper()
	body := `{"mounts":[{"destination":"` + mountpoint + `","type":"bind","source":"` + source + `"}]}`
	if err := os.WriteFile(filepath.Join(imagesDir, "config.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
}

// pverifyContentSelftest feeds one mountpoints-shaped entry through the SHIPPED
// mountContentAxisPy --content-selftest entry point (never a Go re-implementation) and returns its
// outcome string.
func pverifyContentSelftest(t *testing.T, ckpt string, entry map[string]any) string {
	t.Helper()
	results := runContentSelftest(t, ckpt, []map[string]any{entry})
	return results[0].Outcome
}

// ---------------------------------------------------------------------------------------------
// V1 — the mandated reproduction.
// ---------------------------------------------------------------------------------------------

// TestADR0426_ContentAbsentMountWithRegFileDemand_IsCapturedAtDump is §P-VERIFY V1: a content-absent
// mount with a live REG-file demand IS captured, and the join back to INTERNALIZE_OK holds.
func TestADR0426_ContentAbsentMountWithRegFileDemand_IsCapturedAtDump(t *testing.T) {
	imagesDir := t.TempDir()
	hostRunDir := t.TempDir()
	withHostRunRootForTest(t, hostRunDir)

	const rootDev = 361
	const mntID = 3
	pverifyWriteCorpus(t, imagesDir,
		[]pverifyMountSpec{{FSType: 5, MntID: mntID, RootDev: rootDev, Mountpoint: "/dev/shm", Source: "shm", ExtKey: "CRIU:AUTOGENERATED"}},
		[]pverifyRegSpec{{ID: 1, Name: "/dev/shm/PostgreSQL.1027000072", MntID: mntID, Mode: 0o100600}},
	)
	pverifyWriteConfigJSON(t, imagesDir, "/dev/shm", "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/8nqtg/shm")
	shmSrc := filepath.Join(hostRunDir, "k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/8nqtg/shm")
	if err := os.MkdirAll(shmSrc, 0o755); err != nil {
		t.Fatalf("create fixture source dir: %v", err)
	}
	payload := make([]byte, 1048576)
	if err := os.WriteFile(filepath.Join(shmSrc, "PostgreSQL.1027000072"), payload, 0o600); err != nil {
		t.Fatalf("write fixture segment file: %v", err)
	}

	out, err := captureContentAbsentMounts(context.Background(), imagesDir)
	if err != nil {
		t.Fatalf("V1: captureContentAbsentMounts must return nil for a reachable content-absent mount; got %v", err)
	}
	if len(out.Captured) != 1 {
		t.Fatalf("V1: expected exactly one captured mount; got %+v", out)
	}

	imgPath := filepath.Join(imagesDir, tmpfsContentImageName(rootDev))
	if _, statErr := os.Stat(imgPath); statErr != nil {
		t.Fatalf("V1: expected %s to exist: %v", imgPath, statErr)
	}
	members := readTarGz(t, imgPath)
	if !members["./PostgreSQL.1027000072"] {
		t.Fatalf("V1: content image missing ./PostgreSQL.1027000072; members=%v", members)
	}
	sizes := readTarGzSizes(t, imgPath)
	if got := sizes["./PostgreSQL.1027000072"]; got != 1048576 {
		t.Fatalf("V1: expected ./PostgreSQL.1027000072 at exactly 1048576 bytes; got %d", got)
	}

	// The join: feed the resulting directory to internalization_outcome via --content-selftest.
	outcome := pverifyContentSelftest(t, imagesDir, map[string]any{
		"fstype": 5, "mnt_id": mntID, "root_dev": rootDev,
	})
	if outcome != "internalize" {
		t.Fatalf("V1: the join — internalization_outcome must now return INTERNALIZE_OK for this entry; got %q", outcome)
	}
}

// ---------------------------------------------------------------------------------------------
// V2 — the single most important assertion change in this revision: empty-but-reachable source
// STILL gets a content image written (not skipped), and that image keeps the mount INTERNALIZE_OK.
// Fixture shape matches the live grl96 baseline (F8a): a 96-byte single-"./"-member tar.
// ---------------------------------------------------------------------------------------------

// TestADR0426_ContentAbsentMountWithEmptyReachableSource_IsStillCaptured is §P-VERIFY V2.
func TestADR0426_ContentAbsentMountWithEmptyReachableSource_IsStillCaptured(t *testing.T) {
	imagesDir := t.TempDir()
	hostRunDir := t.TempDir()
	withHostRunRootForTest(t, hostRunDir)

	const rootDev = 290 // grl96's live root_dev (F8a)
	const mntID = 3700  // grl96's live mnt_id (F8a)
	pverifyWriteCorpus(t, imagesDir,
		[]pverifyMountSpec{{FSType: 5, MntID: mntID, RootDev: rootDev, Mountpoint: "/dev/shm", Source: "shm", ExtKey: "/dev/shm"}},
		nil, // no files.img at all: zero demand, exactly the grl96 shape
	)
	pverifyWriteConfigJSON(t, imagesDir, "/dev/shm", "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/grl96/shm")
	shmSrc := filepath.Join(hostRunDir, "k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/grl96/shm")
	if err := os.MkdirAll(shmSrc, 0o755); err != nil {
		t.Fatalf("create fixture source dir (exists and empty, exactly redis's live shape): %v", err)
	}

	out, err := captureContentAbsentMounts(context.Background(), imagesDir)
	if err != nil {
		t.Fatalf("V2: an empty but reachable source must capture, not fail closed or skip: %v", err)
	}
	if len(out.Captured) != 1 {
		t.Fatalf("V2: expected the empty mount counted CAPTURED (never a 'nothing_to_capture'/skip outcome); got %+v", out)
	}

	imgPath := filepath.Join(imagesDir, tmpfsContentImageName(rootDev))
	info, statErr := os.Stat(imgPath)
	if statErr != nil {
		t.Fatalf("V2: tmpfs-dev-%d.tar.gz.img MUST be written even for a genuinely empty source; %v", rootDev, statErr)
	}
	members := readTarGz(t, imgPath)
	if len(members) != 1 || !members["./"] {
		t.Fatalf("V2: expected exactly one member, \"./\" (CRIU's own dump_tmpfs shape for an empty tmpfs); got %v", members)
	}
	t.Logf("V2: empty-source content image is %d bytes (live grl96 baseline: 96 bytes)", info.Size())

	// The load-bearing half: internalization_outcome must return INTERNALIZE_OK, not
	// INTERNALIZE_CONTENT_ABSENT, so the mount is INTERNALIZED (ext_key popped) and NOT
	// destination-rebound.
	outcome := pverifyContentSelftest(t, imagesDir, map[string]any{
		"fstype": 5, "mnt_id": mntID, "root_dev": rootDev,
	})
	if outcome != "internalize" {
		t.Fatalf("V2: the load-bearing join — an empty-but-captured mount must classify INTERNALIZE_OK, never INTERNALIZE_CONTENT_ABSENT; got %q", outcome)
	}
}

// ---------------------------------------------------------------------------------------------
// V2b — reachable, non-empty source is captured EVEN AT ZERO DEMAND (F7b's written-and-closed
// scratch-file shape). This is the mechanical guard against re-introducing demand-gated capture.
// ---------------------------------------------------------------------------------------------

// TestADR0426_ReachableNonEmptySourceIsCapturedEvenWithZeroDemand is §P-VERIFY V2b.
func TestADR0426_ReachableNonEmptySourceIsCapturedEvenWithZeroDemand(t *testing.T) {
	imagesDir := t.TempDir()
	hostRunDir := t.TempDir()
	withHostRunRootForTest(t, hostRunDir)

	const rootDev = 130
	const mntID = 3977
	// files.img is written (regs non-nil) but carries ZERO entries under this mnt_id — the
	// written-and-closed shape: nothing holds the file open at freeze, yet the bytes are real.
	pverifyWriteCorpus(t, imagesDir,
		[]pverifyMountSpec{{FSType: 5, MntID: mntID, RootDev: rootDev, Mountpoint: "/dev/shm", Source: "shm", ExtKey: "/dev/shm"}},
		[]pverifyRegSpec{}, // files.img present, zero REG entries
	)
	pverifyWriteConfigJSON(t, imagesDir, "/dev/shm", "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/5qnzj/shm")
	shmSrc := filepath.Join(hostRunDir, "k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/5qnzj/shm")
	if err := os.MkdirAll(shmSrc, 0o755); err != nil {
		t.Fatalf("create fixture source dir: %v", err)
	}
	scratch := make([]byte, 4096)
	if err := os.WriteFile(filepath.Join(shmSrc, "scratch.tmp"), scratch, 0o600); err != nil {
		t.Fatalf("write scratch file: %v", err)
	}

	out, err := captureContentAbsentMounts(context.Background(), imagesDir)
	if err != nil {
		t.Fatalf("V2b: a reachable non-empty source must capture even at zero demand; got %v", err)
	}
	if len(out.Captured) != 1 {
		t.Fatalf("V2b: expected one captured mount; got %+v", out)
	}
	imgPath := filepath.Join(imagesDir, tmpfsContentImageName(rootDev))
	members := readTarGz(t, imgPath)
	if !members["./scratch.tmp"] {
		t.Fatalf("V2b: expected ./scratch.tmp in the captured image; members=%v", members)
	}
}

// ---------------------------------------------------------------------------------------------
// V2c — the capture leg reads NO property of the source directory but reachability. Table-driven
// over source shapes that differ ONLY in content; every row must capture.
// ---------------------------------------------------------------------------------------------

// TestADR0426_CaptureLegReadsNoPropertyOfTheSourceDirectoryButReachability is §P-VERIFY V2c.
func TestADR0426_CaptureLegReadsNoPropertyOfTheSourceDirectoryButReachability(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, dir string)
	}{
		{"empty", func(t *testing.T, dir string) {}},
		{"one_zero_byte_file", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "zero"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"one_4096_byte_file", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "four-k"), make([]byte, 4096), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"1000_small_files", func(t *testing.T, dir string) {
			for i := 0; i < 1000; i++ {
				if err := os.WriteFile(filepath.Join(dir, "f"+strings.Repeat("x", i%5+1)+".dat"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"subdirectory_tree", func(t *testing.T, dir string) {
			nested := filepath.Join(dir, "a", "b", "c")
			if err := os.MkdirAll(nested, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(nested, "leaf"), []byte("leaf-bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"sparse_file", func(t *testing.T, dir string) {
			f, err := os.Create(filepath.Join(dir, "sparse"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := f.Truncate(1 << 20); err != nil {
				t.Fatal(err)
			}
		}},
		{"dangling_symlink", func(t *testing.T, dir string) {
			if err := os.Symlink("/nonexistent/target", filepath.Join(dir, "dangling")); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imagesDir := t.TempDir()
			hostRunDir := t.TempDir()
			withHostRunRootForTest(t, hostRunDir)

			rootDev := 400 + i
			mntID := 4000 + i
			pverifyWriteCorpus(t, imagesDir,
				[]pverifyMountSpec{{FSType: 5, MntID: mntID, RootDev: rootDev, Mountpoint: "/dev/shm", Source: "shm", ExtKey: "/dev/shm"}},
				nil,
			)
			pverifyWriteConfigJSON(t, imagesDir, "/dev/shm", "/run/sandboxes/v2c/shm")
			shmSrc := filepath.Join(hostRunDir, "sandboxes/v2c/shm")
			if err := os.MkdirAll(shmSrc, 0o755); err != nil {
				t.Fatalf("create fixture source dir: %v", err)
			}
			c.build(t, shmSrc)

			out, err := captureContentAbsentMounts(context.Background(), imagesDir)
			if err != nil {
				t.Fatalf("V2c[%s]: must capture regardless of source content shape; got %v", c.name, err)
			}
			if len(out.Captured) != 1 {
				t.Fatalf("V2c[%s]: expected outcome=captured; got %+v (a design that reintroduces an emptiness/property test fails here)", c.name, out)
			}
			if len(out.DestinationReconstructable) != 0 || len(out.AlreadyPresent) != 0 {
				t.Fatalf("V2c[%s]: no outcome label other than captured may be emitted by this leg; got %+v", c.name, out)
			}
			if _, statErr := os.Stat(filepath.Join(imagesDir, tmpfsContentImageName(int64(rootDev)))); statErr != nil {
				t.Fatalf("V2c[%s]: expected a content image to be written: %v", c.name, statErr)
			}
			outcome := pverifyContentSelftest(t, imagesDir, map[string]any{
				"fstype": 5, "mnt_id": mntID, "root_dev": rootDev,
			})
			if outcome != "internalize" {
				t.Fatalf("V2c[%s]: expected INTERNALIZE_OK; got %q", c.name, outcome)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// V4 — the capture image name matches the restore-side lookup, across a table of root_dev values.
// ---------------------------------------------------------------------------------------------

// TestADR0426_CaptureImageNameMatchesTheRestoreSideLookup is §P-VERIFY V4.
func TestADR0426_CaptureImageNameMatchesTheRestoreSideLookup(t *testing.T) {
	for _, rootDev := range []int64{1, 130, 290, 361, 999999} {
		t.Run("", func(t *testing.T) {
			ckpt := t.TempDir()
			name := tmpfsContentImageName(rootDev)
			if err := os.WriteFile(filepath.Join(ckpt, name), []byte("x"), 0o600); err != nil {
				t.Fatalf("stage %s: %v", name, err)
			}
			outcome := pverifyContentSelftest(t, ckpt, map[string]any{
				"fstype": 5, "mnt_id": rootDev + 1000000, "root_dev": rootDev,
			})
			if outcome != "internalize" {
				t.Fatalf("root_dev=%d: tmpfsContentImageName produced %q, which _has_captured_content (via --content-selftest) did not recognize; got outcome=%q", rootDev, name, outcome)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// V5 — the content-axis primitive is the SAME single definition across ALL THREE decoder call
// sites, not just two (round-3 D1c required THREE; contentCaptureDemandScanPy was the exempted
// third consumer).
// ---------------------------------------------------------------------------------------------

// TestADR0426_ContentAxisIsTheSingleDefinitionInAllThreeDecoders is §P-VERIFY V5.
func TestADR0426_ContentAxisIsTheSingleDefinitionInAllThreeDecoders(t *testing.T) {
	assembled := assemblePatchScript()
	if !strings.Contains(assembled, mountContentAxisPy) {
		t.Error("assemblePatchScript must embed mountContentAxisPy verbatim")
	}
	if !strings.Contains(readDemandScanAssemblySource(t), "mountContentAxisPy + destinationRebindDemandScanPy") {
		t.Error("destinationRebindDemandSet must prepend mountContentAxisPy verbatim")
	}
	// The third consumer: contentCaptureDemandScan assembles its script inline via
	// createScratchScript("pm-capture-scan-*.py", mountContentAxisPy+contentCaptureDemandScanPy) —
	// read the production source and assert the concatenation is present, exactly as the other two
	// call sites are asserted via their own assembly source.
	captureSrc := readADR0426CaptureSource(t)
	if !strings.Contains(captureSrc, "mountContentAxisPy+contentCaptureDemandScanPy") {
		t.Error("contentCaptureDemandScan must prepend mountContentAxisPy verbatim to contentCaptureDemandScanPy — this is the THIRD consumer D1c requires and round 2 undercounted")
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{"patchCheckpointScriptBody", patchCheckpointScriptBody},
		{"destinationRebindDemandScanPy", destinationRebindDemandScanPy},
		{"contentCaptureDemandScanPy", contentCaptureDemandScanPy},
	} {
		for _, redecl := range []string{
			"RECREATABLE_FSTYPES = frozenset",
			"CONTENT_BEARING_FSTYPES = frozenset",
			"def _is_recreatable_fstype",
			"def _has_captured_content",
			"def internalization_outcome",
		} {
			if strings.Contains(tc.body, redecl) {
				t.Errorf("%s re-declares %q — there must be exactly ONE definition across all three consumers", tc.name, redecl)
			}
		}
	}

	if !strings.Contains(contentCaptureDemandScanPy, "internalization_outcome(ckpt, e)") {
		t.Error("contentCaptureDemandScanPy must classify via the shared internalization_outcome, not a local re-derivation")
	}
}

// readADR0426CaptureSource returns adr0426_dump_side_content_capture.go's source text.
func readADR0426CaptureSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRootForADR0420(t), "internal", "agent", "server", "adr0426_dump_side_content_capture.go"))
	if err != nil {
		t.Fatalf("read adr0426_dump_side_content_capture.go: %v", err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------------------------
// V6b — a forced mountpoints/files scan failure genuinely fails closed, distinguishable from a
// legitimate zero-entry scan result.
// ---------------------------------------------------------------------------------------------

// TestADR0426_ScanFailureFailsClosedAndIsNotASilentNoOp is §P-VERIFY V6b.
func TestADR0426_ScanFailureFailsClosedAndIsNotASilentNoOp(t *testing.T) {
	t.Run("unparseable_mountpoints_image", func(t *testing.T) {
		imagesDir := t.TempDir()
		// Not a valid CRIU image at all: pycriu.images.load raises on the malformed magic/payload,
		// which the scan script does not catch (D1a-SCAN) -> non-zero exit.
		if err := os.WriteFile(filepath.Join(imagesDir, "mountpoints-10.img"), []byte("not a criu image"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := captureContentAbsentMounts(context.Background(), imagesDir)
		if err == nil {
			t.Fatal("V6b: an unparseable mountpoints image must fail closed, never proceed as a zero-entry scan")
		}
		if !errors.Is(err, ErrMountContentCaptureFailed) {
			t.Fatalf("expected errors.Is(err, ErrMountContentCaptureFailed); got %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(imagesDir, tmpfsContentImageName(0))); statErr == nil {
			t.Fatal("V6b: no content image should be written on a scan failure")
		}
		st := newMountContentCaptureFailedStatus(err)
		if status.Code(st) != codes.FailedPrecondition {
			t.Fatalf("V6b: the checkpoint must not proceed — expected codes.FailedPrecondition; got %v", status.Code(st))
		}
	})

	t.Run("forced_non_zero_exit_via_permission_denied", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: a chmod 0000 permission-denied fixture cannot force a read failure")
		}
		imagesDir := t.TempDir()
		hostRunDir := t.TempDir()
		withHostRunRootForTest(t, hostRunDir)
		pverifyWriteCorpus(t, imagesDir,
			[]pverifyMountSpec{{FSType: 5, MntID: 3, RootDev: 361, Mountpoint: "/dev/shm", Source: "shm", ExtKey: "/dev/shm"}},
			nil,
		)
		mpImg := filepath.Join(imagesDir, "mountpoints-10.img")
		if err := os.Chmod(mpImg, 0o000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(mpImg, 0o600)

		_, err := captureContentAbsentMounts(context.Background(), imagesDir)
		if err == nil {
			t.Fatal("V6b: a scan subprocess forced to fail (permission denied reading the mountpoints image) must fail closed, never emit a silent zero-entry result")
		}
		if !errors.Is(err, ErrMountContentCaptureFailed) {
			t.Fatalf("expected errors.Is(err, ErrMountContentCaptureFailed); got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------------------------
// V6c — the /var/run -> /run normalization is actually exercised at THIS call site, not assumed
// to work because it delegates to ADR-0419's normalizeContainerMountPath.
// ---------------------------------------------------------------------------------------------

// TestADR0426_VarRunMountpointAliasResolvesToItsOCIEntry is §P-VERIFY V6c.
func TestADR0426_VarRunMountpointAliasResolvesToItsOCIEntry(t *testing.T) {
	t.Run("var_run_destination_matches_run_mountpoint", func(t *testing.T) {
		imagesDir := t.TempDir()
		// config.json spells the destination /var/run/... (as production actually records it,
		// F8c); the mountpoints image spells the mountpoint /run/... .
		pverifyWriteConfigJSON(t, imagesDir, "/var/run/secrets/kubernetes.io/serviceaccount",
			"/var/lib/kubelet/pods/uid/volumes/kubernetes.io~projected/kube-api-access-xyz")

		hostDir, ociSource, ok, origin := mountHostSourceDir(imagesDir,
			"/run/secrets/kubernetes.io/serviceaccount", "tmpfs")
		if !ok {
			// This mount's OCI source is under /var/lib/kubelet, so it is correctly unreachable —
			// what matters here is that the OCI ENTRY was found at all (ociSource populated),
			// proving the /var/run normalization matched it rather than missing it entirely.
			if ociSource == "" {
				t.Fatalf("V6c: expected the /var/run-spelled config.json entry to be FOUND via normalization (ociSource populated) even though it is unreachable; got ociSource=%q origin=%q", ociSource, origin)
			}
		}
		if ociSource != "/var/lib/kubelet/pods/uid/volumes/kubernetes.io~projected/kube-api-access-xyz" {
			t.Fatalf("V6c: expected the normalized lookup to find the OCI entry and return its Source; got %q (hostDir=%q ok=%v)", ociSource, hostDir, ok)
		}
		class := mountSourceReconstructability(ociSource, "tmpfs")
		if class != sourceClassReconstructable {
			t.Fatalf("V6c: a projected-volume OCI source found via /var/run normalization must classify RECONSTRUCTABLE; got %v", class)
		}
	})

	t.Run("without_normalization_the_entry_would_be_missed_and_fail_closed", func(t *testing.T) {
		// Negative control: no OCI entry under EITHER spelling -> WORKLOAD_STATE, fail closed.
		// This is what production would do for every migration if /var/run -> /run normalization
		// broke silently (F8c fact 3): every migration on this cluster hard-stops.
		imagesDir := t.TempDir()
		pverifyWriteConfigJSON(t, imagesDir, "/some/unrelated/destination", "/var/lib/kubelet/pods/uid/x")

		_, ociSource, ok, _ := mountHostSourceDir(imagesDir, "/run/secrets/kubernetes.io/serviceaccount", "tmpfs")
		if ok {
			t.Fatal("V6c negative control: expected ok=false with no matching OCI entry under either spelling")
		}
		class := mountSourceReconstructability(ociSource, "tmpfs")
		if class != sourceClassWorkloadState {
			t.Fatalf("V6c negative control: no OCI entry under either spelling must classify WORKLOAD_STATE (fail closed); got %v", class)
		}
	})

	t.Run("end_to_end_through_captureContentAbsentMounts_does_not_fail_closed", func(t *testing.T) {
		// The end-to-end proof named in F8c fact 3: an un-normalized lookup would hard-stop this
		// checkpoint. With normalization it must skip cleanly (destination_reconstructable).
		imagesDir := t.TempDir()
		pverifyWriteCorpus(t, imagesDir,
			[]pverifyMountSpec{{
				FSType: 5, MntID: 9, RootDev: 393,
				Mountpoint: "/run/secrets/kubernetes.io/serviceaccount",
				Source:     "tmpfs", ExtKey: "/run/secrets/kubernetes.io/serviceaccount",
			}},
			nil,
		)
		pverifyWriteConfigJSON(t, imagesDir, "/var/run/secrets/kubernetes.io/serviceaccount",
			"/var/lib/kubelet/pods/uid/volumes/kubernetes.io~projected/kube-api-access-xyz")

		out, err := captureContentAbsentMounts(context.Background(), imagesDir)
		if err != nil {
			t.Fatalf("V6c: without /var/run normalization every migration on this cluster hard-stops (F8c fact 3) — expected nil, got %v", err)
		}
		if len(out.DestinationReconstructable) != 1 {
			t.Fatalf("V6c: expected the serviceaccount mount counted destination_reconstructable; got %+v", out)
		}
	})
}
