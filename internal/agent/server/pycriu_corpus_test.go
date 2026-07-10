/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// pycriu_corpus_test.go — Q2 blocking corpus test (DEFECT-2026-06-15 condition Q2).
//
// Exercises both pycriu call sites:
//   - patchCheckpointImages (server.go ~2645): patch script (pm-patch-ckpt.py)
//   - buildMaskedPathExtMountArgs (server.go ~1663): scan script (pm-scan-mounts.py)
//
// Uses synthetic fixture CRIU images created with pycriu itself so the test does not
// require a live cluster or CRIU binary. Python + pycriu must be available in the
// test environment (same requirement as the production code path).
//
// Coverage:
//   1. Known-magic images (IFADDR, NETDEV, NETNS, MNTS) load without MagicException.
//   2. Unknown-magic strip-only images (netdev/netns/ifaddr) are skipped with a warning.
//   3. Unknown-magic mountpoints image fails loud with PATCH_ERROR on stderr + exit 1.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// resolveRepoPycriuPath walks up from the current directory to find the module root
// (identified by go.mod) and returns it as the PYTHONPATH so the vendored pycriu
// package (pycriu/ subdir of the repo) is importable.
func resolveRepoPycriuPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod / module root")
		}
		dir = parent
	}
}

// pycriuEnv returns the environment variables and PYTHONPATH needed to import pycriu.
// Tries /usr/lib/python3/dist-packages (production path) first; falls back to the
// vendored copy in the repo root. Sets PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python
// for compatibility with newer protobuf packages on dev machines.
func pycriuEnv(t *testing.T) (pypath string, extraEnv []string) {
	t.Helper()
	candidatePaths := []string{
		"/usr/lib/python3/dist-packages",
		resolveRepoPycriuPath(t),
	}
	baseEnv := append(os.Environ(), "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python")
	for _, p := range candidatePaths {
		cmd := exec.Command("python3", "-c", "import pycriu")
		cmd.Env = append(baseEnv, "PYTHONPATH="+p)
		if err := cmd.Run(); err == nil {
			return p, baseEnv
		}
	}
	t.Skip("python3/pycriu not available in any candidate path — skipping corpus test")
	return "", nil
}

// checkPycriuAvailable is a no-op alias; availability is checked in pycriuEnv.
func checkPycriuAvailable(_ *testing.T, _ string) {}

// magicByName returns the 32-bit magic value for the given pycriu image type name,
// looked up at runtime via the vendored magic.py. extraEnv must include PYTHONPATH.
func magicByName(t *testing.T, pypath, name string) uint32 {
	t.Helper()
	script := fmt.Sprintf(`from pycriu.images import magic; print(magic.by_name[%q])`, name)
	cmd := exec.Command("python3", "-c", script)
	cmd.Env = append(os.Environ(),
		"PYTHONPATH="+pypath,
		"PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python",
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("magicByName(%q): %v", name, err)
	}
	var val uint32
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &val); err != nil {
		t.Fatalf("magicByName(%q): parse %q: %v", name, out, err)
	}
	return val
}

// writeMinimalImg writes a minimal valid CRIU v1.1 image file containing zero entries.
// Format: [IMG_COMMON magic (4 bytes LE)] [image-type magic (4 bytes LE)]
// (no entries — zero-length payload is valid for load purposes).
func writeMinimalImg(t *testing.T, path string, imgCommonMagic, typeMagic uint32) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := binary.Write(f, binary.LittleEndian, imgCommonMagic); err != nil {
		t.Fatalf("write IMG_COMMON magic: %v", err)
	}
	if err := binary.Write(f, binary.LittleEndian, typeMagic); err != nil {
		t.Fatalf("write type magic: %v", err)
	}
}

// writeUnknownMagicImg writes a CRIU image file with an unknown magic value
// (guaranteed not in the pycriu magic table).
func writeUnknownMagicImg(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	// 0xDEADBEEF — not a valid CRIU image type.
	const unknownMagic uint32 = 0xDEADBEEF
	if err := binary.Write(f, binary.LittleEndian, unknownMagic); err != nil {
		t.Fatalf("write unknown magic: %v", err)
	}
}

// TestPycriuCorpus_KnownMagicImagesLoadWithoutException exercises both pycriu call sites
// against synthetic fixture images with known magic values. Asserts no MagicException.
// This is the Q2 blocking corpus test (DEFECT-2026-06-15).
func TestPycriuCorpus_KnownMagicImagesLoadWithoutException(t *testing.T) {
	pypath, extraEnv := pycriuEnv(t)

	// Resolve magic values from the vendored table at test time.
	imgCommonMagic := magicByName(t, pypath, "IMG_COMMON")
	mntsMagic := magicByName(t, pypath, "MNTS")
	netdevMagic := magicByName(t, pypath, "NETDEV")
	netnsMagic := magicByName(t, pypath, "NETNS")
	ifaddrMagic := magicByName(t, pypath, "IFADDR")

	// Create a scratch checkpoint directory with minimal fixture images.
	ckptDir := t.TempDir()

	writeMinimalImg(t, filepath.Join(ckptDir, "mountpoints-10.img"), imgCommonMagic, mntsMagic)
	writeMinimalImg(t, filepath.Join(ckptDir, "netdev-10.img"), imgCommonMagic, netdevMagic)
	writeMinimalImg(t, filepath.Join(ckptDir, "netns-10.img"), imgCommonMagic, netnsMagic)
	writeMinimalImg(t, filepath.Join(ckptDir, "ifaddr-10.img"), imgCommonMagic, ifaddrMagic)

	// --- Call site 1: patchCheckpointImages (pm-patch-ckpt.py) ---
	t.Run("patchCheckpointImages", func(t *testing.T) {
		maskedJSON, _ := json.Marshal([]string{})
		patchScript := buildPatchScript()
		scriptPath := filepath.Join(t.TempDir(), "pm-patch-ckpt.py")
		if err := os.WriteFile(scriptPath, []byte(patchScript), 0o600); err != nil {
			t.Fatalf("write patch script: %v", err)
		}
		// argv[3]=inheritJSON (C-R3-1): the production call passes the --inherit-fd name set as a
		// third arg; assemblePatchScript() reads sys.argv[3]. Empty set here (no cgroup fds inherited).
		cmd := exec.Command("python3", scriptPath, ckptDir, string(maskedJSON), "[]")
		cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("patchCheckpointImages script failed: %v\noutput: %s", err, out)
		}
		if strings.Contains(string(out), "MagicException") {
			t.Errorf("unexpected MagicException in patchCheckpointImages output: %s", out)
		}
		if strings.Contains(string(out), "PATCH_ERROR") {
			t.Errorf("unexpected PATCH_ERROR in patchCheckpointImages output: %s", out)
		}
	})

	// --- Call site 2: buildMaskedPathExtMountArgs (pm-scan-mounts.py) ---
	t.Run("buildMaskedPathExtMountArgs", func(t *testing.T) {
		scanScript := buildScanScript()
		scriptPath := filepath.Join(t.TempDir(), "pm-scan-mounts.py")
		if err := os.WriteFile(scriptPath, []byte(scanScript), 0o600); err != nil {
			t.Fatalf("write scan script: %v", err)
		}
		cmd := exec.Command("python3", scriptPath, ckptDir)
		cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("buildMaskedPathExtMountArgs script failed: %v\noutput: %s", err, out)
		}
		if strings.Contains(string(out), "MagicException") {
			t.Errorf("unexpected MagicException in buildMaskedPathExtMountArgs output: %s", out)
		}
	})
}

// TestPycriuCorpus_StripOnlyUnknownMagicSkipped verifies S1: strip-only images
// (netdev, netns, ifaddr) with unknown magic are skipped with a warning, not aborted.
func TestPycriuCorpus_StripOnlyUnknownMagicSkipped(t *testing.T) {
	pypath, extraEnv := pycriuEnv(t)

	imgCommonMagic := magicByName(t, pypath, "IMG_COMMON")
	mntsMagic := magicByName(t, pypath, "MNTS")

	ckptDir := t.TempDir()

	// Valid mountpoints image so the script gets past that block.
	writeMinimalImg(t, filepath.Join(ckptDir, "mountpoints-10.img"), imgCommonMagic, mntsMagic)
	// Unknown-magic strip-only images — must be skipped, not fatal.
	writeUnknownMagicImg(t, filepath.Join(ckptDir, "netdev-10.img"))
	writeUnknownMagicImg(t, filepath.Join(ckptDir, "netns-10.img"))
	writeUnknownMagicImg(t, filepath.Join(ckptDir, "ifaddr-10.img"))

	maskedJSON, _ := json.Marshal([]string{})
	patchScript := buildPatchScript()
	scriptPath := filepath.Join(t.TempDir(), "pm-patch-ckpt.py")
	if err := os.WriteFile(scriptPath, []byte(patchScript), 0o600); err != nil {
		t.Fatalf("write patch script: %v", err)
	}
	// argv[3]=inheritJSON (C-R3-1): production passes the --inherit-fd name set; empty here.
	cmd := exec.Command("python3", scriptPath, ckptDir, string(maskedJSON), "[]")
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	// Script must succeed (exit 0) — strip-only unknown magic is skip-on-unknown.
	if err != nil {
		t.Fatalf("S1: script should succeed on unknown-magic strip-only images but failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "WARNING") {
		t.Errorf("S1: expected WARNING log for skipped strip-only unknown-magic image; got: %s", out)
	}
	if strings.Contains(string(out), "PATCH_ERROR") {
		t.Errorf("S1: unexpected PATCH_ERROR for strip-only unknown-magic image; got: %s", out)
	}
}

// TestPycriuCorpus_MountpointsUnknownMagicFailsLoud verifies S1 + A3: unknown-magic
// mountpoints image must fail loud with a typed PATCH_ERROR on stderr and exit 1.
func TestPycriuCorpus_MountpointsUnknownMagicFailsLoud(t *testing.T) {
	pypath, extraEnv := pycriuEnv(t)

	ckptDir := t.TempDir()
	// Unknown-magic mountpoints image — must fail loud.
	writeUnknownMagicImg(t, filepath.Join(ckptDir, "mountpoints-10.img"))

	maskedJSON, _ := json.Marshal([]string{})
	patchScript := buildPatchScript()
	scriptPath := filepath.Join(t.TempDir(), "pm-patch-ckpt.py")
	if err := os.WriteFile(scriptPath, []byte(patchScript), 0o600); err != nil {
		t.Fatalf("write patch script: %v", err)
	}
	// argv[3]=inheritJSON (C-R3-1): production passes the --inherit-fd name set; empty here.
	cmd := exec.Command("python3", scriptPath, ckptDir, string(maskedJSON), "[]")
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	// Script must fail (exit 1) — mountpoints unknown magic is fail-loud.
	if err == nil {
		t.Fatalf("A3/S1: script should fail on unknown-magic mountpoints image but succeeded; output: %s", out)
	}
	combined := string(out)
	if !strings.Contains(combined, "PATCH_ERROR") {
		t.Errorf("A3: expected PATCH_ERROR in stderr output; got: %s", combined)
	}
	if !strings.Contains(combined, "mountpoints-10.img") {
		t.Errorf("A3: expected image filename in PATCH_ERROR output; got: %s", combined)
	}
}

// buildPatchScript returns the EXACT patch script that patchCheckpointImages ships (H-19).
//
// Before Sprint 43 this helper hand-copied an OUTDATED reproduction of the embedded script:
// it lacked the entire ADR-0190/0193/0194/0311 mount-graph closure (parent_mnt_id fixpoint),
// the files.img↔mountpoints P-0193-1/P-0194-1 reconciliation, the external-mount B-2 drop, and
// the tmpfs/shm REG-fd rebind. The corpus tests therefore exercised stale logic that could never
// decode or fail on the real checkpoint shapes. buildPatchScript now delegates to
// assemblePatchScript() — the single source of truth production also uses — so the corpus tests
// run byte-for-byte the shipped script and no divergent copy can drift (H-19 fix).
func buildPatchScript() string {
	return assemblePatchScript()
}

// TestPatchCheckpointImages_IfaddrDeletedWhenNoNonLoopback is the regression guard for
// SPRINT32-COLD-CHURN3: patchCheckpointImages must DELETE ifaddr-10.img (not write a stub)
// when there are no non-loopback address entries, so CRIU's external 'ip addr restore'
// subprocess is never launched against the file.
//
// Two sub-cases:
//   A. pycriu CAN parse the image but all entries are non-loopback → file deleted.
//   B. pycriu CANNOT parse the image (unknown magic / no handler) → file deleted.
//
// Regression: the old code wrote an 8-byte magic-only stub that CRIU's 'ip' tool
// rejected with "Magic mismatch (1 elems, 54564319 magic)" (CHURN3 R2-ATTEMPT-3).
func TestPatchCheckpointImages_IfaddrDeletedWhenNoNonLoopback(t *testing.T) {
	pypath, extraEnv := pycriuEnv(t)

	imgCommonMagic := magicByName(t, pypath, "IMG_COMMON")
	mntsMagic := magicByName(t, pypath, "MNTS")
	ifaddrMagic := magicByName(t, pypath, "IFADDR")
	maskedJSON, _ := json.Marshal([]string{})

	runScript := func(t *testing.T, ckptDir string) (string, error) {
		t.Helper()
		patchScript := buildPatchScript()
		scriptPath := filepath.Join(t.TempDir(), "pm-patch-ckpt.py")
		if err := os.WriteFile(scriptPath, []byte(patchScript), 0o600); err != nil {
			t.Fatalf("write patch script: %v", err)
		}
		// argv[3]=inheritJSON (C-R3-1): the production call passes the --inherit-fd name set as a
		// third arg; assemblePatchScript() reads sys.argv[3]. Empty set here (no cgroup fds inherited).
		cmd := exec.Command("python3", scriptPath, ckptDir, string(maskedJSON), "[]")
		cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Sub-case A: parseable image with zero non-loopback entries → file must be absent after patch.
	t.Run("parseable_zero_nonloopback_entries_deletes_file", func(t *testing.T) {
		ckptDir := t.TempDir()
		writeMinimalImg(t, filepath.Join(ckptDir, "mountpoints-10.img"), imgCommonMagic, mntsMagic)
		// Minimal valid IFADDR image — zero entries (no non-loopback addresses).
		writeMinimalImg(t, filepath.Join(ckptDir, "ifaddr-10.img"), imgCommonMagic, ifaddrMagic)

		out, err := runScript(t, ckptDir)
		if err != nil {
			t.Fatalf("script failed: %v\noutput: %s", err, out)
		}
		ifaddrPath := filepath.Join(ckptDir, "ifaddr-10.img")
		if _, statErr := os.Stat(ifaddrPath); statErr == nil {
			t.Errorf("REGRESSION(CHURN3): ifaddr-10.img must be deleted when zero non-loopback entries, but file still exists; script output: %s", out)
		}
		if !strings.Contains(out, "deleted") {
			t.Errorf("expected 'deleted' in script output; got: %s", out)
		}
	})

	// Sub-case B: unknown-magic image (pycriu cannot parse) → file must be absent after patch.
	t.Run("unknown_magic_ifaddr_deletes_file", func(t *testing.T) {
		ckptDir := t.TempDir()
		writeMinimalImg(t, filepath.Join(ckptDir, "mountpoints-10.img"), imgCommonMagic, mntsMagic)
		// Write unknown-magic ifaddr image — pycriu will fail to parse it.
		writeUnknownMagicImg(t, filepath.Join(ckptDir, "ifaddr-10.img"))

		out, err := runScript(t, ckptDir)
		if err != nil {
			t.Fatalf("script failed: %v\noutput: %s", err, out)
		}
		ifaddrPath := filepath.Join(ckptDir, "ifaddr-10.img")
		if _, statErr := os.Stat(ifaddrPath); statErr == nil {
			t.Errorf("REGRESSION(CHURN3): ifaddr-10.img must be deleted when pycriu cannot parse it, but file still exists; script output: %s", out)
		}
		if !strings.Contains(out, "deleted") {
			t.Errorf("expected 'deleted' in script output; got: %s", out)
		}
	})
}

// buildScanScript returns the embedded mount-scan script from buildMaskedPathExtMountArgs.
func buildScanScript() string {
	return `
import pycriu, glob, json, sys
imgs = glob.glob(sys.argv[1] + '/mountpoints-*.img')
results = []
for img in imgs:
    with open(img, 'rb') as f:
        data = pycriu.images.load(f)
    for e in data.get('entries', []):
        if e.get('ext_key') or e.get('root') in ('null', '/null', None):
            results.append({'mnt_id': e.get('mnt_id'), 'mountpoint': e.get('mountpoint', ''), 'root': e.get('root', ''), 'ext_key': e.get('ext_key', '')})
print(json.dumps(results))
`
}
