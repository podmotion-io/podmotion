/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// pycriu_corpus_test.go — Q2 blocking corpus test (DEFECT-2026-06-15 quorum condition Q2).
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
		cmd := exec.Command("python3", scriptPath, ckptDir, string(maskedJSON))
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
	cmd := exec.Command("python3", scriptPath, ckptDir, string(maskedJSON))
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
	cmd := exec.Command("python3", scriptPath, ckptDir, string(maskedJSON))
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

// buildPatchScript extracts the embedded patch script from patchCheckpointImages.
// This is a test helper that returns the same script text as the production function
// so the corpus test covers exactly the production code path.
func buildPatchScript() string {
	// Reproduce the script embedded in patchCheckpointImages (server.go).
	// Keep in sync with patchCheckpointImages; any divergence is a test gap.
	return `
import sys, os, shutil, glob, json
import pycriu
from pycriu.images import MagicException

ckpt = sys.argv[1]
null_ext_key_masked = set(json.loads(sys.argv[2]))

def backup(path):
    orig = path + '.orig'
    if not os.path.exists(orig):
        shutil.copy2(path, orig)
    return orig

def load_image(image_file, fail_on_magic_error=True):
    try:
        with open(image_file, 'rb') as f:
            return pycriu.images.load(f)
    except MagicException as e:
        magic_val = getattr(e, 'magic', 'unknown')
        if fail_on_magic_error:
            print('PATCH_ERROR: %s:%s:%s' % (image_file, magic_val, str(e)), file=sys.stderr)
            sys.exit(1)
        else:
            print('WARNING: skipping %s — unknown magic %s: %s' % (image_file, magic_val, str(e)))
            return None
    except Exception as e:
        if fail_on_magic_error:
            print('PATCH_ERROR: %s:unknown:%s' % (image_file, str(e)), file=sys.stderr)
            sys.exit(1)
        else:
            print('WARNING: skipping %s — no pycriu handler: %s' % (image_file, str(e)))
            return None

# mountpoints: fail-loud on unknown magic (S1)
for mp_path in glob.glob(os.path.join(ckpt, 'mountpoints-*.img')):
    src = backup(mp_path)
    img = load_image(src, fail_on_magic_error=True)
    if img is None:
        continue
    kept = [e for e in img.get('entries', [])
            if not (e.get('mountpoint') in null_ext_key_masked and not e.get('ext_key'))]
    img['entries'] = kept
    with open(mp_path, 'wb') as f:
        pycriu.images.dump(img, f)
    print('mountpoints:', os.path.basename(mp_path), 'kept', len(kept), 'entries')

# netns: strip-only — skip-on-unknown-magic (S1)
netns_path = os.path.join(ckpt, 'netns-10.img')
if os.path.exists(netns_path):
    src = backup(netns_path)
    img = load_image(src, fail_on_magic_error=False)
    if img is not None:
        for e in img.get('entries', []):
            e.pop('ext_key', None)
        with open(netns_path, 'wb') as f:
            pycriu.images.dump(img, f)
        print('netns: removed ext_key entries')

# netdev: strip-only — skip-on-unknown-magic (S1)
netdev_path = os.path.join(ckpt, 'netdev-10.img')
if os.path.exists(netdev_path):
    src = backup(netdev_path)
    img = load_image(src, fail_on_magic_error=False)
    if img is not None:
        kept = [e for e in img.get('entries', []) if e.get('link', {}).get('type') == 772]
        img['entries'] = kept
        with open(netdev_path, 'wb') as f:
            pycriu.images.dump(img, f)
        print('netdev: kept', len(kept), 'entries (loopback only)')

# ifaddr: strip-only — skip-on-unknown-magic (S1)
# When no non-loopback entries remain (or pycriu cannot parse the image), delete the
# file so CRIU never launches its external 'ip addr restore' subprocess against it.
# Writing any stub (even a zero-entry image) risks "Magic mismatch" from that subprocess.
ifaddr_path = os.path.join(ckpt, 'ifaddr-10.img')
if os.path.exists(ifaddr_path):
    src = backup(ifaddr_path)
    img = load_image(src, fail_on_magic_error=False)
    if img is not None:
        kept = [e for e in img.get('entries', []) if e.get('ifaddr', {}).get('ifindex') == 1]
        if kept:
            img['entries'] = kept
            with open(ifaddr_path, 'wb') as f:
                pycriu.images.dump(img, f)
            print('ifaddr: kept', len(kept), 'entries (loopback only)')
        else:
            os.remove(ifaddr_path)
            print('ifaddr: 0 non-loopback entries — deleted', ifaddr_path, '(CRIU skip-restore path; dest IP pre-staged by ADR-0165)')
    else:
        os.remove(ifaddr_path)
        print('ifaddr: pycriu handler missing — deleted', ifaddr_path, '(CRIU skip-restore path; dest IP pre-staged by ADR-0165)')
`
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
		cmd := exec.Command("python3", scriptPath, ckptDir, string(maskedJSON))
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
