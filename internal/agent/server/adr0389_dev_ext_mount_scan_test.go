/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// adr0389_dev_ext_mount_scan_test.go — regression test carried forward under ADR-0415.
//
// HISTORY: ADR-0384 declared /dev external ("--external mnt[/dev]:pm-dev") so /dev/shm's parent
// resolved in CRIU's dump-side mount tree; ADR-0389 then had to teach buildMaskedPathExtMountArgs's
// restore-time pre-scan to recognize that "pm-dev" ext_key as covered (or it D4-fail-loud-refused
// every restore). ADR-0415 RETIRES that whole machinery: /dev is a pod-owned tmpfs captured with
// content and restored CRIU-owned, never declared external, so NO "pm-dev" entry is ever produced,
// and patchCheckpointImages INTERNALIZES any external /dev/shm the ctr fast path recorded (clears
// its ext_key). By the time buildMaskedPathExtMountArgs runs, /dev and /dev/shm carry no ext_key.
//
// This test now asserts that post-ADR-0415 shape: an internalized /dev and /dev/shm (no ext_key)
// are NOT flagged as externals, while a genuine containerd masked-path (null root) is still mapped
// to /dev/null — run through the ACTUAL production function, not a hand-copied re-implementation.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// devInternalizedCorpusGenPy writes a real-shape mountpoints-*.img matching what patchCheckpointImages
// leaves for the restore pre-scan under ADR-0415: an overlay root, /dev as a CRIU-owned INTERNAL
// tmpfs (no ext_key — internalized), /dev/shm as its ordinary owned tmpfs child (no ext_key —
// internalized), and one containerd masked-path entry (/proc/acpi, null root) so the masked-path
// branch is exercised in the same corpus.
const devInternalizedCorpusGenPy = `
import sys, os
import pycriu

d = sys.argv[1]
mnts = [
    {'fstype': 17, 'mnt_id': 1, 'root_dev': 0, 'parent_mnt_id': 0, 'flags': 0,
     'root': '/', 'mountpoint': '/', 'source': 'overlay', 'options': '', 'sb_flags': 0},
    {'fstype': 5, 'mnt_id': 2, 'root_dev': 0, 'parent_mnt_id': 1, 'flags': 0,
     'root': '/', 'mountpoint': '/dev', 'source': 'tmpfs', 'options': '', 'sb_flags': 0},
    {'fstype': 5, 'mnt_id': 3, 'root_dev': 0, 'parent_mnt_id': 2, 'flags': 0,
     'root': '/', 'mountpoint': '/dev/shm', 'source': 'shm', 'options': '', 'sb_flags': 0},
    {'fstype': 2, 'mnt_id': 4, 'root_dev': 0, 'parent_mnt_id': 1, 'flags': 0,
     'root': 'null', 'mountpoint': '/proc/acpi', 'source': 'proc', 'options': '', 'sb_flags': 0},
]
with open(os.path.join(d, 'mountpoints-10.img'), 'wb') as f:
    pycriu.images.dump({'magic': 'MNTS', 'entries': mnts}, f)
print('CORPUS_OK')
`

func TestBuildMaskedPathExtMountArgs_ADR0415InternalizedDevIsNotExternal(t *testing.T) {
	pypath, extraEnv := pycriuEnv(t)

	ckptDir := t.TempDir()
	genPath := filepath.Join(t.TempDir(), "dev-internalized-corpus-gen.py")
	if err := os.WriteFile(genPath, []byte(devInternalizedCorpusGenPy), 0o600); err != nil {
		t.Fatalf("write corpus generator: %v", err)
	}
	cmd := exec.Command("python3", genPath, ckptDir)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generate ADR-0415 internalized-dev corpus: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "CORPUS_OK") {
		t.Fatalf("corpus generator did not report CORPUS_OK; output: %s", out)
	}

	// Call the REAL production function — an internalized /dev and /dev/shm (no ext_key) must not
	// D4-fail-loud, and the masked /proc/acpi (null root) must still be mapped to /dev/null.
	args, err := buildMaskedPathExtMountArgs(ckptDir, nil)
	if err != nil {
		t.Fatalf("buildMaskedPathExtMountArgs must not D4-fail-loud on ADR-0415 internalized /dev "+
			"/dev/shm (no ext_key): %v", err)
	}

	found := false
	for i := 0; i+1 < len(args); i += 2 {
		if args[i] == "--ext-mount-map" && args[i+1] == "4:/dev/null" {
			found = true
		}
		// /dev (mnt_id 2) and /dev/shm (mnt_id 3) are internal (no ext_key) — they must NOT be
		// mapped to /dev/null at all (they are captured/restored as CRIU-owned content).
		if args[i] == "--ext-mount-map" && (args[i+1] == "2:/dev/null" || args[i+1] == "3:/dev/null") {
			t.Errorf("ADR-0415: internalized owned mount (%s) must not be numeric-mapped to /dev/null; got args=%v",
				args[i+1], args)
		}
	}
	if !found {
		t.Errorf("expected /proc/acpi (mnt_id 4, masked path) to be mapped \"--ext-mount-map 4:/dev/null\"; got args=%v", args)
	}
}
