/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// patch_checkpoint_realcorpus_test.go — B-09 real-shape checkpoint corpus fixtures.
//
// Purpose (Sprint 43 item B-09 / H-19):
//
// The pre-Sprint-43 corpus tests (pycriu_corpus_test.go) exercised the patch script against
// zero-entry writeMinimalImg synthetics, and they invoked a HAND-COPIED reproduction of the
// script (the old buildPatchScript()). That copy had drifted out of sync with production — it
// lacked the entire ADR-0190/0193/0194/0311 mount-graph closure, the files.img reconciliation,
// the external-mount B-2 drop, and the tmpfs REG-fd rebind, and it used a 2-arg argv contract
// where production uses 3 (argv[3]=inheritJSON). A zero-entry synthetic can never decode to the
// real failing shapes, so the tests were green while skipping every hard case.
//
// This file closes that gap two ways:
//
//  1. buildPatchScript() now delegates to assemblePatchScript() (the single source of truth
//     production uses) — see pycriu_corpus_test.go. No divergent copy can drift.
//
//  2. These tests build REAL-SHAPE corpora with pycriu — a mountpoints image with a real
//     parent_mnt_id graph (root → /sys → /sys/<child>, plus /proc, /dev/shm, and an external
//     /data mount), a files.img with a /data orphan REG-fd, and a matching fdinfo image — and run
//     the ACTUAL assembled production script (assemblePatchScript()) against them. They assert the
//     real behaviors the zero-entry synthetics could never reach:
//       - parent_mnt_id graph closure drops the /sys subtree (the mount.c:381 shape)
//       - the external /data mount is B-2 dropped (CRIU_EXTERNAL_MOUNT_DROPPED emitted)
//       - the /data orphan REG-fd hard-stops with a typed CRIU_IMAGE_INCONSISTENCY (P-0193-1)
//       - an --inherit-fd name (argv[3]) excludes its fd from the firing class (KEEP, not DECLINE)
//
// FALSIFIABILITY: each assertion runs the shipped script and checks a distinct structured token.
// If a future edit deletes the graph closure, the ext-drop, the P-0193-1 hard-stop, or the
// inherit exclusion, the corresponding test fails. Because buildPatchScript() == assemblePatchScript()
// there is no second copy to keep green independently.
//
// GROUNDING BOUNDARY (C-06 MUST_ROUTE_BROKER): the ADR-0311 tmpfs/shm REG-fd rebind keys on the
// mount fstype rendered as an enum-NAME string ('TMPFS'/'DEVTMPFS'). The vendored pycriu declares
// mnt_entry.fstype as a bare uint32 (mnt_pb2.py: type=13, enum_type=None), so an image DUMPED and
// re-LOADED by this pycriu renders fstype as an INT (e.g. 5), never the name — a synthetic fixture
// therefore cannot faithfully exercise the tmpfs-rebind REBIND_TO_ROOT branch (it DECLINEs on the
// int). That path is grounded ONLY by a corpus produced by real CRIU 4.2 on a cluster node, which
// does not produce in-sandbox (a new-mount-ns dump fails on the dev host's unsupported
// filesystems). TestRealCorpus_TmpfsShmRebind_RequiresRealCRIUImage records this explicitly and
// skips rather than assert a shape the substrate cannot honestly produce.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// realCorpusGenPy is a pycriu fixture generator. argv[1] is the output directory; argv[2] selects
// a named corpus shape. It writes real CRIU image files (non-trivial entries, real parent_mnt_id
// graph) that the production patch script decodes. It is intentionally standalone (imports only
// pycriu) so it runs under the exact PYTHONPATH the production script uses.
const realCorpusGenPy = `
import sys, os
import pycriu

out = sys.argv[1]
shape = sys.argv[2]

def dump(fn, magic, entries):
    with open(os.path.join(out, fn), 'wb') as f:
        pycriu.images.dump({'magic': magic, 'entries': entries}, f)

# FSTYPE enum ints (criu mnt.proto): PROC=1, SYSFS=2, TMPFS=5, OVERLAYFS=17.
def mnt(mid, par, mp, fstype, ext_key=None, src='none'):
    e = {'fstype': fstype, 'mnt_id': mid, 'root_dev': 0, 'parent_mnt_id': par,
         'flags': 0, 'root': '/', 'mountpoint': mp, 'source': src, 'options': '', 'sb_flags': 0}
    if ext_key is not None:
        e['ext_key'] = ext_key
    return e

_FOWN = {'uid': 0, 'euid': 0, 'signum': 0, 'pid_type': 0, 'pid': 0}

def reg(fid, name, mnt_id, mode=0o100644):
    r = {'id': fid, 'flags': 0, 'pos': 0, 'fown': _FOWN, 'name': name, 'mode': mode}
    if mnt_id is not None:
        r['mnt_id'] = mnt_id
    return {'type': 'REG', 'id': fid, 'reg': r}

def fd(fid, fdnum):
    return {'id': fid, 'flags': 0, 'type': 'REG', 'fd': fdnum}

if shape == 'full':
    # Real failing topology: root(overlay) → /sys(sysfs) → /sys/<child>(sysfs) [orphan-if-only-/sys-
    # dropped, the mount.c:381 shape]; /proc(proc); /dev/shm(tmpfs); /data(overlay, ext_key set).
    dump('mountpoints-10.img', 'MNTS', [
        mnt(2943, 0,    '/',     17, src='overlay'),
        mnt(9107, 2943, '/sys',  2,  src='sysfs'),
        mnt(7730, 9107, '/sys/devices/virtual/dmi/id/product_name', 2, src='sysfs'),
        mnt(2945, 2943, '/proc', 1,  src='proc'),
        mnt(943,  2943, '/dev/shm', 5, src='shm'),
        mnt(2951, 2943, '/data', 17, ext_key='/data', src='/dev/vdb'),
    ])
    # files.img: a /data orphan REG-fd (mnt_id 2951 = the external-dropped /data mount) plus a
    # kept root fd plus a /sys/fs/cgroup fd (would DECLINE unless inherited).
    dump('files.img', 'FILES', [
        reg(1, '/data/base/relation.db', 2951),
        reg(2, '/app/main.py', 2943),
        reg(3, '/sys/fs/cgroup/cpu.max', 9107),
    ])
    dump('fdinfo-2.img', 'FDINFO', [fd(1, 10), fd(2, 11), fd(3, 12)])

elif shape == 'inherit_only':
    # Same mounts, but the ONLY files.img entry is the /data orphan fd, and the test passes its
    # slash-stripped name as an --inherit-fd name (argv[3]) so classify_reg_fd returns KEEP.
    dump('mountpoints-10.img', 'MNTS', [
        mnt(2943, 0,    '/',     17, src='overlay'),
        mnt(2945, 2943, '/proc', 1,  src='proc'),
    ])
    dump('files.img', 'FILES', [
        reg(1, '/app/main.py', 2943),
        reg(2, '/sys/fs/cgroup/cpu.max', 55),
    ])
    dump('fdinfo-2.img', 'FDINFO', [fd(1, 10), fd(2, 11)])

else:
    sys.stderr.write('unknown corpus shape: %s\n' % shape)
    sys.exit(2)

print('CORPUS_OK', shape)
`

// generateRealShapeCorpus writes a named real-shape corpus into dir using pycriu. It skips the
// test (like pycriuEnv) when python3/pycriu are unavailable. Returns the pypath/env so the caller
// can run the production script against the corpus with the same interpreter.
func generateRealShapeCorpus(t *testing.T, dir, shape string) (pypath string, extraEnv []string) {
	t.Helper()
	pypath, extraEnv = pycriuEnv(t) // skips if pycriu unavailable
	genPath := filepath.Join(t.TempDir(), "pm-gen-corpus.py")
	if err := os.WriteFile(genPath, []byte(realCorpusGenPy), 0o600); err != nil {
		t.Fatalf("write corpus generator: %v", err)
	}
	cmd := exec.Command("python3", genPath, dir, shape)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generateRealShapeCorpus(%q): %v\noutput: %s", shape, err, out)
	}
	if !strings.Contains(string(out), "CORPUS_OK") {
		t.Fatalf("generateRealShapeCorpus(%q): generator did not report CORPUS_OK; output: %s", shape, out)
	}
	return pypath, extraEnv
}

// runProductionPatchScript writes assemblePatchScript() (the shipped script) to disk and runs it
// against ckptDir with the given masked-paths and inherit-fd-name sets (argv[2], argv[3]). Returns
// combined stdout+stderr and the process error (non-nil on exit!=0).
func runProductionPatchScript(t *testing.T, pypath string, extraEnv []string, ckptDir string, masked, inherit []string) (string, error) {
	t.Helper()
	// Production normalizes nil→[] so json.Marshal emits "[]" not "null" (patchCheckpointImages:
	// set(json.loads(...)) raises TypeError on null). Mirror that here.
	if masked == nil {
		masked = []string{}
	}
	if inherit == nil {
		inherit = []string{}
	}
	maskedJSON, _ := json.Marshal(masked)
	inheritJSON, _ := json.Marshal(inherit)
	scriptPath := filepath.Join(t.TempDir(), "pm-patch-ckpt.py")
	if err := os.WriteFile(scriptPath, []byte(assemblePatchScript()), 0o600); err != nil {
		t.Fatalf("write production patch script: %v", err)
	}
	cmd := exec.Command("python3", scriptPath, ckptDir, string(maskedJSON), string(inheritJSON))
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestRealCorpus_ParentMntGraphClosureAndExternalDrop drives the shipped patch script against a
// real-shape corpus and asserts the parent_mnt_id graph closure + external-mount B-2 drop fire.
//
// This is the "test that would have caught the bug" for the mount.c:381 / mount.c:3141 family: a
// zero-entry synthetic (the old fixture) has no parent_mnt_id graph and no external mount, so it
// could never observe either behavior. Here the /sys subtree (2 entries) and the external /data
// mount are all present in the input and must be gone from the kept set after the patch.
func TestRealCorpus_ParentMntGraphClosureAndExternalDrop(t *testing.T) {
	ckptDir := t.TempDir()
	pypath, extraEnv := generateRealShapeCorpus(t, ckptDir, "full")

	// masked=["/data"] mirrors containerdMaskedPaths carrying /data; inherit empty.
	out, err := runProductionPatchScript(t, pypath, extraEnv, ckptDir, []string{"/data"}, nil)

	// The /data orphan REG-fd (fd_id 1, mnt_id 2951) must hard-stop with a typed inconsistency
	// error — the external /data mount is dropped, orphaning that fd, and a non-tmpfs orphan
	// DECLINEs (P-0193-1). So the script exits non-zero here; that is the CORRECT shape.
	if err == nil {
		t.Fatalf("expected P-0193-1 hard-stop (exit!=0) on /data orphan REG-fd, but script succeeded; output: %s", out)
	}

	// (a) parent_mnt_id graph closure: the mountpoints reduced from 6 to 2 kept entries
	// (root + /proc). The /sys subtree and dropped/external mounts are gone.
	if !strings.Contains(out, "mountpoints-10.img") || !strings.Contains(out, "kept 2 entries") {
		t.Errorf("expected mountpoints graph closure to keep exactly 2 entries (root + /proc); got: %s", out)
	}

	// (b) external-mount B-2 drop: /data must emit CRIU_EXTERNAL_MOUNT_DROPPED with its mnt_id/ext_key.
	if !strings.Contains(out, `CRIU_EXTERNAL_MOUNT_DROPPED:`) || !strings.Contains(out, `"mnt_id":2951`) || !strings.Contains(out, `"ext_key":"/data"`) {
		t.Errorf("expected CRIU_EXTERNAL_MOUNT_DROPPED for /data (mnt_id 2951); got: %s", out)
	}

	// (c) the /data orphan REG-fd P-0193-1 hard-stop must be structured and name the fd + backing.
	if !strings.Contains(out, `CRIU_IMAGE_INCONSISTENCY:`) || !strings.Contains(out, `"fd_id":1`) || !strings.Contains(out, `"backing_mnt_id":2951`) {
		t.Errorf("expected CRIU_IMAGE_INCONSISTENCY for the /data orphan REG-fd (fd_id 1, backing_mnt_id 2951); got: %s", out)
	}
	// P-0193-1 grounding: the decoded backing mountpoint must be reported (not just the bare mnt_id).
	if !strings.Contains(out, `"backing_mountpoint":"/data"`) {
		t.Errorf("expected decoded backing_mountpoint=/data in the P-0193-1 marker (grounding); got: %s", out)
	}
}

// TestRealCorpus_InheritFdNameExcludesFromFiringClass proves the argv[3] inherit-fd contract: an
// orphan REG-fd whose slash-stripped name is in the --inherit-fd set is classified KEEP (CRIU's
// inherited_fd() exits before open_path()), so it does NOT hard-stop.
//
// This is the argv[3] behavior the OLD hand-copied buildPatchScript() could not test at all — it
// had a 2-arg contract and no inherit set. It is falsifiable: run it with the inherit set EMPTY
// (the negative control) and the same corpus hard-stops on the cgroup fd.
func TestRealCorpus_InheritFdNameExcludesFromFiringClass(t *testing.T) {
	// Negative control: WITHOUT inherit coverage, the /sys/fs/cgroup orphan fd (mnt_id 55, absent
	// from kept mountpoints) must hard-stop (proves the assertion is not vacuous).
	t.Run("without_inherit_declines", func(t *testing.T) {
		ckptDir := t.TempDir()
		pypath, extraEnv := generateRealShapeCorpus(t, ckptDir, "inherit_only")
		out, err := runProductionPatchScript(t, pypath, extraEnv, ckptDir, nil, nil)
		if err == nil {
			t.Fatalf("negative control: expected hard-stop on the un-inherited /sys/fs/cgroup orphan fd, but script succeeded; output: %s", out)
		}
		if !strings.Contains(out, `CRIU_IMAGE_INCONSISTENCY:`) {
			t.Errorf("negative control: expected CRIU_IMAGE_INCONSISTENCY; got: %s", out)
		}
	})

	// With inherit coverage: the same orphan fd is inherited (slash-stripped name), so it KEEPs and
	// the script completes cleanly (exit 0).
	t.Run("with_inherit_keeps", func(t *testing.T) {
		ckptDir := t.TempDir()
		pypath, extraEnv := generateRealShapeCorpus(t, ckptDir, "inherit_only")
		// inherit_fd_names is slash-stripped in production (ADR-0188); pass the stripped name.
		out, err := runProductionPatchScript(t, pypath, extraEnv, ckptDir, nil, []string{"sys/fs/cgroup/cpu.max"})
		if err != nil {
			t.Fatalf("with inherit coverage the /sys/fs/cgroup fd must be KEEP (no hard-stop), but script exited non-zero: %v\noutput: %s", err, out)
		}
		// It must NOT have hard-stopped on that fd.
		if strings.Contains(out, `CRIU_IMAGE_INCONSISTENCY:`) {
			t.Errorf("an inherited fd must not fire CRIU_IMAGE_INCONSISTENCY; got: %s", out)
		}
	})
}

// TestRealCorpus_TmpfsShmRebind_RequiresRealCRIUImage records the grounding boundary for the
// ADR-0311 tmpfs/shm REG-fd rebind (C-06 MUST_ROUTE_BROKER).
//
// classify_reg_fd authorizes REBIND_TO_ROOT for a non-directory orphan REG-fd only when its
// backing mount's fstype is the enum-NAME 'TMPFS'/'DEVTMPFS'. The vendored pycriu declares
// mnt_entry.fstype as a bare uint32 (mnt_pb2.py: type=13, enum_type=None), so any image dumped and
// re-loaded by this pycriu renders fstype as an INT (5), and a /dev/shm PostgreSQL orphan fd
// DECLINEs instead of rebinding. A synthetic pycriu fixture therefore CANNOT honestly exercise the
// rebind branch; only a corpus produced by real CRIU 4.2 (which does not produce in-sandbox: a
// new-mount-namespace dump fails on the dev host's unsupported filesystems) can. This test asserts
// the boundary — that a pycriu-round-tripped /dev/shm orphan renders fstype as an int, so the
// rebind is un-fixturable here — and skips, routing the real-image validation to the cluster
// broker rather than faking a green.
func TestRealCorpus_TmpfsShmRebind_RequiresRealCRIUImage(t *testing.T) {
	pypath, extraEnv := pycriuEnv(t)
	// Dump a single tmpfs mount + one orphan REG-fd, reload, and read back the rendered fstype.
	dir := t.TempDir()
	probe := `
import sys, os
import pycriu
d = sys.argv[1]
mnt = {'fstype': 5, 'mnt_id': 943, 'root_dev': 0, 'parent_mnt_id': 100, 'flags': 0,
       'root': '/', 'mountpoint': '/dev/shm', 'source': 'shm', 'options': '', 'sb_flags': 0}
with open(os.path.join(d, 'mountpoints-10.img'), 'wb') as f:
    pycriu.images.dump({'magic': 'MNTS', 'entries': [mnt]}, f)
with open(os.path.join(d, 'mountpoints-10.img'), 'rb') as f:
    back = pycriu.images.load(f)
print('FSTYPE_RENDER=%r' % (back['entries'][0]['fstype'],))
`
	probePath := filepath.Join(t.TempDir(), "pm-fstype-probe.py")
	if err := os.WriteFile(probePath, []byte(probe), 0o600); err != nil {
		t.Fatalf("write fstype probe: %v", err)
	}
	cmd := exec.Command("python3", probePath, dir)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fstype probe failed: %v\noutput: %s", err, out)
	}
	rendered := strings.TrimSpace(string(out))
	// If this pycriu renders the name (a build where mnt_entry.fstype is a proper enum), the
	// synthetic rebind fixture WOULD be faithful — surface that so a future env upgrade is noticed.
	if strings.Contains(rendered, "'TMPFS'") {
		t.Fatalf("fstype now renders as the enum NAME (%s) under this pycriu — the tmpfs-rebind path is NOW fixturable synthetically; add the REBIND_TO_ROOT contract test and remove this skip", rendered)
	}
	if !strings.Contains(rendered, "FSTYPE_RENDER=5") {
		t.Fatalf("unexpected fstype rendering from pycriu round-trip: %q (expected the int 5)", rendered)
	}
	t.Skip("ADR-0311 tmpfs/shm REG-fd rebind (REBIND_TO_ROOT) keys on the fstype enum-NAME 'TMPFS', " +
		"but vendored pycriu round-trips fstype as the int 5 — a synthetic fixture cannot exercise the " +
		"rebind branch (it DECLINEs). Grounds ONLY against a real CRIU-4.2 corpus (routed to the cluster " +
		"broker, C-06 MUST_ROUTE_BROKER); real full-mount-ns dump does not produce in-sandbox.")
}
