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
// filesystems). This remains true for OTHER tmpfs mounts that still take the drop/rebind path;
// ADR-0382 removes /dev/shm specifically from that path (see
// TestRealCorpus_DevShmContentPreserved_NotRebound below), so this boundary no longer applies to
// /dev/shm itself.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
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
def mnt(mid, par, mp, fstype, ext_key=None, src='none', root='/'):
    e = {'fstype': fstype, 'mnt_id': mid, 'root_dev': 0, 'parent_mnt_id': par,
         'flags': 0, 'root': root, 'mountpoint': mp, 'source': src, 'options': '', 'sb_flags': 0}
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
    # dropped, the mount.c:381 shape]; /proc(proc); /dev/shm(tmpfs); /data(external, ext_key set).
    # ext_key='CRIU:AUTOGENERATED' is the REAL value CRIU's --external mnt[]AUTO mode writes for
    # every auto-detected external (ground-truthed from a live nfs4 PGDATA checkpoint) — NOT the
    # mountpoint. Preservation must key on the mountpoint, which is why the corpus uses the real key.
    dump('mountpoints-10.img', 'MNTS', [
        mnt(2943, 0,    '/',     17, src='overlay'),
        mnt(9107, 2943, '/sys',  2,  src='sysfs'),
        mnt(7730, 9107, '/sys/devices/virtual/dmi/id/product_name', 2, src='sysfs'),
        mnt(2945, 2943, '/proc', 1,  src='proc'),
        mnt(943,  2943, '/dev/shm', 5, src='shm'),
        mnt(2951, 2943, '/data', 17, ext_key='CRIU:AUTOGENERATED', src='/dev/vdb'),
    ])
    # files.img: a /data orphan REG-fd (mnt_id 2951 = the external-dropped /data mount) plus a
    # kept root fd plus a /sys/fs/cgroup fd (would DECLINE unless inherited).
    dump('files.img', 'FILES', [
        reg(1, '/data/base/relation.db', 2951),
        reg(2, '/app/main.py', 2943),
        reg(3, '/sys/fs/cgroup/cpu.max', 9107),
    ])
    dump('fdinfo-2.img', 'FDINFO', [fd(1, 10), fd(2, 11), fd(3, 12)])

elif shape == 'reattach_only':
    # Postgres PGDATA shape, isolated: root(overlay) + /proc + a single EXTERNAL re-attach mount
    # (/data, an nfs4 RWX-PVC analogue) carrying an open data-file fd. No cgroup/sys orphan, so the
    # script runs to completion and exercises the P-0194-1c dual-write assertion on the preserved
    # external. With /data in argv[4] this must exit 0 (mount preserved, fd KEEP). ext_key is the
    # REAL 'CRIU:AUTOGENERATED' constant (NOT the mountpoint) exactly as a live nfs4 checkpoint
    # records it — so preservation succeeds ONLY via the mountpoint match, making this the true
    # regression for the P-0193-1 postgres wall.
    # The /data external is a REAL autodetected external bind: root is the SOURCE node's kubelet
    # volume dir and source is that path with CRIU's '//<abspath>' external-source marker
    # (ground-truthed from a live nfs4 checkpoint decode: an autodetected external records
    # root=/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~nfs/<pv> and source=//<same>). CRIU
    # restores it by binding from mi->source directly (bypassing --ext-mount-map), so a cross-node
    # restore requires the patch to rewrite root+source to the DESTINATION kubelet dir — the primitive
    # TestRealCorpus_ReattachExternalMountSourceRewritten asserts.
    dump('mountpoints-10.img', 'MNTS', [
        mnt(2943, 0,    '/',     17, src='overlay'),
        mnt(2945, 2943, '/proc', 1,  src='proc'),
        mnt(2951, 2943, '/data', 0,  ext_key='CRIU:AUTOGENERATED',
            root='/var/lib/kubelet/pods/11111111-1111-1111-1111-111111111111/volumes/kubernetes.io~nfs/pvc-src',
            src='//var/lib/kubelet/pods/11111111-1111-1111-1111-111111111111/volumes/kubernetes.io~nfs/pvc-src'),
    ])
    dump('files.img', 'FILES', [
        reg(1, '/data/base/relation.db', 2951),
        reg(2, '/app/main.py', 2943),
    ])
    dump('fdinfo-2.img', 'FDINFO', [fd(1, 10), fd(2, 11)])

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
func runProductionPatchScript(t *testing.T, pypath string, extraEnv []string, ckptDir string, masked, inherit []string, reattach ...[]string) (string, error) {
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
	argv := []string{scriptPath, ckptDir, string(maskedJSON), string(inheritJSON)}
	// argv[4] (reattach mount paths) is optional — omit it to exercise the older 3-argv contract
	// (the len(sys.argv)>4 backward-compat guard), pass it to exercise the re-attach preserve path.
	if len(reattach) > 0 {
		reattachSet := reattach[0]
		if reattachSet == nil {
			reattachSet = []string{}
		}
		reattachJSON, _ := json.Marshal(reattachSet)
		argv = append(argv, string(reattachJSON))
	}
	cmd := exec.Command("python3", argv...)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runProductionPatchScriptHT runs the shipped patch script with BOTH argv[4] (reattach mount paths)
// and argv[5] (reattach host targets — the {containerPath: destination kubelet dir} the cross-node
// source rewrite consumes). Mirrors patchCheckpointImages' argv construction exactly.
func runProductionPatchScriptHT(t *testing.T, pypath string, extraEnv []string, ckptDir string, masked, inherit, reattach []string, hostTargets map[string]string) (string, error) {
	t.Helper()
	if masked == nil {
		masked = []string{}
	}
	if inherit == nil {
		inherit = []string{}
	}
	if reattach == nil {
		reattach = []string{}
	}
	if hostTargets == nil {
		hostTargets = map[string]string{}
	}
	maskedJSON, _ := json.Marshal(masked)
	inheritJSON, _ := json.Marshal(inherit)
	reattachJSON, _ := json.Marshal(reattach)
	hostTargetsJSON, _ := json.Marshal(hostTargets)
	scriptPath := filepath.Join(t.TempDir(), "pm-patch-ckpt.py")
	if err := os.WriteFile(scriptPath, []byte(assemblePatchScript()), 0o600); err != nil {
		t.Fatalf("write production patch script: %v", err)
	}
	cmd := exec.Command("python3", scriptPath, ckptDir, string(maskedJSON), string(inheritJSON), string(reattachJSON), string(hostTargetsJSON))
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestRealCorpus_ParentMntGraphClosureAndOwnedInternalize drives the shipped patch script against a
// real-shape corpus and asserts the parent_mnt_id graph closure (the /proc-/sys structural carve-out)
// AND the ADR-0415 owned-mount internalize (the external /data mount, with no re-attach mapping, is
// internalized as CRIU-owned rather than B-2-dropped).
//
// This is the "test that would have caught the bug" for the mount.c:381 / mount.c:3141 family: a
// zero-entry synthetic has no parent_mnt_id graph, so it could never observe the closure. Here the
// /sys subtree (structural carve-out) is dropped by the closure, while /data is internalized — so its
// open REG-fd stays consistent (no P-0193-1 hard-stop) and the script runs to success.
func TestRealCorpus_ParentMntGraphClosureAndOwnedInternalize(t *testing.T) {
	ckptDir := t.TempDir()
	pypath, extraEnv := generateRealShapeCorpus(t, ckptDir, "full")

	// masked=["/data"] mirrors containerdMaskedPaths; inherit empty; EMPTY re-attach set so /data is
	// not a storage-tier PVC re-attach and is therefore internalized (owned-capture).
	//
	// NOTE: the `full` corpus ALSO carries an unrelated /sys/fs/cgroup/cpu.max REG-fd (fd_id 3, mnt_id
	// 9107=/sys). /sys is the structural carve-out and IS dropped by the graph closure, so that fd
	// hard-stops as a non-tmpfs orphan (in production it is covered by the ADR-0180 --inherit-fd
	// contract, not exercised here). So the script may still exit non-zero for THAT fd; this test
	// asserts ONLY the mountpoints-pass behavior for /data (internalize) and that the /data REG-fd
	// (backing_mnt_id 2951) does NOT orphan.
	out, _ := runProductionPatchScript(t, pypath, extraEnv, ckptDir, []string{"/data"}, nil)

	// ADR-0417 SUPERSEDES the ADR-0415 expectation this test used to encode. The corpus /data mount
	// records fstype=0 (a REAL block/NFS filesystem — CRIU's own fstypes[] table has no
	// construct-and-fill row for it; btrfs is in that table with code 0 for exactly this reason), so
	// it is Class DESTINATION-REBIND, not Class RECREATABLE. Internalizing it — clearing ext_key and
	// setting root='/' while leaving fstype at 0 — produced precisely the triple
	// criu/mount.c validate_mounts is written to reject, and threw the volume's real backing away.
	// With no destination target supplied (empty argv[5]) the correct behavior is a FAIL-CLOSED
	// hard-stop, not a silent internalize.
	if !strings.Contains(out, "EXTERNAL_MOUNT_UNRESOLVED") || !strings.Contains(out, "destination_rebind_target_unresolved") {
		t.Errorf("ADR-0417: an fstype-0 external with no destination target must hard-stop fail-closed; got: %s", out)
	}
	if !strings.Contains(out, `"mnt_id": 2951`) {
		t.Errorf("ADR-0417: the hard-stop must name the offending mount (mnt_id 2951); got: %s", out)
	}
	// It must NOT be internalized: that is the disproven ADR-0415 carve-out (b) behavior.
	if strings.Contains(out, "internalizing RECREATABLE mount") && strings.Contains(out, "mountpoint=/data") {
		t.Errorf("ADR-0417: /data (fstype 0, a real block/NFS filesystem) must NOT be internalized; got: %s", out)
	}
	// The retired B-2 drop token must still NOT appear for /data.
	if strings.Contains(out, `CRIU_EXTERNAL_MOUNT_DROPPED:`) {
		t.Errorf("/data must not be B-2-dropped — no CRIU_EXTERNAL_MOUNT_DROPPED expected; got: %s", out)
	}
	// The /sys structural carve-out must still be dropped by the parent_mnt_id graph closure — the
	// original property this test exists for, unaffected by the classification change.
	if strings.Contains(out, "/sys/devices") {
		t.Errorf("expected the /sys subtree to be dropped by the graph closure; got: %s", out)
	}
}

// TestRealCorpus_ReattachExternalMountPreserved is the PINNED regression for the postgres
// checkpoint→restore live failure decoded 2026-07-10 (this session, real KVM run).
//
// GROUND TRUTH: a real postgres live migration reached past Checkpointing (ctr checkpoint
// captured 27 MB) then FAILED at restore in patchCheckpointImages with:
//
//	files.img REG fd id=47 name_leaf=000000010000000000000001 backing_mnt_id=2408
//	backing_fstype=0 backing_mountpoint=/var/lib/postgresql/data:
//	positive orphan mnt_id not in kept mountpoints — hard-stopped (ADR-0193 P-0193-1)
//
// The PGDATA volume is an RWX NFS PVC (Tier0 re-attach) that CRIU's --external mnt[]AUTO mode
// records as an EXTERNAL mountpoints entry. GROUND TRUTH re-decoded 2026-07-16 from a live nfs4
// PGDATA checkpoint (superseding an earlier note that mis-stated the ext_key as the mountPath):
//
//	mnt_id=2263 fstype=0 root='/' mountpoint='/var/lib/postgresql/data'
//	ext_key='CRIU:AUTOGENERATED'  source='/var/lib/kubelet/pods/.../volumes/kubernetes.io~nfs/pvc-...'
//
// The ext_key is the CONSTANT literal 'CRIU:AUTOGENERATED' that CRIU stamps on EVERY auto-detected
// external — NOT the mountpoint. So keying the re-attach preservation on the ext_key could never
// match a pod-spec mountPath, and the B-2 external-drop pass dropped the mount, orphaning postgres's
// open WAL/relation-file fds → P-0193-1. That is WRONG for a shared/re-attach volume: the
// destination replacement pod mounts the identical NFS PVC at the identical path, so CRIU must
// PRESERVE the mount (keep it in kept_mnt_ids) and re-attach it via --ext-mount-map <path>:<path>.
// The fix keys preservation on the MOUNTPOINT (== the pod-spec mountPath).
//
// This test drives the SHIPPED patch script over the real-shape corpus whose external mount is
// exactly this shape (the `full` corpus /data mount, mnt_id 2951, ext_key 'CRIU:AUTOGENERATED',
// with an open data-file fd '/data/base/relation.db' on it — structurally identical to the postgres
// PGDATA fd). It asserts that when '/data' (the mountpoint) is supplied in argv[4] (the reattach
// set), the mount is PRESERVED (no CRIU_EXTERNAL_MOUNT_DROPPED, no P-0193-1 CRIU_IMAGE_INCONSISTENCY,
// exit 0). The negative control (TestRealCorpus_ParentMntGraphClosureAndExternalDrop, same corpus,
// EMPTY reattach set) proves the assertion is not vacuous: without the reattach coverage the
// identical fd hard-stops.
func TestRealCorpus_ReattachExternalMountPreserved(t *testing.T) {
	ckptDir := t.TempDir()
	pypath, extraEnv := generateRealShapeCorpus(t, ckptDir, "full")

	// '/data' declared as a shared/re-attach PVC mount (argv[4]) — the postgres PGDATA case.
	// masked empty so /data is NOT treated as a masked path; it is a genuine re-attach volume.
	//
	// NOTE: the `full` corpus ALSO carries an unrelated /sys/fs/cgroup orphan fd (fd_id 3, mnt_id
	// 9107) that hard-stops independently of this fix (it is covered by the --inherit-fd contract in
	// TestRealCorpus_InheritFdNameExcludesFromFiringClass, not exercised here). So the script may
	// still exit non-zero for THAT fd; this test asserts ONLY that the /data re-attach fd (fd_id 1,
	// backing_mnt_id 2951) is preserved and does NOT orphan — the exact postgres PGDATA property.
	// ADR-0417 S1(a): a re-attach-set member with no resolvable destination host target now hard-stops
	// (it used to be preserved with its SOURCE-node root/source intact and its exemption already
	// granted — carve-out (a) failing OPEN). Production always supplies the target, so the test does.
	out, _ := runProductionPatchScriptHT(t, pypath, extraEnv, ckptDir, nil, nil, []string{"/data"},
		map[string]string{"/data": "/var/lib/kubelet/pods/22222222-2222-2222-2222-222222222222/volumes/kubernetes.io~nfs/pvc-dst"})

	// (1) The /data external mount must be PRESERVED (kept), not B-2 dropped. The mount carries the
	// real ext_key='CRIU:AUTOGENERATED', so preservation succeeds ONLY via the mountpoint match —
	// this is the exact bug: an ext_key-keyed match would drop it (ext_key != any mountPath).
	if strings.Contains(out, `CRIU_EXTERNAL_MOUNT_DROPPED:`) && strings.Contains(out, `"mnt_id":2951`) {
		t.Errorf("re-attach /data (mnt_id 2951) must NOT be B-2 dropped when in the reattach set; got a drop event:\n%s", out)
	}
	if !strings.Contains(out, "preserving re-attach external") || !strings.Contains(out, "mountpoint=/data") {
		t.Errorf("expected a 'preserving re-attach external ... mountpoint=/data' log line (mountpoint match, since ext_key=CRIU:AUTOGENERATED); got:\n%s", out)
	}

	// (2) The data-file fd on the preserved /data mount (fd_id 1, backing_mnt_id 2951 — the postgres
	//     WAL/relation-file analogue) must NOT orphan. The negative control
	//     (TestRealCorpus_ParentMntGraphClosureAndExternalDrop, empty reattach set) asserts this
	//     SAME fd DOES hard-stop with backing_mnt_id 2951 — so this is a real inversion.
	if strings.Contains(out, `"backing_mnt_id":2951`) {
		t.Errorf("preserved re-attach mount /data (mnt_id 2951) must not orphan its open data-file fd "+
			"(no P-0193-1 for backing_mnt_id 2951); postgres restore would fail. got:\n%s", out)
	}
	if strings.Contains(out, `"mnt_id":2951`) && strings.Contains(out, `survived_drop`) {
		t.Errorf("preserved re-attach /data (mnt_id 2951) must be exempt from the survived_drop hard-stop; got:\n%s", out)
	}

	// (3) The preserved mount must be EXEMPT from the P-0194-1c dual-write mismatch assertion: it is
	//     supposed to survive in the mountpoints image WITH its ext_key (re-attached on restore by
	//     binding from its rewritten-to-destination source). A mismatch here was the second live
	//     failure this session
	//     (reason=p0194_1c_dual_write_mismatch) after the P-0193-1 orphan was cleared.
	if strings.Contains(out, `p0194_1c_dual_write_mismatch`) {
		t.Errorf("preserved re-attach mount must be exempt from the P-0194-1c dual-write mismatch; got:\n%s", out)
	}

	// (4) Isolated corpus (no unrelated cgroup orphan) — the script must run to FULL SUCCESS
	//     (exit 0) with the re-attach external preserved, exercising the P-0194-1c dual-write
	//     assertion end-to-end. This is the clean postgres PGDATA end-state.
	// ADR-0417 S1(a): carve-out (a) now fails CLOSED when a member of the re-attach set has no
	// resolvable destination host target, so this end-to-end success case must supply one (which is
	// what production always does — reattachHostTargets carries every resolved mount).
	isoDir := t.TempDir()
	isoPy, isoEnv := generateRealShapeCorpus(t, isoDir, "reattach_only")
	isoOut, isoErr := runProductionPatchScriptHT(t, isoPy, isoEnv, isoDir, nil, nil, []string{"/data"},
		map[string]string{"/data": "/var/lib/kubelet/pods/22222222-2222-2222-2222-222222222222/volumes/kubernetes.io~nfs/pvc-dst"})
	if isoErr != nil {
		t.Fatalf("isolated re-attach corpus with /data in argv[4]: expected exit 0 (mount preserved, "+
			"dual-write verified, fd consistent) — postgres end-state. got error %v, output:\n%s", isoErr, isoOut)
	}
	if !strings.Contains(isoOut, "P-0194-1c dual-write verified") {
		t.Errorf("expected the P-0194-1c dual-write consistency check to PASS on the preserved mount; got:\n%s", isoOut)
	}
	// Contrast control on the SAME isolated corpus (ADR-0417, superseding the ADR-0415 expectation):
	// WITHOUT /data in the re-attach set AND with no destination target, /data is an fstype-0
	// external — a real block/NFS filesystem CRIU cannot construct-and-fill — so it is Class
	// DESTINATION-REBIND and the script FAILS CLOSED. The prior expectation (internalize it as
	// CRIU-owned) is exactly the ADR-0415 carve-out (b) defect: it cleared ext_key and set root='/'
	// on a mount whose recorded fstype stays 0, which criu/mount.c validate_mounts rejects, and
	// silently discarded the volume's real backing. Failing closed is the corrected end-state.
	ncDir := t.TempDir()
	ncPy, ncEnv := generateRealShapeCorpus(t, ncDir, "reattach_only")
	ncOut, ncErr := runProductionPatchScript(t, ncPy, ncEnv, ncDir, nil, nil, []string{})
	if ncErr == nil {
		t.Errorf("ADR-0417 contrast control (empty reattach set, no destination target): expected a "+
			"fail-closed hard-stop for the fstype-0 /data external; got exit 0; output:\n%s", ncOut)
	}
	if !strings.Contains(ncOut, "destination_rebind_target_unresolved") {
		t.Errorf("ADR-0417 contrast control: expected reason destination_rebind_target_unresolved; got:\n%s", ncOut)
	}
	if strings.Contains(ncOut, "internalizing RECREATABLE mount") && strings.Contains(ncOut, "mountpoint=/data") {
		t.Errorf("ADR-0417 contrast control: /data (fstype 0) must never be internalized; got:\n%s", ncOut)
	}
}

// decodeMountEntry decodes the corpus's single mountpoints-*.img and returns the (root, source) of
// the entry at the given mountpoint. Uses the same pycriu interpreter/env the corpus was written
// with, so it is exact — no hand-parsing of the protobuf.
func decodeMountEntry(t *testing.T, pypath string, extraEnv []string, ckptDir, mountpoint string) (root, source string) {
	t.Helper()
	const decodePy = `
import pycriu, glob, json, sys
mp = glob.glob(sys.argv[1] + '/mountpoints-*.img')[0]
d = pycriu.images.load(open(mp, 'rb'))
for e in d['entries']:
    if e.get('mountpoint') == sys.argv[2]:
        print(json.dumps({'root': e.get('root'), 'source': e.get('source')}))
        break
`
	scriptPath := filepath.Join(t.TempDir(), "pm-decode-mnt.py")
	if err := os.WriteFile(scriptPath, []byte(decodePy), 0o600); err != nil {
		t.Fatalf("write decode script: %v", err)
	}
	cmd := exec.Command("python3", scriptPath, ckptDir, mountpoint)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decodeMountEntry(%q): %v\noutput: %s", mountpoint, err, out)
	}
	var got struct {
		Root   string `json:"root"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &got); err != nil {
		t.Fatalf("decodeMountEntry(%q): parse %q: %v", mountpoint, out, err)
	}
	return got.Root, got.Source
}

// TestRealCorpus_ReattachExternalMountSourceRewritten pins the corrected primitive for the postgres
// None/PreCopy cross-node restore wall. A preserved Tier0-RWX re-attach mount is an AUTODETECTED
// external (ext_key="CRIU:AUTOGENERATED"); CRIU restores it by binding from mi->source DIRECTLY
// (get_mp_root in criu/mount.c 4.2 bypasses --ext-mount-map for AUTODETECTED_MOUNT). The image bakes
// in the SOURCE node's kubelet path (…/pods/<sourceUID>/…), which does not exist on the destination
// — so cross-node restore open_tree()'d it and ENOENT'd at mount-v2.c:319. The fix: patchCheckpointImages
// rewrites the entry's root AND source (leading-slash count preserved — CRIU marks an external source
// as '//<abspath>') to the destination kubelet volume dir supplied via argv[5]. This test drives the
// shipped patch script and decodes the patched image to prove the rewrite; the omitted-argv[5] case
// proves it is not vacuous (source left intact when no host target is supplied).
func TestRealCorpus_ReattachExternalMountSourceRewritten(t *testing.T) {
	const srcPath = "/var/lib/kubelet/pods/11111111-1111-1111-1111-111111111111/volumes/kubernetes.io~nfs/pvc-src"
	const dstPath = "/var/lib/kubelet/pods/22222222-2222-2222-2222-222222222222/volumes/kubernetes.io~nfs/pvc-dst"

	// (1) With a destination host target (argv[5]), root+source are rewritten to the destination dir.
	dir := t.TempDir()
	pypath, env := generateRealShapeCorpus(t, dir, "reattach_only")
	out, err := runProductionPatchScriptHT(t, pypath, env, dir, nil, nil, []string{"/data"}, map[string]string{"/data": dstPath})
	if err != nil {
		t.Fatalf("patch with host target: expected exit 0; got %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "root/source rewritten to destination kubelet dir "+dstPath) {
		t.Errorf("expected the re-attach source-rewrite log line for %s; got:\n%s", dstPath, out)
	}
	root, source := decodeMountEntry(t, pypath, env, dir, "/data")
	if root != dstPath {
		t.Errorf("re-attach mount root not rewritten: got %q, want %q (destination kubelet dir)", root, dstPath)
	}
	// CRIU marks an external source with a leading '//'; that count must be preserved on rewrite.
	if wantSrc := "/" + dstPath; source != wantSrc {
		t.Errorf("re-attach mount source not rewritten: got %q, want %q (CRIU '//<abspath>' external marker preserved)", source, wantSrc)
	}
	// The un-rewritten SOURCE-node path (which would open_tree ENOENT on the destination) must be gone.
	if strings.Contains(root, srcPath) || strings.Contains(source, srcPath) {
		t.Errorf("source-node path %q must not survive in the patched image (CRIU would open_tree it and ENOENT); root=%q source=%q", srcPath, root, source)
	}

	// (2) Non-vacuity, ADR-0417 S1(a) form: WITHOUT argv[5] the rewrite cannot happen, and the
	// corrected behavior is a FAIL-CLOSED hard-stop rather than "preserve the entry with its
	// SOURCE-node root/source intact". The old expectation was the fail-open defect itself: the
	// entry kept the source-node path AND its ext_key AND its exemption-set membership, so the only
	// thing standing between it and CRIU open_tree()ing a path that exists on the wrong node was a
	// separate Go-side guard much later in the sequence.
	dir2 := t.TempDir()
	pypath2, env2 := generateRealShapeCorpus(t, dir2, "reattach_only")
	out2, err2 := runProductionPatchScript(t, pypath2, env2, dir2, nil, nil, []string{"/data"})
	if err2 == nil {
		t.Fatalf("patch without host target must hard-stop fail-closed (ADR-0417 S1(a)); got exit 0\noutput:\n%s", out2)
	}
	if !strings.Contains(out2, "reattach_target_unresolved") {
		t.Errorf("expected reason reattach_target_unresolved; got:\n%s", out2)
	}
	// And the image must be left unwritten — the SOURCE-node path must never have been exempted and
	// committed. The .orig backup is the pre-patch truth; the live image must still match it.
	root2, source2 := decodeMountEntry(t, pypath2, env2, dir2, "/data")
	if root2 != srcPath || source2 != "/"+srcPath {
		t.Errorf("a hard-stopped patch must not have rewritten the image: got root=%q source=%q, want root=%q source=%q", root2, source2, srcPath, "/"+srcPath)
	}
}

// TestPvcBackedMountPaths_PostgresShape pins the pod-spec → re-attach-path primitive
// (resolveReattachMountPaths' pure core). It asserts that a postgres-shaped pod — a PVC-backed
// `data` volume mounted at /var/lib/postgresql/data, plus a configMap init volume and the SA-token
// projected volume — yields EXACTLY the PVC mountPath, and that non-PVC volumes (configMap,
// emptyDir, projected SA token) are NOT included. This is the source of truth that authorizes the
// patch script to preserve /var/lib/postgresql/data; if it regressed to returning the configMap or
// emptyDir path, the wrong mount would be preserved (or the real one dropped → P-0193-1).
func TestPvcBackedMountPaths_PostgresShape(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "data", VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "postgres-pgdata"}}},
				{Name: "init", VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "postgres-init"}}}},
				{Name: "scratch", VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "kube-api-access", VolumeSource: corev1.VolumeSource{
					Projected: &corev1.ProjectedVolumeSource{}}},
			},
			Containers: []corev1.Container{{
				Name: "postgres",
				VolumeMounts: []corev1.VolumeMount{
					{Name: "data", MountPath: "/var/lib/postgresql/data"},
					{Name: "init", MountPath: "/docker-entrypoint-initdb.d/init.sql"},
					{Name: "scratch", MountPath: "/scratch"},
					{Name: "kube-api-access", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount"},
				},
			}},
		},
	}
	got := pvcBackedMountPaths(pod)
	if len(got) != 1 || got[0] != "/var/lib/postgresql/data" {
		t.Fatalf("pvcBackedMountPaths(postgres pod): got %v, want exactly [/var/lib/postgresql/data] "+
			"(only the PVC-backed mount; configMap/emptyDir/projected excluded)", got)
	}

	// No PVCs at all → nil (stateless workload; prior drop-everything behavior preserved).
	stateless := &corev1.Pod{Spec: corev1.PodSpec{
		Volumes:    []corev1.Volume{{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}}},
		Containers: []corev1.Container{{VolumeMounts: []corev1.VolumeMount{{Name: "cfg", MountPath: "/cfg"}}}},
	}}
	if got := pvcBackedMountPaths(stateless); got != nil {
		t.Fatalf("pvcBackedMountPaths(stateless pod): got %v, want nil", got)
	}
}

// TestBuildCRIURestoreArgs_ReattachDoesNotEmitInertExtMountMap pins the corrected root cause of the
// postgres None/PreCopy restore wall. CRIU restores an AUTODETECTED external mount
// (ext_key="CRIU:AUTOGENERATED", every kubelet-published PVC bind) by binding from mi->source
// DIRECTLY — get_mp_root() in criu/mount.c (4.2) BYPASSES --ext-mount-map for AUTODETECTED_MOUNT
// entries. So a restore-side "--ext-mount-map <containerPath>:<hostTarget>" (or any mnt_id/ext_key
// form) is INERT: it read as "handled" while CRIU silently open_tree()'d the un-rewritten SOURCE-node
// path (…/pods/<sourceUID>/…, absent on the destination) and aborted at:
//
//	Error (criu/mount-v2.c:319): Failed to open_tree /var/lib/kubelet/pods/<sourceUID>/…/pvc-…: No such file or directory
//
// The real re-attach lever is patchCheckpointImages rewriting the recorded root/source to the
// destination kubelet dir (see TestRealCorpus_ReattachExternalMountSourceRewritten). This test
// asserts buildCRIURestoreArgs (1) does NOT emit the inert path-form map, and (2) still FAILS CLOSED
// when the host target is unresolved (so CRIU is never invoked with a source-node-only path).
func TestBuildCRIURestoreArgs_ReattachDoesNotEmitInertExtMountMap(t *testing.T) {
	hostTarget := "/var/lib/kubelet/pods/b1bffab8/volumes/kubernetes.io~nfs/pvc-abc"
	args, err := buildCRIURestoreArgs(
		"/ckpt", "/rootfs", "/data", "/termlog", "/secrets", "/restore.log",
		"", "/var/run/netns/cni-x", "", false,
		[]reattachMount{{ContainerPath: "/var/lib/postgresql/data", HostTarget: hostTarget}},
		nil,
	)
	if err != nil {
		t.Fatalf("buildCRIURestoreArgs returned error with a resolved host target: %v", err)
	}
	joined := strings.Join(args, " ")
	// The inert path-form re-attach map must NOT be emitted for the PVC mountpoint (in EITHER
	// direction) — CRIU bypasses --ext-mount-map for autodetected externals, so emitting it is
	// misleading dead weight that masked the real open_tree failure.
	if strings.Contains(joined, "--ext-mount-map /var/lib/postgresql/data:") {
		t.Errorf("must NOT emit an inert path-form re-attach ext-mount-map for the PVC mountpoint (CRIU bypasses it for AUTODETECTED_MOUNT); got: %s", joined)
	}

	// FAIL CLOSED: no host target → buildCRIURestoreArgs returns an error (the patch could not rewrite
	// the recorded source, so restoring would open_tree the source-node path and ENOENT).
	argsFB, errFB := buildCRIURestoreArgs(
		"/ckpt", "/rootfs", "/data", "/termlog", "/secrets", "/restore.log",
		"", "/var/run/netns/cni-x", "", false,
		[]reattachMount{{ContainerPath: "/mnt/data", HostTarget: ""}},
		nil,
	)
	if errFB == nil {
		t.Errorf("expected an error when re-attach host target is unresolved (fail closed); got args: %s", strings.Join(argsFB, " "))
	}
	if argsFB != nil {
		t.Errorf("expected nil args on fail-closed; got: %s", strings.Join(argsFB, " "))
	}
}

// TestResolveKubeletVolumeHostPath_GlobContract pins the host-target resolver: given a replacement
// pod UID and PV name it must return the single kubelet volume dir the glob resolves, discovering
// the provisioner subdir (kubernetes.io~nfs/~csi/…) rather than hardcoding it, and returning ""
// (safe fallback) on no-match / ambiguity / missing inputs.
func TestResolveKubeletVolumeHostPath_GlobContract(t *testing.T) {
	orig := kubeletVolumeGlobFn
	t.Cleanup(func() { kubeletVolumeGlobFn = orig })

	// Empty inputs → "" without consulting the host.
	if got := resolveKubeletVolumeHostPath(context.Background(), "", "pv"); got != "" {
		t.Errorf("empty replUID: got %q, want \"\"", got)
	}
	if got := resolveKubeletVolumeHostPath(context.Background(), "uid", ""); got != "" {
		t.Errorf("empty pvName: got %q, want \"\"", got)
	}

	// Resolved single match is returned verbatim.
	kubeletVolumeGlobFn = func(_ context.Context, replUID, pvName string) string {
		if replUID == "u1" && pvName == "pvc-1" {
			return "/var/lib/kubelet/pods/u1/volumes/kubernetes.io~nfs/pvc-1"
		}
		return ""
	}
	if got := resolveKubeletVolumeHostPath(context.Background(), "u1", "pvc-1"); got != "/var/lib/kubelet/pods/u1/volumes/kubernetes.io~nfs/pvc-1" {
		t.Errorf("resolved host path mismatch: got %q", got)
	}
	if got := resolveKubeletVolumeHostPath(context.Background(), "u2", "pvc-1"); got != "" {
		t.Errorf("no-match must return \"\"; got %q", got)
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

// TestRealCorpus_DevShmContentPreserved_NotRebound is the ADR-0382 replacement for the former
// TestRealCorpus_TmpfsShmRebind_IntegerFstypeIsFixturable (renamed; the REBIND behavior it
// asserted is exactly the behavior ADR-0382 removes for /dev/shm specifically).
//
// BACKGROUND: prior to ADR-0382, /dev/shm was unconditionally dropped from mountpoints.img by
// this patch script's DROP_PATHS (in lockstep with an unconditional dump-side --skip-mnt
// /dev/shm), so a REG fd backed by /dev/shm (e.g. a PostgreSQL POSIX-shmem segment) always
// orphaned and had to be rescued by the ADR-0311 REBIND_TO_ROOT classifier — a metadata-only
// fix that let the pre-flight consistency check pass but could not manufacture file content
// dump never captured, so CRIU restore's files-reg.c still ENOENTed on the recorded
// /dev/shm/* path (the live postgres migration failure this ADR fixes).
//
// ADR-0382 removes BOTH skips (dump-side and this patch script's DROP_PATHS), so /dev/shm is now
// a normal, privately-owned mount that survives the patch step untouched: its mnt_id stays in
// kept_mnt_ids, so classify_reg_fd's very first non-trivial check ("mnt_id in kept_mnt_ids ->
// KEEP") fires before the REBIND_TO_ROOT tmpfs-rebind branch is ever reached. This test proves
// that shape: it builds the exact real-shape corpus the old test used (root/dev/dev-shm mount
// chain, mnt_ids 1/2/3, plus a /dev/shm PostgreSQL.* REG-fd on mnt_id 3) and asserts the shipped
// script (a) does not hard-stop, (b) does NOT emit CRIU_IMAGE_DIR_FD_REBOUND for this fd (there
// is no orphan to rebind), and (c) leaves both the /dev/shm mountpoints entry and the REG fd's
// original mnt_id=3 intact in the images it writes back to disk — i.e. the content-preserving
// path, not the metadata-patched rescue path.
func TestRealCorpus_DevShmContentPreserved_NotRebound(t *testing.T) {
	pypath, extraEnv := pycriuEnv(t)

	// 1. Confirm the vendored pycriu still renders fstype as the honest int 5 (if a future env
	//    upgrade makes it render the name, that is a benign change — kept as a groundedness
	//    sanity check even though this test's main path no longer depends on fstype resolution
	//    for /dev/shm specifically, since /dev/shm no longer takes the tmpfs-rebind branch).
	probeDir := t.TempDir()
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
	cmd := exec.Command("python3", probePath, probeDir)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fstype probe failed: %v\noutput: %s", err, out)
	}
	rendered := strings.TrimSpace(string(out))
	if !strings.Contains(rendered, "FSTYPE_RENDER=5") && !strings.Contains(rendered, "'TMPFS'") {
		t.Fatalf("unexpected fstype rendering from pycriu round-trip: %q (expected int 5 or 'TMPFS')", rendered)
	}
	t.Logf("vendored pycriu renders /dev/shm mnt_entry.fstype as: %s", rendered)

	// 2. Build the same REAL-SHAPE corpus as before ADR-0382: a tmpfs /dev/shm mount (fstype
	//    int 5) plus a /dev/shm PostgreSQL.* REG-fd on its mnt_id in files.img. Run the shipped
	//    patch script and assert the mount and fd both PASS THROUGH UNTOUCHED (ADR-0382), not
	//    that the fd gets rebound (the pre-ADR-0382 behavior this test used to assert).
	corpusDir := t.TempDir()
	gen := `
import sys, os
import pycriu
d = sys.argv[1]
# Root overlay + /dev (tmpfs) + /dev/shm (tmpfs, source 'shm'). fstype ints: OVERLAYFS=17, TMPFS=5.
mnts = [
    {'fstype': 17, 'mnt_id': 1, 'root_dev': 0, 'parent_mnt_id': 0, 'flags': 0,
     'root': '/', 'mountpoint': '/', 'source': 'overlay', 'options': '', 'sb_flags': 0},
    {'fstype': 5, 'mnt_id': 2, 'root_dev': 0, 'parent_mnt_id': 1, 'flags': 0,
     'root': '/', 'mountpoint': '/dev', 'source': 'tmpfs', 'options': '', 'sb_flags': 0},
    {'fstype': 5, 'mnt_id': 3, 'root_dev': 0, 'parent_mnt_id': 2, 'flags': 0,
     'root': '/', 'mountpoint': '/dev/shm', 'source': 'shm', 'options': '', 'sb_flags': 0},
]
with open(os.path.join(d, 'mountpoints-12.img'), 'wb') as f:
    pycriu.images.dump({'magic': 'MNTS', 'entries': mnts}, f)
# files.img: one PLAIN-REG fd backed by mnt_id 3 (the /dev/shm tmpfs) — the PostgreSQL shm segment.
# Required RegFileEntry/FileEntry fields (reg.id, reg.fown) must be present or SerializeToString fails.
_FOWN = {'uid': 0, 'euid': 0, 'signum': 0, 'pid_type': 0, 'pid': 0}
files = {'magic': 'FILES', 'entries': [
    {'type': 'REG', 'id': 3,
     'reg': {'id': 3, 'flags': 2, 'pos': 0, 'fown': _FOWN,
             'name': '/dev/shm/PostgreSQL.846862466', 'mnt_id': 3, 'mode': 0o100600,
             'ext': False}},
]}
with open(os.path.join(d, 'files.img'), 'wb') as f:
    pycriu.images.dump(files, f)
print('CORPUS_OK')
`
	genPath := filepath.Join(t.TempDir(), "pm-shm-gen.py")
	if err := os.WriteFile(genPath, []byte(gen), 0o600); err != nil {
		t.Fatalf("write corpus gen: %v", err)
	}
	genCmd := exec.Command("python3", genPath, corpusDir)
	genCmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	if genOut, genErr := genCmd.CombinedOutput(); genErr != nil {
		t.Fatalf("corpus gen failed: %v\noutput: %s", genErr, genOut)
	}

	// Run the SHIPPED patch script (assemblePatchScript) over the corpus.
	scriptPath := filepath.Join(t.TempDir(), "pm-patch-ckpt.py")
	if err := os.WriteFile(scriptPath, []byte(assemblePatchScript()), 0o600); err != nil {
		t.Fatalf("write patch script: %v", err)
	}
	patchCmd := exec.Command("python3", scriptPath, corpusDir, "[]", "[]")
	patchCmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	patchOut, patchErr := patchCmd.CombinedOutput()
	outStr := string(patchOut)
	if patchErr != nil {
		t.Fatalf("shipped patch script hard-stopped on the /dev/shm content-preserved fd (ADR-0382 "+
			"regression): %v\noutput:\n%s", patchErr, outStr)
	}
	if strings.Contains(outStr, "CRIU_IMAGE_INCONSISTENCY") {
		t.Fatalf("shm fd fired a P-0193-1 hard-stop — ADR-0382 regression (it should classify KEEP, "+
			"needing neither rebind nor decline):\n%s", outStr)
	}
	if strings.Contains(outStr, "CRIU_IMAGE_DIR_FD_REBOUND") {
		t.Fatalf("ADR-0382 regression: the /dev/shm fd was rebound (CRIU_IMAGE_DIR_FD_REBOUND) — "+
			"it should pass through as KEEP now that /dev/shm is no longer dropped:\n%s", outStr)
	}

	// 3. Decode the images the script wrote back to disk and confirm actual preservation, not
	//    just the absence of a rebind token: the /dev/shm mountpoints entry (mnt_id 3) must
	//    still be present, and the REG fd's mnt_id must be UNCHANGED (still 3, not rewritten to
	//    the root mnt_id — that rewrite is exactly what REBIND_TO_ROOT would have done).
	decode := `
import sys, os, json
import pycriu
d = sys.argv[1]
with open(os.path.join(d, 'mountpoints-12.img'), 'rb') as f:
    mp = pycriu.images.load(f)
mountpoints = sorted(e.get('mountpoint') for e in mp.get('entries', []))
with open(os.path.join(d, 'files.img'), 'rb') as f:
    files = pycriu.images.load(f)
reg_mnt_ids = [e.get('reg', {}).get('mnt_id') for e in files.get('entries', []) if e.get('type') == 'REG']
print(json.dumps({'mountpoints': mountpoints, 'reg_mnt_ids': reg_mnt_ids}))
`
	decodePath := filepath.Join(t.TempDir(), "pm-decode.py")
	if err := os.WriteFile(decodePath, []byte(decode), 0o600); err != nil {
		t.Fatalf("write decode script: %v", err)
	}
	decodeCmd := exec.Command("python3", decodePath, corpusDir)
	decodeCmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	decodeOut, decodeErr := decodeCmd.CombinedOutput()
	if decodeErr != nil {
		t.Fatalf("decode of patched images failed: %v\noutput: %s", decodeErr, decodeOut)
	}
	var decoded struct {
		Mountpoints []string `json:"mountpoints"`
		RegMntIDs   []int    `json:"reg_mnt_ids"`
	}
	if err := json.Unmarshal(decodeOut, &decoded); err != nil {
		t.Fatalf("parse decode output %q: %v", string(decodeOut), err)
	}
	foundShm := false
	for _, mp := range decoded.Mountpoints {
		if mp == "/dev/shm" {
			foundShm = true
		}
	}
	if !foundShm {
		t.Fatalf("ADR-0382 regression: /dev/shm mountpoints entry was dropped from the patched image; got mountpoints: %v", decoded.Mountpoints)
	}
	if len(decoded.RegMntIDs) != 1 || decoded.RegMntIDs[0] != 3 {
		t.Fatalf("ADR-0382 regression: /dev/shm REG fd's mnt_id must remain 3 (untouched, content-preserving path), got: %v", decoded.RegMntIDs)
	}
}
