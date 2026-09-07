/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0420_mount_content_axis.go — ADR-0420 D1: gate internalization on captured-content
// availability, and D1c: hold the two decoders that ask that question in lockstep by construction.
//
// THE DEFECT THIS CORRECTS (ADR-0420 M5/M6, decoded against the deployed CRIU 4.2 binaries on all
// three standing nodes and confirmed on 7/7 live restores). ADR-0417 replaced ADR-0415's OWNERSHIP
// axis with a RECREATABILITY axis, which answers "can CRIU construct this superblock type?". That
// is a necessary question. Internalizing a mount makes a SECOND question load-bearing and nothing
// asked it: "is this mount's CONTENT actually in this checkpoint?"
//
// The two are independent. A recreatable-fstype mount that was EXTERNAL at dump time has, by CRIU's
// own dump rules, no captured content — CRIU does not dump content for external mounts.
// Internalizing it hands CRIU an empty superblock to fill from an image that does not exist, and
// criu/filesystems.c tmpfs_restore returns -1 having printed NOTHING: its three failure exits all
// converge on `mov $0xffffffff,%ebp` and its only pr_err is the tar-failed branch. The caller loads
// fstype->restore through a function pointer and propagates the -1 with no print_on_level between
// the call and the failure, so a failing fstype->restore emits no "Error (criu/...)" line at all.
// The pod serviceaccount-token tmpfs is exactly that shape on every pod in the cluster.
//
// /dev/shm survives the identical treatment ONLY because this project separately BUILT a dump-side
// capture for it (ADR-0426 captureContentAbsentMounts -> tmpfs-dev-<root_dev>.tar.gz.img, with the ADR-0415
// fail-closed capture gate). That is a per-mount carve-out matched by the literal string
// "/dev/shm", standing in for a class-level rule. D1 is the class-level form of the question the
// ADR-0415 gate already asks for that one mount, put on the RESTORE side where the internalization
// decision is actually made.
//
// WHY THIS IS A SUBSTRATE PRIMITIVE AND NOT A SERVICEACCOUNT-TOKEN PATCH: the predicate names no
// path, no workload and no mountpoint. It is keyed on a fact about the checkpoint ON DISK, read
// from the directory both decoders already receive and already glob. It covers ANY runtime-injected
// external tmpfs — the serviceaccount token today, a projected-volume tmpfs, a CSI ephemeral tmpfs,
// a future sidecar-injected credential mount tomorrow — with no new code and no skip list.
// Explicitly rejected by name, as the shapes the standing substrate-primitive bias forbids: adding
// /run/secrets/kubernetes.io/serviceaccount to a skip list; a SERVICEACCOUNT_MOUNT_PATHS constant;
// dropping the offending mount; extending the dump-side capture's literal /dev/shm match to a
// second literal path; retrying the restore (there is nothing to retry — the content does not
// exist).
//
// D1c — WHY THIS IS ONE GO CONSTANT RENDERED INTO BOTH SCRIPTS RATHER THAN TWO COPIES. Two
// decoders ask the recreatability question: the patch script's classification loop
// (patch_checkpoint_script.go) and the Go-side destination-rebind DEMAND scanner
// (destinationRebindDemandScanPy). Before this ADR each carried its OWN RECREATABLE_FSTYPES
// literal, and the demand scanner `continue`d past every recreatable fstype because under ADR-0417
// those were ALWAYS internalized. Under D1 that is no longer true: a contentless recreatable tmpfs
// now routes to DESTINATION-REBIND and therefore DEMANDS a destination target. If the demand
// scanner kept skipping recreatable fstypes while the patch script started routing them, the target
// would never be demanded, never resolved, and the patch script would hard-stop on a mount the
// destination could have supplied — a FALSE STOP ON EVERY MIGRATION. Duplicating the predicate is
// therefore no longer merely untidy, it is a live failure mode, so the definition is unified here
// and rendered into both scripts. TestADR0420_ContentAxisIsTheSingleDefinitionInBothDecoders
// asserts that mechanically rather than by review.

// mountContentAxisPy is the SINGLE definition of CRIU's recreatability allowlist and of ADR-0420's
// content-availability axis. It is prepended verbatim to ALL THREE production Python decoders
// (assemblePatchScript, destinationRebindDemandScanPy, and — as of ADR-0426 D1a —
// contentCaptureDemandScanPy) and is exercised directly, in
// --content-selftest mode, by adr0420_content_availability_test.go — so the shipped predicate is
// the one that is tested, never a Go re-implementation of it (the anti-pattern that let a Go mirror
// drift from the real Python and miss defects; see patch_classify_test.go).
//
// CONTENT-BEARING, DEFINED EXPLICITLY AND FAIL-CLOSED. RECREATABLE_FSTYPES mixes two kinds of
// filesystem and the content axis applies to only one:
//
//   - Content-bearing (the axis APPLIES): TMPFS (5) and DEVTMPFS (3) — the two whose CRIU
//     fstypes[] rows carry a construct-and-fill .dump/.restore pair, i.e. the ones whose restore
//     goes looking for a content image and fails SILENTLY when it is missing.
//   - Kernel-regenerated (the axis does NOT apply): PROC (1), SYSFS (2), BINFMT_MISC (4),
//     DEVPTS (6), MQUEUE (14) — the kernel re-lays their entire content on mount, CRIU stores no
//     content image for them, and demanding one would be nonsense.
//   - DEVTMPFS is included DELIBERATELY, and the direction of the doubt is stated: whether CRIU 4.2
//     routes devtmpfs through tmpfs_restore or through a distinct hook is NOT decoded. Including it
//     is the fail-closed choice — a wrongly-demanded content image routes the entry to
//     DESTINATION-REBIND, which either resolves (correct restore) or hard-stops LOUDLY, whereas a
//     wrongly-skipped check reproduces exactly today's silent failure. RECORDED AS OWED (ADR-0420
//     out-of-scope 6a): decode fstypes[]'s devtmpfs row and narrow the set if it turns out not to
//     be content-bearing. An external devtmpfs has never been observed on this substrate.
//   - Any fstype a future CRIU adds to the recreatable allowlist inherits the content requirement
//     by default: the predicate is "content-bearing unless proven kernel-regenerated", matching
//     ADR-0417's own drift direction (fail closed on the unknown).
//
// THE LOOKUP MIRRORS tmpfs_restore's OWN TWO-STEP ORDER, and that is load-bearing rather than
// stylistic: criu/filesystems.c:437 resolves a mount's content by open_image_at(CR_FD_TMPFS_DEV,
// mi->s_dev) -> tmpfs-dev-<root_dev>.tar.gz, falling back on an EMPTY image to
// open_image_at(CR_FD_TMPFS_IMG, mi->mnt_id) -> tmpfs-<mnt_id>.tar.gz. Checking only the first name
// would classify a checkpoint that carries only the fallback image as contentless and re-externalize
// a mount that would have restored fine. Any divergence here reintroduces the silent failure, which
// is why the helper's own docstring names the CRIU function it must track. This is the single
// external contract D1 depends on: if a future CRIU renames or reorders these images, D1 silently
// reverts to today's behavior.
const mountContentAxisPy = `
import sys, os, json

# ---- ADR-0417 recreatability axis (MOVED here verbatim in ADR-0420 D1c, not redefined) ----------
#
# Source of truth: CRIU 4.2 criu/filesystems.c fstypes[]. RECREATABLE_FSTYPES is the enumerated set
# of codes for which internalizing (pop ext_key, root='/', let CRIU do_new_mount it) is CORRECT:
# either CRIU genuinely captures and re-lays the content (devtmpfs, tmpfs), or the filesystem is a
# kernel-constructed pseudo-fs whose entire content is regenerated by the kernel on mount and
# carries no source-node identity (proc, sysfs, devpts, binfmt_misc, mqueue). EVERYTHING ELSE —
# including any code a future CRIU introduces — falls through to Class DESTINATION-REBIND and must
# resolve a real destination target or hard-stop. That is the correct drift direction: a NEW
# non-recreatable filesystem (btrfs/nfs/zfs are all fstype code 0) fails closed with no code change
# instead of silently internalizing into the ADR-0415 defect.
#
# mnt_entry.fstype (criu/images/mnt.proto) is a plain protobuf uint32, NOT a TYPE_ENUM field, so
# pycriu returns the raw integer CRIU wrote (tmpfs=5), never a decoded enum-name string. Absent/None
# and 0 are both FSTYPE_UNSUPPORTED and neither is in the allowlist; anything that is not an int (a
# malformed or hostile image writing a string or object here) is likewise not in the allowlist and
# falls through to DESTINATION-REBIND — fail-closed by construction.
FSTYPE_UNSUPPORTED = 0
RECREATABLE_FSTYPES = frozenset((
    1,   # PROC        — kernel-synthesized, no captured content, CRIU mounts natively
    2,   # SYSFS       — kernel-synthesized, no captured content, CRIU mounts natively
    3,   # DEVTMPFS    — fstypes[].dump/.restore both present (construct-and-fill)
    4,   # BINFMT_MISC — kernel-constructed; registrations restored from binfmt-misc images
    5,   # TMPFS       — fstypes[].dump/.restore both present (construct-and-fill)
    6,   # DEVPTS      — fstypes[].restore present (devpts_restore); CRIU constructs it
    14,  # MQUEUE      — kernel-constructed; CRIU asserts it is empty at dump (dump_empty_fs)
))

# ---- ADR-0420 D1: the CONTENT-AVAILABILITY axis --------------------------------------------------
#
# The construct-and-fill subset of RECREATABLE_FSTYPES: the fstypes whose CRIU restore hook goes
# looking for a captured content image, and returns -1 SILENTLY when it is not there. Every other
# member of the allowlist is kernel-regenerated and stores no content image at all, so demanding one
# for those would hard-stop every migration on mounts that restore correctly today.
CONTENT_BEARING_FSTYPES = frozenset((
    3,   # DEVTMPFS — included fail-closed; its fstypes[] row is NOT decoded (ADR-0420, recorded as owed)
    5,   # TMPFS    — decoded: criu/filesystems.c tmpfs_restore
))

# Outcome vocabulary shared by both decoders. Kept as named constants so the patch script's branch
# and the demand scanner's branch cannot drift into differently-spelled string literals.
INTERNALIZE_OK = 'internalize'
INTERNALIZE_CONTENT_ABSENT = 'content_absent'
NOT_RECREATABLE = 'not_recreatable'


def _is_recreatable_fstype(fstype):
    """ADR-0417: can CRIU's own fstypes[] table construct this superblock?"""
    return isinstance(fstype, int) and not isinstance(fstype, bool) and fstype in RECREATABLE_FSTYPES


def _is_content_bearing_fstype(fstype):
    """ADR-0420: is this one of the construct-and-FILL fstypes, i.e. does its restore hook need a
    captured content image? False for the kernel-regenerated members of the recreatable allowlist."""
    return isinstance(fstype, int) and not isinstance(fstype, bool) and fstype in CONTENT_BEARING_FSTYPES


def _has_captured_content(ckpt, entry):
    """True iff this checkpoint carries the tmpfs content image CRIU's tmpfs_restore will look for.

    Mirrors criu/filesystems.c tmpfs_restore's own lookup order EXACTLY: tmpfs-dev-<root_dev> first
    (CR_FD_TMPFS_DEV, keyed on mi->s_dev), then tmpfs-<mnt_id> (CR_FD_TMPFS_IMG). Any divergence
    here reintroduces the silent failure, so this comment names the CRIU function it must track.

    Fail-closed on a missing or non-integer root_dev/mnt_id: an entry whose identifiers cannot be
    read is treated as CONTENT ABSENT, never as content present. bool is excluded explicitly
    because it is a subclass of int in Python and True would otherwise format as image name 1.
    """
    rd = entry.get('root_dev')
    mid = entry.get('mnt_id')
    if isinstance(rd, int) and not isinstance(rd, bool):
        if os.path.exists(os.path.join(ckpt, 'tmpfs-dev-%d.tar.gz.img' % rd)):
            return True
    if isinstance(mid, int) and not isinstance(mid, bool):
        if os.path.exists(os.path.join(ckpt, 'tmpfs-%d.tar.gz.img' % mid)):
            return True
    return False


def internalization_outcome(ckpt, entry):
    """The ONE decision both decoders make about one EXTERNAL mountpoints entry.

    Returns:
      INTERNALIZE_OK             — recreatable, and either kernel-regenerated (no content image is
                                   expected) or content-bearing WITH its content in this checkpoint.
                                   Pop ext_key, set root='/', let CRIU own and fill it.
      INTERNALIZE_CONTENT_ABSENT — recreatable and content-bearing, but this checkpoint carries NO
                                   content image for it. Internalizing would hand CRIU an empty
                                   superblock to fill from an image that does not exist and
                                   tmpfs_restore would fail SILENTLY (ADR-0420 M5). Falls through to
                                   Class DESTINATION-REBIND, where the destination runtime's own
                                   freshly-provisioned mount is used instead.
      NOT_RECREATABLE            — ADR-0417's existing Class DESTINATION-REBIND. Unchanged.

    Recreatability is NECESSARY BUT NOT SUFFICIENT for internalization. That is the whole decision.
    """
    fstype = entry.get('fstype')
    if not _is_recreatable_fstype(fstype):
        return NOT_RECREATABLE
    if not _is_content_bearing_fstype(fstype):
        return INTERNALIZE_OK
    if _has_captured_content(ckpt, entry):
        return INTERNALIZE_OK
    return INTERNALIZE_CONTENT_ABSENT


# --content-selftest: read {"ckpt":"<dir>","entries":[...]} from stdin, print one result object per
# entry. Dormant in production — neither production caller passes this argv (both pass the
# checkpoint directory as argv[1]). This is the entry point the Go unit tests drive, so the shipped
# predicate is what gets tested.
if len(sys.argv) >= 2 and sys.argv[1] == '--content-selftest':
    _payload = json.loads(sys.stdin.read())
    _ckpt = _payload.get('ckpt', '')
    print(json.dumps([
        {
            'outcome': internalization_outcome(_ckpt, _e),
            'recreatable': _is_recreatable_fstype(_e.get('fstype')),
            'content_bearing': _is_content_bearing_fstype(_e.get('fstype')),
            'has_content': _has_captured_content(_ckpt, _e),
        }
        for _e in _payload.get('entries', [])
    ]))
    sys.exit(0)
`
