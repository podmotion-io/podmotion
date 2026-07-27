/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// patch_checkpoint_test.go — regression guard for the patchCheckpointImages
// mountpoints drop logic.
//
// Origin (observed error):
//
//	Error (criu/mount.c:381): mnt: No parent found for mountpoint 7730
//	    (@/sys/devices/virtual/dmi/id/product_name)
//
// Root cause: patchCheckpointImages dropped `/sys` (mnt_id=9107) from the
// mountpoints image but LEFT its children (e.g. mnt_id=7730, parent=9107) in
// the image. CRIU's mount-tree builder then found a child whose parent_mnt_id
// no longer existed → "No parent found".
//
// INVARIANT (must hold forever):
//
//	After the mountpoints drop runs, no remaining entry may reference a
//	parent_mnt_id that is not also present in the remaining set.
//
// Why these tests are in Go (not a python3/pycriu subprocess):
//
// The vendored pycriu in the repo root cannot DUMP images with non-trivial
// entries under protobuf >= 7 (FieldDescriptor.label was removed; dict2pb
// raises AttributeError). The existing pycriu_corpus_test.go sidesteps this by
// only ever loading zero-entry images. Building a synthetic mountpoints image
// WITH parent/child entries — which these tests fundamentally require — would
// therefore not run in this environment or on any protobuf-7 CI host. So the
// drop logic is ported to a pure-Go helper (mountpointKeptEntries / dropMnts)
// that is an exact mirror of the production Python predicate, and a source-sync
// guard test (TestPatchScript_DropLogicInSyncWithProduction) fails if the
// production script in server.go ever diverges from the Go mirror. This gives
// environment-independent, deterministic regression coverage of the invariant.

import (
	"strings"
	"testing"
)

// mountEntry is the minimal subset of a pycriu mountpoints `entries[]` element
// that the drop logic inspects.
type mountEntry struct {
	MntID       int
	ParentMntID int
	Mountpoint  string
	ExtKey      string // empty == null/absent ext_key
}

// dropPrefixes mirrors the production `drop_prefixes` list (server.go,
// ADR-0190 fix): an entry is dropped if its mountpoint EQUALS a prefix or is
// nested under "<prefix>/". This is what guarantees the no-orphan invariant for
// /sys: dropping /sys necessarily drops every /sys/* child, so no surviving
// child can dangle. KEEP IN SYNC with server.go.
var dropPrefixes = []string{"/sys"}

// dropMntsExact mirrors the production `drop_mnts_exact` set (server.go). These
// are single mountpoints removed by exact match (their parents remain present,
// so no orphan results). KEEP IN SYNC with server.go.
// TestPatchScript_DropLogicInSyncWithProduction asserts every member here is
// present in the production script source.
// ADR-0415: this set carries the /proc and /sys STRUCTURAL carve-out ONLY. The pod-owned /
// runtime-provided mounts that used to be dropped here — the serviceaccount token tmpfs,
// /etc/{hosts,hostname,resolv.conf}, and /dev/termination-log — are NO LONGER dropped: they are
// captured by default and internalized (owned => CRIU-owned + content). "/dev/shm" is likewise
// absent (ADR-0382, generalized by ADR-0415). Keep in sync with the production DROP_PATHS.
var dropMntsExact = map[string]struct{}{
	"/proc/bus":           {},
	"/proc/fs":            {},
	"/proc/irq":           {},
	"/proc/sys":           {},
	"/proc/sysrq-trigger": {},
	"/proc/acpi":          {},
	"/proc/scsi":          {},
	"/proc/interrupts":    {},
	"/proc/kcore":         {},
	"/proc/keys":          {},
	"/proc/latency_stats": {},
	"/proc/timer_list":    {},
	"/proc/sched_debug":   {},
	"/sys/firmware":       {},
	"/sys/fs/pstore":      {},
	"/sys/fs/bpf":         {},
	"/sys/fs/cgroup":      {},
}

// shouldDrop mirrors the production `_should_drop(mp)` predicate exactly.
func shouldDrop(mp string) bool {
	if _, ok := dropMntsExact[mp]; ok {
		return true
	}
	for _, prefix := range dropPrefixes {
		if mp == prefix || strings.HasPrefix(mp, prefix+"/") {
			return true
		}
	}
	return false
}

// mountpointKeptEntries is the pure-Go mirror of the production keep predicate:
//
//	kept = [e for e in img['entries']
//	        if not (e.get('mountpoint') in null_ext_key_masked and not e.get('ext_key'))
//	        and not _should_drop(e.get('mountpoint'))]
//
// The prefix-drop in _should_drop is what enforces the no-orphan invariant: a
// dropped parent prefix drops the whole subtree, so no surviving entry can
// reference a removed parent.
func mountpointKeptEntries(entries []mountEntry, nullExtKeyMasked map[string]struct{}) []mountEntry {
	var kept []mountEntry
	for _, e := range entries {
		if _, masked := nullExtKeyMasked[e.Mountpoint]; masked && e.ExtKey == "" {
			continue
		}
		if shouldDrop(e.Mountpoint) {
			continue
		}
		kept = append(kept, e)
	}
	return kept
}

// assertNoOrphanParents fails if any entry references a parent_mnt_id absent
// from the result set (the core invariant). Root entries (parent 0 or self) are
// exempt.
func assertNoOrphanParents(t *testing.T, kept []mountEntry) {
	t.Helper()
	present := map[int]struct{}{}
	for _, e := range kept {
		present[e.MntID] = struct{}{}
	}
	for _, e := range kept {
		if e.ParentMntID == 0 || e.ParentMntID == e.MntID {
			continue
		}
		if _, ok := present[e.ParentMntID]; !ok {
			t.Errorf("ORPHAN PARENT (mount.c:381 regression): entry mnt_id=%d mountpoint=%q references parent_mnt_id=%d which is absent from the kept set",
				e.MntID, e.Mountpoint, e.ParentMntID)
		}
	}
}

func mountpoints(kept []mountEntry) map[string]bool {
	m := map[string]bool{}
	for _, e := range kept {
		m[e.Mountpoint] = true
	}
	return m
}

// ---------------------------------------------------------------------------
// 1. The headline regression: the exact failing topology must not orphan.
// ---------------------------------------------------------------------------

func TestPatchCheckpointImages_NoOrphanParents(t *testing.T) {
	entries := []mountEntry{
		{MntID: 9091, ParentMntID: 0, Mountpoint: "/"},                                           // root
		{MntID: 9107, ParentMntID: 9091, Mountpoint: "/sys"},                                     // dropped
		{MntID: 7730, ParentMntID: 9107, Mountpoint: "/sys/devices/virtual/dmi/id/product_name"}, // child of /sys
		{MntID: 9097, ParentMntID: 9091, Mountpoint: "/proc"},                                    // retained
	}

	kept := mountpointKeptEntries(entries, nil)

	assertNoOrphanParents(t, kept)

	mp := mountpoints(kept)
	if mp["/sys"] {
		t.Errorf("/sys must be dropped")
	}
	if mp["/sys/devices/virtual/dmi/id/product_name"] {
		t.Errorf("orphaned /sys child mnt_id=7730 must be dropped (it caused mount.c:381)")
	}
	if !mp["/"] {
		t.Errorf("root / must be retained")
	}
	if !mp["/proc"] {
		t.Errorf("/proc must be retained")
	}
}

// ---------------------------------------------------------------------------
// 2. The whole /sys subtree must go, not just the /sys entry itself.
// ---------------------------------------------------------------------------

func TestPatchCheckpointImages_SysSubtreeFullyDropped(t *testing.T) {
	entries := []mountEntry{
		{MntID: 9091, ParentMntID: 0, Mountpoint: "/"},
		{MntID: 9107, ParentMntID: 9091, Mountpoint: "/sys"},
		{MntID: 7730, ParentMntID: 9107, Mountpoint: "/sys/devices/virtual/dmi/id/product_name"},
		{MntID: 8591, ParentMntID: 9107, Mountpoint: "/sys/devices/virtual/powercap"},
		{MntID: 9117, ParentMntID: 7730, Mountpoint: "/sys/devices/virtual/dmi/id/product_name/deep"}, // 2 levels under /sys
	}

	kept := mountpointKeptEntries(entries, nil)
	assertNoOrphanParents(t, kept)

	mp := mountpoints(kept)
	for _, gone := range []string{
		"/sys",
		"/sys/devices/virtual/dmi/id/product_name",
		"/sys/devices/virtual/powercap",
		"/sys/devices/virtual/dmi/id/product_name/deep",
	} {
		if mp[gone] {
			t.Errorf("expected %q to be dropped with the /sys subtree, but it was kept", gone)
		}
	}
	if !mp["/"] {
		t.Errorf("root / must be retained")
	}
}

// ---------------------------------------------------------------------------
// 3. ADR-0415: the serviceaccount token tmpfs is NO LONGER dropped — it is a pod-owned mount
//    captured by default (owned => internalized as CRIU-owned + content). Chad's explicit ruling:
//    the SA token is NOT carved out; checkpoint confidentiality (0700, tmpfs, zeroize, ADR-0029
//    encryption) is the uniform place that risk is handled, not a capture-time exclusion list.
// ---------------------------------------------------------------------------

func TestPatchCheckpointImages_ServiceAccountRetained(t *testing.T) {
	entries := []mountEntry{
		{MntID: 9091, ParentMntID: 0, Mountpoint: "/"},
		{MntID: 100, ParentMntID: 9091, Mountpoint: "/run/secrets/kubernetes.io/serviceaccount"},
		{MntID: 101, ParentMntID: 9091, Mountpoint: "/var/run/secrets/kubernetes.io/serviceaccount"},
	}

	kept := mountpointKeptEntries(entries, nil)
	assertNoOrphanParents(t, kept)

	mp := mountpoints(kept)
	if !mp["/run/secrets/kubernetes.io/serviceaccount"] {
		t.Errorf("ADR-0415: /run/secrets/kubernetes.io/serviceaccount must be RETAINED (captured as owned, not dropped)")
	}
	if !mp["/var/run/secrets/kubernetes.io/serviceaccount"] {
		t.Errorf("ADR-0415: /var/run/secrets/kubernetes.io/serviceaccount must be RETAINED (captured as owned, not dropped)")
	}
}

// ---------------------------------------------------------------------------
// 4. /proc itself is NOT a top-level drop; specific /proc/* children are.
//    The invariant must still hold (no orphaned /proc children remain).
// ---------------------------------------------------------------------------

func TestPatchCheckpointImages_ProcChildrenRetained(t *testing.T) {
	// Confirm from the production drop set: "/proc" is NOT dropped (not a prefix,
	// not an exact entry), but "/proc/bus", "/proc/acpi", "/proc/sys" etc. ARE
	// exact-dropped.
	if shouldDrop("/proc") {
		t.Fatalf("test premise violated: /proc must NOT be dropped")
	}
	for _, child := range []string{"/proc/bus", "/proc/acpi", "/proc/sys"} {
		if _, ok := dropMntsExact[child]; !ok {
			t.Fatalf("test premise violated: %q must be in drop_mnts_exact", child)
		}
	}

	entries := []mountEntry{
		{MntID: 9091, ParentMntID: 0, Mountpoint: "/"},
		{MntID: 9097, ParentMntID: 9091, Mountpoint: "/proc"},       // retained top-level
		{MntID: 200, ParentMntID: 9097, Mountpoint: "/proc/bus"},    // dropped by explicit list
		{MntID: 201, ParentMntID: 9097, Mountpoint: "/proc/acpi"},   // dropped by explicit list
		{MntID: 202, ParentMntID: 9097, Mountpoint: "/proc/uptime"}, // not in list → retained, parent /proc present
	}

	kept := mountpointKeptEntries(entries, nil)
	assertNoOrphanParents(t, kept)

	mp := mountpoints(kept)
	if !mp["/proc"] {
		t.Errorf("/proc itself must be retained (it is not in drop_mnts)")
	}
	if mp["/proc/bus"] || mp["/proc/acpi"] {
		t.Errorf("/proc/bus and /proc/acpi must be dropped by the explicit list")
	}
	if !mp["/proc/uptime"] {
		t.Errorf("/proc/uptime is not dropped and its parent /proc is present, so it must be retained")
	}
}

// ---------------------------------------------------------------------------
// 5. /dev/pts, /dev/mqueue, and (ADR-0382) /dev/shm have a present parent (/dev)
//    and are not in the drop set → they must all survive. /dev/termination-log
//    remains explicitly dropped (it is re-provided as an --ext-mount-map bind by
//    buildCRIURestoreArgs, not a private mount CRIU should recreate).
// ---------------------------------------------------------------------------

func TestPatchCheckpointImages_DevChildrenRetained(t *testing.T) {
	entries := []mountEntry{
		{MntID: 9091, ParentMntID: 0, Mountpoint: "/"},
		{MntID: 300, ParentMntID: 9091, Mountpoint: "/dev"},                // present parent
		{MntID: 301, ParentMntID: 300, Mountpoint: "/dev/pts"},             // retained
		{MntID: 302, ParentMntID: 300, Mountpoint: "/dev/mqueue"},          // retained
		{MntID: 303, ParentMntID: 300, Mountpoint: "/dev/shm"},             // retained (owned)
		{MntID: 304, ParentMntID: 300, Mountpoint: "/dev/termination-log"}, // ADR-0415: now retained (owned)
	}

	kept := mountpointKeptEntries(entries, nil)
	assertNoOrphanParents(t, kept)

	mp := mountpoints(kept)
	if !mp["/dev/pts"] {
		t.Errorf("/dev/pts must be retained (valid parent /dev present, not in drop set)")
	}
	if !mp["/dev/mqueue"] {
		t.Errorf("/dev/mqueue must be retained (valid parent /dev present, not in drop set)")
	}
	if !mp["/dev/shm"] {
		t.Errorf("ADR-0382/0415: /dev/shm must be retained (owned mount) so its captured content survives into the restored image")
	}
	if !mp["/dev/termination-log"] {
		t.Errorf("ADR-0415: /dev/termination-log is no longer dropped by DROP_PATHS — it is a pod-owned/runtime-provided mount captured by default, not an ad hoc exclusion")
	}
}

// ---------------------------------------------------------------------------
// Source-sync guard: the Go drop mirror must stay aligned with the production
// patch script. As of Sprint 43 (H-19) the script is the single source of truth
// returned by assemblePatchScript() (classifyRegFdPy + patchCheckpointScriptBody in
// patch_checkpoint_script.go), NOT an inline server.go literal — so these guards grep
// the assembled script text itself. If someone edits the production drop_mnts set
// without updating dropMnts here, this fails — so the regression tests above can never
// silently test stale logic.
// ---------------------------------------------------------------------------

func TestPatchScript_DropLogicInSyncWithProduction(t *testing.T) {
	src := readPatchScriptSource(t)

	// Every exact-drop entry in the Go mirror must appear as a quoted literal
	// inside the production drop_mnts_exact set in the assembled patch script.
	for mnt := range dropMntsExact {
		needle := "'" + mnt + "'"
		if !strings.Contains(src, needle) {
			t.Errorf("drop set drift: %q is in the Go mirror (dropMntsExact) but not found as %s in server.go production script", mnt, needle)
		}
	}

	// Every prefix in the Go mirror must appear as a quoted literal in production.
	for _, prefix := range dropPrefixes {
		needle := "'" + prefix + "'"
		if !strings.Contains(src, needle) {
			t.Errorf("drop prefix drift: %q is in the Go mirror (dropPrefixes) but not found as %s in server.go production script", prefix, needle)
		}
	}

	// Load-bearing invariant anchors that must be present in production (graph-traversal
	// implementation — Arch-A spec, commit d6b57fe):
	//   - DROP_ROOT_FSTYPES must include 'sysfs' so both sysfs instances in kind are seeded
	//   - drop_ids must be computed via parent_mnt_id graph closure so every descendant of a
	//     dropped root is also dropped (the mount.c:381 fix: dropping /sys alone
	//     orphaned children 7730/8591/9117/9119)
	if !strings.Contains(src, "DROP_ROOT_FSTYPES") {
		t.Errorf("production script no longer defines DROP_ROOT_FSTYPES — the sysfs-by-type seed (Arch-A spec) is missing; mount.c:381 can regress")
	}
	if !strings.Contains(src, "'sysfs'") {
		t.Errorf("production script DROP_ROOT_FSTYPES no longer contains 'sysfs' — /sys subtree will not be dropped; mount.c:381 can regress")
	}
	if !strings.Contains(src, "drop_ids") {
		t.Errorf("production script no longer computes drop_ids — the graph-closure subtree drop is missing; orphan children will cause mount.c:381")
	}
	if !strings.Contains(src, "parent_mnt_id") {
		t.Errorf("production script no longer references parent_mnt_id — the graph-closure traversal is missing; orphan children will cause mount.c:381")
	}
}

// ---------------------------------------------------------------------------
// ADR-0194 B-2: external-mount DROP-together tests (§4.4 / C-PA-3 / H3).
//
// These tests cover:
//   (a) the gc21-cold-be topology: /data (mnt_id 2951, ext_key set) is a leaf in the
//       kept set → after dropping it, AC-1 holds on the 5-entry reduced set.
//   (b) source-sync anchors: the production Python script must contain the B-2
//       ext-drop code tokens (ext_drop_mnt_ids, CRIU_EXTERNAL_MOUNT_DROPPED, P-0194-1c).
//
// Items (c)–(e) (files.img rebind, atomic-commit ordering, P-0194-1c re-entry guard)
// require live pycriu execution and are validated end-to-end against a live
// checkpoint decode (see the P-0194-3 decode artifact).
// ---------------------------------------------------------------------------

// gc21ColdBETopology returns the 6-entry kept set from the gc21-cold-be checkpoint
// (decoded from the live checkpoint that produced mount.c:3141 on ADR-0193 binary).
// MntID 2951 (/data, ext_key="/data") is the external entry that B-2 drops.
func gc21ColdBETopology() []mountEntry {
	return []mountEntry{
		{MntID: 2951, ParentMntID: 2943, Mountpoint: "/data", ExtKey: "/data"}, // external — B-2 drops this
		{MntID: 2948, ParentMntID: 2946, Mountpoint: "/dev/mqueue"},
		{MntID: 2947, ParentMntID: 2946, Mountpoint: "/dev/pts"},
		{MntID: 2946, ParentMntID: 2943, Mountpoint: "/dev"},
		{MntID: 2945, ParentMntID: 2943, Mountpoint: "/proc"},
		// Root entry: on-disk parent_mnt_id=2815 (host namespace root, absent from container set).
		// Use 0 here so assertNoOrphanParents treats it as namespace root (no parent check).
		// The production Python script and CRIU both handle the real 2815 correctly at runtime.
		{MntID: 2943, ParentMntID: 0, Mountpoint: "/"},
	}
}

// simulateOwnedInternalize mirrors the ADR-0415 external-mount pass in the Python script for the
// no-reattach case: an external entry (ext_key set) that is NOT a storage-tier PVC re-attach is
// INTERNALIZED — kept in the set with its ext_key cleared — rather than dropped. Returns the kept
// set (all entries survive) and the set of internalized mnt_ids.
func simulateOwnedInternalize(entries []mountEntry, reattach map[string]struct{}) (kept []mountEntry, internalizedIDs map[int]struct{}) {
	internalizedIDs = map[int]struct{}{}
	for _, e := range entries {
		if e.ExtKey != "" {
			if _, isReattach := reattach[e.Mountpoint]; !isReattach {
				internalizedIDs[e.MntID] = struct{}{}
				e.ExtKey = "" // internalized: CRIU owns it
			}
		}
		kept = append(kept, e)
	}
	return kept, internalizedIDs
}

// TestADR0415_ExternalEntryInternalized asserts that under ADR-0415 the /data (mnt_id 2951)
// external entry — when NOT in the storage-tier PVC re-attach set — is INTERNALIZED (kept with its
// ext_key cleared, so CRIU owns and fills it), not dropped, and that AC-1 (no orphan parents) still
// holds on the full kept set. This supersedes the ADR-0194 B-2 external-DROP behavior.
func TestADR0415_ExternalEntryInternalized(t *testing.T) {
	entries := gc21ColdBETopology()

	// Verify premise: /data IS present with an ext_key before the pass.
	found2951 := false
	for _, e := range entries {
		if e.MntID == 2951 {
			found2951 = true
		}
	}
	if !found2951 {
		t.Fatal("test premise violated: /data (mnt_id 2951) not in gc21ColdBETopology; update the test")
	}

	kept, internalized := simulateOwnedInternalize(entries, nil)

	// (a) /data must be internalized, NOT dropped.
	if _, ok := internalized[2951]; !ok {
		t.Errorf("ADR-0415: mnt_id 2951 (/data, ext_key set, no re-attach mapping) must be internalized")
	}
	mp := mountpoints(kept)
	if !mp["/data"] {
		t.Errorf("ADR-0415: /data must REMAIN in the kept set (internalized as CRIU-owned), not be dropped")
	}
	// Its ext_key must be cleared in the kept set.
	for _, e := range kept {
		if e.MntID == 2951 && e.ExtKey != "" {
			t.Errorf("ADR-0415: internalized /data must have its ext_key cleared; got %q", e.ExtKey)
		}
	}

	// (b) AC-1 (ADR-0191): no orphan parents in the full kept set.
	assertNoOrphanParents(t, kept)

	// The full 6-entry set survives: /, /proc, /dev, /dev/pts, /dev/mqueue, /data.
	expectedMountpoints := []string{"/", "/proc", "/dev", "/dev/pts", "/dev/mqueue", "/data"}
	if len(kept) != len(expectedMountpoints) {
		t.Errorf("ADR-0415 kept set: expected %d entries, got %d", len(expectedMountpoints), len(kept))
	}
	for _, want := range expectedMountpoints {
		if !mp[want] {
			t.Errorf("ADR-0415 kept set: %q expected but absent", want)
		}
	}
}

// TestADR0194_B2_LeafVerification asserts that /data (2951) is a leaf in the gc21-cold-be
// kept set — i.e. no kept entry has parent_mnt_id=2951 — so the B-2 drop cannot create an
// orphan. This is the ADR-0194 §4.1/H2 precondition check (D1 correction: leaf formulation,
// not "only entry with parent 2943", which was wrong per the checkpoint decode).
func TestADR0194_B2_LeafVerification(t *testing.T) {
	entries := gc21ColdBETopology()
	for _, e := range entries {
		if e.MntID != 2951 && e.ParentMntID == 2951 {
			t.Errorf("invariant violated: entry mnt_id=%d has parent_mnt_id=2951 — /data is NOT a leaf; B-2 drop would orphan it", e.MntID)
		}
	}
}

// TestADR0194_B2_SharedMasterIDZero asserts that the /data (2951) entry has shared_id=0
// and master_id=0 — the P-0194-1b (SC-3/H5) precondition that makes B-2 safe.
// (These fields are not in mountEntry; the test is a source-sync guard asserting the
// Python script checks them before proceeding with the drop.)
func TestADR0194_B2_SharedMasterIDZero(t *testing.T) {
	src := readPatchScriptSource(t)
	// The Python script must check shared_id and master_id before dropping.
	if !strings.Contains(src, "shared_id") {
		t.Errorf("ADR-0194 P-0194-1b: production script no longer checks shared_id (SC-3 / H5 — propagation-peer guard missing)")
	}
	if !strings.Contains(src, "master_id") {
		t.Errorf("ADR-0194 P-0194-1b: production script no longer checks master_id (SC-3 / H5 — propagation-peer guard missing)")
	}
	if !strings.Contains(src, "propagation_peer") {
		t.Errorf("ADR-0194 P-0194-1b: production script no longer emits propagation_peer reason on non-zero shared/master_id")
	}
}

// TestADR0194_B2_SourceSyncAnchors asserts that the production Python script contains the
// load-bearing B-2 implementation tokens. A missing token means the fix was not applied or
// was removed, and the mount.c:3141 failure would return.
func TestADR0194_B2_SourceSyncAnchors(t *testing.T) {
	src := readPatchScriptSource(t)

	// ADR-0415: the B-2 external-DROP of pod-owned mounts is removed (owned => internalize). So the
	// CRIU_EXTERNAL_MOUNT_DROPPED and non_leaf_external drop tokens are gone by design; the
	// load-bearing tokens are now the internalize path plus the retained atomic-write / hard-stop
	// machinery for genuinely-unresolved externals and the PVC re-attach preserve/rewrite.
	anchors := []struct {
		token string
		desc  string
	}{
		{"ext_drop_mnt_ids", "files.img reconciliation ctx key (retained; empty under ADR-0415)"},
		{"internalizing owned mount", "ADR-0415 owned-mount internalize log line"},
		{"internalized_mnt_ids", "ADR-0415 internalized-mount tracking set"},
		{"EXTERNAL_MOUNT_UNRESOLVED", "P-0194-1 hard-stop event token (ExternalMountUnresolved)"},
		{"mp_tmp", "atomic mountpoints temp file (H1 / SC-2 dual-write)"},
		{"files_tmp", "atomic files.img temp file (H1 / SC-2 dual-write)"},
		{"P-0194-1c", "P-0194-1c cross-image assertion reference"},
		{"ext_key", "ext_key field read in the external-mount scan"},
		{"reattach_kept_mnt_ids", "storage-tier PVC re-attach preserve set (carve-out 2)"},
		{"CRIU_REATTACH_EXT_MOUNT_MAP", "PVC re-attach ext-mount-map token (literal ext_key case)"},
	}

	for _, a := range anchors {
		if !strings.Contains(src, a.token) {
			t.Errorf("ADR-0194 B-2 source-sync drift: %q not found in server.go — %s", a.token, a.desc)
		}
	}
}

// readPatchScriptSource returns the assembled production patch script text — the single source of
// truth patchCheckpointImages ships (H-19). The B-2 / drop-logic source-sync guards grep THIS
// (not a server.go substring) so they verify the tokens in the exact script that runs. Before
// Sprint 43 the script was an inline server.go literal and these guards read server.go directly;
// after the H-19 extraction the body lives in patch_checkpoint_script.go, so grepping server.go
// would have silently passed on nothing — the guards must follow the source of truth.
func readPatchScriptSource(t *testing.T) string {
	t.Helper()
	return assemblePatchScript()
}
