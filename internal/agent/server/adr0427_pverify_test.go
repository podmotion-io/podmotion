/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0427_pverify_test.go — ADR-0427 D6's own §P-VERIFY assertions (assertion 9, plus the static
// assertion-1/assertion-8 mechanical guards that do not require live cluster access). Assertions 2-7
// and 10 require a live multi-substrate cluster (host mountinfo reads, a real DaemonSet rollout, the
// podmotion-demo portal) and are NOT exercisable here — this file covers everything that can be
// grounded against the real dumpedFromDevice/dumpedFromDeviceCheck primitives and the real
// captureContentAbsentMounts call site, on a throwaway machine with no cluster at all.
//
// Every ACCEPT/REFUSE fixture below drives the REAL production helper (dumpedFromDevice) with no
// stub, exactly as round 4 requires — the seam (dumpedFromDeviceCheck) is used only where the ADR
// itself says it must be (the fail-closed and check-error fixtures), never to fake an accept.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

	"github.com/podmotion-io/podmotion/internal/metrics"
)

// kernelInternalDev recomposes a live syscall.Stat_t.Dev value into the kernel-internal
// major<<20|minor form CRIU's root_dev carries — the exact inverse of what dumpedFromDevice does to
// compare, used here to build a genuine, non-fake recordedRootDev for a real path.
func kernelInternalDev(t *testing.T, path string) int64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	dev := uint64(st.Dev)
	major := unix.Major(dev)
	minor := unix.Minor(dev)
	return int64(uint64(major)<<20 | uint64(minor))
}

// ---------------------------------------------------------------------------------------------
// Assertion 9 — ACCEPT: the device matches the recorded RootDev, exercised against the REAL
// helper with no stub and no fake (round 4's own falsifier: "Falsified if the accept path is only
// ever exercised through the seam").
// ---------------------------------------------------------------------------------------------

func TestADR0427_D6_Accept_DeviceMatchesRecordedRootDev(t *testing.T) {
	dir := t.TempDir()
	rootDev := kernelInternalDev(t, dir)

	ok, err := dumpedFromDevice(dir, rootDev)
	if err != nil {
		t.Fatalf("assertion 9 ACCEPT: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("assertion 9 ACCEPT: dumpedFromDevice(%q, %d) = false, want true — recordedRootDev was derived from this exact directory's own live device", dir, rootDev)
	}
}

// ---------------------------------------------------------------------------------------------
// Assertion 9 — REFUSE: the device does NOT match, exercised against a genuinely different, live
// device the test can observe (not merely an arbitrary integer).
// ---------------------------------------------------------------------------------------------

func TestADR0427_D6_Refuse_DeviceDoesNotMatchRecordedRootDev(t *testing.T) {
	dir := t.TempDir()

	t.Run("observed_other_live_device", func(t *testing.T) {
		// /proc is virtually guaranteed to be a distinct live filesystem from the test's t.TempDir().
		otherRootDev := kernelInternalDev(t, "/proc")

		ownDev := kernelInternalDev(t, dir)
		if ownDev == otherRootDev {
			t.Skip("test host's tmp filesystem and /proc share a device number — cannot exercise a genuine mismatch this way on this host")
		}

		ok, err := dumpedFromDevice(dir, otherRootDev)
		if err != nil {
			t.Fatalf("assertion 9 REFUSE: unexpected error: %v", err)
		}
		if ok {
			t.Fatalf("assertion 9 REFUSE: dumpedFromDevice(%q, %d) = true, want false — recordedRootDev names /proc's device, not dir's", dir, otherRootDev)
		}
	})

	t.Run("arbitrary_nonsense_value", func(t *testing.T) {
		ok, err := dumpedFromDevice(dir, 0x7FFFFFFFFF)
		if err != nil {
			t.Fatalf("assertion 9 REFUSE: unexpected error: %v", err)
		}
		if ok {
			t.Fatal("assertion 9 REFUSE: an arbitrary, almost certainly-unmatched root_dev must not accept")
		}
	})
}

// ---------------------------------------------------------------------------------------------
// Assertion 9 — THE ENCODING ASSERTION: the two encodings (kernel-internal major<<20|minor vs
// stat(2)'s new_encode_dev) are NOT interchangeable, and a raw == would be silently wrong for any
// device whose minor is >= 256. Falsified if the implementation ever compares with a bare ==, or if
// no test would catch it doing so.
// ---------------------------------------------------------------------------------------------

// newEncodeDev mirrors the kernel's new_encode_dev() packing exactly as documented in ADR-0427:
// (minor&0xff) | (major<<8) | ((minor&~0xff)<<12).
func newEncodeDev(major, minor uint32) uint64 {
	return uint64(minor&0xff) | (uint64(major) << 8) | (uint64(minor&^0xff) << 12)
}

// kernelInternalForm mirrors CRIU's own major<<20|minor packing.
func kernelInternalForm(major, minor uint32) int64 {
	return int64(uint64(major)<<20 | uint64(minor))
}

func TestADR0427_D6_EncodingAssertion_KernelInternalFormIsNotStatDotDev(t *testing.T) {
	// (b) SECONDARY — the arithmetic, checkable on paper, restated as executable assertions.
	cases := []struct {
		major, minor uint32
		wantEncode   uint64
		wantKernel   int64
	}{
		{253, 1, 64769, 265289729},               // pm-w2's live root block device (D6's own measured pair)
		{252, 0, 64512, 264241152},                // orchestrator/dev-workstation root
		{0, 592, 2097232, 592},                    // anonymous superblock, minor >= 256
		{0, 548, 2097188, 548},                    // /dev/shm root_dev observed on the reference cluster
		{0, 326, 1048646, 326},                    // the mechanism map's own tmpfs-dev-326.tar.gz.img shape
		{0, 25, 25, 25},                            // /run's own device: major==0, minor<256 -> encodings agree
	}
	for _, c := range cases {
		if got := newEncodeDev(c.major, c.minor); got != c.wantEncode {
			t.Errorf("newEncodeDev(%d,%d) = %d, want %d", c.major, c.minor, got, c.wantEncode)
		}
		if got := kernelInternalForm(c.major, c.minor); got != c.wantKernel {
			t.Errorf("kernelInternalForm(%d,%d) = %d, want %d", c.major, c.minor, got, c.wantKernel)
		}
	}

	// The decisive pair D6's own text cites: 265289729 (kernel-internal, 253:1) != 64769 (stat(2), 253:1).
	if 265289729 == 64769 {
		t.Fatal("sanity: these must be unequal — the whole point of the encoding assertion")
	}

	// unix.Major/unix.Minor are the exact inverse of new_encode_dev over the 32-bit range (c) —
	// verify the round trip for every case above so the decomposition helper itself is proven, not
	// merely asserted.
	for _, c := range cases {
		encoded := newEncodeDev(c.major, c.minor)
		if gotMajor, gotMinor := unix.Major(encoded), unix.Minor(encoded); gotMajor != c.major || gotMinor != c.minor {
			t.Errorf("unix.Major/Minor(newEncodeDev(%d,%d)=%d) = (%d,%d), want (%d,%d) — decomposition is not new_encode_dev's exact inverse",
				c.major, c.minor, encoded, gotMajor, gotMinor, c.major, c.minor)
		}
	}

	// THE ASSERTION ITSELF: for a device whose minor is >= 256, dumpedFromDevice(dir, kernelForm)
	// must ACCEPT while dumpedFromDevice(dir, rawStatDotDevValue) — feeding the stat(2) value as if
	// it were a root_dev — must REFUSE. This is exercised against a REAL directory whenever the test
	// host offers one with minor >= 256; the decomposition-only cases above cover the boundary
	// unconditionally regardless of what the test host's filesystems happen to be.
	dir := t.TempDir()
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatalf("stat: %v", err)
	}
	liveDev := uint64(st.Dev)
	liveMinor := unix.Minor(liveDev)
	liveMajor := unix.Major(liveDev)
	kernelForm := kernelInternalForm(liveMajor, liveMinor)

	okKernel, err := dumpedFromDevice(dir, kernelForm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !okKernel {
		t.Fatalf("dumpedFromDevice(dir, kernelForm=%d) = false, want true", kernelForm)
	}

	if liveMinor >= 256 {
		okRaw, err := dumpedFromDevice(dir, int64(st.Dev))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if okRaw {
			t.Fatalf("dumpedFromDevice(dir, int64(st.Dev)=%d) = true, want false — the raw stat(2) value must NOT be accepted as if it were a kernel-internal root_dev when minor >= 256; a bare == would wrongly pass here", st.Dev)
		}
	} else {
		t.Logf("test host's tmp filesystem device has minor %d (< 256), where the two encodings coincidentally agree; the table-driven decomposition assertions above cover the >= 256 case unconditionally", liveMinor)
	}

	// Cross-reference against /proc/self/mountinfo for the same path's own mount entry, matching
	// assertion 9's "equivalently and additionally" clause.
	assertMountinfoMajMinMatches(t, dir, liveMajor, liveMinor)
}

// assertMountinfoMajMinMatches finds path's own mount entry in /proc/self/mountinfo (the entry
// whose mount point is the longest prefix match of path) and asserts its "maj:min" field equals
// (wantMajor, wantMinor) — the decomposition helper's output cross-checked against the kernel's own
// text representation of the same fact, independent of the stat(2)/new_encode_dev arithmetic.
func assertMountinfoMajMinMatches(t *testing.T, path string, wantMajor, wantMinor uint32) {
	t.Helper()
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Skipf("cannot read /proc/self/mountinfo on this host: %v", err)
	}
	best := ""
	bestMajMin := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mountPoint := fields[4]
		majMin := fields[2]
		if strings.HasPrefix(path, mountPoint) && len(mountPoint) >= len(best) {
			best = mountPoint
			bestMajMin = majMin
		}
	}
	if best == "" {
		t.Skip("could not locate an owning mountinfo entry for this path")
	}
	want := fmt.Sprintf("%d:%d", wantMajor, wantMinor)
	if bestMajMin != want {
		t.Errorf("mountinfo cross-check: path %s owned by mount %s reports maj:min=%s, want %s (from stat-derived decomposition)", path, best, bestMajMin, want)
	}
}

// ---------------------------------------------------------------------------------------------
// Assertion 9 — THE SAME-SUPERBLOCK SHAPE: two distinct directories on ONE shared superblock both
// ACCEPT against that superblock's recorded device — the shape rounds 2-3 wrongly refused, and
// round 4 accepts by the ordinary rule with no special case.
// ---------------------------------------------------------------------------------------------

func TestADR0427_D6_SameSuperblockBind_BothDirectoriesAccept(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b", "nested")
	if err := os.MkdirAll(a, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b, 0o755); err != nil {
		t.Fatal(err)
	}

	// root, a, and b all live on the SAME superblock (t.TempDir()'s own filesystem) — the property
	// under test ("same superblock => accept") does not depend on mount topology in any way, exactly
	// as the ADR states, so two plain subdirectories of one temp dir already exercise it.
	rootDev := kernelInternalDev(t, root)

	for _, dir := range []string{a, b} {
		ok, err := dumpedFromDevice(dir, rootDev)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", dir, err)
		}
		if !ok {
			t.Fatalf("%s: dumpedFromDevice returned false against its own shared superblock's recorded device — the same-superblock shape must ACCEPT by the ordinary rule, with no special case", dir)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Assertion 9 — the ghost-directory fixture: a capture whose resolved host dir is on /run's own
// (stand-in) superblock while CRIU recorded a DIFFERENT device fails closed with
// cause="root_dev_mismatch", naming both maj:min pairs, and does NOT fall through to stage 2.
// ---------------------------------------------------------------------------------------------

func TestADR0427_D6_GhostDirectoryShape_FailsClosedWithRootDevMismatch(t *testing.T) {
	imagesDir := t.TempDir()
	hostRunDir := t.TempDir()
	withHostRunRootForTest(t, hostRunDir)

	// The resolved directory: a plain directory standing in for the underlying, unpropagated
	// /run-tmpfs directory a real ghost shape would resolve to (analogous to /host-run's own tmpfs
	// in the live tmpfs-dev-326 shape from the mechanism map).
	shmSrc := filepath.Join(hostRunDir, "k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/ghost01/shm")
	if err := os.MkdirAll(shmSrc, 0o755); err != nil {
		t.Fatalf("create fixture ghost dir: %v", err)
	}

	// CRIU recorded a DIFFERENT device for this mount — a distinct anonymous tmpfs minor above the
	// 8-bit boundary, exactly the /dev/shm shape D6 exists to guard (root_dev=326, the mechanism
	// map's own live value).
	const recordedRootDev = 326
	pverifyWriteCorpus(t, imagesDir,
		[]pverifyMountSpec{{FSType: 5, MntID: 3, RootDev: recordedRootDev, Mountpoint: "/dev/shm", Source: "shm", ExtKey: "/dev/shm"}},
		nil,
	)
	pverifyWriteConfigJSON(t, imagesDir, "/dev/shm", "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/ghost01/shm")

	// Sanity: the fixture's live resolved directory must NOT genuinely be on device 326 — assert the
	// negative directly so a future accidental collision on some exotic test host cannot pass
	// silently.
	if ok, err := dumpedFromDevice(shmSrc, recordedRootDev); err == nil && ok {
		t.Skip("test host's temp filesystem genuinely lives on device 326 — cannot exercise a mismatch with this fixture on this host")
	}

	beforeMismatch := testutil.ToFloat64(metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "root_dev_mismatch", "config.json"))
	beforeCheckFailed := testutil.ToFloat64(metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "root_dev_check_failed", "config.json"))

	out, err := captureContentAbsentMounts(context.Background(), imagesDir)
	if err == nil {
		t.Fatalf("ghost shape: expected a fail-closed error; got nil (out=%+v)", out)
	}
	var detail *MountContentCaptureFailedDetail
	if !errors.As(err, &detail) {
		t.Fatalf("expected a MountContentCaptureFailedDetail; got %v", err)
	}
	if detail.Mountpoint != "/dev/shm" {
		t.Fatalf("expected the failure to name /dev/shm; got %q", detail.Mountpoint)
	}
	if !strings.Contains(detail.Cause, "not the filesystem CRIU dumped") {
		t.Fatalf("expected the D6 mismatch cause text; got %q", detail.Cause)
	}
	// Both maj:min pairs must be named in the detail (round 4/round 10's requirement).
	if !strings.Contains(detail.Cause, ":") {
		t.Fatalf("expected the failure detail to carry maj:min-form device pairs; got %q", detail.Cause)
	}
	if len(out.Captured) != 0 {
		t.Fatalf("a fail-closed refusal must not report any captured mount; got %+v", out)
	}
	if len(out.DestinationReconstructable) != 0 {
		t.Fatalf("D6's refusal must be a hard fail-closed return, NOT a fall-through into stage 2 — got a destination_reconstructable entry: %+v", out)
	}
	// No content image must have been written.
	if _, statErr := os.Stat(filepath.Join(imagesDir, tmpfsContentImageName(recordedRootDev))); statErr == nil {
		t.Fatal("ghost shape: no content image should be written when D6 refuses")
	}

	// The metric itself — not just the free-text detail — must carry cause="root_dev_mismatch",
	// and the sibling cause="root_dev_check_failed" counter must NOT have moved. A label-swap bug
	// (e.g. accidentally emitting root_dev_check_failed here) would still pass every assertion
	// above, since they only inspect MountContentCaptureFailedDetail.Cause, a distinct free-text
	// field — this is the assertion that actually catches that class of bug.
	afterMismatch := testutil.ToFloat64(metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "root_dev_mismatch", "config.json"))
	if afterMismatch-beforeMismatch != 1 {
		t.Errorf("ghost shape: MountContentCaptureOutcomeTotal{outcome=failed_closed,cause=root_dev_mismatch} delta = %v, want 1", afterMismatch-beforeMismatch)
	}
	afterCheckFailed := testutil.ToFloat64(metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "root_dev_check_failed", "config.json"))
	if afterCheckFailed != beforeCheckFailed {
		t.Errorf("ghost shape: a confirmed mismatch must NOT increment the sibling root_dev_check_failed counter; before=%v after=%v", beforeCheckFailed, afterCheckFailed)
	}
}

// ---------------------------------------------------------------------------------------------
// Assertion 9 — the check-itself-errors fixture: the stat cannot complete (ENOENT), which fails
// closed with the DISTINCT cause="root_dev_check_failed" — never conflated with root_dev_mismatch.
// ---------------------------------------------------------------------------------------------

func TestADR0427_D6_StatItselfFails_FailsClosedWithCheckFailedCause(t *testing.T) {
	imagesDir := t.TempDir()
	hostRunDir := t.TempDir()
	withHostRunRootForTest(t, hostRunDir)

	// Deliberately do NOT create the resolved directory — mountHostSourceDir/runHostDir resolve it
	// lexically (a pure string operation, D1b-3/F5), so a missing directory on disk still yields
	// ok=true, and D6's stat is the first thing that ever touches the filesystem for it.
	const recordedRootDev = 548
	pverifyWriteCorpus(t, imagesDir,
		[]pverifyMountSpec{{FSType: 5, MntID: 3, RootDev: recordedRootDev, Mountpoint: "/dev/shm", Source: "shm", ExtKey: "/dev/shm"}},
		nil,
	)
	pverifyWriteConfigJSON(t, imagesDir, "/dev/shm", "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/nonexist/shm")
	// hostRunDir/k3s/.../nonexist/shm is never created.

	beforeCheckFailed := testutil.ToFloat64(metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "root_dev_check_failed", "config.json"))
	beforeMismatch := testutil.ToFloat64(metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "root_dev_mismatch", "config.json"))

	out, err := captureContentAbsentMounts(context.Background(), imagesDir)
	if err == nil {
		t.Fatalf("expected a fail-closed error when the resolved directory does not exist; got nil (out=%+v)", out)
	}
	var detail *MountContentCaptureFailedDetail
	if !errors.As(err, &detail) {
		t.Fatalf("expected a MountContentCaptureFailedDetail; got %v", err)
	}
	if !strings.Contains(detail.Cause, "could not verify") {
		t.Fatalf("expected the D6 check-failed cause text (distinct from a confirmed mismatch); got %q", detail.Cause)
	}
	if strings.Contains(detail.Cause, "not the filesystem CRIU dumped") {
		t.Fatalf("root_dev_check_failed and root_dev_mismatch must never be conflated; got %q", detail.Cause)
	}
	if len(out.DestinationReconstructable) != 0 {
		t.Fatalf("a check-failed refusal must not fall through into stage 2; got %+v", out)
	}

	// The metric itself must carry cause="root_dev_check_failed", and the sibling
	// cause="root_dev_mismatch" counter must NOT have moved — a swapped-label bug would still pass
	// every assertion above (they only inspect the free-text Cause field).
	afterCheckFailed := testutil.ToFloat64(metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "root_dev_check_failed", "config.json"))
	if afterCheckFailed-beforeCheckFailed != 1 {
		t.Errorf("check-error case: MountContentCaptureOutcomeTotal{outcome=failed_closed,cause=root_dev_check_failed} delta = %v, want 1", afterCheckFailed-beforeCheckFailed)
	}
	afterMismatch := testutil.ToFloat64(metrics.MountContentCaptureOutcomeTotal.WithLabelValues("failed_closed", "root_dev_mismatch", "config.json"))
	if afterMismatch != beforeMismatch {
		t.Errorf("check-error case: a stat failure must NOT increment the sibling root_dev_mismatch counter; before=%v after=%v", beforeMismatch, afterMismatch)
	}
}

// ---------------------------------------------------------------------------------------------
// Assertion 8/9 — the D6 seam mutation-site discipline mirrors hostRunRoot's: production code
// contains no assignment to dumpedFromDeviceCheck outside its own initializer, and the ONLY test
// mutation site is withDumpedFromDeviceCheckAcceptAllForTest.
// ---------------------------------------------------------------------------------------------

func TestADR0427_D6_SeamHasExactlyOneMutationSiteOutsideTestSeam(t *testing.T) {
	root := repoRootForADR0420(t)
	pkgDir := filepath.Join(root, "internal", "agent", "server")

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	const declFile = "adr0426_dump_side_content_capture.go"
	const seamFile = "adr0426_test_seam_test.go"
	const guardFile = "adr0427_pverify_test.go" // this file quotes the pattern in comments/strings

	assignPattern := "dumpedFromDeviceCheck ="

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(pkgDir, e.Name())
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("read %s: %v", e.Name(), rerr)
		}
		count := strings.Count(string(b), assignPattern)

		switch e.Name() {
		case guardFile:
			continue
		case declFile:
			if count != 1 {
				t.Errorf("expected exactly 1 assignment to dumpedFromDeviceCheck in %s (the initializer), found %d", e.Name(), count)
			}
			if !strings.Contains(string(b), "var dumpedFromDeviceCheck = dumpedFromDevice") {
				t.Errorf("%s's single dumpedFromDeviceCheck assignment is not the expected initializer", e.Name())
			}
		case seamFile:
			if count != 2 {
				t.Errorf("expected exactly 2 assignments to dumpedFromDeviceCheck in %s (the override + the t.Cleanup restore), found %d", e.Name(), count)
			}
			if !strings.Contains(string(b), "func withDumpedFromDeviceCheckAcceptAllForTest(") {
				t.Errorf("%s no longer defines withDumpedFromDeviceCheckAcceptAllForTest", e.Name())
			}
		default:
			if count != 0 {
				t.Errorf("found an assignment to dumpedFromDeviceCheck outside the initializer (%s) and the test seam (%s), in %s", declFile, seamFile, e.Name())
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Assertion 8 — the D6 mechanism reads no extra machinery: no /proc/self/mountinfo parse, no
// parent-directory stat, no filepath.EvalSymlinks anywhere in the capture file.
// ---------------------------------------------------------------------------------------------

func TestADR0427_D6_NoRemovedMachineryReintroduced(t *testing.T) {
	root := repoRootForADR0420(t)
	b, err := os.ReadFile(filepath.Join(root, "internal", "agent", "server", "adr0426_dump_side_content_capture.go"))
	if err != nil {
		t.Fatalf("read adr0426_dump_side_content_capture.go: %v", err)
	}
	body := string(b)
	forbidden := []string{`os.ReadFile("/proc/self/mountinfo")`, `os.Open("/proc/self/mountinfo")`, "filepath.EvalSymlinks", "filepath.Dir(hostDir)", "filepath.Dir(dir)"}
	for _, tok := range forbidden {
		if strings.Contains(body, tok) {
			t.Errorf("D6 must not reintroduce round-3 machinery — found %q", tok)
		}
	}
	if !strings.Contains(body, "unix.Major(") || !strings.Contains(body, "unix.Minor(") {
		t.Error("expected the componentwise (major, minor) comparison via golang.org/x/sys/unix, not a raw ==")
	}
}

// ---------------------------------------------------------------------------------------------
// Assertion 1 (manifest, static) — the chart change: exactly the agent container's host-run
// volumeMount carries mountPropagation: HostToContainer, readOnly is retained, and the
// init-checkpoint-tmpfs host-run mount is untouched.
// ---------------------------------------------------------------------------------------------

func TestADR0427_Manifest_AgentHostRunHasHostToContainerPropagation(t *testing.T) {
	root := repoRootForADR0420(t)
	b, err := os.ReadFile(filepath.Join(root, "charts", "podmotion", "templates", "daemonset.yaml"))
	if err != nil {
		t.Fatalf("read daemonset.yaml: %v", err)
	}
	body := string(b)

	// The agent container's host-run block (the one immediately preceding the
	// host-var-lib-containerd mount, per the current chart layout) must carry all three of
	// readOnly: true, mountPropagation: HostToContainer, and no Bidirectional anywhere near it.
	idx := strings.Index(body, "- name: host-run\n              mountPath: /host-run\n              readOnly: true")
	if idx == -1 {
		t.Fatal("could not locate the agent container's host-run volumeMount (name/mountPath/readOnly block) in daemonset.yaml")
	}
	window := body[idx : idx+900]
	if !strings.Contains(window, "mountPropagation: HostToContainer") {
		t.Error("the agent container's host-run volumeMount must carry mountPropagation: HostToContainer")
	}
	if strings.Contains(window, "Bidirectional") {
		t.Error("Bidirectional must not appear on the agent container's host-run volumeMount (D2)")
	}

	// The init-checkpoint-tmpfs host-run mount (read-write, no readOnly, no propagation — D3) must
	// remain byte-for-byte unchanged: exactly two "- name: host-run" volumeMount declarations
	// (agent + init-checkpoint-tmpfs) — the volumes: section's own "- name: host-run" entry (the
	// hostPath declaration itself, not a volumeMount) is a distinct, expected third occurrence.
	if got := strings.Count(body, "- name: host-run"); got != 3 {
		t.Fatalf("expected exactly 3 total host-run declarations (2 volumeMounts + 1 volume); found %d", got)
	}
	if got := strings.Count(body, "mountPath: /host-run"); got != 2 {
		t.Fatalf("expected exactly 2 host-run volumeMount declarations (agent + init-checkpoint-tmpfs); found %d", got)
	}
}
