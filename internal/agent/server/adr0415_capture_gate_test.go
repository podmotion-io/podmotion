/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// adr0415_capture_gate_test.go — ADR-0415's fail-closed capture gate, RETARGETED by ADR-0426 D1e at
// captureContentAbsentMounts (the class-level primitive that replaces the deleted
// /dev/shm-literal captureCtrDevShmContent). The fail-closed CONTRACT ADR-0415 established is
// preserved exactly; only its subject widens.
//
// Round-3 note carried into this retarget: the gating condition is the mount's OCI SOURCE CLASS, not
// a demand count — every fixture below is at ZERO files.img demand (this generator never writes a
// files.img at all) so a future re-introduction of demand-gating on the dump side would fail here.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"
)

// writeDevShmMountpointsImg generates a single mountpoints-10.img with the given /dev/shm ext_key
// and root_dev via the vendored pycriu, matching the ctr fast path's recorded shape. The mountpoints
// `source` field for the synthetic /dev/shm entry is always the bare non-path string "shm" (F8c fact
// 1's ctr-path shape) — deliberately not a candidate for either the reachability fallback or the
// RECONSTRUCTABLE classification.
func writeDevShmMountpointsImg(t *testing.T, imagesDir, devShmExtKey string, rootDev int, includeDevShm bool) {
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
    {'fstype': 5, 'mnt_id': 2, 'root_dev': 0, 'parent_mnt_id': 1, 'flags': 0,
     'root': '/', 'mountpoint': '/dev', 'source': 'tmpfs', 'options': '', 'sb_flags': 0},
]
if spec.get('include_devshm'):
    e = {'fstype': 5, 'mnt_id': 3, 'root_dev': spec.get('root_dev', 0), 'parent_mnt_id': 2,
         'flags': 0, 'root': '/', 'mountpoint': '/dev/shm', 'source': 'shm', 'options': '', 'sb_flags': 0}
    if spec.get('ext_key'):
        e['ext_key'] = spec['ext_key']
    mnts.append(e)
with open(os.path.join(d, 'mountpoints-10.img'), 'wb') as f:
    pycriu.images.dump({'magic': 'MNTS', 'entries': mnts}, f)
print('CORPUS_OK')
`
	genPath := filepath.Join(t.TempDir(), "devshm-corpus-gen.py")
	if err := os.WriteFile(genPath, []byte(genPy), 0o600); err != nil {
		t.Fatalf("write corpus gen: %v", err)
	}
	spec := `{"include_devshm":` + boolStr(includeDevShm) + `,"ext_key":"` + devShmExtKey + `","root_dev":` + itoa(rootDev) + `}`
	cmd := exec.Command("python3", genPath, imagesDir, spec)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate devshm corpus: %v\n%s", err, out)
	}
}

// writeExternalTmpfsMountpointsImg generates a single mountpoints-10.img carrying ONE external,
// content-bearing (fstype=5, TMPFS) mount at mountpoint, with the given raw mountpoints `source`
// string — used to fixture the projected-volume RECONSTRUCTABLE class over a non-/dev/shm mountpoint
// (the raw-path serviceaccount-token shape, F8c/F8d), where mountpointsSource IS the full host path.
func writeExternalTmpfsMountpointsImg(t *testing.T, imagesDir, mountpoint, source string, rootDev int) {
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
    {'fstype': 5, 'mnt_id': 9, 'root_dev': spec['root_dev'], 'parent_mnt_id': 1, 'flags': 0,
     'root': '/', 'mountpoint': spec['mountpoint'], 'source': spec['source'],
     'ext_key': spec['mountpoint'], 'options': '', 'sb_flags': 0},
]
with open(os.path.join(d, 'mountpoints-10.img'), 'wb') as f:
    pycriu.images.dump({'magic': 'MNTS', 'entries': mnts}, f)
print('CORPUS_OK')
`
	genPath := filepath.Join(t.TempDir(), "ext-tmpfs-corpus-gen.py")
	if err := os.WriteFile(genPath, []byte(genPy), 0o600); err != nil {
		t.Fatalf("write corpus gen: %v", err)
	}
	spec, err := json.Marshal(map[string]any{
		"mountpoint": mountpoint, "source": source, "root_dev": rootDev,
	})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	cmd := exec.Command("python3", genPath, imagesDir, string(spec))
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate external-tmpfs corpus: %v\n%s", err, out)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

// mountContentCaptureFailedStatusHasReason reports whether the typed gRPC status carries the
// attributed MOUNT_CONTENT_CAPTURE_FAILED errdetails.ErrorInfo reason.
func mountContentCaptureFailedStatusHasReason(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == MountContentCaptureFailedReason {
			return true
		}
	}
	return false
}

// TestCaptureContentAbsentMounts_FailsClosedWhenSourceUnreachableAndWorkloadState asserts the
// fail-closed capture gate (round-3 gating condition): an external, content-absent mount whose
// content the agent cannot reach (no config.json, and the mountpoints `source` is the ctr path's
// non-path "shm" string, so it is not even a reachability candidate) AND whose OCI source class is
// not affirmatively RECONSTRUCTABLE fails CLOSED with a wrapped ErrMountContentCaptureFailed — never
// a silent skip. This fixture carries ZERO demand (no files.img at all).
func TestCaptureContentAbsentMounts_FailsClosedWhenSourceUnreachableAndWorkloadState(t *testing.T) {
	imagesDir := t.TempDir()
	writeDevShmMountpointsImg(t, imagesDir, "/dev/shm", 532, true)
	// No config.json in imagesDir, and the mountpoints source is the non-path "shm" string =>
	// mountHostSourceDir returns ok=false and mountSourceReconstructability returns WORKLOAD_STATE.

	_, err := captureContentAbsentMounts(context.Background(), imagesDir)
	if err == nil {
		t.Fatalf("ADR-0426 fail-closed capture gate: expected a fail-closed error for an unreachable WORKLOAD_STATE mount, got nil")
	}
	if !errors.Is(err, ErrMountContentCaptureFailed) {
		t.Fatalf("expected errors.Is(err, ErrMountContentCaptureFailed); got %v", err)
	}
	var detail *MountContentCaptureFailedDetail
	if !errors.As(err, &detail) || detail.Mountpoint != "/dev/shm" {
		t.Fatalf("expected a MountContentCaptureFailedDetail naming /dev/shm; got %v", err)
	}
	// The typed gRPC status must carry the attributed reason.
	st := newMountContentCaptureFailedStatus(err)
	if !mountContentCaptureFailedStatusHasReason(st) {
		t.Fatalf("typed status is missing the MOUNT_CONTENT_CAPTURE_FAILED reason: %v", st)
	}
}

// TestCaptureContentAbsentMounts_UnreachableProjectedSourceDoesNotFailClosed is the round-3 fixture
// that must NOT fail closed even though the source is unreachable: the raw-path serviceaccount-token
// shape, where config.json is absent and the mountpoints `source` field IS the full host path under
// kubernetes.io~projected (F8c fact 2 / F8d). This is the "skip, count destination_reconstructable"
// leg, not a fail-closed leg.
func TestCaptureContentAbsentMounts_UnreachableProjectedSourceDoesNotFailClosed(t *testing.T) {
	imagesDir := t.TempDir()
	writeExternalTmpfsMountpointsImg(t, imagesDir,
		"/run/secrets/kubernetes.io/serviceaccount",
		"/var/lib/kubelet/pods/uid/volumes/kubernetes.io~projected/kube-api-access-bwzml", 393)

	out, err := captureContentAbsentMounts(context.Background(), imagesDir)
	if err != nil {
		t.Fatalf("a source unreachable but affirmatively RECONSTRUCTABLE must skip, not fail closed: %v", err)
	}
	if len(out.DestinationReconstructable) != 1 || out.DestinationReconstructable[0] != "/run/secrets/kubernetes.io/serviceaccount" {
		t.Fatalf("expected the serviceaccount mount counted destination_reconstructable; got %+v", out)
	}
	if _, statErr := os.Stat(filepath.Join(imagesDir, tmpfsContentImageName(393))); statErr == nil {
		t.Fatalf("no content image must be written for a RECONSTRUCTABLE mount")
	}
}

// TestCaptureContentAbsentMounts_CapturesReachableRawPathSource asserts the round-4 fix directly:
// no config.json, and the mountpoints source IS an absolute /run/ path (the raw-path sandbox shm
// shape, F8d) — this must be CAPTURED, not fail closed.
//
// Uses withHostRunRootForTest (the ADR-0426 injectable root-path seam) rather than writing into the
// real machine's /host-run: the prior version of this test called os.MkdirAll("/host-run/...")
// directly against the host filesystem and t.Skipf()'d when that failed, which it does on any
// non-root machine or CI runner without a live daemonset /run mount — so this, the one test meant to
// exercise a successful raw-path capture, silently never ran in most environments. With the seam in
// place this test now EXECUTES and asserts unconditionally, everywhere.
func TestCaptureContentAbsentMounts_CapturesReachableRawPathSource(t *testing.T) {
	imagesDir := t.TempDir()
	hostRunDir := t.TempDir()
	withHostRunRootForTest(t, hostRunDir)
	writeExternalTmpfsMountpointsImg(t, imagesDir, "/dev/shm",
		"/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/38b9ff67/shm", 399)
	shmSrc := filepath.Join(hostRunDir, "k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/38b9ff67/shm")
	if err := os.MkdirAll(shmSrc, 0o755); err != nil {
		t.Fatalf("create fixture source dir under the seam's temp host-run root: %v", err)
	}

	out, err := captureContentAbsentMounts(context.Background(), imagesDir)
	if err != nil {
		t.Fatalf("a reachable raw-path mountpoints source must capture, not fail closed: %v", err)
	}
	if len(out.Captured) != 1 || out.Captured[0].SourceOrigin != "mountpoints" {
		t.Fatalf("expected one captured mount with sourceOrigin=mountpoints; got %+v", out)
	}
}

// TestCaptureContentAbsentMounts_NilWhenNoDevShmMount asserts the legitimate no-op: the image records
// no /dev/shm mount (the pod owns none) => nil, not a fail-closed error.
func TestCaptureContentAbsentMounts_NilWhenNoDevShmMount(t *testing.T) {
	imagesDir := t.TempDir()
	writeDevShmMountpointsImg(t, imagesDir, "", 0, false)
	if _, err := captureContentAbsentMounts(context.Background(), imagesDir); err != nil {
		t.Fatalf("expected nil when no /dev/shm mount is recorded (nothing owned to capture); got %v", err)
	}
}

// TestCaptureContentAbsentMounts_NilWhenAlreadyInternal asserts the legitimate no-op: /dev/shm
// already CRIU-internal (ext_key empty — the raw-CRIU path already captured it, per today's CRIU
// behavior for a genuinely internal tmpfs) => nil.
func TestCaptureContentAbsentMounts_NilWhenAlreadyInternal(t *testing.T) {
	imagesDir := t.TempDir()
	writeDevShmMountpointsImg(t, imagesDir, "", 532, true) // /dev/shm present but no ext_key => internal
	if _, err := captureContentAbsentMounts(context.Background(), imagesDir); err != nil {
		t.Fatalf("expected nil when /dev/shm is already CRIU-internal; got %v", err)
	}
}
