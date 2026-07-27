/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// adr0415_capture_gate_test.go — ADR-0415 fail-closed capture gate: captureCtrDevShmContent must FAIL CLOSED when
// an owned /dev/shm's content should be captured but cannot, and return the legitimate "nothing
// owned to capture" nil only for the real no-op states (no /dev/shm mount; already CRIU-internal).

import (
	"context"
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
// and root_dev via the vendored pycriu, matching the ctr fast path's recorded shape.
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

// TestCaptureCtrDevShmContent_FailsClosedWhenSourceUnreachable asserts fail-closed capture gate: an external
// /dev/shm the pod owns, whose content the agent cannot reach (no config.json => no sandbox shm
// source), fails CLOSED with a wrapped ErrMountContentCaptureFailed — never a silent skip.
func TestCaptureCtrDevShmContent_FailsClosedWhenSourceUnreachable(t *testing.T) {
	imagesDir := t.TempDir()
	writeDevShmMountpointsImg(t, imagesDir, "/dev/shm", 532, true)
	// No config.json in imagesDir => devShmHostSourceDir returns ok=false => unreachable owned content.

	err := captureCtrDevShmContent(context.Background(), imagesDir)
	if err == nil {
		t.Fatalf("ADR-0415 fail-closed capture gate: expected a fail-closed error for an unreachable owned /dev/shm, got nil")
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

// TestCaptureCtrDevShmContent_NilWhenNoDevShmMount asserts the legitimate no-op: the image records
// no /dev/shm mount (the pod owns none) => nil, not a fail-closed error.
func TestCaptureCtrDevShmContent_NilWhenNoDevShmMount(t *testing.T) {
	imagesDir := t.TempDir()
	writeDevShmMountpointsImg(t, imagesDir, "", 0, false)
	if err := captureCtrDevShmContent(context.Background(), imagesDir); err != nil {
		t.Fatalf("expected nil when no /dev/shm mount is recorded (nothing owned to capture); got %v", err)
	}
}

// TestCaptureCtrDevShmContent_NilWhenAlreadyInternal asserts the legitimate no-op: /dev/shm already
// CRIU-internal (ext_key empty — the raw-CRIU path already captured it) => nil.
func TestCaptureCtrDevShmContent_NilWhenAlreadyInternal(t *testing.T) {
	imagesDir := t.TempDir()
	writeDevShmMountpointsImg(t, imagesDir, "", 532, true) // /dev/shm present but no ext_key => internal
	if err := captureCtrDevShmContent(context.Background(), imagesDir); err != nil {
		t.Fatalf("expected nil when /dev/shm is already CRIU-internal; got %v", err)
	}
}
