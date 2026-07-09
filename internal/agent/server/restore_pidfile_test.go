/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

// restore_pidfile_test.go — unit coverage for readRestoredPIDFromPidfile(WithReader), the
// net-new PID-resolution mechanism that replaces the cgroup-population-polling/debounce logic covered by
// restore_pid_debounce_test.go on the primary restore path. The host-mount-namespace read is
// injected via readFn (readRestoredPIDFromPidfileWithReader) so these tests never need a real
// broker/nsenter round-trip.

import (
	"errors"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestReadRestoredPIDFromPidfile_ValidPID scripts the pidfile appearing on the second read
// attempt with a well-formed integer PID, and asserts it is parsed and returned.
func TestReadRestoredPIDFromPidfile_ValidPID(t *testing.T) {
	calls := 0
	readFn := func(path string) ([]byte, error) {
		calls++
		if calls < 2 {
			return nil, errors.New("no such file or directory")
		}
		return []byte("54321\n"), nil
	}

	pid, err := readRestoredPIDFromPidfileWithReader("/fake/restored.pid", 5*time.Second, readFn, nil)
	if err != nil {
		t.Fatalf("readRestoredPIDFromPidfileWithReader returned unexpected error: %v", err)
	}
	if pid != 54321 {
		t.Fatalf("got pid=%d, want 54321", pid)
	}
	if calls < 2 {
		t.Fatalf("expected at least 2 read attempts (file absent then present), got %d", calls)
	}
}

// TestReadRestoredPIDFromPidfile_GarbageContentTimesOut scripts the pidfile always existing but
// containing unparseable content, and asserts the bounded poll eventually times out with
// ErrRestoredPIDNotFound rather than returning a garbage value.
func TestReadRestoredPIDFromPidfile_GarbageContentTimesOut(t *testing.T) {
	readFn := func(path string) ([]byte, error) {
		return []byte("not-a-pid\n"), nil
	}

	pid, err := readRestoredPIDFromPidfileWithReader("/fake/restored.pid", 300*time.Millisecond, readFn, nil)
	if err == nil {
		t.Fatalf("expected an error for garbage pidfile content, got pid=%d", pid)
	}
	if !errors.Is(err, ErrRestoredPIDNotFound) {
		t.Fatalf("expected error to wrap ErrRestoredPIDNotFound, got: %v", err)
	}
}

// TestReadRestoredPIDFromPidfile_NeverAppearsTimesOut scripts the pidfile never appearing
// (every read fails) and asserts the bounded poll times out with ErrRestoredPIDNotFound within
// roughly the configured budget, rather than blocking indefinitely.
func TestReadRestoredPIDFromPidfile_NeverAppearsTimesOut(t *testing.T) {
	readFn := func(path string) ([]byte, error) {
		return nil, errors.New("no such file or directory")
	}

	start := time.Now()
	pid, err := readRestoredPIDFromPidfileWithReader("/fake/restored.pid", 300*time.Millisecond, readFn, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected timeout error, got pid=%d", pid)
	}
	if !errors.Is(err, ErrRestoredPIDNotFound) {
		t.Fatalf("expected error to wrap ErrRestoredPIDNotFound, got: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("readRestoredPIDFromPidfileWithReader took %v, expected to honor the short bounded budget", elapsed)
	}
}

// TestReadRestoredPIDFromPidfile_NonPositivePIDRejected scripts the pidfile containing a
// syntactically-integer but semantically-invalid PID (zero/negative), and asserts it is rejected
// rather than returned.
func TestReadRestoredPIDFromPidfile_NonPositivePIDRejected(t *testing.T) {
	readFn := func(path string) ([]byte, error) {
		return []byte("0\n"), nil
	}

	pid, err := readRestoredPIDFromPidfileWithReader("/fake/restored.pid", 300*time.Millisecond, readFn, nil)
	if err == nil {
		t.Fatalf("expected an error for non-positive pidfile content, got pid=%d", pid)
	}
	if !errors.Is(err, ErrRestoredPIDNotFound) {
		t.Fatalf("expected error to wrap ErrRestoredPIDNotFound, got: %v", err)
	}
}

// TestReadRestoredPIDFromPidfile_ExitsFastOnProcessDeath is the brittle-chain-timeout
// regression test: the pidfile
// never appears AND the CRIU/wrapper process (per pollFn) has already exited. The loop must fail
// immediately with ErrRestoredPIDNotFound rather than waiting out the full (here, long) backstop
// budget — this is the "failed migrations detected as soon as CRIU actually exits" half of the
// fix.
func TestReadRestoredPIDFromPidfile_ExitsFastOnProcessDeath(t *testing.T) {
	readFn := func(path string) ([]byte, error) {
		return nil, errors.New("no such file or directory")
	}
	pollFn := func() (bool, error) {
		return true, nil // process already exited
	}

	start := time.Now()
	pid, err := readRestoredPIDFromPidfileWithReader("/fake/restored.pid", 300*time.Second, readFn, pollFn)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected an error when the process has exited without writing the pidfile, got pid=%d", pid)
	}
	if !errors.Is(err, ErrRestoredPIDNotFound) {
		t.Fatalf("expected error to wrap ErrRestoredPIDNotFound, got: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("readRestoredPIDFromPidfileWithReader took %v to detect process death — expected fast failure, not waiting out the 300s backstop", elapsed)
	}
}

// TestReadRestoredPIDFromPidfile_PidfileWinsEvenIfProcessAlreadyExited scripts the pidfile
// appearing with a valid PID on the same tick pollFn reports the process has exited — this can
// happen because CRIU writes the pidfile shortly before it fully exits. Success (pidfile present)
// must win; the process-exit check must never override an already-successful read.
func TestReadRestoredPIDFromPidfile_PidfileWinsEvenIfProcessAlreadyExited(t *testing.T) {
	readFn := func(path string) ([]byte, error) {
		return []byte("777\n"), nil
	}
	pollFn := func() (bool, error) {
		t.Fatalf("pollFn should not be consulted when the pidfile read already succeeded")
		return true, nil
	}

	pid, err := readRestoredPIDFromPidfileWithReader("/fake/restored.pid", 300*time.Millisecond, readFn, pollFn)
	if err != nil {
		t.Fatalf("readRestoredPIDFromPidfileWithReader returned unexpected error: %v", err)
	}
	if pid != 777 {
		t.Fatalf("got pid=%d, want 777", pid)
	}
}

// --- C1 stale-pidfile unlink regression coverage ---
//
// removeStalePidfile is the injectable decomposition of the C1 fix: os.Remove(stalePidfilePath)
// runs immediately before every CRIU restore launch inside joinNsRestore, and must fail CLOSED on
// any removal error other than "not present". The removeFn is injected (os.Remove in production)
// exactly like readFn/pollFn above, so the fail-open-on-not-exist vs fail-closed-on-any-other-error
// contract is proven here without a live CRIU/broker round-trip. This is the BLOCKING Security
// Reviewer finding's regression test — before this, the fix had zero coverage.

func TestRemoveStalePidfile_RemovesExistingStaleFile(t *testing.T) {
	// (a) A pre-existing stale restored.pid IS removed before CRIU launch: removeFn is invoked
	// with the exact pidfile path and, on success, the helper returns nil (launch proceeds).
	const path = "/fake/data/restored.pid"
	called := false
	var gotPath string
	removeFn := func(p string) error {
		called = true
		gotPath = p
		return nil // simulate a real, present file being unlinked successfully
	}

	if err := removeStalePidfile(path, removeFn); err != nil {
		t.Fatalf("removeStalePidfile returned unexpected error on successful unlink: %v", err)
	}
	if !called {
		t.Fatal("removeFn was never called — the stale pidfile unlink did not run before CRIU launch")
	}
	if gotPath != path {
		t.Fatalf("removeFn called with path=%q, want %q", gotPath, path)
	}
}

func TestRemoveStalePidfile_FailOpenVsFailClosed(t *testing.T) {
	otherErr := errors.New("read-only filesystem")
	cases := []struct {
		name      string
		removeErr error
		wantErr   bool // true = hard fail-closed; false = fail-open (proceed to launch)
	}{
		{
			name:      "not-exist is fail-open (no stale file to remove)",
			removeErr: os.ErrNotExist,
			wantErr:   false,
		},
		{
			name:      "success is fail-open (stale file removed)",
			removeErr: nil,
			wantErr:   false,
		},
		{
			name:      "permission-denied is fail-closed (unremovable stale file must not be polled past)",
			removeErr: os.ErrPermission,
			wantErr:   true,
		},
		{
			name:      "any other error is fail-closed",
			removeErr: otherErr,
			wantErr:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			removeFn := func(string) error { return tc.removeErr }
			err := removeStalePidfile("/fake/data/restored.pid", removeFn)
			if tc.wantErr && err == nil {
				t.Fatalf("removeStalePidfile returned nil, want a hard fail-closed error (removeErr=%v)", tc.removeErr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("removeStalePidfile returned error %v, want nil (fail-open on removeErr=%v)", err, tc.removeErr)
			}
			// On the fail-closed path the original removeFn error must be wrapped (not swallowed),
			// so operators can see WHY the launch was blocked.
			if tc.wantErr && !errors.Is(err, tc.removeErr) {
				t.Fatalf("fail-closed error %v does not wrap the underlying removeFn error %v", err, tc.removeErr)
			}
		})
	}
}

// --- ADR-0228 restore-idempotency: priorRestoredPIDIfAlive ---
//
// These cover the source-of-truth guard the gRPC Restore fallback uses to avoid a
// double-restore hang: if a prior restore for this migration already produced a LIVE
// workload PID (recorded at <dataDir>/restored.pid by CRIU --pidfile), the RPC confirms
// idempotently instead of re-running CRIU (which would spawn a second do_wait-blocked parent).

// TestPriorRestoredPIDIfAlive_LivePID: a pidfile holding a live PID (this test process)
// returns (pid, true) — the confirm-and-advance path.
func TestPriorRestoredPIDIfAlive_LivePID(t *testing.T) {
	dataDir := t.TempDir()
	live := os.Getpid()
	if err := os.WriteFile(dataDir+"/"+restoredPidfileName, []byte(strconv.Itoa(live)), 0o600); err != nil {
		t.Fatalf("write pidfile: %v", err)
	}
	pid, ok := priorRestoredPIDIfAlive(dataDir)
	if !ok {
		t.Fatalf("priorRestoredPIDIfAlive returned ok=false for a live PID %d", live)
	}
	if pid != live {
		t.Fatalf("priorRestoredPIDIfAlive returned pid=%d, want %d", pid, live)
	}
}

// TestPriorRestoredPIDIfAlive_AbsentFile: no pidfile → (0,false), caller proceeds to a real restore.
func TestPriorRestoredPIDIfAlive_AbsentFile(t *testing.T) {
	dataDir := t.TempDir() // empty — no restored.pid
	if pid, ok := priorRestoredPIDIfAlive(dataDir); ok || pid != 0 {
		t.Fatalf("priorRestoredPIDIfAlive on absent pidfile returned (%d,%v), want (0,false)", pid, ok)
	}
}

// TestPriorRestoredPIDIfAlive_DeadPID: a pidfile holding a PID that is not alive → (0,false),
// caller proceeds to a real restore rather than falsely confirming.
func TestPriorRestoredPIDIfAlive_DeadPID(t *testing.T) {
	dataDir := t.TempDir()
	// PID 2^31-1 is effectively guaranteed not to exist on Linux (pid_max is far lower).
	if err := os.WriteFile(dataDir+"/"+restoredPidfileName, []byte("2147483646"), 0o600); err != nil {
		t.Fatalf("write pidfile: %v", err)
	}
	if pid, ok := priorRestoredPIDIfAlive(dataDir); ok || pid != 0 {
		t.Fatalf("priorRestoredPIDIfAlive on dead PID returned (%d,%v), want (0,false)", pid, ok)
	}
}

// TestPriorRestoredPIDIfAlive_GarbageContent: unparseable pidfile → (0,false).
func TestPriorRestoredPIDIfAlive_GarbageContent(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(dataDir+"/"+restoredPidfileName, []byte("not-a-pid"), 0o600); err != nil {
		t.Fatalf("write pidfile: %v", err)
	}
	if pid, ok := priorRestoredPIDIfAlive(dataDir); ok || pid != 0 {
		t.Fatalf("priorRestoredPIDIfAlive on garbage returned (%d,%v), want (0,false)", pid, ok)
	}
}
