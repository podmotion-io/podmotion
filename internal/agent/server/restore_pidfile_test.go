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
