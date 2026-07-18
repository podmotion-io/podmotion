/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

// restore_pid_verify_test.go — unit coverage for verifyRestoredPIDAlive and
// parsePidfileContent, the ADR-0228 Invariant-1 liveness gate that runs on the PID resolved
// authoritatively from CRIU's --pidfile (identity is guaranteed by the source-of-truth, so
// this gate is liveness-only and never consults the spoofable comm field).

import (
	"errors"
	"os"
	"testing"
	"time"
)

// withLocalProcAlive points verifyRestoredPIDAlive's procAliveFn seam at a direct
// same-process /proc read (localProcAlive) for the duration of the test, restoring
// the production default (brokerProcAlive) on cleanup. Unit tests exercise PIDs in
// the TEST BINARY's own process tree (self, or a forked-and-reaped child) — no
// broker socket is running here, and no cross-AppArmor-profile mediation applies,
// so the direct read is both sufficient and correct for these cases (see
// procAliveFn's doc comment in server.go for why production must NOT do this for a
// real CRIU-restored workload root).
func withLocalProcAlive(t *testing.T) {
	t.Helper()
	orig := procAliveFn
	procAliveFn = localProcAlive
	t.Cleanup(func() { procAliveFn = orig })
}

func TestVerifyRestoredPIDAlive_SelfIsAlive(t *testing.T) {
	withLocalProcAlive(t)
	// The test process itself is unambiguously alive across the settle window.
	if err := verifyRestoredPIDAlive(os.Getpid(), 20*time.Millisecond); err != nil {
		t.Fatalf("expected own PID to pass liveness, got: %v", err)
	}
}

func TestVerifyRestoredPIDAlive_NonPositiveRejected(t *testing.T) {
	withLocalProcAlive(t)
	for _, pid := range []int{0, -1} {
		if err := verifyRestoredPIDAlive(pid, 0); !errors.Is(err, ErrRestoredPIDDead) {
			t.Errorf("pid %d: expected ErrRestoredPIDDead, got: %v", pid, err)
		}
	}
}

func TestVerifyRestoredPIDAlive_DeadPIDRejected(t *testing.T) {
	withLocalProcAlive(t)
	// PID 2^30 is effectively guaranteed not to exist (well above /proc/sys/kernel/pid_max).
	deadPID := 1 << 30
	if err := verifyRestoredPIDAlive(deadPID, 0); !errors.Is(err, ErrRestoredPIDDead) {
		t.Fatalf("expected a non-existent PID to fail liveness with ErrRestoredPIDDead, got: %v", err)
	}
}

func TestParsePidfileContent(t *testing.T) {
	cases := []struct {
		in     string
		wantN  int
		wantOK bool
	}{
		{"54321\n", 54321, true},
		{"  777  ", 777, true},
		{"", 0, false},
		{"not-a-pid\n", 0, false},
		{"0\n", 0, false},
		{"-5\n", 0, false},
	}
	for _, c := range cases {
		gotN, gotOK := parsePidfileContent([]byte(c.in))
		if gotN != c.wantN || gotOK != c.wantOK {
			t.Errorf("parsePidfileContent(%q) = (%d,%v), want (%d,%v)", c.in, gotN, gotOK, c.wantN, c.wantOK)
		}
	}
}
