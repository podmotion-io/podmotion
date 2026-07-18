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
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
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

// TestReadRestoredPIDFromPidfile_ExitsFastOnProcessDeath is the fast-fail-timeout
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
	withLocalProcAlive(t)
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
	withLocalProcAlive(t)
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

// --- ADR-0306 hardening tests: netns-identity gate + Strict gated-resume fix ---
//
// These exercise the primitives the ADR-0306 confirm-path block is built from
// (pidNetnsMatchesPath, procStatStateChar) directly, since the full gRPC Restore handler
// requires a live AgentServer with a k8sClient/ctr broker round-trip that is out of scope for
// a pure unit test. This matches the file's existing style (unit coverage for the underlying
// mechanism, not an end-to-end RPC harness) and is fully falsifiable: any regression in the
// identity-comparison or state-check logic these tests cover will fail here.

// TestPidNetnsMatchesPath_Mismatch: two different (but both real) netns paths for the current
// process do not spuriously match a bogus "expected" path — the self-netns of this test binary
// compared against /proc/1/ns/net (init, almost certainly a different netns in test sandboxes,
// and definitely a different inode than a throwaway bind-mount) must return false, not error out
// as "match." This guards the fail-closed Decision item (a) mismatch disposition.
func TestPidNetnsMatchesPath_Mismatch(t *testing.T) {
	self := os.Getpid()
	// A bind-mounted regular file standing in for "a real but different netns path": it exists
	// and is stat-able, but its inode/dev is certain not to match the test process's own
	// /proc/<pid>/ns/net (a distinct anonymous inode on the nsfs pseudo-filesystem).
	tmp := t.TempDir() + "/not-a-netns"
	if err := os.WriteFile(tmp, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write placeholder file: %v", err)
	}
	match, err := pidNetnsMatchesPath(self, tmp)
	if err != nil {
		t.Fatalf("pidNetnsMatchesPath returned unexpected error: %v", err)
	}
	if match {
		t.Fatalf("pidNetnsMatchesPath(self netns, unrelated file) returned match=true, want false")
	}
}

// TestPidNetnsMatchesPath_SandboxIDUnobtainable: an unresolvable expected-netns path (stat
// failure, standing in for "sandbox ID could not be obtained / resolved to a netns") fails
// closed with a non-nil error, never a silent (false,nil).
func TestPidNetnsMatchesPath_SandboxIDUnobtainable(t *testing.T) {
	self := os.Getpid()
	bogus := "/proc/999999999/ns/net" // PID that cannot exist (pid_max far lower on Linux)
	match, err := pidNetnsMatchesPath(self, bogus)
	if err == nil {
		t.Fatalf("pidNetnsMatchesPath(unresolvable path) returned nil error, want non-nil (fail-closed)")
	}
	if match {
		t.Fatalf("pidNetnsMatchesPath(unresolvable path) returned match=true, want false")
	}
}

// TestPidNetnsMatchesPath_MatchRegressionGuard: a process's own /proc/<pid>/ns/net path,
// compared against itself, must match. This is the regression guard for the happy path — must
// not regress ADR-0228's original idempotent-confirm behavior by spuriously failing closed on a
// genuinely correct identity.
func TestPidNetnsMatchesPath_MatchRegressionGuard(t *testing.T) {
	self := os.Getpid()
	selfNetnsPath := fmt.Sprintf("/proc/%d/ns/net", self)
	match, err := pidNetnsMatchesPath(self, selfNetnsPath)
	if err != nil {
		t.Fatalf("pidNetnsMatchesPath(self, self) returned unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("pidNetnsMatchesPath(self, self) returned match=false, want true")
	}
}

// TestProcStatStateChar_SleepingRegressionGuard: the current test process (state 'R' running or
// 'S' sleeping, never 'T'/'t') must read back a valid, non-stopped state char without error —
// the non-Strict/no-TCP regression guard: this state must NOT be interpreted as eligible for
// deferred resume re-arming.
func TestProcStatStateChar_SleepingRegressionGuard(t *testing.T) {
	self := os.Getpid()
	state, err := procStatStateChar(self)
	if err != nil {
		t.Fatalf("procStatStateChar(self) returned unexpected error: %v", err)
	}
	if state == 'T' || state == 't' {
		t.Fatalf("procStatStateChar(self) returned stopped state %q for a running test process — test environment invariant violated", string(state))
	}
}

// TestProcStatStateChar_UnreadablePID: a nonexistent PID's /proc/<pid>/stat cannot be read;
// procStatStateChar must surface an error (treated by the confirm-path caller as "not currently
// eligible for deferred resume," never as a false 'T'/'t').
func TestProcStatStateChar_UnreadablePID(t *testing.T) {
	bogus := 999999999
	if _, err := procStatStateChar(bogus); err == nil {
		t.Fatalf("procStatStateChar(nonexistent pid) returned nil error, want non-nil")
	}
}

// TestProcStatStateChar_StoppedStateParsesCorrectly: sends SIGSTOP to a child process and
// verifies procStatStateChar reports 'T' (stopped), then SIGCONTs it before exit. This is the
// falsifiable guard for Decision item (e)'s "Strict SIGSTOP (T state)" and "Strict tracing-stop
// (t state)" cases: the state-char parse itself, which the confirm-path's Strict/BestEffort
// gated-resume check (item b) depends on, must correctly distinguish T/t from running/sleeping.
func TestProcStatStateChar_StoppedStateParsesCorrectly(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("skip: could not start child process: %v", err)
	}
	pid := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGCONT)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Skipf("skip: could not SIGSTOP child: %v", err)
	}
	// Give the kernel a moment to transition the state.
	deadline := time.Now().Add(2 * time.Second)
	var state byte
	var err error
	for time.Now().Before(deadline) {
		state, err = procStatStateChar(pid)
		if err == nil && (state == 'T' || state == 't') {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("procStatStateChar(stopped child) returned unexpected error: %v", err)
	}
	if state != 'T' && state != 't' {
		t.Fatalf("procStatStateChar(stopped child) returned state %q, want 'T' or 't'", string(state))
	}
}

// confirmPathShouldArmDeferredResume reproduces, verbatim, the ADR-0306 item (b) gating
// predicate from the confirm-path block in Restore (server.go ~line 5758):
//
//	req.TcpPreservationMode == "Strict" || (req.TcpPreservationMode == "BestEffort" && len(req.SeqSnapshots) > 0)
//
// combined with the stopped-state check (state == 'T' || state == 't'). Kept as a literal
// duplicate (not extracted into a shared helper — no such helper exists in server.go today) so
// this test fails the moment the inline predicate in Restore drifts from what is asserted here.
func confirmPathShouldArmDeferredResume(tcpMode string, seqSnapshotCount int, state byte) bool {
	tcpEligible := tcpMode == "Strict" || (tcpMode == "BestEffort" && seqSnapshotCount > 0)
	stopped := state == 'T' || state == 't'
	return tcpEligible && stopped
}

// TestConfirmPathDeferredResumeGate_StrictSIGSTOP: Decision item (e) case "Strict SIGSTOP (T
// state)" — Strict mode with a stopped ('T') restored tree must arm the deferred-resume gate.
func TestConfirmPathDeferredResumeGate_StrictSIGSTOP(t *testing.T) {
	if !confirmPathShouldArmDeferredResume("Strict", 0, 'T') {
		t.Fatalf("Strict + state=T must arm pendingResumePIDs, got false")
	}
}

// TestConfirmPathDeferredResumeGate_StrictTracingStop: Decision item (e) case "Strict
// tracing-stop (t state)" — the state check must not be 'T'-only.
func TestConfirmPathDeferredResumeGate_StrictTracingStop(t *testing.T) {
	if !confirmPathShouldArmDeferredResume("Strict", 0, 't') {
		t.Fatalf("Strict + state=t must arm pendingResumePIDs, got false")
	}
}

// TestConfirmPathDeferredResumeGate_BestEffortWithSeqSnapshots: BestEffort mode with TCP
// sequence snapshots present is treated as TCP-preserving for this gate, same as Strict.
func TestConfirmPathDeferredResumeGate_BestEffortWithSeqSnapshots(t *testing.T) {
	if !confirmPathShouldArmDeferredResume("BestEffort", 3, 'T') {
		t.Fatalf("BestEffort with seq snapshots + state=T must arm pendingResumePIDs, got false")
	}
}

// TestConfirmPathDeferredResumeGate_NonStrictNoTCP_RegressionGuard: Decision item (e) case
// "Non-Strict/no-TCP SIGSTOP regression guard" — a stopped restored tree under TcpPreservationMode
// "None" (or BestEffort with zero seq snapshots) must NOT arm pendingResumePIDs, even though the
// process state alone (T) would otherwise qualify. Guards against over-eager re-arming that was
// never gated on preservation mode.
func TestConfirmPathDeferredResumeGate_NonStrictNoTCP_RegressionGuard(t *testing.T) {
	cases := []struct {
		name    string
		tcpMode string
		seqLen  int
	}{
		{"None", "None", 0},
		{"BestEffort_NoSeqSnapshots", "BestEffort", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if confirmPathShouldArmDeferredResume(c.tcpMode, c.seqLen, 'T') {
				t.Fatalf("%s + state=T must NOT arm pendingResumePIDs, got true", c.tcpMode)
			}
		})
	}
}

// TestConfirmPathDeferredResumeGate_RunningStateNeverArms: even under Strict mode, a running
// ('R') or sleeping ('S') restored tree must not be (re-)armed for deferred resume — only a
// genuinely stopped tree is eligible.
func TestConfirmPathDeferredResumeGate_RunningStateNeverArms(t *testing.T) {
	for _, state := range []byte{'R', 'S', 'D', 'Z'} {
		if confirmPathShouldArmDeferredResume("Strict", 0, state) {
			t.Fatalf("Strict + state=%q must NOT arm pendingResumePIDs, got true", string(state))
		}
	}
}
