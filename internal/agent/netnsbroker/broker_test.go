package netnsbroker

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// TestHandleResolveVeth locks in the SC-1 properties of the resolve_veth broker op:
// it rejects srcPID <= 0, rejects a dead/nonexistent PID (liveness), and — because the
// broker builds the fixed argv itself — takes NO client-supplied argv. Handle is the
// pure-logic core exported for socket-free testing.
func TestHandleResolveVeth(t *testing.T) {
	t.Run("rejects srcPID <= 0", func(t *testing.T) {
		for _, pid := range []int{0, -1, -1000} {
			resp := Handle(Request{Op: "resolve_veth", SrcPID: pid})
			if resp.Error == "" {
				t.Fatalf("srcPID %d: expected broker Error, got success (%+v)", pid, resp)
			}
			if !strings.Contains(resp.Error, "resolve_veth") {
				t.Fatalf("srcPID %d: error %q should mention resolve_veth", pid, resp.Error)
			}
			if resp.ExitCode != nil {
				t.Fatalf("srcPID %d: rejected request must not carry an ExitCode (no command spawned)", pid)
			}
		}
	})

	t.Run("rejects a dead PID", func(t *testing.T) {
		deadPID := findDeadPID(t)
		resp := Handle(Request{Op: "resolve_veth", SrcPID: deadPID})
		if resp.Error == "" {
			t.Fatalf("dead PID %d: expected liveness rejection, got success (%+v)", deadPID, resp)
		}
		if resp.ExitCode != nil {
			t.Fatalf("dead PID %d: liveness rejection must not spawn a command (ExitCode should be nil)", deadPID)
		}
	})

	t.Run("takes no client argv (SC-1)", func(t *testing.T) {
		// Even with an attacker-supplied Argv, the resolve_veth path must ignore it entirely:
		// the broker builds its own fixed `nsenter --net=... -- ip -o link show eth0`. With a
		// non-positive srcPID the request is rejected BEFORE any spawn, so a poisoned Argv can
		// never reach exec — proving the op does not consult client argv.
		resp := Handle(Request{
			Op:     "resolve_veth",
			SrcPID: -1,
			Argv:   []string{"/bin/sh", "-c", "touch /tmp/pwned"},
		})
		if resp.Error == "" {
			t.Fatalf("expected rejection regardless of Argv, got success (%+v)", resp)
		}
		if resp.ExitCode != nil {
			t.Fatalf("poisoned Argv must not be executed (ExitCode should be nil), got %+v", resp)
		}
	})

	t.Run("unknown op error names resolve_veth", func(t *testing.T) {
		resp := Handle(Request{Op: "bogus"})
		if resp.Error == "" || !strings.Contains(resp.Error, "resolve_veth") {
			t.Fatalf("unknown-op error should list resolve_veth, got %q", resp.Error)
		}
	})
}

// TestHandleSignalPID locks in the SC-1 properties of the signal_pid broker op
// (ADR-0312): it accepts ONLY SIGCONT/SIGSTOP, refuses without a PID-reuse
// starttime identity, refuses on a starttime mismatch, and rejects a dead PID —
// each BEFORE delivering any signal. signal_pid must NOT consult asyncExecReg (it
// targets a PID the broker never spawned).
func TestHandleSignalPID(t *testing.T) {
	self := os.Getpid()
	liveStart, err := procStartTime(self)
	if err != nil {
		t.Fatalf("procStartTime(self=%d): %v", self, err)
	}

	t.Run("rejects non-cont/stop signals", func(t *testing.T) {
		for _, sig := range []int{int(syscall.SIGKILL), int(syscall.SIGTERM), int(syscall.SIGINT), 0} {
			resp := Handle(Request{Op: "signal_pid", SignalPID: self, Signal: sig, ExpectedStartTime: liveStart})
			if resp.Error == "" {
				t.Fatalf("signal %d: expected allowlist rejection, got success", sig)
			}
			if !strings.Contains(resp.Error, "signal_pid") {
				t.Fatalf("signal %d: error %q should mention signal_pid", sig, resp.Error)
			}
		}
	})

	t.Run("rejects missing starttime identity", func(t *testing.T) {
		resp := Handle(Request{Op: "signal_pid", SignalPID: self, Signal: int(syscall.SIGCONT), ExpectedStartTime: 0})
		if resp.Error == "" || !strings.Contains(resp.Error, "identity") {
			t.Fatalf("expected refusal without starttime identity, got %q", resp.Error)
		}
	})

	t.Run("rejects starttime mismatch (PID reuse guard)", func(t *testing.T) {
		resp := Handle(Request{Op: "signal_pid", SignalPID: self, Signal: int(syscall.SIGCONT), ExpectedStartTime: liveStart + 1})
		if resp.Error == "" || !strings.Contains(resp.Error, "starttime mismatch") {
			t.Fatalf("expected PID-reuse rejection on starttime mismatch, got %q", resp.Error)
		}
	})

	t.Run("rejects non-positive PID", func(t *testing.T) {
		for _, pid := range []int{0, -1} {
			resp := Handle(Request{Op: "signal_pid", SignalPID: pid, Signal: int(syscall.SIGCONT), ExpectedStartTime: 1})
			if resp.Error == "" {
				t.Fatalf("pid %d: expected rejection", pid)
			}
		}
	})

	t.Run("rejects a dead PID", func(t *testing.T) {
		deadPID := findDeadPID(t)
		resp := Handle(Request{Op: "signal_pid", SignalPID: deadPID, Signal: int(syscall.SIGCONT), ExpectedStartTime: 12345})
		if resp.Error == "" {
			t.Fatalf("dead PID %d: expected rejection, got success", deadPID)
		}
	})

	t.Run("delivers SIGCONT to a live matching PID", func(t *testing.T) {
		// A running (not stopped) process is harmlessly a no-op under SIGCONT.
		resp := Handle(Request{Op: "signal_pid", SignalPID: self, Signal: int(syscall.SIGCONT), ExpectedStartTime: liveStart})
		if resp.Error != "" {
			t.Fatalf("expected SIGCONT to self to succeed, got error %q", resp.Error)
		}
	})

	t.Run("unknown op error names signal_pid", func(t *testing.T) {
		resp := Handle(Request{Op: "bogus"})
		if resp.Error == "" || !strings.Contains(resp.Error, "signal_pid") {
			t.Fatalf("unknown-op error should list signal_pid, got %q", resp.Error)
		}
	})
}

// findDeadPID returns a PID that is not currently live. We start a child, capture its
// PID, wait for it to exit, and return that PID — reliably reaped and gone.
func findDeadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start helper process to obtain a dead PID: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()
	return pid
}
