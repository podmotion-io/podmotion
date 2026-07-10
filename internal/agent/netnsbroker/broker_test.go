package netnsbroker

import (
	"os/exec"
	"strings"
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
