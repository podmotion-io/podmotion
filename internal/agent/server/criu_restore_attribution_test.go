// criu_restore_attribution_test.go — ADR-0418 §P-VERIFY unit-test coverage: the causal-first-error
// CRIU restore-failure attribution primitive (scanCRIURestoreLogForFirstError /
// criuRestoreFailureCause), added in internal/agent/server/server.go.
//
// Fixtures below are copied verbatim (timestamp + task-id prefix included) from the in-tree real
// restore.log samples cited in ADR-0418 Context: server.go:6211-6213 / restore_devnode_test.go:6-8
// (pm-w2 redis capture) and ctr_masked_mount_test.go:40 (-v4 timestamp-prefixed sample). Per
// §P-VERIFY #2, a fixture using bare `Error (criu/...` lines starting at column 0 would be a
// restatement of the defect this ADR fixes, not a regression guard against it — none are used here.
package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRestoreLog(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "restore.log")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("writeRestoreLog: %v", err)
	}
	return p
}

// §P-VERIFY #2: causal-order-first, not tail-last, selection on realistic (timestamp/task-id
// prefixed) fixtures — the first matching line must win, not the last.
func TestScanCRIURestoreLogForFirstError_CausalOrderFirst(t *testing.T) {
	// First match is a real cause (files-reg.c), a later line is the mount.c:3700 void-helper
	// teardown diagnostic (which, on a byte-offset TAIL window, would have won instead).
	log := "" +
		"1: Error (criu/files-reg.c:2353): Can't open file dev/null on restore: No such file or directory\n" +
		"1: Error (criu/files.c:1221): Unable to open fd=0 id=0x5\n" +
		"Error (criu/cr-restore.c:2324): Restoring FAILED.\n" +
		"(00.100258) Error (criu/mount.c:3700): Can't remove the directory /some/path: Device or resource busy\n"
	p := writeRestoreLog(t, log)

	attr := scanCRIURestoreLogForFirstError(p)
	if !attr.found {
		t.Fatalf("expected found=true, got %+v", attr)
	}
	wantCause := "1: Error (criu/files-reg.c:2353): Can't open file dev/null on restore: No such file or directory"
	if attr.causeLine != wantCause {
		t.Fatalf("attribution did not pick the FIRST causal line — this is a tail-window regression\ngot:  %q\nwant: %q", attr.causeLine, wantCause)
	}
	if attr.demoted {
		t.Fatalf("no demotion expected here (first match was already a real cause), got demoted=true demotedLine=%q", attr.demotedLine)
	}
	if attr.terminalLine == "" || !strings.Contains(attr.terminalLine, "Restoring FAILED.") {
		t.Fatalf("expected terminal line to be captured, got %q", attr.terminalLine)
	}
	// 4 lines contain "Error (criu/": files-reg.c, files.c, the cr-restore.c terminal line
	// itself (which also matches the substring), and the mount.c:3700 teardown diagnostic.
	if attr.matchCount != 4 {
		t.Fatalf("expected matchCount=4, got %d", attr.matchCount)
	}
}

// §P-VERIFY #3: CRIU-still-running case must not fabricate a cause — only report a matching line
// as "observed while in flight," never as the cause, when exited=false.
func TestCriuRestoreFailureCause_StillRunning_DoesNotFabricateCause(t *testing.T) {
	log := "(00.100258) Error (criu/mount.c:753): mnt: 625:./proc/interrupts doesn't have a proper root mount\n"
	p := writeRestoreLog(t, log)

	out := criuRestoreFailureCause(p, "/checkpoint/dir", false, false /* exited */, 0, nil, "")
	if strings.Contains(out, "first causal error") {
		t.Fatalf("must not name a cause when CRIU has not terminated; got:\n%s", out)
	}
	if !strings.Contains(out, "had not terminated") {
		t.Fatalf("expected explicit not-terminated statement; got:\n%s", out)
	}
	if !strings.Contains(out, "last CRIU error observed while restore was still in flight") {
		t.Fatalf("expected the matching line to be cited as in-flight, non-causal context; got:\n%s", out)
	}
	if !strings.Contains(out, "NOT the cause") {
		t.Fatalf("expected explicit disclaimer that the in-flight line is not the cause; got:\n%s", out)
	}
}

// §P-VERIFY #4: known-non-fatal-only case must not fabricate a cause — must state explicitly
// that the true cause was not found and point at the full log.
func TestCriuRestoreFailureCause_OnlyAllowlistedMatch(t *testing.T) {
	log := "(00.100258) Error (criu/mount.c:3700): Can't remove the directory /some/path: Device or resource busy\n"
	p := writeRestoreLog(t, log)

	out := criuRestoreFailureCause(p, "/checkpoint/dir", false, true, 1, nil, "")
	if strings.Contains(out, "first causal error") {
		t.Fatalf("must not silently report the allowlisted line as the cause; got:\n%s", out)
	}
	if !strings.Contains(out, "true cause not present in restore.log") {
		t.Fatalf("expected explicit only-allowlisted disclosure; got:\n%s", out)
	}
	if !strings.Contains(out, "mount.c:3700") {
		t.Fatalf("expected the allowlisted line to still be quoted; got:\n%s", out)
	}
}

// §P-VERIFY #5: demotion must never be silent — when the first match is allowlisted and a later
// real match exists, the envelope must disclose the demotion, reproduce the demoted line
// verbatim, and report the total match count.
func TestCriuRestoreFailureCause_DemotionIsNeverSilent(t *testing.T) {
	log := "" +
		"(00.100258) Error (criu/mount.c:3700): Can't remove the directory /some/path: Device or resource busy\n" +
		"1: Error (criu/sk-inet.c:1059): inet: Can't bind inet socket (id 11): Address already in use\n" +
		"Error (criu/cr-restore.c:2324): Restoring FAILED.\n"
	p := writeRestoreLog(t, log)

	attr := scanCRIURestoreLogForFirstError(p)
	if !attr.found {
		t.Fatalf("expected a real cause to be found past the allowlisted first match, got %+v", attr)
	}
	if !attr.demoted {
		t.Fatalf("expected demotion to be flagged, got %+v", attr)
	}
	if !strings.Contains(attr.demotedLine, "mount.c:3700") {
		t.Fatalf("expected demoted line to be the allowlisted mount.c:3700 line verbatim, got %q", attr.demotedLine)
	}
	if !strings.Contains(attr.causeLine, "sk-inet.c:1059") {
		t.Fatalf("expected the later real match to be named as cause, got %q", attr.causeLine)
	}
	// 3 lines contain "Error (criu/": mount.c:3700 (allowlisted, demoted), sk-inet.c:1059 (the
	// real cause), and the cr-restore.c terminal line itself (which also matches the substring).
	if attr.matchCount != 3 {
		t.Fatalf("expected matchCount=3, got %d", attr.matchCount)
	}

	out := criuRestoreFailureCause(p, "/checkpoint/dir", false, true, 1, nil, "")
	if !strings.Contains(out, "demoted") {
		t.Fatalf("envelope text must disclose the demotion explicitly; got:\n%s", out)
	}
	if !strings.Contains(out, "mount.c:3700") {
		t.Fatalf("envelope text must reproduce the demoted line verbatim; got:\n%s", out)
	}
	if !strings.Contains(out, "sk-inet.c:1059") {
		t.Fatalf("envelope text must name the later real match as the cause; got:\n%s", out)
	}
	if !strings.Contains(out, "total \"Error (criu/ or soccr/)\" lines found in restore.log: 3") {
		t.Fatalf("envelope text must report the total match count; got:\n%s", out)
	}
}

// §P-VERIFY #9: the full-log path citation must be accurate, not aspirational — the checkpoint-dir
// copy must only be cited when it has actually been written by the time the call site executes.
func TestCriuRestoreFailureCause_PathCitationAccuracy(t *testing.T) {
	p := writeRestoreLog(t, "Error (criu/cr-restore.c:2324): Restoring FAILED.\n")

	notYetCopied := criuRestoreFailureCause(p, "/run/podmotion/checkpoints/mig1", false, true, 1, nil, "")
	if strings.Contains(notYetCopied, "/run/podmotion/checkpoints/mig1/restore.log") {
		t.Fatalf("must not cite the checkpoint-dir copy before it has been written; got:\n%s", notYetCopied)
	}
	if !strings.Contains(notYetCopied, p) {
		t.Fatalf("must still cite the host restoreLogPath; got:\n%s", notYetCopied)
	}

	alreadyCopied := criuRestoreFailureCause(p, "/run/podmotion/checkpoints/mig1", true, true, 1, nil, "")
	if !strings.Contains(alreadyCopied, "/run/podmotion/checkpoints/mig1/restore.log") {
		t.Fatalf("must cite the checkpoint-dir copy once it has been written; got:\n%s", alreadyCopied)
	}
	if !strings.Contains(alreadyCopied, "checkpoint GC") {
		t.Fatalf("checkpoint-dir citation must be annotated as GC-scoped, not durable; got:\n%s", alreadyCopied)
	}
}

// Mechanism-failure class: a persistently failing broker/poll round-trip must be reported as its
// own distinct class, never folded into "CRIU ran and failed" or "CRIU has not finished."
func TestCriuRestoreFailureCause_MechanismFailureIsDistinctClass(t *testing.T) {
	p := writeRestoreLog(t, "Error (criu/mount.c:753): mnt: bad mount\n")
	mechErr := os.ErrClosed

	out := criuRestoreFailureCause(p, "/checkpoint/dir", false, false, 0, mechErr, "")
	if !strings.Contains(out, "mechanism failure") {
		t.Fatalf("expected an explicit mechanism-failure class; got:\n%s", out)
	}
	if strings.Contains(out, "first causal error") {
		t.Fatalf("mechanism failure must not name a CRIU-log cause; got:\n%s", out)
	}
}

func TestIsKnownNonFatalCRIULine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"(00.100258) Error (criu/mount.c:3700): Can't remove the directory /x: Device or resource busy", true},
		{"(00.096933) Error (criu/cgroup.c:1998): cg: cgroupd: recv req error: No such file or directory", true},
		{"1: Error (criu/files-reg.c:2353): Can't open file dev/null on restore: No such file or directory", false},
		{"(00.070369) Error (criu/cr-restore.c:2324): Restoring FAILED.", false},
	}
	for _, c := range cases {
		if got := isKnownNonFatalCRIULine(c.line); got != c.want {
			t.Errorf("isKnownNonFatalCRIULine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}
