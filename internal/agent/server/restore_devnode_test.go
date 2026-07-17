// restore_devnode_test.go — the coverage that was ABSENT when sprint46 live-proof cycle 1 failed.
//
// On pm-w2 the real redis Strict migration aborted inside CRIU restore with (decoded from
// /var/lib/podmotion/restore/redis-live-strict/data/restore.log):
//
//	1: Error (criu/files-reg.c:2353): Can't open file dev/null on restore: No such file or directory
//	1: Error (criu/files.c:1221): Unable to open fd=0 id=0x5
//	Error (criu/cr-restore.c:2324): Restoring FAILED.
//
// CRIU dumped the workload's fd 0 (stdin) as a REG-file open of /dev/null; on restore it reopens
// that backing file by PATH under --root <rootfsDir>. A container overlay IMAGE ships an EMPTY
// /dev (verified live: redis:7-alpine /dev has no `null` node), so the reopen ENOENTs and CRIU
// aborts the ENTIRE restore before writing --pidfile — surfacing only as the misleading downstream
// "restored process PID not found … pidfile never appeared" symptom the panel rejected on.
//
// joinNsRestore now provisions the OCI-standard device-node set into the restore rootfs before
// CRIU restore. These tests pin that contract: a test asserting /dev/null is provisioned (fail
// closed, char 1,3) fails against the pre-fix tree and passes after — exactly the acceptance a
// green pidfile-reader unit test (which injects a fake reader and never touches /dev) could not
// give.
package server

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestStandardRestoreDevNodes_ProvisionsDevNull(t *testing.T) {
	var devnull *restoreDevNode
	for i := range standardRestoreDevNodes {
		if standardRestoreDevNodes[i].rel == "dev/null" {
			devnull = &standardRestoreDevNodes[i]
			break
		}
	}
	if devnull == nil {
		t.Fatal("standardRestoreDevNodes does not provision dev/null — CRIU aborts the restore reopening fd 0 backed by /dev/null (pm-w2 files-reg.c:2353)")
	}
	if devnull.major != 1 || devnull.minor != 3 {
		t.Fatalf("dev/null must be char 1,3 (host crw-rw-rw- 1,3); got %d,%d", devnull.major, devnull.minor)
	}
	if !devnull.required {
		t.Fatal("dev/null must be `required` (fail-closed): its absence aborts the whole restore before --pidfile, so a best-effort skip would re-surface as the misleading 'restored PID not found' symptom")
	}
}

func TestStandardRestoreDevNodes_OCIDefaultSet(t *testing.T) {
	want := map[string][2]int{
		"dev/null":    {1, 3},
		"dev/zero":    {1, 5},
		"dev/full":    {1, 7},
		"dev/random":  {1, 8},
		"dev/urandom": {1, 9},
		"dev/tty":     {5, 0},
	}
	got := map[string][2]int{}
	for _, n := range standardRestoreDevNodes {
		got[n.rel] = [2]int{n.major, n.minor}
	}
	for rel, mm := range want {
		g, ok := got[rel]
		if !ok {
			t.Errorf("standardRestoreDevNodes missing %s", rel)
			continue
		}
		if g != mm {
			t.Errorf("%s: want major/minor %v, got %v", rel, mm, g)
		}
	}
	// Only /dev/null is load-bearing; the rest must be best-effort so a node-creation hiccup on an
	// unusual runtime cannot fail an otherwise-healthy migration.
	for _, n := range standardRestoreDevNodes {
		if n.required && n.rel != "dev/null" {
			t.Errorf("only dev/null may be `required`; %s is marked required", n.rel)
		}
	}
}

func TestDevNodeMknodShellCmd_IdempotentAndCorrectDevNumbers(t *testing.T) {
	root := "/var/lib/podmotion/restore/redis-live-strict/rootfs"
	p := filepath.Join(root, "dev/null")
	cmd := devNodeMknodShellCmd(root, restoreDevNode{rel: "dev/null", major: 1, minor: 3, required: true})
	want := fmt.Sprintf("umask 0000; [ -e %q ] || mknod -m 666 %q c 1 3", p, p)
	if cmd != want {
		t.Fatalf("devNodeMknodShellCmd mismatch:\n got: %s\nwant: %s", cmd, want)
	}
	// The `[ -e ]` idempotency guard must be present so re-provisioning (NRI bundle already
	// populated /dev, or a second restore attempt of the same migration) does not fail on EEXIST.
	if !strings.Contains(cmd, "[ -e ") {
		t.Error("mknod command lacks the `[ -e ]` idempotency guard")
	}
	// `umask 0000` must precede mknod so `-m 666` is not masked (a write-mode /dev/null fd — e.g.
	// stdout redirected to /dev/null — would EACCES on an 0644 node).
	if !strings.HasPrefix(cmd, "umask 0000;") {
		t.Error("mknod command must start with `umask 0000;` so -m 666 yields crw-rw-rw-")
	}
	// It is a character device with the exact major/minor (a REG file or wrong numbers would not
	// satisfy CRIU's reopen of the /dev/null-backed fd).
	if !strings.Contains(cmd, "mknod -m 666 ") || !strings.HasSuffix(cmd, " c 1 3") {
		t.Errorf("dev/null must be created as char device `c 1 3`; got %q", cmd)
	}
}
