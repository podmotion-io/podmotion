/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0349_netns_source_of_truth_test.go — ADR-0349 regression tests: the authoritative
// restored-pod netns/ifname source of truth for the agent-side ReplVethMAC kernel read.
//
// Named tests (a)-(d) per the ADR's "Named regression tests" section:
//   - (a) TestCaptureRestoredVethMAC_ReadsProcessOwnNetns_NotRecordedBindPath (+ the
//         TestCaptureRestoredVethMAC_SucceedsWhereBindPathReadFails_LiveProofCycle1Regression
//         substrate-asymmetry regression). REVISED (Security Reviewer, sprint46B2 validation cycle
//         1): the authoritative MAC is CAPTURED at restore time from the restored process's OWN
//         netns (SrcPID) and written back — the recorded-bind-path re-read the prior test pinned is
//         the exact read the live-proof falsified, so it is retired, not asserted.
//   - (b) TestFinalizeRestore_Strict_FailClosed_OnUnrecordableNetns (+ malformed-MAC sub-case)
//   - (c) TestStoreResolvedNetnsPath_And_Confirmation_Idempotent
//   - (d) TestJoinNsRestore_EveryNonHostNetworkReturn_RecordsGateReadableHandle_OrIsNoHandoff
//     (+ companion TestRestore_StrictUnresolvableSandbox_FailsClosedBeforeJoinNsRestore)

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// newTestScheme builds the minimal runtime.Scheme these tests need (pmv1 only). Local helper —
// this package does not export a shared scheme var (see adr0244_ip_reclaim_test.go's
// newFakeAgentServerWithPM for the established per-file pattern).
func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return scheme
}

// assertNetnsPathShape checks the lexical properties netnsPathRe + validateNetnsPath's
// pre-EvalSymlinks guards enforce (broker.go:111, 116-142) WITHOUT importing the unexported
// broker symbols (different package) or requiring the path to exist on disk. The
// filesystem-dependent EvalSymlinks-in-scope property is proven live (ADR-0349 D5), not here.
func assertNetnsPathShape(p string) error {
	if filepath.Clean(p) != p {
		return fmt.Errorf("path %q is not clean", p)
	}
	if strings.Contains(p, "/proc/") {
		return fmt.Errorf("path %q references /proc", p)
	}
	matched, _ := regexp.MatchString(`^(?:/run/netns|/var/run/netns)/[A-Za-z0-9_.-]{1,64}$`, p)
	if !matched {
		return fmt.Errorf("path %q does not match the /run/netns|/var/run/netns convention", p)
	}
	return nil
}

// shrinkCaptureWait shrinks the captureRestoredVethMAC bounded wait so tests never sleep on the
// happy path, restoring the production values on cleanup.
func shrinkCaptureWait(t *testing.T) {
	t.Helper()
	ob, oi := restoredVethMACCaptureBudget, restoredVethMACCaptureInterval
	restoredVethMACCaptureBudget, restoredVethMACCaptureInterval = 2*time.Second, time.Millisecond
	t.Cleanup(func() { restoredVethMACCaptureBudget, restoredVethMACCaptureInterval = ob, oi })
}

// (a) TestCaptureRestoredVethMAC_ReadsProcessOwnNetns_NotRecordedBindPath is the ADR-0349
// authoritative AT-RESTORE-TIME capture (Security Reviewer, sprint46B2 validation cycle 1). It
// constructs the live branch-2 (pod-sandbox) restore state where joinNsRestore recorded
// /var/run/netns/cni-<id>, then drives captureRestoredVethMAC — the capture joinNsRestore runs the
// instant CRIU brings the process up — and asserts it reads the MAC from the restored process's OWN
// netns by SrcPID (pid>0, netnsPath==""), writes it back, and that finalizeRestore then SERVES that
// value. It MUST NOT re-enter the recorded bind PATH: that path-mode read is the one that returned
// empty for ~75s on the live substrate (live-proof-cycle1) even though the pod was reachable.
func TestCaptureRestoredVethMAC_ReadsProcessOwnNetns_NotRecordedBindPath(t *testing.T) {
	shrinkCaptureWait(t)
	s := New("test-node", &criu.StubCheckpointer{}, nil)

	const migration = "redis-live-branch2-srcpid"
	// joinNsRestore recorded the gate-readable handle via recordAuthoritativeRestoreNetns.
	storeResolvedNetnsPath(migration, "/var/run/netns/cni-abc123", "eth0")

	gotPath, gotIfname := s.finalizeNetnsPath(migration)
	if gotPath != "/var/run/netns/cni-abc123" || gotIfname != "eth0" {
		t.Fatalf("finalizeNetnsPath = (%q, %q), want the recorded branch-2 record", gotPath, gotIfname)
	}
	if err := assertNetnsPathShape(gotPath); err != nil {
		t.Errorf("recorded path does not match the broker's gate shape (netnsPathRe, broker.go:111): %v", err)
	}

	var capPID = -1 // sentinel; overwritten by the spy
	capNetnsPath := "SENTINEL"
	origMAC := readReplVethMACFn
	readReplVethMACFn = func(pid int, netnsPath, ifname string) (string, error) {
		capPID, capNetnsPath = pid, netnsPath
		return "aa:bb:cc:dd:ee:ff", nil
	}
	defer func() { readReplVethMACFn = origMAC }()

	// The at-restore capture reads the restored process's OWN netns (SrcPID), never a bind path.
	captureRestoredVethMAC(migration, 4242, "")
	if capPID != 4242 {
		t.Errorf("capture invoked readReplVethMACFn with pid=%d, want 4242 — the MAC is captured from the restored process's OWN netns (SrcPID /proc/<pid>/ns/net), the denial-free entry the lo-up uses", capPID)
	}
	if capNetnsPath != "" {
		t.Errorf("capture invoked readReplVethMACFn with netnsPath=%q, want \"\" — it MUST NOT re-enter the recorded bind path (the broker path-mode read that returned empty for ~75s live)", capNetnsPath)
	}
	if got := s.resolvedNetnsMAC(migration); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("resolvedNetnsMAC = %q after capture, want the written-back value (write-back did not latch)", got)
	}

	if fr, err := s.finalizeRestore(context.Background(), 4242, gotPath, gotIfname, migration, "", "Strict"); err != nil {
		t.Fatalf("finalizeRestore [Strict] fail-closed despite an at-restore-captured MAC: %v", err)
	} else if fr.mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("finalizeRestore mac = %q, want the captured value it serves from the write-back", fr.mac)
	}
}

// TestCaptureRestoredVethMAC_SucceedsWhereBindPathReadFails_LiveProofCycle1Regression is the RED
// TEST for the exact live cycle-1 failure (docs/sprints/sprint46B2/live-proof-cycle1.md): the redis
// Strict pm-w1→pm-w2 restore reached RestoreSocketReattach, the restored pod was reachable at its
// pod IP (so eth0 IS present in the process's netns), yet finalizeRestore fail-closed with
// "replVethMAC empty after restore" because the recorded /var/run/netns/cni-<id> BIND PATH read
// returned empty for ~75s. The stub reproduces that substrate asymmetry: a path-mode read
// (netnsPath != "") yields empty (the broker's EvalSymlink path-mode nsenter could not resolve the
// bind), while a SrcPID read (netnsPath == "", the restored process's own /proc/<pid>/ns/net) yields
// the real MAC. This test FAILS against the pre-fix code (finalizeRestore read the bind path with
// pid=0 → empty → Strict fail-closed) and PASSES after (the at-restore capture reads the process's
// own netns → non-empty → migration proceeds). This is the coverage the OSS QA Lead flagged missing.
func TestCaptureRestoredVethMAC_SucceedsWhereBindPathReadFails_LiveProofCycle1Regression(t *testing.T) {
	shrinkCaptureWait(t)
	const wantMAC = "02:42:ac:11:00:1a"

	origMAC := readReplVethMACFn
	readReplVethMACFn = func(pid int, netnsPath, ifname string) (string, error) {
		if netnsPath != "" {
			// Bind-path (path-mode) read — the live substrate returned empty here for ~75s.
			return "", nil
		}
		// SrcPID read of the restored process's OWN netns — where eth0 actually is.
		if pid > 0 && ifname == "eth0" {
			return wantMAC, nil
		}
		return "", nil
	}
	defer func() { readReplVethMACFn = origMAC }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	const migration = "redis-live-cycle1-bindpath-empty"
	storeResolvedNetnsPath(migration, "/var/run/netns/cni-cycle1", "eth0")

	// joinNsRestore runs the at-restore capture the instant CRIU brings the process up.
	captureRestoredVethMAC(migration, 9001, "")

	netnsPath, ifname := s.finalizeNetnsPath(migration)
	fr, err := s.finalizeRestore(context.Background(), 9001, netnsPath, ifname, migration, "", "Strict")
	if err != nil {
		t.Fatalf("finalizeRestore [Strict] fail-closed even though eth0 IS present in the restored process's own netns: %v — "+
			"this is the sprint46B2 live-proof cycle-1 failure (the recorded bind-path read returns empty; the SrcPID capture must carry the migration)", err)
	}
	if fr.mac != wantMAC {
		t.Errorf("finalizeRestore mac = %q, want %q captured from the process's own netns", fr.mac, wantMAC)
	}
}

// (b) TestFinalizeRestore_Strict_FailClosed_OnUnrecordableNetns is the NON-NEGOTIABLE inverse:
// prove the fail-closed branch (server.go finalizeRestore, Strict) STILL fires when no
// gate-readable netns is recorded and the kernel read yields empty. Asserts the distinct R3
// string, that Status.ReplVethMAC is never read (spy client, zero Get calls), and that no
// pid>0 / /proc attempt is constructed on the unrecordable-netns path.
func TestFinalizeRestore_Strict_FailClosed_OnUnrecordableNetns(t *testing.T) {
	origMAC := readReplVethMACFn
	var procAttemptPID = -1
	readReplVethMACFn = func(pid int, netnsPath, ifname string) (string, error) {
		procAttemptPID = pid
		return "", errors.New("stub: no netns source")
	}
	defer func() { readReplVethMACFn = origMAC }()

	// Spy client: records every Get so we can assert Status.ReplVethMAC is never read.
	var getCalls int
	spy := interceptor.NewClient(fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build(), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			getCalls++
			return c.Get(ctx, key, obj, opts...)
		},
	})

	s := New("test-node", &criu.StubCheckpointer{}, spy)

	const migration = "redis-strict-unrecordable"
	netnsPath, ifname := s.finalizeNetnsPath(migration) // no storeResolvedNetnsPath call — nothing recorded
	if netnsPath != "" {
		t.Fatalf("test setup invalid: finalizeNetnsPath returned %q, want \"\" (nothing recorded)", netnsPath)
	}

	_, err := s.finalizeRestore(context.Background(), 4242, netnsPath, ifname, migration, "podmotion-test", "Strict")
	if err == nil {
		t.Fatal("expected fail-closed error, got nil")
	}
	wantSubstr := fmt.Sprintf("no authoritative restored netns recorded for migration %s", migration)
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Errorf("error = %q, want it to contain %q (R3 distinct string, not the transient-read string)", err.Error(), wantSubstr)
	}
	if strings.Contains(err.Error(), "path-independent contract violation") {
		t.Errorf("error = %q collided with the transient-read string — D8 requires the two to be distinct", err.Error())
	}
	if getCalls != 0 {
		t.Errorf("finalizeRestore made %d Get call(s) against the k8s client on the fail-closed path — must never read Status.ReplVethMAC (D3/D4)", getCalls)
	}
	// netnsPath == "" here, so R2's pid=0 gating does NOT apply (that gating is conditioned on
	// netnsPath != ""); the real restored pid is passed straight through. This is the only
	// remaining legitimate use of the PID-scoped read (no netns was ever recorded to bind-read
	// against), and it is exactly this call's stub failure that drives fail-closed.
	if procAttemptPID != 4242 {
		t.Errorf("readReplVethMACFn invoked with pid=%d, want pid=4242 (netnsPath==\"\" — pid passed through unchanged per R2)", procAttemptPID)
	}
}

// TestFinalizeRestore_Strict_FailClosed_OnMalformedMAC covers R4's producer-side net.ParseMAC
// validation: a syntactically invalid MAC against a KNOWN (recorded) netns is a transient READ
// failure, not a missing-record condition — it must emit the EXISTING string, not the new R3
// "no authoritative restored netns" string (D8: the two strings must never collide).
func TestFinalizeRestore_Strict_FailClosed_OnMalformedMAC(t *testing.T) {
	origMAC := readReplVethMACFn
	readReplVethMACFn = func(pid int, netnsPath, ifname string) (string, error) {
		return "not-a-mac", nil
	}
	defer func() { readReplVethMACFn = origMAC }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	const migration = "redis-strict-malformed-mac"
	storeResolvedNetnsPath(migration, "/var/run/netns/cni-malformed", "eth0")
	netnsPath, ifname := s.finalizeNetnsPath(migration)

	_, err := s.finalizeRestore(context.Background(), 4242, netnsPath, ifname, migration, "", "Strict")
	if err == nil {
		t.Fatal("expected fail-closed error for an unparseable MAC, got nil")
	}
	// netnsPath is non-empty (recorded) here, so this MUST be the EXISTING transient string,
	// not the R3 "no authoritative restored netns" string — a parse failure against a KNOWN
	// netns is a read failure, not a missing-record condition.
	if !strings.Contains(err.Error(), "path-independent contract violation") {
		t.Errorf("error = %q, want the existing transient-read string (R4: malformed MAC treated as empty)", err.Error())
	}
	if strings.Contains(err.Error(), "no authoritative restored netns recorded") {
		t.Errorf("error = %q collided with the R3 no-record string — D8 requires the two to be distinct", err.Error())
	}
}

// (c) TestStoreResolvedNetnsPath_And_Confirmation_Idempotent covers R5: repeated
// storeResolvedNetnsPath and repeated confirmation writebacks for the same migration converge
// to one (path, ifname) and one MAC, with no duplicate neighbor install side effects surfaced.
func TestStoreResolvedNetnsPath_And_Confirmation_Idempotent(t *testing.T) {
	const migration = "redis-idempotent-confirm"
	storeResolvedNetnsPath(migration, "/var/run/netns/cni-idem", "eth0")
	storeResolvedNetnsPath(migration, "/var/run/netns/cni-idem", "eth0") // repeat — must converge, not append/duplicate

	p, ifn := (&AgentServer{}).ResolvedNetnsPath(migration), (&AgentServer{}).resolvedNetnsIfname(migration)
	if p != "/var/run/netns/cni-idem" || ifn != "eth0" {
		t.Fatalf("storeResolvedNetnsPath not idempotent: got (%q, %q)", p, ifn)
	}

	pm := &pmv1.PodMigration{ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: "podmotion-test"}}
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
	s := New("test-node", &criu.StubCheckpointer{}, cl)

	for i := 0; i < 2; i++ {
		if err := s.ReportRestoreConfirmed(context.Background(), migration, "podmotion-test", 4242, "aa:bb:cc:dd:ee:ff"); err != nil {
			t.Fatalf("ReportRestoreConfirmed call %d: %v", i, err)
		}
	}

	got := &pmv1.PodMigration{}
	if err := cl.Get(context.Background(), types.NamespacedName{Name: migration, Namespace: "podmotion-test"}, got); err != nil {
		t.Fatalf("get PodMigration: %v", err)
	}
	if got.Status.ReplVethMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Status.ReplVethMAC = %q after 2 identical confirmations, want the single converged value", got.Status.ReplVethMAC)
	}
}

// (d) TestJoinNsRestore_EveryNonHostNetworkReturn_RecordsGateReadableHandle_OrIsNoHandoff is the
// R1 CI PIN (table-driven, invariant #10). Drives recordAuthoritativeRestoreNetns directly (the
// extracted decision point) across the branch-1 (no sandboxID) and branch-2 (sandboxID, resolve
// success/failure) cases and asserts the recording behavior a future joinNsRestore refactor must
// not silently drop.
func TestJoinNsRestore_EveryNonHostNetworkReturn_RecordsGateReadableHandle_OrIsNoHandoff(t *testing.T) {
	tests := []struct {
		name         string
		sandboxID    string
		resolveErr   error
		resolvedPath string
		wantRecord   bool
		wantPath     string
		wantIfname   string
		wantErr      bool
	}{
		{
			name:       "branch1_no_sandboxID_records_nothing_no_handoff",
			sandboxID:  "",
			wantRecord: false,
		},
		{
			name:         "branch2_live_sandboxID_records_gate_readable_handle",
			sandboxID:    "sbx-live-1",
			resolvedPath: "/var/run/netns/cni-abc123",
			wantRecord:   true,
			wantPath:     "/var/run/netns/cni-abc123",
			wantIfname:   "eth0",
		},
		{
			name:       "branch2_resolve_failure_returns_error_records_nothing",
			sandboxID:  "sbx-fail-1",
			resolveErr: errors.New("stub: sandbox resolve failed"),
			wantErr:    true,
			wantRecord: false,
		},
	}

	origResolve := resolveNetnsFromSandboxFn
	defer func() { resolveNetnsFromSandboxFn = origResolve }()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolvedNetnsPathsMu.Lock()
			delete(resolvedNetnsPaths, tc.name)
			resolvedNetnsPathsMu.Unlock()

			resolveNetnsFromSandboxFn = func(ctx context.Context, _ interface{}, sandboxID string) (*os.File, string, error) {
				if tc.resolveErr != nil {
					return nil, "", tc.resolveErr
				}
				f, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatalf("open devnull stub fd: %v", err)
				}
				return f, tc.resolvedPath, nil
			}

			gotPath, gotIfname, err := recordAuthoritativeRestoreNetns(context.Background(), tc.name, tc.sandboxID)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotPath != tc.wantPath || gotIfname != tc.wantIfname {
				t.Errorf("recordAuthoritativeRestoreNetns = (%q, %q), want (%q, %q)", gotPath, gotIfname, tc.wantPath, tc.wantIfname)
			}

			stored := (&AgentServer{}).ResolvedNetnsPath(tc.name)
			if tc.wantRecord {
				if stored == "" {
					t.Fatal("expected storeResolvedNetnsPath to have recorded a handle, map entry is empty")
				}
				if err := assertNetnsPathShape(stored); err != nil {
					t.Errorf("recorded path fails the broker's gate shape: %v", err)
				}
			} else if stored != "" {
				t.Errorf("branch-1/error row recorded %q, want no record at all", stored)
			}
		})
	}
}

// Companion assertion (D2's second half — the ADR-0325 upstream gate, tested independently
// since it lives in Restore(), not joinNsRestore): a Strict/BestEffort gRPC restore with a live
// k8sClient that cannot resolve the replacement pod's sandbox MUST fail closed BEFORE
// joinNsRestoreFn is ever called — branch 1 (sandboxID=="") inside joinNsRestore is therefore
// structurally unreachable on this path with a live k8sClient.
func TestRestore_StrictUnresolvableSandbox_FailsClosedBeforeJoinNsRestore(t *testing.T) {
	imagesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(imagesDir, "inventory.img"), []byte("CRIU\x00\x01"), 0o600); err != nil {
		t.Fatalf("seed inventory.img: %v", err)
	}
	if err := os.WriteFile(filepath.Join(imagesDir, "config.json"), []byte(`{"ociVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatalf("seed config.json: %v", err)
	}

	joinCalled := false
	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, migName, checkpointDir, imageName, containerID, destNetnsFd, sandboxID, storedHostVeth string, strictMode bool, reattachMountPaths []reattachMount, containerCgroupsPath, podCgroupParent string) (int, []ExternalMountDroppedInfo, error) {
		joinCalled = true
		return 99999, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	// PodMigration exists (so resolveNamespaceForMigration/resolveSandboxIDForMigration get past
	// the namespace lookup) but NO replacement pod exists and Status.ReplacementPodName is
	// empty — resolveSandboxIDForMigration fails, resolvePodNetnsSandbox returns ("", true).
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "strict-unresolvable", Namespace: "podmotion-test"},
		Spec:       pmv1.PodMigrationSpec{PodNamespace: "podmotion-test"},
	}
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).Build()
	s := New("test-node", &criu.StubCheckpointer{}, cl)

	resp, err := s.Restore(context.Background(), &agentpb.RestoreRequest{
		MigrationName:       "strict-unresolvable",
		CheckpointRef:       imagesDir,
		TcpPreservationMode: "Strict",
		// B2 (Sprint 32 gate25, server.go:~6416) fails closed BEFORE the ADR-0325 gate this test
		// targets when Strict carries an empty DestNetnsFd ("DestinationNetnsReady stage did not
		// plumb netns fd"). A non-empty (not required to exist on disk — resolvePodNetnsSandbox
		// self-resolves unconditionally on migration name, independent of this value) DestNetnsFd
		// clears that earlier guard so the RPC reaches the ADR-0325 sandbox self-resolve this test
		// exercises.
		DestNetnsFd: "/run/podmotion/netns/pm-mig-companion-stub/bind",
	})
	if err != nil {
		t.Fatalf("Restore returned a transport-level error (want a Success:false response instead): %v", err)
	}
	if resp == nil || resp.Success {
		t.Fatalf("Restore = %+v, want Success:false (ADR-0325 fail-closed on unresolvable sandbox)", resp)
	}
	if !strings.Contains(resp.ErrorMessage, "could not resolve replacement pod sandbox netns (ADR-0325)") {
		t.Errorf("ErrorMessage = %q, want the ADR-0325 fail-closed message", resp.ErrorMessage)
	}
	if joinCalled {
		t.Fatal("joinNsRestoreFn was called — the ADR-0325 gate must fail closed BEFORE joinNsRestore, not after")
	}
}
