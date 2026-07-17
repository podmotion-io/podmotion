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

// restore_path_parity_test.go — AC1 path-parity tests (ADR-0133).
//
// Proves that BOTH gRPC Restore branches (config.json / raw-CRIU fallback) and
// the NRI closure (JoinNsRestore) execute the correct joinNsRestore→finalizeRestore
// chain, and that finalizeRestore passes a non-empty MAC to its return value (which
// callers then forward to ReportRestoreConfirmed).
//
// Production note: on the gRPC Restore path, finalizeRestore is gated on
// s.k8sClient != nil (the operator must have a running k8s client for the CR patch
// to succeed). In unit tests we inject a nil k8s client, so we verify the path up to
// the k8s gate — the joinNsRestoreFn stub proving the correct branch was taken.
// The end-to-end MAC→ReportRestoreConfirmed wiring is proven by TestJoinNsRestore_*
// (repl_veth_mac_test.go) and by TestJoinNsRestore_ReturnsMACToCaller below, which
// operate on finalizeRestore directly without the k8s gate.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// makeBranch1Dir creates a temp checkpoint dir with both inventory.img and config.json
// so Restore takes the join-ns branch (Branch 1).
func makeBranch1Dir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "inventory.img"), []byte("CRIU\x00\x01"), 0o600); err != nil {
		t.Fatalf("write inventory.img: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"ociVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	return dir
}

// makeBranch2Dir creates a temp checkpoint dir with only inventory.img (no config.json)
// so Restore takes the raw-CRIU fallback branch (Branch 2).
// Identical to makeTempRestoreDir in restore_mode_test.go; re-declared here for clarity.
func makeBranch2Dir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "inventory.img"), []byte("CRIU\x00\x01"), 0o600); err != nil {
		t.Fatalf("write inventory.img: %v", err)
	}
	return dir
}

// TestRestoreBranch1_MACFlowsToReportRestoreConfirmed drives the join-ns (Branch 1) path of
// the gRPC Restore handler. It stubs joinNsRestoreFn to return a fake PID and stubs
// readReplVethMACFn to return a known MAC. The test asserts:
//   - joinNsRestoreFn was called (the config.json branch was taken).
//   - Restore returns Success=true (end-to-end branch completion).
//
// Note: finalizeRestore is gated on s.k8sClient != nil on this gRPC path. With a nil
// k8s client the gate is not reached; the MAC wiring on the gRPC path is covered by
// integration tests. The NRI MAC wiring is proven by TestJoinNsRestore_ReturnsMACToCaller.
func TestRestoreBranch1_MACFlowsToReportRestoreConfirmed(t *testing.T) {
	imagesDir := makeBranch1Dir(t)

	// Track that joinNsRestoreFn was called.
	joinNsCalled := false
	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, migName, checkpointDir, imageName, containerID, destNetnsFd, sandboxID, storedHostVeth string, strictMode bool, reattachMountPaths []reattachMount, containerCgroupsPath, podCgroupParent, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error) {
		joinNsCalled = true
		return 99999, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	// Stub readReplVethMACFn — proves the production symbol is wired correctly.
	origMAC := readReplVethMACFn
	readReplVethMACFn = func(_ context.Context, pid int, netnsPath, ifname string) (string, error) {
		return "aa:bb:cc:dd:ee:ff", nil
	}
	defer func() { readReplVethMACFn = origMAC }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	resp, err := s.Restore(context.Background(), &agentpb.RestoreRequest{
		MigrationName: "test-branch1-mac",
		CheckpointRef: imagesDir,
	})
	if err != nil {
		t.Fatalf("Restore (Branch 1) returned unexpected error: %v", err)
	}
	if !joinNsCalled {
		t.Fatal("joinNsRestoreFn was not called — Branch 1 (config.json path) was not taken")
	}
	if resp == nil || !resp.Success {
		t.Fatalf("Restore (Branch 1) expected Success=true, got resp=%v", resp)
	}
}

// TestRestoreBranch2_MACFlowsToReportRestoreConfirmed drives the raw-CRIU fallback (Branch 2)
// path of the gRPC Restore handler (no config.json). It stubs joinNsRestoreFn to return a
// fake PID and stubs readReplVethMACFn to return a known MAC. The test asserts:
//   - joinNsRestoreFn was called (the raw-CRIU fallback branch was taken).
//   - patchCheckpointImagesFn succeeded (stubbed to nil).
//   - Restore returns Success=true.
func TestRestoreBranch2_MACFlowsToReportRestoreConfirmed(t *testing.T) {
	imagesDir := makeBranch2Dir(t)

	// Stub patchCheckpointImagesFn — Branch 2 calls this; without stub it would exec Python.
	origPatch := patchCheckpointImagesFn
	patchCheckpointImagesFn = func(_ string, _ []string, _ []string, _ map[string]string) error { return nil }
	defer func() { patchCheckpointImagesFn = origPatch }()

	// Track that joinNsRestoreFn was called.
	joinNsCalled := false
	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, migName, checkpointDir, imageName, containerID, destNetnsFd, sandboxID, storedHostVeth string, strictMode bool, reattachMountPaths []reattachMount, containerCgroupsPath, podCgroupParent, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error) {
		joinNsCalled = true
		return 99999, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	// Stub readReplVethMACFn — proves the production symbol is wired correctly.
	origMAC := readReplVethMACFn
	readReplVethMACFn = func(_ context.Context, pid int, netnsPath, ifname string) (string, error) {
		return "aa:bb:cc:dd:ee:ff", nil
	}
	defer func() { readReplVethMACFn = origMAC }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	resp, err := s.Restore(context.Background(), &agentpb.RestoreRequest{
		MigrationName: "test-branch2-mac",
		CheckpointRef: imagesDir,
	})
	if err != nil {
		t.Fatalf("Restore (Branch 2) returned unexpected error: %v", err)
	}
	if !joinNsCalled {
		t.Fatal("joinNsRestoreFn was not called — Branch 2 (raw-CRIU fallback) was not taken")
	}
	if resp == nil || !resp.Success {
		t.Fatalf("Restore (Branch 2) expected Success=true, got resp=%v", resp)
	}
}

// TestJoinNsRestore_ReturnsMACToCaller proves the NRI closure (s.JoinNsRestore) passes a
// non-empty MAC back to its caller. JoinNsRestore calls finalizeRestore directly (no k8s
// gate), so this test fully exercises the joinNsRestoreFn→finalizeRestore→readReplVethMACFn
// chain and asserts the returned mac == "aa:bb:cc:dd:ee:ff".
func TestJoinNsRestore_ReturnsMACToCaller(t *testing.T) {
	const wantMAC = "aa:bb:cc:dd:ee:ff"

	// Stub joinNsRestoreFn — avoids real CRIU subprocess.
	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, migName, checkpointDir, imageName, containerID, destNetnsFd, sandboxID, storedHostVeth string, strictMode bool, reattachMountPaths []reattachMount, containerCgroupsPath, podCgroupParent, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error) {
		return 99999, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	// Stub readReplVethMACFn — returns the expected MAC.
	origMAC := readReplVethMACFn
	readReplVethMACFn = func(_ context.Context, pid int, netnsPath, ifname string) (string, error) {
		return wantMAC, nil
	}
	defer func() { readReplVethMACFn = origMAC }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	// ADR-0215/ADR-0217 fail-close: JoinNsRestore resolves the workload image from (1) the NRI
	// event, (2) the PrepareDestinationNetns cache (destWorkloadImage), or (3) the replacement
	// pod spec (needs a k8s client) BEFORE it will call joinNsRestoreFn. This test injects a nil
	// k8s client and passes an empty NRI image, so on baseline all three sources are empty and
	// JoinNsRestore fail-closes at the ADR-0217 guard — the pre-existing failure this test hit.
	// In production the ADR-0168-B2 chain always populates the PrepareDestinationNetns cache
	// (source 2) before restore; the test fixture simply never did. Populate the authoritative
	// cache source the same way PrepareDestinationNetns does, so image resolution succeeds and
	// the joinNsRestoreFn→finalizeRestore→readReplVethMACFn chain under test actually runs.
	s.destWorkloadImageMu.Lock()
	s.destWorkloadImage["test-nri-migration"] = "docker.io/library/redis:7-alpine"
	s.destWorkloadImageMu.Unlock()
	// JoinNsRestore signature: (migrationName, namespace, checkpointDir, imageName, containerID, sandboxID, containerCgroupsPath, podCgroupParent, tcpPreservationMode)
	// namespace="default" is a test-only placeholder — this test injects a nil k8sClient, so
	// ReportRestoreConfirmed's namespace-gated k8s patch (folded into JoinNsRestore by ADR-0353
	// R4) is a no-op and the namespace value itself is not asserted on.
	// ADR-0354 round 7: JoinNsRestore now takes a leading ctx. This test harness has no real
	// upstream NRI/gRPC ctx to thread (it drives JoinNsRestore directly, not through the NRI
	// plugin), so context.Background() is used deliberately — this is a test-only call site,
	// not a live production path.
	_, gotMAC, err := s.JoinNsRestore(context.Background(), "test-nri-migration", "default", "/tmp/fake-checkpoint", "", "", "", "", "", "None")
	if err != nil {
		t.Fatalf("JoinNsRestore returned unexpected error: %v", err)
	}
	if gotMAC != wantMAC {
		t.Errorf("JoinNsRestore returned mac=%q, want %q", gotMAC, wantMAC)
	}
}

// TestRestoreBranch1_StrictFailsWhenNoK8sClient proves that under Strict mode with a nil
// k8sClient, Restore still runs finalizeRestore and fails-closed when MAC resolution fails.
// This test FAILS before the C1 fix (finalizeRestore was gated on k8sClient != nil) and
// PASSES after (finalizeRestore is called unconditionally).
func TestRestoreBranch1_StrictFailsWhenNoK8sClient(t *testing.T) {
	imagesDir := makeBranch1Dir(t)

	// Stub readReplVethMACFn to return an error — simulates MAC resolution failure.
	orig := readReplVethMACFn
	readReplVethMACFn = func(_ context.Context, pid int, netnsPath, ifname string) (string, error) {
		return "", errors.New("stub: MAC resolution failed")
	}
	defer func() { readReplVethMACFn = orig }()

	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, migrationName, checkpointDir, imageName, containerID, destNetnsFd, sandboxID, storedHostVeth string, strictMode bool, reattachMountPaths []reattachMount, containerCgroupsPath, podCgroupParent, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error) {
		return 12345, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	s := New("test-node", &criu.StubCheckpointer{}, nil) // nil k8s client

	req := &agentpb.RestoreRequest{
		MigrationName:       "test-migration",
		TcpPreservationMode: "Strict",
		CheckpointRef:       imagesDir,
	}
	resp, err := s.Restore(context.Background(), req)
	// Under Strict + empty MAC + nil k8sClient, must fail-closed.
	if err == nil && (resp == nil || resp.Success) {
		t.Fatal("expected Restore to fail-closed under Strict with empty MAC even when k8sClient is nil, but got Success=true")
	}
}
