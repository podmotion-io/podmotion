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

// restore_mode_test.go — ADR-0385 regression tests for the raw-CRIU gRPC Restore branch's
// single patch-invocation fix.
//
// Prior to ADR-0385, this branch ran its OWN standalone patchCheckpointImages pre-call BEFORE
// calling joinNsRestoreFn (which performs the identical patch step again internally, always
// unconditionally). The pre-call's Strict-fails/BestEffort-degrades mode split
// (TestRestoreAbortOnPatchFailure_Strict / TestRestoreSkipPatchFailure_BestEffort, this file's
// prior contents) was moot in practice: joinNsRestoreFn's internal patch call fails closed on
// ANY patch error regardless of mode, so the pre-call's "BestEffort/None degrade-and-continue"
// never actually reached CRIU restore — the second, real call inside joinNsRestoreFn re-failed
// the identical patch and aborted regardless of what the pre-call decided. ADR-0385 removed the
// redundant pre-call (and the mode split along with it, since it never functioned).
//
// These tests verify the corrected, real behavior: a restore-drive failure on this branch
// (represented by stubbing joinNsRestoreFn, since the real patch/CRIU/ctr chain requires a live
// node) now propagates as a Restore() error UNIFORMLY across tcpPreservationMode values — there
// is no longer a mode-dependent branch to diverge on, and no "restore aborted (strict)" sentinel
// string is fabricated or expected any more.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// makeTempRestoreDir creates a minimal checkpoint directory that passes the inventory.img
// sanity check but does NOT contain config.json, so Restore proceeds to the raw CRIU path.
func makeTempRestoreDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// inventory.img must be non-empty to pass the pre-restore sanity check.
	invPath := filepath.Join(dir, "inventory.img")
	if err := os.WriteFile(invPath, []byte("CRIU\x00\x01"), 0o600); err != nil {
		t.Fatalf("write inventory.img: %v", err)
	}
	return dir
}

// TestRestoreBranch2_JoinFailurePropagates_Strict verifies that on the raw-CRIU fallback branch,
// a joinNsRestoreFn failure (standing in for a real patch/CRIU failure — see file doc) is
// returned as a non-nil Restore() error under Strict mode.
func TestRestoreBranch2_JoinFailurePropagates_Strict(t *testing.T) {
	imagesDir := makeTempRestoreDir(t)

	joinErr := errors.New("join-ns restore: PATCH_ERROR: unknown magic 0xdeadbeef")
	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, _, _, _, _, _, _, _ string, _ bool, _ []reattachMount, _, _, _ string) (int, []ExternalMountDroppedInfo, error) {
		return 0, nil, joinErr
	}
	t.Cleanup(func() { joinNsRestoreFn = origJoin })

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	resp, err := s.Restore(context.Background(), &agentpb.RestoreRequest{
		MigrationName:       "test-strict-join-fail",
		CheckpointRef:       imagesDir,
		TcpPreservationMode: "Strict",
		// DestNetnsFd is non-empty so the D2-C1 mode-keyed netns guard (mode==Strict) is
		// satisfied and Restore proceeds to the raw-CRIU / joinNsRestoreFn call under test.
		DestNetnsFd: "/proc/self/ns/net",
	})
	if err == nil {
		t.Fatalf("expected non-nil error when joinNsRestoreFn fails under Strict, got nil (resp=%v)", resp)
	}
	if !errors.Is(err, joinErr) {
		t.Errorf("expected joinErr to be wrapped in the returned error; errors.Is returned false (err=%v)", err)
	}
}

// TestRestoreBranch2_JoinFailurePropagates_BestEffortOrNone verifies the SAME failure-propagates
// behavior holds under BestEffort/None — ADR-0385 removed the mode-dependent branch entirely, so
// there is no longer a degrade-and-continue path to diverge on for this failure.
func TestRestoreBranch2_JoinFailurePropagates_BestEffortOrNone(t *testing.T) {
	for _, mode := range []string{"BestEffort", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			imagesDir := makeTempRestoreDir(t)

			joinErr := errors.New("join-ns restore: PATCH_ERROR: unknown magic 0xdeadbeef")
			origJoin := joinNsRestoreFn
			joinNsRestoreFn = func(_ context.Context, _, _, _, _, _, _, _ string, _ bool, _ []reattachMount, _, _, _ string) (int, []ExternalMountDroppedInfo, error) {
				return 0, nil, joinErr
			}
			t.Cleanup(func() { joinNsRestoreFn = origJoin })

			s := New("test-node", &criu.StubCheckpointer{}, nil)
			_, err := s.Restore(context.Background(), &agentpb.RestoreRequest{
				MigrationName:       "test-besteffort-join-fail",
				CheckpointRef:       imagesDir,
				TcpPreservationMode: mode,
			})
			if err == nil {
				t.Fatalf("expected non-nil error when joinNsRestoreFn fails (mode=%q) — ADR-0385 removed the standalone pre-call's degrade-and-continue, which never actually reached CRIU restore anyway", mode)
			}
			if !errors.Is(err, joinErr) {
				t.Errorf("expected joinErr to be wrapped in the returned error; errors.Is returned false (err=%v)", err)
			}
		})
	}
}
