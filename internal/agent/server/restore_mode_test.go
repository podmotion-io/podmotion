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

// restore_mode_test.go — A1 regression tests for ADR-0049 Amendment D explicit mode field.
//
// Verifies that patchCheckpointImages failures are correctly gated on TCPPreservationMode:
//   - TestRestoreAbortOnPatchFailure_Strict: Strict mode must abort (return error, not delete
//     source pod — ADR-0012 is enforced because rollback is triggered, not silent delete).
//   - TestRestoreSkipPatchFailure_BestEffort: BestEffort/None must degrade-and-continue.
//
// These tests inject a failing patchCheckpointImagesFn without requiring a live CRIU binary
// or real checkpoint images.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// makeTempRestoreDir creates a minimal checkpoint directory that passes the inventory.img
// sanity check but does NOT contain config.json, so Restore proceeds to the raw CRIU path
// where patchCheckpointImagesFn is called.
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

// TestRestoreAbortOnPatchFailure_Strict verifies A1: when patchCheckpointImages fails and
// TCPPreservationMode is "Strict", Restore must return a non-nil error (abort path).
// ADR-0012: source pod is NOT deleted because a non-nil error triggers controller rollback
// rather than advancing the migration state machine to source-pod deletion.
func TestRestoreAbortOnPatchFailure_Strict(t *testing.T) {
	imagesDir := makeTempRestoreDir(t)

	patchErr := errors.New("PATCH_ERROR: unknown magic 0xdeadbeef")

	// Inject a failing patchCheckpointImagesFn for the duration of the test.
	origFn := patchCheckpointImagesFn
	patchCheckpointImagesFn = func(_ string, _ []string, _ []string) error { return patchErr }
	t.Cleanup(func() { patchCheckpointImagesFn = origFn })

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	resp, err := s.Restore(ctx, &agentpb.RestoreRequest{
		MigrationName:       "test-strict-abort",
		CheckpointRef:       imagesDir,
		TcpPreservationMode: "Strict",
		// DestNetnsFd is non-empty so the D2-C1 mode-keyed netns guard (which now fires on
		// mode==Strict regardless of SeqSnapshots) is satisfied and Restore proceeds to the
		// raw CRIU / patchCheckpointImages path this test exercises.
		DestNetnsFd: "/proc/self/ns/net",
	})

	// Under Strict + patch failure: must return a non-nil error (abort).
	if err == nil {
		t.Fatalf("expected non-nil error under Strict on patchCheckpointImages failure, got nil (resp=%v)", resp)
	}
	if !strings.Contains(err.Error(), "restore aborted (strict)") {
		t.Errorf("error message does not contain 'restore aborted (strict)': %q", err.Error())
	}
	// Underlying error must be wrapped.
	if !errors.Is(err, patchErr) {
		t.Errorf("expected patchErr to be wrapped in the returned error; errors.Is returned false")
	}
}

// TestRestoreSkipPatchFailure_BestEffort verifies A1 degrade path: when patchCheckpointImages
// fails and TCPPreservationMode is "BestEffort" (or ""), Restore must NOT abort on the patch
// failure — it must continue past the patch step (degrade-and-continue).
// We verify this by checking that the error returned is NOT the patch abort sentinel.
func TestRestoreSkipPatchFailure_BestEffort(t *testing.T) {
	for _, mode := range []string{"BestEffort", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			imagesDir := makeTempRestoreDir(t)

			patchErr := errors.New("PATCH_ERROR: unknown magic 0xdeadbeef")

			origFn := patchCheckpointImagesFn
			patchCheckpointImagesFn = func(_ string, _ []string, _ []string) error { return patchErr }
			t.Cleanup(func() { patchCheckpointImagesFn = origFn })

			s := New("test-node", &criu.StubCheckpointer{}, nil)
			ctx := context.Background()

			_, err := s.Restore(ctx, &agentpb.RestoreRequest{
				MigrationName:       "test-besteffort-degrade",
				CheckpointRef:       imagesDir,
				TcpPreservationMode: mode,
			})

			// BestEffort/None: patch failure must NOT cause the strict abort.
			// The restore will fail further down (no real CRIU binary), but the error
			// must not be the "restore aborted (strict)" sentinel.
			if err != nil && strings.Contains(err.Error(), "restore aborted (strict)") {
				t.Errorf("BestEffort/None patch failure must not trigger strict abort; got: %v", err)
			}
		})
	}
}
