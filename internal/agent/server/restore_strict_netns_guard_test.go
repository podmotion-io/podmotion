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

// restore_strict_netns_guard_test.go — D2-C1 contract tests for the mode-keyed destination
// netns-fd fail-closed guard on the gRPC Restore path (server.go).
//
// The guard requires that a Strict migration carry a non-empty DestNetnsFd (the pre-staged
// destination netns from the DestinationNetnsReady stage). The KEY of that requirement is the
// DECLARED preservation mode (mode==Strict), NOT whether any TCP connection happened to exist
// at the freeze instant (SeqSnapshots>0).
//
// TestStrictIdleWorkloadEmptyNetnsRefused is the "test that would have caught the bug": a
// legitimately-Strict but momentarily-idle workload transfers ZERO SeqSnapshots. Under the
// pre-change logic (`len(req.SeqSnapshots) > 0 && req.DestNetnsFd == ""`) the guard never
// fired for such a workload and Restore silently degraded to the None cold path — bricking
// the process tree. This test FAILS against that pre-change logic (Restore would proceed past
// the guard rather than refuse) and PASSES after keying the guard on mode==Strict.

import (
	"context"
	"strings"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// refusalSubstring is the stable marker the guard emits when it refuses the cold-path
// fallthrough under Strict with an empty DestNetnsFd.
const refusalSubstring = "refusing None cold path fallthrough"

// TestStrictIdleWorkloadEmptyNetnsRefused is the falsifiable contract test the panel demanded.
// Inputs model an idle-but-Strict workload: mode==Strict, ZERO SeqSnapshots, empty DestNetnsFd.
// Expected: Restore refuses (Success=false, ErrorMessage carries the refusal marker) BEFORE it
// can fall through to the cold path.
//
// Falsifiability: with the pre-change guard (`len(req.SeqSnapshots) > 0 && DestNetnsFd == ""`)
// this input has zero SeqSnapshots, so the guard is skipped, Restore does NOT emit the refusal
// marker, and this test FAILS. That is the bug this test is designed to catch.
func TestStrictIdleWorkloadEmptyNetnsRefused(t *testing.T) {
	imagesDir := makeTempRestoreDir(t)

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	resp, err := s.Restore(ctx, &agentpb.RestoreRequest{
		MigrationName:       "test-strict-idle-empty-netns",
		CheckpointRef:       imagesDir,
		TcpPreservationMode: "Strict",
		// SeqSnapshots deliberately empty: the workload was idle at the freeze instant.
		// DestNetnsFd deliberately empty: the DestinationNetnsReady stage failed to plumb it.
	})

	// The fail-closed guard returns a normal RestoreResponse (Success=false) with nil error,
	// mirroring the other early-refusal returns on this path.
	if err != nil {
		t.Fatalf("expected nil transport error from fail-closed refusal, got: %v (resp=%v)", err, resp)
	}
	if resp == nil {
		t.Fatalf("expected non-nil RestoreResponse from fail-closed refusal, got nil")
	}
	if resp.Success {
		t.Fatalf("Strict + empty DestNetnsFd must be REFUSED (Success=false); an idle-Strict workload silently fell through to the cold path")
	}
	if !strings.Contains(resp.ErrorMessage, refusalSubstring) {
		t.Fatalf("expected refusal marker %q in ErrorMessage; got: %q", refusalSubstring, resp.ErrorMessage)
	}
}

// TestNoneAndBestEffortEmptyNetnsNotGuarded confirms the guard does NOT fire for the declared
// cold-path modes: for mode==None and mode==BestEffort an empty DestNetnsFd is the explicitly
// declared cold-path value, not an inferred one. Restore must proceed PAST the guard (it will
// fail later for lack of a real CRIU binary, but it must NOT emit the Strict refusal marker).
func TestNoneAndBestEffortEmptyNetnsNotGuarded(t *testing.T) {
	for _, mode := range []string{"None", "BestEffort", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			imagesDir := makeTempRestoreDir(t)

			s := New("test-node", &criu.StubCheckpointer{}, nil)
			ctx := context.Background()

			resp, err := s.Restore(ctx, &agentpb.RestoreRequest{
				MigrationName:       "test-coldpath-empty-netns",
				CheckpointRef:       imagesDir,
				TcpPreservationMode: mode,
				// Empty DestNetnsFd is the declared cold-path value for these modes.
			})

			// Must NOT be the Strict netns refusal. (Some other downstream failure is fine —
			// there is no real CRIU binary in the sandbox.)
			if err != nil && strings.Contains(err.Error(), refusalSubstring) {
				t.Fatalf("mode=%q must not trigger the Strict netns refusal; got err: %v", mode, err)
			}
			if resp != nil && strings.Contains(resp.ErrorMessage, refusalSubstring) {
				t.Fatalf("mode=%q must not trigger the Strict netns refusal; got resp.ErrorMessage: %q", mode, resp.ErrorMessage)
			}
		})
	}
}

// TestStrictWithSnapshotsEmptyNetnsStillRefused confirms the original protected case still
// holds: Strict WITH SeqSnapshots and an empty DestNetnsFd is refused (no behavior regressed
// for the case the old guard already covered).
func TestStrictWithSnapshotsEmptyNetnsStillRefused(t *testing.T) {
	imagesDir := makeTempRestoreDir(t)

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	resp, err := s.Restore(ctx, &agentpb.RestoreRequest{
		MigrationName:       "test-strict-with-snaps-empty-netns",
		CheckpointRef:       imagesDir,
		TcpPreservationMode: "Strict",
		SeqSnapshots: []*agentpb.SeqSnapshot{
			{SrcIp: "10.0.0.1", SrcPort: 5432, DstIp: "10.0.0.2", DstPort: 40000},
		},
		// DestNetnsFd empty.
	})

	if err != nil {
		t.Fatalf("expected nil transport error from fail-closed refusal, got: %v (resp=%v)", err, resp)
	}
	if resp == nil || resp.Success {
		t.Fatalf("Strict + SeqSnapshots + empty DestNetnsFd must be REFUSED (Success=false); got resp=%v", resp)
	}
	if !strings.Contains(resp.ErrorMessage, refusalSubstring) {
		t.Fatalf("expected refusal marker %q in ErrorMessage; got: %q", refusalSubstring, resp.ErrorMessage)
	}
}
