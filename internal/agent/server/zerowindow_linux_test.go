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

//go:build linux

package server

// zerowindow_linux_test.go — regression tests for ADR-0049 Amendment D fail-closed contract.
//
// Properties verified:
//   A2: armZeroWindowBPF returns a typed error on ArmZeroWindowHold failure under Strict.
//   C3: armZeroWindowBPF returns a typed error on ifindex==0 under Strict.
//   BE: armZeroWindowBPF returns nil (degrade) on the same failures under BestEffort/None.
//   RM: resolveVethIfindex returns a TYPED ERROR on a read-mechanism failure (no host PID
//       sharing the pod netns), so the Strict caller reports an accurate resolution failure
//       instead of the false terminal "non-veth CNI" verdict — while the empty/cold-path input
//       still returns (0, nil) without error.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/network"
)

// mockEBPFManager is a minimal network.EBPFManager that returns a pre-configured error
// from ArmZeroWindowHold. All other methods are no-op stubs that return nil.
type mockEBPFManager struct {
	armErr error
}

func (m *mockEBPFManager) EnsureXDPBridgeLoaded(_ context.Context, _ string, _ bool) error {
	return nil
}
func (m *mockEBPFManager) ArmZeroWindowHold(_ context.Context, _ uint32) error {
	return m.armErr
}
func (m *mockEBPFManager) DisarmZeroWindowHold(_ context.Context, _ uint32) error { return nil }
func (m *mockEBPFManager) ArmXDPBridge(_ context.Context, _, _ net.IP, _ uint16) error {
	return nil
}
func (m *mockEBPFManager) DisarmXDPBridge(_ context.Context, _ net.IP) error { return nil }
func (m *mockEBPFManager) CheckXDPHookConflict(_ context.Context, _ uint32) (bool, error) {
	return false, nil
}
func (m *mockEBPFManager) ArmRelay(_ context.Context, _ string, _ network.SeqXlatKey, _ network.SeqXlatEntry) error {
	return nil
}
func (m *mockEBPFManager) DisarmRelay(_ context.Context, _ network.SeqXlatKey) error { return nil }
func (m *mockEBPFManager) ArmVTEP(_ context.Context, _ net.IP, _ network.VtepEntry, _, _ string) error {
	return nil
}
func (m *mockEBPFManager) DisarmVTEP(_ context.Context, _ net.IP) error { return nil }
func (m *mockEBPFManager) PatchRelayTsDelta(_ context.Context, _ network.SeqXlatKey, _ int32) error {
	return nil
}

// Ensure mockEBPFManager satisfies the interface at compile time.
var _ network.EBPFManager = (*mockEBPFManager)(nil)

// TestArmZeroWindowBPF_StrictFailsClosedOnArmFailure verifies A2:
// when ArmZeroWindowHold returns an error under Strict, armZeroWindowBPF returns a non-nil
// typed error containing "zero-window arm failed under Strict".
func TestArmZeroWindowBPF_StrictFailsClosedOnArmFailure(t *testing.T) {
	mock := &mockEBPFManager{armErr: errors.New("bpf object: no symbol section")}
	err := armZeroWindowBPF(context.Background(), 42, "Strict", mock)
	if err == nil {
		t.Fatal("expected error under Strict on ArmZeroWindowHold failure, got nil")
	}
	if !strings.Contains(err.Error(), "zero-window arm failed under Strict") {
		t.Errorf("error message does not contain expected prefix: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "ArmZeroWindowHold") {
		t.Errorf("error message does not mention ArmZeroWindowHold: %q", err.Error())
	}
	// Verify the underlying error is wrapped.
	if !errors.Is(err, mock.armErr) {
		t.Errorf("expected underlying error to be wrapped via %%w; errors.Is returned false")
	}
}

// TestArmZeroWindowBPF_StrictFailsClosedOnIfindexZero verifies C3:
// when ifindex==0 (veth unresolved / non-veth CNI) under Strict, armZeroWindowBPF returns
// a non-nil error containing "CNI unsupported for zero-window hold".
func TestArmZeroWindowBPF_StrictFailsClosedOnIfindexZero(t *testing.T) {
	// No mock needed — ifindex==0 is handled before the EBPFManager is consulted.
	err := armZeroWindowBPF(context.Background(), 0, "Strict")
	if err == nil {
		t.Fatal("expected error under Strict when ifindex==0, got nil")
	}
	if !strings.Contains(err.Error(), "zero-window arm failed under Strict") {
		t.Errorf("error message does not contain expected prefix: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "CNI unsupported for zero-window hold") {
		t.Errorf("error message does not surface CR-status reason: %q", err.Error())
	}
}

// TestArmZeroWindowBPF_BestEffortDegradesContinues verifies the BestEffort/None contract:
// the same failures (ArmZeroWindowHold error and ifindex==0) MUST return nil so the migration
// degrades without hard failure.
func TestArmZeroWindowBPF_BestEffortDegradesContinues(t *testing.T) {
	for _, mode := range []string{"BestEffort", "None", ""} {
		t.Run("mode="+mode+"_ArmFailure", func(t *testing.T) {
			mock := &mockEBPFManager{armErr: errors.New("bpf object: no symbol section")}
			err := armZeroWindowBPF(context.Background(), 42, mode, mock)
			if err != nil {
				t.Errorf("expected nil (degrade) under %q on ArmZeroWindowHold failure, got: %v", mode, err)
			}
		})
		t.Run("mode="+mode+"_IfindexZero", func(t *testing.T) {
			err := armZeroWindowBPF(context.Background(), 0, mode)
			if err != nil {
				t.Errorf("expected nil (degrade) under %q when ifindex==0, got: %v", mode, err)
			}
		})
	}
}

// TestResolveVethIfindex_ReadMechanismFailureReturnsTypedError verifies RM:
// a pod UID with no matching host process (no sandbox/container PID sharing its netns) is a
// READ-MECHANISM failure, not an authoritative "no veth peer". resolveVethIfindex must return
// a non-nil typed error (ifindex 0) so the Strict ArmZeroWindow caller fails closed with an
// accurate reason rather than the false "ifindex=0 (non-veth CNI)" verdict. This pins the
// distinction against a regression back to the previous swallow-to-(0, nil) behavior, which
// mislabeled a veth-substrate resolution failure as a terminal CNI capability gap.
func TestResolveVethIfindex_ReadMechanismFailureReturnsTypedError(t *testing.T) {
	// A UID that cannot appear in any /proc/<pid>/cgroup on the test host, so both
	// FindSandboxPID and FindContainerPID fail and the netns cannot be entered at all.
	idx, err := resolveVethIfindex("pm-nonexistent-pod-uid-zzzz-0000000000000000")
	if err == nil {
		t.Fatal("expected a non-nil typed error on a read-mechanism failure (unresolvable pod netns PID); got nil — this is the swallow-to-(0,nil) regression that mislabels the failure as a non-veth CNI")
	}
	if idx != 0 {
		t.Errorf("expected ifindex 0 alongside the error, got %d", idx)
	}
	if !strings.Contains(err.Error(), "veth ifindex unresolvable") {
		t.Errorf("error should identify the read-mechanism failure class, got: %q", err.Error())
	}
}

// TestResolveVethIfindex_EmptyPodUIDNoError verifies the stub/cold path is preserved: an empty
// pod UID returns (0, nil) without error — it must NOT be reclassified as a read-mechanism
// failure (the None/BestEffort cold path relies on the (0, nil) degrade).
func TestResolveVethIfindex_EmptyPodUIDNoError(t *testing.T) {
	idx, err := resolveVethIfindex("")
	if err != nil {
		t.Errorf("expected (0, nil) for empty podUID (cold path), got err: %v", err)
	}
	if idx != 0 {
		t.Errorf("expected ifindex 0 for empty podUID, got %d", idx)
	}
}
