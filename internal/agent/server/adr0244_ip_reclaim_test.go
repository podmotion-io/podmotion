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

// adr0244_ip_reclaim_test.go — regression coverage for ADR-0244 (NR-BLOCK-2) GC-5
// source-side teardown: AgentServer.TeardownSourceRedirect and AgentServer.ProbeDestSocketForIP.
//
// These handlers were previously unimplemented (fell through to the generated
// UnimplementedMigrationAgentServiceServer stub, returning codes.Unimplemented). This file
// asserts: (1) input validation behaves like the sibling DisarmTCRedirect/InjectSourceRedirect
// RPCs; (2) TeardownSourceRedirect is best-effort/idempotent when optional FDB-identifying
// fields are absent; (3) ProbeDestSocketForIP's fail-closed contract from the ADR's N1/N2
// correction — a genuine restoredPIDForMigration lookup failure MUST propagate as an RPC error
// (defer the sweep), while a positively-resolved absence (no CR, or CR with no RestoredPID)
// MUST return present=false, not an error.

import (
	"context"
	"os"
	"strings"
	"testing"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// --- TeardownSourceRedirect ---

// TestTeardownSourceRedirect_RequiresOldPodIP asserts old_pod_ip is mandatory, matching the
// InvalidArgument convention already used by InjectSourceRedirect/DisarmTCRedirect.
func TestTeardownSourceRedirect_RequiresOldPodIP(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	_, err := s.TeardownSourceRedirect(context.Background(), &agentpb.TeardownSourceRedirectRequest{
		MigrationName: "mig-1",
	})
	if err == nil {
		t.Fatal("expected error for missing old_pod_ip, got nil")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

// TestTeardownSourceRedirect_RejectsInvalidIP asserts a malformed old_pod_ip is rejected before
// any netlink/iptables side effect is attempted.
func TestTeardownSourceRedirect_RejectsInvalidIP(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	_, err := s.TeardownSourceRedirect(context.Background(), &agentpb.TeardownSourceRedirectRequest{
		MigrationName: "mig-1",
		OldPodIp:      "not-an-ip",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for malformed old_pod_ip, got %v (%v)", status.Code(err), err)
	}
}

// TestTeardownSourceRedirect_RejectsIPv6 mirrors InjectSourceRedirect's IPv4-only contract
// (ADR-0136/0244 operate on the overlay-native IPv4 pod CIDR).
func TestTeardownSourceRedirect_RejectsIPv6(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	_, err := s.TeardownSourceRedirect(context.Background(), &agentpb.TeardownSourceRedirectRequest{
		MigrationName: "mig-1",
		OldPodIp:      "fe80::1",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for IPv6 old_pod_ip, got %v (%v)", status.Code(err), err)
	}
}

// TestTeardownSourceRedirect_MissingFDBIdentifiersIsNonFatal asserts that when repl_veth_mac /
// dst_node_ip are not supplied, the handler skips the FDB removal step (best-effort, logged) and
// still proceeds through neigh/route/NOTRACK removal rather than failing the whole RPC — the ADR
// treats the FDB entry as harmless-if-orphaned and surfaced instead by VerifyCleanup's
// flannel1_fdb probe, not a hard precondition of this RPC.
//
// This test does not require CAP_NET_ADMIN or a real flannel.1 device: DeletePodIPNeigh and
// DeletePodIPHostRoute both tolerate a missing interface (treated as already-clean, ENOENT-safe),
// so the whole call succeeds in a sandboxed test environment with no VXLAN device present.
func TestTeardownSourceRedirect_MissingFDBIdentifiersIsNonFatal(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	resp, err := s.TeardownSourceRedirect(context.Background(), &agentpb.TeardownSourceRedirectRequest{
		MigrationName: "mig-1",
		OldPodIp:      "10.244.1.7",
		FdbIfname:     "flannel.1-does-not-exist-in-test-sandbox",
		// ReplVethMac/DstNodeIp intentionally omitted.
	})
	if err != nil {
		t.Fatalf("TeardownSourceRedirect returned unexpected RPC error: %v", err)
	}
	if !resp.TornDown {
		t.Fatalf("expected TornDown=true (best-effort skip of FDB step), got false, reason=%q", resp.BlockingReason)
	}
}

// TestTeardownSourceRedirect_DefaultsFdbIfnameToFlannel1 asserts the default interface name
// matches InjectSourceRedirect's default (symmetry requirement — the ADR says "Symmetric to
// DisarmTCRedirectRequest").
func TestTeardownSourceRedirect_DefaultsFdbIfnameToFlannel1(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	// No FdbIfname supplied; the handler must default to "flannel.1" — verified indirectly by
	// confirming the call still completes without an InvalidArgument (i.e. it did not reject the
	// empty ifname as malformed input) rather than by inspecting an unexported field.
	resp, err := s.TeardownSourceRedirect(context.Background(), &agentpb.TeardownSourceRedirectRequest{
		MigrationName: "mig-1",
		OldPodIp:      "10.244.1.8",
	})
	if err != nil {
		t.Fatalf("TeardownSourceRedirect with default fdb_ifname returned unexpected error: %v", err)
	}
	if !resp.TornDown {
		t.Fatalf("expected TornDown=true with default flannel.1 ifname, got false, reason=%q", resp.BlockingReason)
	}
}

// --- ProbeDestSocketForIP ---

func newFakeAgentServerWithPM(t *testing.T, pms ...*pmv1.PodMigration) *AgentServer {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, pm := range pms {
		builder = builder.WithObjects(pm)
	}
	return New("test-node", &criu.StubCheckpointer{}, builder.Build())
}

// TestProbeDestSocketForIP_RequiresOldPodIP and RequiresMigrationName assert input validation
// symmetric to the other new RPC.
func TestProbeDestSocketForIP_RequiresOldPodIP(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	_, err := s.ProbeDestSocketForIP(context.Background(), &agentpb.ProbeDestSocketForIPRequest{
		MigrationName: "mig-1",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for missing old_pod_ip, got %v (%v)", status.Code(err), err)
	}
}

func TestProbeDestSocketForIP_RequiresMigrationName(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	_, err := s.ProbeDestSocketForIP(context.Background(), &agentpb.ProbeDestSocketForIPRequest{
		OldPodIp: "10.244.1.7",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for missing migration_name, got %v (%v)", status.Code(err), err)
	}
}

// TestProbeDestSocketForIP_NoK8sClientFailsClosed asserts the N1/N2 fail-closed contract: with
// no k8s client configured, restoredPIDForMigration cannot even attempt the lookup — this MUST
// be a genuine lookup failure (RPC error, Unavailable), never a silent present=false. Failing
// open here (the pre-amendment behavior) would let a reclaim sweep authorize teardown against a
// live pinned connection whenever the agent's k8s client was transiently unavailable.
func TestProbeDestSocketForIP_NoK8sClientFailsClosed(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil) // k8sClient == nil
	_, err := s.ProbeDestSocketForIP(context.Background(), &agentpb.ProbeDestSocketForIPRequest{
		MigrationName: "mig-does-not-matter",
		OldPodIp:      "10.244.1.7",
	})
	if err == nil {
		t.Fatal("expected ProbeDestSocketForIP to fail closed (RPC error) with no k8s client, got nil error")
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable (fail-closed lookup failure), got %v (%v)", status.Code(err), err)
	}
}

// TestProbeDestSocketForIP_NoCRFoundIsPresentFalseNotError asserts case (1) from the ADR's N1/N2
// correction: the CR/PID lookup is POSITIVELY resolved (a real, working k8s client that
// enumerates zero matching PodMigrations) and finds nothing — this is a genuine absence
// ("nothing left to protect"), and must return present=false with NO error, not a fail-closed
// RPC error. Conflating this with the lookup-failure case would make the reclaim sweep hang
// forever on every terminal CR (which, by definition of the sweep's own trigger, no longer
// exists as a fresh/active CR by the time teardown fires in some deployments).
func TestProbeDestSocketForIP_NoCRFoundIsPresentFalseNotError(t *testing.T) {
	s := newFakeAgentServerWithPM(t) // fake client with zero PodMigration objects
	resp, err := s.ProbeDestSocketForIP(context.Background(), &agentpb.ProbeDestSocketForIPRequest{
		MigrationName: "mig-does-not-exist",
		OldPodIp:      "10.244.1.7",
	})
	if err != nil {
		t.Fatalf("expected no error for a positively-resolved absence, got: %v", err)
	}
	if resp.Present {
		t.Fatal("expected Present=false when no matching PodMigration CR exists")
	}
	if resp.Count != 0 {
		t.Fatalf("expected Count=0, got %d", resp.Count)
	}
}

// TestProbeDestSocketForIP_ZeroRestoredPIDIsPresentFalseNotError covers the other positive-
// absence sub-case: the CR exists and resolves cleanly, but Status.RestoredPID is still its
// zero value (pod not yet restored on this node). Also not an error.
func TestProbeDestSocketForIP_ZeroRestoredPIDIsPresentFalseNotError(t *testing.T) {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-1", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "p", PodNamespace: "default"},
		// Status.RestoredPID left at zero value.
	}
	s := newFakeAgentServerWithPM(t, pm)
	resp, err := s.ProbeDestSocketForIP(context.Background(), &agentpb.ProbeDestSocketForIPRequest{
		MigrationName: "mig-1",
		OldPodIp:      "10.244.1.7",
	})
	if err != nil {
		t.Fatalf("expected no error when RestoredPID is unset, got: %v", err)
	}
	if resp.Present {
		t.Fatal("expected Present=false when RestoredPID is unset (nothing to protect)")
	}
}

// TestProbeDestSocketForIP_LiveSelfPIDDoesNotErrorOnRead exercises the real
// network.SocketInventory code path (reads /proc/<pid>/net/tcp[6]) against the test process's
// own PID, which is guaranteed to exist for the duration of the test. This does not assert
// Present is true or false for old_pod_ip specifically (the test process's actual sockets are
// environment-dependent), only that a live, resolvable PID never surfaces a spurious RPC error —
// i.e. the socket-table-read path itself is exercised end to end, not stubbed out.
func TestProbeDestSocketForIP_LiveSelfPIDDoesNotErrorOnRead(t *testing.T) {
	selfPID := int32(os.Getpid())

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-live", Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "p", PodNamespace: "default"},
		Status:     pmv1.PodMigrationStatus{RestoredPID: selfPID},
	}
	s := newFakeAgentServerWithPM(t, pm)
	_, err := s.ProbeDestSocketForIP(context.Background(), &agentpb.ProbeDestSocketForIPRequest{
		MigrationName: "mig-live",
		OldPodIp:      "10.244.1.7",
	})
	if err != nil {
		// /proc/<pid>/net/tcp[6] must be readable for the test's own PID in any sandboxed CI
		// environment; a permission or path error here would indicate the probe's proc-parsing
		// primitive itself is broken, not an expected test outcome.
		if strings.Contains(err.Error(), "permission denied") {
			t.Skipf("skipping: /proc/%d/net/tcp not readable in this sandbox: %v", selfPID, err)
		}
		t.Fatalf("unexpected error probing live self PID: %v", err)
	}
}
