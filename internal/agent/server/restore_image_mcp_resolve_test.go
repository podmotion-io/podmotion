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

// restore_image_mcp_resolve_test.go — pinned regression for the restore-image
// resolution race on the agent-Restore-RPC fallback path.
//
// Root cause (postgres/redis restore frontier): on the gRPC Restore fallback path
// (invoked ~60s after the NRI confirm window times out), the PrepareDestinationNetns
// B2 cache was empty and the ADR-0217 D2 resolveImageFromReplacementPod returned "" —
// a timing race where Status.ReplacementPodName was not yet populated / the replacement
// pod was mid-teardown when the resolver ran. Restore then fail-closed with
// "restore image unresolved (ADR-0215) ... controller must plumb MCP.Spec.WorkloadImage",
// EVEN THOUGH MCP.Spec.WorkloadImage was already set authoritatively (ADR-0217 D1, in
// Validating).
//
// Fix: resolveImageFromMCP reads MCP.Spec.WorkloadImage directly (race-free: independent
// of Status.ReplacementPodName / a live replacement pod), preferred over the pod resolver.
//
// These tests pin: (1) the MCP resolver returns the authoritative image with NO replacement
// pod present (the observed race); (2) it returns "" gracefully when the MCP is absent or its
// WorkloadImage is empty (caller then falls through to the pod resolver, then fail-closes);
// (3) the MCP resolver tolerates the PodMigration CR living in a non-agent namespace.

import (
	"testing"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeAgentServerWithObjects(t *testing.T, objs ...client.Object) *AgentServer {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	builder := fake.NewClientBuilder().WithScheme(scheme)
	if len(objs) > 0 {
		builder = builder.WithObjects(objs...)
	}
	return New("test-node", &criu.StubCheckpointer{}, builder.Build())
}

// TestResolveImageFromMCP_AuthoritativeWithNoReplacementPod is the core regression: the
// authoritative MCP.Spec.WorkloadImage resolves EVEN when there is no replacement pod and
// Status.ReplacementPodName is empty — the exact race that broke postgres/redis restore.
func TestResolveImageFromMCP_AuthoritativeWithNoReplacementPod(t *testing.T) {
	const migName = "postgres-mig-1"
	const wantImage = "postgres:16-alpine"

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "podmotion-system"},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "postgres-0",
			PodNamespace: "default",
		},
		// Status.ReplacementPodName deliberately EMPTY — the racy pod resolver would return "".
	}
	mcp := &pmv1.MigrationCheckpoint{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "podmotion-system"},
		Spec: pmv1.MigrationCheckpointSpec{
			PodMigrationRef: migName,
			WorkloadImage:   wantImage,
		},
	}
	s := newFakeAgentServerWithObjects(t, pm, mcp)

	// The pod resolver must fail (no replacement pod / empty ReplacementPodName)...
	if got := s.resolveImageFromReplacementPod(migName); got != "" {
		t.Fatalf("resolveImageFromReplacementPod: expected \"\" (no replacement pod), got %q", got)
	}
	// ...but the authoritative MCP resolver must succeed.
	if got := s.resolveImageFromMCP(migName); got != wantImage {
		t.Fatalf("resolveImageFromMCP: got %q, want %q", got, wantImage)
	}
}

// TestResolveImageFromMCP_EmptyWhenMCPAbsent asserts graceful "" when no MCP exists — the
// caller then falls through to the pod resolver and finally fail-closes (ADR-0215), never
// substituting a guessed image.
func TestResolveImageFromMCP_EmptyWhenMCPAbsent(t *testing.T) {
	const migName = "redis-mig-2"
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "podmotion-system"},
		Spec:       pmv1.PodMigrationSpec{PodName: "redis-0", PodNamespace: "default"},
	}
	s := newFakeAgentServerWithObjects(t, pm) // no MCP
	if got := s.resolveImageFromMCP(migName); got != "" {
		t.Fatalf("resolveImageFromMCP: expected \"\" when MCP absent, got %q", got)
	}
}

// TestResolveImageFromMCP_EmptyWhenWorkloadImageUnset asserts "" when the MCP exists but its
// WorkloadImage is empty (D1 producer never ran) — again fall-through, never a guess.
func TestResolveImageFromMCP_EmptyWhenWorkloadImageUnset(t *testing.T) {
	const migName = "redis-mig-3"
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "podmotion-system"},
		Spec:       pmv1.PodMigrationSpec{PodName: "redis-0", PodNamespace: "default"},
	}
	mcp := &pmv1.MigrationCheckpoint{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "podmotion-system"},
		Spec:       pmv1.MigrationCheckpointSpec{PodMigrationRef: migName}, // WorkloadImage empty
	}
	s := newFakeAgentServerWithObjects(t, pm, mcp)
	if got := s.resolveImageFromMCP(migName); got != "" {
		t.Fatalf("resolveImageFromMCP: expected \"\" when WorkloadImage unset, got %q", got)
	}
}

// TestResolveImageFromMCP_ToleratesNonAgentNamespace asserts the CR-namespace resolution (via
// the shared lookupPodMigration List fallback) finds the MCP when the PodMigration CR lives in a
// workload namespace (e.g. "default"), not the agent's POD_NAMESPACE.
func TestResolveImageFromMCP_ToleratesNonAgentNamespace(t *testing.T) {
	const migName = "postgres-mig-4"
	const wantImage = "postgres:16-alpine"
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "postgres-0", PodNamespace: "default"},
	}
	mcp := &pmv1.MigrationCheckpoint{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "default"},
		Spec: pmv1.MigrationCheckpointSpec{
			PodMigrationRef: migName,
			WorkloadImage:   wantImage,
		},
	}
	s := newFakeAgentServerWithObjects(t, pm, mcp)
	if got := s.resolveImageFromMCP(migName); got != wantImage {
		t.Fatalf("resolveImageFromMCP (non-agent ns): got %q, want %q", got, wantImage)
	}
}

// TestResolveImageFromMCP_NilClient asserts the nil-guard (agent started without a k8s client).
func TestResolveImageFromMCP_NilClient(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	if got := s.resolveImageFromMCP("any-mig"); got != "" {
		t.Fatalf("resolveImageFromMCP with nil client: expected \"\", got %q", got)
	}
}
