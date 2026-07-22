/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// prepare_source_compatible_test.go — fail-closed phase-gate remediation (item 4) unit coverage.
//
// PrepareSource previously hardcoded Compatible=true regardless of the /proc cgroup scan
// result — even a confirmed-negative scan for a real supplied PodUid still reported
// compatible. This exercises the real fail-closed scenario: a PodUid that matches no live
// process on this machine must now report Compatible=false.

import (
	"context"
	"testing"

	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

func TestPrepareSource_IncompatibleWhenUIDNotFound(t *testing.T) {
	s := &AgentServer{migrationPodUID: make(map[string]string)}

	resp, err := s.PrepareSource(context.Background(), &agentpb.PrepareSourceRequest{
		PodName:       "does-not-exist-pod",
		PodNamespace:  "default",
		PodUid:        "00000000-0000-0000-0000-000000000000-does-not-exist",
		MigrationName: "test-migration",
	})
	if err != nil {
		t.Fatalf("PrepareSource: unexpected RPC error: %v", err)
	}
	if resp.Compatible {
		t.Fatalf("expected Compatible=false for a PodUid confirmed absent via /proc scan, got true (blocking reason: %q)", resp.BlockingReason)
	}
}

// TestPrepareSource_DevModeOptOut_NoUID confirms the explicit "caller didn't supply a UID"
// opt-out path remains Compatible=true — distinct from a supplied-but-not-found UID.
func TestPrepareSource_DevModeOptOut_NoUID(t *testing.T) {
	s := &AgentServer{migrationPodUID: make(map[string]string)}

	resp, err := s.PrepareSource(context.Background(), &agentpb.PrepareSourceRequest{
		PodName:       "some-pod",
		PodNamespace:  "default",
		MigrationName: "test-migration",
	})
	if err != nil {
		t.Fatalf("PrepareSource: unexpected RPC error: %v", err)
	}
	if !resp.Compatible {
		t.Fatalf("expected Compatible=true for the explicit no-UID dev-mode opt-out, got false")
	}
}
