/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// estimate_checkpoint_fail_closed_test.go — fail-closed phase-gate remediation (item 1a) unit coverage.
//
// EstimateCheckpoint previously returned a (fabricatedResponse, nil) pair on any PreDump
// error — indistinguishable at the type level from a genuine measurement. This exercises the
// real failure scenario (PreDump returning an error) and asserts the RPC now fails closed with
// a typed gRPC error instead.

import (
	"context"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestEstimateCheckpoint_FailsClosedOnPreDumpError(t *testing.T) {
	stub := &criu.StubCheckpointer{InjectPreDumpError: criu.ErrCRIUCapability}
	s := &AgentServer{checkpointer: stub}

	resp, err := s.EstimateCheckpoint(context.Background(), &agentpb.EstimateCheckpointRequest{
		PodName:      "test-pod",
		PodNamespace: "default",
	})
	if err == nil {
		t.Fatalf("expected EstimateCheckpoint to fail closed on PreDump error, got response: %+v", resp)
	}
	if resp != nil {
		t.Fatalf("expected a nil response alongside the error, got: %+v", resp)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected a gRPC status error, got: %v", err)
	}
	if st.Code() != codes.Unavailable {
		t.Errorf("expected codes.Unavailable, got %v", st.Code())
	}
}
