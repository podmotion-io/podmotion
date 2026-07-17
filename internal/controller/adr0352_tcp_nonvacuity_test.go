/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0352_tcp_nonvacuity_test.go — ADR-0352 B8-DR-2 / D6(i) / DR-23 NON-VACUITY regression.
//
// The sprint46B8 live-proof reached phase=Complete but certified
// TCPSequenceContinuityVerified=True over "0/0 connections" (ConnectionsExpected=0): a VACUOUS
// pass the ADR declares a hard FAIL, because seq_delta==0 is trivially true over zero connections
// and TCPSequenceContinuityVerified is a REQUIRED Strict source-teardown predicate
// (api/v1alpha1/source_teardown.go:80-84) — so a 0/0 pass authorises deleting the source on a
// proof of nothing (invariant #1). reconcileTCPVerifying now gates the final True-write on
// strictTCPContinuityVacuityReason, which reads the agent's source-of-truth held-connection count
// (ConnectionsExpected) directly and fails CLOSED under Strict. This test pins that predicate so a
// future regression that re-admits the 0/0 vacuity goes red here, not silently green live.

import (
	"strings"
	"testing"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

func TestStrictTCPContinuityVacuityReason(t *testing.T) {
	tests := []struct {
		name        string
		mode        pmv1.TCPPreservationMode
		resp        *agentpb.VerifyTCPResponse
		wantVacuous bool
	}{
		{
			// The exact live-proof case: Strict, VerifyTCP Verified=true, 0/0 connections.
			name:        "Strict_zero_connections_is_vacuous",
			mode:        pmv1.TCPPreservationModeStrict,
			resp:        &agentpb.VerifyTCPResponse{Verified: true, ConnectionsVerified: 0, ConnectionsExpected: 0},
			wantVacuous: true,
		},
		{
			// A real held connection: non-vacuous, must be allowed to certify.
			name:        "Strict_one_held_connection_is_not_vacuous",
			mode:        pmv1.TCPPreservationModeStrict,
			resp:        &agentpb.VerifyTCPResponse{Verified: true, ConnectionsVerified: 1, ConnectionsExpected: 1},
			wantVacuous: false,
		},
		{
			// server.go:7599 sentinel (snapshots missing) — fail closed under Strict too.
			name:        "Strict_negative_sentinel_is_vacuous",
			mode:        pmv1.TCPPreservationModeStrict,
			resp:        &agentpb.VerifyTCPResponse{Verified: false, ConnectionsVerified: 0, ConnectionsExpected: -1},
			wantVacuous: true,
		},
		{
			// BestEffort legitimately preserves nothing — never vacuous here.
			name:        "BestEffort_zero_connections_is_not_vacuous",
			mode:        pmv1.TCPPreservationModeBestEffort,
			resp:        &agentpb.VerifyTCPResponse{Verified: true, ConnectionsExpected: 0},
			wantVacuous: false,
		},
		{
			// None never runs the full producer at all — never vacuous here.
			name:        "None_zero_connections_is_not_vacuous",
			mode:        pmv1.TCPPreservationModeNone,
			resp:        &agentpb.VerifyTCPResponse{Verified: true, ConnectionsExpected: 0},
			wantVacuous: false,
		},
		{
			// Strict with a real held count > 1 stays non-vacuous.
			name:        "Strict_many_held_connections_is_not_vacuous",
			mode:        pmv1.TCPPreservationModeStrict,
			resp:        &agentpb.VerifyTCPResponse{Verified: true, ConnectionsVerified: 7, ConnectionsExpected: 7},
			wantVacuous: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := strictTCPContinuityVacuityReason(tc.mode, tc.resp)
			if tc.wantVacuous && got == "" {
				t.Fatalf("expected VACUOUS (non-empty block reason) for mode=%s ConnectionsExpected=%d, got empty (would falsely certify TCPSequenceContinuityVerified over a 0/0 proof)",
					tc.mode, tc.resp.GetConnectionsExpected())
			}
			if !tc.wantVacuous && got != "" {
				t.Fatalf("expected NON-vacuous (empty block reason) for mode=%s ConnectionsExpected=%d, got %q (would wrongly roll back a valid migration)",
					tc.mode, tc.resp.GetConnectionsExpected(), got)
			}
			if tc.wantVacuous && !strings.Contains(got, "vacuous 0/0 proof") {
				t.Fatalf("vacuity reason must name the 0/0 proof for operator triage, got %q", got)
			}
		})
	}
}
