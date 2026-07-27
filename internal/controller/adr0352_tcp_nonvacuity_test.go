/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0352_tcp_nonvacuity_test.go — ADR-0352 B8-DR-2 / D6(i) / DR-23 NON-VACUITY regression,
// updated per ADR-0388 (docs/adr/0388-strict-vacuous-pass-and-default.md), which corrects
// ADR-0352 B8-DR-2.
//
// The sprint46B8 live-proof reached phase=Complete and certified
// TCPSequenceContinuityVerified=True over "0/0 connections" (ConnectionsExpected=0). Prior to
// ADR-0388 this was declared a VACUOUS proof / hard FAIL under Strict. Chad's standing direction
// (2026-07-23) corrected that premise: a genuine, positively-observed zero means there was nothing
// to preserve, so Strict is TRIVIALLY SATISFIED, not unprovable — a 0/0 completion is now an
// intended PASS, not a defect. What remains vacuous (still fails closed) is the NEGATIVE
// missing-snapshot sentinel (ConnectionsExpected<0): source SeqSnapshots absent while the
// destination reports live ESTABLISHED connections is an infra/proto problem, not a confirmed
// zero, and absence of evidence is still not proof of continuity (ADR-0049).
// strictTCPContinuityVacuityReason now reads the agent's source-of-truth held-connection count
// (ConnectionsExpected) directly and fails CLOSED under Strict only for that negative-sentinel
// case. This test pins that predicate so a future regression that re-admits the sentinel as a
// pass, or that re-fails a genuine zero, goes red here, not silently wrong live.

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
			// ADR-0388: the exact live-proof case — Strict, VerifyTCP Verified=true, a genuine
			// 0/0 — is now TRIVIALLY SATISFIED (not vacuous). Nothing was held, nothing needed
			// to be preserved.
			name:        "Strict_zero_connections_is_not_vacuous",
			mode:        pmv1.TCPPreservationModeStrict,
			resp:        &agentpb.VerifyTCPResponse{Verified: true, ConnectionsVerified: 0, ConnectionsExpected: 0},
			wantVacuous: false,
		},
		{
			// A real held connection: non-vacuous, must be allowed to certify.
			name:        "Strict_one_held_connection_is_not_vacuous",
			mode:        pmv1.TCPPreservationModeStrict,
			resp:        &agentpb.VerifyTCPResponse{Verified: true, ConnectionsVerified: 1, ConnectionsExpected: 1},
			wantVacuous: false,
		},
		{
			// server.go negative sentinel (snapshots missing, NOT a genuine zero) — this is an
			// infra/proto problem, still fails closed under Strict even after ADR-0388.
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
			if tc.wantVacuous && !strings.Contains(got, "missing-snapshot sentinel") {
				t.Fatalf("vacuity reason must name the missing-snapshot sentinel for operator triage, got %q", got)
			}
		})
	}
}
