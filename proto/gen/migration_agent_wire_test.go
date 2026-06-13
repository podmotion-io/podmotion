// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package agentpb wire round-trip tests.
//
// These tests guard against the hand-patch class of failure: a developer adds
// a Go struct field to a generated .pb.go but forgets to regenerate the binary
// rawDesc descriptor, causing proto.Marshal to silently drop the field on the
// wire (it is absent from the descriptor so the runtime does not encode it).
//
// Run with: go test ./proto/gen/...
package agentpb_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// TestCheckpointResponseSeqSnapshotsWireRoundTrip verifies that SeqSnapshots
// (field 4 of CheckpointResponse) survives a proto.Marshal/proto.Unmarshal
// round-trip. If the rawDesc descriptor does not contain field 4 this test
// produces wire len=0 and unmarshal yields len(SeqSnapshots)==0, catching the
// hand-patch bug before it silently corrupts TCP continuity in production.
func TestCheckpointResponseSeqSnapshotsWireRoundTrip(t *testing.T) {
	orig := &agentpb.CheckpointResponse{
		FreezeDurationMs:    42,
		CheckpointSha256:    "abc123",
		CheckpointSizeBytes: 1024,
		SeqSnapshots: []*agentpb.SeqSnapshot{
			{
				SrcIp:    "10.0.0.1",
				SrcPort:  12345,
				DstIp:    "10.0.0.2",
				DstPort:  80,
				SndNxt:   0x0000FFFF, // deliberately near 16-bit boundary to test checksum carry
				RcvNxt:   0x00010001,
				TsRecent: 999,
			},
		},
	}

	wire, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("proto.Marshal failed: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("proto.Marshal produced 0 bytes — rawDesc descriptor is missing SeqSnapshots field; run 'protoc + make generate' on Linux to regenerate pb.go")
	}

	got := &agentpb.CheckpointResponse{}
	if err := proto.Unmarshal(wire, got); err != nil {
		t.Fatalf("proto.Unmarshal failed: %v", err)
	}
	if len(got.SeqSnapshots) != 1 {
		t.Fatalf("SeqSnapshots not preserved across wire: want 1 snapshot, got %d — descriptor mismatch", len(got.SeqSnapshots))
	}
	snap := got.SeqSnapshots[0]
	if snap.SrcIp != "10.0.0.1" || snap.SrcPort != 12345 || snap.SndNxt != 0x0000FFFF {
		t.Errorf("SeqSnapshot fields corrupted: got %+v", snap)
	}
}

// TestRestoreRequestSeqSnapshotsWireRoundTrip verifies that SeqSnapshots
// (field 7) and RelayIfname (field 8) of RestoreRequest survive the wire.
func TestRestoreRequestSeqSnapshotsWireRoundTrip(t *testing.T) {
	orig := &agentpb.RestoreRequest{
		MigrationName:           "test-migration",
		CheckpointRef:           "/run/podmotion/checkpoints/test/final",
		SourceNodeAddr:          "10.1.0.1:7777",
		DestNetnsFd:             "/proc/1234/fd/5",
		SourceFreezeTimestampNs: 1_000_000_000,
		RelayIfname:             "flannel.1",
		SeqSnapshots: []*agentpb.SeqSnapshot{
			{SrcIp: "192.168.1.1", SrcPort: 54321, DstIp: "192.168.1.2", DstPort: 443, SndNxt: 100, RcvNxt: 200},
			{SrcIp: "192.168.1.1", SrcPort: 54322, DstIp: "192.168.1.3", DstPort: 5432, SndNxt: 300, RcvNxt: 400},
		},
	}

	wire, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("proto.Marshal failed: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("proto.Marshal produced 0 bytes — rawDesc descriptor is missing RestoreRequest fields")
	}

	got := &agentpb.RestoreRequest{}
	if err := proto.Unmarshal(wire, got); err != nil {
		t.Fatalf("proto.Unmarshal failed: %v", err)
	}
	if len(got.SeqSnapshots) != 2 {
		t.Fatalf("SeqSnapshots not preserved: want 2, got %d", len(got.SeqSnapshots))
	}
	if got.RelayIfname != "flannel.1" {
		t.Errorf("RelayIfname not preserved: want flannel.1, got %q", got.RelayIfname)
	}
	if got.SeqSnapshots[0].SrcPort != 54321 || got.SeqSnapshots[1].DstPort != 5432 {
		t.Errorf("SeqSnapshot fields corrupted: %+v", got.SeqSnapshots)
	}
}

// TestVerifyTCPRequestWireRoundTrip verifies VerifyTCPRequest source_seq_snapshots (field 3).
func TestVerifyTCPRequestWireRoundTrip(t *testing.T) {
	orig := &agentpb.VerifyTCPRequest{
		MigrationName: "test-migration",
		PodUid:        "abc-123",
		SourceSeqSnapshots: []*agentpb.SeqSnapshot{
			{SrcIp: "10.0.0.1", SrcPort: 8080, DstIp: "10.0.0.2", DstPort: 9090, SndNxt: 777, RcvNxt: 888},
		},
		AppProbeProtocol: "TCP",
	}

	wire, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("proto.Marshal failed: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("proto.Marshal produced 0 bytes")
	}

	got := &agentpb.VerifyTCPRequest{}
	if err := proto.Unmarshal(wire, got); err != nil {
		t.Fatalf("proto.Unmarshal failed: %v", err)
	}
	if len(got.SourceSeqSnapshots) != 1 {
		t.Fatalf("SourceSeqSnapshots not preserved: want 1, got %d", len(got.SourceSeqSnapshots))
	}
	if got.AppProbeProtocol != "TCP" {
		t.Errorf("AppProbeProtocol not preserved: got %q", got.AppProbeProtocol)
	}
}

// TestConfirmOverlayReadyWireRoundTrip verifies ConfirmOverlayReadyRequest/Response.
func TestConfirmOverlayReadyWireRoundTrip(t *testing.T) {
	reqOrig := &agentpb.ConfirmOverlayReadyRequest{
		MigrationName:         "test-migration",
		SeqXlatSeeded:         true,
		FdbIfname:             "flannel.1",
		PodIp:                 "10.0.1.5",
		PodMac:                "aa:bb:cc:dd:ee:ff",
		VtepIp:                "10.0.1.100",
		SourceConntrackArmed:  true,
		RestoreComplete:       true,
		SourceClockNs:         1_234_567_890,
	}
	wire, err := proto.Marshal(reqOrig)
	if err != nil {
		t.Fatalf("proto.Marshal ConfirmOverlayReadyRequest failed: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("proto.Marshal ConfirmOverlayReadyRequest produced 0 bytes")
	}
	reqGot := &agentpb.ConfirmOverlayReadyRequest{}
	if err := proto.Unmarshal(wire, reqGot); err != nil {
		t.Fatalf("proto.Unmarshal ConfirmOverlayReadyRequest failed: %v", err)
	}
	if !reqGot.SeqXlatSeeded || !reqGot.RestoreComplete || reqGot.FdbIfname != "flannel.1" {
		t.Errorf("ConfirmOverlayReadyRequest fields corrupted: %+v", reqGot)
	}

	respOrig := &agentpb.ConfirmOverlayReadyResponse{
		Ready:          true,
		PredicateBOk:   true,
		PredicateCOk:   true,
		PredicateDOk:   true,
		PredicateEOk:   true,
		PredicateFOk:   true,
		TsDelta:        42,
		DestClockNs:    9_876_543_210,
	}
	wire, err = proto.Marshal(respOrig)
	if err != nil {
		t.Fatalf("proto.Marshal ConfirmOverlayReadyResponse failed: %v", err)
	}
	respGot := &agentpb.ConfirmOverlayReadyResponse{}
	if err := proto.Unmarshal(wire, respGot); err != nil {
		t.Fatalf("proto.Unmarshal ConfirmOverlayReadyResponse failed: %v", err)
	}
	if respGot.TsDelta != 42 || !respGot.Ready || respGot.DestClockNs != 9_876_543_210 {
		t.Errorf("ConfirmOverlayReadyResponse fields corrupted: %+v", respGot)
	}
}
