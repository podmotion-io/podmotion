/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

import (
	"context"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

func TestCephRBDStubMigrator_ProgressEmission(t *testing.T) {
	stub := &storage.CephRBDStubMigrator{}

	// Before PreStage, SyncPercent should return 0.
	pct, err := stub.SyncPercent(context.Background(), storage.MigrationOptions{})
	if err != nil {
		t.Fatalf("SyncPercent before PreStage: unexpected error: %v", err)
	}
	if pct != 0 {
		t.Errorf("expected 0%% before PreStage, got %d%%", pct)
	}

	opts := storage.MigrationOptions{
		MigrationName:   "test-migration",
		PodNamespace:    "default",
		SourceNode:      "node-a",
		DestinationNode: "node-b",
		Classifications: []storage.TierClassification{
			{
				Tier:    storage.TierCephRBD,
				PVCName: "test-pvc",
			},
		},
	}

	if err := stub.PreStage(context.Background(), opts); err != nil {
		t.Fatalf("PreStage: unexpected error: %v", err)
	}

	if !stub.PreStageCalled {
		t.Error("expected PreStageCalled=true after PreStage")
	}

	// After PreStage completes the stub should report 100%.
	pct, err = stub.SyncPercent(context.Background(), opts)
	if err != nil {
		t.Fatalf("SyncPercent after PreStage: unexpected error: %v", err)
	}
	if pct != 100 {
		t.Errorf("expected 100%% after PreStage, got %d%%", pct)
	}

	// Verify Cutover records the call.
	if err := stub.Cutover(context.Background(), opts); err != nil {
		t.Fatalf("Cutover: unexpected error: %v", err)
	}
	if !stub.CutoverCalled {
		t.Error("expected CutoverCalled=true after Cutover")
	}
}

func TestCephRBDStubMigrator_InjectError(t *testing.T) {
	stub := &storage.CephRBDStubMigrator{
		InjectPreStageError: errTestSentinel,
	}

	err := stub.PreStage(context.Background(), storage.MigrationOptions{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCephRBDMigrator_Tier(t *testing.T) {
	m := storage.NewCephRBDMigrator("rbd")
	if m.Tier() != storage.TierCephRBD {
		t.Errorf("expected TierCephRBD, got %v", m.Tier())
	}
}
