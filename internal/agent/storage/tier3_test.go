/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

var errTestSentinel = errors.New("injected test error")

func TestSnapshotRsyncStubMigrator_PVCCreation(t *testing.T) {
	stub := &storage.SnapshotRsyncStubMigrator{}

	opts := storage.MigrationOptions{
		MigrationName:   "mig-abc",
		PodNamespace:    "default",
		SourceNode:      "node-a",
		DestinationNode: "node-b",
		Classifications: []storage.TierClassification{
			{Tier: storage.TierSnapshotRsync, PVCName: "data-pvc"},
			{Tier: storage.TierSnapshotRsync, PVCName: "log-pvc"},
		},
	}

	if err := stub.PreStage(context.Background(), opts); err != nil {
		t.Fatalf("PreStage: unexpected error: %v", err)
	}

	if !stub.PreStageCalled {
		t.Error("expected PreStageCalled=true")
	}

	if len(stub.CreatedPVCs) != 2 {
		t.Errorf("expected 2 created PVCs, got %d: %v", len(stub.CreatedPVCs), stub.CreatedPVCs)
	}

	// Verify expected PVC names follow the convention pm-<migration>-<pvc>-dest.
	wantPVCs := map[string]bool{
		"pm-mig-abc-data-pvc-dest": true,
		"pm-mig-abc-log-pvc-dest":  true,
	}
	for _, pvc := range stub.CreatedPVCs {
		if !wantPVCs[pvc] {
			t.Errorf("unexpected created PVC name: %q", pvc)
		}
	}

	// SyncPercent should always be 100 for the stub.
	pct, err := stub.SyncPercent(context.Background(), opts)
	if err != nil {
		t.Fatalf("SyncPercent: unexpected error: %v", err)
	}
	if pct != 100 {
		t.Errorf("expected 100%%, got %d%%", pct)
	}

	if err := stub.Cutover(context.Background(), opts); err != nil {
		t.Fatalf("Cutover: unexpected error: %v", err)
	}
	if !stub.CutoverCalled {
		t.Error("expected CutoverCalled=true")
	}
}

func TestSnapshotRsyncStubMigrator_InjectError(t *testing.T) {
	stub := &storage.SnapshotRsyncStubMigrator{
		InjectPreStageError: errTestSentinel,
	}
	err := stub.PreStage(context.Background(), storage.MigrationOptions{})
	if err == nil {
		t.Fatal("expected error from InjectPreStageError, got nil")
	}
}

func TestSnapshotRsyncMigrator_Tier(t *testing.T) {
	m := storage.NewSnapshotRsyncMigrator(nil)
	if m.Tier() != storage.TierSnapshotRsync {
		t.Errorf("expected TierSnapshotRsync, got %v", m.Tier())
	}
}
