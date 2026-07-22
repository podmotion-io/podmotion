/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

// fakeExecCommandCephVersion returns an ExecCommand func that fakes `ceph version --format
// json` (echoing the given JSON) while any other command (rbd ...) fails immediately — so tests
// can isolate the version-gate check in PreStage without needing classifications to reach the
// rbd calls at all.
func fakeExecCommandCephVersion(t *testing.T, cephVersionJSON string, cephShouldFail bool) func(name string, args ...string) *exec.Cmd {
	t.Helper()
	return func(name string, args ...string) *exec.Cmd {
		if name == "ceph" && len(args) > 0 && args[0] == "version" {
			if cephShouldFail {
				// "false" always exits 1 with no output — simulates ceph binary missing/erroring.
				return exec.Command("false")
			}
			return exec.Command("echo", cephVersionJSON)
		}
		return exec.Command("false")
	}
}

// fail-closed phase-gate (item 6): checkCephVersionGate (invoked via PreStage) must fail closed — never
// silently discard — on a `ceph version` exec/parse failure. The prior warnIfReefCluster
// returned nothing and let PreStage proceed unconditionally on ANY version-check failure.
func TestCephRBDMigrator_PreStage_FailsClosedOnVersionCheckError(t *testing.T) {
	m := storage.NewCephRBDMigrator("rbd")
	m.ExecCommand = fakeExecCommandCephVersion(t, "", true)

	err := m.PreStage(context.Background(), storage.MigrationOptions{})
	if err == nil {
		t.Fatal("expected PreStage to fail closed when ceph version check fails, got nil error")
	}
	if !strings.Contains(err.Error(), "ceph version check failed") {
		t.Errorf("expected error to mention ceph version check failure, got: %v", err)
	}
}

// fail-closed phase-gate (item 6): a confirmed Reef 18.x cluster must hard-block Tier2 PreStage (ADR-0026 §1),
// not just log a warning and proceed.
func TestCephRBDMigrator_PreStage_BlocksOnConfirmedReef(t *testing.T) {
	m := storage.NewCephRBDMigrator("rbd")
	reefJSON := fmt.Sprintf(`{"version": "ceph version 18.2.1 (abcdef) reef (stable)"}`)
	m.ExecCommand = fakeExecCommandCephVersion(t, reefJSON, false)

	err := m.PreStage(context.Background(), storage.MigrationOptions{})
	if err == nil {
		t.Fatal("expected PreStage to block on confirmed Reef 18.x, got nil error")
	}
	if !strings.Contains(err.Error(), "Reef") {
		t.Errorf("expected error to mention Reef, got: %v", err)
	}
}

// A confirmed Squid 19.x+ cluster must NOT be blocked by the version gate (with no
// classifications, PreStage should return nil once the gate passes).
func TestCephRBDMigrator_PreStage_PassesOnSquid(t *testing.T) {
	m := storage.NewCephRBDMigrator("rbd")
	squidJSON := fmt.Sprintf(`{"version": "ceph version 19.2.0 (abcdef) squid (stable)"}`)
	m.ExecCommand = fakeExecCommandCephVersion(t, squidJSON, false)

	err := m.PreStage(context.Background(), storage.MigrationOptions{})
	if err != nil {
		t.Fatalf("expected PreStage to pass the version gate on Squid, got error: %v", err)
	}
}

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
