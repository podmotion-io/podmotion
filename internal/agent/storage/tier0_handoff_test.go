/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

import (
	"context"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

// fakeHandoffClient is a scripted storage.StorageHandoffClient for
// ADR-0344 Decision A.1 unit tests.
type fakeHandoffClient struct {
	resp *storage.StorageHandoffReadyResponse
	err  error
}

func (f *fakeHandoffClient) StorageHandoffReady(_ context.Context, _ *storage.StorageHandoffReadyRequest) (*storage.StorageHandoffReadyResponse, error) {
	return f.resp, f.err
}

// TestRWXReattachMigratorCutover_HandoffConfirmed exercises ADR-0344 §P-VERIFY
// case (a): with a fake StorageHandoffReady responder returning
// source_readonly:true, Cutover returns nil.
func TestRWXReattachMigratorCutover_HandoffConfirmed(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newManagerScheme(t)).Build()
	m := storage.NewRWXReattachMigrator(c).WithHandoffClient(&fakeHandoffClient{
		resp: &storage.StorageHandoffReadyResponse{SourceReadonly: true},
	})

	opts := storage.MigrationOptions{
		MigrationName: "pm-test",
		PodNamespace:  "default",
		Classifications: []storage.TierClassification{
			{PVCName: "pgdata", Tier: storage.TierRWX},
		},
	}

	if err := m.Cutover(context.Background(), opts); err != nil {
		t.Fatalf("Cutover with source_readonly=true: unexpected error: %v", err)
	}
}

// TestRWXReattachMigratorCutover_HandoffRefused exercises ADR-0344 §P-VERIFY
// case (b): with the responder returning false, Cutover returns an error and
// no destination-mount side effect occurs (this migrator performs no
// destination-mount side effect itself — that guarantee is enforced by the
// controller never proceeding to Restoring on a non-nil Cutover error).
func TestRWXReattachMigratorCutover_HandoffRefused(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newManagerScheme(t)).Build()
	m := storage.NewRWXReattachMigrator(c).WithHandoffClient(&fakeHandoffClient{
		resp: &storage.StorageHandoffReadyResponse{SourceReadonly: false, Reason: "RemountTimeout"},
	})

	opts := storage.MigrationOptions{
		MigrationName: "pm-test",
		PodNamespace:  "default",
		Classifications: []storage.TierClassification{
			{PVCName: "pgdata", Tier: storage.TierRWX},
		},
	}

	if err := m.Cutover(context.Background(), opts); err == nil {
		t.Fatalf("Cutover with source_readonly=false: expected error, got nil")
	}
}

// TestRWXReattachMigratorCutover_NoHandoffClientFailsOpen preserves the
// pre-ADR-0344 no-op Cutover behavior for callers that never wire a
// StorageHandoffClient (e.g. NewRWXReattachMigrator direct construction).
func TestRWXReattachMigratorCutover_NoHandoffClientFailsOpen(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newManagerScheme(t)).Build()
	m := storage.NewRWXReattachMigrator(c)

	opts := storage.MigrationOptions{
		MigrationName: "pm-test",
		PodNamespace:  "default",
		Classifications: []storage.TierClassification{
			{PVCName: "pgdata", Tier: storage.TierRWX},
		},
	}

	if err := m.Cutover(context.Background(), opts); err != nil {
		t.Fatalf("Cutover with no handoff client configured: unexpected error: %v", err)
	}
}
