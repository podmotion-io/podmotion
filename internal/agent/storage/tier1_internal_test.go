/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

// tier1_internal_test.go is a white-box (package storage) companion to
// adr0365_fail_closed_test.go: it exercises addDestReplica's own empty-destNode guard
// directly, since it is unexported and unreachable from the external storage_test package.
// PreStage's own guard (tested black-box) already rejects an empty opts.DestinationNode before
// ever reaching addDestReplica in the normal call path — this test proves addDestReplica is an
// independent backstop, per ADR-0365 Decision §2 item 3's "PreStage (and/or addDestReplica)".

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAddDestReplica_EmptyDestNode_FailsClosedNoHTTPCall(t *testing.T) {
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dialed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &LonghornMigrator{
		ManagerURL: srv.URL,
		HTTPClient: srv.Client(),
	}

	err := m.addDestReplica(context.Background(), "some-volume", "")
	if err == nil {
		t.Fatalf("expected addDestReplica to reject an empty destNode, got nil error")
	}
	if !errors.Is(err, errEmptyDestinationNode) {
		t.Errorf("expected errEmptyDestinationNode, got %v", err)
	}
	if dialed {
		t.Errorf("addDestReplica dialed the Longhorn Manager API with an empty destNode — must fail closed before issuing any HTTP call")
	}
}

// TestLonghornMigrator_ReleaseDestination_EmptyDestNode_FailsClosedNoHTTPCall is ReleaseDestination's
// own independent empty-destNode backstop guard (ADR-0368 §5.2, mirroring PreStage/addDestReplica's
// identical guard) — white-box because errEmptyDestinationNode is unexported.
func TestLonghornMigrator_ReleaseDestination_EmptyDestNode_FailsClosedNoHTTPCall(t *testing.T) {
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dialed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &LonghornMigrator{
		ManagerURL: srv.URL,
		HTTPClient: srv.Client(),
	}

	opts := MigrationOptions{
		Classifications: []TierClassification{{Tier: TierLonghorn, PVCName: "pgdata"}},
		DestinationNode: "",
	}

	err := m.ReleaseDestination(context.Background(), opts)
	if err == nil {
		t.Fatalf("expected ReleaseDestination to reject an empty DestinationNode, got nil error")
	}
	if !errors.Is(err, errEmptyDestinationNode) {
		t.Errorf("expected errEmptyDestinationNode, got %v", err)
	}
	if dialed {
		t.Errorf("ReleaseDestination dialed the Longhorn Manager API with an empty destNode — must fail closed before issuing any HTTP call")
	}
}
