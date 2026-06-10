/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package tls_test

import (
	"testing"

	tlspkg "github.com/podmotion-io/podmotion/internal/agent/tls"
)

// TestNodeScopedToken_AudienceValidation verifies that the stub returns a non-empty token
// and that ValidateToken accepts it without error, and rejects an empty token.
func TestNodeScopedToken_AudienceValidation(t *testing.T) {
	stub := &tlspkg.ServiceAccountTokenStub{}

	token, err := stub.CreateMigrationToken("default", "source-pod", "node-1")
	if err != nil {
		t.Fatalf("CreateMigrationToken: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	if err := stub.ValidateToken(token, "node-1"); err != nil {
		t.Fatalf("ValidateToken with valid token: %v", err)
	}

	// Empty token must be rejected.
	if err := stub.ValidateToken("", "node-1"); err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}
