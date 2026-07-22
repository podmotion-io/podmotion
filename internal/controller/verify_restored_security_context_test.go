/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package controller

// verify_restored_security_context_test.go — fail-closed phase-gate remediation (item 2) unit coverage.
//
// verifyRestoredSecurityContext used to be a hard `return nil` no-op — the condition it gates
// went True on nothing at all. This asserts the interim-compliant fail-closed replacement: a
// visible, typed "not yet implemented" error, distinguishable via errors.Is, rather than a
// silent pass.

import (
	"context"
	"errors"
	"testing"
)

func TestVerifyRestoredSecurityContext_FailsClosed_NotYetImplemented(t *testing.T) {
	r := &PodMigrationReconciler{}

	err := r.verifyRestoredSecurityContext(context.Background(), nil)
	if err == nil {
		t.Fatal("expected verifyRestoredSecurityContext to fail closed (non-nil error), got nil")
	}
	if !errors.Is(err, errSecurityContextVerificationNotImplemented) {
		t.Errorf("expected errors.Is match against errSecurityContextVerificationNotImplemented, got: %v", err)
	}
}
