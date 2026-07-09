// Copyright 2026 PodMotion Authors.
// Licensed under the Apache License, Version 2.0.

package authz

// Provenance pin for ADR "Provenance pinning for the two Sprint 41 abort-path
// regression proofs" (D2).
//
// This test reads authz.go at test time and asserts that the methodPolicy
// map literal still contains all three ADR-0244 GC-5 RPC entries —
// TeardownSourceRedirect, ProbeConntrackForIP, ProbeDestSocketForIP — and
// that each is still bound specifically to RoleOperator, not merely present
// under some looser role set. Matching on a looser role (e.g. one that also
// grants RolePeerAgent or any other principal) would silently reopen a
// privilege-widening variant of the original deny-by-default gap this ADR
// closed, even though the method name itself would still appear in the map.
//
// Remediation guidance: if this test fails after an intentional, reviewed
// change to widen or narrow the roles allowed to invoke one of these three
// RPCs, update the pinned role-binding string here to match the new,
// deliberately-reviewed policy — do not treat this as an ordinary broken test
// to be silenced or deleted. If the failure is because a symbol was renamed,
// update the pinned method name here instead.

import (
	"os"
	"regexp"
	"testing"
)

// TestProvenance_GC5MethodPolicyBoundToRoleOperator pins that each of the
// three ADR-0244 GC-5 RPCs is present in methodPolicy and bound specifically
// and solely to RoleOperator.
func TestProvenance_GC5MethodPolicyBoundToRoleOperator(t *testing.T) {
	src, err := os.ReadFile("authz.go")
	if err != nil {
		t.Fatalf("failed to read authz.go: %v", err)
	}
	content := string(src)

	gc5Methods := []string{
		"TeardownSourceRedirect",
		"ProbeConntrackForIP",
		"ProbeDestSocketForIP",
	}

	for _, method := range gc5Methods {
		// Match: agentpb.MigrationAgentService_<Method>_FullMethodName: {RoleOperator: true},
		// allowing for arbitrary alignment whitespace between the key and the
		// map-literal value, but requiring the value to be EXACTLY
		// {RoleOperator: true} — not a looser set that also includes another
		// role, which would reopen a privilege-widening variant of the
		// original gap.
		pattern := `agentpb\.MigrationAgentService_` + method + `_FullMethodName:\s*\{RoleOperator: true\},`
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Fatalf("internal error compiling regexp for %s: %v", method, err)
		}
		if !re.MatchString(content) {
			t.Errorf("authz.go: methodPolicy entry for %s not found bound solely to {RoleOperator: true} — either the entry is missing, or it has been widened to include another role; see file doc comment for remediation guidance", method)
		}
	}
}
