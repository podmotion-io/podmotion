package authz

import (
	"testing"

	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// TestADR0244MethodPolicy_RPCsListed guards against the exact defect found and fixed alongside
// ADR-0244 (NR-BLOCK-2) GC-5: TeardownSourceRedirect, ProbeConntrackForIP and ProbeDestSocketForIP
// had real handler implementations in internal/agent/server/server.go but were absent from
// methodPolicy. Because UnaryInterceptor denies-by-default (ADR-SEC-A §2.2.3), any RPC missing
// from this map is rejected with PermissionDenied even though its handler is fully implemented
// and unit-tested — a silent authz gap that only surfaces against a real mTLS-connected caller,
// not in a handler-level unit test. This test fails fast if any of the three is ever dropped from
// the map again, or added without RoleOperator permission.
func TestADR0244MethodPolicy_RPCsListed(t *testing.T) {
	for _, method := range []string{
		agentpb.MigrationAgentService_TeardownSourceRedirect_FullMethodName,
		agentpb.MigrationAgentService_ProbeConntrackForIP_FullMethodName,
		agentpb.MigrationAgentService_ProbeDestSocketForIP_FullMethodName,
	} {
		allowed, listed := methodPolicy[method]
		if !listed {
			t.Fatalf("methodPolicy missing entry for %q (deny-by-default would reject this RPC)", method)
		}
		if !allowed[RoleOperator] {
			t.Fatalf("methodPolicy[%q] does not permit RoleOperator", method)
		}
	}
}
