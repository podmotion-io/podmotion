package authz

import (
	"testing"

	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// TestADR0284MethodPolicy_VerifyCleanupListed guards the ADR-0284 GC-6 authz obligation: the
// agent-side VerifyCleanup handler (internal/agent/server/verify_cleanup.go) is driven by the
// controller's reconcileIPReclaimSweep on every eligible pass. Because UnaryInterceptor
// denies-by-default (ADR-SEC-A §2.2.3), an unlisted method is rejected with PermissionDenied even
// though the handler exists — which would leave ConditionIPReclaimVerified permanently unable to
// converge for a *different* reason than the pre-fix Unimplemented. This fails fast if the entry
// is ever dropped or added without RoleOperator.
func TestADR0284MethodPolicy_VerifyCleanupListed(t *testing.T) {
	method := agentpb.MigrationAgentService_VerifyCleanup_FullMethodName
	allowed, listed := methodPolicy[method]
	if !listed {
		t.Fatalf("methodPolicy missing entry for %q (deny-by-default would reject the reclaim sweep's VerifyCleanup call)", method)
	}
	if !allowed[RoleOperator] {
		t.Fatalf("methodPolicy[%q] does not permit RoleOperator", method)
	}
}
