/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package authz implements the ADR-SEC-A §2.2 deny-by-default per-RPC authorization
// interceptor for the node-agent gRPC server. It runs FIRST in the server's unary
// interceptor chain — before any handler logic — so an unauthorized caller never reaches
// a handler.
//
// Trust model: identity is the verified mTLS client cert's SPIFFE ID (first URI SAN), not a
// bearer token (ADR-SEC-A §4). The interceptor classifies the SPIFFE ID into a role, applies a
// static per-method allowed-role policy (a method absent from the map is DENIED), and binds the
// caller to the migration named in the request.
//
// Marker: this package carries the ADR-SEC-A deployed-provenance marker string.
package authz

import (
	"context"
	"crypto/x509"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// adrSecAMarker forces the ADR-SEC-A marker string into the agent binary's string table so the
// deployed binary can be verified to contain the expected marker (`strings /agent | grep -c 'ADR-SEC-A'`).
const adrSecAMarker = "ADR-SEC-A"

// SPIFFEPrefix is the trust-domain prefix every PodMotion SPIFFE ID must carry. Centralized here
// so both the agent authz interceptor (suffix-routing in classify) and the operator client
// callback (exact-equality pinning in the tls package) consult one source of truth (M3).
const SPIFFEPrefix = "spiffe://podmotion.io/"

// CanonicalSPIFFEID returns the single canonical SPIFFE ID of a VERIFIED leaf certificate.
//
// ADR-SEC-C / ADR-SEC-A §2.2: a SPIFFE SVID carries EXACTLY ONE URI SAN. This is the shared
// single-source-of-truth extractor (M3) consumed by BOTH:
//   - the agent authz interceptor (verifiedSPIFFEID → classify, which SUFFIX-routes to a role), and
//   - the operator→agent client callback (which EXACT-equality pins one specific agent ID).
//
// The exact-equality pin is the CLIENT caller's contract — this helper only enforces the
// exactly-one-URI invariant and reads the ID from the leaf. It does NOT itself decide the role or
// the expected ID. ok=false means the cert is not a well-formed single-URI SVID (zero or >1 URI
// SANs) and MUST be rejected by callers that require SPIFFE identity.
func CanonicalSPIFFEID(leaf *x509.Certificate) (id string, ok bool) {
	if leaf == nil || len(leaf.URIs) != 1 {
		return "", false
	}
	return leaf.URIs[0].String(), true
}

var log = logf.Log.WithName("agent-authz")

// Role is the classified identity of a verified caller.
type Role int

const (
	// RoleUnknown is any verified cert whose SPIFFE ID matches no known role — denied by default.
	RoleUnknown Role = iota
	// RoleOperator is the control authority (spiffe://.../sa/podmotion-operator).
	RoleOperator
	// RolePeerAgent is a peer node agent (spiffe://.../sa/podmotion-agent).
	RolePeerAgent
)

// MigrationBinder reads, for a migration, the source and destination node names so the
// interceptor can enforce the §2.2.4 caller-to-migration binding. Implemented by the agent
// server over its cached k8s client. A nil binder skips the binding check (no k8s client).
type MigrationBinder interface {
	// MigrationNodes returns (sourceNode, destNode, found). found=false when the CR is absent.
	MigrationNodes(ctx context.Context, migrationName string) (sourceNode, destNode string, found bool)
}

// migrationNamed is satisfied by every agent RPC request carrying a migration name.
type migrationNamed interface {
	GetMigrationName() string
}

// methodPolicy maps a gRPC full method name to the set of roles allowed to invoke it.
// A method ABSENT from this map is DENIED by default (ADR-SEC-A §2.2.3) — a newly added RPC
// is denied until explicitly listed here.
var methodPolicy = map[string]map[Role]bool{
	agentpb.MigrationAgentService_Checkpoint_FullMethodName:              {RoleOperator: true},
	agentpb.MigrationAgentService_Restore_FullMethodName:                 {RoleOperator: true},
	agentpb.MigrationAgentService_PrepareSource_FullMethodName:           {RoleOperator: true},
	agentpb.MigrationAgentService_PrepareDestination_FullMethodName:      {RoleOperator: true},
	agentpb.MigrationAgentService_PrepareDestinationNetns_FullMethodName: {RoleOperator: true},
	agentpb.MigrationAgentService_ConfirmOverlayReady_FullMethodName:     {RoleOperator: true},
	agentpb.MigrationAgentService_ReleaseCheckpoint_FullMethodName:       {RoleOperator: true},
	agentpb.MigrationAgentService_Abort_FullMethodName:                   {RoleOperator: true},
	agentpb.MigrationAgentService_ArmZeroWindow_FullMethodName:           {RoleOperator: true},
	agentpb.MigrationAgentService_DisarmZeroWindow_FullMethodName:        {RoleOperator: true},
	agentpb.MigrationAgentService_InjectSourceRedirect_FullMethodName:    {RoleOperator: true},
	agentpb.MigrationAgentService_InjectIPHandoff_FullMethodName:         {RoleOperator: true},
	agentpb.MigrationAgentService_CleanupSourceIPHandoff_FullMethodName:  {RoleOperator: true},
	agentpb.MigrationAgentService_DisarmTCRedirect_FullMethodName:        {RoleOperator: true},
	// ADR-0244 (NR-BLOCK-2) GC-5/R6/R7: source-side teardown and the two reclaim-eligibility
	// probes. All three are controller (operator)-driven only, same as DisarmTCRedirect/
	// InjectSourceRedirect above — absent from this map, deny-by-default (§2.2.3) would reject
	// them even though the handlers exist in server.go.
	agentpb.MigrationAgentService_TeardownSourceRedirect_FullMethodName: {RoleOperator: true},
	agentpb.MigrationAgentService_ProbeConntrackForIP_FullMethodName:    {RoleOperator: true},
	agentpb.MigrationAgentService_ProbeDestSocketForIP_FullMethodName:   {RoleOperator: true},
	// ADR-0284 GC-6: agent-side VerifyCleanup(IP_RECLAIM) presence-probe handler, controller-driven
	// only. Absent from this map, deny-by-default (§2.2.3) would reject the bounded-retry sweep's
	// confirmation call even though the handler now exists in verify_cleanup.go.
	agentpb.MigrationAgentService_VerifyCleanup_FullMethodName: {RoleOperator: true},
	agentpb.MigrationAgentService_Verify_FullMethodName:                  {RoleOperator: true},
	agentpb.MigrationAgentService_VerifyTCP_FullMethodName:               {RoleOperator: true},
	agentpb.MigrationAgentService_PreDumpRound_FullMethodName:            {RoleOperator: true},
	agentpb.MigrationAgentService_EstimateCheckpoint_FullMethodName:      {RoleOperator: true},
	// ADR-0236: ADR-0210 cross-node reachability nonce round-trip. Both halves are
	// controller-driven (operator → dest agent StartReachabilityEcho; operator → source
	// agent ProbeDataplaneReachability) and were ABSENT from this map, so deny-by-default
	// (§2.2.3) denied the operator and DataplaneReachabilityVerified never fired — migration
	// stalled in Verifying indefinitely. Both are RoleOperator only.
	agentpb.MigrationAgentService_StartReachabilityEcho_FullMethodName:      {RoleOperator: true},
	agentpb.MigrationAgentService_ProbeDataplaneReachability_FullMethodName: {RoleOperator: true},
	// Transfer RPCs: operator-driven push AND peer-agent transfer both permitted.
	agentpb.MigrationAgentService_PutCheckpointTar_FullMethodName: {RoleOperator: true, RolePeerAgent: true},
	agentpb.MigrationAgentService_GetCheckpointTar_FullMethodName: {RoleOperator: true, RolePeerAgent: true},
}

// transferMethods are the only methods a PEER_AGENT may invoke, and only for a migration its
// node is party to. (Subset of methodPolicy where RolePeerAgent is allowed.)
var transferMethods = map[string]bool{
	agentpb.MigrationAgentService_PutCheckpointTar_FullMethodName: true,
	agentpb.MigrationAgentService_GetCheckpointTar_FullMethodName: true,
}

// UnaryInterceptor returns the deny-by-default ADR-SEC-A authz interceptor. nodeName is this
// agent's node; binder may be nil (skips the migration-binding check when no k8s client exists).
func UnaryInterceptor(nodeName string, binder MigrationBinder) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		spiffeID, err := verifiedSPIFFEID(ctx)
		if err != nil {
			return nil, err
		}
		role := classify(spiffeID)
		if role == RoleUnknown {
			log.Info("ADR-SEC-A authz: DENY — unknown role", "spiffe", spiffeID, "method", info.FullMethod)
			return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-A: caller identity %q has no authorized role", spiffeID)
		}

		allowed, listed := methodPolicy[info.FullMethod]
		if !listed {
			// Deny-by-default: a method not in the policy map is denied.
			log.Info("ADR-SEC-A authz: DENY — method not in policy map (deny-by-default)", "method", info.FullMethod, "spiffe", spiffeID)
			return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-A: method %q not authorized (deny-by-default)", info.FullMethod)
		}
		if !allowed[role] {
			log.Info("ADR-SEC-A authz: DENY — role not permitted for method", "method", info.FullMethod, "role", role, "spiffe", spiffeID)
			return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-A: role not permitted to call %q", info.FullMethod)
		}

		// §2.2.4 caller-to-migration binding. OPERATOR owns all migrations it issues — permitted.
		// A PEER_AGENT may only invoke transfer RPCs for a migration its node is source/dest of.
		if role == RolePeerAgent {
			if !transferMethods[info.FullMethod] {
				return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-A: peer agent may not call %q", info.FullMethod)
			}
			if binder != nil {
				mn := ""
				if m, ok := req.(migrationNamed); ok {
					mn = m.GetMigrationName()
				}
				src, dst, found := binder.MigrationNodes(ctx, mn)
				if !found || (nodeName != src && nodeName != dst) {
					log.Info("ADR-SEC-A authz: DENY — peer agent not party to migration", "method", info.FullMethod, "migration", mn, "node", nodeName, "src", src, "dst", dst, "found", found)
					return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-A: peer agent node %q not party to migration %q", nodeName, mn)
				}
			}
		}

		return handler(ctx, req)
	}
}

// verifiedSPIFFEID extracts the verified peer's SPIFFE ID (first URI SAN of the leaf cert),
// falling back to the CN. Under RequireAndVerifyClientCert a missing verified chain cannot
// normally occur — checked belt-and-braces and rejected codes.Unauthenticated.
func verifiedSPIFFEID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return "", status.Error(codes.Unauthenticated, "ADR-SEC-A: no peer info on RPC")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "ADR-SEC-A: connection is not mTLS")
	}
	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "ADR-SEC-A: no verified client certificate")
	}
	leaf := chains[0][0]
	// Read the canonical single SPIFFE URI from the verified leaf via the shared M3 helper so the
	// agent and operator sides cannot skew on what "the leaf's SPIFFE ID" means. Fall back to CN
	// only when the leaf is not a single-URI SVID (legacy belt-and-braces).
	if id, ok := CanonicalSPIFFEID(leaf); ok {
		return id, nil
	}
	return cnOf(leaf), nil
}

func cnOf(c *x509.Certificate) string { return c.Subject.CommonName }

// classify maps a SPIFFE ID to a role. The trailing path segment .../sa/<name> determines role.
func classify(spiffeID string) Role {
	if !strings.HasPrefix(spiffeID, SPIFFEPrefix) {
		return RoleUnknown
	}
	switch {
	case strings.HasSuffix(spiffeID, "/sa/podmotion-operator"):
		return RoleOperator
	case strings.HasSuffix(spiffeID, "/sa/podmotion-agent"):
		return RolePeerAgent
	default:
		return RoleUnknown
	}
}
