package server

import (
	"context"
	"net"
	"testing"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// dialAllowedForMigrationProbe (sprint46B7 Validation cycle-2 fix) — coverage for the exact
// composed-datapath break the live-proof exposed. Under ADR-0352 the Strict completion path is the
// Service-continuity model, and the preserved-IP-on-endpoint gate is RETIRED from Strict, so
// cluster-pool IPAM may hand the replacement pod a FRESH destination-local IP that is NOT the
// migration's requested Spec.SourcePodIP. The controller builds the ADR-0325 WorkloadLivenessVerified
// probe against destPod.Status.PodIP (the replacement pod's ACTUAL IP), so the dial-auth must admit
// THAT exact IP — read from the SAME source of truth (the replacement pod's Status.PodIP), not
// Spec.SourcePodIP. The cycle-1 code keyed on Spec.SourcePodIP; when the pod came up on a fresh IP
// the probe target and the admit key diverged and the probe was refused (NonPodCIDRRefused),
// wedging the migration in ServiceVerifying. These tests are derived from that REAL state: a
// replacement pod whose Status.PodIP differs from Spec.SourcePodIP.

const (
	testDestCIDR = "10.244.2.0/24"
	// preservedReqIP is the migration's REQUESTED preserved IP (Spec.SourcePodIP), in the SOURCE
	// node's Cilium block — NOT in the destination allowlist and NOT the IP the pod came up with.
	preservedReqIP = "10.244.0.63"
	// freshReplIP is the replacement pod's ACTUAL Status.PodIP: a fresh destination-local Cilium IP
	// (pm-w2's real 10.244.1.0/24 block), which Node.Spec.PodCIDRs for the dest (10.244.2.0/24)
	// does NOT contain — the exact live cycle-2 value the controller probed and the agent refused.
	freshReplIP = "10.244.1.203"
)

// serverWithDestCIDRObjs returns an AgentServer whose pod-CIDR allowlist is pinned to the
// DESTINATION node's Node.Spec.PodCIDRs (10.244.2.0/24) and whose k8s client holds the given
// objects (PodMigration CRs and replacement Pods). Setting podCIDRAllowlist directly exercises the
// same cached slice nodePodCIDRAllowlist returns, without needing a Node object.
func serverWithDestCIDRObjs(t *testing.T, objs ...client.Object) *AgentServer {
	t.Helper()
	_, destCIDR, err := net.ParseCIDR(testDestCIDR)
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("pmv1.AddToScheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}
	b := fake.NewClientBuilder().WithScheme(scheme)
	if len(objs) > 0 {
		b = b.WithObjects(objs...)
	}
	s := &AgentServer{k8sClient: b.Build()}
	s.podCIDRAllowlist = []*net.IPNet{destCIDR}
	return s
}

// migrationCR builds a Strict PodMigration whose Spec.SourcePodIP is the REQUESTED preserved IP and
// whose PodNamespace is "default" (where resolveReplacementPod lists for the replacement pod).
func migrationCR(name, sourcePodIP, replPodName string) *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodNamespace:        "default",
			SourcePodIP:         sourcePodIP,
			TCPPreservationMode: pmv1.TCPPreservationModeStrict,
		},
		Status: pmv1.PodMigrationStatus{ReplacementPodName: replPodName},
	}
}

// replacementPod builds the replacement pod carrying the authoritative migration-name label
// (resolveReplacementPod's source of truth) and the given ACTUAL Status.PodIP.
func replacementPod(name, migrationName, statusPodIP string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    map[string]string{replacementPodLabelKey: migrationName},
		},
		Status: corev1.PodStatus{PodIP: statusPodIP},
	}
}

// TestDialAllowedForMigrationProbe_AdmitsReplacementPodStatusIP is the direct regression for the
// live-proof cycle-2 failure: the replacement pod came up on a FRESH destination-local IP
// (10.244.1.203) that is NOT Spec.SourcePodIP (10.244.0.63) and NOT in the destination allowlist
// (10.244.2.0/24). The controller probes 10.244.1.203; the dial-auth must ADMIT it because it is
// the replacement pod's own authoritative Status.PodIP.
func TestDialAllowedForMigrationProbe_AdmitsReplacementPodStatusIP(t *testing.T) {
	s := serverWithDestCIDRObjs(t,
		migrationCR("redis-mig", preservedReqIP, "redis-src-m-abc"),
		replacementPod("redis-src-m-abc", "redis-mig", freshReplIP),
	)
	req := &agentpb.VerifyTCPRequest{
		MigrationName:   "redis-mig",
		AppProbeAddress: freshReplIP + ":6379",
	}
	if err := s.dialAllowedForMigrationProbe(context.Background(), req); err != nil {
		t.Fatalf("expected the replacement pod's actual Status.PodIP (%s) to be admitted (source-of-truth read the controller also probes), got refusal: %v", freshReplIP, err)
	}
}

// TestDialAllowedForMigrationProbe_RefusesStaleSpecSourcePodIP proves the divergence bug cannot
// recur: Spec.SourcePodIP (the requested preserved IP the pod did NOT come up with) is no longer
// admitted, because the replacement pod does not answer on it. Admitting it was the cycle-1 defect.
func TestDialAllowedForMigrationProbe_RefusesStaleSpecSourcePodIP(t *testing.T) {
	s := serverWithDestCIDRObjs(t,
		migrationCR("redis-mig", preservedReqIP, "redis-src-m-abc"),
		replacementPod("redis-src-m-abc", "redis-mig", freshReplIP),
	)
	req := &agentpb.VerifyTCPRequest{
		MigrationName:   "redis-mig",
		AppProbeAddress: preservedReqIP + ":6379",
	}
	if err := s.dialAllowedForMigrationProbe(context.Background(), req); err == nil {
		t.Fatalf("expected refusal for Spec.SourcePodIP (%s): the replacement pod answers on %s, not the requested preserved IP — admitting the stale requested IP was the cycle-1 mis-key", preservedReqIP, freshReplIP)
	}
}

// TestDialAllowedForMigrationProbe_AdmitsHonoredPreservedIP proves correctness in the OTHER case:
// when the ipam.cilium.io/ip pin IS honored, the replacement pod's Status.PodIP EQUALS the requested
// preserved IP, and that out-of-destination-CIDR IP is still admitted (reading Status.PodIP covers
// both the honored and the fresh-IP cases from one source of truth).
func TestDialAllowedForMigrationProbe_AdmitsHonoredPreservedIP(t *testing.T) {
	s := serverWithDestCIDRObjs(t,
		migrationCR("redis-mig", preservedReqIP, "redis-src-m-abc"),
		replacementPod("redis-src-m-abc", "redis-mig", preservedReqIP),
	)
	req := &agentpb.VerifyTCPRequest{
		MigrationName:   "redis-mig",
		AppProbeAddress: preservedReqIP + ":6379",
	}
	if err := s.dialAllowedForMigrationProbe(context.Background(), req); err != nil {
		t.Fatalf("expected the honored preserved IP (replacement pod Status.PodIP == %s) to be admitted, got refusal: %v", preservedReqIP, err)
	}
}

// TestDialAllowedForMigrationProbe_RefusesUnrelatedForeignIP proves this is NOT a CIDR-widening or
// a blanket "any out-of-CIDR IP is fine": an address that is neither in the pod-CIDR allowlist nor
// equal to this migration's replacement pod IP is still refused — ADR-0325 SSRF containment survives.
func TestDialAllowedForMigrationProbe_RefusesUnrelatedForeignIP(t *testing.T) {
	s := serverWithDestCIDRObjs(t,
		migrationCR("redis-mig", preservedReqIP, "redis-src-m-abc"),
		replacementPod("redis-src-m-abc", "redis-mig", freshReplIP),
	)
	req := &agentpb.VerifyTCPRequest{
		MigrationName:   "redis-mig",
		AppProbeAddress: "10.99.7.7:6379",
	}
	if err := s.dialAllowedForMigrationProbe(context.Background(), req); err == nil {
		t.Fatalf("expected refusal for an address that is neither in the pod-CIDR allowlist nor this migration's replacement pod IP (SSRF containment)")
	}
}

// TestDialAllowedForMigrationProbe_FailsClosedWhenMigrationUnknown proves the admit is anchored to
// an authoritative k8s read, not to AppProbeAddress on trust: a foreign IP whose migration CR /
// replacement pod does not exist is refused. A construction bug or hostile caller threading an
// unrelated address cannot self-authorize.
func TestDialAllowedForMigrationProbe_FailsClosedWhenMigrationUnknown(t *testing.T) {
	s := serverWithDestCIDRObjs(t) // no objects
	req := &agentpb.VerifyTCPRequest{
		MigrationName:   "does-not-exist",
		AppProbeAddress: freshReplIP + ":6379",
	}
	if err := s.dialAllowedForMigrationProbe(context.Background(), req); err == nil {
		t.Fatalf("expected fail-closed refusal when the migration CR/replacement pod cannot supply an authoritative IP")
	}
}

// TestDialAllowedForMigrationProbe_FailsClosedWhenReplacementPodMissing proves that a CR without a
// resolvable replacement pod (label race lost AND no Status.ReplacementPodName pod) does not admit
// the out-of-CIDR probe — it falls closed rather than reaching back to Spec.SourcePodIP.
func TestDialAllowedForMigrationProbe_FailsClosedWhenReplacementPodMissing(t *testing.T) {
	s := serverWithDestCIDRObjs(t, migrationCR("redis-mig", preservedReqIP, ""))
	req := &agentpb.VerifyTCPRequest{
		MigrationName:   "redis-mig",
		AppProbeAddress: freshReplIP + ":6379",
	}
	if err := s.dialAllowedForMigrationProbe(context.Background(), req); err == nil {
		t.Fatalf("expected fail-closed refusal when no replacement pod is resolvable (no Spec.SourcePodIP fallback)")
	}
}

// TestDialAllowedForMigrationProbe_AdmitsOrdinaryInCIDR confirms the ordinary same-node / Mode=None
// new-IP case (target inside the destination node's pod-CIDR) is unchanged — the fast path admits
// without needing any CR read.
func TestDialAllowedForMigrationProbe_AdmitsOrdinaryInCIDR(t *testing.T) {
	s := serverWithDestCIDRObjs(t)
	req := &agentpb.VerifyTCPRequest{
		MigrationName:   "any",
		AppProbeAddress: "10.244.2.9:6379",
	}
	if err := s.dialAllowedForMigrationProbe(context.Background(), req); err != nil {
		t.Fatalf("expected an in-pod-CIDR destination IP to be admitted on the ordinary fast path, got: %v", err)
	}
}

// TestDialAllowedForMigrationProbe_PreservesServiceContinuityClusterIP confirms delegating the
// ClusterIP case (ADR-0352 D1.2) is unchanged: an out-of-pod-CIDR Service ClusterIP is admitted
// only when it matches the controller-resolved ExpectedClusterIp exactly.
func TestDialAllowedForMigrationProbe_PreservesServiceContinuityClusterIP(t *testing.T) {
	s := serverWithDestCIDRObjs(t)
	ok := &agentpb.VerifyTCPRequest{
		AppProbeAddress:   "10.96.0.10:6379",
		ExpectedClusterIp: "10.96.0.10",
	}
	if err := s.dialAllowedForMigrationProbe(context.Background(), ok); err != nil {
		t.Fatalf("expected the exact expected Service ClusterIP to be admitted (ADR-0352 D1.2 delegation), got: %v", err)
	}
	mismatch := &agentpb.VerifyTCPRequest{
		AppProbeAddress:   "10.96.0.99:6379",
		ExpectedClusterIp: "10.96.0.10",
	}
	if err := s.dialAllowedForMigrationProbe(context.Background(), mismatch); err == nil {
		t.Fatalf("expected refusal for a ClusterIP that does not match ExpectedClusterIp (no CIDR widening)")
	}
}
