/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0.
*/

package server

// adr0422_bindprep_authoritative_test.go — regression tests for ADR-0422: bind-prep must read the
// authoritative socket-identity address (Status.TCPSeqSnapshots[0].SrcIP) instead of
// Spec.SourcePodIP, the D1a/b/c authoritative-reader (cache-race) fix, the D1f bindIP/homeIP split
// in SingleHomeRestoredPod, D1g fail-closed scoping, D1i's threaded-not-re-resolved bindIP, D1i5's
// idempotent-confirm write-back latch, D1j's nil-apiReader startup guard, and D2's soccr/ scanner
// widening.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// gc09WzhhqBindIP / gc09WzhhqHomeIP are the live divergent-shape values the mechanism map's
// wzhhq/gc09 comparison table (ADR-0422 §Context) recorded: a second-generation migration where
// Spec.SourcePodIP (the pod's tracked-forward Kubernetes identity) and
// Status.TCPSeqSnapshots[0].SrcIP (the checkpointed socket's bind address, which cannot follow the
// pod across hops) have genuinely diverged.
const (
	gc09WzhhqBindIP = "10.42.2.150" // the checkpointed socket's local address (bindIP)
	gc09WzhhqHomeIP = "10.42.1.55"  // Spec.SourcePodIP (homeIP)
)

func migrationWithSnapshot(name, namespace, homeIP, bindIP string) *pmv1.PodMigration {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       pmv1.PodMigrationSpec{SourcePodIP: homeIP},
	}
	if bindIP != "" {
		pm.Status.TCPSeqSnapshots = []pmv1.TCPSeqSnapshot{{SrcIP: bindIP}}
	}
	return pm
}

// §P-VERIFY #1 (BLOCKING) — resolvePreservedSourceIPAuthoritative returns the SNAPSHOT value, never
// the spec value, when the two disagree (the live gc09/wzhhq shape).
func TestResolvePreservedSourceIPAuthoritative_PrefersSnapshotOverSpec(t *testing.T) {
	const migration, ns = "adr0422-prefer-snapshot", "podmotion-test"
	pm := migrationWithSnapshot(migration, ns, gc09WzhhqHomeIP, gc09WzhhqBindIP)
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()

	got, err := resolvePreservedSourceIPAuthoritative(context.Background(), cl, ns, migration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != gc09WzhhqBindIP {
		t.Fatalf("resolvePreservedSourceIPAuthoritative = %q, want the snapshot value %q (not the spec value %q) — D1 is not implemented as decided",
			got, gc09WzhhqBindIP, gc09WzhhqHomeIP)
	}
}

// §P-VERIFY #2 (BLOCKING) — the empty-snapshot fallback: Spec.SourcePodIP set, TCPSeqSnapshots
// empty, returns the spec value unchanged (D1b), never a fail-closed "".
func TestResolvePreservedSourceIPAuthoritative_EmptySnapshotFallsBackToSpec(t *testing.T) {
	const migration, ns = "adr0422-empty-snapshot-fallback", "podmotion-test"
	pm := migrationWithSnapshot(migration, ns, gc09WzhhqHomeIP, "")
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()

	got, err := resolvePreservedSourceIPAuthoritative(context.Background(), cl, ns, migration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != gc09WzhhqHomeIP {
		t.Fatalf("resolvePreservedSourceIPAuthoritative = %q, want the spec fallback %q (D1b) — silently returning \"\" here would disable bind-prep on every first-generation migration",
			got, gc09WzhhqHomeIP)
	}
}

// §P-VERIFY #2f (BLOCKING) — a Get/List failure propagates as an error, distinct from a genuine
// empty-both-fields no-op.
func TestResolvePreservedSourceIPAuthoritative_GetFailureIsAnError(t *testing.T) {
	stub := &stubReader{err: errors.New("transport: connection refused")}
	got, err := resolvePreservedSourceIPAuthoritative(context.Background(), stub, "podmotion-test", "some-migration")
	if err == nil {
		t.Fatalf("expected a non-nil error on Get failure, got (%q, nil) — indistinguishable from a genuine no-op (D1g0's fail-open regression)", got)
	}
	if got != "" {
		t.Fatalf("expected \"\" alongside the error, got %q", got)
	}
}

// §P-VERIFY #2f — a successfully-read CR with both fields empty is a genuine, error-free no-op.
func TestResolvePreservedSourceIPAuthoritative_BothFieldsEmptyIsRealNoOp(t *testing.T) {
	const migration, ns = "adr0422-both-empty", "podmotion-test"
	pm := migrationWithSnapshot(migration, ns, "", "")
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()

	got, err := resolvePreservedSourceIPAuthoritative(context.Background(), cl, ns, migration)
	if err != nil {
		t.Fatalf("expected a genuine no-op (nil error), got err=%v", err)
	}
	if got != "" {
		t.Fatalf("got = %q, want \"\"", got)
	}
}

// §P-VERIFY #24 (BLOCKING, D1g1a) — a nil apiReader fails closed (non-nil error), never ("", nil):
// collapsing the two would make an established-TCP restore on a node whose agent started with a nil
// apiReader silently skip bind-prep.
func TestResolvePreservedSourceIPAuthoritative_NilReaderFailsClosed(t *testing.T) {
	got, err := resolvePreservedSourceIPAuthoritative(context.Background(), nil, "podmotion-test", "some-migration")
	if err == nil {
		t.Fatalf("expected a non-nil error for a nil reader, got (%q, nil)", got)
	}
	if !errors.Is(err, errNilAuthoritativeReader) {
		t.Fatalf("expected errors.Is(err, errNilAuthoritativeReader), got %v", err)
	}
}

// §P-VERIFY #24 (BLOCKING, D1g1a) — the opposite direction: an empty namespace/migrationName with a
// REAL (non-nil) reader remains a genuine, error-free no-op — the two conditions must stay
// distinguishable in both directions, not just collapsed together whenever either fires.
func TestResolvePreservedSourceIPAuthoritative_EmptyIdentityWithRealReaderIsNoOp(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
	got, err := resolvePreservedSourceIPAuthoritative(context.Background(), cl, "", "some-migration")
	if err != nil {
		t.Fatalf("expected a genuine no-op for an empty namespace with a real reader, got err=%v", err)
	}
	if got != "" {
		t.Fatalf("got = %q, want \"\"", got)
	}
}

// stubReader is a minimal client.Reader whose Get/List always return err (or a supplied PodMigration
// on success), used to exercise resolvePreservedSourceIPAuthoritative's failure-propagation branch
// without a full fake client.
type stubReader struct {
	err error
	pm  *pmv1.PodMigration
}

func (r *stubReader) Get(_ context.Context, _ types.NamespacedName, obj client.Object, _ ...client.GetOption) error {
	if r.err != nil {
		return r.err
	}
	if pm, ok := obj.(*pmv1.PodMigration); ok && r.pm != nil {
		*pm = *r.pm
	}
	return nil
}

func (r *stubReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return r.err
}

var _ client.Reader = (*stubReader)(nil)

// §P-VERIFY #2f-ii (BLOCKING) — bindIPFromRestoreRequest prefers req.SeqSnapshots[0].SrcIp, a
// pure zero-I/O read, and is the value the gRPC call sites consult BEFORE any CR read.
func TestBindIPFromRestoreRequest(t *testing.T) {
	t.Run("empty_request", func(t *testing.T) {
		if ip, ok := bindIPFromRestoreRequest(nil); ok || ip != "" {
			t.Fatalf("bindIPFromRestoreRequest(nil) = (%q, %v), want (\"\", false)", ip, ok)
		}
	})
	t.Run("no_snapshots", func(t *testing.T) {
		req := &agentpb.RestoreRequest{MigrationName: "mig"}
		if ip, ok := bindIPFromRestoreRequest(req); ok || ip != "" {
			t.Fatalf("bindIPFromRestoreRequest(no snapshots) = (%q, %v), want (\"\", false)", ip, ok)
		}
	})
	t.Run("blank_src_ip", func(t *testing.T) {
		req := &agentpb.RestoreRequest{SeqSnapshots: []*agentpb.SeqSnapshot{{SrcIp: "  "}}}
		if ip, ok := bindIPFromRestoreRequest(req); ok || ip != "" {
			t.Fatalf("bindIPFromRestoreRequest(blank SrcIp) = (%q, %v), want (\"\", false)", ip, ok)
		}
	})
	t.Run("present_takes_index_zero", func(t *testing.T) {
		req := &agentpb.RestoreRequest{SeqSnapshots: []*agentpb.SeqSnapshot{
			{SrcIp: gc09WzhhqBindIP},
			{SrcIp: "10.99.99.99"},
		}}
		ip, ok := bindIPFromRestoreRequest(req)
		if !ok || ip != gc09WzhhqBindIP {
			t.Fatalf("bindIPFromRestoreRequest = (%q, %v), want (%q, true)", ip, ok, gc09WzhhqBindIP)
		}
	})
}

// §P-VERIFY #9 (BLOCKING, D1f-R4a) — bindIP non-empty / homeIP empty fails closed with the named
// error, before any gateway/address-add/route-install site is reached.
func TestSingleHomeRestoredPod_D1f_BindIPWithoutHomeIPFailsClosed(t *testing.T) {
	const migration, ns = "adr0422-bindip-no-homeip", "podmotion-test"
	pm := migrationWithSnapshot(migration, ns, "", gc09WzhhqBindIP) // homeIP empty, bindIP set
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
	s := New("test-node", nil, cl)

	fk := &fakeEth0Broker{addrs: []eth0Addr{{CIDR: gc09WzhhqBindIP + "/32", Scope: "host"}}}
	orig := brokerNetnsExecFn
	brokerNetnsExecFn = fk.exec
	defer func() { brokerNetnsExecFn = orig }()

	err := s.SingleHomeRestoredPod(context.Background(), migration, ns, 4242, gc09WzhhqBindIP)
	if err == nil {
		t.Fatal("expected the D1f-R4a fail-closed error, got nil")
	}
	if len(fk.addCalls) != 0 || len(fk.delCalls) != 0 {
		t.Fatalf("no gateway/address-add/route-install call may be reached with an empty homeIP; addCalls=%v delCalls=%v", fk.addCalls, fk.delCalls)
	}
}

// §P-VERIFY #2a (BLOCKING, D1f) — the dual-home oldPresent check keys on bindIP, not homeIP: eth0
// carries the snapshot (bind) address plus a foreign scope-global CNI primary equal to homeIP —
// dual-home must succeed against bindIP.
func TestSingleHomeRestoredPod_D1f_DualHomeKeysOnBindIP(t *testing.T) {
	const migration, ns = "adr0422-dualhome-bindip", "podmotion-test"
	pm := migrationWithSnapshot(migration, ns, gc09WzhhqHomeIP, gc09WzhhqBindIP)
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
	s := New("test-node", nil, cl)

	fk := &fakeEth0Broker{addrs: []eth0Addr{
		{CIDR: "10.42.2.200/24", Scope: "global"},      // foreign CNI primary (pin not honored)
		{CIDR: gc09WzhhqBindIP + "/32", Scope: "host"}, // D1's bind-prep artifact
	}}
	orig := brokerNetnsExecFn
	brokerNetnsExecFn = fk.exec
	defer func() { brokerNetnsExecFn = orig }()

	if err := s.SingleHomeRestoredPod(context.Background(), migration, ns, 4242, gc09WzhhqBindIP); err != nil {
		t.Fatalf("expected dual-home success keyed on bindIP, got error: %v", err)
	}
}

// §P-VERIFY #2a2 (BLOCKING, D1f) — the dualHomePrimary detection loop keys on homeIP, not bindIP.
//
// Discriminator: eth0 carries homeIP itself as the sole scope-global address (the pin IS honored —
// no foreign primary) and does NOT carry bindIP at all (bind-prep never ran / a connectionless
// restore for this call, or the artifact was already gone). A correct, homeIP-keyed loop sees no
// address differing from homeIP at global scope, so dualHomePrimary stays "" and the function takes
// the STRIP branch, which does not require bindIP's presence at all and returns nil. A loop that
// (bug) compares against bindIP instead would see homeIP itself as "differs from bindIP, scope
// global" and wrongly set dualHomePrimary, entering the dual-home branch — which then fails closed
// with "OLD IP absent from eth0" because bindIP genuinely is not present. The two implementations
// are therefore distinguishable by nil-vs-error, not by side-effect emptiness (both branches emit no
// add/del calls in this particular fixture).
func TestSingleHomeRestoredPod_D1f_DualHomeDetectionKeysOnHomeIP(t *testing.T) {
	const migration, ns = "adr0422-dualhomeloop-homeip", "podmotion-test"
	pm := migrationWithSnapshot(migration, ns, gc09WzhhqHomeIP, gc09WzhhqBindIP)
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
	s := New("test-node", nil, cl)

	fk := &fakeEth0Broker{addrs: []eth0Addr{
		{CIDR: gc09WzhhqHomeIP + "/24", Scope: "global"}, // pin honored: homeIP is the CNI primary
		// bindIP deliberately ABSENT — a dual-home branch reached here can only succeed by
		// tolerating a missing bindIP, which it must not (D1's own subject, row 2700-2712).
	}}
	orig := brokerNetnsExecFn
	brokerNetnsExecFn = fk.exec
	defer func() { brokerNetnsExecFn = orig }()

	if err := s.SingleHomeRestoredPod(context.Background(), migration, ns, 4242, gc09WzhhqBindIP); err != nil {
		t.Fatalf("expected nil (strip branch — homeIP is already the sole scope-global primary, no foreign primary present), got: %v — "+
			"a non-nil \"dual-home ... absent from eth0\" error here means the dualHomePrimary loop compared against bindIP instead of homeIP", err)
	}
}

// §P-VERIFY #2b (BLOCKING, D1f) — the strip branch never strips EITHER bindIP or homeIP.
func TestSingleHomeRestoredPod_D1f_StripBranchNeverStripsEither(t *testing.T) {
	const migration, ns = "adr0422-strip-union", "podmotion-test"
	pm := migrationWithSnapshot(migration, ns, gc09WzhhqHomeIP, gc09WzhhqBindIP)
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
	s := New("test-node", nil, cl)

	fk := &fakeEth0Broker{addrs: []eth0Addr{
		{CIDR: gc09WzhhqHomeIP + "/24", Scope: "global"}, // homeIP present, scope-global
		{CIDR: gc09WzhhqBindIP + "/32", Scope: "host"},   // bindIP present, D1 artifact
	}}
	orig := brokerNetnsExecFn
	brokerNetnsExecFn = fk.exec
	defer func() { brokerNetnsExecFn = orig }()

	if err := s.SingleHomeRestoredPod(context.Background(), migration, ns, 4242, gc09WzhhqBindIP); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containsStr(fk.delCalls, gc09WzhhqHomeIP+"/24") || containsStr(fk.delCalls, gc09WzhhqBindIP+"/32") {
		t.Fatalf("neither bindIP nor homeIP may be stripped — delCalls=%v", fk.delCalls)
	}
}

// §P-VERIFY #2d (BLOCKING, D1f) — the terminal verify predicate accepts a legitimately-surviving
// bindIP that differs from homeIP; AC5 success (oldPresent) is keyed on homeIP.
func TestSingleHomeRestoredPod_D1f_VerifyAcceptsDivergentBindIP(t *testing.T) {
	const migration, ns = "adr0422-verify-union", "podmotion-test"
	pm := migrationWithSnapshot(migration, ns, gc09WzhhqHomeIP, gc09WzhhqBindIP)
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
	s := New("test-node", nil, cl)

	fk := &fakeEth0Broker{addrs: []eth0Addr{
		{CIDR: gc09WzhhqHomeIP + "/24", Scope: "global"},
		{CIDR: gc09WzhhqBindIP + "/32", Scope: "host"},
	}}
	orig := brokerNetnsExecFn
	brokerNetnsExecFn = fk.exec
	defer func() { brokerNetnsExecFn = orig }()

	if err := s.SingleHomeRestoredPod(context.Background(), migration, ns, 4242, gc09WzhhqBindIP); err != nil {
		t.Fatalf("expected nil (verify must accept the surviving bindIP artifact), got: %v", err)
	}
}

// §P-VERIFY #2e (BLOCKING, D1f) — the strip branch's derived gateway and reverse-path route key on
// homeIP, not bindIP, when they differ (the gc09/wzhhq shape: bindIP's /24 (10.42.2.0/24) differs
// from homeIP's /24 (10.42.1.0/24)). Only bindIP is present on eth0 (the D1 scope-host /32
// artifact) and it is never stripped, so no address in the loop can override cni0Gateway away from
// its homeIP fallback — this isolates the keying instead of merely being plausible: a broken
// implementation that keyed the gateway or reverse-path CIDR on bindIP instead of homeIP would
// install routes for 10.42.2.0/24 / gateway 10.42.2.1, and this test fails against it.
func TestSingleHomeRestoredPod_D1f_GatewayAndRouteKeyOnHomeIP(t *testing.T) {
	const migration, ns = "adr0422-gateway-homeip", "podmotion-test"
	pm := migrationWithSnapshot(migration, ns, gc09WzhhqHomeIP, gc09WzhhqBindIP)
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
	s := New("test-node", nil, cl)

	homeGateway := gatewayForIP(gc09WzhhqHomeIP) // "10.42.1.1" — the ONLY correct keying
	bindGateway := gatewayForIP(gc09WzhhqBindIP) // "10.42.2.1" — what a wrong bindIP-keyed impl would use
	homeCIDR := cidr24ForIP(gc09WzhhqHomeIP)     // "10.42.1.0/24"
	bindCIDR := cidr24ForIP(gc09WzhhqBindIP)     // "10.42.2.0/24"
	if homeGateway == bindGateway || homeCIDR == bindCIDR {
		t.Fatalf("fixture invalid — gc09WzhhqHomeIP and gc09WzhhqBindIP must derive DIFFERENT gateways/CIDRs for this test to discriminate correct keying (homeGateway=%s bindGateway=%s homeCIDR=%s bindCIDR=%s)", homeGateway, bindGateway, homeCIDR, bindCIDR)
	}

	fk := &fakeEth0Broker{addrs: []eth0Addr{
		{CIDR: gc09WzhhqBindIP + "/32", Scope: "host"}, // only the D1 bind artifact present; never stripped
	}}
	orig := brokerNetnsExecFn
	brokerNetnsExecFn = fk.exec
	defer func() { brokerNetnsExecFn = orig }()

	if err := s.SingleHomeRestoredPod(context.Background(), migration, ns, 4242, gc09WzhhqBindIP); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// homeIP itself must have been ADDED (it was not previously present at scope-global).
	if !containsStr(fk.addCalls, gc09WzhhqHomeIP+"/24") {
		t.Fatalf("expected homeIP/24 to be added (oldSeen must be homeIP-keyed) — addCalls=%v", fk.addCalls)
	}
	if !containsStr(fk.routeCalls, "ip route add "+homeGateway+" dev eth0") {
		t.Fatalf("expected the gateway link route to be installed via homeIP's gateway (%s) — routeCalls=%v", homeGateway, fk.routeCalls)
	}
	if containsStr(fk.routeCalls, "ip route add "+bindGateway+" dev eth0") {
		t.Fatalf("gateway link route must NOT be keyed on bindIP's gateway (%s) — routeCalls=%v", bindGateway, fk.routeCalls)
	}
	if !containsStr(fk.routeCalls, "ip route replace "+homeCIDR+" via "+homeGateway+" dev eth0") {
		t.Fatalf("expected the reverse-path route to be keyed on homeIP's /24 (%s) — routeCalls=%v", homeCIDR, fk.routeCalls)
	}
	if containsStr(fk.routeCalls, "ip route replace "+bindCIDR+" via "+homeGateway+" dev eth0") {
		t.Fatalf("reverse-path route must NOT be keyed on bindIP's /24 (%s) — routeCalls=%v", bindCIDR, fk.routeCalls)
	}
}

// §P-VERIFY #18 (BLOCKING, D1i) — SingleHomeRestoredPod uses the THREADED bindIP parameter, never
// an independent re-read: a stale/wrong CR-resident snapshot must not influence the outcome.
func TestSingleHomeRestoredPod_D1i_UsesThreadedParameterNotCRRead(t *testing.T) {
	const migration, ns = "adr0422-threaded-not-reread", "podmotion-test"
	// CR carries a DIFFERENT (stale) snapshot than the threaded parameter.
	pm := migrationWithSnapshot(migration, ns, gc09WzhhqHomeIP, "10.99.99.99")
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
	s := New("test-node", nil, cl)

	// eth0 carries the THREADED bindIP's /32 artifact, not the stale CR snapshot's.
	fk := &fakeEth0Broker{addrs: []eth0Addr{
		{CIDR: "10.42.2.200/24", Scope: "global"}, // foreign primary -> dual-home branch
		{CIDR: gc09WzhhqBindIP + "/32", Scope: "host"},
	}}
	orig := brokerNetnsExecFn
	brokerNetnsExecFn = fk.exec
	defer func() { brokerNetnsExecFn = orig }()

	if err := s.SingleHomeRestoredPod(context.Background(), migration, ns, 4242, gc09WzhhqBindIP); err != nil {
		t.Fatalf("expected the dual-home branch to succeed against the THREADED bindIP (%s), not the stale CR snapshot: %v", gc09WzhhqBindIP, err)
	}
}

// §P-VERIFY #23 (BLOCKING, D1i5) — the idempotent-confirm path serves the LATCHED bindIP, never a
// fresh resolution: a latch of X followed by a CR/RPC state that would resolve to a DIFFERENT value
// Y must still yield X at finalizeRestore. A second case: no latch exists and
// checkpointHasEstablishedTCP is true — must fail closed with the exact D1i5 message the real RPC
// returns, not confirm with an empty bindIP.
// (§P-VERIFY #19 is folded into this assertion per ADR-0422 D1i5 —
// #19 as originally specified did not by itself distinguish a latch-read from the exact
// re-resolution behavior D1i5 forbids; this test's first sub-case is the discriminating version.)
func TestResolvedBindIP_D1i5_LatchServedNotReResolved(t *testing.T) {
	const migration = "adr0422-latch-not-reresolve"

	// latch_served_verbatim drives the SAME two production statements the idempotent-confirm
	// branch of Restore() executes (server.go: `bindIP, _ := s.resolveIdempotentConfirmBindIP(...)`
	// then `s.finalizeRestore(..., bindIP)`), following
	// TestSingleHomeRestoredPod_D1i_UsesThreadedParameterNotCRRead's exact pattern: construct a CR
	// whose snapshot address (Y) DIFFERS from the latched value (X), give eth0 only X's /32
	// artifact, and assert the value that actually reaches SingleHomeRestoredPod (via
	// finalizeRestore) is X, not Y. A non-compliant implementation that re-resolved via the CR
	// instead of serving the latch would hand SingleHomeRestoredPod the address Y — which is absent
	// from eth0 — and the dual-home branch would fail with "OLD IP absent from eth0" instead of
	// succeeding. This test FAILS against that forbidden implementation and PASSES against the
	// accepted one, closing the tautological-round-trip gap (ADR-0422 D1i5).
	t.Run("latch_served_verbatim", func(t *testing.T) {
		const ns = "podmotion-test"
		resolvedNetnsPathsMu.Lock()
		delete(resolvedNetnsPaths, migration)
		resolvedNetnsPathsMu.Unlock()

		const latchedX = gc09WzhhqBindIP      // the value actually latched by a prior successful restore
		const wouldReresolveY = "10.99.99.99" // what a FORBIDDEN re-resolution of the CR would return

		storeResolvedNetnsPath(migration, "/var/run/netns/cni-latch", "eth0")
		storeResolvedBindIP(migration, latchedX)

		// CR carries the DIVERGENT snapshot Y — present so a non-compliant re-resolving
		// implementation has something different to (wrongly) pick up.
		pm := migrationWithSnapshot(migration, ns, gc09WzhhqHomeIP, wouldReresolveY)
		cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
		s := New("test-node", nil, cl)

		// eth0 carries X's (latched) /32 artifact plus a foreign scope-global primary, so the
		// dual-home branch's oldPresent check only succeeds if the value actually used is X.
		fk := &fakeEth0Broker{addrs: []eth0Addr{
			{CIDR: "10.42.2.200/24", Scope: "global"}, // foreign primary -> dual-home branch
			{CIDR: latchedX + "/32", Scope: "host"},
		}}
		origBroker := brokerNetnsExecFn
		brokerNetnsExecFn = fk.exec
		defer func() { brokerNetnsExecFn = origBroker }()

		imagesDir := writeCheckpointWithTCP(t, true)

		gotBindIP, failClosedMsg := s.resolveIdempotentConfirmBindIP(migration, imagesDir)
		if failClosedMsg != "" {
			t.Fatalf("resolveIdempotentConfirmBindIP unexpectedly failed closed: %q", failClosedMsg)
		}
		if gotBindIP != latchedX {
			t.Fatalf("resolveIdempotentConfirmBindIP = %q, want the latched %q (not the CR's divergent %q)", gotBindIP, latchedX, wouldReresolveY)
		}

		if _, err := s.finalizeRestore(context.Background(), 4242, "/var/run/netns/cni-latch", "eth0", migration, ns, "BestEffort", imagesDir, gotBindIP); err != nil {
			t.Fatalf("finalizeRestore failed with the latched bindIP %q threaded through — a forbidden re-resolving implementation would have handed SingleHomeRestoredPod the CR's divergent %q, which is absent from eth0, and failed here instead: %v", latchedX, wouldReresolveY, err)
		}
	})

	// no_latch_established_tcp_checkpoint_fails_closed asserts the ACTUAL D1i5 fail-closed outcome
	// — the exact message text resolveIdempotentConfirmBindIP (and therefore the real RPC's
	// RestoreResponse.ErrorMessage) produces — not merely that its two preconditions are
	// individually true.
	t.Run("no_latch_established_tcp_checkpoint_fails_closed", func(t *testing.T) {
		const noLatchMigration = "adr0422-no-latch"
		resolvedNetnsPathsMu.Lock()
		delete(resolvedNetnsPaths, noLatchMigration)
		resolvedNetnsPathsMu.Unlock()

		s := &AgentServer{}
		imagesDir := writeCheckpointWithTCP(t, true)

		gotBindIP, failClosedMsg := s.resolveIdempotentConfirmBindIP(noLatchMigration, imagesDir)
		if gotBindIP != "" {
			t.Fatalf("resolveIdempotentConfirmBindIP bindIP = %q on the fail-closed path, want \"\"", gotBindIP)
		}
		wantMsg := fmt.Sprintf("Restore: idempotent confirm path — no latched bindIP for an established-TCP checkpoint (bind-prep result not in memory, possibly agent-restart loss); refusing to confirm without the address the prior restore actually programmed (ADR-0422 D1i5, fail-closed): %s", noLatchMigration)
		if failClosedMsg != wantMsg {
			t.Fatalf("resolveIdempotentConfirmBindIP failClosedMsg = %q, want the exact D1i5 message %q — this is the literal text the real RPC returns as RestoreResponse.ErrorMessage", failClosedMsg, wantMsg)
		}
	})
}

// §P-VERIFY #20 (BLOCKING, D1j) remains UNRUN and OWED. Quoted in full, #20 requires: "the agent
// starts without panicking when cluster.New() fails. A test (or a live run with cluster.New forced
// to error, e.g. an unreachable API server at startup) asserts cmd/agent/main.go reaches the
// <-ctx.Done() steady state — gRPC server started, NRI plugin started — rather than crashing on a
// nil-cl dereference when computing apiReader." This test does NOT drive cmd/agent/main.go and never
// reaches that steady state, so it does NOT discharge #20.
//
// What this test DOES establish — a real, useful, but distinct fact #20 presupposes rather than
// satisfies — is server.New's own construction contract for a nil apiReader value: reproducing the
// exact call shape at cmd/agent/main.go:487 (`server.New(nodeName, checkpointer, k8sClient,
// apiReader)` with both arguments at their client zero values, mirroring what the clErr != nil branch
// leaves them at) and asserting the resulting AgentServer genuinely carries a nil apiReader rather
// than synthesizing a non-nil one. That precondition is what
// TestResolvePreservedSourceIPAuthoritative_NilReaderFailsClosed's fail-closed logic assumes but does
// not itself prove is reachable through the real wiring — this test proves that reachability.
//
// A refactor of cmd/agent/main.go's main() to make cluster.New's failure branch itself unit-testable
// (e.g. extracting the guard into a standalone function) would be required to actually discharge #20
// (drive main() to <-ctx.Done() with cluster.New forced to fail) and is out of scope for this fix.
// #20 stays OWED until that refactor lands and a test exercises it.
func TestNew_NilAPIReaderWiring_D1j(t *testing.T) {
	// Mirrors cmd/agent/main.go's clErr != nil branch: k8sClient and apiReader both stay at their
	// zero values (nil), exactly as they do when cluster.New(cfg, ...) fails at agent startup.
	var k8sClient client.Client
	var apiReader client.Reader

	s := New("test-node", nil, k8sClient, apiReader)

	if s == nil {
		t.Fatal("server.New returned nil — D1j's guard must not crash agent construction on a nil apiReader")
	}
	if s.apiReader != nil {
		t.Fatalf("s.apiReader = %v, want nil — server.New must not synthesize a non-nil reader from a nil client.Reader argument", s.apiReader)
	}

	// Tie the wiring to D1g1a's fail-closed expectation end-to-end: the AgentServer produced by
	// this exact construction path must fail closed (non-nil error), never silently no-op, when an
	// established-TCP restore needs the authoritative reader.
	got, err := resolvePreservedSourceIPAuthoritative(context.Background(), s.apiReader, "podmotion-test", "some-migration")
	if err == nil {
		t.Fatalf("expected a non-nil fail-closed error via the real New(...) wiring, got (%q, nil)", got)
	}
	if !errors.Is(err, errNilAuthoritativeReader) {
		t.Fatalf("expected errors.Is(err, errNilAuthoritativeReader), got %v", err)
	}
}

// Arch-B + Security Reviewer finding 1 (blocking) — the two D2 corpus tests below correctly SKIP
// (not fail) when the host-local, gitignored gc09 corpus log is absent, but that means D2's soccr/
// scanner widening has ZERO exercised coverage on any other machine or in CI. This synthetic fixture
// test runs UNCONDITIONALLY (no skip): it writes a small multi-line string to t.TempDir() containing
// a soccr/soccr.c:499 "Can't bind inet socket back" line plus several criu/ "Error (" lines, and
// asserts the scanner correctly identifies the soccr line as the causal first error and that
// matchCount includes it. This is additive to, not a replacement for, the two real-corpus tests below
// (which remain a valuable bonus check whenever that corpus file happens to be present on disk).
func TestScanCRIURestoreLogForFirstError_D2_SoccrFamilySyntheticFixture(t *testing.T) {
	const synthetic = `(00.000123) Undumping process
(00.000789) Error (soccr/soccr.c:499): Can't bind inet socket back: Cannot assign requested address
(00.000999) Error (criu/files.c:1221): Unable to open fd=10 id=0xf
(00.001001) Error (criu/cr-restore.c:2324): Restoring FAILED.
(00.001002) Error (criu/cgroup.c:1998): cg: cgroupd: recv req error: No such file or directory
`
	dir := t.TempDir()
	logPath := dir + "/synthetic-restore.log"
	if err := os.WriteFile(logPath, []byte(synthetic), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	attr := scanCRIURestoreLogForFirstError(logPath)
	if !attr.found {
		t.Fatalf("expected found=true, got %+v", attr)
	}
	if !containsSubstr(attr.causeLine, "soccr/soccr.c:499") {
		t.Fatalf("causeLine = %q, want the soccr bind failure (soccr/soccr.c:499) identified as the causal first error, not the earlier criu/cr-restore.c:1234 line", attr.causeLine)
	}
	// 4 "Error (" lines total in the fixture: criu/cr-restore.c:1234, soccr/soccr.c:499,
	// criu/files.c:1221, criu/cr-restore.c:2324 — matchCount must include the soccr/ line (ADR-0422 D2).
	if attr.matchCount != 4 {
		t.Fatalf("matchCount = %d, want 4 (matchCount must include the soccr/ line)", attr.matchCount)
	}
}

// realGc09CorpusPath is the gc09 gate incident restore.log this ADR's D2 fix was derived from — 440
// lines, exactly 4 "Error (" lines (verified directly against the file, not trusted from the ADR's
// own citation of it). This file is HOST-LOCAL and gitignored (docs/SPRINT* in .gitignore matches
// docs/sprints/*.log), NOT committed to the repository — it is not guaranteed present in every
// checkout or CI run. Both tests below follow the repoRootForADR0420/adr0420_attribution_rekey_test.go
// pattern of skipping cleanly, rather than failing, when the corpus file is absent.
const realGc09CorpusPath = "../../../docs/sprints/gc09-gate-test-rv2tg-restore.log"

// §P-VERIFY #4 (D2) — the scanner's match is exercised against the real gc09 corpus file on disk
// (docs/sprints/gc09-gate-test-rv2tg-restore.log) when present, not a synthetic string: causeLine
// must be the soccr bind failure, not the criu/files.c wrapper frame. The corpus file is host-local
// and gitignored, so its absence is a skip, not a failure.
func TestScanCRIURestoreLogForFirstError_D2_SoccrFamilyAgainstRealCorpus(t *testing.T) {
	if _, err := os.Stat(realGc09CorpusPath); err != nil {
		t.Skip("gc09 corpus log is host-local and gitignored (docs/sprints/gc09-gate-test-rv2tg-restore.log) — not present in this checkout")
	}
	attr := scanCRIURestoreLogForFirstError(realGc09CorpusPath)
	if !attr.found {
		t.Fatalf("expected found=true, got %+v", attr)
	}
	if !containsSubstr(attr.causeLine, "soccr/soccr.c:499") {
		t.Fatalf("causeLine = %q, want the soccr bind failure (soccr/soccr.c:499), not the criu/files.c:1221 wrapper frame — the pre-D2 misattribution this ADR fixes", attr.causeLine)
	}
}

// §P-VERIFY #5 (D2) — matchCount is accurate post-D2 against the real gc09 corpus file when present:
// the real 440-line file contains exactly 4 "Error (" lines (soccr/soccr.c:499 + 3 criu/ lines), so
// matchCount must be 4 (was 3 pre-D2, excluding the soccr/ root cause). The corpus file is host-local
// and gitignored, so its absence is a skip, not a failure.
func TestScanCRIURestoreLogForFirstError_D2_MatchCountIncludesSoccr(t *testing.T) {
	if _, err := os.Stat(realGc09CorpusPath); err != nil {
		t.Skip("gc09 corpus log is host-local and gitignored (docs/sprints/gc09-gate-test-rv2tg-restore.log) — not present in this checkout")
	}
	attr := scanCRIURestoreLogForFirstError(realGc09CorpusPath)
	if attr.matchCount != 4 {
		t.Fatalf("matchCount = %d, want 4 (soccr/soccr.c:499 + 3 criu/ lines) against the real gc09 corpus file", attr.matchCount)
	}
}

func containsSubstr(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}

// Security Reviewer finding 3(b) — no test previously constructed a stale/wrong k8sClient
// alongside a working apiReader and confirmed the NRI resolution path (JoinNsRestore's D1a item 2
// call to resolvePreservedSourceIPAuthoritative) actually reads via s.apiReader, never s.k8sClient
// (server.go's own comment on that call site: "never s.k8sClient, which races the controller's
// Status.TCPSeqSnapshots write"). This test wires a k8sClient that carries NO PodMigration for this
// migration at all (so a wrong implementation reading via k8sClient would resolve to "", a real
// no-op) and an apiReader that DOES carry one, with a distinguishing snapshot IP — proving the
// resolved preservedSourceIP threaded into joinNsRestoreFn came from the apiReader.
func TestJoinNsRestore_NRIPath_UsesAPIReaderNotStaleK8sClient(t *testing.T) {
	const migration = "adr0422-apireader-not-stale-k8sclient"
	const namespace = "podmotion-test"
	const correctBindIP = "10.42.9.9" // present ONLY in the apiReader's copy of the CR

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	// The replacement pod ADR-0419's mount resolution looks up via s.k8sClient — present there,
	// unrelated to the preserved-source-IP resolution under test.
	replPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "adr0422-apireader-src-r",
			Namespace: namespace,
			UID:       types.UID("apireader-not-stale-repl-uid"),
			Labels:    map[string]string{replacementPodLabelKey: migration},
		},
	}
	// The STALE k8sClient carries NO PodMigration object for this migration at all — a wrong
	// implementation reading the preserved source IP via s.k8sClient would resolve "" (a
	// distinguishable, wrong outcome from the apiReader's real value).
	staleK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(replPod).Build()

	// The apiReader carries the REAL PodMigration with a snapshot IP.
	pm := migrationWithSnapshot(migration, namespace, "", correctBindIP)
	workingAPIReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()

	s := New("test-node", &criu.StubCheckpointer{}, staleK8sClient, workingAPIReader)

	s.destWorkloadImageMu.Lock()
	s.destWorkloadImage[migration] = "docker.io/library/redis:7-alpine"
	s.destWorkloadImageMu.Unlock()

	origMAC := readReplVethMACFn
	readReplVethMACFn = func(context.Context, int, string, string) (string, error) { return "aa:bb:cc:dd:ee:ff", nil }
	defer func() { readReplVethMACFn = origMAC }()

	var gotPreservedSourceIP string
	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, _, _, _, _, _, _, _ string, _ bool, _ []reattachMount, _, _, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error) {
		gotPreservedSourceIP = preservedSourceIP
		return 88888, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	_, _, err := s.JoinNsRestore(context.Background(), migration, namespace, "/tmp/fake-checkpoint", "", "", "", "", "", "None", nil)
	if err != nil {
		t.Fatalf("JoinNsRestore returned unexpected error: %v", err)
	}
	if gotPreservedSourceIP != correctBindIP {
		t.Fatalf("preservedSourceIP threaded to joinNsRestoreFn = %q, want %q (the apiReader's value) — the NRI resolution path must never read via the stale s.k8sClient", gotPreservedSourceIP, correctBindIP)
	}
}

// Security Reviewer finding 3(c) — resolveNamespaceForMigrationE (the D1g1 error-propagating
// sibling of resolveNamespaceForMigration) had zero test coverage. Covers: nil k8sClient (real
// no-op), empty migrationName (real no-op), a successful "default"-namespace Get, a successful
// List-based match in a NON-default namespace, a genuinely-not-found migration (real no-op, not an
// error), and a List failure (must surface as a distinguishable error, not collapse to "").
func TestResolveNamespaceForMigrationE(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}

	t.Run("nil_k8sClient_is_real_noop", func(t *testing.T) {
		s := New("test-node", nil, nil)
		ns, err := s.resolveNamespaceForMigrationE(context.Background(), "some-migration")
		if err != nil || ns != "" {
			t.Fatalf("resolveNamespaceForMigrationE(nil client) = (%q, %v), want (\"\", nil)", ns, err)
		}
	})

	t.Run("empty_migrationName_is_real_noop", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()
		s := New("test-node", nil, cl)
		ns, err := s.resolveNamespaceForMigrationE(context.Background(), "")
		if err != nil || ns != "" {
			t.Fatalf("resolveNamespaceForMigrationE(\"\") = (%q, %v), want (\"\", nil)", ns, err)
		}
	})

	t.Run("found_via_default_namespace_get", func(t *testing.T) {
		const migration = "adr0422-ns-default-get"
		pm := &pmv1.PodMigration{ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: "default"}}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).Build()
		s := New("test-node", nil, cl)
		ns, err := s.resolveNamespaceForMigrationE(context.Background(), migration)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ns != "default" {
			t.Fatalf("resolveNamespaceForMigrationE = %q, want \"default\"", ns)
		}
	})

	t.Run("found_via_list_in_nondefault_namespace", func(t *testing.T) {
		const migration = "adr0422-ns-list-match"
		pm := &pmv1.PodMigration{ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: "podmotion-test"}}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).Build()
		s := New("test-node", nil, cl)
		ns, err := s.resolveNamespaceForMigrationE(context.Background(), migration)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ns != "podmotion-test" {
			t.Fatalf("resolveNamespaceForMigrationE = %q, want \"podmotion-test\" (found via the List fallback)", ns)
		}
	})

	t.Run("genuinely_not_found_is_real_noop", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()
		s := New("test-node", nil, cl)
		ns, err := s.resolveNamespaceForMigrationE(context.Background(), "no-such-migration")
		if err != nil || ns != "" {
			t.Fatalf("resolveNamespaceForMigrationE(not found) = (%q, %v), want (\"\", nil) — a genuinely-absent migration is a real no-op, not an error", ns, err)
		}
	})

	t.Run("list_failure_surfaces_as_distinguishable_error", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).
			WithInterceptorFuncs(interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					return errors.New("stub: injected List failure")
				},
			}).Build()
		s := New("test-node", nil, cl)
		ns, err := s.resolveNamespaceForMigrationE(context.Background(), "adr0422-ns-list-failure")
		if err == nil {
			t.Fatal("expected a non-nil error on injected List failure, got nil")
		}
		if ns != "" {
			t.Fatalf("resolveNamespaceForMigrationE on List failure returned ns=%q, want \"\"", ns)
		}
	})
}

// Security Reviewer finding 3(d) — every pre-existing ADR-0422 test drove an established-TCP
// checkpoint. These three tests cover the CONNECTIONLESS/no-TCP no-op case at each of the three
// new fail-closed call sites this ADR introduced (JoinNsRestore's NRI path, and both gRPC Restore
// branches): a genuine, transient preserved-source-IP resolution failure (here, a nil apiReader —
// errNilAuthoritativeReader) on a checkpoint with NO tcp-stream-*.img file must NOT hard-abort the
// restore — it must proceed with an empty preservedSourceIP (checkpointHasEstablishedTCP-scoped
// no-op), never surface the resolution error to the caller.
func TestJoinNsRestore_D1g2_NoEstablishedTCP_ResolutionFailureIsNoOp(t *testing.T) {
	const migration = "adr0422-d1g2-joinns-notcp-noop"

	origMAC := readReplVethMACFn
	readReplVethMACFn = func(context.Context, int, string, string) (string, error) { return "aa:bb:cc:dd:ee:ff", nil }
	defer func() { readReplVethMACFn = origMAC }()

	var gotPreservedSourceIP string
	joinCalled := false
	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, _, _, _, _, _, _, _ string, _ bool, _ []reattachMount, _, _, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error) {
		joinCalled = true
		gotPreservedSourceIP = preservedSourceIP
		return 77777, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	// s.apiReader is nil (New called with no variadic apiReader arg) — resolvePreservedSourceIPAuthoritative
	// fails closed with errNilAuthoritativeReader. checkpointDir does not exist, so
	// checkpointHasEstablishedTCP finds no tcp-stream-*.img and returns false (CONNECTIONLESS/no-TCP).
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	s.destWorkloadImageMu.Lock()
	s.destWorkloadImage[migration] = "docker.io/library/redis:7-alpine"
	s.destWorkloadImageMu.Unlock()

	_, _, err := s.JoinNsRestore(context.Background(), migration, "default", "/tmp/adr0422-nonexistent-checkpoint-dir", "", "", "", "", "", "None", nil)
	if err != nil {
		t.Fatalf("JoinNsRestore returned an error on a resolution failure with NO established TCP — expected a scoped no-op, got: %v", err)
	}
	if !joinCalled {
		t.Fatal("joinNsRestoreFn was never called — the restore hard-aborted instead of proceeding as a scoped no-op")
	}
	if gotPreservedSourceIP != "" {
		t.Fatalf("preservedSourceIP = %q, want \"\" (resolution failed and there is no established TCP to preserve)", gotPreservedSourceIP)
	}
}

func TestRestoreBranch1_D1g2_NoEstablishedTCP_ResolutionFailureIsNoOp(t *testing.T) {
	imagesDir := makeBranch1Dir(t) // config.json branch; no tcp-stream-*.img present

	var gotPreservedSourceIP string
	joinCalled := false
	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, _, _, _, _, _, _, _ string, _ bool, _ []reattachMount, _, _, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error) {
		joinCalled = true
		gotPreservedSourceIP = preservedSourceIP
		return 66666, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	origMAC := readReplVethMACFn
	readReplVethMACFn = func(context.Context, int, string, string) (string, error) { return "aa:bb:cc:dd:ee:ff", nil }
	defer func() { readReplVethMACFn = origMAC }()

	// s.k8sClient is nil, so resolveNamespaceForMigrationE is a real no-op (nsErr==nil, ns=="").
	// s.apiReader is then nil too — resolvePreservedSourceIPAuthoritative fails closed with
	// errNilAuthoritativeReader, and imagesDir has no tcp-stream-*.img, so this must be a no-op.
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	resp, err := s.Restore(context.Background(), &agentpb.RestoreRequest{
		MigrationName: "test-branch1-d1g2-notcp-noop",
		CheckpointRef: imagesDir,
	})
	if err != nil {
		t.Fatalf("Restore (Branch 1) returned an error on a resolution failure with NO established TCP — expected a scoped no-op, got: %v", err)
	}
	if resp == nil || !resp.Success {
		t.Fatalf("Restore (Branch 1) expected Success=true, got resp=%v", resp)
	}
	if !joinCalled {
		t.Fatal("joinNsRestoreFn was never called — the restore hard-aborted instead of proceeding as a scoped no-op")
	}
	if gotPreservedSourceIP != "" {
		t.Fatalf("preservedSourceIP = %q, want \"\" (resolution failed and there is no established TCP to preserve)", gotPreservedSourceIP)
	}
}

func TestRestoreBranch2_D1g2_NoEstablishedTCP_ResolutionFailureIsNoOp(t *testing.T) {
	imagesDir := makeBranch2Dir(t) // raw-CRIU fallback branch; no tcp-stream-*.img present

	var gotPreservedSourceIP string
	joinCalled := false
	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, _, _, _, _, _, _, _ string, _ bool, _ []reattachMount, _, _, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error) {
		joinCalled = true
		gotPreservedSourceIP = preservedSourceIP
		return 55555, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	origMAC := readReplVethMACFn
	readReplVethMACFn = func(context.Context, int, string, string) (string, error) { return "aa:bb:cc:dd:ee:ff", nil }
	defer func() { readReplVethMACFn = origMAC }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	resp, err := s.Restore(context.Background(), &agentpb.RestoreRequest{
		MigrationName: "test-branch2-d1g2-notcp-noop",
		CheckpointRef: imagesDir,
	})
	if err != nil {
		t.Fatalf("Restore (Branch 2) returned an error on a resolution failure with NO established TCP — expected a scoped no-op, got: %v", err)
	}
	if resp == nil || !resp.Success {
		t.Fatalf("Restore (Branch 2) expected Success=true, got resp=%v", resp)
	}
	if !joinCalled {
		t.Fatal("joinNsRestoreFn was never called — the restore hard-aborted instead of proceeding as a scoped no-op")
	}
	if gotPreservedSourceIP != "" {
		t.Fatalf("preservedSourceIP = %q, want \"\" (resolution failed and there is no established TCP to preserve)", gotPreservedSourceIP)
	}
}

// Security Reviewer finding 3(e) — emitPreservedSourceIPUnresolvedEvent and
// emitBindIPWithoutHomeIPEvent had zero test coverage. Confirm each emits the expected Kubernetes
// Event type/reason/message on the PodMigration CR.
func TestEmitPreservedSourceIPUnresolvedEvent_EmitsWarningEvent(t *testing.T) {
	const migration = "adr0422-emit-unresolved-event"
	const namespace = "podmotion-test"

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	pm := &pmv1.PodMigration{ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: namespace}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).Build()
	s := New("test-node", nil, cl)

	resolveErr := errors.New("stub: injected resolution failure")
	s.emitPreservedSourceIPUnresolvedEvent(context.Background(), migration, resolveErr)

	events := &corev1.EventList{}
	if err := s.k8sClient.List(context.Background(), events); err != nil {
		t.Fatalf("list Events: %v", err)
	}
	found := false
	for _, ev := range events.Items {
		if ev.Reason == "PreservedSourceIPUnresolved" && ev.InvolvedObject.Name == migration && ev.Type == corev1.EventTypeWarning &&
			containsSubstr(ev.Message, resolveErr.Error()) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a Warning PreservedSourceIPUnresolved Event on PodMigration %q carrying the resolve error, got events=%+v", migration, events.Items)
	}
}

func TestEmitBindIPWithoutHomeIPEvent_EmitsWarningEvent(t *testing.T) {
	const migration = "adr0422-emit-bindip-without-homeip-event"
	const namespace = "podmotion-test"

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	pm := &pmv1.PodMigration{ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: namespace}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).Build()
	s := New("test-node", nil, cl)

	bhErr := &BindIPWithoutHomeIPError{BindIP: gc09WzhhqBindIP}
	s.emitBindIPWithoutHomeIPEvent(context.Background(), migration, bhErr)

	events := &corev1.EventList{}
	if err := s.k8sClient.List(context.Background(), events); err != nil {
		t.Fatalf("list Events: %v", err)
	}
	found := false
	for _, ev := range events.Items {
		if ev.Reason == "BindIPWithoutHomeIP" && ev.InvolvedObject.Name == migration && ev.Type == corev1.EventTypeWarning &&
			ev.Message == bhErr.Error() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a Warning BindIPWithoutHomeIP Event on PodMigration %q with the exact D1f-R4a message, got events=%+v", migration, events.Items)
	}
}
