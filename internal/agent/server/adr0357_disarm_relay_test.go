/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

// adr0357_disarm_relay_test.go — ADR-0357 D5 / AC7 regression coverage, AND the mandatory
// Security Reviewer round-2 CONDITION carried forward from ADR-0357's approval review: a non-nil,
// non-ErrKeyNotExist DisarmRelay error inside DisarmTCRedirect must never be silently
// swallowed. This file drives DisarmTCRedirect's REAL handler code (not a re-implementation)
// against a fake k8sClient + a mock EBPFManager, covering both the happy path (D5's own
// removal-symmetry mechanism) and the fault-injection path the CONDITION requires (a NEW test
// specifically injecting a DisarmRelay failure to verify it is actually handled, not just the
// happy path).

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/network"
	"github.com/podmotion-io/podmotion/internal/metrics"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// disarmRelayStub is a minimal network.EBPFManager whose DisarmRelay is fully scripted: it
// records every key it is called with and returns disarmErr (nil for the happy path). All
// other methods are no-op stubs — DisarmTCRedirect's D5 step is the only one exercised here.
type disarmRelayStub struct {
	network.EBPFManager // nil-embedded on purpose — panics loudly if any unstubbed method is
	// reached, so this test never silently exercises unrelated eBPF behavior.
	disarmErr   error
	disarmCalls []network.SeqXlatKey
}

func (d *disarmRelayStub) DisarmRelay(_ context.Context, key network.SeqXlatKey) error {
	d.disarmCalls = append(d.disarmCalls, key)
	return d.disarmErr
}

// newDisarmTCRedirectFixture builds a fake AgentServer + PodMigration CR with one
// TCPSeqSnapshot entry (so DisarmTCRedirect's D5 step has exactly one PM_SEQ_XLAT entry to
// disarm) and a scheme that includes BOTH pmv1 (for the CR lookup) and corev1 (for the
// DisarmRelayFailed Event this test asserts on — newFakeAgentServerWithPM's scheme, used
// elsewhere in this package, does not register corev1).
func newDisarmTCRedirectFixture(t *testing.T, migrationName string, ebpfMgr network.EBPFManager) (*AgentServer, *pmv1.PodMigration) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migrationName, Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "redis-src",
			PodNamespace: "default",
		},
		Status: pmv1.PodMigrationStatus{
			TCPSeqSnapshots: []pmv1.TCPSeqSnapshot{
				{SrcIP: "10.0.0.9", SrcPort: 6379, DstIP: "10.0.0.1", DstPort: 40000, SndNxt: 100, RcvNxt: 200},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).Build()
	s := New("test-node", &criu.StubCheckpointer{}, fakeClient)
	s.ebpfMgr = ebpfMgr
	return s, pm
}

// TestDisarmTCRedirect_DisarmRelay_HappyPath is the AC7 mechanism check: DisarmTCRedirect
// calls DisarmRelay for the migration's PM_SEQ_XLAT entry (reconstructed from
// pm.Status.TCPSeqSnapshots via s.lookupPodMigration, exactly as D5 specifies) and the RPC
// completes successfully with no error surfaced.
func TestDisarmTCRedirect_DisarmRelay_HappyPath(t *testing.T) {
	mock := &disarmRelayStub{}
	s, pm := newDisarmTCRedirectFixture(t, "d5-happy", mock)

	before := testutil.ToFloat64(metrics.DisarmRelayFailedTotal.WithLabelValues(pm.Name, pm.Namespace))

	resp, err := s.DisarmTCRedirect(context.Background(), &agentpb.DisarmTCRedirectRequest{
		MigrationName: pm.Name,
	})
	if err != nil {
		t.Fatalf("DisarmTCRedirect returned unexpected RPC error: %v", err)
	}
	if resp == nil || !resp.Disarmed {
		t.Fatalf("expected Disarmed=true, got resp=%v", resp)
	}
	if len(mock.disarmCalls) != 1 {
		t.Fatalf("expected DisarmRelay to be called exactly once (one TCPSeqSnapshot entry), got %d calls", len(mock.disarmCalls))
	}

	after := testutil.ToFloat64(metrics.DisarmRelayFailedTotal.WithLabelValues(pm.Name, pm.Namespace))
	if after != before {
		t.Fatalf("DisarmRelayFailedTotal must NOT increment on the happy path: before=%v after=%v", before, after)
	}
}

// TestDisarmTCRedirect_DisarmRelay_FailureIsHandled is the MANDATORY Security Reviewer
// round-2 CONDITION regression: a non-nil, non-ErrKeyNotExist DisarmRelay error must not be
// silently swallowed. Per ADR-0357 D5's own explicit disposition (warn-only, matching D3's
// ADR-0224 3h-SYM posture — the same non-fatal pattern this handler's other teardown steps
// already use, so a PM_SEQ_XLAT entry that fails to disarm does not block IP reclaim), this
// asserts option (b) of the condition: DisarmTCRedirect stays non-fatal (RPC still succeeds),
// but the failure is made operator-visible via BOTH a distinct Warning Event
// ("DisarmRelayFailed") on the PodMigration CR and the DisarmRelayFailedTotal counter — never
// just a discarded error.
func TestDisarmTCRedirect_DisarmRelay_FailureIsHandled(t *testing.T) {
	injectedErr := errors.New("injected: bpf map delete failed")
	mock := &disarmRelayStub{disarmErr: injectedErr}
	s, pm := newDisarmTCRedirectFixture(t, "d5-fail", mock)

	before := testutil.ToFloat64(metrics.DisarmRelayFailedTotal.WithLabelValues(pm.Name, pm.Namespace))

	resp, err := s.DisarmTCRedirect(context.Background(), &agentpb.DisarmTCRedirectRequest{
		MigrationName: pm.Name,
	})

	// (1) Non-fatal: matches D5's explicit warn-only disposition and D3's existing pattern in
	// this same handler (tc filter/qdisc/FORWARD-ACCEPT removal are all warn-only already) — a
	// DisarmRelay failure must not block the rest of DisarmTCRedirect's teardown or the RPC's
	// own success, since the controller's ipReclaimEligible gate already proved no live traffic
	// can reach the OLD 4-tuple.
	if err != nil {
		t.Fatalf("DisarmTCRedirect must stay non-fatal on a DisarmRelay failure (ADR-0357 D5 warn-only posture), got RPC error: %v", err)
	}
	if resp == nil || !resp.Disarmed {
		t.Fatalf("expected Disarmed=true even when DisarmRelay failed (non-fatal by design), got resp=%v", resp)
	}
	if len(mock.disarmCalls) != 1 {
		t.Fatalf("expected DisarmRelay to have been attempted once, got %d calls", len(mock.disarmCalls))
	}

	// (2) Operator-visible via metric: the Security Reviewer condition's alertable signal.
	after := testutil.ToFloat64(metrics.DisarmRelayFailedTotal.WithLabelValues(pm.Name, pm.Namespace))
	if after != before+1 {
		t.Fatalf("DisarmRelayFailedTotal{migration=%q} = %v after an injected DisarmRelay failure, want %v (before=%v) — "+
			"the failure was NOT made operator-visible via the counter", pm.Name, after, before+1, before)
	}

	// (3) Operator-visible via a distinct Kubernetes Event: never just a discarded/logged error.
	events := &corev1.EventList{}
	if listErr := s.k8sClient.List(context.Background(), events); listErr != nil {
		t.Fatalf("list Events: %v", listErr)
	}
	found := false
	for _, ev := range events.Items {
		if ev.Reason == "DisarmRelayFailed" && ev.InvolvedObject.Name == pm.Name && ev.Type == corev1.EventTypeWarning {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a Warning DisarmRelayFailed Event on PodMigration %q, got events=%+v", pm.Name, events.Items)
	}
}

// TestDisarmTCRedirect_DisarmRelay_ErrKeyNotExistIsNotAFailure confirms an already-gone entry
// (network.DisarmRelayForSnapshots filters ebpf.ErrKeyNotExist before it ever reaches
// DisarmTCRedirect) does not trip the failure-visibility path — it is not a partial failure,
// it is the expected idempotent outcome.
func TestDisarmTCRedirect_DisarmRelay_ErrKeyNotExistIsNotAFailure(t *testing.T) {
	mock := &disarmRelayStub{disarmErr: ebpf.ErrKeyNotExist}
	s, pm := newDisarmTCRedirectFixture(t, "d5-notexist", mock)

	before := testutil.ToFloat64(metrics.DisarmRelayFailedTotal.WithLabelValues(pm.Name, pm.Namespace))

	resp, err := s.DisarmTCRedirect(context.Background(), &agentpb.DisarmTCRedirectRequest{
		MigrationName: pm.Name,
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp == nil || !resp.Disarmed {
		t.Fatalf("expected Disarmed=true, got resp=%v", resp)
	}

	after := testutil.ToFloat64(metrics.DisarmRelayFailedTotal.WithLabelValues(pm.Name, pm.Namespace))
	if after != before {
		t.Fatalf("DisarmRelayFailedTotal must NOT increment for ErrKeyNotExist (idempotent, not a failure): before=%v after=%v", before, after)
	}
}
