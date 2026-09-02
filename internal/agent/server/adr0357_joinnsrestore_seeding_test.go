/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

// adr0357_joinnsrestore_seeding_test.go — ADR-0357 D2 / AC3 regression coverage: PM_SEQ_XLAT
// seeding must fire from within JoinNsRestore (the NRI path this migration actually takes),
// sourced via s.lookupPodMigration reading pm.Status.TCPSeqSnapshots, using
// discoverHostInterface for relayIfname (never a "flannel.1" literal), and writing
// Status.SeqXlatSeeded=true only after a verified seed.

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/network"
)

// trackingRelayManager is a minimal, fully-scripted network.EBPFManager that behaves like a
// real kernel map for ArmRelay/LookupSeqXlat (round-trips whatever ArmRelay wrote) so
// network.SeedRelayFromSnapshots' D1.2 verification step succeeds — the same fixture shape as
// recordingEBPFStub in the network package's own tests, reimplemented here because that type is
// unexported to its package.
type trackingRelayManager struct {
	network.EBPFManager // nil-embedded — panics loudly on any unstubbed method call.
	seqXlat             map[network.SeqXlatKey]network.SeqXlatEntry
	armedIfnames        []string
}

func (t *trackingRelayManager) ArmRelay(_ context.Context, ifname string, key network.SeqXlatKey, entry network.SeqXlatEntry) error {
	if t.seqXlat == nil {
		t.seqXlat = make(map[network.SeqXlatKey]network.SeqXlatEntry)
	}
	t.seqXlat[key] = entry
	t.armedIfnames = append(t.armedIfnames, ifname)
	return nil
}

func (t *trackingRelayManager) LookupSeqXlat(_ context.Context, key network.SeqXlatKey) (network.SeqXlatEntry, bool, error) {
	e, ok := t.seqXlat[key]
	return e, ok, nil
}

func (t *trackingRelayManager) DisarmRelay(_ context.Context, key network.SeqXlatKey) error {
	delete(t.seqXlat, key)
	return nil
}

// TestJoinNsRestore_SeedsPMSeqXlat_NRIPath is the ADR-0357 D2/AC3 mechanism check: a
// PodMigration CR with non-empty Status.TCPSeqSnapshots drives JoinNsRestore to call
// SeedRelayFromSnapshots inline (NOT via the Restore RPC — joinNsRestoreFn is stubbed and
// asserted called exactly once, proving no second CRIU restore is triggered), resolve
// relayIfname via discoverHostInterface (never "flannel.1"), and write
// Status.SeqXlatSeeded=true only after the seed is verified.
func TestJoinNsRestore_SeedsPMSeqXlat_NRIPath(t *testing.T) {
	const migration = "test-nri-seed-migration"
	const namespace = "default"

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: namespace},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "redis-src",
			PodNamespace: namespace,
		},
		Status: pmv1.PodMigrationStatus{
			TCPSeqSnapshots: []pmv1.TCPSeqSnapshot{
				{SrcIP: "10.244.1.9", SrcPort: 6379, DstIP: "10.244.0.1", DstPort: 40000, SndNxt: 100, RcvNxt: 200},
			},
		},
	}
	// ADR-0417: the NRI restore path resolves Class DESTINATION-REBIND targets from the replacement
	// pod (its UID keys the kubelet pod dir and its containerd sandbox). Production always has one by
	// the time restore runs — the controller creates it and stamps the migration-name label — so the
	// fixture carries one too. Without it this test would exercise a state the live path never
	// reaches. The host-environment seams are stubbed package-wide in TestMain
	// (adr0417_destination_rebind_test.go).
	replPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "redis-src-r-seed",
			Namespace: namespace,
			UID:       types.UID("seed-repl-uid"),
			Labels:    map[string]string{replacementPodLabelKey: migration},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, replPod).WithStatusSubresource(pm).Build()

	s := New("test-node", &criu.StubCheckpointer{}, fakeClient)
	mock := &trackingRelayManager{}
	s.ebpfMgr = mock

	// Avoid a real CRIU subprocess — stub joinNsRestoreFn like every other JoinNsRestore test in
	// this package (restore_path_parity_test.go, restore_inflight_ownership_test.go).
	origJoin := joinNsRestoreFn
	joinCalls := 0
	joinNsRestoreFn = func(_ context.Context, _, _, _, _, _, _, _ string, _ bool, _ []reattachMount, _, _, _ string) (int, []ExternalMountDroppedInfo, error) {
		joinCalls++
		return 55555, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	origMAC := readReplVethMACFn
	readReplVethMACFn = func(context.Context, int, string, string) (string, error) { return "aa:bb:cc:dd:ee:ff", nil }
	defer func() { readReplVethMACFn = origMAC }()

	// ADR-0215/ADR-0217 fail-close: JoinNsRestore needs a resolvable workload image before it
	// will call joinNsRestoreFn (see TestJoinNsRestore_ReturnsMACToCaller for the same seam).
	s.destWorkloadImageMu.Lock()
	s.destWorkloadImage[migration] = "docker.io/library/redis:7-alpine"
	s.destWorkloadImageMu.Unlock()

	_, _, err := s.JoinNsRestore(context.Background(), migration, namespace, "/tmp/fake-checkpoint", "", "", "", "", "", "None")
	if err != nil {
		t.Fatalf("JoinNsRestore returned unexpected error: %v", err)
	}
	if joinCalls != 1 {
		t.Fatalf("expected joinNsRestoreFn (the ONE CRIU restore) called exactly once, got %d — a second call would mean D2 triggered a second CRIU restore, which it must never do", joinCalls)
	}

	// D2 mechanism: SeedRelayFromSnapshots fired inline (ArmRelay observed).
	if len(mock.armedIfnames) != 1 {
		t.Fatalf("expected ArmRelay called once (one TCPSeqSnapshot entry) via the NRI path, got %d calls", len(mock.armedIfnames))
	}

	// D2.4: relayIfname resolved via discoverHostInterface — never the "flannel.1" literal.
	if mock.armedIfnames[0] == "flannel.1" {
		t.Fatalf("relayIfname resolved to the literal \"flannel.1\" — D2.4 requires discoverHostInterface, no CNI-literal fallback")
	}
	if mock.armedIfnames[0] == "" {
		t.Fatal("relayIfname resolved to empty string")
	}

	// D2.3: Status.SeqXlatSeeded=true written only after the verified seed.
	got := &pmv1.PodMigration{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: migration, Namespace: namespace}, got); err != nil {
		t.Fatalf("get PodMigration: %v", err)
	}
	if !got.Status.SeqXlatSeeded {
		t.Fatal("expected Status.SeqXlatSeeded=true after a verified NRI-path seed, got false")
	}
}

// TestJoinNsRestore_SeedFailure_FailsClosed is the D2.2 fault-injection regression: when
// SeedRelayFromSnapshots fails (here, LookupSeqXlat verification never round-trips because the
// mock's ArmRelay is scripted to error), JoinNsRestore must return an error — the NRI callback
// then returns an error, containerd marks the replacement container failed, and the operator
// requeues/rolls back (ADR-0144 NB-2) — never silently proceed as if seeding succeeded.
func TestJoinNsRestore_SeedFailure_FailsClosed(t *testing.T) {
	const migration = "test-nri-seed-failure"
	const namespace = "default"

	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: namespace},
		Spec: pmv1.PodMigrationSpec{
			PodName:      "redis-src",
			PodNamespace: namespace,
		},
		Status: pmv1.PodMigrationStatus{
			TCPSeqSnapshots: []pmv1.TCPSeqSnapshot{
				{SrcIP: "10.244.1.9", SrcPort: 6379, DstIP: "10.244.0.1", DstPort: 40000, SndNxt: 100, RcvNxt: 200},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).WithStatusSubresource(pm).Build()

	s := New("test-node", &criu.StubCheckpointer{}, fakeClient)
	s.ebpfMgr = &failingArmRelayManager{err: errors.New("injected: ArmRelay failed")}

	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, _, _, _, _, _, _, _ string, _ bool, _ []reattachMount, _, _, _ string) (int, []ExternalMountDroppedInfo, error) {
		return 55555, nil, nil
	}
	defer func() { joinNsRestoreFn = origJoin }()

	origMAC := readReplVethMACFn
	readReplVethMACFn = func(context.Context, int, string, string) (string, error) { return "aa:bb:cc:dd:ee:ff", nil }
	defer func() { readReplVethMACFn = origMAC }()

	s.destWorkloadImageMu.Lock()
	s.destWorkloadImage[migration] = "docker.io/library/redis:7-alpine"
	s.destWorkloadImageMu.Unlock()

	_, _, err := s.JoinNsRestore(context.Background(), migration, namespace, "/tmp/fake-checkpoint", "", "", "", "", "", "None")
	if err == nil {
		t.Fatal("expected JoinNsRestore to fail closed when SeedRelayFromSnapshots fails, got nil error")
	}

	got := &pmv1.PodMigration{}
	if getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: migration, Namespace: namespace}, got); getErr != nil {
		t.Fatalf("get PodMigration: %v", getErr)
	}
	if got.Status.SeqXlatSeeded {
		t.Fatal("Status.SeqXlatSeeded must remain false when seeding failed — never report a false success")
	}
}

// failingArmRelayManager: ArmRelay always errors (simulates the ArmRelay-Update-itself-fails
// class of D2.2 failure, distinct from the LookupSeqXlat-verification-fails class already
// covered at the network-package level by TestSeedRelayFromSnapshots_LookupVerificationFailure).
type failingArmRelayManager struct {
	network.EBPFManager
	err error
}

func (f *failingArmRelayManager) ArmRelay(context.Context, string, network.SeqXlatKey, network.SeqXlatEntry) error {
	return f.err
}
