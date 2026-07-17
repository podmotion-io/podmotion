// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 The PodMotion Authors

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These tests pin the ADR-0325 restore-gate bounded wait for the replacement pod's real sandbox
// netns — the security-lens fix for the sprint46B2 live-proof-cycle1 failure. Root cause (grounded
// on the KVM substrate, pm-w2 agent log 2026-07-13T15:11:54Z): a one-shot ctr lookup
// (sandboxIDForPodUID) fired at restore-dispatch while the destination kubelet had not yet created
// the NodeName-pinned replacement pod's containerd sandbox, so the fail-closed gate misclassified a
// benign "not yet" race as a detached namespace and killed the migration in 9s. The reproduction
// (scratchpad repro) showed the sandbox present on pm-w2 ~6s AFTER the replacement pod appeared and
// still BEFORE the migration went terminal — i.e. a bounded wait of a few seconds wins the race.
//
// The tests inject the sandboxIDForPodUIDFn seam so they exercise the REAL resolve→classify→wait
// path (resolveSandboxIDForMigration → ReplacementSandboxNotYetCreatedError →
// resolvePodNetnsSandboxWaiting), not a stub of the whole gate — the "green test derived from real
// system state" bar, closing the coverage gap the Security Reviewer flagged at review.

func newSandboxWaitScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("pmv1.AddToScheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}
	return scheme
}

// sandboxWaitFixture builds a fake client with a PodMigration and a labeled, UID-bearing replacement
// pod — the exact state resolveSandboxIDForMigration walks to reach sandboxIDForPodUIDFn.
func sandboxWaitFixture(t *testing.T, ns, migration, replUID string) client.Client {
	t.Helper()
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: ns},
		Spec:       pmv1.PodMigrationSpec{PodNamespace: ns},
	}
	repl := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "redis-src-m-" + replUID,
			Namespace: ns,
			// Non-empty UID: resolveSandboxIDForMigration rejects an empty pod.UID before it ever
			// reaches sandboxIDForPodUIDFn.
			UID:    k8stypes.UID("k8s-repl-" + replUID),
			Labels: map[string]string{replacementPodLabelKey: migration},
		},
	}
	return fake.NewClientBuilder().WithScheme(newSandboxWaitScheme(t)).WithObjects(pm, repl).Build()
}

// (A) The sandbox is missing on the first probe(s) then appears — the live race. The gate must
// WIN it via the bounded wait and return the real sandbox ID, never failing closed.
func TestResolvePodNetnsSandboxWaiting_SandboxAppearsAfterRace_Resolves(t *testing.T) {
	const ns, migration, replUID = "pm-sbwait", "sbwait-mig-a", "reptest-a-uid"
	cl := sandboxWaitFixture(t, ns, migration, replUID)
	s := New("pm-w2", &criu.StubCheckpointer{}, cl)

	// Fast polls so the test is quick; restore afterward.
	origPoll := replacementSandboxPollInterval
	replacementSandboxPollInterval = 5 * time.Millisecond
	defer func() { replacementSandboxPollInterval = origPoll }()

	var calls int32
	origFn := sandboxIDForPodUIDFn
	sandboxIDForPodUIDFn = func(podUID string) (string, error) {
		// Not-found for the first 3 probes (kubelet still creating the sandbox), then it appears —
		// the exact errNoSandboxForPodUID edge resolveSandboxIDForMigration classifies as retryable.
		if atomic.AddInt32(&calls, 1) <= 3 {
			return "", errNoSandboxForPodUID
		}
		return "sandbox-" + podUID, nil
	}
	defer func() { sandboxIDForPodUIDFn = origFn }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id, attempted := s.resolvePodNetnsSandboxWaiting(ctx, migration)

	if !attempted {
		t.Fatal("attempted=false, want true (k8sClient present, resolution was attempted)")
	}
	if id == "" {
		t.Fatalf("resolvePodNetnsSandboxWaiting returned empty id — the bounded wait FAILED CLOSED on a race it should win (this is the live-proof-cycle1 defect). calls=%d", atomic.LoadInt32(&calls))
	}
	if !strings.HasPrefix(id, "sandbox-") {
		t.Fatalf("resolved id = %q, want the sandbox that appeared after the race", id)
	}
	if got := atomic.LoadInt32(&calls); got < 4 {
		t.Fatalf("sandbox resolver called %d times, want >=4 (proves it re-probed across the race, did not one-shot)", got)
	}
}

// (B) NON-NEGOTIABLE inverse — the sandbox NEVER appears within the budget. The gate must still
// FAIL CLOSED (attempted=true, empty id): a sandbox that never materializes IS the detached/non-pod
// namespace the ADR-0325 gate exists to refuse. The bounded wait must not turn "never" into "hang".
func TestResolvePodNetnsSandboxWaiting_SandboxNeverAppears_FailsClosed(t *testing.T) {
	const ns, migration, replUID = "pm-sbwait", "sbwait-mig-b", "reptest-b-uid"
	cl := sandboxWaitFixture(t, ns, migration, replUID)
	s := New("pm-w2", &criu.StubCheckpointer{}, cl)

	origPoll, origBudget := replacementSandboxPollInterval, replacementSandboxWaitBudget
	replacementSandboxPollInterval = 5 * time.Millisecond
	replacementSandboxWaitBudget = 60 * time.Millisecond
	defer func() {
		replacementSandboxPollInterval = origPoll
		replacementSandboxWaitBudget = origBudget
	}()

	origFn := sandboxIDForPodUIDFn
	sandboxIDForPodUIDFn = func(string) (string, error) { return "", errNoSandboxForPodUID }
	defer func() { sandboxIDForPodUIDFn = origFn }()

	start := time.Now()
	id, attempted := s.resolvePodNetnsSandboxWaiting(context.Background(), migration)
	elapsed := time.Since(start)

	if id != "" || !attempted {
		t.Fatalf("got (id=%q, attempted=%v), want ('' , true) — must fail closed when the sandbox never appears", id, attempted)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("wait took %s — budget (%s) was not honored; the gate must be bounded (invariant #8)", elapsed, replacementSandboxWaitBudget)
	}
}

// (C) A HARD ctr/containerd error (NOT errNoSandboxForPodUID) is terminal, not a race. The gate must
// fail closed IMMEDIATELY without consuming the wait budget — otherwise a broken runtime would stall
// every restore for the full budget. Proven by asserting exactly ONE resolver call.
func TestResolvePodNetnsSandboxWaiting_HardCtrError_FailsClosedImmediately(t *testing.T) {
	const ns, migration, replUID = "pm-sbwait", "sbwait-mig-c", "reptest-c-uid"
	cl := sandboxWaitFixture(t, ns, migration, replUID)
	s := New("pm-w2", &criu.StubCheckpointer{}, cl)

	origPoll := replacementSandboxPollInterval
	replacementSandboxPollInterval = 50 * time.Millisecond // large: a wrongful retry would be visible
	defer func() { replacementSandboxPollInterval = origPoll }()

	var calls int32
	origFn := sandboxIDForPodUIDFn
	sandboxIDForPodUIDFn = func(string) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "", errors.New("ctr containers list: connection refused") // containerd down — terminal
	}
	defer func() { sandboxIDForPodUIDFn = origFn }()

	id, attempted := s.resolvePodNetnsSandboxWaiting(context.Background(), migration)
	if id != "" || !attempted {
		t.Fatalf("got (id=%q, attempted=%v), want ('' , true) — a hard ctr error must fail closed", id, attempted)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("resolver called %d times, want exactly 1 (a terminal error must NOT be retried/waited)", got)
	}
}

// (D) End-to-end through Restore() — the direct inverse of the existing
// TestRestore_StrictUnresolvableSandbox_FailsClosedBeforeJoinNsRestore. With a labeled replacement
// pod whose sandbox appears on the SECOND probe, the ADR-0325 gate must PASS (hand control to
// joinNsRestore) rather than returning the "could not resolve replacement pod sandbox netns" fail-
// closed response. This is the gate-level proof that the live-proof-cycle1 restore now completes.
func TestRestore_StrictSandboxAppearsAfterRace_PassesGate(t *testing.T) {
	imagesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(imagesDir, "inventory.img"), []byte("CRIU\x00\x01"), 0o600); err != nil {
		t.Fatalf("seed inventory.img: %v", err)
	}
	if err := os.WriteFile(filepath.Join(imagesDir, "config.json"), []byte(`{"ociVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatalf("seed config.json: %v", err)
	}

	const ns, migration, replUID = "pm-sbwait", "sbwait-mig-d", "reptest-d-uid"
	cl := sandboxWaitFixture(t, ns, migration, replUID)
	s := New("pm-w2", &criu.StubCheckpointer{}, cl)

	origPoll := replacementSandboxPollInterval
	replacementSandboxPollInterval = 5 * time.Millisecond
	defer func() { replacementSandboxPollInterval = origPoll }()

	// Sandbox missing on probe 1, present on probe 2 — the race.
	var sbCalls int32
	origFn := sandboxIDForPodUIDFn
	sandboxIDForPodUIDFn = func(podUID string) (string, error) {
		if atomic.AddInt32(&sbCalls, 1) < 2 {
			return "", errNoSandboxForPodUID
		}
		return "sandbox-" + podUID, nil
	}
	defer func() { sandboxIDForPodUIDFn = origFn }()

	// Stub joinNsRestore to record that the gate handed control to it, then stop the flow with a
	// distinct marker error so the test does not depend on the (broker-backed) downstream MAC read.
	var joinCalled int32
	var gotSandboxID string
	origJoin := joinNsRestoreFn
	joinNsRestoreFn = func(_ context.Context, migName, checkpointDir, imageName, containerID, destNetnsFd, sandboxID, storedHostVeth string, strictMode bool, reattachMountPaths []reattachMount, containerCgroupsPath, podCgroupParent, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error) {
		atomic.StoreInt32(&joinCalled, 1)
		gotSandboxID = sandboxID
		return 0, nil, errors.New("stub-join-stop: gate-passed marker")
	}
	defer func() { joinNsRestoreFn = origJoin }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := s.Restore(ctx, &agentpb.RestoreRequest{
		MigrationName:       migration,
		CheckpointRef:       imagesDir,
		TcpPreservationMode: "Strict",
		// Non-empty DestNetnsFd clears the earlier B2 Strict guard so the RPC reaches the ADR-0325
		// gate this test targets (see the sibling companion test's rationale).
		DestNetnsFd: "/run/podmotion/netns/pm-mig-sbwait-d/bind",
	})

	if atomic.LoadInt32(&joinCalled) != 1 {
		t.Fatalf("joinNsRestoreFn was NOT called — the ADR-0325 gate failed closed on a winnable race instead of passing after the bounded wait (resp=%+v, err=%v)", resp, err)
	}
	if gotSandboxID == "" || !strings.HasPrefix(gotSandboxID, "sandbox-") {
		t.Fatalf("gate handed sandboxID=%q to joinNsRestore, want the real sandbox that appeared after the race", gotSandboxID)
	}
	// The gate must NOT have produced the ADR-0325 fail-closed response.
	if resp != nil && strings.Contains(resp.ErrorMessage, "could not resolve replacement pod sandbox netns (ADR-0325)") {
		t.Fatalf("Restore returned the ADR-0325 fail-closed message after the sandbox appeared: %q", resp.ErrorMessage)
	}
	if err != nil && strings.Contains(err.Error(), "could not resolve replacement pod sandbox netns (ADR-0325)") {
		t.Fatalf("Restore errored with the ADR-0325 fail-closed message after the sandbox appeared: %v", err)
	}
	if got := atomic.LoadInt32(&sbCalls); got < 2 {
		t.Fatalf("sandbox resolver called %d times, want >=2 (proves the gate re-probed across the race)", got)
	}
}
