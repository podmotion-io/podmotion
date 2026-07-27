/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// These tests pin the ADR-0370 containerd self-discovery primitive: the RKE2/k3s dual-
// containerd fix (agent's own pod sandbox as ground truth), and the zero-tech-debt
// fail-loud-never-guess requirement on every anomaly (override contradiction, zero hits,
// ambiguous multi-hit). They exercise discoverContainerdSocket/EnsureContainerdDiscovered
// through the containerdCandidateHitFn/discoverContainerdSocketFn injection seams — the same
// "inject the seam, exercise the real resolve/classify logic" discipline
// adr0325_sandbox_wait_test.go uses for sandboxIDForPodUIDFn — never a live dual-containerd
// node or a real broker/ctr invocation.

// --- buildContainerdCandidates -----------------------------------------------------------
//
// Env vars are cleared via t.Setenv(key, "") rather than a real unset: every check in this
// file (and in the production code) treats an empty string identically to "not set"
// (os.Getenv returns "" either way, and all call sites gate on != ""), so this is sufficient
// and lets every test use the standard t.Setenv auto-restore instead of custom bookkeeping.

func TestBuildContainerdCandidates_DefaultIsSystemThenRKE2(t *testing.T) {
	t.Setenv("PODMOTION_CONTAINERD_SOCKET", "")
	t.Setenv(containerdSocketCandidatesEnv, "")

	got := buildContainerdCandidates()
	if len(got) != 2 {
		t.Fatalf("buildContainerdCandidates() len = %d, want 2: %+v", len(got), got)
	}
	if got[0].Socket != systemContainerdSocket {
		t.Errorf("candidate[0].Socket = %q, want %q (system must be tried first)", got[0].Socket, systemContainerdSocket)
	}
	if got[1].Socket != rke2ContainerdSocket {
		t.Errorf("candidate[1].Socket = %q, want %q", got[1].Socket, rke2ContainerdSocket)
	}
	if got[1].RunRoot != rke2ContainerdRunRoot || got[1].StateRoot != rke2ContainerdStateRoot {
		t.Errorf("RKE2 candidate roots = (%q, %q), want (%q, %q)",
			got[1].RunRoot, got[1].StateRoot, rke2ContainerdRunRoot, rke2ContainerdStateRoot)
	}
}

func TestBuildContainerdCandidates_ExplicitOverrideIsSoleCandidate(t *testing.T) {
	t.Setenv(containerdSocketCandidatesEnv, "")
	t.Setenv("PODMOTION_CONTAINERD_SOCKET", "/custom/containerd.sock")
	t.Setenv("PODMOTION_CONTAINERD_RUN_ROOT", "")
	t.Setenv("PODMOTION_CONTAINERD_STATE_ROOT", "")

	got := buildContainerdCandidates()
	if len(got) != 1 {
		t.Fatalf("buildContainerdCandidates() with override len = %d, want 1: %+v", len(got), got)
	}
	if got[0].Socket != "/custom/containerd.sock" {
		t.Errorf("override candidate socket = %q, want /custom/containerd.sock", got[0].Socket)
	}
	if got[0].RunRoot != "/custom" || got[0].StateRoot != "/custom" {
		t.Errorf("override candidate roots = (%q, %q), want derived from filepath.Dir (/custom, /custom)", got[0].RunRoot, got[0].StateRoot)
	}
}

func TestBuildContainerdCandidates_ExtraCandidatesAppended(t *testing.T) {
	t.Setenv("PODMOTION_CONTAINERD_SOCKET", "")
	t.Setenv(containerdSocketCandidatesEnv, "/opt/foo/containerd.sock, /opt/bar/containerd.sock")

	got := buildContainerdCandidates()
	if len(got) != 4 {
		t.Fatalf("buildContainerdCandidates() with extras len = %d, want 4: %+v", len(got), got)
	}
	if got[2].Socket != "/opt/foo/containerd.sock" || got[2].RunRoot != "/opt/foo" {
		t.Errorf("extra candidate[2] = %+v, want socket=/opt/foo/containerd.sock runRoot=/opt/foo", got[2])
	}
	if got[3].Socket != "/opt/bar/containerd.sock" {
		t.Errorf("extra candidate[3].Socket = %q, want /opt/bar/containerd.sock", got[3].Socket)
	}
}

// --- discoverContainerdSocket --------------------------------------------------------------

// fakeHit builds a containerdCandidateHitFn stub reporting a hit ONLY for sockets in hitSet,
// and records every socket it was asked about (in call order) into *calls.
func fakeHit(hitSet map[string]bool, calls *[]string) func(ctx context.Context, socket, podUID string) (bool, string, error) {
	return func(_ context.Context, socket, _ string) (bool, string, error) {
		*calls = append(*calls, socket)
		if hitSet[socket] {
			return true, "owns this agent's own pod sandbox", nil
		}
		return false, "empty result (does not own this agent's own pod sandbox)", nil
	}
}

func withContainerdCandidateHitFn(t *testing.T, fn func(ctx context.Context, socket, podUID string) (bool, string, error)) {
	t.Helper()
	prev := containerdCandidateHitFn
	containerdCandidateHitFn = fn
	t.Cleanup(func() { containerdCandidateHitFn = prev })
}

// (A) Multiple candidate sockets, correct one wins — the RKE2 dual-containerd scenario this
// ADR exists to fix: the system socket exists but is empty (misses), the RKE2 socket owns the
// agent's own pod sandbox (hits). discoverContainerdSocket must adopt the RKE2 triple.
func TestDiscoverContainerdSocket_CorrectCandidateWins(t *testing.T) {
	t.Setenv("PODMOTION_CONTAINERD_SOCKET", "")
	t.Setenv(containerdSocketCandidatesEnv, "")

	var calls []string
	withContainerdCandidateHitFn(t, fakeHit(map[string]bool{rke2ContainerdSocket: true}, &calls))

	winner, err := discoverContainerdSocket(context.Background(), "test-pod-uid")
	if err != nil {
		t.Fatalf("discoverContainerdSocket returned error, want success: %v", err)
	}
	if winner.Socket != rke2ContainerdSocket {
		t.Errorf("winner.Socket = %q, want %q (the RKE2 daemon that actually owns the sandbox)", winner.Socket, rke2ContainerdSocket)
	}
	if winner.RunRoot != rke2ContainerdRunRoot || winner.StateRoot != rke2ContainerdStateRoot {
		t.Errorf("winner roots = (%q, %q), want (%q, %q)", winner.RunRoot, winner.StateRoot, rke2ContainerdRunRoot, rke2ContainerdStateRoot)
	}
	// Every candidate must actually be probed (never short-circuit on the first hit without
	// checking the rest — that is how an ambiguous multi-hit would go undetected).
	if len(calls) != 2 {
		t.Errorf("probed %d candidates, want 2 (both system and RKE2 must be tried)", len(calls))
	}
}

// (B) Failure mode when none work: zero candidates hit. Must fail loud (never guess a
// default) and the error must name every candidate tried plus why each failed.
func TestDiscoverContainerdSocket_ZeroHits_FailsLoud(t *testing.T) {
	t.Setenv("PODMOTION_CONTAINERD_SOCKET", "")
	t.Setenv(containerdSocketCandidatesEnv, "")

	var calls []string
	withContainerdCandidateHitFn(t, fakeHit(map[string]bool{}, &calls))

	_, err := discoverContainerdSocket(context.Background(), "test-pod-uid")
	if err == nil {
		t.Fatal("discoverContainerdSocket returned nil error, want a fail-loud error when no candidate hits")
	}
	if !strings.Contains(err.Error(), systemContainerdSocket) || !strings.Contains(err.Error(), rke2ContainerdSocket) {
		t.Errorf("error does not name every candidate tried: %v", err)
	}
	if len(calls) != 2 {
		t.Errorf("probed %d candidates, want 2", len(calls))
	}
}

// (C) Ambiguous multi-hit: more than one candidate claims to own the agent's own pod sandbox
// (should never happen by CRI construction, but the primitive must still refuse to guess which
// one is real rather than silently picking the first).
func TestDiscoverContainerdSocket_AmbiguousMultiHit_FailsLoud(t *testing.T) {
	t.Setenv("PODMOTION_CONTAINERD_SOCKET", "")
	t.Setenv(containerdSocketCandidatesEnv, "")

	var calls []string
	withContainerdCandidateHitFn(t, fakeHit(map[string]bool{systemContainerdSocket: true, rke2ContainerdSocket: true}, &calls))

	_, err := discoverContainerdSocket(context.Background(), "test-pod-uid")
	if err == nil {
		t.Fatal("discoverContainerdSocket returned nil error, want a fail-loud error on an ambiguous multi-hit")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ambiguous") {
		t.Errorf("error does not flag ambiguity: %v", err)
	}
}

// (D) Empty POD_UID: discovery must refuse before ever probing a candidate (nothing to anchor
// ground truth on).
func TestDiscoverContainerdSocket_EmptyPodUID_FailsLoudWithoutProbing(t *testing.T) {
	var calls []string
	withContainerdCandidateHitFn(t, fakeHit(map[string]bool{rke2ContainerdSocket: true}, &calls))

	_, err := discoverContainerdSocket(context.Background(), "")
	if err == nil {
		t.Fatal("discoverContainerdSocket(\"\") returned nil error, want a fail-loud error")
	}
	if len(calls) != 0 {
		t.Errorf("discoverContainerdSocket probed %d candidates with an empty POD_UID, want 0 (must fail before probing)", len(calls))
	}
}

// (E) Explicit operator override, confirmed against ground truth: succeeds using ONLY the
// override candidate.
func TestDiscoverContainerdSocket_OverrideConfirmed(t *testing.T) {
	t.Setenv(containerdSocketCandidatesEnv, "")
	t.Setenv("PODMOTION_CONTAINERD_SOCKET", rke2ContainerdSocket)
	t.Setenv("PODMOTION_CONTAINERD_RUN_ROOT", "")
	t.Setenv("PODMOTION_CONTAINERD_STATE_ROOT", "")

	var calls []string
	withContainerdCandidateHitFn(t, fakeHit(map[string]bool{rke2ContainerdSocket: true}, &calls))

	winner, err := discoverContainerdSocket(context.Background(), "test-pod-uid")
	if err != nil {
		t.Fatalf("discoverContainerdSocket with confirmed override returned error: %v", err)
	}
	if winner.Socket != rke2ContainerdSocket {
		t.Errorf("winner.Socket = %q, want %q", winner.Socket, rke2ContainerdSocket)
	}
	if len(calls) != 1 {
		t.Errorf("probed %d candidates under an override, want exactly 1 (tried first and exclusively)", len(calls))
	}
}

// (F) Explicit operator override that does NOT own the agent's own pod sandbox — must fail
// loud and must NOT fall through to the built-in candidate list (only the override itself is
// ever probed).
func TestDiscoverContainerdSocket_OverrideContradiction_FailsLoudNoFallthrough(t *testing.T) {
	t.Setenv(containerdSocketCandidatesEnv, "")
	t.Setenv("PODMOTION_CONTAINERD_SOCKET", systemContainerdSocket)
	t.Setenv("PODMOTION_CONTAINERD_RUN_ROOT", "")
	t.Setenv("PODMOTION_CONTAINERD_STATE_ROOT", "")

	// Ground truth: the RKE2 socket is the real owner (the exact RKE2 misconfiguration this ADR
	// targets) — the override (system socket) must NOT hit, and RKE2 must never even be tried.
	var calls []string
	withContainerdCandidateHitFn(t, fakeHit(map[string]bool{rke2ContainerdSocket: true}, &calls))

	_, err := discoverContainerdSocket(context.Background(), "test-pod-uid")
	if err == nil {
		t.Fatal("discoverContainerdSocket with a contradicted override returned nil error, want fail-loud")
	}
	if !strings.Contains(err.Error(), systemContainerdSocket) {
		t.Errorf("error does not name the contradicted override value: %v", err)
	}
	if len(calls) != 1 || calls[0] != systemContainerdSocket {
		t.Errorf("calls = %v, want exactly [%s] (must never silently fall through to the built-in candidate list)", calls, systemContainerdSocket)
	}
}

// --- EnsureContainerdDiscovered (sync.Once adoption) ----------------------------------------

// resetContainerdDiscoveryStateForTest clears the sync.Once guard, the cached error, and
// restores the package-level path vars — this function's job is exactly to let each test start
// from a clean, unadopted state despite the production code deliberately resolving only once
// per process.
func resetContainerdDiscoveryStateForTest(t *testing.T) {
	t.Helper()
	prevSocket, prevRun, prevState := containerdSocketPath, containerdRunRoot, containerdStateRoot
	prevErr := containerdDiscoveryErr
	containerdDiscoveryOnce = sync.Once{}
	containerdDiscoveryErr = nil
	t.Cleanup(func() {
		containerdSocketPath, containerdRunRoot, containerdStateRoot = prevSocket, prevRun, prevState
		// Reset (never copy: sync.Once must never be assigned from an existing value — vet
		// flags that as a lock copy) so the NEXT test that calls EnsureContainerdDiscovered
		// also starts from a fresh, un-fired Once, exactly as this test did on entry.
		containerdDiscoveryOnce = sync.Once{}
		containerdDiscoveryErr = prevErr
	})
}

func TestEnsureContainerdDiscovered_AdoptsWinnerExactlyOnce(t *testing.T) {
	resetContainerdDiscoveryStateForTest(t)

	calls := 0
	prevFn := discoverContainerdSocketFn
	discoverContainerdSocketFn = func(context.Context, string) (containerdCandidate, error) {
		calls++
		return containerdCandidate{Socket: "/fake/containerd.sock", RunRoot: "/fake", StateRoot: "/fake/state", Label: "fake"}, nil
	}
	t.Cleanup(func() { discoverContainerdSocketFn = prevFn })

	if err := EnsureContainerdDiscovered(context.Background(), "uid-1"); err != nil {
		t.Fatalf("EnsureContainerdDiscovered() error = %v, want nil", err)
	}
	if containerdSocketPath != "/fake/containerd.sock" || containerdRunRoot != "/fake" || containerdStateRoot != "/fake/state" {
		t.Errorf("package vars not adopted: socket=%q runRoot=%q stateRoot=%q", containerdSocketPath, containerdRunRoot, containerdStateRoot)
	}
	if got := CurrentContainerdSocketPath(); got != "/fake/containerd.sock" {
		t.Errorf("CurrentContainerdSocketPath() = %q, want /fake/containerd.sock", got)
	}

	// A second call must NOT re-run discovery (process-lifetime resolution, sync.Once).
	if err := EnsureContainerdDiscovered(context.Background(), "uid-1"); err != nil {
		t.Fatalf("second EnsureContainerdDiscovered() error = %v, want nil", err)
	}
	if calls != 1 {
		t.Errorf("discoverContainerdSocketFn called %d times, want exactly 1 (sync.Once)", calls)
	}
}

func TestEnsureContainerdDiscovered_PropagatesFailure(t *testing.T) {
	resetContainerdDiscoveryStateForTest(t)

	wantErr := errors.New("no candidate containerd socket owns this agent's own pod sandbox")
	prevFn := discoverContainerdSocketFn
	discoverContainerdSocketFn = func(context.Context, string) (containerdCandidate, error) {
		return containerdCandidate{}, wantErr
	}
	t.Cleanup(func() { discoverContainerdSocketFn = prevFn })

	prevSocket := containerdSocketPath
	err := EnsureContainerdDiscovered(context.Background(), "uid-1")
	if err == nil {
		t.Fatal("EnsureContainerdDiscovered() error = nil, want the discovery failure surfaced")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("EnsureContainerdDiscovered() error = %v, want it to wrap/equal %v", err, wantErr)
	}
	if containerdSocketPath != prevSocket {
		t.Errorf("containerdSocketPath changed on discovery failure: got %q, want unchanged %q", containerdSocketPath, prevSocket)
	}
}

// --- nriSocketPathFromConfig ------------------------------------------------------------------

func TestNRISocketPathFromConfig_ExtractsOverride(t *testing.T) {
	cfg := `
version = 2

[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "registry.k8s.io/pause:3.9"

[plugins."io.containerd.nri.v1.nri"]
  disable = false
  socket_path = "/custom/nri.sock"
`
	got := nriSocketPathFromConfig(cfg)
	if got != "/custom/nri.sock" {
		t.Errorf("nriSocketPathFromConfig() = %q, want /custom/nri.sock", got)
	}
}

func TestNRISocketPathFromConfig_AbsentSectionReturnsEmpty(t *testing.T) {
	cfg := `
version = 2

[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "registry.k8s.io/pause:3.9"
`
	if got := nriSocketPathFromConfig(cfg); got != "" {
		t.Errorf("nriSocketPathFromConfig() = %q, want \"\" (no NRI section present)", got)
	}
}

func TestNRISocketPathFromConfig_KeyFromOtherSectionIgnored(t *testing.T) {
	// A socket_path-looking key in a DIFFERENT table must never be picked up.
	cfg := `
[plugins."io.containerd.some.other.plugin"]
  socket_path = "/wrong/socket"

[plugins."io.containerd.nri.v1.nri"]
  disable = true
`
	if got := nriSocketPathFromConfig(cfg); got != "" {
		t.Errorf("nriSocketPathFromConfig() = %q, want \"\" (NRI section has no socket_path key; must not borrow the other table's)", got)
	}
}

// --- remapWorkTargetToDumpLog (ADR-0370 RKE2/k3s runRoot==stateRoot case) -------------------

func TestRemapWorkTargetToDumpLog_RKE2RunRootEqualsStateRoot_UsesHostRunMount(t *testing.T) {
	prevRun, prevState := containerdRunRoot, containerdStateRoot
	containerdRunRoot = rke2ContainerdRunRoot
	containerdStateRoot = rke2ContainerdStateRoot
	t.Cleanup(func() { containerdRunRoot, containerdStateRoot = prevRun, prevState })

	const taskID = "deadbeefcafefeed"
	target := rke2ContainerdRunRoot + "/io.containerd.runtime.v2.task/k8s.io/" + taskID

	got := remapWorkTargetToDumpLog(target)
	want := "/host-run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/" + taskID + "/criu-dump.log"
	if got != want {
		t.Errorf("remapWorkTargetToDumpLog(%q) = %q, want %q (RKE2's state dir lives under /run, already covered by the broad host-run mount — no new hostPath volume required)", target, got, want)
	}
}

func TestRemapWorkTargetToDumpLog_KubeadmUnaffectedByRKE2Branch(t *testing.T) {
	// Regression guard: the kubeadm/system-containerd case (runRoot and stateRoot are disjoint
	// trees) must still resolve via /host-var-lib-containerd exactly as before this ADR.
	prevRun, prevState := containerdRunRoot, containerdStateRoot
	containerdRunRoot = systemContainerdRunRoot
	containerdStateRoot = systemContainerdStateRoot
	t.Cleanup(func() { containerdRunRoot, containerdStateRoot = prevRun, prevState })

	const taskID = "03fbc0283c4874446bca6e35679ec8330b170d54595bdd9ffe8e42d1adc325b4"
	target := systemContainerdStateRoot + "/io.containerd.runtime.v2.task/k8s.io/" + taskID

	got := remapWorkTargetToDumpLog(target)
	want := "/host-var-lib-containerd/io.containerd.runtime.v2.task/k8s.io/" + taskID + "/criu-dump.log"
	if got != want {
		t.Errorf("remapWorkTargetToDumpLog(%q) = %q, want %q", target, got, want)
	}
}
