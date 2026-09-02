/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0419_destination_mounts_test.go — the ADR-0419 §P-VERIFY assertions that are unit-testable
// off-cluster against a FAKE EVENT.
//
// That "against a fake event" clause is the point, not an implementation detail. ADR-0417's suite
// could not express any of these, because every one of its tests stubbed the very seam whose real
// behaviour was the defect: sandboxIDForPodUIDFn was replaced wholesale in every test, so the CLI
// scrape and its first-row-wins bug never executed in CI even once, and the expected-target map was
// computed with production's own filepath.Join formula, so the assertion was tautological and would
// have passed against any wrong path production happened to build.
//
// Here the expectations come from the fixture, never from production's formula.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/podmotion-io/podmotion/internal/agent/nri"
)

// ---------------------------------------------------------------------------------------------
// Fixture — a fake NRI event, with the EXACT Source shapes the live G0 probe recorded.
// ---------------------------------------------------------------------------------------------

// adr0419LiveKubeletHostsSource / adr0419LiveSandboxDir are TRANSCRIBED from the §P-VERIFY #1 live
// probe on pm-w1 (RKE2 v1.35.6+rke2r1, containerd 2.2.5-k3s2), not constructed by joining the same
// components production joins. They are two DIFFERENT writers under two DIFFERENT roots — the fact
// ADR-0417's four-entry table encoded as a taxonomy and got wrong for two of its four members.
const (
	adr0419LiveKubeletHostsSource = "/var/lib/kubelet/pods/c2f1f8c0-d013-434f-9bcc-7f9f60c4ce74/etc-hosts"
	adr0419LiveSandboxDir         = "/var/lib/rancher/rke2/agent/containerd/io.containerd.grpc.v1.cri/sandboxes/efe76598ff12390195a455964c6bb14d184b9eb8cc1ab07c899d4b99a6525308"
	adr0419LiveHostnameSource     = adr0419LiveSandboxDir + "/hostname"
	adr0419LiveResolvConfSource   = adr0419LiveSandboxDir + "/resolv.conf"
)

// adr0419FakeEventMounts is a fake nri.ContainerEvent.Mounts payload shaped exactly like the live
// one: 13 entries, of which the three /etc/* binds are what any real checkpoint demands.
func adr0419FakeEventMounts() []nri.ContainerMount {
	return []nri.ContainerMount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs"},
		{Destination: "/dev/shm", Type: "tmpfs", Source: "shm"},
		{Destination: "/etc/hosts", Type: "bind", Source: adr0419LiveKubeletHostsSource, Options: []string{"rbind", "rprivate", "rw"}},
		{Destination: "/etc/hostname", Type: "bind", Source: adr0419LiveHostnameSource, Options: []string{"rbind", "rprivate", "rw"}},
		{Destination: "/etc/resolv.conf", Type: "bind", Source: adr0419LiveResolvConfSource, Options: []string{"rbind", "rprivate", "rw"}},
		{Destination: "/dev/termination-log", Type: "bind", Source: "/var/lib/kubelet/pods/c2f1f8c0/containers/redis/deadbeef"},
	}
}

// withDemandSet installs a fake checkpoint demand set (D4) and returns a restore func.
func withDemandSet(t *testing.T, demand ...string) func() {
	t.Helper()
	orig := destinationRebindDemandSetFn
	destinationRebindDemandSetFn = func(context.Context, string, string) ([]string, error) {
		return demand, nil
	}
	return func() { destinationRebindDemandSetFn = orig }
}

func withObserve(t *testing.T, sink *string, attempts *int) func() {
	t.Helper()
	orig := destinationRebindObserveFn
	destinationRebindObserveFn = func(_ string, a int, _ time.Duration, outcome string) {
		*sink = outcome
		*attempts = a
	}
	return func() { destinationRebindObserveFn = orig }
}

// ---------------------------------------------------------------------------------------------
// §P-VERIFY #6(b) + D3 — resolution is a LOOKUP, and the expectation comes from the fixture.
// ---------------------------------------------------------------------------------------------

// TestADR0419_ResolvesTargetsByLookupInTheRuntimeMountList is the replacement for the deleted,
// tautological _ResolvesRealWriterPaths. The expected host targets are read off the SAME fake event
// the resolver is handed — so this asserts "production returned what the runtime said", which is
// the actual contract, rather than "production's filepath.Join agrees with the test's filepath.Join".
func TestADR0419_ResolvesTargetsByLookupInTheRuntimeMountList(t *testing.T) {
	defer withDemandSet(t, "/etc/hosts", "/etc/hostname", "/etc/resolv.conf")()
	var outcome string
	var attempts int
	defer withObserve(t, &outcome, &attempts)()
	s := newADR0417Server(t)

	got, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID,
		adr0419FakeEventMounts(), nil)
	if err != nil {
		t.Fatalf("resolution must succeed against a runtime list that carries every demanded mount: %v", err)
	}

	want := map[string]string{
		"/etc/hosts":       adr0419LiveKubeletHostsSource,
		"/etc/hostname":    adr0419LiveHostnameSource,
		"/etc/resolv.conf": adr0419LiveResolvConfSource,
	}
	if len(got) != len(want) {
		t.Fatalf("resolved %d mounts, want %d: %+v", len(got), len(want), got)
	}
	for _, m := range got {
		if m.Tier != reattachTierDestinationRebind {
			t.Errorf("%s: Tier=%v, want reattachTierDestinationRebind", m.ContainerPath, m.Tier)
		}
		w, ok := want[m.ContainerPath]
		if !ok {
			t.Errorf("unexpected destination-rebind mount for %s", m.ContainerPath)
			continue
		}
		if m.HostTarget != w {
			t.Errorf("%s host target: got %q, want the runtime-supplied source %q", m.ContainerPath, m.HostTarget, w)
		}
	}
	// The specific falsified assumption ADR-0417's writer taxonomy encoded: hostname and
	// resolv.conf are NOT under the kubelet pod dir. Live `ls -A` on a kubelet pod dir returns
	// exactly `containers etc-hosts plugins volumes`.
	for _, m := range got {
		if m.ContainerPath == "/etc/hostname" || m.ContainerPath == "/etc/resolv.conf" {
			if strings.HasPrefix(m.HostTarget, "/var/lib/kubelet/pods/") {
				t.Errorf("%s resolved into the kubelet pod dir (%q) — two different writers, two different directories", m.ContainerPath, m.HostTarget)
			}
		}
	}
	if outcome != "resolved" {
		t.Errorf("outcome: got %q, want %q", outcome, "resolved")
	}
	if attempts != 1 {
		t.Errorf("the NRI path holds the answer already — it must resolve in exactly one attempt, with no wait; got %d", attempts)
	}
}

// TestADR0419_NRIPathIssuesZeroRuntimeLookups is the NRI half of §P-VERIFY #10's broker-load
// collapse, asserted mechanically rather than measured: destination-rebind resolution on the NRI
// path must issue ZERO round-trips of any kind. ADR-0417 issued ~580 broker round-trips and ~97
// full containerd enumerations per restore, against the very containerd control socket the
// in-flight CRIU restore depends on.
func TestADR0419_NRIPathIssuesZeroRuntimeLookups(t *testing.T) {
	defer withDemandSet(t, "/etc/hosts", "/etc/hostname", "/etc/resolv.conf")()
	lookups := 0
	orig := containerdRuntimeMountsOnceFn
	containerdRuntimeMountsOnceFn = func(context.Context, string, string) ([]nri.ContainerMount, error) {
		lookups++
		return adr0419FakeEventMounts(), nil
	}
	defer func() { containerdRuntimeMountsOnceFn = orig }()

	s := newADR0417Server(t)
	if _, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID,
		adr0419FakeEventMounts(), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lookups != 0 {
		t.Errorf("the NRI path carries its own mount list — it must query the runtime ZERO times; got %d", lookups)
	}
}

// ---------------------------------------------------------------------------------------------
// §P-VERIFY #3 — the assertion ADR-0417's hardcoded table structurally could not satisfy.
// ---------------------------------------------------------------------------------------------

// TestADR0419_WorkloadWithNoHostnameMountRestoresCleanly: a checkpoint that never recorded an
// /etc/hostname mount must not be required to produce an /etc/hostname destination target. Under
// ADR-0417 all four members of a hardcoded table had to be observed SIMULTANEOUSLY or nothing
// resolved, so a workload whose checkpoint made no such demand still hard-stopped on it.
func TestADR0419_WorkloadWithNoHostnameMountRestoresCleanly(t *testing.T) {
	// The checkpoint demands only /etc/hosts, and the runtime list likewise omits /etc/hostname.
	defer withDemandSet(t, "/etc/hosts")()
	var outcome string
	var attempts int
	defer withObserve(t, &outcome, &attempts)()

	runtimeMounts := []nri.ContainerMount{
		{Destination: "/etc/hosts", Type: "bind", Source: adr0419LiveKubeletHostsSource},
	}
	s := newADR0417Server(t)
	got, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID, runtimeMounts, nil)
	if err != nil {
		t.Fatalf("a checkpoint that never demanded /etc/hostname must resolve cleanly, not hard-stop: %v", err)
	}
	if len(got) != 1 || got[0].ContainerPath != "/etc/hosts" {
		t.Fatalf("want exactly the one demanded mount; got %+v", got)
	}
	for _, m := range got {
		if m.ContainerPath == "/etc/hostname" {
			t.Errorf("produced an /etc/hostname entry for a checkpoint that never demanded one")
		}
	}
	if outcome != "resolved" {
		t.Errorf("outcome: got %q, want %q", outcome, "resolved")
	}
}

// TestADR0419_NoDemandedMountsIsNotAFailure covers the empty-demand-set leg explicitly: a
// checkpoint with no Class DESTINATION-REBIND mount at all resolves to nothing, successfully.
func TestADR0419_NoDemandedMountsIsNotAFailure(t *testing.T) {
	defer withDemandSet(t)()
	var outcome string
	var attempts int
	defer withObserve(t, &outcome, &attempts)()

	s := newADR0417Server(t)
	got, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID, adr0419FakeEventMounts(), nil)
	if err != nil {
		t.Fatalf("an empty demand set is not a failure: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("no demand means no targets; got %+v", got)
	}
	if outcome != "not_demanded" {
		t.Errorf("outcome: got %q, want %q", outcome, "not_demanded")
	}
}

// ---------------------------------------------------------------------------------------------
// D3 — the new hard stop. A DIFFERENT fact from anything ADR-0419 deletes.
// ---------------------------------------------------------------------------------------------

// TestADR0419_DemandedMountAbsentFromRuntimeListIsTerminal: the runtime did not give this container
// this mount. That is a definite fact from an authoritative source, available immediately — not
// "we could not observe a file within a 30-second budget".
func TestADR0419_DemandedMountAbsentFromRuntimeListIsTerminal(t *testing.T) {
	defer withDemandSet(t, "/etc/hosts", "/etc/hostname")()
	var outcome string
	var attempts int
	defer withObserve(t, &outcome, &attempts)()

	// The runtime supplies /etc/hosts but NOT /etc/hostname.
	runtimeMounts := []nri.ContainerMount{
		{Destination: "/etc/hosts", Type: "bind", Source: adr0419LiveKubeletHostsSource},
	}
	s := newADR0417Server(t)
	got, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID, runtimeMounts, nil)
	if err == nil {
		t.Fatalf("a demanded mount the runtime does not supply must be terminal; got mounts %+v", got)
	}
	var absent *DestinationRuntimeMountAbsentError
	if !errors.As(err, &absent) {
		t.Fatalf("want *DestinationRuntimeMountAbsentError; got %T: %v", err, err)
	}
	if absent.ContainerPath != "/etc/hostname" {
		t.Errorf("the terminal error must name the unsupplied path; got %q", absent.ContainerPath)
	}
	if absent.SandboxID != adr0417SandboxID {
		t.Errorf("the terminal error must name the sandbox it asked about; got %q", absent.SandboxID)
	}
	// The message must state what the runtime DID offer — otherwise the transcript shows only what
	// was missing, which is the reporting gap that let the old failure walk between targets.
	if !strings.Contains(absent.Error(), "/etc/hosts") {
		t.Errorf("the error must report the destinations the runtime did supply; got %q", absent.Error())
	}
	if len(got) != 0 {
		t.Errorf("no mounts may be returned on the terminal leg; got %+v", got)
	}
	if outcome != "runtime_mount_absent" {
		t.Errorf("outcome: got %q, want %q", outcome, "runtime_mount_absent")
	}
}

// ---------------------------------------------------------------------------------------------
// §P-VERIFY #9 / #14 + D3.1/D7 — /dev/termination-log.
// ---------------------------------------------------------------------------------------------

// TestADR0419_TerminationLogUsesAgentStagedPathAndIsNeverProbed pins D3.1: for this ONE path the
// agent is itself the authoritative writer, so its own os.OpenFile postcondition outranks the
// runtime's. The runtime's Source for /dev/termination-log is kubelet's per-container-instance
// path, so taking it (D3's general rule) would silently change the emitted --ext-mount-map target
// away from ADR-0417's current emission — a §P-VERIFY #14 violation, not a D4 consequence.
func TestADR0419_TerminationLogUsesAgentStagedPathAndIsNeverProbed(t *testing.T) {
	defer withDemandSet(t, "/dev/termination-log")()
	_ = os.RemoveAll(restoreStagingDir(adr0417Migration))
	s := newADR0417Server(t)

	got, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID,
		adr0419FakeEventMounts(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly one resolved mount; got %+v", got)
	}
	want := restoreTerminationLogPath(adr0417Migration)
	if got[0].HostTarget != want {
		t.Errorf("/dev/termination-log must resolve to the AGENT-staged path %q (byte-identical to ADR-0417's emission), not to the runtime's kubelet per-instance source; got %q", want, got[0].HostTarget)
	}
	// D7: the write edge survives and ran, so the target the agent emits actually exists.
	if st, serr := os.Stat(want); serr != nil || !st.Mode().IsRegular() {
		t.Errorf("agent-staged termination-log %s was not created: stat err=%v", want, serr)
	}
}

// TestADR0419_TerminationLogAbsentFromRuntimeListIsNotAHardStop: D3.1 states this explicitly, and
// it is the exact edge where a naive implementation of D3 would regress every migration —
// /dev/termination-log is an ext4-backed bind on every container, so it lands in Class
// DESTINATION-REBIND on EVERY migration.
func TestADR0419_TerminationLogAbsentFromRuntimeListIsNotAHardStop(t *testing.T) {
	defer withDemandSet(t, "/dev/termination-log")()
	s := newADR0417Server(t)

	// A runtime mount list with NO /dev/termination-log entry at all.
	runtimeMounts := []nri.ContainerMount{
		{Destination: "/etc/hosts", Type: "bind", Source: adr0419LiveKubeletHostsSource},
	}
	got, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID, runtimeMounts, nil)
	if err != nil {
		t.Fatalf("/dev/termination-log absent from the runtime list must NOT be a D3 hard stop (D3.1): %v", err)
	}
	if len(got) != 1 || got[0].HostTarget != restoreTerminationLogPath(adr0417Migration) {
		t.Fatalf("want the agent-staged termination-log target; got %+v", got)
	}
}

// ---------------------------------------------------------------------------------------------
// §P-VERIFY #7 — the D5.3 FOUR-way status classification. This is the assertion that FM5's
// inversion is actually fixed and not merely relocated.
// ---------------------------------------------------------------------------------------------

func TestADR0419_TypedLookupStatusMapsToFourClasses(t *testing.T) {
	mounts := adr0419FakeEventMounts()
	cases := []struct {
		name string
		in   []nri.ContainerMount
		err  error
		want runtimeMountLookupClass
		why  string
	}{
		{"resolved", mounts, nil, runtimeMountLookupResolved, "a real mount list came back"},
		{"unavailable_is_not_yet", nil, status.Error(codes.Unavailable, "containerd restarting"), runtimeMountLookupNotYet,
			"THE FM5 CASE: a transient control-plane blip must be re-probed, not kill a live migration on first occurrence with 29 of 30 seconds unspent"},
		{"deadline_exceeded_is_not_yet", nil, status.Error(codes.DeadlineExceeded, "deadline"), runtimeMountLookupNotYet,
			"one exec/RPC hitting its deadline under load is the expected tail of a loaded distribution, not evidence the mechanism is broken"},
		{"not_found_is_not_yet", nil, status.Error(codes.NotFound, "no such container"), runtimeMountLookupNotYet,
			"the sandbox/container genuinely has not been created yet"},
		{"empty_result_is_not_yet", nil, nil, runtimeMountLookupNotYet,
			"an empty result is 'not created yet', never an error"},
		{"permission_denied_is_terminal", nil, status.Error(codes.PermissionDenied, "denied"), runtimeMountLookupTerminal,
			"a structurally broken read is terminal"},
		{"internal_is_terminal", nil, status.Error(codes.Internal, "boom"), runtimeMountLookupTerminal, "ditto"},
		{"plain_error_is_terminal", nil, errors.New("decode failure"), runtimeMountLookupTerminal,
			"a non-status error carries codes.Unknown and must not be retried"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRuntimeMountLookup(tc.in, tc.err); got != tc.want {
				t.Errorf("classify(%v) = %v, want %v — %s", tc.err, got, tc.want, tc.why)
			}
		})
	}
}

// TestADR0419_NotYetThatNeverConvergesGetsANamedTerminal is the D5.3 NEVER leg. Without it, a
// NOT-YET that never converged would have NO terminal at all: it would burn the whole restore
// deadline and surface as a bare RPC timeout, re-creating exactly the misattribution ADR-0418 just
// fixed. The terminal must NAME the unresolved in-container path.
func TestADR0419_NotYetThatNeverConvergesGetsANamedTerminal(t *testing.T) {
	defer withDemandSet(t, "/etc/hosts", "/etc/hostname")()
	origBudget, origInterval := destinationMountLookupBudget, destinationMountLookupInterval
	destinationMountLookupBudget = 120 * time.Millisecond
	destinationMountLookupInterval = 10 * time.Millisecond
	defer func() {
		destinationMountLookupBudget, destinationMountLookupInterval = origBudget, origInterval
	}()

	calls := 0
	orig := containerdRuntimeMountsOnceFn
	containerdRuntimeMountsOnceFn = func(context.Context, string, string) ([]nri.ContainerMount, error) {
		calls++
		return nil, status.Error(codes.Unavailable, "containerd is down")
	}
	defer func() { containerdRuntimeMountsOnceFn = orig }()

	var outcome string
	var attempts int
	defer withObserve(t, &outcome, &attempts)()

	s := newADR0417Server(t)
	// runtimeMounts == nil selects the gRPC/typed branch.
	_, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID, nil, nil)
	if err == nil {
		t.Fatal("a NOT-YET that never converges must produce a named terminal, not silence")
	}
	var timeoutErr *DestinationRuntimeMountLookupTimeoutError
	if !errors.As(err, &timeoutErr) {
		t.Fatalf("want *DestinationRuntimeMountLookupTimeoutError; got %T: %v", err, err)
	}
	if timeoutErr.ContainerPath != "/etc/hosts" {
		t.Errorf("the terminal must name an unresolved in-container path; got %q", timeoutErr.ContainerPath)
	}
	if !strings.Contains(timeoutErr.LastStatus, "Unavailable") {
		t.Errorf("the terminal must record the last gRPC status seen; got %q", timeoutErr.LastStatus)
	}
	if calls < 2 {
		t.Errorf("Unavailable is NOT YET — it must be re-probed within the budget, not terminal on first occurrence; got %d call(s)", calls)
	}
	if outcome != "runtime_lookup_failed" {
		t.Errorf("outcome: got %q, want %q", outcome, "runtime_lookup_failed")
	}
}

// TestADR0419_TransientBlipThenSuccessResolves is the positive half of the same inversion fix: the
// migration ADR-0417 would have killed on the first Unavailable now completes.
func TestADR0419_TransientBlipThenSuccessResolves(t *testing.T) {
	defer withDemandSet(t, "/etc/hosts")()
	origInterval := destinationMountLookupInterval
	destinationMountLookupInterval = 5 * time.Millisecond
	defer func() { destinationMountLookupInterval = origInterval }()

	calls := 0
	orig := containerdRuntimeMountsOnceFn
	containerdRuntimeMountsOnceFn = func(context.Context, string, string) ([]nri.ContainerMount, error) {
		calls++
		if calls < 3 {
			return nil, status.Error(codes.Unavailable, "blip")
		}
		return adr0419FakeEventMounts(), nil
	}
	defer func() { containerdRuntimeMountsOnceFn = orig }()

	s := newADR0417Server(t)
	got, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID, nil, nil)
	if err != nil {
		t.Fatalf("a transient blip that clears must resolve, not kill the migration: %v", err)
	}
	if len(got) != 1 || got[0].HostTarget != adr0419LiveKubeletHostsSource {
		t.Fatalf("want the runtime-supplied /etc/hosts source; got %+v", got)
	}
}

// TestADR0419_TerminalStatusIsNotRetried: a structurally broken read must NOT be re-probed. The
// classification is genuinely four-way, not "retry everything now".
func TestADR0419_TerminalStatusIsNotRetried(t *testing.T) {
	defer withDemandSet(t, "/etc/hosts")()
	calls := 0
	orig := containerdRuntimeMountsOnceFn
	containerdRuntimeMountsOnceFn = func(context.Context, string, string) ([]nri.ContainerMount, error) {
		calls++
		return nil, status.Error(codes.PermissionDenied, "denied")
	}
	defer func() { containerdRuntimeMountsOnceFn = orig }()

	s := newADR0417Server(t)
	if _, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID, nil, nil); err == nil {
		t.Fatal("a terminal gRPC status must fail closed")
	}
	if calls != 1 {
		t.Errorf("a terminal status must not be retried; got %d calls", calls)
	}
}

// ---------------------------------------------------------------------------------------------
// §P-VERIFY #10 (static half) — the D5.2 budget invariant.
// ---------------------------------------------------------------------------------------------

// TestADR0419_LookupBudgetIsStrictlyUnderBothSiblings asserts the invariant the retired
// destinationRebindWaitBudget carried and its successor must carry forward: this lookup can NEVER
// be the component that consumes the restore deadline. Deleting a bound while mandating a retry
// loop would have made "the remaining budget" mean all of D_restore.
func TestADR0419_LookupBudgetIsStrictlyUnderBothSiblings(t *testing.T) {
	const reattachMountWaitBudget = 85 * time.Second // server.go joinNsRestore's reCtx sub-budget
	if !(destinationMountLookupBudget < replacementSandboxWaitBudget) {
		t.Errorf("destinationMountLookupBudget (%s) must be STRICTLY under replacementSandboxWaitBudget (%s)",
			destinationMountLookupBudget, replacementSandboxWaitBudget)
	}
	if !(destinationMountLookupBudget < reattachMountWaitBudget) {
		t.Errorf("destinationMountLookupBudget (%s) must be STRICTLY under the 85s reattach-mount wait",
			destinationMountLookupBudget)
	}
	if destinationMountLookupInterval >= destinationMountLookupBudget {
		t.Errorf("the interval (%s) must fit inside the budget (%s) with room for more than one attempt",
			destinationMountLookupInterval, destinationMountLookupBudget)
	}
}

// ---------------------------------------------------------------------------------------------
// §P-VERIFY #8 — sandboxIDForPodUID's TRI-STATE contract, asserted END TO END through its
// surviving consumer. Testing the mutated function alone against a fake listing is exactly the
// coverage gap that let the original, regressing D8 through review.
// ---------------------------------------------------------------------------------------------

// withRunningSandboxes installs a fake pod-sandbox listing and restores the REAL sandboxIDForPodUID
// (not a stub of it) so the tri-state classification under test actually executes.
func withRunningSandboxes(t *testing.T, fn func(podUID string) ([]string, error)) func() {
	t.Helper()
	origList := runningPodSandboxesForPodUIDFn
	origSeam := sandboxIDForPodUIDFn
	runningPodSandboxesForPodUIDFn = func(_ context.Context, podUID string) ([]string, error) { return fn(podUID) }
	sandboxIDForPodUIDFn = sandboxIDForPodUID // the REAL function, not a stub
	return func() {
		runningPodSandboxesForPodUIDFn = origList
		sandboxIDForPodUIDFn = origSeam
	}
}

// TestADR0419_D8a_ZeroMatchesStaysRetryable is THE INVARIANT. If zero-match stopped satisfying
// errors.Is(err, errNoSandboxForPodUID), then resolveSandboxIDForMigration would never construct
// ReplacementSandboxNotYetCreatedError — its ONLY construction site repo-wide — errors.As in
// resolvePodNetnsSandboxWaiting would never match, and the pod-netns join gate would collapse from
// "bounded-wait 60s for the destination kubelet" to "fail terminal on first look", on the very ~6s
// kubelet race it was built to win. Adding the kind+state filter WIDENS this window, which makes
// preserving the leg more load-bearing after D8, not less.
func TestADR0419_D8a_ZeroMatchesStaysRetryable(t *testing.T) {
	defer withRunningSandboxes(t, func(string) ([]string, error) { return nil, nil })()

	_, err := sandboxIDForPodUID(context.Background(), adr0417ReplUID)
	if !errors.Is(err, errNoSandboxForPodUID) {
		t.Fatalf("zero matches MUST remain the retryable errNoSandboxForPodUID sentinel; got %T: %v", err, err)
	}
	var ambiguous *AmbiguousPodSandboxError
	if errors.As(err, &ambiguous) {
		t.Error("zero matches must NOT be the ambiguous terminal — they are opposite facts")
	}

	// End to end through the surviving consumer.
	s := &AgentServer{k8sClient: sandboxWaitFixture(t, adr0417Namespace, adr0417Migration, adr0417ReplUID)}
	_, rerr := s.resolveSandboxIDForMigration(context.Background(), adr0417Migration)
	var notYet *ReplacementSandboxNotYetCreatedError
	if !errors.As(rerr, &notYet) {
		t.Fatalf("resolveSandboxIDForMigration must still yield *ReplacementSandboxNotYetCreatedError on zero matches; got %T: %v", rerr, rerr)
	}
}

// TestADR0419_D8b_PodNetnsJoinGateStillBoundedWaitsAndWinsTheRace asserts through
// resolvePodNetnsSandboxWaiting — the GATE — not through sandboxIDForPodUID in isolation. A sandbox
// that appears on poll N (the in-tree-grounded ~6s kubelet edge) must be WAITED for and then
// succeed.
func TestADR0419_D8b_PodNetnsJoinGateStillBoundedWaitsAndWinsTheRace(t *testing.T) {
	appearOnPoll := 3
	seen := 0
	defer withRunningSandboxes(t, func(podUID string) ([]string, error) {
		seen++
		if seen < appearOnPoll {
			return nil, nil // kubelet has not created the pause container yet
		}
		return []string{"sandbox-" + podUID}, nil
	})()

	origBudget, origInterval := replacementSandboxWaitBudget, replacementSandboxPollInterval
	replacementSandboxWaitBudget = 3 * time.Second
	replacementSandboxPollInterval = 5 * time.Millisecond
	defer func() {
		replacementSandboxWaitBudget, replacementSandboxPollInterval = origBudget, origInterval
	}()

	s := &AgentServer{k8sClient: sandboxWaitFixture(t, adr0417Namespace, adr0417Migration, adr0417ReplUID)}
	id, attempted := s.resolvePodNetnsSandboxWaiting(context.Background(), adr0417Migration)
	if !attempted {
		t.Fatal("the gate must report that it attempted resolution")
	}
	if id == "" {
		t.Fatal("the gate must WAIT for the kubelet sandbox edge and then succeed — not fail terminal on first look")
	}
	// sandboxWaitFixture stamps the replacement pod's UID as "k8s-repl-"+replUID, so this asserts
	// the gate resolved the sandbox for the REPLACEMENT POD it actually walked to — not merely that
	// some non-empty string came back.
	if want := "sandbox-k8s-repl-" + adr0417ReplUID; id != want {
		t.Errorf("gate resolved %q, want %q — the one RUNNING sandbox for the replacement pod UID", id, want)
	}
	if seen < appearOnPoll {
		t.Errorf("the gate did not actually re-probe; saw %d attempts", seen)
	}
}

// TestADR0419_D8c_MoreThanOneRunningSandboxIsTerminalNamingBoth is the only NEW terminal surface D8
// adds.
//
// D8.1 GATED THIS LEG on a live settle, and the settle was run before it shipped: on pm-w1 and
// pm-w2, 27 pod UIDs carry TWO kind==sandbox rows each — including all four the ADR named — but
// ZERO carry more than one in SANDBOX_READY. The second row is always a stale, not-ready sandbox.
// So two-RUNNING is not a steady state this substrate produces and this leg does not terminalize a
// gate that works today. The multiplicity IS real, which is precisely why the RUNNING filter — not
// the kind filter alone — is what makes the answer unique.
func TestADR0419_D8c_MoreThanOneRunningSandboxIsTerminalNamingBoth(t *testing.T) {
	defer withRunningSandboxes(t, func(string) ([]string, error) {
		return []string{"sandbox-aaa", "sandbox-bbb"}, nil
	})()

	_, err := sandboxIDForPodUID(context.Background(), adr0417ReplUID)
	var ambiguous *AmbiguousPodSandboxError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("two RUNNING sandboxes for one pod UID must be terminal; got %T: %v", err, err)
	}
	if errors.Is(err, errNoSandboxForPodUID) {
		t.Error("the ambiguous terminal must NOT satisfy the retryable zero-match sentinel — the gate would bounded-wait forever on a condition that never clears")
	}
	for _, want := range []string{"sandbox-aaa", "sandbox-bbb"} {
		if !strings.Contains(ambiguous.Error(), want) {
			t.Errorf("the ambiguous terminal must name BOTH sandbox IDs; %q missing from %q", want, ambiguous.Error())
		}
	}
}

// TestADR0419_D8_ExactlyOneRunningSandboxIsReturnedNotTheFirstRow pins root cause (A) directly.
func TestADR0419_D8_ExactlyOneRunningSandboxIsReturnedNotTheFirstRow(t *testing.T) {
	defer withRunningSandboxes(t, func(string) ([]string, error) {
		return []string{"the-only-running-sandbox"}, nil
	})()
	got, err := sandboxIDForPodUID(context.Background(), adr0417ReplUID)
	if err != nil {
		t.Fatalf("exactly one RUNNING sandbox must resolve: %v", err)
	}
	if got != "the-only-running-sandbox" {
		t.Errorf("got %q", got)
	}
}

// TestADR0419_D8_TypedFailureStaysTerminalAndIsNotTheRetryableSentinel: "we could not ask" and
// "the answer is not yet" are different facts and must not read the same (root cause D).
func TestADR0419_D8_TypedFailureStaysTerminalAndIsNotTheRetryableSentinel(t *testing.T) {
	defer withRunningSandboxes(t, func(string) ([]string, error) {
		return nil, status.Error(codes.Unavailable, "containerd down")
	})()
	_, err := sandboxIDForPodUID(context.Background(), adr0417ReplUID)
	if err == nil {
		t.Fatal("a transport failure must be an error")
	}
	if errors.Is(err, errNoSandboxForPodUID) {
		t.Error("a hard lookup failure must NOT become the retryable 'not yet' sentinel")
	}
}

// ---------------------------------------------------------------------------------------------
// §P-VERIFY #16 — D9's realpath confinement. §P-VERIFY #4 asserts only the lexically-outside case;
// these are the cases the provenance shift creates and #4 never covered.
// ---------------------------------------------------------------------------------------------

func withExtMountPrefixes(t *testing.T) func() {
	t.Helper()
	orig := extMountTokenPrefixesFn
	extMountTokenPrefixesFn = func() []string {
		return []string{"/var/lib/kubelet/pods/", filepath.Clean(restoreStagingRoot) + "/"}
	}
	return func() { extMountTokenPrefixesFn = orig }
}

// TestADR0419_D9_RealpathEscapeIsRejectedBeforeArgv: a target that is absolute, lexically clean,
// prefix-matching AND present in resolvedHostTargets — i.e. it passes every lexical rule — but
// whose HOST realpath lands outside every allowed prefix must be rejected. Lexical prefix
// membership stops being sufficient the moment the target's provenance shifts from an
// agent-constructed table to a runtime-supplied host path.
func TestADR0419_D9_RealpathEscapeIsRejectedBeforeArgv(t *testing.T) {
	defer withExtMountPrefixes(t)()
	target := "/var/lib/kubelet/pods/" + adr0417ReplUID + "/etc-hosts"

	orig := hostRealpathFn
	hostRealpathFn = func(string) (string, error) { return "/etc/shadow", nil }
	defer func() { hostRealpathFn = orig }()

	err := validateExtMountToken("/etc/hosts", target, map[string]bool{target: true})
	if err == nil {
		t.Fatal("a target whose HOST realpath escapes every allowed prefix must be rejected before argv")
	}
	if !strings.Contains(err.Error(), "/etc/shadow") || !strings.Contains(err.Error(), "outside every allowed destination prefix") {
		t.Errorf("the rejection must name the RESOLVED path it escaped to; got %q", err.Error())
	}
}

// TestADR0419_D9_UnresolvableRealpathFailsClosed is the correction of the fail-OPEN. The replaced
// branch read `if real, err := EvalSymlinks(target); err == nil && ...` — on resolve error the
// whole escape check was SKIPPED — and because the agent's mount namespace carries neither the
// kubelet pod tree nor the containerd sandbox tree, that error was the ONLY outcome for both path
// families that matter. This must now be a rejection, matching ADR-0351's own confinement.
func TestADR0419_D9_UnresolvableRealpathFailsClosed(t *testing.T) {
	defer withExtMountPrefixes(t)()
	target := "/var/lib/kubelet/pods/" + adr0417ReplUID + "/etc-hosts"

	orig := hostRealpathFn
	hostRealpathFn = func(string) (string, error) { return "", errors.New("broker unreachable") }
	defer func() { hostRealpathFn = orig }()

	err := validateExtMountToken("/etc/hosts", target, map[string]bool{target: true})
	if err == nil {
		t.Fatal("an unverifiable target must be REJECTED, not admitted — the err==nil fail-open is the defect D9 closes")
	}
	if !errors.Is(err, errExtMountRealpathUnresolved) {
		t.Errorf("the fail-closed leg must be classifiable; got %q", err.Error())
	}
}

// TestADR0419_D9_ResolvedInPrefixIsAccepted keeps the guard honest in the positive direction: D9
// must reject escapes, not reject everything.
func TestADR0419_D9_ResolvedInPrefixIsAccepted(t *testing.T) {
	defer withExtMountPrefixes(t)()
	target := "/var/lib/kubelet/pods/" + adr0417ReplUID + "/etc-hosts"
	orig := hostRealpathFn
	hostRealpathFn = func(p string) (string, error) { return p, nil }
	defer func() { hostRealpathFn = orig }()

	if err := validateExtMountToken("/etc/hosts", target, map[string]bool{target: true}); err != nil {
		t.Fatalf("a legitimate target whose realpath stays inside an allowed prefix must validate; got %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// §P-VERIFY #11 / #15 / #17 — the BIDIRECTIONAL removal-symmetry re-check, run mechanically against the
// real source. Over-deletion is as much a failure as under-deletion, and a reference count is
// blind to a CONTRACT changed behind a surviving reference — so this asserts both.
// ---------------------------------------------------------------------------------------------

func adr0419ReadSource(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// TestADR0419_RemovalSymmetry_RemovedSymbolsAreGone is the §P-VERIFY #11(a) forward direction.
func TestADR0419_RemovalSymmetry_RemovedSymbolsAreGone(t *testing.T) {
	src := adr0419ReadSource(t, "server.go") +
		adr0419ReadSource(t, "containerd_discovery.go") +
		adr0419ReadSource(t, "adr0419_destination_mounts.go")
	// Each removed symbol, with the removal-symmetry audit row that dispositioned it.
	removed := map[string]string{
		"destinationRebindWellKnownTargets":      "row 1",
		"destinationRebindWellKnownTarget":       "row 1",
		"destinationRebindWriter":                "row 2",
		"rebindWriterKubeletPodDir":              "row 2",
		"rebindWriterContainerdSandboxDir":       "row 2",
		"rebindWriterAgentStaged":                "row 2",
		"hostRegularFileExistsFn":                "row 3",
		"hostRegularFileExists":                  "row 3",
		"containerdCRISandboxDir":                "row 4",
		"destinationRebindWaitBudget":            "row 5",
		"destinationRebindPollInterval":          "row 5",
		"resolveDestinationRebindTargetsOnce":    "row 6",
		"describeMissingDestinationRebindTarget": "row 6",
		"destinationRebindMissing":               "row 6",
		"DestinationRebindTargetNotStagedError":  "row 6/7",
		"DestinationRebindProbeError":            "row 7",
	}
	for sym, row := range removed {
		// Comments legitimately NAME these symbols to explain the removal, so only count
		// occurrences outside comment lines.
		for _, line := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || trimmed == "" {
				continue
			}
			if strings.Contains(line, sym) {
				t.Errorf("removal-symmetry %s: removed symbol %q still referenced in live code: %s", row, sym, trimmed)
			}
		}
	}
}

// TestADR0419_RemovalSymmetry_RetainedSymbolsSurvive is the §P-VERIFY #11(a) REVERSE direction —
// the half that catches OVER-deletion. Each of these has an independent surviving consumer and is
// exactly the shape a mechanical "delete everything the removed function touched" pass sweeps up.
func TestADR0419_RemovalSymmetry_RetainedSymbolsSurvive(t *testing.T) {
	server := adr0419ReadSource(t, "server.go")
	discovery := adr0419ReadSource(t, "containerd_discovery.go")

	cases := []struct {
		sym, in, why string
		src          string
	}{
		{"resolveContainerdRootDirFn", "server.go", "allowedExtMountHostTargetPrefixes needs the containerd root to authorize sandbox-dir prefixes (row 8)", server},
		{"criSandboxDirRel", "server.go", "same allowlist consumer as row 8 (row 9)", server},
		{"resolveContainerdRootDir", "containerd_discovery.go", "the production implementation behind the retained seam (row 8)", discovery},
		{"sandboxIDForPodUID", "server.go", "the ADR-0306 pod-netns join gate still calls it — it is HARDENED, not deleted (row 10)", server},
		{"errNoSandboxForPodUID", "server.go", "its zero-match retryable contract is invariant (row 10 contract-delta)", server},
		{"ensureRestoreTerminationLogFile", "server.go", "the real destination-side write edge, with a second independent caller (row 12)", server},
		{"resolveReplacementPod", "server.go", "six independent surviving consumers, including the pod-netns join gate itself (row 15)", server},
		{"validateExtMountToken", "server.go", "the --ext-mount-map guard survives; only its fail-open realpath branch changed (row 16)", server},
		{"reattachTierDestinationRebind", "server.go", "ADR-0417's classification-and-emission axis, explicitly preserved (row 11)", server},
		{"allowedExtMountHostTargetPrefixes", "server.go", "the token allowlist itself", server},
	}
	for _, c := range cases {
		if !strings.Contains(c.src, c.sym) {
			t.Errorf("OVER-DELETION: retained symbol %q vanished from %s — %s", c.sym, c.in, c.why)
		}
	}
}

// TestADR0419_RemovalSymmetry_SurvivingContractEdges is §P-VERIFY #11(b) — the half a reference
// count is structurally blind to. An over-deletion of a CONTRACT is as much a removal-symmetry failure as an
// over-deletion of a symbol, and the original #11 would have passed cleanly while the semantics
// underneath it were broken.
func TestADR0419_RemovalSymmetry_SurvivingContractEdges(t *testing.T) {
	server := adr0419ReadSource(t, "server.go")
	// The construction site count is asserted EXACTLY, because the ADR's contract is that it stays
	// exactly one — not zero (severed) and not two (a second, divergent path).
	if n := strings.Count(server, "&ReplacementSandboxNotYetCreatedError{"); n != 1 {
		t.Errorf("ReplacementSandboxNotYetCreatedError is constructed %d times in server.go, want exactly 1 — it is the sole construction site repo-wide, reached only through the errNoSandboxForPodUID classifier", n)
	}
	// The classifier edges are asserted as PRESENT. errors.As(err, &notYet) legitimately appears on
	// a second, unrelated bounded-wait path, so an exact count would assert something the contract
	// does not claim.
	for _, e := range []struct{ frag, why string }{
		{"errors.Is(err, errNoSandboxForPodUID)", "the ONLY surviving classifier of the zero-match sentinel; without it ReplacementSandboxNotYetCreatedError is never constructed anywhere in the tree"},
		{"errors.As(err, &notYet)", "the edge that arms the 60s pod-netns-join bounded wait"},
	} {
		if !strings.Contains(server, e.frag) {
			t.Errorf("surviving contract edge %q is gone from server.go — %s", e.frag, e.why)
		}
	}
	// And specifically inside the gate that owns the 60s wait, not merely somewhere in the file.
	gi := strings.Index(server, "func (s *AgentServer) resolvePodNetnsSandboxWaiting(")
	if gi < 0 {
		t.Fatal("resolvePodNetnsSandboxWaiting not found")
	}
	gate := server[gi:]
	if end := strings.Index(gate, "\n}\n"); end > 0 {
		gate = gate[:end]
	}
	if !strings.Contains(gate, "errors.As(err, &notYet)") {
		t.Error("the pod-netns join gate no longer classifies ReplacementSandboxNotYetCreatedError — its 60s bounded wait can never arm")
	}
}

// TestADR0419_CallSiteArityAndNoFailOpen is §P-VERIFY #11(c) + #15. #11's symbol grep is blind to
// arity, which is exactly how the third call site stayed invisible through a whole ADR revision.
func TestADR0419_CallSiteArityAndNoFailOpen(t *testing.T) {
	server := adr0419ReadSource(t, "server.go")

	// (a) THREE call sites, not two.
	if n := strings.Count(server, "s.appendDestinationRebindReattachMounts("); n != 3 {
		t.Errorf("appendDestinationRebindReattachMounts must have exactly THREE call sites; found %d", n)
	}
	// (b) None passes "" for sandboxID — the shape that makes every demanded mount hit D3's hard
	// stop and fails every raw-path restore closed.
	for _, bad := range []string{`, "", nil, reattachMounts)`, `, "", nil, rawReattachMounts)`} {
		if strings.Contains(server, bad) {
			t.Errorf("a call site passes an empty sandboxID (%q) — an explicitly rejected shape", bad)
		}
	}
	// (c) The early return was NOT extended to cover an empty sandbox ID. That is a FAIL-OPEN: the
	// DESTINATION-REBIND targets silently vanish from --ext-mount-map, CRIU restores against the
	// SOURCE node's recorded source, and it ENOENTs mid-restore — the exact defect ADR-0417 exists
	// to fix, reintroduced. Hard reject.
	if strings.Contains(server, `if s.k8sClient == nil || migrationName == "" || sandboxID == ""`) {
		t.Error("FAIL-OPEN: the early return was extended to tolerate an empty sandboxID — explicitly rejected shape")
	}

	// (d) D2b: on the raw branch the sandbox gate is invoked BEFORE the rebind fold-in.
	gate := strings.Index(server, "joinSandboxID2, sandboxAttempted2 :=")
	rebind := strings.Index(server, "rawReattachMounts, rawDRErr :=")
	if gate < 0 || rebind < 0 {
		t.Fatal("could not locate the raw-branch gate and rebind call")
	}
	if gate > rebind {
		t.Error("D2b: on the raw branch resolvePodNetnsSandboxWaiting must run BEFORE appendDestinationRebindReattachMounts, converging on the config.json branch's already-deliberate order")
	}
}

// TestADR0419_DeletedProbeShapeIsGone is §P-VERIFY #9's RESCOPED grep. It asserts zero remaining
// hits for the deleted `sh -c '[ -f ... ]'` broker-exec shape — NOT zero hits for all
// host-namespace target validation, which would have forbidden D9's required remedy.
func TestADR0419_DeletedProbeShapeIsGone(t *testing.T) {
	src := adr0419ReadSource(t, "server.go") + adr0419ReadSource(t, "adr0419_destination_mounts.go")
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}
		if strings.Contains(line, "PM_PRESENT") || strings.Contains(line, "PM_ABSENT") || strings.Contains(line, "[ -f ") {
			t.Errorf("the deleted host-file probe shape survives: %s", trimmed)
		}
	}
	// And the remedy D9 requires DOES exist — the rescoping is what makes both true at once.
	if !strings.Contains(adr0419ReadSource(t, "adr0419_destination_mounts.go"), "hostRealpathFn") {
		t.Error("D9's typed broker realpath read must exist — §P-VERIFY #9's grep is rescoped precisely so it does not forbid it")
	}
}

// TestADR0419_StaleCompensatingControlCommentIsRewritten is §P-VERIFY #16(c). Leaving a comment
// that cites a deleted compensating control asserts a guard that no longer exists, which is worse
// than the gap itself.
func TestADR0419_StaleCompensatingControlCommentIsRewritten(t *testing.T) {
	server := adr0419ReadSource(t, "server.go")
	idx := strings.Index(server, "func validateExtMountToken(")
	if idx < 0 {
		t.Fatal("validateExtMountToken not found")
	}
	body := server[idx:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	// The stale CLAIM, verbatim from the comment D9 requires rewritten. Naming the deleted function
	// in order to say it was deleted is correct and expected; asserting it as a live compensating
	// control is the thing that must be gone.
	if strings.Contains(body, "are instead resolved and existence-probed in the host namespace at resolution time") {
		t.Error("validateExtMountToken still asserts the DELETED resolveDestinationRebindTargetsOnce as a live compensating control")
	}
	// The fail-open itself must be gone from CODE. Comments quoting the retired branch to explain
	// why it was retired are correct and must not trip this.
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}
		if strings.Contains(line, "EvalSymlinks") {
			t.Errorf("validateExtMountToken still resolves symlinks in the AGENT's own mount namespace (%s) — the kubelet and containerd trees are not present there, so that check can only ever fail open", trimmed)
		}
	}
	if !strings.Contains(body, "confineExtMountTargetRealpath") {
		t.Error("validateExtMountToken must delegate confinement to the typed host-namespace realpath read (D9)")
	}
}

// TestADR0419_NoPathResolvedCtrInvocations is §P-VERIFY #17. internal/agent/nri/plugin.go's
// fetchContainerImage was the ONLY one of the in-tree `ctr` invocations that was PATH-resolved
// rather than pinned to /usr/local/bin/ctr — inside a hostPID:true pod, i.e. a binary-shadowing
// primitive: anything that could place a `ctr` earlier on PATH would have had its output parsed as
// containerd's. It carries its own assertion here rather than living in a subordinate clause of D5,
// where it would not otherwise have landed.
func TestADR0419_NoPathResolvedCtrInvocations(t *testing.T) {
	var hits []string
	root := ".."
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		// _test.go files are excluded: this very assertion contains the literal it searches for.
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(b), `exec.Command("ctr"`) {
			hits = append(hits, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf(`exec.Command("ctr", ...) must have ZERO hits — every ctr invocation is pinned to an absolute path; found in %v`, hits)
	}
}

// ---------------------------------------------------------------------------------------------
// D4 — the demand-set decoder, driven against a REAL mountpoints image via the real pycriu decode.
// ---------------------------------------------------------------------------------------------

// TestADR0419_D4_DemandSetAgreesWithThePatchScriptClassifier runs the PRODUCTION
// destinationRebindDemandSet against real, pycriu-written mountpoints images.
//
// The two classifiers MUST agree. destinationRebindDemandSet decides which mounts the Go side goes
// and resolves a host target for; patch_checkpoint_script.go decides which mounts REQUIRE one. A
// mount the script classifies DESTINATION-REBIND but this scan fails to demand would reach the
// script with no resolved target and hard-stop there — a worse-worded version of the very failure
// this ADR removes. So this asserts agreement on both sides of the allowlist boundary, using the
// same fstype corpus generator the ADR-0417 classifier tests use.
func TestADR0419_D4_DemandSetAgreesWithThePatchScriptClassifier(t *testing.T) {
	// Codes drawn from CRIU 4.2's own fstypes[] table, as decoded for ADR-0417.
	recreatable := []int{1, 2, 3, 4, 5, 6, 14}        // construct-and-fill: NOT demanded
	notRecreatable := []int{0, 7, 15, 16, 17, 20, 99} // must be demanded, incl. codes outside the table

	origStaging := restoreStagingRoot
	defer func() { restoreStagingRoot = origStaging }()

	for _, code := range recreatable {
		t.Run("recreatable_not_demanded_"+strconv.Itoa(code), func(t *testing.T) {
			pypath, extraEnv := pycriuEnv(t)
			ckpt := t.TempDir()
			writeADR0417FstypeCorpus(t, pypath, extraEnv, ckpt, code)
			restoreStagingRoot = t.TempDir()
			got, err := destinationRebindDemandSet(context.Background(), "d4-mig", ckpt)
			if err != nil {
				t.Fatalf("demand-set scan: %v", err)
			}
			for _, mp := range got {
				if mp == "/mnt/probe" {
					t.Errorf("fstype %d is CRIU-recreatable — the script internalizes it and never asks for a destination target, so it must NOT be demanded; got %v", code, got)
				}
			}
		})
	}

	for _, code := range notRecreatable {
		t.Run("not_recreatable_demanded_"+strconv.Itoa(code), func(t *testing.T) {
			pypath, extraEnv := pycriuEnv(t)
			ckpt := t.TempDir()
			writeADR0417FstypeCorpus(t, pypath, extraEnv, ckpt, code)
			restoreStagingRoot = t.TempDir()
			got, err := destinationRebindDemandSet(context.Background(), "d4-mig", ckpt)
			if err != nil {
				t.Fatalf("demand-set scan: %v", err)
			}
			var found bool
			for _, mp := range got {
				if mp == "/mnt/probe" {
					found = true
				}
			}
			if !found {
				t.Errorf("fstype %d is NOT CRIU-recreatable — patch_checkpoint_script.go hard-stops without a destination target, so it MUST be demanded; got %v", code, got)
			}
		})
	}
}

// TestADR0419_D4_EmptyCheckpointDirFailsClosed: the demand set is what decides whether ANY target is
// required, so being unable to read it must never silently mean "nothing is demanded". That would
// be a fail-open with exactly the shape ADR-0417 exists to prevent.
func TestADR0419_D4_EmptyCheckpointDirFailsClosed(t *testing.T) {
	if _, err := destinationRebindDemandSet(context.Background(), "d4-mig", ""); err == nil {
		t.Fatal("an unreadable/absent checkpoint dir must fail closed, never resolve to an empty demand set")
	}
}
