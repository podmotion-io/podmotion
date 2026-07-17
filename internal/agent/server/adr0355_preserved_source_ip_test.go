/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0.
*/

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
	"github.com/podmotion-io/podmotion/internal/metrics"
)

// ADR-0355 D5 — regression tests for the preserved-source-IP pre-CRIU bind-prep and its
// composition with the now-live ADR-0138 single-home backfill.

const bindPrepReason = "restore_preserved_source_addr_bind_prep"

func bindPrepFailCount() float64 {
	return testutil.ToFloat64(metrics.MigrationsFailedTotal.WithLabelValues(bindPrepReason))
}

// addCall records one addPreservedSourceAddrFn invocation.
type addCall struct {
	netnsPath string
	ifname    string
	ip        string
}

func makeCountingAddFn(calls *[]addCall) func(context.Context, string, string, net.IP) error {
	return func(_ context.Context, netnsPath, ifname string, ip net.IP) error {
		*calls = append(*calls, addCall{netnsPath, ifname, ip.String()})
		return nil
	}
}

func makeErrorAddFn(err error) func(context.Context, string, string, net.IP) error {
	return func(_ context.Context, _, _ string, _ net.IP) error { return err }
}

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad test IP %q", s)
	}
	return ip
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeCheckpointWithTCP creates a temp checkpoint dir; if established is true it drops a
// tcp-stream-*.img so checkpointHasEstablishedTCP reports true.
func writeCheckpointWithTCP(t *testing.T, established bool) string {
	t.Helper()
	dir := t.TempDir()
	if established {
		if err := os.WriteFile(filepath.Join(dir, "tcp-stream-42.img"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write tcp-stream img: %v", err)
		}
	}
	return dir
}

// D5 test 3 (DR-8): checkpointHasEstablishedTCP has both-branch coverage (was zero).
func TestCheckpointHasEstablishedTCP_BothBranches(t *testing.T) {
	if got := checkpointHasEstablishedTCP(writeCheckpointWithTCP(t, false)); got {
		t.Errorf("checkpointHasEstablishedTCP(no tcp-stream img) = true, want false")
	}
	if got := checkpointHasEstablishedTCP(writeCheckpointWithTCP(t, true)); !got {
		t.Errorf("checkpointHasEstablishedTCP(with tcp-stream img) = false, want true")
	}
}

// D5 test 1 (DR-3/DR-12/DR-15/DR-9): the joinNsRestore bind-prep gate. Asserts the broker-add seam
// call count is EXACTLY ZERO on every negative branch (preservedSourceIP=="",
// !checkpointHasEstablishedTCP, and the malformed-non-empty branch), that the malformed branch is
// fail-closed (metric +1, errInvalidPreservedSourceIP), and that on the positive branch the seam is
// invoked exactly once with (netnsPath, ifname, parsedIP). "No error" is never the assertion — the
// call count + counter delta are. CRIU is never invoked on any fail-closed branch because
// joinNsRestore propagates the returned error BEFORE buildCRIURestoreArgs (code-position invariant).
func TestPrepPreservedSourceAddrForRestore_Gating(t *testing.T) {
	tcpDir := writeCheckpointWithTCP(t, true)
	noTCPDir := writeCheckpointWithTCP(t, false)

	tests := []struct {
		name             string
		preservedIP      string
		checkpointDir    string
		wantCalls        int
		wantErr          bool
		wantInvalidIPErr bool
		wantCounterDelta float64
	}{
		{name: "empty_preserved_ip_gate_not_met", preservedIP: "", checkpointDir: tcpDir, wantCalls: 0},
		{name: "no_established_tcp_gate_not_met", preservedIP: "10.244.0.41", checkpointDir: noTCPDir, wantCalls: 0},
		{name: "malformed_octet_fails_closed", preservedIP: "10.244.0.999", checkpointDir: tcpDir, wantCalls: 0, wantErr: true, wantInvalidIPErr: true, wantCounterDelta: 1},
		{name: "garbage_fails_closed", preservedIP: "garbage", checkpointDir: tcpDir, wantCalls: 0, wantErr: true, wantInvalidIPErr: true, wantCounterDelta: 1},
		{name: "ipv6_literal_fails_closed", preservedIP: "fe80::1", checkpointDir: tcpDir, wantCalls: 0, wantErr: true, wantInvalidIPErr: true, wantCounterDelta: 1},
		{name: "valid_ipv4_established_tcp_one_add", preservedIP: "10.244.0.41", checkpointDir: tcpDir, wantCalls: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []addCall
			orig := addPreservedSourceAddrFn
			addPreservedSourceAddrFn = makeCountingAddFn(&calls)
			defer func() { addPreservedSourceAddrFn = orig }()

			before := bindPrepFailCount()
			err := prepPreservedSourceAddrForRestore(context.Background(), "mig-"+tc.name, tc.checkpointDir, "/var/run/netns/cni-test", "eth0", tc.preservedIP)

			if len(calls) != tc.wantCalls {
				t.Fatalf("addPreservedSourceAddrFn call count = %d, want %d", len(calls), tc.wantCalls)
			}
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tc.wantInvalidIPErr && !errors.Is(err, errInvalidPreservedSourceIP) {
				t.Fatalf("expected errors.Is(err, errInvalidPreservedSourceIP), got %v", err)
			}
			if delta := bindPrepFailCount() - before; delta != tc.wantCounterDelta {
				t.Fatalf("MigrationsFailedTotal{%s} delta = %v, want %v", bindPrepReason, delta, tc.wantCounterDelta)
			}
			if tc.wantCalls == 1 {
				got := calls[0]
				if got.netnsPath != "/var/run/netns/cni-test" || got.ifname != "eth0" || got.ip != "10.244.0.41" {
					t.Fatalf("positive-branch add args = %+v, want {netnsPath:/var/run/netns/cni-test ifname:eth0 ip:10.244.0.41}", got)
				}
			}
		})
	}
}

// D5 test 4 (DR-9/DR-12): a broker addPreservedSourceAddr FAILURE on the positive branch is
// fail-closed — the gate returns an error (which joinNsRestore propagates before CRIU) and the
// distinct counter increments exactly once. "returned an error" is not the load-bearing assertion;
// the labeled counter is.
func TestPrepPreservedSourceAddrForRestore_BrokerAddError_FailClosed(t *testing.T) {
	tcpDir := writeCheckpointWithTCP(t, true)
	orig := addPreservedSourceAddrFn
	addPreservedSourceAddrFn = makeErrorAddFn(errors.New("broker unreachable"))
	defer func() { addPreservedSourceAddrFn = orig }()

	before := bindPrepFailCount()
	err := prepPreservedSourceAddrForRestore(context.Background(), "mig-broker-err", tcpDir, "/var/run/netns/cni-x", "eth0", "10.244.0.41")
	if err == nil {
		t.Fatal("expected fail-closed error on broker add failure, got nil")
	}
	if errors.Is(err, errInvalidPreservedSourceIP) {
		t.Fatal("broker-add failure must NOT be the malformed-IP sentinel — distinct fail-closed cause")
	}
	if delta := bindPrepFailCount() - before; delta != 1 {
		t.Fatalf("MigrationsFailedTotal{%s} delta = %v, want 1", bindPrepReason, delta)
	}
}

// D5 test 2 (DR-2/DR-10): addPreservedSourceAddr is BROKER-DELEGATED. Asserts (i) argv shape is the
// idempotent `ip -4 addr replace <ip>/32 scope host dev <ifname>`; (ii) a bind-path target maps to
// the broker netnsPath arg with srcPID==0; (iii) a /proc/<N>/ns/net target maps to srcPID==N with
// netnsPath==""; (iv) a non-IPv4 ip errors WITHOUT any broker call; (v) SpawnErr!=nil or
// ExitCode!=0 makes addPreservedSourceAddr fail-closed. No unix.Setns anywhere.
func TestAddPreservedSourceAddr_BrokerDelegation(t *testing.T) {
	type capture struct {
		called    bool
		srcPID    int
		netnsPath string
		argv      []string
	}

	install := func(cap *capture, ret netnsbroker.ExecResult) func() {
		orig := brokerNetnsExecFn
		brokerNetnsExecFn = func(_ context.Context, srcPID int, netnsPath string, argv ...string) netnsbroker.ExecResult {
			cap.called = true
			cap.srcPID = srcPID
			cap.netnsPath = netnsPath
			cap.argv = argv
			return ret
		}
		return func() { brokerNetnsExecFn = orig }
	}

	ip := mustIP(t, "10.244.0.41")

	t.Run("bind_path_target_and_argv_shape", func(t *testing.T) {
		var cap capture
		defer install(&cap, netnsbroker.ExecResult{ExitCode: 0})()
		if err := addPreservedSourceAddr(context.Background(), "/var/run/netns/cni-abc", "eth0", ip); err != nil {
			t.Fatalf("addPreservedSourceAddr returned error: %v", err)
		}
		if !cap.called {
			t.Fatal("broker was not called — addPreservedSourceAddr must delegate, never in-process setns")
		}
		if cap.srcPID != 0 || cap.netnsPath != "/var/run/netns/cni-abc" {
			t.Fatalf("target mapping = (srcPID=%d, netnsPath=%q), want (0, /var/run/netns/cni-abc)", cap.srcPID, cap.netnsPath)
		}
		want := []string{"ip", "-4", "addr", "replace", "10.244.0.41/32", "scope", "host", "dev", "eth0"}
		if !equalStrs(cap.argv, want) {
			t.Fatalf("argv = %v, want %v", cap.argv, want)
		}
	})

	t.Run("proc_path_target_maps_to_srcPID", func(t *testing.T) {
		var cap capture
		defer install(&cap, netnsbroker.ExecResult{ExitCode: 0})()
		if err := addPreservedSourceAddr(context.Background(), "/proc/8123/ns/net", "eth0", ip); err != nil {
			t.Fatalf("addPreservedSourceAddr returned error: %v", err)
		}
		if cap.srcPID != 8123 || cap.netnsPath != "" {
			t.Fatalf("proc target mapping = (srcPID=%d, netnsPath=%q), want (8123, \"\")", cap.srcPID, cap.netnsPath)
		}
	})

	t.Run("non_ipv4_errors_without_broker_call", func(t *testing.T) {
		var cap capture
		defer install(&cap, netnsbroker.ExecResult{ExitCode: 0})()
		if err := addPreservedSourceAddr(context.Background(), "/var/run/netns/cni-abc", "eth0", mustIP(t, "fe80::1")); err == nil {
			t.Fatal("expected error for non-IPv4 ip")
		}
		if cap.called {
			t.Fatal("broker must NOT be called for a non-IPv4 ip")
		}
	})

	t.Run("fail_closed_on_spawn_err", func(t *testing.T) {
		var cap capture
		defer install(&cap, netnsbroker.ExecResult{ExitCode: -1, SpawnErr: errors.New("broker down")})()
		if err := addPreservedSourceAddr(context.Background(), "/var/run/netns/cni-abc", "eth0", ip); err == nil {
			t.Fatal("expected fail-closed error on broker SpawnErr")
		}
	})
	t.Run("fail_closed_on_nonzero_exit", func(t *testing.T) {
		var cap capture
		defer install(&cap, netnsbroker.ExecResult{ExitCode: 2, Combined: []byte("RTNETLINK answers: ...")})()
		if err := addPreservedSourceAddr(context.Background(), "/var/run/netns/cni-abc", "eth0", ip); err == nil {
			t.Fatal("expected fail-closed error on broker non-zero exit")
		}
	})
}

// TestProcNetnsPID_TwoFormMapping locks the /proc/<N>/ns/net → srcPID vs bind-path → netnsPath
// deterministic dispatch addPreservedSourceAddr relies on (the broker's validateNetnsPath rejects
// /proc paths by design).
func TestProcNetnsPID_TwoFormMapping(t *testing.T) {
	cases := []struct {
		in      string
		wantPID int
		wantOK  bool
	}{
		{"/proc/8123/ns/net", 8123, true},
		{"/proc/1/ns/net", 1, true},
		{"/var/run/netns/cni-abc", 0, false},
		{"/run/netns/foo", 0, false},
		{"/proc//ns/net", 0, false},
		{"/proc/abc/ns/net", 0, false},
		{"/proc/12/ns/mnt", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		gotPID, gotOK := procNetnsPID(c.in)
		if gotPID != c.wantPID || gotOK != c.wantOK {
			t.Errorf("procNetnsPID(%q) = (%d, %v), want (%d, %v)", c.in, gotPID, gotOK, c.wantPID, c.wantOK)
		}
	}
}

// TestParseEth0IPv4Addrs_RetainsScope (DR-7 fragment / D4 part 3): the parser retains the scope
// token so the scope-aware oldSeen can distinguish a scope-host /32 from a scope-global /24.
func TestParseEth0IPv4Addrs_RetainsScope(t *testing.T) {
	out := "" +
		"2: eth0    inet 10.244.0.41/24 brd 10.244.0.255 scope global eth0\\       valid_lft forever preferred_lft forever\n" +
		"2: eth0    inet 10.244.0.41/32 scope host eth0\\       valid_lft forever preferred_lft forever\n"
	got := parseEth0IPv4Addrs(out)
	if len(got) != 2 {
		t.Fatalf("parsed %d addrs, want 2: %+v", len(got), got)
	}
	if got[0].CIDR != "10.244.0.41/24" || got[0].Scope != "global" {
		t.Errorf("addr[0] = %+v, want {10.244.0.41/24 global}", got[0])
	}
	if got[1].CIDR != "10.244.0.41/32" || got[1].Scope != "host" {
		t.Errorf("addr[1] = %+v, want {10.244.0.41/32 host}", got[1])
	}
}

// D5 test 5 (DR-7/DR-14): finalizeRestore liveness + fail-closed, driven through the REAL
// finalizeRestore entry (a direct SingleHomeRestoredPod call is explicitly rejected as the liveness
// proof). Uses the singleHomeRestoredPodFn seam and a fake client so the ADR-0138 backfill's
// liveness (namespace resolved even when the caller passes "") and the established-TCP fail-closed
// boundary are observable without a real netns broker.
func TestFinalizeRestore_D4_LivenessAndFailClosed(t *testing.T) {
	origMAC := readReplVethMACFn
	readReplVethMACFn = func(_ int, _, _ string) (string, error) { return "aa:bb:cc:dd:ee:ff", nil }
	defer func() { readReplVethMACFn = origMAC }()

	newServerWithPM := func(t *testing.T, migration string) *AgentServer {
		pm := &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: "podmotion-test"},
			Spec:       pmv1.PodMigrationSpec{SourcePodIP: "10.244.0.41"},
		}
		cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
		return New("test-node", &criu.StubCheckpointer{}, cl)
	}

	// (a) LIVENESS: caller passes namespace="" (as all four production callers do); the backfill
	// must still run because finalizeRestore resolves the namespace. establishedTCP=false here so
	// the override's nil return is the non-fatal happy path.
	t.Run("liveness_namespace_resolved_from_CR", func(t *testing.T) {
		const migration = "adr0355-liveness"
		s := newServerWithPM(t, migration)
		var gotNS string
		var invoked bool
		orig := singleHomeRestoredPodFn
		singleHomeRestoredPodFn = func(_ *AgentServer, _ context.Context, _, namespace string, _ int) error {
			invoked = true
			gotNS = namespace
			return nil
		}
		defer func() { singleHomeRestoredPodFn = orig }()

		fr, err := s.finalizeRestore(context.Background(), 4242, "", "eth0", migration, "", "None", writeCheckpointWithTCP(t, false))
		if err != nil {
			t.Fatalf("finalizeRestore returned error: %v", err)
		}
		if !invoked {
			t.Fatal("SingleHomeRestoredPod path was NOT invoked — the ADR-0138 backfill is still dead (namespace not resolved at the call site)")
		}
		if gotNS != "podmotion-test" {
			t.Fatalf("SingleHomeRestoredPod invoked with namespace=%q, want the CR-resolved \"podmotion-test\"", gotNS)
		}
		if !fr.singleHomed {
			t.Fatal("result.singleHomed = false, want true after a successful single-home backfill")
		}
	})

	// (c) FAIL-CLOSED on established TCP: a backfill error MUST fail the restore.
	t.Run("established_tcp_backfill_error_fails_closed", func(t *testing.T) {
		const migration = "adr0355-failclosed-estab"
		s := newServerWithPM(t, migration)
		orig := singleHomeRestoredPodFn
		singleHomeRestoredPodFn = func(_ *AgentServer, _ context.Context, _, _ string, _ int) error {
			return errors.New("backfill failed")
		}
		defer func() { singleHomeRestoredPodFn = orig }()

		_, err := s.finalizeRestore(context.Background(), 4242, "", "eth0", migration, "", "None", writeCheckpointWithTCP(t, true))
		if err == nil {
			t.Fatal("expected finalizeRestore to FAIL CLOSED on an established-TCP backfill error (DR-14), got nil — the deferred SIGCONT would resume onto the non-routable /32")
		}
	})

	// (c) BOUNDARY: the SAME backfill error on a NON-established-TCP restore is non-fatal.
	t.Run("non_established_tcp_backfill_error_is_non_fatal", func(t *testing.T) {
		const migration = "adr0355-nonfatal"
		s := newServerWithPM(t, migration)
		orig := singleHomeRestoredPodFn
		singleHomeRestoredPodFn = func(_ *AgentServer, _ context.Context, _, _ string, _ int) error {
			return errors.New("backfill failed")
		}
		defer func() { singleHomeRestoredPodFn = orig }()

		if _, err := s.finalizeRestore(context.Background(), 4242, "", "eth0", migration, "", "None", writeCheckpointWithTCP(t, false)); err != nil {
			t.Fatalf("non-established-TCP backfill error must be non-fatal, got %v", err)
		}
	})

	// (c) FAIL-CLOSED on unresolved namespace + established TCP: the /24 backfill cannot run.
	t.Run("unresolved_namespace_established_tcp_fails_closed", func(t *testing.T) {
		const migration = "adr0355-ns-unresolved"
		cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
		s := New("test-node", &criu.StubCheckpointer{}, cl)
		var invoked bool
		orig := singleHomeRestoredPodFn
		singleHomeRestoredPodFn = func(_ *AgentServer, _ context.Context, _, _ string, _ int) error {
			invoked = true
			return nil
		}
		defer func() { singleHomeRestoredPodFn = orig }()

		_, err := s.finalizeRestore(context.Background(), 4242, "", "eth0", migration, "", "None", writeCheckpointWithTCP(t, true))
		if err == nil {
			t.Fatal("expected fail-closed on unresolved namespace + established TCP (DR-14), got nil")
		}
		if invoked {
			t.Fatal("SingleHomeRestoredPod must NOT be invoked when the namespace is unresolved")
		}
	})
}

// newAgentServerWithPM builds an AgentServer backed by a fake client holding one PodMigration whose
// Spec.SourcePodIP is sourceIP — the field SingleHomeRestoredPod single-homes on (ADR-0355 D2).
func newAgentServerWithPM(t *testing.T, migration, namespace, sourceIP string) *AgentServer {
	t.Helper()
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migration, Namespace: namespace},
		Spec:       pmv1.PodMigrationSpec{SourcePodIP: sourceIP},
	}
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pm).WithStatusSubresource(pm).Build()
	return New("test-node", &criu.StubCheckpointer{}, cl)
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func hasAddr(addrs []eth0Addr, cidr, scope string) bool {
	for _, a := range addrs {
		if a.CIDR == cidr && a.Scope == scope {
			return true
		}
	}
	return false
}

func argvAfter(argv []string, key string) (string, bool) {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == key {
			return argv[i+1], true
		}
	}
	return "", false
}

func argvHas(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

// fakeEth0Broker is a stateful stand-in for brokerNetnsExecFn that models eth0's IPv4 address set the
// way iproute2 would, so SingleHomeRestoredPod's strip/add/verify sequence runs end-to-end without a
// real netns broker. It records `ip addr add`/`ip addr del` CIDRs for assertions.
type fakeEth0Broker struct {
	addrs    []eth0Addr
	addCalls []string
	delCalls []string
}

func (f *fakeEth0Broker) exec(_ context.Context, _ int, _ string, argv ...string) netnsbroker.ExecResult {
	switch {
	case argvHas(argv, "addr") && argvHas(argv, "show"):
		var b strings.Builder
		for _, a := range f.addrs {
			fmt.Fprintf(&b, "2: eth0    inet %s brd 10.244.255.255 scope %s eth0\\       valid_lft forever preferred_lft forever\n", a.CIDR, a.Scope)
		}
		return netnsbroker.ExecResult{ExitCode: 0, Combined: []byte(b.String())}
	case argvHas(argv, "addr") && argvHas(argv, "add"):
		cidr, _ := argvAfter(argv, "add")
		f.addCalls = append(f.addCalls, cidr)
		scope := "global" // iproute2 default for a /24; the mutating code passes no `scope` on the add
		if s, ok := argvAfter(argv, "scope"); ok {
			scope = s
		}
		f.addrs = append(f.addrs, eth0Addr{CIDR: cidr, Scope: scope})
		return netnsbroker.ExecResult{ExitCode: 0}
	case argvHas(argv, "addr") && argvHas(argv, "del"):
		cidr, _ := argvAfter(argv, "del")
		f.delCalls = append(f.delCalls, cidr)
		var kept []eth0Addr
		for _, a := range f.addrs {
			if a.CIDR != cidr {
				kept = append(kept, a)
			}
		}
		f.addrs = kept
		return netnsbroker.ExecResult{ExitCode: 0}
	default: // `ip route ...` and anything else — succeed, no address-set effect
		return netnsbroker.ExecResult{ExitCode: 0}
	}
}

// D5 test 5(b) (DR-7): SingleHomeRestoredPod's ADR-0138 /24 backfill is scope-aware. D1's oldIP/32
// scope-host artifact must NOT be treated as "already single-homed" (the scope-blind bug the ADR
// fixes) and must NOT be stripped; a scope-GLOBAL oldIP correctly suppresses the re-add. Driven
// directly (a direct call is acceptable for the MUTATION assertion — only the LIVENESS assertion,
// test 5a, must go through finalizeRestore) with a stateful fake broker.
func TestSingleHomeRestoredPod_D4_ScopeAwareBackfill(t *testing.T) {
	const oldIP = "10.244.0.41"

	t.Run("pin_not_honored_dual_homes_keeps_cni_primary_and_old_ip", func(t *testing.T) {
		// sprint46B9 regression fix: when the preserved-IP pin is NOT honored, eth0 carries a
		// non-OLD scope-GLOBAL Cilium primary (the pod's real routable identity / k8s Status.PodIP /
		// WorkloadLivenessVerified probe target) alongside D1's oldIP/32 scope-host. SingleHomeRestoredPod
		// must DUAL-HOME: keep BOTH and strip NEITHER. Stripping the CNI primary is exactly what made the
		// live probe fail "no route to host" for 240s. No addr add and no del may occur.
		const migration = "adr0355-dualhome"
		s := newAgentServerWithPM(t, migration, "podmotion-test", oldIP)
		fk := &fakeEth0Broker{addrs: []eth0Addr{
			{CIDR: "10.244.2.55/24", Scope: "global"}, // the Cilium-assigned primary (pin not honored)
			{CIDR: oldIP + "/32", Scope: "host"},      // the D1 pre-CRIU artifact
		}}
		orig := brokerNetnsExecFn
		brokerNetnsExecFn = fk.exec
		defer func() { brokerNetnsExecFn = orig }()

		if err := s.SingleHomeRestoredPod(context.Background(), migration, "podmotion-test", 4242); err != nil {
			t.Fatalf("SingleHomeRestoredPod returned error: %v", err)
		}
		if len(fk.delCalls) != 0 {
			t.Fatalf("dual-home must strip NOTHING — the CNI primary is the probe/Service target (delCalls=%v)", fk.delCalls)
		}
		if len(fk.addCalls) != 0 {
			t.Fatalf("dual-home must NOT re-home onto oldIP/24 — the CNI primary stays the routable identity (addCalls=%v)", fk.addCalls)
		}
		if !hasAddr(fk.addrs, "10.244.2.55/24", "global") || !hasAddr(fk.addrs, oldIP+"/32", "host") {
			t.Fatalf("terminal eth0 = %v, want BOTH the CNI primary 10.244.2.55/24 global and %s/32 host retained", fk.addrs, oldIP)
		}
	})

	t.Run("scope_global_24_suppresses_add_and_no_strip", func(t *testing.T) {
		const migration = "adr0355-scope-nostrip"
		s := newAgentServerWithPM(t, migration, "podmotion-test", oldIP)
		fk := &fakeEth0Broker{addrs: []eth0Addr{
			{CIDR: oldIP + "/24", Scope: "global"}, // pin honored: oldIP is already the scope-global primary
			{CIDR: oldIP + "/32", Scope: "host"},   // the D1 pre-CRIU artifact
		}}
		orig := brokerNetnsExecFn
		brokerNetnsExecFn = fk.exec
		defer func() { brokerNetnsExecFn = orig }()

		if err := s.SingleHomeRestoredPod(context.Background(), migration, "podmotion-test", 4242); err != nil {
			t.Fatalf("SingleHomeRestoredPod returned error: %v", err)
		}
		if containsStr(fk.addCalls, oldIP+"/24") {
			t.Fatalf("oldIP/24 was re-added though a scope-global oldIP was already present — oldSeen not set (addCalls=%v)", fk.addCalls)
		}
		if containsStr(fk.delCalls, oldIP+"/24") || containsStr(fk.delCalls, oldIP+"/32") {
			t.Fatalf("an OLD-IP address was stripped — OLD IPs must never be stripped (delCalls=%v)", fk.delCalls)
		}
	})
}
