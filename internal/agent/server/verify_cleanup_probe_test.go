/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

// verify_cleanup_probe_test.go — ADR-0284 GC-6 deterministic probe-branch coverage.
//
// The RPC-contract tests in verify_cleanup_test.go run against whatever binaries happen to be in
// the CI sandbox, so they can only assert the invariants that hold regardless of tool presence.
// These tests instead swap the package-level newExecCmd for a fake that replays scripted stdout +
// exit codes, so every probe branch is exercised deterministically:
//
//   - a positively-present object (iptables -C exits 0; tc/ip/bridge dump contains the OLD IP)
//     => present + clean=false
//   - a positively-absent object (iptables -C reports "does a matching rule exist"; empty dump)
//     => absent + clean=true
//   - a genuine command error (non-absence stderr) => FAIL-CLOSED to present + blocking_reason
//   - device-absent stderr on ip/tc/bridge => absent (a missing device implies the object is gone)
//   - the CUTOVER_COMPLETE scope routing (cni0_neigh / cni0_host_route)
//
// The fail-closed cases are the load-bearing reclaim-safety asymmetry (§ADR-0284 header): a probe
// whose command errors must never read as "clean", or the controller would reclaim a still-wired IP.

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// --- fake exec harness (standard TestHelperProcess technique) ---

// fakeExecScript is consulted by installFakeExec; keyed by the first arg after the binary name
// (or the binary name itself) it returns the stdout to emit and the exit code.
type fakeExecResult struct {
	stdout string
	exit   int
}

// installFakeExec swaps newExecCmd for the duration of the test. matchFn inspects (name, args) and
// returns the scripted result; if it returns ok=false the call is treated as exit 0 empty output.
func installFakeExec(t *testing.T, matchFn func(name string, args []string) (fakeExecResult, bool)) {
	t.Helper()
	orig := newExecCmd
	t.Cleanup(func() { newExecCmd = orig })
	newExecCmd = func(name string, args ...string) *exec.Cmd {
		res, ok := matchFn(name, args)
		if !ok {
			res = fakeExecResult{stdout: "", exit: 0}
		}
		cs := []string{"-test.run=TestVerifyCleanupHelperProcess", "--", name}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = append(os.Environ(),
			"GO_WANT_VERIFYCLEANUP_HELPER=1",
			"HELPER_STDOUT="+res.stdout,
			"HELPER_EXIT="+strconv.Itoa(res.exit),
		)
		return cmd
	}
}

// TestVerifyCleanupHelperProcess is not a real test — it is the child process launched by the fake
// newExecCmd. It emits the scripted stdout and exits with the scripted code.
func TestVerifyCleanupHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_VERIFYCLEANUP_HELPER") != "1" {
		return
	}
	if out := os.Getenv("HELPER_STDOUT"); out != "" {
		os.Stdout.WriteString(out)
	}
	code := 0
	if os.Getenv("HELPER_EXIT") == "1" {
		code = 1
	}
	if os.Getenv("HELPER_EXIT") == "2" {
		code = 2
	}
	os.Exit(code)
}

func newTestServer() *AgentServer {
	return New("test-node", &criu.StubCheckpointer{}, nil)
}

// --- IP_RECLAIM: all objects absent => clean ---

func TestVerifyCleanup_IPReclaim_AllAbsent_Clean(t *testing.T) {
	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		switch name {
		case "iptables":
			// -C on a missing rule: iptables exits nonzero with this message.
			return fakeExecResult{stdout: "iptables: Bad rule (does a matching rule exist in that chain?).", exit: 1}, true
		case "tc":
			// device absent => no filter/qdisc can exist.
			return fakeExecResult{stdout: "Cannot find device \"flannel.1\"", exit: 1}, true
		case "ip":
			// empty route/neigh dump => absent.
			return fakeExecResult{stdout: "", exit: 0}, true
		case "bridge":
			return fakeExecResult{stdout: "", exit: 0}, true
		}
		return fakeExecResult{}, false
	})

	resp, err := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-clean",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		FdbIfname:     "flannel.1",
		ReplVethMac:   "aa:bb:cc:dd:ee:ff",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if !resp.Clean {
		t.Fatalf("expected clean=true when every probe reports absent; got present=%v reason=%q", resp.PresentObjects, resp.BlockingReason)
	}
	if len(resp.PresentObjects) != 0 {
		t.Fatalf("expected no present objects; got %v", resp.PresentObjects)
	}
}

// --- IP_RECLAIM: a leaked iptables NOTRACK rule is caught (proves the probe SEES presence) ---

func TestVerifyCleanup_IPReclaim_NotrackPresent_Detected(t *testing.T) {
	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		if name == "iptables" {
			// -C succeeds (exit 0) => the rule EXISTS.
			return fakeExecResult{stdout: "", exit: 0}, true
		}
		return fakeExecResult{stdout: "", exit: 0}, true
	})

	resp, err := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-leak",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		Objects:       []string{"source_notrack"},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.Clean {
		t.Fatal("expected clean=false: a present NOTRACK rule must block the clean verdict")
	}
	if len(resp.PresentObjects) != 1 || resp.PresentObjects[0] != "source_notrack" {
		t.Fatalf("expected source_notrack echoed as present; got %v", resp.PresentObjects)
	}
	if resp.BlockingReason == "" {
		t.Fatal("expected a non-empty blocking_reason for a detected present object")
	}
}

// --- IP_RECLAIM: a genuine command error is FAIL-CLOSED to present (reclaim-safety asymmetry) ---

func TestVerifyCleanup_IPReclaim_CommandError_FailsClosed(t *testing.T) {
	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		if name == "iptables" {
			// A genuine error that is NOT the expected "rule does not exist" message.
			return fakeExecResult{stdout: "iptables v1.8.7: can't initialize iptables table `raw': Permission denied", exit: 2}, true
		}
		return fakeExecResult{stdout: "", exit: 0}, true
	})

	resp, err := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-err",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		Objects:       []string{"dest_notrack"},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.Clean {
		t.Fatal("expected clean=false: an unknown-state command error must fail CLOSED (present), never read as clean")
	}
	if !strings.Contains(strings.ToLower(resp.BlockingReason), "fail-closed") {
		t.Fatalf("expected blocking_reason to mark the fail-closed path; got %q", resp.BlockingReason)
	}
}

// --- IP_RECLAIM: a positively-present tc filter (OLD IP in the dump) is detected ---

func TestVerifyCleanup_IPReclaim_TCFilterPresent_Detected(t *testing.T) {
	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		if name == "tc" && len(args) > 0 && args[0] == "filter" {
			return fakeExecResult{stdout: "filter protocol ip pref 1 u32 match ip dst 10.244.1.7/32", exit: 0}, true
		}
		return fakeExecResult{stdout: "", exit: 0}, true
	})

	resp, err := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-tc",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		FdbIfname:     "flannel.1",
		Objects:       []string{"tc_filter"},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.Clean || len(resp.PresentObjects) != 1 || resp.PresentObjects[0] != "tc_filter" {
		t.Fatalf("expected tc_filter detected present; got clean=%v present=%v", resp.Clean, resp.PresentObjects)
	}
}

// --- IP_RECLAIM (kindnet, ADR-0199): FdbIfname=="" must probe the DISCOVERED host interface,
// not a flannel.1 literal. A live tc-ingress redirect on the discovered interface must read as
// present (clean=false), never as a device-absent false-clean. This is the reclaim-safety
// regression the sign-off DECLINE identified: probing flannel.1 (which does not exist on kindnet)
// returned clean=true while the real redirect survived on eth0. ---

func TestVerifyCleanup_IPReclaim_EmptyFdbIfname_TCRedirectOnHostIface_Detected(t *testing.T) {
	// Resolve the interface the RPC will discover, so the fake can key on it precisely.
	discovered, err := discoverHostInterface(context.Background())
	if err != nil || discovered == "" {
		t.Skipf("no discoverable host interface in this sandbox (%v); cannot exercise kindnet path", err)
	}

	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		// A live u32 ingress redirect matching the OLD IP survives on the DISCOVERED interface.
		if name == "tc" && len(args) >= 5 && args[0] == "filter" && args[3] == discovered {
			return fakeExecResult{stdout: "filter protocol ip pref 1 u32 match ip dst 10.244.1.7/32", exit: 0}, true
		}
		// If the probe (wrongly) queried flannel.1, tc would report device-absent — the exact
		// path that produced the false-clean. This branch proves we do NOT take it.
		if name == "tc" && len(args) >= 5 && args[0] == "filter" && args[3] == "flannel.1" {
			return fakeExecResult{stdout: "Cannot find device \"flannel.1\"", exit: 1}, true
		}
		return fakeExecResult{stdout: "", exit: 0}, true
	})

	resp, rpcErr := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-kindnet-tc",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		FdbIfname:     "", // kindnet: operator sends OverlayFdbIfname==""
		Objects:       []string{"tc_filter"},
	})
	if rpcErr != nil {
		t.Fatalf("unexpected RPC error: %v", rpcErr)
	}
	if resp.Clean {
		t.Fatalf("RECLAIM-SAFETY REGRESSION: a live tc redirect on the discovered host interface (%s) "+
			"read as clean with FdbIfname==\"\"; the probe queried the wrong interface", discovered)
	}
	if len(resp.PresentObjects) != 1 || resp.PresentObjects[0] != "tc_filter" {
		t.Fatalf("expected tc_filter reported present; got %v", resp.PresentObjects)
	}
}

// --- IP_RECLAIM: a leaked /32 host route is detected ---

func TestVerifyCleanup_IPReclaim_HostRoutePresent_Detected(t *testing.T) {
	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		if name == "ip" && len(args) > 0 && args[0] == "route" {
			return fakeExecResult{stdout: "10.244.1.7 dev flannel.1 scope link", exit: 0}, true
		}
		return fakeExecResult{stdout: "", exit: 0}, true
	})

	resp, err := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-route",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		FdbIfname:     "flannel.1",
		Objects:       []string{"flannel1_route"},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.Clean || len(resp.PresentObjects) != 1 {
		t.Fatalf("expected flannel1_route detected present; got clean=%v present=%v", resp.Clean, resp.PresentObjects)
	}
}

// --- IP_RECLAIM: a leaked FDB entry keyed on the repl_veth MAC is detected ---

func TestVerifyCleanup_IPReclaim_FDBPresent_Detected(t *testing.T) {
	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		if name == "bridge" {
			return fakeExecResult{stdout: "aa:bb:cc:dd:ee:ff dev flannel.1 dst 192.168.1.2 self permanent", exit: 0}, true
		}
		return fakeExecResult{stdout: "", exit: 0}, true
	})

	resp, err := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-fdb",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		FdbIfname:     "flannel.1",
		ReplVethMac:   "aa:bb:cc:dd:ee:ff",
		Objects:       []string{"flannel1_fdb"},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.Clean || len(resp.PresentObjects) != 1 {
		t.Fatalf("expected flannel1_fdb detected present; got clean=%v present=%v", resp.Clean, resp.PresentObjects)
	}
}

// --- IP_RECLAIM: a neigh entry in FAILED state with no lladdr is a negative cache entry => absent ---

func TestVerifyCleanup_IPReclaim_NeighFailedIsAbsent(t *testing.T) {
	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		if name == "ip" && len(args) > 0 && args[0] == "neigh" {
			return fakeExecResult{stdout: "10.244.1.7 dev flannel.1 FAILED", exit: 0}, true
		}
		return fakeExecResult{stdout: "", exit: 0}, true
	})

	resp, err := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-neigh",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		FdbIfname:     "flannel.1",
		Objects:       []string{"flannel1_neigh"},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if !resp.Clean {
		t.Fatalf("expected FAILED negative-cache neigh to read as absent (clean); got present=%v", resp.PresentObjects)
	}
}

// --- IP_RECLAIM: a live permanent neigh entry (with lladdr) is detected present ---

func TestVerifyCleanup_IPReclaim_NeighPermanentPresent(t *testing.T) {
	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		if name == "ip" && len(args) > 0 && args[0] == "neigh" {
			return fakeExecResult{stdout: "10.244.1.7 dev flannel.1 lladdr aa:bb:cc:dd:ee:ff PERMANENT", exit: 0}, true
		}
		return fakeExecResult{stdout: "", exit: 0}, true
	})

	resp, err := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-neigh2",
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      "10.244.1.7",
		FdbIfname:     "flannel.1",
		Objects:       []string{"flannel1_neigh"},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.Clean || len(resp.PresentObjects) != 1 {
		t.Fatalf("expected a live permanent neigh entry detected present; got clean=%v present=%v", resp.Clean, resp.PresentObjects)
	}
}

// --- CUTOVER_COMPLETE scope routing: probes the cni0 objects, clean when absent ---

func TestVerifyCleanup_CutoverComplete_Routing_Absent(t *testing.T) {
	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		// empty ip neigh / ip route dumps => both cni0 objects absent.
		return fakeExecResult{stdout: "", exit: 0}, true
	})

	resp, err := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-cutover",
		Scope:         agentpb.CleanupScope_CUTOVER_COMPLETE,
		OldPodIp:      "10.244.1.7",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if !resp.Clean {
		t.Fatalf("expected CUTOVER_COMPLETE clean with empty dumps; got present=%v", resp.PresentObjects)
	}
}

func TestVerifyCleanup_CutoverComplete_HostRoutePresent(t *testing.T) {
	installFakeExec(t, func(name string, args []string) (fakeExecResult, bool) {
		if name == "ip" && len(args) > 0 && args[0] == "route" {
			return fakeExecResult{stdout: "10.244.1.7 dev cni0 scope link", exit: 0}, true
		}
		return fakeExecResult{stdout: "", exit: 0}, true
	})

	resp, err := newTestServer().VerifyCleanup(context.Background(), &agentpb.VerifyCleanupRequest{
		MigrationName: "mig-cutover2",
		Scope:         agentpb.CleanupScope_CUTOVER_COMPLETE,
		OldPodIp:      "10.244.1.7",
		Objects:       []string{"cni0_host_route"},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.Clean || len(resp.PresentObjects) != 1 || resp.PresentObjects[0] != "cni0_host_route" {
		t.Fatalf("expected cni0_host_route detected present; got clean=%v present=%v", resp.Clean, resp.PresentObjects)
	}
}

// --- classifier unit tests (the fail-closed decision hinges on these) ---

func TestIsIPTablesAbsent(t *testing.T) {
	absent := []string{
		"iptables: bad rule (does a matching rule exist in that chain?).",
		"iptables: no chain/target/match by that name.",
		"the rule does not exist",
	}
	for _, m := range absent {
		if !isIPTablesAbsent(strings.ToLower(m)) {
			t.Errorf("expected %q classified as absent", m)
		}
	}
	present := []string{
		"can't initialize iptables table `raw': permission denied",
		"another app is currently holding the xtables lock",
	}
	for _, m := range present {
		if isIPTablesAbsent(strings.ToLower(m)) {
			t.Errorf("expected %q NOT classified as absent (must fail closed)", m)
		}
	}
}

func TestIsTCDeviceOrQdiscAbsent(t *testing.T) {
	absent := []string{
		"Cannot find device \"flannel.1\"",
		"RTNETLINK answers: No such device",
	}
	for _, m := range absent {
		if !isTCDeviceOrQdiscAbsent(strings.ToLower(m)) {
			t.Errorf("expected %q classified as device/qdisc absent", m)
		}
	}
	if isTCDeviceOrQdiscAbsent(strings.ToLower("RTNETLINK answers: Operation not permitted")) {
		t.Error("expected a permission error NOT classified as absent (must fail closed)")
	}
}
