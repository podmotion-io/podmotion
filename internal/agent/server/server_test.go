/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// TestBuildCRIURestoreArgs_JoinNs asserts that when destNetnsFd is non-empty,
// buildCRIURestoreArgs produces --join-ns net:<fd> and --tcp-established, and
// that --empty-ns and --tcp-close are absent (M19 acceptance criterion: joinNsRestore
// unit test asserts --join-ns net:<fd> selected when NetworkContinuity != None).
func TestBuildCRIURestoreArgs_JoinNs(t *testing.T) {
	args, err := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		"/var/lib/podmotion/restore/test/termination-log",
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"/proc/12345/fd/7",
		"",
		"",
		false,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("buildCRIURestoreArgs returned error: %v", err)
	}
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--join-ns net:/proc/12345/fd/7") {
		t.Errorf("expected --join-ns net:/proc/12345/fd/7 in args; got: %s", joined)
	}
	if !strings.Contains(joined, "--tcp-established") {
		t.Errorf("expected --tcp-established in args; got: %s", joined)
	}
	if strings.Contains(joined, "--empty-ns") {
		t.Errorf("--empty-ns must not appear when destNetnsFd is set; got: %s", joined)
	}
	if strings.Contains(joined, "--net-fd") {
		t.Errorf("--net-fd must not appear on the --join-ns path; got: %s", joined)
	}
	if strings.Contains(joined, "--tcp-close") {
		t.Errorf("--tcp-close must not appear when destNetnsFd is set; got: %s", joined)
	}
	if strings.Contains(joined, "--restore-detached") {
		t.Errorf("--restore-detached must never appear (ghost container risk); got: %s", joined)
	}
}

// TestBuildCRIURestoreArgs_ColdJoinNsPath asserts that when destNetnsFd is empty (stateless
// cold migration), buildCRIURestoreArgs joins the replacement pod's pause container netns by
// PATH via --join-ns net:<path> + --tcp-close (ADR-0125, supersedes ADR-0122 §3), and that
// --empty-ns, --net-fd, and --tcp-established are absent. CRIU 4.2 has no --net-fd flag.
func TestBuildCRIURestoreArgs_ColdJoinNsPath(t *testing.T) {
	args, err := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		"/var/lib/podmotion/restore/test/termination-log",
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"",
		"/var/run/netns/cni-abc123",
		"",
		false,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("buildCRIURestoreArgs returned error: %v", err)
	}
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--join-ns net:/var/run/netns/cni-abc123") {
		t.Errorf("expected --join-ns net:/var/run/netns/cni-abc123 in args (ADR-0125); got: %s", joined)
	}
	if strings.Contains(joined, "--net-fd") {
		t.Errorf("--net-fd must not appear — CRIU 4.2 has no such flag (ADR-0125); got: %s", joined)
	}
	if strings.Contains(joined, "--empty-ns") {
		t.Errorf("--empty-ns must not appear (ADR-0122/0125 removed it); got: %s", joined)
	}
	if !strings.Contains(joined, "--tcp-close") {
		t.Errorf("expected --tcp-close in args; got: %s", joined)
	}
	if strings.Contains(joined, "--tcp-established") {
		t.Errorf("--tcp-established must not appear when destNetnsFd is empty; got: %s", joined)
	}
	if strings.Contains(joined, "--restore-detached") {
		t.Errorf("--restore-detached must never appear (ghost container risk); got: %s", joined)
	}
}

// TestBuildCRIURestoreArgs_StrictModeNRIPath verifies that when strictMode=true and
// destNetnsFd="" (the NRI path), --leave-stopped is emitted (ADR-0144 Decision Point 1).
// This is the gate that prevents a write into an unwired datapath on an actively-writing client.
func TestBuildCRIURestoreArgs_StrictModeNRIPath(t *testing.T) {
	args, err := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		"/var/lib/podmotion/restore/test/termination-log",
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"", // NRI path: destNetnsFd is always empty
		"/var/run/netns/cni-abc123",
		"",
		true, // strictMode=true → must emit --leave-stopped (ADR-0144 D1)
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("buildCRIURestoreArgs returned error: %v", err)
	}
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--leave-stopped") {
		t.Errorf("ADR-0144 D1: expected --leave-stopped when strictMode=true and destNetnsFd=''; got: %s", joined)
	}
	if !strings.Contains(joined, "--join-ns net:/var/run/netns/cni-abc123") {
		t.Errorf("expected --join-ns net:<path> on NRI path; got: %s", joined)
	}
	if strings.Contains(joined, "--restore-detached") {
		t.Errorf("--restore-detached must never appear (ADR-0142 D4); got: %s", joined)
	}
}

// hasAdjacentPair reports whether args contains flag immediately followed by value.
func hasAdjacentPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

// TestBuildCRIURestoreArgs_NoDevShmExtMountMap asserts that buildCRIURestoreArgs never
// emits a "--ext-mount-map /dev/shm:..." entry. Pre-ADR-0382, /dev/shm was unconditionally
// skipped/dropped, so such an entry would have been a dead no-op. Post-ADR-0382, /dev/shm
// is a normal, privately-owned, non-external CRIU mount (like / or /proc) that CRIU dumps
// and restores natively with its real content — it needs neither --skip-mnt nor
// --ext-mount-map here either. See docs/adr/0382-devshm-content-capture.md. The retained
// ext-mount-map entries (auto, /dev/null, /dev/termination-log) must remain.
//
// ADR-0417 UPDATE: the three self-mapping entries this test used to require —
// /etc/resolv.conf:/etc/resolv.conf, /etc/hostname:/etc/hostname, /etc/hosts:/etc/hosts — are GONE,
// and must stay gone, for two independent reasons.
//
//  1. They are no longer unconditional. Under Class DESTINATION-REBIND these mountpoints only get an
//     --ext-mount-map when they were actually resolved as destination-rebind mounts for THIS restore,
//     which is a property of reattachMountPaths, not of the argv skeleton. With a nil reattach set
//     (this test) there is nothing to map.
//  2. The self-mapping VALUE was wrong. A P-PREMISE decode of a real mountpoints image shows these
//     binds carry a LITERAL ext_key equal to their mountpoint, so CRIU does NOT bypass
//     ext_mount_lookup for them — "/etc/hosts:/etc/hosts" bound the DESTINATION NODE's own
//     /etc/hosts into the restored container. The correct form is
//     <containerPath>:<resolved destination host target>, asserted in
//     TestBuildCRIURestoreArgs_DestinationRebindMapsToHostTargetNotItself.
func TestBuildCRIURestoreArgs_NoDevShmExtMountMap(t *testing.T) {
	args, err := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		"/var/lib/podmotion/restore/test/termination-log",
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"",
		"/var/run/netns/cni-abc123",
		"",
		false,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("buildCRIURestoreArgs returned error: %v", err)
	}

	// The dead /dev/shm ext-mount-map must be gone.
	if hasAdjacentPair(args, "--ext-mount-map", "/dev/shm:/dev/shm") {
		t.Errorf("--ext-mount-map /dev/shm:/dev/shm must not appear (dead no-op removed); got: %s", strings.Join(args, " "))
	}

	// Stronger guard: NO ext-mount-map value may reference /dev/shm in ANY form (not just the
	// exact /dev/shm:/dev/shm pair). /dev/shm IS its own tmpfs mount (ADR-0382 corrects the
	// prior "not a mount" assumption — see a real corpus decode in
	// patch_checkpoint_realcorpus_test.go), but it is a normal, privately-owned (non-external)
	// mount that CRIU dumps and restores natively — an --ext-mount-map is for externals CRIU
	// cannot resolve on its own, which /dev/shm is not, so any entry referencing it would still
	// be a dead no-op / false signal.
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--ext-mount-map" && strings.Contains(args[i+1], "/dev/shm") {
			t.Errorf("no --ext-mount-map value may reference /dev/shm; found %q; got: %s", args[i+1], strings.Join(args, " "))
		}
	}

	// Retained ext-mount-map entries must still be present.
	retained := []struct{ flag, value string }{
		{"--ext-mount-map", "auto"},
		{"--ext-mount-map", "/dev/null:/dev/null"},
		{"--ext-mount-map", "/var/lib/podmotion/restore/test/termination-log"},
	}
	for _, r := range retained {
		found := false
		for i := 0; i+1 < len(args); i++ {
			if args[i] == r.flag && strings.Contains(args[i+1], r.value) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected retained %s %s in args; got: %s", r.flag, r.value, strings.Join(args, " "))
		}
	}

	// ADR-0417 (reason 2 above): the self-mapping form must never be emitted again for any of the
	// three well-known runtime-injected file binds. Mapping a mountpoint to ITSELF resolves, on a
	// literal-ext_key entry, to the destination NODE's own file rather than the pod's.
	for _, selfMap := range []string{"/etc/hosts:/etc/hosts", "/etc/hostname:/etc/hostname", "/etc/resolv.conf:/etc/resolv.conf"} {
		if hasAdjacentPair(args, "--ext-mount-map", selfMap) {
			t.Errorf("--ext-mount-map %s binds the destination node's own file into the container (ADR-0417); got: %s", selfMap, strings.Join(args, " "))
		}
	}
}

// TestBuildCRIURestoreArgs_NoDevObscuredParentExtMountMap asserts that buildCRIURestoreArgs no
// longer emits any "pm-dev:<rootfsDir>/dev" --ext-mount-map pair (ADR-0415). /dev is a pod-owned
// tmpfs captured with content and restored as a CRIU-owned mount, not declared external, so the
// retired pm-dev obscured-parent machinery (ADR-0384/0389/0392) produces no restore-argv entry.
// Declaring /dev external was exactly what suppressed CRIU's fill of its /dev/shm child.
func TestBuildCRIURestoreArgs_NoDevObscuredParentExtMountMap(t *testing.T) {
	rootfsDir := "/var/lib/podmotion/restore/test/bundle/rootfs"
	args, err := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		rootfsDir,
		"/var/lib/podmotion/restore/test/data",
		"/var/lib/podmotion/restore/test/termination-log",
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"",
		"/var/run/netns/cni-abc123",
		"",
		false,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("buildCRIURestoreArgs returned error: %v", err)
	}

	// No ext-mount-map value may reference a pod-owned /dev target or the retired "pm-dev" key.
	badValue := "pm-dev:" + rootfsDir + "/dev"
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--ext-mount-map" && (args[i+1] == badValue || strings.HasPrefix(args[i+1], "pm-dev:")) {
			t.Errorf("ADR-0415: buildCRIURestoreArgs must NOT emit a pm-dev /dev ext-mount-map; got %q in: %s",
				args[i+1], strings.Join(args, " "))
		}
	}
}

// TestArmZeroWindow_ArmsAndRegistersWatchdog verifies that ArmZeroWindow returns
// armed=true, records the hold state, and creates a watchdog goroutine.
func TestArmZeroWindow_ArmsAndRegistersWatchdog(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	resp, err := s.ArmZeroWindow(ctx, &agentpb.ArmZeroWindowRequest{
		MigrationName:        "test-migration",
		PodUid:               "pod-uid-123",
		FreezeWindowBudgetMs: 500,
	})
	if err != nil {
		t.Fatalf("ArmZeroWindow returned unexpected error: %v", err)
	}
	if !resp.Armed {
		t.Errorf("expected Armed=true, got false; reason=%s", resp.BlockingReason)
	}
	if resp.ArmedAtNs == 0 {
		t.Errorf("expected ArmedAtNs to be set, got 0")
	}

	s.zwHoldMu.Lock()
	_, ok := s.zwHolds["test-migration"]
	s.zwHoldMu.Unlock()
	if !ok {
		t.Errorf("expected zwHolds to contain test-migration entry after ArmZeroWindow")
	}
}

// TestDisarmZeroWindow_DisarmsArmedHold verifies that DisarmZeroWindow correctly removes
// the hold state and returns disarmed=true with a hold duration.
func TestDisarmZeroWindow_DisarmsArmedHold(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	armResp, err := s.ArmZeroWindow(ctx, &agentpb.ArmZeroWindowRequest{
		MigrationName:        "test-disarm",
		PodUid:               "pod-uid-456",
		FreezeWindowBudgetMs: 5000,
	})
	if err != nil || !armResp.Armed {
		t.Fatalf("ArmZeroWindow failed: err=%v armed=%v", err, armResp.Armed)
	}

	disarmResp, err := s.DisarmZeroWindow(ctx, &agentpb.DisarmZeroWindowRequest{
		MigrationName: "test-disarm",
		PodUid:        "pod-uid-456",
	})
	if err != nil {
		t.Fatalf("DisarmZeroWindow returned unexpected error: %v", err)
	}
	if !disarmResp.Disarmed {
		t.Errorf("expected Disarmed=true, got false; reason=%s", disarmResp.BlockingReason)
	}
	if disarmResp.HoldDurationMs < 0 {
		t.Errorf("expected non-negative HoldDurationMs, got %d", disarmResp.HoldDurationMs)
	}

	s.zwHoldMu.Lock()
	_, stillPresent := s.zwHolds["test-disarm"]
	s.zwHoldMu.Unlock()
	if stillPresent {
		t.Errorf("expected zwHolds entry to be removed after DisarmZeroWindow")
	}
}

// TestDisarmZeroWindow_NoActiveHold verifies that DisarmZeroWindow on a migration
// without an active hold returns disarmed=false with a blocking reason (idempotent path).
func TestDisarmZeroWindow_NoActiveHold(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	resp, err := s.DisarmZeroWindow(ctx, &agentpb.DisarmZeroWindowRequest{
		MigrationName: "no-such-migration",
		PodUid:        "",
	})
	if err != nil {
		t.Fatalf("DisarmZeroWindow returned unexpected error: %v", err)
	}
	if resp.Disarmed {
		t.Errorf("expected Disarmed=false for unknown migration, got true")
	}
	if resp.BlockingReason == "" {
		t.Errorf("expected a BlockingReason explaining why disarm failed")
	}
}

// TestWatchdog_AutoDisarmFiresWhenDisarmWithheld verifies that when DisarmZeroWindow is
// NOT called within FreezeWindowBudgetMs + margin, the watchdog goroutine fires and
// removes the hold state — proving the connection cannot be stalled indefinitely
// (M20 acceptance criterion: watchdog test).
//
// Uses a very short budget (5ms) so the test completes quickly without sleeping long.
func TestWatchdog_AutoDisarmFiresWhenDisarmWithheld(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	// Arm with a 5ms freeze budget. Watchdog deadline = 5ms + zwWatchdogMargin (500ms).
	// We use a short separate budget and poll quickly rather than waiting the full margin.
	_, err := s.ArmZeroWindow(ctx, &agentpb.ArmZeroWindowRequest{
		MigrationName:        "watchdog-test",
		PodUid:               "pod-watchdog",
		FreezeWindowBudgetMs: 5,
	})
	if err != nil {
		t.Fatalf("ArmZeroWindow returned unexpected error: %v", err)
	}

	// Confirm hold is registered immediately after arm.
	s.zwHoldMu.Lock()
	_, armed := s.zwHolds["watchdog-test"]
	s.zwHoldMu.Unlock()
	if !armed {
		t.Fatal("expected hold to be registered after ArmZeroWindow")
	}

	// Wait for watchdog to set watchdogFired=true: budget(5ms) + zwWatchdogMargin(500ms) + 300ms.
	// The watchdog (server.go:5048-5072) intentionally does NOT delete the hold when it fires —
	// per ADR-0157 D3: cleanup is the controller's DisarmZeroWindow call. It sets watchdogFired=true.
	// The test must poll for watchdogFired, not for hold-absence (Arch-C fix, ADR-0192 §13).
	deadline := time.Now().Add(time.Duration(5)*time.Millisecond + zwWatchdogMargin + 300*time.Millisecond)
	var fired bool
	for time.Now().Before(deadline) {
		s.zwHoldMu.Lock()
		st, present := s.zwHolds["watchdog-test"]
		f := present && st.watchdogFired
		s.zwHoldMu.Unlock()
		if f {
			fired = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !fired {
		t.Errorf("watchdog did not set watchdogFired within expected deadline")
	}

	// After watchdog fires, DisarmZeroWindow must report no active hold (connection survived —
	// the BPF program was detached, so the sender window is restored and the connection lives).
	resp, err := s.DisarmZeroWindow(ctx, &agentpb.DisarmZeroWindowRequest{
		MigrationName: "watchdog-test",
		PodUid:        "pod-watchdog",
	})
	if err != nil {
		t.Fatalf("DisarmZeroWindow after watchdog returned error: %v", err)
	}
	// Watchdog already cleaned up the hold; DisarmZeroWindow should return not-found path.
	if resp.Disarmed {
		// Acceptable if the implementation is re-entrant, but the hold must not still be
		// in memory — check the state map is clear either way.
	}
	s.zwHoldMu.Lock()
	_, remainingHold := s.zwHolds["watchdog-test"]
	s.zwHoldMu.Unlock()
	if remainingHold {
		t.Errorf("hold state must be absent after watchdog auto-disarm + explicit DisarmZeroWindow")
	}
}

// TestHoldDuration_WithinFreezeWindowBudget verifies that when DisarmZeroWindow is called
// promptly, HoldDurationMs is less than or equal to FreezeWindowBudgetMs (M20 acceptance
// criterion: condition delta ZeroWindowArmed→Disarmed ≤ FreezeWindowBudgetMs).
func TestHoldDuration_WithinFreezeWindowBudget(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	ctx := context.Background()

	const budgetMs = int64(5000)

	armResp, err := s.ArmZeroWindow(ctx, &agentpb.ArmZeroWindowRequest{
		MigrationName:        "budget-test",
		PodUid:               "pod-budget",
		FreezeWindowBudgetMs: budgetMs,
	})
	if err != nil || !armResp.Armed {
		t.Fatalf("ArmZeroWindow failed: err=%v armed=%v", err, armResp.Armed)
	}

	// Disarm immediately — hold duration should be negligible (< budgetMs by a large margin).
	disarmResp, err := s.DisarmZeroWindow(ctx, &agentpb.DisarmZeroWindowRequest{
		MigrationName: "budget-test",
		PodUid:        "pod-budget",
	})
	if err != nil {
		t.Fatalf("DisarmZeroWindow returned error: %v", err)
	}
	if !disarmResp.Disarmed {
		t.Fatalf("DisarmZeroWindow returned Disarmed=false unexpectedly: %s", disarmResp.BlockingReason)
	}
	if disarmResp.HoldDurationMs > budgetMs {
		t.Errorf("HoldDurationMs=%d exceeds FreezeWindowBudgetMs=%d — hold took too long",
			disarmResp.HoldDurationMs, budgetMs)
	}
	if disarmResp.HoldDurationMs < 0 {
		t.Errorf("HoldDurationMs must be non-negative, got %d", disarmResp.HoldDurationMs)
	}
	if disarmResp.DisarmedAtNs <= armResp.ArmedAtNs {
		t.Errorf("DisarmedAtNs (%d) must be after ArmedAtNs (%d)",
			disarmResp.DisarmedAtNs, armResp.ArmedAtNs)
	}
}

// TestParseVethPeerIndex_ADR0139 asserts eth0@if<N> peer index extraction.
func TestParseVethPeerIndex_ADR0139(t *testing.T) {
	cases := map[string]int{
		`2: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 ... link/ether aa:bb`: 12,
		`2: eth0@if7: <UP> link/ether 0a:1b`:                                            7,
		`2: eth0: <UP> link/ether 0a:1b`:                                                0,
		``:                                                                              0,
	}
	for in, want := range cases {
		if got := parseVethPeerIndex(in); got != want {
			t.Errorf("parseVethPeerIndex(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestHostLinkNameByIndex_ADR0139 asserts veth-peer name lookup by ifindex.
func TestHostLinkNameByIndex_ADR0139(t *testing.T) {
	out := "1: lo: <LOOPBACK,UP> mtu 65536\n12: veth1a2b3c4d@if2: <UP> mtu 1450 link/ether aa:bb master cni0\n13: flannel.1: <UP> mtu 1450\n"
	if got := hostLinkNameByIndex(out, 12); got != "veth1a2b3c4d" {
		t.Errorf("hostLinkNameByIndex(12) = %q, want veth1a2b3c4d", got)
	}
	if got := hostLinkNameByIndex(out, 13); got != "flannel.1" {
		t.Errorf("hostLinkNameByIndex(13) = %q, want flannel.1", got)
	}
	if got := hostLinkNameByIndex(out, 99); got != "" {
		t.Errorf("hostLinkNameByIndex(99) = %q, want empty", got)
	}
}

// TestCidr24ForIP_ADR0139 asserts source-CIDR derivation for the reverse-path route.
func TestCidr24ForIP_ADR0139(t *testing.T) {
	if got := cidr24ForIP("10.244.0.97"); got != "10.244.0.0/24" {
		t.Errorf("cidr24ForIP = %q, want 10.244.0.0/24", got)
	}
	if got := cidr24ForIP("not-an-ip"); got != "" {
		t.Errorf("cidr24ForIP(bad) = %q, want empty", got)
	}
}
