/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// repl_veth_mac_ifname_test.go — live-bug regression for the replVeth MAC interface name.
//
// Live failure (2026-07-10, redis Strict migration): finalizeNetnsPath correctly routed the
// MAC read to the PrepareDestinationNetns bind mount (ADR-0308), but ReadReplVethMAC then ran
// `ip link show eth0` inside that netns — which holds only "lo" and the migration veth peer
// network.MigrationVethPeer ("pmdst0"), never "eth0". The read returned "device does not
// exist" → empty MAC → finalizeRestore [Strict] fail-closed ("replVethMAC empty"). These
// tests pin the fix: whenever finalizeNetnsPath returns a migration-netns bind path, it must
// also return the "pmdst0" ifname, and finalizeRestore must pass that ifname through to the
// MAC read. Both fail against the pre-fix code (which hardcoded "eth0").

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/network"
)

// TestFinalizeNetnsPath_MigrationBindReturnsPmdst0Ifname pinned the old Tier-2
// (destMigrationNetns bind-mount fallback) that ADR-0349 R2 deletes — finalizeNetnsPath is now
// Tier-1-only. DELETED atomically with the R2 change: the fallback tier it pinned no longer
// exists, so keeping/weakening this test would silently re-legitimize it.

// TestFinalizeNetnsPath_NoBindReturnsEth0 asserts the PID-fallback branch still names "eth0":
// when no netns bind is available, finalizeRestore falls back to /proc/<pid>/ns/net, which IS
// the restored process's own sandbox netns where the pod interface is "eth0".
func TestFinalizeNetnsPath_NoBindReturnsEth0(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)
	gotPath, gotIfname := s.finalizeNetnsPath("no-such-migration")
	if gotPath != "" {
		t.Errorf("finalizeNetnsPath path = %q, want \"\" (no bind, no resolved netns)", gotPath)
	}
	if gotIfname != "eth0" {
		t.Errorf("finalizeNetnsPath ifname = %q, want \"eth0\" for the PID-fallback (pod sandbox netns)", gotIfname)
	}
}

// TestFinalizeNetnsPath_ResolvedSandboxNetnsReturnsEth0Ifname pins the sprint46 live-proof
// cycle-2 fix: when joinNsRestore recorded a POD SANDBOX netns for the migration (ADR-0325
// --join-ns net:<pod-sandbox>, the default restore path), finalizeNetnsPath must return that
// path AND "eth0" — NOT the migration-netns "pmdst0". Pre-fix this branch hardcoded pmdst0, so
// `ip link show pmdst0` inside the sandbox netns failed → empty MAC → Strict fail-closed
// ("replVethMAC empty after restore"). This branch is the one exercised live and had no unit
// guard before this test.
func TestFinalizeNetnsPath_ResolvedSandboxNetnsReturnsEth0Ifname(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)

	const migration = "redis-live-strict-sandbox"
	// joinNsRestore records the pod sandbox netns it joined, with ifname "eth0" (ADR-0325).
	storeResolvedNetnsPath(migration, "/var/run/netns/cni-abc123", "eth0")

	gotPath, gotIfname := s.finalizeNetnsPath(migration)
	if gotPath != "/var/run/netns/cni-abc123" {
		t.Errorf("finalizeNetnsPath path = %q, want the recorded pod sandbox netns path", gotPath)
	}
	if gotIfname != "eth0" {
		t.Errorf("finalizeNetnsPath ifname = %q, want \"eth0\" for a pod sandbox netns (ADR-0325). "+
			"Returning %q would make `ip link show %s` fail → empty MAC → Strict fail-closed (the exact cycle-2 bug)",
			gotIfname, gotIfname, gotIfname)
	}
	if gotIfname == network.MigrationVethPeer {
		t.Fatal("finalizeNetnsPath returned pmdst0 for a recorded pod SANDBOX netns — this is the exact sprint46 cycle-2 live failure (sandbox netns has no pmdst0)")
	}
}

// TestFinalizeNetnsPath_ResolvedMigrationNetnsReturnsPmdst0Ifname asserts the legacy path is
// preserved: when joinNsRestore recorded an agent-staged MIGRATION netns (destNetnsFd!="" join),
// finalizeNetnsPath returns that path AND "pmdst0" — the migration netns has no eth0.
func TestFinalizeNetnsPath_ResolvedMigrationNetnsReturnsPmdst0Ifname(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)

	const migration = "redis-live-strict-mignetns"
	storeResolvedNetnsPath(migration, "/run/podmotion/netns/pm-mig-xyz/bind", network.MigrationVethPeer)

	gotPath, gotIfname := s.finalizeNetnsPath(migration)
	if gotPath != "/run/podmotion/netns/pm-mig-xyz/bind" {
		t.Errorf("finalizeNetnsPath path = %q, want the recorded migration netns bind path", gotPath)
	}
	if gotIfname != network.MigrationVethPeer {
		t.Errorf("finalizeNetnsPath ifname = %q, want %q for an agent-staged migration netns",
			gotIfname, network.MigrationVethPeer)
	}
}

// TestFinalizeRestore_SandboxNetnsStrictDoesNotFailClosed reproduces the full sprint46 cycle-2
// failure chain end-to-end and proves the fix: a Strict restore that joined the pod sandbox
// netns (ADR-0325) reads the MAC from "eth0" and does NOT hit the fail-closed branch. The MAC
// stub mimics the real substrate — `ip link show <ifname>` returns a MAC only for "eth0" inside
// a pod sandbox netns and empty for "pmdst0" (which does not exist there). Pre-fix,
// finalizeNetnsPath handed "pmdst0" to the read → empty MAC → Strict fail-closed.
func TestFinalizeRestore_SandboxNetnsStrictDoesNotFailClosed(t *testing.T) {
	orig := readReplVethMACFn
	readReplVethMACFn = func(_ context.Context, pid int, netnsPath, ifname string) (string, error) {
		if ifname == "eth0" {
			return "aa:bb:cc:dd:ee:ff", nil
		}
		// Any other ifname (e.g. the pre-fix hardcoded "pmdst0") does not exist in the pod
		// sandbox netns — exactly what `ip link show pmdst0` returns live.
		return "", nil
	}
	defer func() { readReplVethMACFn = orig }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)

	const migration = "redis-live-strict-e2e"
	// joinNsRestore recorded the pod sandbox netns (ADR-0325) with ifname "eth0".
	storeResolvedNetnsPath(migration, "/var/run/netns/cni-e2e", "eth0")

	netnsPath, ifname := s.finalizeNetnsPath(migration)
	fr, err := s.finalizeRestore(context.Background(), 4242, netnsPath, ifname, migration, "", "Strict", "", "")
	if err != nil {
		t.Fatalf("finalizeRestore [Strict] fail-closed on a pod-sandbox-netns restore: %v — "+
			"this is the sprint46 cycle-2 regression (ifname resolved to %q instead of eth0)", err, ifname)
	}
	if fr.mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("finalizeRestore mac = %q, want the eth0 MAC — the read must target eth0 in the sandbox netns", fr.mac)
	}
}

// TestFinalizeRestore_PassesIfnameToMACRead asserts the ifname resolved by finalizeNetnsPath is
// threaded all the way into the MAC read — i.e. a migration-netns restore reads "pmdst0", not
// the hardcoded "eth0". This is the end-to-end contract the live redis failure violated.
func TestFinalizeRestore_PassesIfnameToMACRead(t *testing.T) {
	var gotIfname string
	orig := readReplVethMACFn
	readReplVethMACFn = func(_ context.Context, pid int, netnsPath, ifname string) (string, error) {
		gotIfname = ifname
		return "aa:bb:cc:dd:ee:ff", nil
	}
	defer func() { readReplVethMACFn = orig }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	if _, err := s.finalizeRestore(context.Background(), 12345, "/run/podmotion/netns/pm-mig-x/bind",
		network.MigrationVethPeer, "redis-live-migration", "", "Strict", "", ""); err != nil {
		t.Fatalf("finalizeRestore returned unexpected error: %v", err)
	}
	if gotIfname != network.MigrationVethPeer {
		t.Errorf("MAC read ifname = %q, want %q (migration netns)", gotIfname, network.MigrationVethPeer)
	}
}

// TestFinalizeRestore_WriteBack_CaptureLatchesValue_NoReReadOnReinvocation is the falsifiable
// proof of the ADR-0349 security write-back (Security Reviewer, sprint46B2 validation cycle 1).
// The live-proof showed the controller re-invoked
// Restore ~25 times over ~75s, each RE-READING eth0 against the recorded /var/run/netns/cni-<id>
// bind handle via the broker's path-mode nsenter and getting empty — the invariant-#10 poll-and-hope
// brittle chain the Security Reviewer rejected on. This test pins the fix: the AT-RESTORE capture
// (captureRestoredVethMAC, invoked by joinNsRestore the instant CRIU brings the process up) reads
// the MAC from the restored process's OWN netns (SrcPID — pid>0, netnsPath=="", NEVER the recorded
// bind path) and WRITES IT BACK; every finalizeRestore thereafter (including the idempotent-confirm
// re-invocations of the gRPC Restore RPC) serves the latched VALUE with ZERO further kernel reads.
// Falsifiable: the spy fails any read the capture did not make, so a regression that re-reads the
// recorded path in finalizeRestore blows the read count and fails the test.
func TestFinalizeRestore_WriteBack_CaptureLatchesValue_NoReReadOnReinvocation(t *testing.T) {
	const migration = "redis-live-strict-writeback"
	const wantMAC = "aa:bb:cc:dd:ee:ff"

	// Shrink the capture bounded wait so the happy path never sleeps.
	ob, oi := restoredVethMACCaptureBudget, restoredVethMACCaptureInterval
	restoredVethMACCaptureBudget, restoredVethMACCaptureInterval = 2*time.Second, time.Millisecond
	defer func() { restoredVethMACCaptureBudget, restoredVethMACCaptureInterval = ob, oi }()

	var reads int
	var captureReadPID int
	captureReadNetnsPath := "SENTINEL"
	orig := readReplVethMACFn
	readReplVethMACFn = func(_ context.Context, pid int, netnsPath, ifname string) (string, error) {
		reads++
		if reads == 1 {
			captureReadPID, captureReadNetnsPath = pid, netnsPath
			return wantMAC, nil
		}
		// Any read AFTER the at-restore capture latched is precisely the recorded-path re-read the
		// write-back retires (invariant #10) — fail it so a regression fails the test loudly.
		return "", errors.New("stub: kernel re-read after the value was already captured and latched")
	}
	defer func() { readReplVethMACFn = orig }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	// joinNsRestore recorded the authoritative pod-sandbox netns handle (ADR-0325 / R1) ...
	storeResolvedNetnsPath(migration, "/var/run/netns/cni-writeback", "eth0")
	// ... and, the instant CRIU brought the process up, captured the MAC from the process's OWN netns.
	captureRestoredVethMAC(context.Background(), migration, 7777, "")

	// The capture read the process's OWN netns by SrcPID (pid>0), NOT the recorded bind PATH — the
	// bind-path read is the exact one that returned empty for ~75s on the live substrate.
	if captureReadPID != 7777 {
		t.Fatalf("capture read pid = %d, want 7777 — the MAC is captured from the restored process's OWN netns (SrcPID), not the recorded bind path", captureReadPID)
	}
	if captureReadNetnsPath != "" {
		t.Fatalf("capture read netnsPath = %q, want \"\" — the capture MUST NOT re-enter the recorded bind path", captureReadNetnsPath)
	}
	// The value is written back into the record.
	if got := s.resolvedNetnsMAC(migration); got != wantMAC {
		t.Fatalf("resolvedNetnsMAC after capture = %q, want %q (write-back did not latch)", got, wantMAC)
	}

	netnsPath, ifname := s.finalizeNetnsPath(migration)

	// Two finalizes (models the idempotent-confirm re-invocations of the gRPC Restore RPC): each
	// serves the latched VALUE with NO kernel read (the spy fails any read after the capture).
	for i := 1; i <= 2; i++ {
		fr, err := s.finalizeRestore(context.Background(), 7777, netnsPath, ifname, migration, "", "Strict", "", "")
		if err != nil {
			t.Fatalf("finalizeRestore #%d re-read the recorded path instead of serving the latched value: %v", i, err)
		}
		if fr.mac != wantMAC {
			t.Fatalf("finalizeRestore #%d mac = %q, want the latched %q", i, fr.mac, wantMAC)
		}
	}
	if reads != 1 {
		t.Fatalf("readReplVethMACFn called %d times, want exactly 1 (the at-restore capture) — finalizeRestore must serve the write-back, never re-read (invariant #10)", reads)
	}
}
