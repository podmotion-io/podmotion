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
	"os"
	"path/filepath"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/network"
)

// TestFinalizeNetnsPath_MigrationBindReturnsPmdst0Ifname asserts that when a
// PrepareDestinationNetns bind mount is recorded for a migration, finalizeNetnsPath returns
// that path AND the "pmdst0" interface name — not "eth0".
func TestFinalizeNetnsPath_MigrationBindReturnsPmdst0Ifname(t *testing.T) {
	s := New("test-node", &criu.StubCheckpointer{}, nil)

	// A real, on-disk path so the os.Stat gate in finalizeNetnsPath passes (the branch
	// returns "" if the bind does not exist).
	dir := t.TempDir()
	bindPath := filepath.Join(dir, "bind")
	if err := os.WriteFile(bindPath, []byte("nsfs-bind-placeholder"), 0o600); err != nil {
		t.Fatalf("seed bind file: %v", err)
	}

	const migration = "redis-live-migration"
	s.destMigrationNetnsMu.Lock()
	s.destMigrationNetns[migration] = &network.MigrationNetns{NetnsPath: bindPath}
	s.destMigrationNetnsMu.Unlock()

	gotPath, gotIfname := s.finalizeNetnsPath(migration)
	if gotPath != bindPath {
		t.Errorf("finalizeNetnsPath path = %q, want %q", gotPath, bindPath)
	}
	if gotIfname != network.MigrationVethPeer {
		t.Errorf("finalizeNetnsPath ifname = %q, want %q (migration netns holds only lo + %s, never eth0)",
			gotIfname, network.MigrationVethPeer, network.MigrationVethPeer)
	}
	if gotIfname == "eth0" {
		t.Fatal("finalizeNetnsPath returned eth0 for a migration-netns bind — this is the exact live bug (ip link show eth0 fails, MAC empty, Strict fail-closed)")
	}
}

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
	readReplVethMACFn = func(pid int, netnsPath, ifname string) (string, error) {
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
	fr, err := s.finalizeRestore(context.Background(), 4242, netnsPath, ifname, migration, "", "Strict")
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
	readReplVethMACFn = func(pid int, netnsPath, ifname string) (string, error) {
		gotIfname = ifname
		return "aa:bb:cc:dd:ee:ff", nil
	}
	defer func() { readReplVethMACFn = orig }()

	s := New("test-node", &criu.StubCheckpointer{}, nil)
	if _, err := s.finalizeRestore(context.Background(), 12345, "/run/podmotion/netns/pm-mig-x/bind",
		network.MigrationVethPeer, "redis-live-migration", "", "Strict"); err != nil {
		t.Fatalf("finalizeRestore returned unexpected error: %v", err)
	}
	if gotIfname != network.MigrationVethPeer {
		t.Errorf("MAC read ifname = %q, want %q (migration netns)", gotIfname, network.MigrationVethPeer)
	}
}
