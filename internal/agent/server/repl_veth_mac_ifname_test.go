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
