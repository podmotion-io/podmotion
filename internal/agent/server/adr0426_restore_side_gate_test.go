/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0426_restore_side_gate_test.go — ADR-0426 D4: the restore-side cross-axis assertion.
//
// destinationRebindDemandSetFn is a test seam (adr0419_destination_mounts.go); these tests drive
// appendDestinationRebindReattachMounts directly with a fixed destinationRebindDemand, exactly as
// TestADR0420_D1b_OutcomeIsCountableOnAllThreePaths does for the D1b counters.

import (
	"context"
	"errors"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/nri"
)

// TestADR0426_D4_InconsistentRegFileDemandHardStops asserts V7: a checkpoint that classifies a mount
// content-absent (so the destination's own empty mount would be used) while ALSO recording a
// non-directory REG file demand under that mount's mnt_id is internally inconsistent and must be
// refused BEFORE resolveDestinationRebindTargets / any CRIU invocation, with the new typed error.
func TestADR0426_D4_InconsistentRegFileDemandHardStops(t *testing.T) {
	const absent = "/dev/shm"
	orig := destinationRebindDemandSetFn
	destinationRebindDemandSetFn = func(context.Context, string, string) (destinationRebindDemand, error) {
		return destinationRebindDemand{
			Paths:                          []string{absent},
			ContentAbsent:                  []string{absent},
			ContentAbsentWithRegFileDemand: map[string]int{absent: 1},
		}, nil
	}
	defer func() { destinationRebindDemandSetFn = orig }()

	var outcome string
	var attempts int
	defer withObserve(t, &outcome, &attempts)()

	s := newADR0417Server(t)
	_, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID, nil, nil)

	var demandErr *ContentAbsentRegFileDemandError
	if !errors.As(err, &demandErr) {
		t.Fatalf("expected ContentAbsentRegFileDemandError; got %v", err)
	}
	if demandErr.Mountpoint != absent || demandErr.RegFileCount != 1 {
		t.Fatalf("expected the error to name %q with count 1; got %+v", absent, demandErr)
	}
}

// TestADR0426_D4_DirectoryOnlyDemandDoesNotHardStop is the restore-side mirror of V3b: a
// content-absent mount whose ONLY files.img demand is a directory fd (the token-rotation
// directory-watch shape) must NOT hard-stop — the S_IFDIR exclusion stays mandatory on this leg
// (round 2), landing the count in the diagnostic-only ContentAbsentWithDirFdDemand map instead.
func TestADR0426_D4_DirectoryOnlyDemandDoesNotHardStop(t *testing.T) {
	const absent = "/run/secrets/kubernetes.io/serviceaccount"
	const hostSrc = "/var/lib/kubelet/pods/DESTUID/volumes/kubernetes.io~projected/kube-api-access-xyz"
	orig := destinationRebindDemandSetFn
	destinationRebindDemandSetFn = func(context.Context, string, string) (destinationRebindDemand, error) {
		return destinationRebindDemand{
			Paths:                        []string{absent},
			ContentAbsent:                []string{absent},
			ContentAbsentWithDirFdDemand: map[string]int{absent: 1},
		}, nil
	}
	defer func() { destinationRebindDemandSetFn = orig }()

	var outcome string
	var attempts int
	defer withObserve(t, &outcome, &attempts)()

	s := newADR0417Server(t)
	got, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID,
		[]nri.ContainerMount{{Destination: absent, Type: "bind", Source: hostSrc}}, nil)
	if err != nil {
		t.Fatalf("a directory-fd-only demand must not hard-stop (round 2's mandatory S_IFDIR exclusion); got %v", err)
	}
	if len(got) != 1 || got[0].HostTarget != hostSrc {
		t.Fatalf("expected the destination's own mount resolved; got %+v", got)
	}
}

// TestADR0426_D4_MixedDirectoryAndRegularDemand asserts V3c: when BOTH a directory fd and a regular
// file are demanded under the same content-absent mount, the regular-file count alone gates — the
// directory entry is excluded, but its presence does not suppress the hard stop the regular file
// earns.
func TestADR0426_D4_MixedDirectoryAndRegularDemand(t *testing.T) {
	const absent = "/dev/shm"
	orig := destinationRebindDemandSetFn
	destinationRebindDemandSetFn = func(context.Context, string, string) (destinationRebindDemand, error) {
		return destinationRebindDemand{
			Paths:                          []string{absent},
			ContentAbsent:                  []string{absent},
			ContentAbsentWithRegFileDemand: map[string]int{absent: 1},
			ContentAbsentWithDirFdDemand:   map[string]int{absent: 1},
		}, nil
	}
	defer func() { destinationRebindDemandSetFn = orig }()

	var outcome string
	var attempts int
	defer withObserve(t, &outcome, &attempts)()

	s := newADR0417Server(t)
	_, err := s.appendDestinationRebindReattachMounts(
		context.Background(), adr0417Migration, "/fake/checkpoint", adr0417SandboxID, nil, nil)
	var demandErr *ContentAbsentRegFileDemandError
	if !errors.As(err, &demandErr) {
		t.Fatalf("a mixed directory+regular demand must still hard-stop on the regular-file count; got %v", err)
	}
}
