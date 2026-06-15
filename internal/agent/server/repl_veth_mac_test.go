/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package server

import (
	"strings"
	"testing"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestJoinNsRestore_PopulatesMAC verifies that finalizeRestoreMAC returns the MAC
// produced by readReplVethMACFn when the function returns a non-empty value (ADR-0133 D3).
func TestJoinNsRestore_PopulatesMAC(t *testing.T) {
	const wantMAC = "de:ad:be:ef:ca:fe"

	// Inject a stub that always returns a well-known MAC.
	orig := readReplVethMACFn
	readReplVethMACFn = func(pid int, sandboxNetnsPath string) (string, error) {
		return wantMAC, nil
	}
	defer func() { readReplVethMACFn = orig }()

	mac, err := finalizeRestoreMAC(0, "", string(pmv1.TCPPreservationModeStrict))
	if err != nil {
		t.Fatalf("expected no error; got: %v", err)
	}
	if mac != wantMAC {
		t.Fatalf("expected MAC %q; got %q", wantMAC, mac)
	}
}

// TestJoinNsRestore_EmptyMACStrictFails verifies that finalizeRestoreMAC returns an
// error when readReplVethMACFn returns "" and tcpPreservationMode is Strict (ADR-0133 D3
// fail-closed contract).
func TestJoinNsRestore_EmptyMACStrictFails(t *testing.T) {
	orig := readReplVethMACFn
	readReplVethMACFn = func(pid int, sandboxNetnsPath string) (string, error) {
		return "", nil
	}
	defer func() { readReplVethMACFn = orig }()

	_, err := finalizeRestoreMAC(0, "", string(pmv1.TCPPreservationModeStrict))
	if err == nil {
		t.Fatal("expected error for empty MAC under Strict mode; got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "mac") &&
		!strings.Contains(err.Error(), "replVethMAC") {
		t.Errorf("expected error to mention MAC or replVethMAC; got: %v", err)
	}
}

// TestJoinNsRestore_EmptyMACBestEffortDegrades verifies that finalizeRestoreMAC returns
// no error when readReplVethMACFn returns "" and tcpPreservationMode is BestEffort
// (ADR-0133 D3 degrade path).
func TestJoinNsRestore_EmptyMACBestEffortDegrades(t *testing.T) {
	orig := readReplVethMACFn
	readReplVethMACFn = func(pid int, sandboxNetnsPath string) (string, error) {
		return "", nil
	}
	defer func() { readReplVethMACFn = orig }()

	mac, err := finalizeRestoreMAC(0, "", string(pmv1.TCPPreservationModeBestEffort))
	if err != nil {
		t.Fatalf("expected no error under BestEffort degrade path; got: %v", err)
	}
	if mac != "" {
		t.Errorf("expected empty MAC on degrade path; got %q", mac)
	}
}
