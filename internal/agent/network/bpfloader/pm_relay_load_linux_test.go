//go:build linux

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package bpfloader_test

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/podmotion-io/podmotion/internal/agent/network/bpfloader"
	"golang.org/x/sys/unix"
)

// TestLoadPmRelayObjects_ActuallyLoads is the ASSERTING load-time regression
// guard mandated by ADR-0403 §P-VERIFY assertion 2. Unlike TestLoadPmRelaySpec
// (which only parses the ELF and treats a load error as acceptable — the exact
// hole that let the off=14/off=64 verifier-rejection class ship and be
// misdiagnosed twice), this test drives the real
//
//	LoadPmRelayObjects -> spec.LoadAndAssign -> BPF_PROG_LOAD
//
// path that ciliumEBPFManager.ensureRelayLoaded uses, and FAILS on any verifier
// rejection of either pm_relay_tc_egress or pm_relay_tc_ingress.
//
// Honesty boundary (ADR-0403): a *verifier* rejection is always a FAIL — never a
// skip. The ONLY tolerated skip is when the test host cannot exercise BPF at all
// because it lacks privilege (CAP_BPF/CAP_NET_ADMIN); that is an environment
// limitation, not a pass. §P-VERIFY assertion 1/2 is only truly satisfied when
// this test runs green on a privileged BPF-capable 6.8.x kernel (e.g. the KVM
// nodes / a privileged CI runner). A skip here does NOT satisfy the gate.
func TestLoadPmRelayObjects_ActuallyLoads(t *testing.T) {
	// Best-effort: raise RLIMIT_MEMLOCK so a low limit on a privileged runner is
	// not misread as a verifier problem. On <5.11 kernels this is required; on
	// 6.8 map memory is memcg-accounted so this is belt-and-suspenders. Failure
	// here (only on ancient kernels) is not fatal to the assertion below.
	_ = rlimit.RemoveMemlock()

	var objs bpfloader.PmRelayObjects
	err := bpfloader.LoadPmRelayObjects(&objs, nil)
	if err == nil {
		// Loaded cleanly: both TC programs passed the verifier. Release them.
		objs.Close()
		return
	}

	// A verifier rejection is the bug this test exists to catch — always fatal,
	// regardless of privilege. off=14 (defect 1) and off=64 (defect 2) both
	// surface here as *ebpf.VerifierError.
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		t.Fatalf("pm_relay verifier REJECTION (ADR-0403 regression: off=14/off=64 class not fixed):\n%+v", verr)
	}

	// Distinguish "cannot test here due to privilege" from a genuine load defect.
	// An unprivileged host returns EPERM from the BPF syscall before the verifier
	// runs. That is the only tolerated non-fatal outcome — and it is a SKIP, not
	// a pass: the §P-VERIFY live-load gate remains UNMET until this runs green on
	// a privileged kernel.
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("SKIP (NOT a pass — ADR-0403 §P-VERIFY gate UNMET): host lacks BPF privilege "+
			"(CAP_BPF/CAP_NET_ADMIN); run on a privileged BPF-capable 6.8.x kernel to satisfy the gate: %v", err)
	}

	// Any other error (bad ELF, missing map support, memlock, unexpected) is a
	// real failure of the load path.
	t.Fatalf("LoadPmRelayObjects failed with a non-verifier, non-privilege error: %v", err)
}
