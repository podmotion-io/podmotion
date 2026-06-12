// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network

import (
	"context"
	"strings"
	"testing"
)

func TestArmConntrackNotrack_EmptyPodIP(t *testing.T) {
	err := ArmConntrackNotrack(context.Background(), ConntrackNotrackRule{PodIP: ""})
	if err == nil {
		t.Fatal("expected error for empty PodIP, got nil")
	}
}

func TestDisarmConntrackNotrack_EmptyPodIP(t *testing.T) {
	err := DisarmConntrackNotrack(context.Background(), ConntrackNotrackRule{PodIP: ""})
	if err == nil {
		t.Fatal("expected error for empty PodIP, got nil")
	}
}

func TestIsIptablesNotFound(t *testing.T) {
	if !isIptablesNotFound("No rule matching specified criteria") {
		t.Error("expected true for 'No rule matching'")
	}
	if isIptablesNotFound("") {
		t.Error("expected false for empty string")
	}
}

// TestDisarmConntrackNotrack_NotFoundIsSuccess verifies that DisarmConntrackNotrack
// treats a "rule not found" iptables error as success — the teardown path must be
// idempotent so a double-disarm during rollback does not block cleanup.
func TestDisarmConntrackNotrack_NotFoundIsSuccess(t *testing.T) {
	// isIptablesNotFound covers all variants that iptables -D emits when the rule
	// is absent; verify each variant is handled.
	notFoundVariants := []string{
		"No rule matching specified criteria",
		"does a matching rule exist in that chain?",
		"Bad rule (does a matching rule exist in that chain?)",
	}
	for _, s := range notFoundVariants {
		if !isIptablesNotFound(s) {
			t.Errorf("isIptablesNotFound(%q) = false; want true", s)
		}
	}
}

// TestNotrackArgsShape verifies that notrackArgs and notrackDeleteArgs produce
// correctly structured iptables arguments covering the PREROUTING and OUTPUT
// chains — these are the cleanup paths exercised on migration Complete/Failed/RollingBack.
func TestNotrackArgsShape(t *testing.T) {
	podIP := "10.244.1.99"
	comment := "pm-notrack-test"

	for _, chain := range []string{"PREROUTING", "OUTPUT"} {
		args := notrackArgs(chain, podIP, comment)
		joined := joinArgs(args)

		if !contains(args, "-t") || !contains(args, "raw") {
			t.Errorf("notrackArgs(%s): must include -t raw; got: %s", chain, joined)
		}
		if !contains(args, "-A") || !contains(args, chain) {
			t.Errorf("notrackArgs(%s): must include -A %s; got: %s", chain, chain, joined)
		}
		if !contains(args, "-d") || !contains(args, podIP) {
			t.Errorf("notrackArgs(%s): must include -d %s; got: %s", chain, podIP, joined)
		}
		if !contains(args, "-j") || !contains(args, "NOTRACK") {
			t.Errorf("notrackArgs(%s): must include -j NOTRACK; got: %s", chain, joined)
		}
		if !contains(args, "--comment") || !contains(args, comment) {
			t.Errorf("notrackArgs(%s): must include --comment %s; got: %s", chain, comment, joined)
		}

		delArgs := notrackDeleteArgs(chain, podIP, comment)
		delJoined := joinArgs(delArgs)
		if !contains(delArgs, "-D") {
			t.Errorf("notrackDeleteArgs(%s): must include -D for teardown; got: %s", chain, delJoined)
		}
		if !contains(delArgs, chain) {
			t.Errorf("notrackDeleteArgs(%s): must include chain name; got: %s", chain, delJoined)
		}
		if !contains(delArgs, podIP) {
			t.Errorf("notrackDeleteArgs(%s): must include pod IP; got: %s", chain, delJoined)
		}
	}
}

// TestNotrackDefaultComment verifies that ArmConntrackNotrack generates a default
// comment from the pod IP when no explicit comment is provided — this comment is
// used as the teardown key in DisarmConntrackNotrack, so the two must agree.
func TestNotrackDefaultComment(t *testing.T) {
	podIP := "10.244.2.5"
	expectedComment := "pm-notrack-" + podIP

	armArgs := notrackArgs("PREROUTING", podIP, expectedComment)
	delArgs := notrackDeleteArgs("PREROUTING", podIP, expectedComment)

	if !contains(armArgs, expectedComment) {
		t.Errorf("arm args must contain default comment %q; got: %s", expectedComment, joinArgs(armArgs))
	}
	if !contains(delArgs, expectedComment) {
		t.Errorf("delete args must contain default comment %q; got: %s", expectedComment, joinArgs(delArgs))
	}
}

// TestNotrackArgs_BothChainsPresent verifies that both PREROUTING and OUTPUT chains
// are covered by notrackArgs — the M21 spec requires both for inbound and outbound
// conntrack bypass on migrated flows.
func TestNotrackArgs_BothChainsPresent(t *testing.T) {
	podIP := "10.244.1.50"
	comment := "pm-notrack-m21"
	for _, chain := range []string{"PREROUTING", "OUTPUT"} {
		args := notrackArgs(chain, podIP, comment)
		if !contains(args, chain) {
			t.Errorf("notrackArgs must cover chain %s; args: %s", chain, joinArgs(args))
		}
		delArgs := notrackDeleteArgs(chain, podIP, comment)
		if !contains(delArgs, chain) {
			t.Errorf("notrackDeleteArgs must cover chain %s; args: %s", chain, joinArgs(delArgs))
		}
	}
}

func contains(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

func joinArgs(args []string) string {
	return strings.Join(args, " ")
}
