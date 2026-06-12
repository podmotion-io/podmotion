// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ConntrackNotrackRule holds the parameters for a NOTRACK rule in the raw table.
// Placed in the raw table PREROUTING + OUTPUT chains so conntrack never sees
// packets for the migrated flow — required by ADR-0048 to prevent the kernel
// from resetting the migrated TCP connection when it sees out-of-window segments
// during the overlay handoff window.
type ConntrackNotrackRule struct {
	// PodIP is the source pod IP to NOTRACK.
	PodIP string
	// Comment is stored in the iptables rule for lifecycle tracing.
	Comment string
}

// ArmConntrackNotrack installs NOTRACK rules in iptables raw table for podIP.
// Two rules are installed: PREROUTING (inbound) and OUTPUT (outbound).
// Idempotent via -C check before -I.
func ArmConntrackNotrack(ctx context.Context, rule ConntrackNotrackRule) error {
	log := logf.FromContext(ctx)
	if rule.PodIP == "" {
		return fmt.Errorf("ArmConntrackNotrack: PodIP must not be empty")
	}
	comment := rule.Comment
	if comment == "" {
		comment = "pm-notrack-" + rule.PodIP
	}

	chains := []string{"PREROUTING", "OUTPUT"}
	for _, chain := range chains {
		args := notrackArgs(chain, rule.PodIP, comment)
		if err := iptablesEnsure(ctx, args); err != nil {
			return fmt.Errorf("ArmConntrackNotrack %s: %w", chain, err)
		}
		log.Info("conntrack NOTRACK armed", "chain", chain, "podIP", rule.PodIP)
	}
	return nil
}

// DisarmConntrackNotrack removes the NOTRACK rules installed by ArmConntrackNotrack.
// ENOENT (rule not found) is treated as success.
func DisarmConntrackNotrack(ctx context.Context, rule ConntrackNotrackRule) error {
	log := logf.FromContext(ctx)
	if rule.PodIP == "" {
		return fmt.Errorf("DisarmConntrackNotrack: PodIP must not be empty")
	}
	comment := rule.Comment
	if comment == "" {
		comment = "pm-notrack-" + rule.PodIP
	}

	chains := []string{"PREROUTING", "OUTPUT"}
	for _, chain := range chains {
		args := notrackDeleteArgs(chain, rule.PodIP, comment)
		if err := iptablesDelete(ctx, args); err != nil {
			return fmt.Errorf("DisarmConntrackNotrack %s: %w", chain, err)
		}
		log.Info("conntrack NOTRACK disarmed", "chain", chain, "podIP", rule.PodIP)
	}
	return nil
}

// notrackArgs builds the iptables -t raw -A args (without the action flag so they
// can be reused for -C / -I).
func notrackArgs(chain, podIP, comment string) []string {
	return []string{
		"-t", "raw",
		"-A", chain,
		"-d", podIP,
		"-j", "NOTRACK",
		"-m", "comment", "--comment", comment,
	}
}

func notrackDeleteArgs(chain, podIP, comment string) []string {
	return []string{
		"-t", "raw",
		"-D", chain,
		"-d", podIP,
		"-j", "NOTRACK",
		"-m", "comment", "--comment", comment,
	}
}

// iptablesEnsure runs iptables -C first; if the rule doesn't exist it inserts it.
func iptablesEnsure(ctx context.Context, appendArgs []string) error {
	checkArgs := make([]string, len(appendArgs))
	copy(checkArgs, appendArgs)
	// Replace -A with -C for the existence check.
	for i, a := range checkArgs {
		if a == "-A" && i+1 < len(checkArgs) {
			checkArgs[i] = "-C"
			break
		}
	}

	checkCmd := exec.CommandContext(ctx, "iptables", checkArgs...)
	if err := checkCmd.Run(); err == nil {
		return nil
	}

	insertArgs := make([]string, len(appendArgs))
	copy(insertArgs, appendArgs)
	for i, a := range insertArgs {
		if a == "-A" && i+1 < len(insertArgs) {
			insertArgs[i] = "-I"
			break
		}
	}

	out, err := exec.CommandContext(ctx, "iptables", insertArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables insert: %w: %s", err, string(out))
	}
	return nil
}

// iptablesDelete runs iptables -D; if the rule is absent the error is suppressed.
func iptablesDelete(ctx context.Context, deleteArgs []string) error {
	out, err := exec.CommandContext(ctx, "iptables", deleteArgs...).CombinedOutput()
	if err != nil {
		outStr := string(out)
		if isIptablesNotFound(outStr) {
			return nil
		}
		return fmt.Errorf("iptables delete: %w: %s", err, outStr)
	}
	return nil
}

func isIptablesNotFound(output string) bool {
	return strings.Contains(output, "No rule matching") ||
		strings.Contains(output, "does a matching rule exist") ||
		strings.Contains(output, "Bad rule")
}
