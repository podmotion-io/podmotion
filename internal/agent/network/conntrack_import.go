/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ConntrackImportOptions controls how ImportConntrack installs entries.
type ConntrackImportOptions struct {
	// DestPodIP is the IP assigned to the restored pod on the destination node.
	// When set, the original-direction source IP in each entry is rewritten from
	// the source pod IP to DestPodIP before insertion. Leave empty to preserve
	// the original IPs as-is (same-IP migration scenarios).
	DestPodIP string

	// SourcePodIP is the original pod IP on the source node. Used together with
	// DestPodIP to rewrite the tuple. Required when DestPodIP is set.
	SourcePodIP string

	// SkipIPVS controls whether IPVS entries (IsIPVS=true) are skipped on
	// import. Set true when kube-proxy is NOT running in IPVS mode on the
	// destination node.
	SkipIPVS bool
}

// ImportConntrack inserts the conntrack entries exported by ExportConntrack into
// the kernel conntrack table on the destination node.
//
// Called after CRIU restore, before the eBPF bridge is disarmed, so that the
// first response packet from the restored pod matches an existing conntrack entry
// and is not treated as an unexpected out-of-state packet.
//
// Source pod is NEVER deleted until TrafficVerified=True (ADR-0012). ImportConntrack
// does not enforce this gate — the caller (state machine) is responsible.
//
// Implementation: entries are inserted via `conntrack -I` subprocesses. No external
// conntrack packages are used (ADR constraint: custom implementation only).
func ImportConntrack(ctx context.Context, entries []ConntrackEntry, opts ConntrackImportOptions) error {
	log := logf.FromContext(ctx)

	if len(entries) == 0 {
		log.Info("ImportConntrack: no entries to import")
		return nil
	}

	var imported, skipped int
	for i := range entries {
		e := rewriteEntry(entries[i], opts)

		if e.IsIPVS && opts.SkipIPVS {
			skipped++
			continue
		}

		if err := insertConntrackEntry(ctx, e); err != nil {
			// Log but do not abort — a partially populated conntrack table is
			// better than blocking the restore. The eBPF bridge will handle
			// the first packet; conntrack will create a new entry automatically
			// when it sees the packet.
			log.Error(err, "ImportConntrack: failed to insert entry",
				"src", e.SrcIP, "dst", e.DstIP,
				"sport", e.SrcPort, "dport", e.DstPort,
				"proto", e.Protocol)
			skipped++
			continue
		}
		imported++
	}

	log.Info("ImportConntrack: complete", "imported", imported, "skipped", skipped)
	return nil
}

// rewriteEntry rewrites the source IP in an entry when a pod IP change is required
// (source pod IP → destination pod IP). Returns a modified copy.
func rewriteEntry(e ConntrackEntry, opts ConntrackImportOptions) ConntrackEntry {
	if opts.SourcePodIP == "" || opts.DestPodIP == "" {
		return e
	}
	srcPod := normalizeIP(net.ParseIP(opts.SourcePodIP))
	dstPod := normalizeIP(net.ParseIP(opts.DestPodIP))
	if srcPod == nil || dstPod == nil {
		return e
	}

	out := e // shallow copy
	if e.SrcIP.Equal(srcPod) {
		out.SrcIP = dstPod
	}
	if e.DstIP.Equal(srcPod) {
		out.DstIP = dstPod
	}
	if e.ReplySrcIP != nil && e.ReplySrcIP.Equal(srcPod) {
		out.ReplySrcIP = dstPod
	}
	if e.ReplyDstIP != nil && e.ReplyDstIP.Equal(srcPod) {
		out.ReplyDstIP = dstPod
	}
	return out
}

// insertConntrackEntry calls `conntrack -I` to inject one entry into the kernel table.
//
// conntrack -I args:
//
//	-p <proto>
//	-s <src>  -d <dst>  --sport <p>  --dport <p>
//	--reply-src <r>  --reply-dst <r>  --reply-sport <p>  --reply-dport <p>
//	--state <state>   (TCP only)
//	--timeout <t>     (seconds; we use a conservative 120s)
//	[--mark <m>]
func insertConntrackEntry(ctx context.Context, e ConntrackEntry) error {
	args := buildConntrackInsertArgs(e)
	cmd := exec.CommandContext(ctx, "conntrack", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(out)
		// "File exists" means an identical entry is already present — treat as success.
		if strings.Contains(outStr, "File exists") || strings.Contains(outStr, "EEXIST") {
			return nil
		}
		return fmt.Errorf("conntrack -I: %w: %s", err, outStr)
	}
	return nil
}

// buildConntrackInsertArgs constructs the argument list for `conntrack -I`.
func buildConntrackInsertArgs(e ConntrackEntry) []string {
	args := []string{
		"-I",
		"-p", e.Protocol,
		"-s", e.SrcIP.String(),
		"-d", e.DstIP.String(),
	}

	if e.SrcPort != 0 {
		args = append(args, "--sport", fmt.Sprintf("%d", e.SrcPort))
	}
	if e.DstPort != 0 {
		args = append(args, "--dport", fmt.Sprintf("%d", e.DstPort))
	}

	// Reply tuple — use original if reply not set.
	replySrc := e.ReplySrcIP
	replyDst := e.ReplyDstIP
	replySport := e.ReplySrcPort
	replyDport := e.ReplyDstPort
	if replySrc == nil {
		replySrc = e.DstIP
	}
	if replyDst == nil {
		replyDst = e.SrcIP
	}
	if replySport == 0 {
		replySport = e.DstPort
	}
	if replyDport == 0 {
		replyDport = e.SrcPort
	}

	if replySrc != nil {
		args = append(args, "--reply-src", replySrc.String())
	}
	if replyDst != nil {
		args = append(args, "--reply-dst", replyDst.String())
	}
	if replySport != 0 {
		args = append(args, "--reply-sport", fmt.Sprintf("%d", replySport))
	}
	if replyDport != 0 {
		args = append(args, "--reply-dport", fmt.Sprintf("%d", replyDport))
	}

	// TCP state.
	if strings.EqualFold(e.Protocol, "tcp") && e.State != "" {
		args = append(args, "--state", strings.ToUpper(e.State))
	}

	// Timeout: 120 seconds is conservative for ESTABLISHED TCP during migration.
	args = append(args, "--timeout", "120")

	if e.Mark != 0 {
		args = append(args, "--mark", fmt.Sprintf("%d", e.Mark))
	}
	if e.Zone != 0 {
		args = append(args, "--zone", fmt.Sprintf("%d", e.Zone))
	}

	return args
}

// PurgeConntrackForPod removes all conntrack entries matching podIP from the
// kernel table. Called after the source pod is deleted (post TrafficVerified=True)
// to ensure no leaked conntrack entries remain.
//
// ADR constraint: no leaked conntrack entries after test run.
func PurgeConntrackForPod(ctx context.Context, podIP string) error {
	log := logf.FromContext(ctx)
	if podIP == "" {
		return fmt.Errorf("PurgeConntrackForPod: podIP must not be empty")
	}

	// Delete by original-direction source.
	if err := runConntrackDelete(ctx, "--orig-src", podIP); err != nil {
		log.Error(err, "PurgeConntrackForPod: delete by orig-src (non-fatal)", "podIP", podIP)
	}
	// Delete by original-direction destination.
	if err := runConntrackDelete(ctx, "--orig-dst", podIP); err != nil {
		log.Error(err, "PurgeConntrackForPod: delete by orig-dst (non-fatal)", "podIP", podIP)
	}
	// Delete by reply-direction source.
	if err := runConntrackDelete(ctx, "--reply-src", podIP); err != nil {
		log.Error(err, "PurgeConntrackForPod: delete by reply-src (non-fatal)", "podIP", podIP)
	}
	// Delete by reply-direction destination.
	if err := runConntrackDelete(ctx, "--reply-dst", podIP); err != nil {
		log.Error(err, "PurgeConntrackForPod: delete by reply-dst (non-fatal)", "podIP", podIP)
	}

	log.Info("PurgeConntrackForPod: complete", "podIP", podIP)
	return nil
}

// runConntrackDelete executes `conntrack -D <filterFlag> <value>`.
// "No entries" (exit 1 with no output) is treated as success.
func runConntrackDelete(ctx context.Context, filterFlag, value string) error {
	cmd := exec.CommandContext(ctx, "conntrack", "-D", filterFlag, value)
	out, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(out)
		// conntrack exits 1 when 0 entries were deleted — not an error.
		if strings.Contains(outStr, "0 flow entries") || outStr == "" {
			return nil
		}
		return fmt.Errorf("conntrack -D %s %s: %w: %s", filterFlag, value, err, outStr)
	}
	return nil
}
