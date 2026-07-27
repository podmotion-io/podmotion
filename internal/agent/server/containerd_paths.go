/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

import (
	"os"
	"strings"
)

// sprint50 (k3s compat): every containerd host-path/socket construction in this package used
// to hardcode kubeadm/standard-containerd's default locations (/run/containerd/...,
// /var/lib/containerd/...). k3s ships its own embedded containerd at different locations
// (UNVERIFIED-EXTERNAL — not confirmed against a live k3s node this round, see
// docs/sprints/sprint50-k3s/K3S-COMPATIBILITY-PLAN.md §0 items 1-4 and §2 Round 2). Rather than
// hardcode a second guessed path, these roots are read once from the environment (set via Helm
// values on the k3s deploy path — see charts/podmotion/values.yaml agent.containerd.*) and
// default to exactly the previous hardcoded values, so behavior on the standing kubeadm/
// containerd cluster is unchanged.
//
// ADR-0370: the envOrDefault-only value below is no longer authoritative by itself. It is the
// STARTUP-TIME PLACEHOLDER for these three vars; EnsureContainerdDiscovered
// (containerd_discovery.go), called once from cmd/agent/main.go before the agent advertises
// readiness, empirically confirms which containerd daemon actually owns this agent's own pod
// sandbox and overwrites all three vars with the confirmed values (or exits the process loud on
// failure — see containerd_discovery.go's doc comments). This closes the RKE2/k3s dual-
// containerd failure mode where the blind default silently pointed at the wrong daemon.

const (
	defaultContainerdRunRoot   = "/run/containerd"
	defaultContainerdStateRoot = "/var/lib/containerd"
)

// containerdRunRoot is the host-side directory holding the containerd socket and the
// containerd v2 runtime task-bundle tree
// (<containerdRunRoot>/io.containerd.runtime.v2.task/k8s.io/<taskID>/...). Standard
// kubeadm/containerd installs use /run/containerd; k3s's embedded containerd uses
// /run/k3s/containerd instead (UNVERIFIED-EXTERNAL). Override via
// PODMOTION_CONTAINERD_RUN_ROOT (charts/podmotion/templates/daemonset.yaml wires this from
// agent.containerd.socketPath's directory).
var containerdRunRoot = envOrDefault("PODMOTION_CONTAINERD_RUN_ROOT", defaultContainerdRunRoot)

// containerdStateRoot is the host-side containerd data/state directory containing the task
// `work` dirs where runc writes criu-dump.log
// (<containerdStateRoot>/io.containerd.runtime.v2.task/k8s.io/<taskID>/). Standard installs use
// /var/lib/containerd; k3s uses /var/lib/rancher/k3s/agent/containerd instead
// (UNVERIFIED-EXTERNAL). Override via PODMOTION_CONTAINERD_STATE_ROOT.
var containerdStateRoot = envOrDefault("PODMOTION_CONTAINERD_STATE_ROOT", defaultContainerdStateRoot)

// containerdSocketPath is the host-side containerd control socket, passed to every `ctr`
// invocation via --address so ctr does not fall back to its own compiled-in default (which is
// the standard-containerd path and would be wrong on a k3s node). Override via
// PODMOTION_CONTAINERD_SOCKET; defaults to <containerdRunRoot>/containerd.sock, matching the
// previous hardcoded behavior when containerdRunRoot is left at its default.
var containerdSocketPath = envOrDefault("PODMOTION_CONTAINERD_SOCKET", containerdRunRoot+"/containerd.sock")

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// hostRunMountPath re-roots a bare host path under containerdRunRoot (e.g.
// "<containerdRunRoot>/io.containerd.runtime.v2.task/k8s.io/<id>") onto the agent-visible
// /host-run bind mount (charts/podmotion/templates/daemonset.yaml mounts host /run at
// /host-run — see hostBundleDir's doc comment for why the bare path is unreadable from the
// agent's own mount namespace).
func hostRunMountPath(rel string) string {
	return "/host-run" + strings.TrimPrefix(containerdRunRoot, "/run") + "/" + strings.TrimPrefix(rel, "/")
}

// ctrTaskBundleRoot returns the bare host-namespace path (as seen by nsenterCmd, which runs in
// the host mount namespace) to containerd's v2 runtime task-bundle root.
func ctrTaskBundleRoot() string {
	return containerdRunRoot + "/io.containerd.runtime.v2.task/k8s.io"
}

// ctrArgs prepends the binary and an explicit --address flag (so ctr never relies on its
// compiled-in default socket path, which is wrong on non-standard-containerd substrates like
// k3s) to the given ctr subcommand args.
func ctrArgs(bin string, rest ...string) []string {
	args := []string{bin, "--address", containerdSocketPath}
	return append(args, rest...)
}
