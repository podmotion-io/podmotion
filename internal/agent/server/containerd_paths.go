/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

import (
	"fmt"
	"os"
	"strings"
)

// sprint50 (k3s compat): every containerd host-path/socket construction in this package used
// to hardcode kubeadm/standard-containerd's default locations (/run/containerd/...,
// /var/lib/containerd/...). k3s ships its own embedded containerd at different locations
// (UNVERIFIED-EXTERNAL — not confirmed against a live k3s node this round). Rather than
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

// hostRunMountRoot is where charts/podmotion/templates/daemonset.yaml bind-mounts the host's
// /run into the AGENT container (read-only). It is the agent's only view of the host /run
// tree: the agent's own /run carries just the handful of paths the chart mounts individually.
const hostRunMountRoot = "/host-run"

// hostRunMountPath re-roots a bare host path under containerdRunRoot (e.g.
// "<containerdRunRoot>/io.containerd.runtime.v2.task/k8s.io/<id>") onto the agent-visible
// /host-run bind mount (charts/podmotion/templates/daemonset.yaml mounts host /run at
// /host-run — see hostBundleDir's doc comment for why the bare path is unreadable from the
// agent's own mount namespace).
func hostRunMountPath(rel string) string {
	return hostRunMountRoot + strings.TrimPrefix(containerdRunRoot, "/run") + "/" + strings.TrimPrefix(rel, "/")
}

// containerdDialPath translates containerdSocketPath — a HOST mount-namespace path — into the
// path that reaches the SAME socket from the AGENT container's own mount namespace.
//
// WHY EVERY IN-PROCESS DIAL NEEDS THIS (ADR-0419, gate attempt 1 root cause). containerdSocketPath
// is documented above as "the host-side containerd control socket", and until ADR-0419 every
// consumer honored that: `ctr --address <socket>` runs through nsenterCmd/the broker, i.e. IN the
// host mount namespace, where the bare path is correct. ADR-0419 introduced the package's first
// IN-PROCESS consumers (the typed containerd containers/tasks clients), which dial from the agent's
// OWN mount namespace — and there the bare path is not reachable. The chart mounts exactly one
// containerd socket into the agent, at the STATIC Helm value agent.containerd.socketPath
// (/run/containerd/containerd.sock by default), while ADR-0370 discovers the AUTHORITATIVE socket
// at runtime. On RKE2 those disagree by construction: discovery correctly selects
// /run/k3s/containerd/containerd.sock (kubelet's containerd, live-confirmed present on the host),
// the chart mounted the system one, and the dial failed "no such file or directory" — a namespace
// mismatch, not a wrong socket. Re-rooting onto /host-run is what makes the discovered answer and
// the dialable path the same fact on every distro, with no second static value to keep in sync.
// (The /host-run bind is read-only; connect(2) to a Unix socket is not a filesystem write and is
// not refused by MS_RDONLY — verified live on this project's standing cluster.)
//
// Fails loud when the discovered socket does not live under /run: /host-run reaches the host's /run
// and nothing else, so a socket elsewhere (an operator override outside /run) has no agent-namespace
// spelling at all, and inventing one would be a guess.
func containerdDialPath() (string, error) {
	sock := containerdSocketPath
	if sock == "" {
		return "", fmt.Errorf("containerd socket path is empty — ADR-0370 discovery has not run or adopted a socket")
	}
	if !strings.HasPrefix(sock, "/run/") {
		return "", fmt.Errorf("containerd socket %q is not under /run — the agent container reaches the host /run tree only through the %s bind mount (charts/podmotion/templates/daemonset.yaml), so this socket has no agent-mount-namespace path; refusing to guess one", sock, hostRunMountRoot)
	}
	return hostRunMountRoot + strings.TrimPrefix(sock, "/run"), nil
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
