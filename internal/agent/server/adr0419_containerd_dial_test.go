/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

import (
	"strings"
	"testing"
)

// TestADR0419_ContainerdDialPathIsAgentNamespaceReachable is the REGRESSION test for the second
// ADR-0419 gate-attempt-1 blocker.
//
// containerdSocketPath is a HOST mount-namespace path. Every consumer before ADR-0419 honored that
// — `ctr --address <socket>` runs through nsenter/the broker, IN the host mount namespace. ADR-0419
// added the package's first IN-PROCESS consumers (the typed containerd containers/tasks clients),
// which dial from the AGENT's own mount namespace, and passed the host path straight through. The
// chart mounts exactly ONE containerd socket into the agent, at the static Helm value
// agent.containerd.socketPath (/run/containerd/containerd.sock by default), while ADR-0370 discovers
// the authoritative one at runtime. On RKE2 those disagree by construction: discovery correctly
// picks /run/k3s/containerd/containerd.sock — live-confirmed present on every node — the chart
// mounted the system socket, and the dial failed "no such file or directory". A namespace mismatch,
// not a wrong socket, which is why swapping in a different hardcoded path would fix nothing.
func TestADR0419_ContainerdDialPathIsAgentNamespaceReachable(t *testing.T) {
	for _, tc := range []struct {
		name, socket, want string
	}{
		{
			name:   "RKE2/k3s embedded containerd (the socket the live failure dialed)",
			socket: "/run/k3s/containerd/containerd.sock",
			want:   "/host-run/k3s/containerd/containerd.sock",
		},
		{
			name:   "system/kubeadm containerd",
			socket: "/run/containerd/containerd.sock",
			want:   "/host-run/containerd/containerd.sock",
		},
		{
			// One primitive, not a per-distro branch: any /run-resident socket the discovery
			// primitive can adopt gets the same treatment, including an operator-extended one.
			name:   "operator-extended candidate under /run",
			socket: "/run/some-distro/containerd.sock",
			want:   "/host-run/some-distro/containerd.sock",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := containerdSocketPath
			t.Cleanup(func() { containerdSocketPath = prev })
			containerdSocketPath = tc.socket

			got, err := containerdDialPath()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q — an in-process dial must use the agent-visible /host-run spelling, not the host-namespace path", got, tc.want)
			}
			if got == tc.socket {
				t.Error("dial path is identical to the host path — this is the exact defect: the agent's own mount namespace does not carry the discovered socket")
			}
		})
	}
}

// TestADR0419_ContainerdDialPathFailsLoudOutsideRun pins the fail-loud leg. /host-run reaches the
// host's /run and nothing else, so a socket elsewhere has no agent-namespace spelling at all.
// Inventing one would be a guess, which this repo's zero-tech-debt pillar forbids outright.
func TestADR0419_ContainerdDialPathFailsLoudOutsideRun(t *testing.T) {
	for _, socket := range []string{
		"",
		"/var/run/containerd/containerd.sock", // a real symlinked spelling, but not literally under /run
		"/tmp/containerd.sock",
		"relative/containerd.sock",
	} {
		prev := containerdSocketPath
		containerdSocketPath = socket
		got, err := containerdDialPath()
		containerdSocketPath = prev

		if err == nil {
			t.Errorf("socket %q: expected a loud error, got dial path %q — a socket with no agent-namespace path must never be guessed at", socket, got)
		}
		if got != "" {
			t.Errorf("socket %q: error leg must return an empty path, got %q", socket, got)
		}
	}
}

// TestADR0419_ContainerdDialPathTracksDiscovery pins the property that makes this a primitive rather
// than a second static value to keep in sync with the chart: the dial path is derived from whatever
// ADR-0370's discovery adopted, at call time. There is no independent knob that can drift.
func TestADR0419_ContainerdDialPathTracksDiscovery(t *testing.T) {
	prev := containerdSocketPath
	t.Cleanup(func() { containerdSocketPath = prev })

	containerdSocketPath = "/run/containerd/containerd.sock"
	before, err := containerdDialPath()
	if err != nil {
		t.Fatal(err)
	}

	// EnsureContainerdDiscovered adopting the RKE2 winner for the process lifetime.
	containerdSocketPath = "/run/k3s/containerd/containerd.sock"
	after, err := containerdDialPath()
	if err != nil {
		t.Fatal(err)
	}

	if before == after {
		t.Fatal("dial path did not follow the adopted socket — it must be derived from discovery, never pinned independently")
	}
	if !strings.HasPrefix(after, hostRunMountRoot+"/") {
		t.Errorf("dial path %q must sit under the %s bind mount the DaemonSet carries", after, hostRunMountRoot)
	}
}
