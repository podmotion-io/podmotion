//go:build linux

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package netnsbroker

import "testing"

// TestADR0419_HostRealpathAllowedPathFamily pins the host_realpath op's SERVER-PINNED path family
// (SC-1). The client never supplies any part of a privileged read path outside this family, so a
// compromised de-privileged agent cannot turn the op into a general host-filesystem oracle.
//
// It is deliberately COARSER than the agent's own allowedExtMountHostTargetPrefixes check: the
// broker bounds what may be ASKED, the agent bounds what may be USED, and neither is trusted alone.
func TestADR0419_HostRealpathAllowedPathFamily(t *testing.T) {
	allowed := []string{
		"/var/lib/kubelet/pods/abc/etc-hosts",
		"/var/lib/podmotion/restore/mig/termination-log",
		// The containerd ROOT dir is discovered at runtime and differs per distro, so the invariant
		// SUBTREE is what is pinned — both of these are real shapes from the standing cluster.
		"/var/lib/rancher/rke2/agent/containerd/io.containerd.grpc.v1.cri/sandboxes/deadbeef/hostname",
		"/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/deadbeef/resolv.conf",
	}
	rejected := []string{
		"",
		"relative/path",
		"/etc/shadow",
		"/",
		"/root/.ssh/id_rsa",
		"/proc/1/root/etc/shadow",
		"/var/lib/kubelet/pods/../../../etc/shadow", // not lexically clean
		"/var/lib/kubelet/pods/a\nb",                // control character
		"/var/lib/kubelet/pods/a\x00b",              // NUL
	}
	for _, p := range allowed {
		if !hostRealpathAllowed(p) {
			t.Errorf("path family must ALLOW %q", p)
		}
	}
	for _, p := range rejected {
		if hostRealpathAllowed(p) {
			t.Errorf("path family must REJECT %q — the op is not a general host-filesystem oracle", p)
		}
	}
}
