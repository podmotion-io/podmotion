// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

// Package cripaths holds the containerd CRI plugin's on-disk subtree segments — the single
// source of truth for every confinement check in this agent that has to name one of them.
//
// WHY THIS PACKAGE EXISTS (ADR-0421 D1e). There are TWO independent confinement bounds on a
// runtime-supplied --ext-mount-map target, and that independence is deliberate (ADR-0419 D9):
//
//  1. the agent's own precise, discovery-derived prefix check
//     (allowedExtMountHostTargetPrefixes, internal/agent/server) — it composes an ABSOLUTE
//     prefix by joining each of these segments onto the containerd root DISCOVERED at runtime
//     (ADR-0370), and bounds what may be USED; and
//  2. the privileged netns-broker's server-pinned path family (hostRealpathAllowed,
//     internal/agent/netnsbroker) — it does not perform containerd root discovery, so it
//     matches the INVARIANT segment as an interior marker instead, and bounds what may be
//     ASKED of an unconfined process.
//
// Neither is trusted alone and neither may be collapsed into the other: they answer different
// questions with different privilege, and merging them would delete a real control. But they
// must never disagree about the SET OF SUBTREE CLASSES that exists, and before this package
// they did. ADR-0421 D1 widened bound (1) with the per-container subtree and left bound (2)
// carrying a hardcoded sandbox-only marker, so a containers-tree target passed the agent's
// check and was then refused by the broker as "outside the server-pinned path family" — the
// restore failed closed on a path both bounds intended to admit. Two hand-maintained copies of
// one list drifted the moment one of them was edited, which is exactly the divergence class
// internal/agent/restoretargets was created to close for the Rule D membership predicate.
//
// So the CLASS LIST lives here, once. Each bound still applies its own matching rule to it —
// absolute-prefix-under-discovered-root for the agent, interior-marker for the broker — and
// AllDirRels is what both iterate, so adding a fifth writer class here reaches both bounds in
// one edit and cannot reach only one.
//
// This package imports nothing and is platform-neutral (the broker is linux-only; the agent
// server package is not), so it can be a leaf dependency of both without a cycle.
package cripaths

// SandboxDirRel is the CRI plugin's per-sandbox subtree, RELATIVE to the containerd root dir.
// It holds the sandbox-scoped files containerd writes and bind-mounts into every container in
// the pod: <root>/io.containerd.grpc.v1.cri/sandboxes/<sandboxID>/{hostname,resolv.conf,shm}.
const SandboxDirRel = "io.containerd.grpc.v1.cri/sandboxes"

// ContainersDirRel is the CRI plugin's per-container subtree, RELATIVE to the containerd root
// dir. It holds the anonymous volume dirs containerd synthesizes for an image VOLUME directive
// the pod spec does not address:
// <root>/io.containerd.grpc.v1.cri/containers/<containerID>/volumes/<hash>.
//
// ADR-0421 D1 established this as a FOURTH legitimate writer of destination mount sources. It
// is not exotic and not a kind artifact: it is documented CRI-plugin behavior for any image
// VOLUME the pod spec does not cover, and ADR-0421 §P-VERIFY #1 measured the identical relative
// segment on two independent substrates (kind/containerd 2.3.1 under root /var/lib/containerd;
// RKE2 v1.36.4+rke2r1 under root /var/lib/rancher/rke2/agent/containerd).
const ContainersDirRel = "io.containerd.grpc.v1.cri/containers"

// AllDirRels is the complete set of CRI subtree classes a destination-rebind --ext-mount-map
// target may legitimately live under. BOTH confinement bounds iterate this slice rather than
// naming the segments individually, so the two can no longer carry different class sets.
//
// It returns a fresh slice on every call: a package-level exported slice is writable by any
// importer, and the whole point of this value is that no consumer may widen it.
func AllDirRels() []string {
	return []string{SandboxDirRel, ContainersDirRel}
}

// Marker renders one relative subtree segment as an INTERIOR PATH MARKER — "/<rel>/" — for a
// consumer that cannot resolve the containerd root and must therefore match the invariant
// segment inside an absolute path instead of anchoring a prefix to it.
//
// The leading and trailing separators are load-bearing, not cosmetic. Without them a substring
// match would also accept a path where the segment appears as a suffix of some other directory
// name, or as a filename leaf rather than a traversed directory.
func Marker(rel string) string { return "/" + rel + "/" }
