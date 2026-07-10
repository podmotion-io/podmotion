/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// ctr_dumplog_path_test.go — live-bug regression for the ctr checkpoint dump-log path.
//
// Live failure (2026-07-10, postgres None-mode migration): `ctr tasks checkpoint` failed
// (runc "exit status 1"), and the classifier tried to read criu-dump.log at the run bundle
// (/host-run/containerd/.../<taskID>/criu-dump.log). On containerd 2.2.1 runc writes that log
// into the task `work` dir instead — a symlink to /var/lib/containerd/... — so the read got
// "no such file or directory", the classifier went blind, and the non-TCP failure hard-failed
// with no CRIU diagnostic surfaced. resolveCtrDumpLogPath now follows the `work` symlink and
// re-roots it onto the agent-visible /host-var-lib-containerd mount.

import (
	"strings"
	"testing"
)

// TestRemapWorkTargetToDumpLog asserts the `work` symlink target (a /var/lib/containerd host
// path) is re-rooted onto /host-var-lib-containerd and gets criu-dump.log appended.
func TestRemapWorkTargetToDumpLog(t *testing.T) {
	const taskID = "03fbc0283c4874446bca6e35679ec8330b170d54595bdd9ffe8e42d1adc325b4"
	target := "/var/lib/containerd/io.containerd.runtime.v2.task/k8s.io/" + taskID

	got := remapWorkTargetToDumpLog(target)
	want := "/host-var-lib-containerd/io.containerd.runtime.v2.task/k8s.io/" + taskID + "/criu-dump.log"
	if got != want {
		t.Errorf("remapWorkTargetToDumpLog(%q) = %q, want %q", target, got, want)
	}
	if strings.HasPrefix(got, "/var/lib/containerd") {
		t.Error("remapped path still points at the host /var/lib/containerd — not readable in the agent mount namespace")
	}
}

// TestRemapWorkTargetToDumpLog_NonContainerdTarget asserts a target outside the containerd
// state prefix yields "" (nothing to remap) so resolveCtrDumpLogPath skips branch (2).
func TestRemapWorkTargetToDumpLog_NonContainerdTarget(t *testing.T) {
	if got := remapWorkTargetToDumpLog("/some/other/path"); got != "" {
		t.Errorf("remapWorkTargetToDumpLog(non-containerd) = %q, want \"\"", got)
	}
}

// TestResolveCtrDumpLogPath_FallsBackToRunBundle asserts that with no ctr-reported path and no
// resolvable work symlink on disk, the resolver returns the run-bundle path so the caller's
// "unreadable" log still names a concrete location (branch 3).
func TestResolveCtrDumpLogPath_FallsBackToRunBundle(t *testing.T) {
	const taskID = "deadbeef"
	got := resolveCtrDumpLogPath(taskID, "runc did not terminate successfully: exit status 1")
	want := hostBundleDir(taskID) + "/criu-dump.log"
	if got != want {
		t.Errorf("resolveCtrDumpLogPath fallback = %q, want %q", got, want)
	}
}
