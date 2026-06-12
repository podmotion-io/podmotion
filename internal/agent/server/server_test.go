/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

import (
	"strings"
	"testing"
)

// TestBuildCRIURestoreArgs_JoinNs asserts that when destNetnsFd is non-empty,
// buildCRIURestoreArgs produces --join-ns net:<fd> and --tcp-established, and
// that --empty-ns and --tcp-close are absent (M19 acceptance criterion: joinNsRestore
// unit test asserts --join-ns net:<fd> selected when NetworkContinuity != None).
func TestBuildCRIURestoreArgs_JoinNs(t *testing.T) {
	args := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		"/var/lib/podmotion/restore/test/termination-log",
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"/proc/12345/fd/7",
	)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--join-ns net:/proc/12345/fd/7") {
		t.Errorf("expected --join-ns net:/proc/12345/fd/7 in args; got: %s", joined)
	}
	if !strings.Contains(joined, "--tcp-established") {
		t.Errorf("expected --tcp-established in args; got: %s", joined)
	}
	if strings.Contains(joined, "--empty-ns") {
		t.Errorf("--empty-ns must not appear when destNetnsFd is set; got: %s", joined)
	}
	if strings.Contains(joined, "--tcp-close") {
		t.Errorf("--tcp-close must not appear when destNetnsFd is set; got: %s", joined)
	}
	if strings.Contains(joined, "--restore-detached") {
		t.Errorf("--restore-detached must never appear (ghost container risk); got: %s", joined)
	}
}

// TestBuildCRIURestoreArgs_EmptyNs asserts that when destNetnsFd is empty (stateless
// cold migration), buildCRIURestoreArgs produces --empty-ns net and --tcp-close, and
// that --join-ns and --tcp-established are absent.
func TestBuildCRIURestoreArgs_EmptyNs(t *testing.T) {
	args := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		"/var/lib/podmotion/restore/test/termination-log",
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"",
	)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--empty-ns net") {
		t.Errorf("expected --empty-ns net in args; got: %s", joined)
	}
	if !strings.Contains(joined, "--tcp-close") {
		t.Errorf("expected --tcp-close in args; got: %s", joined)
	}
	if strings.Contains(joined, "--join-ns") {
		t.Errorf("--join-ns must not appear when destNetnsFd is empty; got: %s", joined)
	}
	if strings.Contains(joined, "--tcp-established") {
		t.Errorf("--tcp-established must not appear when destNetnsFd is empty; got: %s", joined)
	}
	if strings.Contains(joined, "--restore-detached") {
		t.Errorf("--restore-detached must never appear (ghost container risk); got: %s", joined)
	}
}
