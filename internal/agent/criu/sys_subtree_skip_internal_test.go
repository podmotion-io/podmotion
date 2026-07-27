/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package criu

import (
	"reflect"
	"strings"
	"testing"
)

// TestParseSysSubtreeMounts_CarvesWholeSysSubtree is the regression for the ADR-0415 follow-up:
// --skip-mnt is path-literal/non-recursive, so skipping only "/sys" orphaned its separately-mounted
// children (tmpfs /sys/firmware, cgroup2 /sys/fs/cgroup, …) and aborted the dump at mount.c:381.
// The parser must return /sys AND every mount nested beneath it, and NOTHING outside the subtree.
func TestParseSysSubtreeMounts_CarvesWholeSysSubtree(t *testing.T) {
	// Realistic mountinfo (proc(5) format: mountID parentID major:minor root MOUNTPOINT …).
	// Field index 4 (0-based) is the mountpoint. Mirrors the captured dump.log topology: sysfs at
	// /sys with tmpfs/cgroup2/bpf/tracefs/debugfs children mounted under it.
	mountinfo := strings.Join([]string{
		"1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw",
		"29 1 0:24 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw",
		"30 1 0:25 / /dev rw,nosuid - tmpfs tmpfs rw,mode=755",
		"31 30 0:26 / /dev/shm rw,nosuid,nodev - tmpfs shm rw",
		"4289 1 0:27 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro",
		"3856 4289 0:40 / /sys/firmware ro,relatime - tmpfs tmpfs ro,mode=755",
		"4290 4289 0:28 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup rw",
		"4291 4289 0:29 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw",
		"4292 4289 0:30 / /sys/kernel/tracing rw,nosuid,nodev,noexec - tracefs tracefs rw",
		"4293 4289 0:31 / /sys/kernel/debug rw,nosuid,nodev,noexec - debugfs debugfs rw",
		"77 1 0:60 / /var/lib/kubelet/pods/abc/volumes/kubernetes.io~csi/pvc-x/mount rw - ext4 /dev/sdb rw",
	}, "\n")

	got := parseSysSubtreeMounts([]byte(mountinfo))
	want := []string{
		"/sys",
		"/sys/firmware",
		"/sys/fs/cgroup",
		"/sys/fs/bpf",
		"/sys/kernel/tracing",
		"/sys/kernel/debug",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSysSubtreeMounts subtree mismatch\n got: %v\nwant: %v", got, want)
	}

	// The orphan-trigger child from the captured failure MUST be present — this is the exact mount
	// (3856 @ ./sys/firmware) whose absent parent aborted the dump when only "/sys" was skipped.
	if !contains(got, "/sys/firmware") {
		t.Errorf("/sys/firmware (the captured orphan child, mnt_id 3856) must be in the skip set")
	}
	// The latent second orphan (cgroup2 4290) must also be carved out.
	if !contains(got, "/sys/fs/cgroup") {
		t.Errorf("/sys/fs/cgroup (latent second orphan) must be in the skip set")
	}
	// Non-/sys mounts must never be skipped (ADR-0415 capture-everything-by-default).
	for _, m := range got {
		if m != "/sys" && !strings.HasPrefix(m, "/sys/") {
			t.Errorf("non-/sys mount %q must not be in the /sys carve-out", m)
		}
	}
}

// TestParseSysSubtreeMounts_PrefixBoundary guards against the classic prefix bug: "/sys" must NOT
// swallow siblings like "/system" or "/sysroot" that merely share the "/sys" string prefix.
func TestParseSysSubtreeMounts_PrefixBoundary(t *testing.T) {
	mountinfo := strings.Join([]string{
		"1 0 8:1 / /sys rw - sysfs sysfs rw",
		"2 1 8:1 / /system rw - ext4 /dev/x rw",  // sibling, must NOT match
		"3 1 8:1 / /sysroot rw - ext4 /dev/y rw", // sibling, must NOT match
		"4 1 8:1 / /sys/kernel/config rw - configfs configfs rw",
		"5 1 8:1 / /var/sys rw - ext4 /dev/z rw", // unrelated, must NOT match
	}, "\n")

	got := parseSysSubtreeMounts([]byte(mountinfo))
	want := []string{"/sys", "/sys/kernel/config"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefix-boundary mismatch\n got: %v\nwant: %v", got, want)
	}
}

// TestParseSysSubtreeMounts_DedupAndMalformed verifies duplicate mountpoints collapse and that
// short/blank lines are skipped rather than panicking on a missing field-4.
func TestParseSysSubtreeMounts_DedupAndMalformed(t *testing.T) {
	mountinfo := strings.Join([]string{
		"1 0 8:1 / /sys rw - sysfs sysfs rw",
		"",                                   // blank line
		"garbage",                            // too few fields
		"1 2 3 4",                            // exactly 4 fields (index 4 absent)
		"2 1 8:1 / /sys rw - sysfs sysfs rw", // duplicate /sys
		"3 1 8:1 / /sys/fs/cgroup rw - cgroup2 c rw",   // child
		"4 1 8:1 / /sys/fs/cgroup rw2 - cgroup2 c rw2", // duplicate child
	}, "\n")

	got := parseSysSubtreeMounts([]byte(mountinfo))
	want := []string{"/sys", "/sys/fs/cgroup"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedup/malformed mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestParseSysSubtreeMounts_Empty(t *testing.T) {
	if got := parseSysSubtreeMounts(nil); got != nil {
		t.Fatalf("empty input should yield nil, got %v", got)
	}
	// A target with no /sys mounted at all: nothing to carve out, and nothing to orphan.
	only := "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n29 1 0:24 / /proc rw - proc proc rw"
	if got := parseSysSubtreeMounts([]byte(only)); got != nil {
		t.Fatalf("no-/sys input should yield nil, got %v", got)
	}
}

// TestUnescapeMountinfoField verifies the kernel's octal path escapes are decoded so a matched
// mountpoint is emitted as its real path, while ordinary paths pass through untouched.
func TestUnescapeMountinfoField(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/sys", "/sys"},
		{"/sys/firmware", "/sys/firmware"},
		{`/sys/weird\040dir`, "/sys/weird dir"},   // \040 = space
		{`/sys/tab\011here`, "/sys/tab\there"},    // \011 = tab
		{`/sys/back\134slash`, `/sys/back\slash`}, // \134 = backslash
		{`/sys/trailing\`, `/sys/trailing\`},      // lone trailing backslash, no octal
		{`/sys/not\99octal`, `/sys/not\99octal`},  // \99 not valid octal, left verbatim
		{`/sys/a\040b\011c`, "/sys/a b\tc"},       // multiple escapes
	}
	for _, c := range cases {
		if got := unescapeMountinfoField(c.in); got != c.want {
			t.Errorf("unescapeMountinfoField(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSysSubtreeSkips_InvalidPid confirms the wrapper fails CLOSED on an unusable pid rather than
// returning an empty (partial) skip set that would let the dump proceed and orphan a /sys child.
func TestSysSubtreeSkips_InvalidPid(t *testing.T) {
	if _, err := sysSubtreeSkips(0); err == nil {
		t.Errorf("sysSubtreeSkips(0) must return an error (fail closed), got nil")
	}
	if _, err := sysSubtreeSkips(-1); err == nil {
		t.Errorf("sysSubtreeSkips(-1) must return an error (fail closed), got nil")
	}
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
