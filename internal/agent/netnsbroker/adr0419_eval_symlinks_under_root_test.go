//go:build linux

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package netnsbroker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestADR0419_AbsoluteSymlinkReAnchorsAtRoot is the REGRESSION test for the ADR-0419 gate-attempt-1
// root cause.
//
// doHostRealpath used filepath.EvalSymlinks(filepath.Join("/proc/1/root", target)) and believed that
// resolved in the host mount namespace. /proc/<pid>/root is a MAGIC symlink whose readlink(2) value
// is the literal "/", and Go's resolver is textual: on an ABSOLUTE link target it discards everything
// resolved so far and restarts at its OWN "/". The gateway was therefore erased at the first
// component and the whole path resolved in the BROKER's mount namespace, which carries none of the
// three path families this op exists for. Live signature: "lstat /var/lib/podmotion: no such file or
// directory" — top-level component, no /proc/1/root prefix — while /proc/1/root/var/lib/podmotion
// existed the entire time.
//
// The test reproduces the mechanism without needing a second mount namespace: a symlink whose target
// is ABSOLUTE must re-anchor at ROOT, and the pre-fix resolver is asserted to give a different answer
// on the identical inputs.
func TestADR0419_AbsoluteSymlinkReAnchorsAtRoot(t *testing.T) {
	root := t.TempDir()

	// A directory name that cannot plausibly exist at the machine's real "/", so the contrast
	// assertion below is deterministic on any host.
	const inner = "pm-adr0419-hostroot-only"
	if err := os.MkdirAll(filepath.Join(root, inner, "restore", "mig"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, inner, "restore", "mig", "termination-log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// An ABSOLUTE symlink, expressed in ROOT's own coordinates — exactly the shape that made the old
	// resolver escape.
	if err := os.Symlink("/"+inner, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	got, err := evalSymlinksUnderRoot(root, "/link/restore/mig/termination-log")
	if err != nil {
		t.Fatalf("evalSymlinksUnderRoot must resolve beneath root, got error: %v", err)
	}
	want := "/" + inner + "/restore/mig/termination-log"
	if got != want {
		t.Errorf("absolute symlink must re-anchor at ROOT: got %q, want %q", got, want)
	}

	// The pre-fix expression, on the identical inputs. It restarts at the test process's own "/",
	// where the target does not exist — the exact failure the live restore hit.
	if _, err := filepath.EvalSymlinks(filepath.Join(root, "link", "restore", "mig", "termination-log")); err == nil {
		t.Error("filepath.EvalSymlinks was expected to escape the root and fail — if it now succeeds, this regression test no longer pins the defect")
	}
}

// TestADR0419_EvalSymlinksUnderRootResolution pins the rest of the walker's contract: plain paths,
// relative symlinks, chained symlinks, and "." segments.
func TestADR0419_EvalSymlinksUnderRootResolution(t *testing.T) {
	root := t.TempDir()
	mustMkdir := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, p), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mustSymlink := func(target, name string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}

	mustMkdir("var/lib/podmotion/restore/mig")
	if err := os.WriteFile(filepath.Join(root, "var/lib/podmotion/restore/mig/termination-log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	mustSymlink("lib/podmotion", "var/pm")            // relative link
	mustSymlink("/var/pm", "pm")                      // absolute link THROUGH a relative link
	mustSymlink("/var/lib/podmotion", "var/lib/self") // absolute link to a real dir

	for _, tc := range []struct {
		name, in, want string
	}{
		{"plain path, no symlinks", "/var/lib/podmotion/restore/mig/termination-log", "/var/lib/podmotion/restore/mig/termination-log"},
		{"relative symlink", "/var/pm/restore/mig", "/var/lib/podmotion/restore/mig"},
		{"chained absolute-through-relative symlink", "/pm/restore/mig", "/var/lib/podmotion/restore/mig"},
		{"absolute symlink to a real dir", "/var/lib/self/restore", "/var/lib/podmotion/restore"},
		{"dot segments are elided", "/var/./lib/./podmotion", "/var/lib/podmotion"},
		{"root itself", "/", "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evalSymlinksUnderRoot(root, tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestADR0419_EvalSymlinksUnderRootCannotEscape pins the property that replaces the deleted
// "resolved outside the host mount namespace root" guard: escape is impossible BY CONSTRUCTION.
// ".." at the root clamps to the root, and every returned component was resolved beneath it.
func TestADR0419_EvalSymlinksUnderRootCannotEscape(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "hostname"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink pointing outside root the only way a path can: upward traversal.
	if err := os.Symlink("../../../../etc/hostname", filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ in, want string }{
		{"/../../../etc/hostname", "/etc/hostname"},
		{"/etc/../etc/hostname", "/etc/hostname"},
		{"/escape", "/etc/hostname"},
		{"/..", "/"},
	} {
		got, err := evalSymlinksUnderRoot(root, tc.in)
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("%q: got %q, want %q — .. must clamp at root, never escape it", tc.in, got, tc.want)
		}
	}
}

// TestADR0419_EvalSymlinksUnderRootFailsClosed pins the fail-closed legs. D9 rejects an unverifiable
// target, so every one of these must surface as an error rather than a plausible-looking path.
func TestADR0419_EvalSymlinksUnderRootFailsClosed(t *testing.T) {
	root := t.TempDir()

	t.Run("absent component", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(root, "var", "lib"), 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := evalSymlinksUnderRoot(root, "/var/lib/podmotion/restore/mig")
		if err == nil {
			t.Fatal("an absent component must be an error, never a resolved path")
		}
		// The diagnostic must name the ROOT-prefixed path, so an operator can tell which namespace
		// was actually consulted — the single fact the original defect's message hid.
		if !strings.Contains(err.Error(), root) {
			t.Errorf("error %q must name the root-prefixed path so the consulted namespace is unambiguous", err)
		}
	})

	t.Run("symlink loop terminates as an error", func(t *testing.T) {
		if err := os.Symlink("/b", filepath.Join(root, "a")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/a", filepath.Join(root, "b")); err != nil {
			t.Fatal(err)
		}
		if _, err := evalSymlinksUnderRoot(root, "/a"); err == nil {
			t.Fatal("a symlink cycle must terminate as an error, not a hang or a bogus path")
		}
	})

	t.Run("relative target rejected", func(t *testing.T) {
		if _, err := evalSymlinksUnderRoot(root, "var/lib/podmotion"); err == nil {
			t.Fatal("a non-absolute target must be rejected")
		}
	})
}
