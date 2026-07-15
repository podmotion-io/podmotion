/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package buildinfo surfaces the authoritative build identity that the Go
// toolchain embeds into every binary at compile time (the -buildvcs settings:
// vcs.revision, vcs.modified, vcs.time).
//
// Why this exists: a running operator/agent binary previously reported NOTHING
// that identified the source tree it was built from. When a live-migration proof
// run was recorded, a stale binary (built before a code change) was
// indistinguishable at runtime from a fresh one — the correspondence between the
// deployed artifact and the reviewed source could only be reconstructed
// STRUCTURALLY, after the fact, from observed behavior. That inference chain is
// the exact failure mode the codebase is meant to avoid: read the authoritative
// value directly instead of guessing it later.
//
// Reading Provenance and logging it at process start converts that after-the-fact
// reconstruction into a direct read: any proof transcript now carries, in the
// operator/agent startup lines, the commit the binary was built from and whether
// that tree carried uncommitted changes. A binary built from a committed tree is
// pinned to a unique revision; a binary built from a dirty tree is flagged as
// such (Dirty==true) so its identity is known to be un-pinnable and a rebuild
// from a committed tree is required to establish artifact/source correspondence.
package buildinfo

import "runtime/debug"

const unknown = "unknown"

// Provenance is the build identity of the currently running binary, read from the
// embedded Go build info. Fields default to "unknown" when the toolchain did not
// stamp VCS data (for example a build produced with -buildvcs=false or outside a
// version-control tree); the zero/"unknown" state is reported honestly rather than
// fabricated.
type Provenance struct {
	// Revision is the VCS commit the binary was built from, or "unknown".
	Revision string
	// Dirty is true when the binary was built from a working tree that had
	// uncommitted changes (vcs.modified == "true"). A dirty build's identity is
	// NOT pinned to a commit.
	Dirty bool
	// CommitTime is the commit timestamp of Revision (vcs.time), or "unknown".
	CommitTime string
	// GoVersion is the Go toolchain version that produced the binary.
	GoVersion string
}

// Read returns the Provenance of the running binary. It never panics and never
// returns an error: when build info is unavailable it reports "unknown" fields.
func Read() Provenance {
	p := Provenance{Revision: unknown, CommitTime: unknown, GoVersion: unknown}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return p
	}
	if info.GoVersion != "" {
		p.GoVersion = info.GoVersion
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if s.Value != "" {
				p.Revision = s.Value
			}
		case "vcs.modified":
			p.Dirty = s.Value == "true"
		case "vcs.time":
			if s.Value != "" {
				p.CommitTime = s.Value
			}
		}
	}
	return p
}

// State returns "clean" or "dirty" for the working tree the binary was built from.
func (p Provenance) State() string {
	if p.Dirty {
		return "dirty"
	}
	return "clean"
}

// LogValues returns structured key/value pairs suitable for a logr.Logger.Info
// call, e.g. logger.Info("...", buildinfo.Read().LogValues()...).
func (p Provenance) LogValues() []any {
	return []any{
		"vcsRevision", p.Revision,
		"vcsState", p.State(),
		"vcsCommitTime", p.CommitTime,
		"goVersion", p.GoVersion,
	}
}
