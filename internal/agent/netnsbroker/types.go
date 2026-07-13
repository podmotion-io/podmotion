// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// ADR-0346 D6: ExecResult lives in this untagged file (no //go:build
// constraint) so it is visible to both the linux Client (client.go) and the
// non-linux stub Client (broker_other.go). It was previously defined only in
// client.go under //go:build linux, which meant broker_other.go's stub could
// not return it — this move is the primitive fix: one shared type, not
// two independently-maintained copies of the same wire shape.
package netnsbroker

// ExecResult is the outcome of a broker exec-family op (host-mount-ns Exec,
// ResolveVeth, or the ADR-0346 netns-scoped NetnsExec). It mirrors what the
// agent would have gotten from running the equivalent nsenter command itself:
// ExitCode is the command's exit status, Stdout/Stderr/Combined are the
// captured streams. SpawnErr is non-nil ONLY when the broker could not run the
// command at all (validation reject, nsenter spawn failure, or — on non-linux
// — unconditionally) — a non-zero ExitCode is NOT a SpawnErr.
type ExecResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	Combined []byte
	SpawnErr error
}

// NetnsExecSelfToken is the fixed self-path sentinel a CLIENT transmits as
// Argv[0] to request the broker's own-binary allowlist entry for the
// __inetns_probe/__inetns_echo helpers (ADR-0346 D3/D5). It is the exported,
// build-tag-neutral home of the wire-contract value so every caller — the linux
// broker's netnsExecAllowlist AND cross-package clients like
// internal/agent/server — reference ONE literal (a single source of truth),
// never a second copy that could drift. It is NEVER a live filesystem path: the
// broker matches it by exact equality and substitutes its own os.Executable()-
// pinned self path server-side, so a client MUST send this token and MUST NOT
// send os.Executable()/"/proc/self/exe" (which the exact-match allowlist rejects).
const NetnsExecSelfToken = "__podmotion_netns_exec_self__"
