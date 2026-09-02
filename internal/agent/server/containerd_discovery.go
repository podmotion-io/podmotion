/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/podmotion-io/podmotion/internal/metrics"
)

// ADR-0370: agent self-discovers the authoritative containerd socket at runtime instead of
// trusting PODMOTION_CONTAINERD_SOCKET blindly. Root cause this replaces: RKE2/k3s nodes run
// TWO independent containerd daemons (system containerd + the embedded one kubelet actually
// drives), and the previous envOrDefault-only default silently wired the agent to whichever one
// happened to be the compiled default — wrong on RKE2 100% of the time, and never loudly wrong.
//
// Ground truth used: THIS agent's own pod's sandbox. By CRI/kubelet contract, RunPodSandbox for
// a pod always completes before CreateContainer/StartContainer runs any container inside it —
// including the agent's own container. So by the time this code runs, the agent's OWN pod's
// sandbox is already, unconditionally, present in whichever containerd kubelet actually used to
// create it. This is a zero-race, always-available, self-verifying signal — a primitive, not a
// smarter guess (CLAUDE.md substrate-primitive bias).
//
// Zero-tech-debt pillar (standing project rule): every anomaly below — an explicit override that
// doesn't check out, zero hits, or an ambiguous multi-hit — fails loud. This code never silently
// falls back to a default and never picks a candidate without ground-truth confirmation.

// containerdCandidate is one (socket, runRoot, stateRoot) triple this agent might be wired to.
type containerdCandidate struct {
	Socket    string
	RunRoot   string
	StateRoot string
	// Label is a human-readable description of where this candidate came from, surfaced in
	// fail-loud diagnostics so an operator can tell which layout was tried.
	Label string
}

const (
	// systemContainerdSocket/RunRoot/StateRoot are the standard kubeadm/plain-containerd
	// locations — today's compiled default, unchanged by this ADR.
	systemContainerdSocket    = "/run/containerd/containerd.sock"
	systemContainerdRunRoot   = "/run/containerd"
	systemContainerdStateRoot = "/var/lib/containerd"

	// rke2ContainerdSocket/RunRoot/StateRoot are RKE2's embedded containerd (k3s-packaging
	// paths reused verbatim) — live-confirmed against v1.35.6+rke2r1 (ADR-0370 Context).
	// RunRoot == StateRoot for this pairing: the task-bundle/work tree sits directly under the
	// run root here, NOT under containerd's separate persistent image/snapshot root at
	// /var/lib/rancher/rke2/agent/containerd (a different tree entirely).
	rke2ContainerdSocket    = "/run/k3s/containerd/containerd.sock"
	rke2ContainerdRunRoot   = "/run/k3s/containerd"
	rke2ContainerdStateRoot = "/run/k3s/containerd"

	// containerdSocketCandidatesEnv lets an operator extend the candidate list without a code
	// change for a distro this ADR does not already know about. Comma-separated socket paths;
	// run/state roots are inferred as filepath.Dir(socket) for each.
	containerdSocketCandidatesEnv = "PODMOTION_CONTAINERD_SOCKET_CANDIDATES"

	// podUIDEnv is the downward-API field (fieldRef: metadata.uid) this discovery primitive
	// requires to probe candidates against the agent's OWN pod sandbox. Wired in
	// charts/podmotion/templates/daemonset.yaml alongside the existing NODE_NAME field.
	podUIDEnv = "POD_UID"
)

// buildContainerdCandidates returns the ordered candidate list per ADR-0370 Decision item 1.
//
// If PODMOTION_CONTAINERD_SOCKET is explicitly set (non-empty), it is returned as the ONLY
// candidate — the operator-override path, tried first and exclusively (Decision item 4): a
// contradiction against ground truth must fail loud, never silently fall through to the
// built-in list, because silently second-guessing an explicit operator instruction is its own
// kind of guess.
func buildContainerdCandidates() []containerdCandidate {
	if override := os.Getenv("PODMOTION_CONTAINERD_SOCKET"); override != "" {
		return []containerdCandidate{{
			Socket:    override,
			RunRoot:   envOrDefault("PODMOTION_CONTAINERD_RUN_ROOT", filepath.Dir(override)),
			StateRoot: envOrDefault("PODMOTION_CONTAINERD_STATE_ROOT", filepath.Dir(override)),
			Label:     "operator override (PODMOTION_CONTAINERD_SOCKET)",
		}}
	}

	candidates := []containerdCandidate{
		{
			Socket:    systemContainerdSocket,
			RunRoot:   systemContainerdRunRoot,
			StateRoot: systemContainerdStateRoot,
			Label:     "system/kubeadm containerd (compiled default)",
		},
		{
			Socket:    rke2ContainerdSocket,
			RunRoot:   rke2ContainerdRunRoot,
			StateRoot: rke2ContainerdStateRoot,
			Label:     "RKE2/k3s embedded containerd",
		},
	}

	if extra := os.Getenv(containerdSocketCandidatesEnv); extra != "" {
		for _, sock := range strings.Split(extra, ",") {
			sock = strings.TrimSpace(sock)
			if sock == "" {
				continue
			}
			candidates = append(candidates, containerdCandidate{
				Socket:    sock,
				RunRoot:   filepath.Dir(sock),
				StateRoot: filepath.Dir(sock),
				Label:     "operator-extended candidate (" + containerdSocketCandidatesEnv + ")",
			})
		}
	}
	return candidates
}

// containerdCandidateHitFn is a test seam (mirrors sandboxIDForPodUIDFn) so unit tests can
// inject a fixed multi-socket fixture without a live dual-containerd node. Production
// implementation: containerdCandidateHit.
var containerdCandidateHitFn = containerdCandidateHit

// containerdCandidateHit probes exactly one candidate: does its socket exist on the host, and —
// if so — does it own a containerd sandbox for THIS agent's own pod UID? This is the identical
// query sandboxIDForPodUID already runs at restore time, run here against the candidate's own
// socket instead of the package-level containerdSocketPath (ADR-0370 Decision item 1 step 2),
// via the same nsenterCmd/broker exec-op delegation (ADR-0177/ADR-0234) — no new privilege
// surface, no new external binary dependency.
func containerdCandidateHit(ctx context.Context, socket, podUID string) (hit bool, detail string, err error) {
	exists, statErr := hostSocketExistsFn(ctx, socket)
	if statErr != nil {
		return false, fmt.Sprintf("socket existence probe error: %v", statErr), statErr
	}
	if !exists {
		return false, "socket path does not exist on host", nil
	}

	out, cerr := nsenterCmd(ctx, "/usr/local/bin/ctr", "--address", socket, "--namespace", "k8s.io",
		"containers", "list", "-q", "labels.\"io.kubernetes.pod.uid\"=="+podUID).Output()
	if cerr != nil {
		return false, fmt.Sprintf("ctr containers list error: %v", cerr), cerr
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) != "" {
			return true, "owns this agent's own pod sandbox", nil
		}
	}
	return false, "empty result (does not own this agent's own pod sandbox)", nil
}

// hostSocketExistsFn is a test seam. Production implementation: hostSocketExists.
var hostSocketExistsFn = hostSocketExists

// hostSocketExists reports whether path exists as a live Unix-domain socket file in the HOST
// mount namespace (via the broker-delegated `sh -c 'test -S ...'`, exactly the pattern
// resolveNetnsBindByProcPath already uses for a host-side stat). A non-zero exit (the normal
// "no" — the broker's execAllowlist allows bare "sh") is reported as (false, nil), not an error;
// discoverContainerdSocket records every non-hit candidate's detail verbatim in its fail-loud
// diagnostic regardless, so collapsing "absent" and "unreachable broker" here does not hide
// anything from that diagnostic.
func hostSocketExists(ctx context.Context, path string) (bool, error) {
	if err := nsenterCmd(ctx, "sh", "-c", fmt.Sprintf("test -S %q", path)).Run(); err != nil {
		return false, nil
	}
	return true, nil
}

// discoverContainerdSocketFn is a test seam (mirrors sandboxIDForPodUIDFn/joinNsRestoreFn) so
// tests can inject a fixed multi-socket fixture without a live dual-containerd node. Production
// implementation: discoverContainerdSocket.
var discoverContainerdSocketFn = discoverContainerdSocket

// discoverContainerdSocket is the ADR-0370 self-referential pod-sandbox-anchored socket
// discovery primitive. It empirically determines which containerd daemon owns THIS agent's own
// pod sandbox and returns that candidate's full (socket, runRoot, stateRoot) triple.
//
// Zero-tech-debt pillar (explicit requirement, no exceptions): every anomaly fails loud —
//   - explicit override set but doesn't own the agent's own sandbox: fail loud, do NOT fall
//     through to the built-in candidate list;
//   - zero candidates hit: fail loud, listing every candidate tried and why each failed;
//   - more than one candidate hits (ambiguous — cannot be a single source of truth): fail loud,
//     do not pick the first.
//
// Never silently guesses.
func discoverContainerdSocket(ctx context.Context, podUID string) (containerdCandidate, error) {
	if podUID == "" {
		return containerdCandidate{}, fmt.Errorf(
			"discoverContainerdSocket: %s is empty — cannot self-resolve without the agent's own pod UID (downward-API field missing from the DaemonSet spec?)", podUIDEnv)
	}

	candidates := buildContainerdCandidates()
	isOverride := os.Getenv("PODMOTION_CONTAINERD_SOCKET") != ""

	type attemptResult struct {
		candidate containerdCandidate
		hit       bool
		detail    string
	}
	attempts := make([]attemptResult, 0, len(candidates))
	var hits []containerdCandidate

	for _, c := range candidates {
		hit, detail, _ := containerdCandidateHitFn(ctx, c.Socket, podUID)
		attempts = append(attempts, attemptResult{candidate: c, hit: hit, detail: detail})
		if hit {
			hits = append(hits, c)
		}
	}

	if isOverride {
		if len(hits) == 1 {
			log.Info("discoverContainerdSocket (ADR-0370): operator override confirmed against ground truth",
				"socket", hits[0].Socket, "podUID", podUID)
			return hits[0], nil
		}
		return containerdCandidate{}, fmt.Errorf(
			"discoverContainerdSocket: PODMOTION_CONTAINERD_SOCKET=%s is set but does not own this agent's own pod sandbox (checked against ground truth POD_UID=%s and failed: %s) — refusing to silently fall through to the built-in candidate list",
			candidates[0].Socket, podUID, attempts[0].detail)
	}

	switch len(hits) {
	case 1:
		log.Info("discoverContainerdSocket (ADR-0370): resolved authoritative containerd socket",
			"socket", hits[0].Socket, "label", hits[0].Label, "podUID", podUID)
		return hits[0], nil
	case 0:
		var sb strings.Builder
		fmt.Fprintf(&sb, "discoverContainerdSocket: no candidate containerd socket owns this agent's own pod sandbox (POD_UID=%s) — refusing to start (zero-tech-debt pillar: never guess a default). Candidates tried:", podUID)
		for _, a := range attempts {
			fmt.Fprintf(&sb, "\n  - %s (%s): %s", a.candidate.Socket, a.candidate.Label, a.detail)
		}
		return containerdCandidate{}, errors.New(sb.String())
	default:
		var sb strings.Builder
		fmt.Fprintf(&sb, "discoverContainerdSocket: %d candidate containerd sockets ALL claim to own this agent's own pod sandbox (POD_UID=%s) — ambiguous, cannot establish a single source of truth (refusing to pick the first). Hits:", len(hits), podUID)
		for _, h := range hits {
			fmt.Fprintf(&sb, "\n  - %s (%s)", h.Socket, h.Label)
		}
		return containerdCandidate{}, errors.New(sb.String())
	}
}

var (
	containerdDiscoveryOnce sync.Once
	containerdDiscoveryErr  error
)

// CurrentContainerdSocketPath returns the process-lifetime containerdSocketPath value —
// the discovery winner's socket once EnsureContainerdDiscovered has succeeded, or the
// startup-time envOrDefault placeholder if called before discovery has run. Exported so
// cmd/agent/main.go can pass the resolved socket into CrossCheckNRISocketOwnership without
// exposing the underlying package var directly.
func CurrentContainerdSocketPath() string {
	return containerdSocketPath
}

// EnsureContainerdDiscovered runs the ADR-0370 discovery primitive exactly once per process and
// adopts the winning candidate into containerdSocketPath/containerdRunRoot/containerdStateRoot
// (containerd_paths.go) for the remainder of the agent's lifetime, replacing their blind
// envOrDefault-only initial values.
//
// The caller (cmd/agent/main.go) MUST call this — and it MUST succeed — before
// nmcregistrar.Register publishes NMC.status.Ready=true and before the gRPC server begins
// accepting Restore/Checkpoint/PrepareDestination RPCs. A node that cannot prove which
// containerd is authoritative must not advertise migration capacity.
func EnsureContainerdDiscovered(ctx context.Context, podUID string) error {
	containerdDiscoveryOnce.Do(func() {
		winner, err := discoverContainerdSocketFn(ctx, podUID)
		if err != nil {
			containerdDiscoveryErr = err
			return
		}
		containerdSocketPath = winner.Socket
		containerdRunRoot = winner.RunRoot
		containerdStateRoot = winner.StateRoot
		log.Info("EnsureContainerdDiscovered (ADR-0370): adopted authoritative containerd socket for process lifetime",
			"socket", winner.Socket, "runRoot", winner.RunRoot, "stateRoot", winner.StateRoot, "label", winner.Label)
	})
	return containerdDiscoveryErr
}

// ---------------------------------------------------------------------------------------------
// Secondary finding (ADR-0370 §"NRI socket collision"): minimum-bar cross-check.
//
// Both containerd daemons on a dual-containerd node can hold a listener at the identical fixed
// NRI socket path (/var/run/nri/nri.sock) — a Unix-domain-socket bind collision where whichever
// daemon (re)claimed the path most recently is the one any NRI client actually reaches. Full
// resolution (eliminating the collision) needs an infra-side containerd config change or a
// future protocol capability neither containerd nor NRI currently expose — explicitly NOT this
// ADR's code (tracked as a follow-up). What IS in scope: detect and loudly flag a mismatch
// between the NRI-socket-owning PID and the discovered-authoritative containerd's PID, without
// blocking agent startup on it (NRI stays an enhancement — internal/agent/nri/plugin.go already
// waits+retries on a missing/absent NRI socket).
// ---------------------------------------------------------------------------------------------

// defaultNRISocketPath mirrors internal/agent/nri/plugin.go's nriSocketPath const — the
// compiled default containerd's own config.toml is only consulted to override.
const defaultNRISocketPath = "/var/run/nri/nri.sock"

// containerdConfigPathFor returns the known, live-confirmed config.toml location for a
// recognized containerd candidate, or ("", false) for a candidate this ADR does not already
// know the config path for (operator-extended candidates via
// PODMOTION_CONTAINERD_SOCKET_CANDIDATES, or an operator override) — those fall back to the
// compiled default NRI socket path without attempting a config read.
func containerdConfigPathFor(socket string) (string, bool) {
	switch socket {
	case systemContainerdSocket:
		return "/etc/containerd/config.toml", true
	case rke2ContainerdSocket:
		return "/var/lib/rancher/rke2/agent/etc/containerd/config.toml", true
	default:
		return "", false
	}
}

// resolveNRISocketPathFn is a test seam. Production implementation: resolveNRISocketPath.
var resolveNRISocketPathFn = resolveNRISocketPath

// resolveNRISocketPath reads the winning containerd daemon's OWN config.toml for
// `[plugins."io.containerd.nri.v1.nri"].socket_path`, the same config-driven approach used to
// resolve containerdRunRoot/containerdStateRoot for the winning daemon (ADR-0370 Decision item
// 4). Falls back to the compiled default when the winning daemon's config does not override it,
// the config file cannot be read (e.g. an operator-extended candidate this ADR has no known
// config path for), or no socket_path key is present under that section — every one of those is
// a legitimate "no override" outcome, not a failure.
func resolveNRISocketPath(ctx context.Context, winnerSocket string) string {
	cfgPath, known := containerdConfigPathFor(winnerSocket)
	if !known {
		return defaultNRISocketPath
	}
	out, err := nsenterCmd(ctx, "cat", cfgPath).Output()
	if err != nil {
		// Config unreadable (absent, permission) — not an error worth failing loud over; NRI
		// stays best-effort and the compiled default is the correct fallback.
		return defaultNRISocketPath
	}
	if p := nriSocketPathFromConfig(string(out)); p != "" {
		return p
	}
	return defaultNRISocketPath
}

// nriSocketPathFromConfig extracts `socket_path = "..."` from inside the
// `[plugins."io.containerd.nri.v1.nri"]` TOML table, ignoring keys from any other table. Returns
// "" if the table or key is absent. Deliberately not a general TOML parser — this only needs to
// answer one narrow question about one known section, matching the ADR's own narrow grounding
// claim about this key.
func nriSocketPathFromConfig(cfg string) string {
	const section = `[plugins."io.containerd.nri.v1.nri"]`
	lines := strings.Split(cfg, "\n")
	inSection := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = line == section
			continue
		}
		if !inSection {
			continue
		}
		if !strings.HasPrefix(line, "socket_path") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)
		if val != "" {
			return val
		}
	}
	return ""
}

// ---------------------------------------------------------------------------------------------
// ADR-0417 Condition 2: containerd CRI sandbox directory resolution.
//
// The CRI plugin — NOT the kubelet — is the writer of a pod's /etc/hostname and /etc/resolv.conf.
// It stages them as regular files in its own PERSISTENT sandbox dir,
// <containerd root>/io.containerd.grpc.v1.cri/sandboxes/<sandboxID>/, and bind-mounts them into
// each workload container. §P-PREMISE decode of a real mountpoints-13.img taken off this project's
// standing cluster (pm-w2, RKE2 v1.35.6+rke2r1, postgres workload) records exactly that:
//
//	/etc/hostname     root=/var/lib/rancher/rke2/agent/containerd/io.containerd.grpc.v1.cri/
//	                       sandboxes/590a5b28.../hostname   source=/dev/vda1  fstype=0
//	/etc/resolv.conf  root=<same sandbox dir>/resolv.conf   source=/dev/vda1  fstype=0
//	/etc/hosts        root=/var/lib/kubelet/pods/<podUID>/etc-hosts  source=/dev/vda1  fstype=0
//
// and `ls -A /var/lib/kubelet/pods/<uid>` on that node returns exactly
// `containers etc-hosts plugins volumes` — there is no etc-hostname and no resolv.conf under the
// kubelet pod dir at all. Two different writers, two different directories.
//
// The containerd ROOT dir is NOT containerdRunRoot or containerdStateRoot: on RKE2 those are both
// /run/k3s/containerd (the `state` dir), while the CRI sandbox dir lives under the `root` dir
// /var/lib/rancher/rke2/agent/containerd. It is read from the authoritative source — the winning
// containerd daemon's OWN config.toml, the identical config file resolveNRISocketPath already reads
// for the same daemon — never guessed.
// ---------------------------------------------------------------------------------------------

// defaultContainerdRootDir is containerd's documented default `root` when its config.toml does not
// set one. Used ONLY when the winning daemon's config was read successfully and simply carries no
// top-level `root` key; an unreadable config or an unrecognized socket resolves to "" (fail closed).
const defaultContainerdRootDir = "/var/lib/containerd"

// criSandboxDirRel is the CRI plugin's sandbox subtree, relative to the containerd root dir.
const criSandboxDirRel = "io.containerd.grpc.v1.cri/sandboxes"

// containerdRootFromConfig extracts the TOP-LEVEL `root = "..."` key from a containerd config.toml.
// Top-level means: before the first `[table]` header — a `root` key inside e.g. `[plugins...]` is a
// different, unrelated key and must not be mistaken for it (RKE2's generated config has exactly
// that shape). Returns "" when absent.
func containerdRootFromConfig(cfg string) string {
	for _, raw := range strings.Split(cfg, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			// First table header ends the top-level key space.
			return ""
		}
		if !strings.HasPrefix(line, "root") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != "root" {
			continue
		}
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if val != "" {
			return val
		}
	}
	return ""
}

// resolveContainerdRootDirFn is a test seam. Production implementation: resolveContainerdRootDir.
var resolveContainerdRootDirFn = resolveContainerdRootDir

// resolveContainerdRootDir returns the winning containerd daemon's `root` directory, read from that
// daemon's own config.toml. Returns "" when the socket is one this package has no known config path
// for (an operator override or an operator-extended candidate) or the config cannot be read — the
// caller must then fail closed rather than substitute a guess.
func resolveContainerdRootDir(ctx context.Context, winnerSocket string) string {
	cfgPath, known := containerdConfigPathFor(winnerSocket)
	if !known {
		return ""
	}
	out, err := nsenterCmd(ctx, "cat", cfgPath).Output()
	if err != nil {
		return ""
	}
	if r := containerdRootFromConfig(string(out)); r != "" {
		return r
	}
	return defaultContainerdRootDir
}

// ADR-0419 D6 item 4: containerdCRISandboxDir is DELETED. It existed only to RECONSTRUCT
// <containerd root>/io.containerd.grpc.v1.cri/sandboxes/<id> so a destination file could be probed
// inside it — and ADR-0419 never reconstructs that path: the runtime hands us the resolved Source
// directly. (As a side effect this moots the origin synthesis' unresolved root-vs-state-dir
// question entirely; the live mount lists confirm the sandbox files do sit under the `root` dir,
// but nothing in this codebase depends on that being true any more.)
//
// ITS TWO DEPENDENCIES ARE DELIBERATELY RETAINED — deleting them alongside it is the specific
// asymmetric-removal error this note exists to prevent. resolveContainerdRootDirFn and
// criSandboxDirRel EACH have an independent surviving consumer in
// allowedExtMountHostTargetPrefixes (server.go), which needs the containerd root to authorize
// sandbox-dir prefixes for --ext-mount-map token validation. That need is unrelated to destination
// target RESOLUTION and outlives this ADR.

// pidOwningUnixSocketFn is a test seam. Production implementation: pidOwningUnixSocket.
var pidOwningUnixSocketFn = pidOwningUnixSocket

// pidOwningUnixSocket resolves the host PID currently holding a listener at a Unix-domain
// socket path, via the same class of technique (`/proc/net/unix` inode lookup + `/proc/*/fd`
// scan by inode) this ADR's authors used manually, live, this session — run through the existing
// broker exec-op delegation (ADR-0231/ADR-0234), no new privilege surface. Returns (0, false,
// nil) when the socket has no live listener (not an error — e.g. NRI genuinely not configured).
func pidOwningUnixSocket(ctx context.Context, path string) (pid int, found bool, err error) {
	// (1) Look up the socket's kernel inode from /proc/net/unix by matching the path field
	//     (last whitespace-separated column). (2) Scan every /proc/<pid>/fd/* symlink for
	//     "socket:[<inode>]" and report the owning PID. Both steps run in ONE `sh -c` (the
	//     broker's execAllowlist permits "sh" but not a bare "awk"/"readlink"; the shell invokes
	//     the node's real awk/readlink), mirroring resolveNetnsBindByProcPath's established
	//     single-shell-invocation pattern for a host-mount-ns inode scan.
	script := fmt.Sprintf(
		`inode=$(awk -v p=%q '$NF==p{print $7}' /proc/net/unix | head -n1); `+
			`[ -z "$inode" ] && exit 0; `+
			`for fd in /proc/[0-9]*/fd/*; do `+
			`ln=$(readlink "$fd" 2>/dev/null) || continue; `+
			`if [ "$ln" = "socket:[$inode]" ]; then echo "$fd" | cut -d/ -f3; exit 0; fi; `+
			`done`,
		path)
	out, cerr := nsenterCmd(ctx, "sh", "-c", script).Output()
	if cerr != nil {
		return 0, false, fmt.Errorf("pidOwningUnixSocket %s: %w", path, cerr)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return 0, false, nil
	}
	var p int
	if _, serr := fmt.Sscanf(trimmed, "%d", &p); serr != nil || p <= 0 {
		return 0, false, fmt.Errorf("pidOwningUnixSocket %s: unparseable pid output %q", path, trimmed)
	}
	return p, true, nil
}

// CrossCheckNRISocketOwnership is the ADR-0370 Decision item 4 minimum-bar NRI check. Called
// once, best-effort, after EnsureContainerdDiscovered succeeds. It resolves the winning
// containerd daemon's own NRI socket_path (config-driven, falling back to the compiled default)
// and cross-checks whether the PID currently holding a listener there is the SAME PID as the
// winning containerd daemon (found by the identical socket-inode-to-PID technique applied to the
// winning containerd's own control socket). A mismatch or an unattributable socket logs CRITICAL
// and increments metrics.NRISocketOwnershipMismatchTotal — it does NOT block agent startup or
// return an error the caller must act on: NRI is explicitly documented
// (internal/agent/nri/plugin.go) as an enhancement with its own retry/backoff, and the gRPC
// Restore fallback ADR-0370 fixes is fully correct and fail-closed on its own regardless of NRI
// health.
func CrossCheckNRISocketOwnership(ctx context.Context, winnerSocket string) {
	nriPath := resolveNRISocketPathFn(ctx, winnerSocket)

	nriPID, nriFound, nriErr := pidOwningUnixSocketFn(ctx, nriPath)
	if nriErr != nil || !nriFound {
		// No live NRI listener yet (or an unreadable /proc scan) — not evidence of a collision;
		// internal/agent/nri/plugin.go already tolerates and retries an absent NRI socket. Only
		// log at Info, no metric.
		log.Info("CrossCheckNRISocketOwnership (ADR-0370): NRI socket not attributable to a live PID yet — skipping cross-check",
			"nriSocketPath", nriPath, "err", nriErr)
		return
	}

	containerdPID, cdFound, cdErr := pidOwningUnixSocketFn(ctx, winnerSocket)
	if cdErr != nil || !cdFound {
		log.Info("CrossCheckNRISocketOwnership (ADR-0370): winning containerd socket not attributable to a live PID — skipping cross-check",
			"containerdSocket", winnerSocket, "err", cdErr)
		return
	}

	if nriPID != containerdPID {
		log.Error(fmt.Errorf("NRI socket %s is owned by pid %d but the discovered-authoritative containerd (%s) is pid %d",
			nriPath, nriPID, winnerSocket, containerdPID),
			"CRITICAL (ADR-0370): NRI socket ownership does NOT match the discovered-authoritative containerd — the NRI plugin is likely registered against the wrong daemon and will never see real pod lifecycle events; NOT blocking startup (NRI is an enhancement, the gRPC Restore fallback is fail-closed on its own)",
			"nriSocketPath", nriPath, "nriOwnerPID", nriPID, "containerdSocket", winnerSocket, "containerdPID", containerdPID)
		metrics.NRISocketOwnershipMismatchTotal.WithLabelValues("pid_mismatch").Inc()
		return
	}

	log.Info("CrossCheckNRISocketOwnership (ADR-0370): NRI socket ownership matches the discovered-authoritative containerd",
		"nriSocketPath", nriPath, "pid", nriPID)
}
