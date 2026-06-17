// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

// Package netnsbroker implements the SD-1-NETNS-BROKER privileged sidecar
// (ADR-0148 Amendment SD-1-NETNS-BROKER) and its in-process client.
//
// The broker is the SOLE container in the agent pod that runs privileged:true.
// It exposes exactly two operations over a root-owned Unix domain socket
// (mode 0600): create a per-migration netns bind-mount in the HOST mount
// namespace, and tear one down. The bind-mount privilege (CAP_SYS_ADMIN /
// host-mount-ns mount/umount2) is irreducible — CRIU must open the netns path
// from the host mount namespace via --join-ns net:<path>. SD-1 moves that
// irreducible privilege out of the long-lived, broad-surface main agent and
// into this narrow-surface sidecar that does ONLY these two mount operations
// and speaks no gRPC.
//
// Host-mount-ns entry mechanism (ADR-0148 Amendment SD-1-NETNS-BROKER, revised):
// the bind/umount that must be visible host-wide is performed by an nsenter
// subprocess (`nsenter --mount=/proc/1/ns/mnt -- <op>`), NOT by an in-process
// unix.Setns(CLONE_NEWNS). The Linux kernel forbids setns(CLONE_NEWNS) from a
// multithreaded process (EINVAL), and the Go runtime is irreducibly
// multithreaded — runtime.LockOSThread pins a goroutine to a thread but does
// NOT make the process single-threaded, so the kernel's "is this process
// multithreaded?" check (more than one task sharing the mm/files) still trips.
// privileged:true gives the broker CAP_SYS_ADMIN in the host init userns so
// ns_capable() passes, but that does not lift the multithreaded restriction.
// A forked nsenter is single-threaded at the moment it calls setns, so it
// succeeds. This is the same nsenter chain migrationnetns.go used before the
// SD-1 broker refactor; SD-1 keeps that mechanism and relocates the privilege
// into the sidecar. The fresh-netns UNSHARE for the srcPID=0 destination-prewarm
// path is still done in-process on a locked OS thread — unshare(CLONE_NEWNET) is
// NOT subject to the multithreaded restriction; only setns(CLONE_NEWNS) is.
//
// SC-1 (Security Reviewer condition): socket mode 0600 authenticates the
// filesystem caller, NOT the request. Every op therefore validates
// migrationUID (non-empty, syntactically a migration token) and, on create,
// srcPID (a live, in-migration PID when supplied). The broker never accepts an
// arbitrary host path from the client — it computes the target path itself
// from migrationUID, so a compromised main agent cannot direct the privileged
// sidecar to bind-mount over an arbitrary host location.
package netnsbroker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// SocketPath is the broker's listening Unix domain socket. Created mode 0600,
	// owned root:root. The main agent dials this; no other client is authorized.
	SocketPath = "/run/podmotion/netns-broker.sock"

	// NetnsBaseDir is the base directory under which per-migration netns bind
	// mounts are created (one subdir per migrationUID). Lives on the rshared
	// /run/podmotion mount so the bind propagates host<->container.
	NetnsBaseDir = "/run/podmotion/netns"

	// hostMountNs is the host init mount-namespace handle. The agent pod runs
	// hostPID:true, so /proc/1 resolves to the host init process and
	// /proc/1/ns/mnt is the host mount namespace. nsenter --mount=<this> runs a
	// subprocess in that namespace so the bind-mount is visible host-wide (CRIU
	// runs there). We use the path form (`--mount=/proc/1/ns/mnt`) rather than an
	// fd because nsenter resolves it itself in a single-threaded child.
	hostMountNs = "/proc/1/ns/mnt"

	// hostMountNsArg is the nsenter flag selecting the host init mount namespace.
	hostMountNsArg = "--mount=" + hostMountNs

	// hostMountInfo is host init's mountinfo, visible because the agent pod runs
	// hostPID:true. Idempotency (is the bind already a live nsfs mount?) reads
	// this — it reflects the HOST mount namespace, where the broker's nsenter
	// binds land. /proc/self/mountinfo would show only the container's view.
	hostMountInfo = "/proc/1/mountinfo"
)

// migrationUIDRe constrains migrationUID to the safe token set used by the
// PodMigration controller (UIDs, names: alphanumerics, hyphen). This is SC-1's
// syntactic gate — it forbids path-traversal (`.`, `/`) and shell metacharacters
// so the broker-computed target path cannot escape NetnsBaseDir.
var migrationUIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)

// Request is the JSON wire request accepted on the broker socket.
type Request struct {
	Op string `json:"op"` // "create" | "teardown"
	// MigrationUID names the per-migration netns dir. Validated by migrationUIDRe.
	MigrationUID string `json:"migrationUID"`
	// SrcPID, when > 0 on a create, selects /proc/<srcPID>/ns/net as the netns to
	// bind (the pod-in-migration's netns). When 0, the broker unshares a FRESH
	// network namespace on a locked thread and binds that — the destination-prewarm
	// behavior PrepareDestinationNetns relied on (createBindMountedNetns).
	SrcPID int `json:"srcPID,omitempty"`
}

// Response is the JSON wire response. Error is "" on success.
type Response struct {
	// Path is the bind-mount path on success (create only). Empty on teardown.
	Path string `json:"path,omitempty"`
	// Error is a human-readable error string, or "" on success. JSON null<->"".
	Error string `json:"error,omitempty"`
}

// netnsPathFor returns the broker-computed bind target for a migrationUID.
// SC-1: the client never supplies a path; it is derived here from the
// validated UID, so a compromised caller cannot mount over an arbitrary host path.
func netnsPathFor(migrationUID string) string {
	return filepath.Join(NetnsBaseDir, migrationUID, "bind")
}

// validateUID enforces SC-1's request authentication for migrationUID.
func validateUID(migrationUID string) error {
	if migrationUID == "" {
		return fmt.Errorf("migrationUID is required")
	}
	if !migrationUIDRe.MatchString(migrationUID) {
		return fmt.Errorf("migrationUID %q is not a valid migration token", migrationUID)
	}
	return nil
}

// validateSrcPID enforces SC-1's request authentication for srcPID on create.
// A srcPID of 0 means "unshare a fresh netns" (destination-prewarm path) and is
// allowed. A positive srcPID must reference a live process whose net namespace
// is openable — the pod-in-migration. The broker does not attempt to prove the
// PID is "owned by a live node-owned migration" beyond liveness here; the
// controller already gates which migrations reach this RPC and the socket is
// root-only. Liveness rejects a stale/dead PID whose number may have been reused
// for an unrelated process before the bind would capture the wrong netns.
func validateSrcPID(srcPID int) error {
	if srcPID < 0 {
		return fmt.Errorf("srcPID %d is negative", srcPID)
	}
	if srcPID == 0 {
		return nil // fresh-unshare path
	}
	nsPath := fmt.Sprintf("/proc/%d/ns/net", srcPID)
	if _, err := os.Stat(nsPath); err != nil {
		return fmt.Errorf("srcPID %d netns not accessible (process not live?): %w", srcPID, err)
	}
	return nil
}

// Handle dispatches a single decoded Request and returns its Response. It is the
// pure-logic core, exported for unit testing without a live socket.
func Handle(req Request) Response {
	switch req.Op {
	case "create":
		path, err := doCreate(req.MigrationUID, req.SrcPID)
		return toResponse(path, err)
	case "teardown":
		err := doTeardown(req.MigrationUID)
		return toResponse("", err)
	default:
		return toResponse("", fmt.Errorf("unknown op %q (want create|teardown)", req.Op))
	}
}

func toResponse(path string, err error) Response {
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{Path: path}
}

// doCreate creates /run/podmotion/netns/<uid>/ and bind-mounts the selected
// netns to .../<uid>/bind in the HOST mount namespace, returning the bind path.
//
// All host-mount-ns mutations (mkdir, touch, bind) are performed by nsenter
// subprocesses entering /proc/1/ns/mnt — single-threaded children that may call
// setns(CLONE_NEWNS), which an in-process multithreaded Go goroutine may not.
//
// Idempotent: if the bind path is already an nsfs mount, it is returned as-is.
func doCreate(migrationUID string, srcPID int) (string, error) {
	if err := validateUID(migrationUID); err != nil {
		return "", err
	}
	if err := validateSrcPID(srcPID); err != nil {
		return "", err
	}

	bindPath := netnsPathFor(migrationUID)
	dir := filepath.Dir(bindPath)

	// Idempotency fast-path: if the bind target is already a live nsfs mount in the
	// HOST mount namespace, the netns is already prepared — reuse it. Reads host
	// init's mountinfo (hostPID:true), which reflects the namespace nsenter binds into.
	if isNsfsMounted(bindPath) {
		return bindPath, nil
	}

	// Create the per-migration dir + bind target file in the HOST mount namespace.
	// These must exist host-side for the subsequent host-ns bind; os.MkdirAll here
	// would create them only in the broker container's private mount namespace, so
	// we create them via nsenter in the host mount namespace (matches the prior
	// createBindMountedNetns mkdir/touch chain).
	if out, err := nsenterHostMnt("mkdir", "-p", dir).CombinedOutput(); err != nil {
		return "", fmt.Errorf("mkdir %s in host mount ns: %w\n%s", dir, err, out)
	}
	if out, err := nsenterHostMnt("sh", "-c",
		fmt.Sprintf("[ -e %q ] || touch %q", bindPath, bindPath),
	).CombinedOutput(); err != nil {
		return "", fmt.Errorf("create bind target %s in host mount ns: %w\n%s", bindPath, err, out)
	}

	if srcPID > 0 {
		// Bind an EXISTING pod netns: /proc/<srcPID>/ns/net -> bindPath, in host mount ns.
		srcNs := fmt.Sprintf("/proc/%d/ns/net", srcPID)
		if err := bindInHostMountNs(srcNs, bindPath); err != nil {
			return "", fmt.Errorf("bind srcPID %d netns: %w", srcPID, err)
		}
		return bindPath, nil
	}

	// Fresh-unshare path (destination prewarm): on a locked OS thread, unshare a
	// new network namespace and bind THAT thread's /proc/<tid>/ns/net into the
	// host mount namespace. Mirrors the prior createBindMountedNetns goroutine.
	if err := unshareAndBind(bindPath); err != nil {
		return "", err
	}
	return bindPath, nil
}

// doTeardown unmounts and removes /run/podmotion/netns/<uid>/. "Not mounted" /
// absent is treated as success (idempotent). The unmount and removals run in the
// HOST mount namespace via nsenter because the bind-mount and bind-target file
// were created there by doCreate.
func doTeardown(migrationUID string) error {
	if err := validateUID(migrationUID); err != nil {
		return err
	}
	bindPath := netnsPathFor(migrationUID)
	dir := filepath.Dir(bindPath)

	// Lazy detach unmount in the host mount namespace — tolerate "not mounted".
	if out, err := nsenterHostMnt("umount", "-l", bindPath).CombinedOutput(); err != nil {
		if !isNotMountedOutput(out) {
			return fmt.Errorf("unmount %s in host mount ns: %w\n%s", bindPath, err, out)
		}
	}
	// Remove the bind-target file in the host mount namespace.
	if out, err := nsenterHostMnt("rm", "-f", bindPath).CombinedOutput(); err != nil {
		return fmt.Errorf("remove %s in host mount ns: %w\n%s", bindPath, err, out)
	}
	// Remove the now-empty per-migration dir in the host mount namespace.
	// `rmdir` on a non-empty dir is non-fatal (idempotent teardown).
	if out, err := nsenterHostMnt("rmdir", dir).CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "not empty") &&
			!strings.Contains(string(out), "No such file") {
			return fmt.Errorf("remove dir %s in host mount ns: %w\n%s", dir, err, out)
		}
	}
	return nil
}

// unshareAndBind runs on a dedicated locked OS thread: it saves the current
// netns, unshares CLONE_NEWNET (creating a fresh netns on this thread), binds
// the thread's netns into the host mount namespace via nsenter, then restores.
// The thread is intentionally NOT unlocked so the Go runtime recycles it rather
// than returning a thread with a swapped netns to the pool.
//
// NOTE: unshare(CLONE_NEWNET) is performed in-process here on purpose — it is
// NOT subject to the multithreaded-process restriction that forbids in-process
// setns(CLONE_NEWNS). Only the host-mount-ns BIND is delegated to nsenter.
func unshareAndBind(bindPath string) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// not unlocked on purpose — see doc comment.

		origNS, err := os.Open("/proc/self/ns/net")
		if err != nil {
			done <- fmt.Errorf("open current netns: %w", err)
			return
		}
		defer origNS.Close()

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("unshare CLONE_NEWNET: %w", err)
			return
		}

		tid := unix.Gettid()
		threadNetns := fmt.Sprintf("/proc/%d/ns/net", tid)

		if err := bindInHostMountNs(threadNetns, bindPath); err != nil {
			_ = unix.Setns(int(origNS.Fd()), unix.CLONE_NEWNET)
			done <- err
			return
		}

		if err := unix.Setns(int(origNS.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("restore original netns: %w", err)
			return
		}
		done <- nil
	}()
	return <-done
}

// bindInHostMountNs performs `mount --bind src target` inside the HOST mount
// namespace via an nsenter subprocess (`nsenter --mount=/proc/1/ns/mnt -- mount
// --bind src target`). nsenter forks a single-threaded child that may legally
// call setns(CLONE_NEWNS) — an in-process Go goroutine may not (EINVAL from a
// multithreaded process even under privileged:true / CAP_SYS_ADMIN).
//
// IMPORTANT: the src path (e.g. /proc/<tid>/ns/net) is resolved by nsenter's
// child AFTER it has joined the host mount namespace. /proc is the same procfs
// across the host mount ns on a hostPID:true pod, so /proc/<tid>/ns/net and
// /proc/<srcPID>/ns/net resolve to the intended netns from the host mount ns.
func bindInHostMountNs(src, target string) error {
	if out, err := nsenterHostMnt("mount", "--bind", src, target).CombinedOutput(); err != nil {
		return fmt.Errorf("bind mount %s -> %s in host mount ns: %w\n%s", src, target, err, out)
	}
	return nil
}

// nsenterHostMnt builds an *exec.Cmd that runs `nsenter --mount=/proc/1/ns/mnt --
// <args...>` — the command executes in the HOST mount namespace as a fresh
// single-threaded process. This is the syscall-free replacement for the prior
// in-process unix.Setns(CLONE_NEWNS) host-mount-ns entry, which returns EINVAL
// from the multithreaded Go runtime regardless of CAP_SYS_ADMIN.
func nsenterHostMnt(args ...string) *exec.Cmd {
	full := append([]string{hostMountNsArg, "--"}, args...)
	return exec.Command("nsenter", full...)
}

// isNotMountedOutput reports whether umount's stderr indicates the target was
// not a mount point (idempotent teardown success). umount(8) phrasing varies by
// util-linux version: "not mounted", "not currently mounted", "not found".
func isNotMountedOutput(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "not mounted") ||
		strings.Contains(s, "not currently mounted") ||
		strings.Contains(s, "not found") ||
		strings.Contains(s, "No such file")
}

// isNsfsMounted reports whether path is a live nsfs (network-namespace) bind
// mount in the HOST mount namespace. Reads /proc/1/mountinfo (host init's
// mountinfo, visible with hostPID:true) so the binds nsenter creates in the host
// mount namespace are visible — the broker container's own /proc/self/mountinfo
// would not show them.
func isNsfsMounted(path string) bool {
	data, err := os.ReadFile(hostMountInfo)
	if err != nil {
		// Fall back to self mountinfo if host mountinfo is inaccessible.
		data, err = os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			return false
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[4] != path {
			continue
		}
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep >= 0 && sep+1 < len(fields) && fields[sep+1] == "nsfs" {
			return true
		}
	}
	return false
}

// decode/encode helpers shared by the listener.

func decodeRequest(b []byte) (Request, error) {
	var req Request
	if err := json.Unmarshal(b, &req); err != nil {
		return Request{}, err
	}
	return req, nil
}

func encodeResponse(resp Response) ([]byte, error) {
	return json.Marshal(resp)
}
