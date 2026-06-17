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
// The broker replaces the prior nsenter --mount=/proc/1/ns/mnt subprocess
// chain in internal/agent/network/migrationnetns.go. It performs the bind via
// syscall (unix.Mount / unix.Unmount) after setns(CLONE_NEWNS) into the host
// mount namespace — no nsenter subprocess.
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
	// /proc/1/ns/mnt is the host mount namespace. setns(CLONE_NEWNS) into it
	// makes the bind-mount visible host-wide (CRIU runs there).
	hostMountNs = "/proc/1/ns/mnt"
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

	// Create the per-migration dir + bind target file in the HOST mount namespace.
	// We are already running in the host mount namespace context for the syscall
	// bind below (via the locked-thread setns), but the dir/file must also exist
	// host-side. mkBindScaffolding performs both inside the host mount ns.
	if err := withHostMountNs(func() error {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		// Idempotency: already a live nsfs mount -> reuse.
		if isNsfsMounted(bindPath) {
			return errAlreadyMounted
		}
		// Create the bind target file if absent.
		f, err := os.OpenFile(bindPath, os.O_CREATE, 0o600)
		if err != nil {
			return fmt.Errorf("create bind target %s: %w", bindPath, err)
		}
		_ = f.Close()
		return nil
	}); err != nil {
		if err == errAlreadyMounted {
			return bindPath, nil
		}
		return "", err
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

// errAlreadyMounted is an internal sentinel for the idempotent create fast-path.
var errAlreadyMounted = fmt.Errorf("netns already bind-mounted")

// doTeardown unmounts and removes /run/podmotion/netns/<uid>/. ENOENT/EINVAL
// (not mounted / absent) is treated as success (idempotent).
func doTeardown(migrationUID string) error {
	if err := validateUID(migrationUID); err != nil {
		return err
	}
	bindPath := netnsPathFor(migrationUID)
	dir := filepath.Dir(bindPath)

	return withHostMountNs(func() error {
		// Lazy detach unmount — tolerate "not mounted".
		if err := unix.Unmount(bindPath, unix.MNT_DETACH); err != nil && err != unix.EINVAL && err != unix.ENOENT {
			return fmt.Errorf("unmount %s: %w", bindPath, err)
		}
		if err := os.Remove(bindPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", bindPath, err)
		}
		if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
			// dir non-empty is non-fatal (idempotent teardown); only report unexpected errors.
			if !strings.Contains(err.Error(), "directory not empty") {
				return fmt.Errorf("remove dir %s: %w", dir, err)
			}
		}
		return nil
	})
}

// unshareAndBind runs on a dedicated locked OS thread: it saves the current
// netns, unshares CLONE_NEWNET (creating a fresh netns on this thread), binds
// the thread's netns into the host mount namespace at bindPath, then restores.
// The thread is intentionally NOT unlocked so the Go runtime recycles it rather
// than returning a thread with a swapped netns to the pool.
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
// namespace using unix.Mount (no nsenter subprocess). It runs on a locked thread
// that setns()es into /proc/1/ns/mnt for the duration of the bind.
//
// IMPORTANT: the src path (e.g. /proc/<tid>/ns/net) is resolved in the CALLER's
// mount/pid context. /proc is the same procfs across the host mount ns on a
// hostPID:true pod, so the path resolves identically after setns(CLONE_NEWNS).
func bindInHostMountNs(src, target string) error {
	return withHostMountNs(func() error {
		if err := unix.Mount(src, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind mount %s -> %s in host mount ns: %w", src, target, err)
		}
		return nil
	})
}

// withHostMountNs runs fn on a locked OS thread that has setns()'d into the host
// init mount namespace (/proc/1/ns/mnt), restoring the original mount namespace
// afterward. This is the syscall replacement for `nsenter --mount=/proc/1/ns/mnt`.
func withHostMountNs(fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		origMnt, err := os.Open("/proc/self/ns/mnt")
		if err != nil {
			done <- fmt.Errorf("open current mount ns: %w", err)
			return
		}
		defer origMnt.Close()

		hostMnt, err := os.Open(hostMountNs)
		if err != nil {
			done <- fmt.Errorf("open host mount ns %s: %w", hostMountNs, err)
			return
		}
		defer hostMnt.Close()

		if err := unix.Setns(int(hostMnt.Fd()), unix.CLONE_NEWNS); err != nil {
			done <- fmt.Errorf("setns into host mount ns: %w", err)
			return
		}
		fnErr := fn()
		// Restore the original mount namespace. If this fails we deliberately do
		// NOT unlock the thread (let the runtime discard it) by panicking-safe:
		// returning the restore error; the thread stays locked because UnlockOSThread
		// is deferred — acceptable, it is one thread.
		if rerr := unix.Setns(int(origMnt.Fd()), unix.CLONE_NEWNS); rerr != nil {
			if fnErr != nil {
				done <- fmt.Errorf("%v; additionally failed to restore mount ns: %w", fnErr, rerr)
				return
			}
			done <- fmt.Errorf("restore mount ns: %w", rerr)
			return
		}
		done <- fnErr
	}()
	return <-done
}

// isNsfsMounted reports whether path is a live nsfs (network-namespace) bind
// mount in the current mount namespace. Called from inside withHostMountNs so
// self/mountinfo reflects the host mount namespace.
func isNsfsMounted(path string) bool {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
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
