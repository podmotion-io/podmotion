// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package netnsbroker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Run injects log into ctx and runs Serve. It is the entrypoint shared by the
// standalone cmd/netns-broker binary and the `agent netns-broker` subcommand,
// so both produce identically-structured logs without each having to wire the
// controller-runtime global logger.
func Run(ctx context.Context, log logr.Logger) error {
	return Serve(logf.IntoContext(ctx, log))
}

// Serve runs the broker: it listens on SocketPath (mode 0600, root:root) and
// serves one JSON Request / one JSON Response per connection until ctx is done.
// This is the entrypoint for both the standalone cmd/netns-broker binary and the
// `agent netns-broker` subcommand — the same code, same image, different invocation.
func Serve(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("netns-broker")

	// ADR-0347 A1 / SR-DEP: resolve the outer-program pins ONCE at startup, before
	// any op is served, so PATH is consulted from the trusted startup environment
	// and never re-asked per call. nsenter is required by EVERY op (host-mount-ns
	// bind/teardown, the `exec` set, and the CRIU-restore wrapper launch via
	// exec_start) — a broker that cannot resolve nsenter cannot do its irreducible
	// job, so fail loud. ip is used ONLY by the reachability/IP-config ops
	// (resolve_veth, netns_exec* with argv[0]=="ip"), which fail CLOSED on an
	// unresolvable ip (ADR-0348 D4) at the point of use — so an absent ip must NOT
	// crash-loop the broker and take the ip-free restore/teardown/rollback path
	// (including the ADR-0012 source-survival rollback) down with it. Pin ip
	// best-effort here; the ip sites hard-fail-closed if it never resolves. No
	// silent bare-name fallback ever occurs (ADR-0347 A1's security property is
	// preserved — the fail-closed point moves from startup crash-loop to use).
	if err := resolvePinnedNsenter(); err != nil {
		return fmt.Errorf("netns-broker: %w", err)
	}
	if err := resolvePinnedIP(); err != nil {
		log.Error(err, "netns-broker: ip not resolvable at startup — resolve_veth and netns_exec ip ops will fail closed until ip is present; the nsenter-only host-mount-ns bind/teardown and CRIU-restore path is unaffected")
	}

	// Ensure the socket parent dir exists (host-shared /run/podmotion).
	if err := os.MkdirAll(filepath.Dir(SocketPath), 0o700); err != nil {
		return fmt.Errorf("netns-broker: mkdir %s: %w", filepath.Dir(SocketPath), err)
	}
	// Remove a stale socket from a prior crashed instance so Listen does not EADDRINUSE.
	if err := os.Remove(SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("netns-broker: remove stale socket %s: %w", SocketPath, err)
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", SocketPath)
	if err != nil {
		return fmt.Errorf("netns-broker: listen %s: %w", SocketPath, err)
	}
	defer ln.Close()

	// SC-1: socket mode 0600 root:root. The process runs as root (privileged
	// sidecar), so the socket is created root-owned; tighten the mode explicitly.
	if err := os.Chmod(SocketPath, 0o600); err != nil {
		return fmt.Errorf("netns-broker: chmod 0600 %s: %w", SocketPath, err)
	}

	log.Info("netns-broker listening", "socket", SocketPath, "mode", "0600")

	// Close the listener when the context is cancelled so Accept unblocks.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				log.Info("netns-broker shutting down")
				return nil
			default:
				log.Error(err, "accept failed")
				continue
			}
		}
		// Handle inline (operations are short, infrequent, and mutate global host
		// mount state — serializing them avoids two concurrent binds racing the
		// same migrationUID dir). One request/response per connection.
		serveConn(ctx, conn)
	}
}

func serveConn(ctx context.Context, conn net.Conn) {
	log := logf.FromContext(ctx).WithName("netns-broker")
	defer conn.Close()

	r := bufio.NewReader(conn)
	line, err := r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		log.Error(err, "read request")
		return
	}
	req, err := decodeRequest(line)
	if err != nil {
		writeResp(conn, Response{Error: fmt.Sprintf("decode request: %v", err)})
		return
	}
	// ADR-0231: exec carries no migrationUID/srcPID; log argv[0] for that op instead.
	var execArgv0 string
	if req.Op == "exec" && len(req.Argv) > 0 {
		execArgv0 = req.Argv[0]
	}
	log.Info("netns-broker op", "op", req.Op, "migrationUID", req.MigrationUID, "srcPID", req.SrcPID, "execArgv0", execArgv0)
	resp := Handle(req)
	if resp.Error != "" {
		log.Error(fmt.Errorf("%s", resp.Error), "netns-broker op failed", "op", req.Op, "migrationUID", req.MigrationUID, "execArgv0", execArgv0)
	}
	writeResp(conn, resp)
}

func writeResp(conn net.Conn, resp Response) {
	b, err := encodeResponse(resp)
	if err != nil {
		b, _ = json.Marshal(Response{Error: fmt.Sprintf("encode response: %v", err)})
	}
	b = append(b, '\n')
	_, _ = conn.Write(b)
}
