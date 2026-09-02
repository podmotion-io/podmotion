// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !linux

// Package netnsbroker — non-linux stub. The broker manipulates network and
// mount namespaces, which exist only on Linux. On other GOOS this package
// compiles to no-ops that error at runtime, so cross-platform `go build ./...`
// and developer tooling on macOS still succeed (mirrors internal/agent/server's
// netns_other.go split).
package netnsbroker

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
)

// SocketPath is exported on all platforms for callers/tests.
const SocketPath = "/run/podmotion/netns-broker.sock"

// Client is the non-linux stub of the broker client.
type Client struct{}

// NewClient returns a stub client; all ops error on non-linux.
func NewClient() *Client { return &Client{} }

// Create errors on non-linux.
func (c *Client) Create(_ context.Context, _ string, _ int) (string, error) {
	return "", fmt.Errorf("netns-broker: unsupported on this OS (linux only)")
}

// Teardown errors on non-linux.
func (c *Client) Teardown(_ context.Context, _ string) error {
	return fmt.Errorf("netns-broker: unsupported on this OS (linux only)")
}

// HolderSentinelReady errors on non-linux (broker is linux-only).
func (c *Client) HolderSentinelReady(_ context.Context, _ string) (bool, error) {
	return false, fmt.Errorf("netns-broker: unsupported on this OS (linux only)")
}

// HostRealpath errors on non-linux (broker is linux-only). Fail-closed on every
// platform: callers treat the error as a rejection (ADR-0419 D9).
func (c *Client) HostRealpath(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("netns-broker: unsupported on this OS (linux only)")
}

// NetnsExec errors on non-linux (ADR-0346 D6).
func (c *Client) NetnsExec(_ context.Context, _ int, _ string, _ ...string) ExecResult {
	return ExecResult{ExitCode: -1, SpawnErr: fmt.Errorf("netns-broker: unsupported on this OS (linux only)")}
}

// NetnsExecStart errors on non-linux (ADR-0346 D6).
func (c *Client) NetnsExecStart(_ context.Context, _ int, _ string, _ ...string) (int, error) {
	return 0, fmt.Errorf("netns-broker: unsupported on this OS (linux only)")
}

// Run errors on non-linux.
func Run(_ context.Context, _ logr.Logger) error {
	return fmt.Errorf("netns-broker: unsupported on this OS (linux only)")
}
