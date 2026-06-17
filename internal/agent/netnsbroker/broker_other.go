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

// Run errors on non-linux.
func Run(_ context.Context, _ logr.Logger) error {
	return fmt.Errorf("netns-broker: unsupported on this OS (linux only)")
}
