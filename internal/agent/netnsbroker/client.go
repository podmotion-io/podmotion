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
	"time"
)

// Client dials the netns-broker Unix domain socket. The main agent (de-privileged
// under SD-1) uses it to request per-migration netns bind/teardown from the
// privileged sidecar instead of running nsenter+mount itself.
type Client struct {
	// SocketPath overrides the default broker socket path (testing). Empty => SocketPath.
	socketPath string
	// dialTimeout bounds connect; opTimeout bounds the whole request/response.
	dialTimeout time.Duration
	opTimeout   time.Duration
}

// NewClient returns a Client dialing the default broker socket.
func NewClient() *Client {
	return &Client{
		socketPath:  SocketPath,
		dialTimeout: 5 * time.Second,
		opTimeout:   30 * time.Second,
	}
}

func (c *Client) path() string {
	if c.socketPath != "" {
		return c.socketPath
	}
	return SocketPath
}

// Create requests a per-migration netns bind-mount and returns the host bind path.
// srcPID > 0 binds /proc/<srcPID>/ns/net (pod-in-migration); srcPID == 0 makes the
// broker unshare a fresh netns and bind it (destination-prewarm path).
func (c *Client) Create(ctx context.Context, migrationUID string, srcPID int) (string, error) {
	resp, err := c.do(ctx, Request{Op: "create", MigrationUID: migrationUID, SrcPID: srcPID})
	if err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", fmt.Errorf("netns-broker create %s: %s", migrationUID, resp.Error)
	}
	return resp.Path, nil
}

// Teardown requests unmount+removal of the per-migration netns. Idempotent broker-side.
func (c *Client) Teardown(ctx context.Context, migrationUID string) error {
	resp, err := c.do(ctx, Request{Op: "teardown", MigrationUID: migrationUID})
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("netns-broker teardown %s: %s", migrationUID, resp.Error)
	}
	return nil
}

func (c *Client) do(ctx context.Context, req Request) (Response, error) {
	dialCtx, cancel := context.WithTimeout(ctx, c.dialTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", c.path())
	if err != nil {
		return Response{}, fmt.Errorf("dial netns-broker %s: %w", c.path(), err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.opTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("marshal request: %w", err)
	}
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		return Response{}, fmt.Errorf("write request: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return Response{}, fmt.Errorf("read response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}
