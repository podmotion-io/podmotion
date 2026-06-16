/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package grpclimits holds the single source of truth for ADR-SEC-A §2.3 (C-333) gRPC
// message-size and decompression bounds, shared by the agent server and the operator client so
// the two ends cannot skew.
package grpclimits

const (
	// MaxCheckpointTarBytes bounds the on-wire gRPC message size for checkpoint transfer (512 MiB).
	// All non-transfer RPCs are small; the single global cap is set to the transfer ceiling.
	MaxCheckpointTarBytes = 512 * 1024 * 1024
	// MaxDecompressedTarBytes bounds gzip decompression on PutCheckpointTar (2 GiB) to defeat a
	// gzip bomb independently of the on-wire cap.
	MaxDecompressedTarBytes = 2 * 1024 * 1024 * 1024
)
