/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

//go:build !linux

package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// PrepareDestinationNetns is not supported on non-Linux platforms.
// Network namespace creation requires Linux kernel primitives (CLONE_NEWNET, bind-mount).
func (s *AgentServer) PrepareDestinationNetns(_ context.Context, req *agentpb.PrepareDestinationNetnsRequest) (*agentpb.PrepareDestinationNetnsResponse, error) {
	log.Info("PrepareDestinationNetns: not supported on this platform (linux only)",
		"migration", req.MigrationName)
	return nil, status.Error(codes.Unimplemented, "PrepareDestinationNetns requires Linux")
}
