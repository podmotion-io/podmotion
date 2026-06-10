/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package server implements the MigrationAgentService gRPC server that runs on every node.
// In M4 the server wires up StubCheckpointer; real CRIU bindings land in M5.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

var log = logf.Log.WithName("agent-server")

// AgentServer implements agentpb.MigrationAgentServiceServer.
// One instance runs per node agent process.
type AgentServer struct {
	agentpb.UnimplementedMigrationAgentServiceServer
	checkpointer criu.Checkpointer
	nodeName     string
}

// New constructs an AgentServer with the given Checkpointer implementation.
func New(nodeName string, cp criu.Checkpointer) *AgentServer {
	return &AgentServer{
		checkpointer: cp,
		nodeName:     nodeName,
	}
}

// ListenAndServe starts the gRPC server on addr (default ":9090").
// tlsCfg may be nil for insecure mode (dev/test only).
// Blocks until ctx is cancelled.
func (s *AgentServer) ListenAndServe(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	if addr == "" {
		addr = ":9090"
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
	}
	if tlsCfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	} else {
		log.Info("gRPC server starting without TLS — dev mode", "addr", addr)
	}

	grpcSrv := grpc.NewServer(opts...)
	agentpb.RegisterMigrationAgentServiceServer(grpcSrv, s)

	log.Info("Agent gRPC server listening", "addr", addr, "node", s.nodeName)

	errCh := make(chan error, 1)
	go func() { errCh <- grpcSrv.Serve(lis) }()

	select {
	case <-ctx.Done():
		log.Info("Shutting down agent gRPC server")
		grpcSrv.GracefulStop()
		return nil
	case err := <-errCh:
		return fmt.Errorf("grpc serve: %w", err)
	}
}

// ── RPC handlers ─────────────────────────────────────────────────────────────

func (s *AgentServer) PrepareSource(_ context.Context, req *agentpb.PrepareSourceRequest) (*agentpb.PrepareSourceResponse, error) {
	log.Info("PrepareSource called", "migration", req.MigrationName, "pod", req.PodName, "ns", req.PodNamespace)
	// M4: stub — real compat probe wired in M5.
	return &agentpb.PrepareSourceResponse{
		Compatible:  true,
		StorageTier: 1,
	}, nil
}

func (s *AgentServer) PreDumpRound(_ context.Context, req *agentpb.PreDumpRoundRequest) (*agentpb.PreDumpRoundResponse, error) {
	log.Info("PreDumpRound called", "migration", req.MigrationName, "round", req.RoundNumber)
	result, err := s.checkpointer.PreDump(context.Background(), criu.PreDumpOptions{
		ImagesDir: fmt.Sprintf("/var/lib/podmotion/checkpoints/%s/round-%d", req.MigrationName, req.RoundNumber),
		TrackMem:  true,
	})
	if err != nil {
		return nil, err
	}
	return &agentpb.PreDumpRoundResponse{
		DirtyPagesMB:    result.DirtyPagesMB,
		RoundDurationMs: result.FreezeDurationMs,
		// Convergence threshold: < 64 MB dirty qualifies as "good enough to freeze" (ADR-0011).
		ThresholdReached: result.DirtyPagesMB < 64,
	}, nil
}

func (s *AgentServer) Checkpoint(_ context.Context, req *agentpb.CheckpointRequest) (*agentpb.CheckpointResponse, error) {
	log.Info("Checkpoint called", "migration", req.MigrationName)
	result, err := s.checkpointer.Dump(context.Background(), criu.DumpOptions{
		ImagesDir: fmt.Sprintf("/var/lib/podmotion/checkpoints/%s/final", req.MigrationName),
	})
	if err != nil {
		return nil, err
	}
	return &agentpb.CheckpointResponse{
		FreezeDurationMs: result.FreezeDurationMs,
		// SHA256 populated by real CRIU checkpointer in M5.
		CheckpointSHA256: "",
	}, nil
}

func (s *AgentServer) PrepareDestination(_ context.Context, req *agentpb.PrepareDestinationRequest) (*agentpb.PrepareDestinationResponse, error) {
	log.Info("PrepareDestination called", "migration", req.MigrationName, "sourceNode", req.SourceNode)
	// M4: stub — cgroup/netns setup wired in M5.
	return &agentpb.PrepareDestinationResponse{
		Ready:        true,
		IPReserved:   true,
		StorageReady: true,
	}, nil
}

func (s *AgentServer) Restore(_ context.Context, req *agentpb.RestoreRequest) (*agentpb.RestoreResponse, error) {
	log.Info("Restore called", "migration", req.MigrationName, "checkpointRef", req.CheckpointRef)
	result, err := s.checkpointer.Restore(context.Background(), criu.RestoreOptions{
		ImagesDir: fmt.Sprintf("/var/lib/podmotion/checkpoints/%s/final", req.MigrationName),
		Detached:  true,
	})
	if err != nil {
		return &agentpb.RestoreResponse{Success: false, ErrorMessage: err.Error()}, nil
	}
	return &agentpb.RestoreResponse{
		Success:           true,
		RestoreDurationMs: time.Since(result.RestoredAt).Milliseconds(),
	}, nil
}

func (s *AgentServer) Verify(_ context.Context, req *agentpb.VerifyRequest) (*agentpb.VerifyResponse, error) {
	log.Info("Verify called", "migration", req.MigrationName, "pod", req.PodName)
	// M4: stub — real readiness probe wired when traffic agent is complete.
	return &agentpb.VerifyResponse{Healthy: true}, nil
}

func (s *AgentServer) Abort(_ context.Context, req *agentpb.AbortRequest) (*agentpb.AbortResponse, error) {
	log.Info("Abort called", "migration", req.MigrationName, "reason", req.Reason)
	if err := s.checkpointer.Abort(context.Background(), "", "k8s.io"); err != nil {
		return &agentpb.AbortResponse{Success: false}, err
	}
	return &agentpb.AbortResponse{Success: true}, nil
}

func (s *AgentServer) EstimateCheckpoint(_ context.Context, req *agentpb.EstimateCheckpointRequest) (*agentpb.EstimateCheckpointResponse, error) {
	log.Info("EstimateCheckpoint called", "pod", req.PodName, "ns", req.PodNamespace)
	// M4: stub estimation — real dirty page sampling wired in M5 via CRIU pre-dump loop.
	return &agentpb.EstimateCheckpointResponse{
		DirtyPageRateMBPerSec:     32.0,
		EstimatedFreezeDurationMs: 150,
		EstimatedCheckpointSizeMB: 512,
		StorageTier:               1,
		Migratable:                true,
	}, nil
}
