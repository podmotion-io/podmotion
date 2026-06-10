/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package client provides the operator-side gRPC client for calling node agents.
// One gRPC connection is maintained per node (keyed by node name) to amortise
// TLS handshake cost across multiple migrations on the same node.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

var log = logf.Log.WithName("agent-client")

// AgentClientPool manages one gRPC connection per node name.
// Thread-safe; safe to use from multiple reconciler goroutines.
type AgentClientPool struct {
	mu      sync.Mutex
	conns   map[string]*grpc.ClientConn
	port    string
	tlsCfg  *tls.Config
}

// NewAgentClientPool creates a pool.
// port is the agent listen port (default "9090").
// tlsCfg may be nil for insecure connections (dev mode).
func NewAgentClientPool(port string, tlsCfg *tls.Config) *AgentClientPool {
	if port == "" {
		port = "9090"
	}
	return &AgentClientPool{
		conns:  make(map[string]*grpc.ClientConn),
		port:   port,
		tlsCfg: tlsCfg,
	}
}

// ForNode returns (or creates) the MigrationAgentServiceClient for the named node.
// The agent is assumed to listen on <nodeName>:<port>.
func (p *AgentClientPool) ForNode(ctx context.Context, nodeName string) (agentpb.MigrationAgentServiceClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, ok := p.conns[nodeName]; ok {
		return agentpb.NewMigrationAgentServiceClient(conn), nil
	}

	addr := fmt.Sprintf("%s:%s", nodeName, p.port)
	conn, err := p.dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial agent on node %q (%s): %w", nodeName, addr, err)
	}

	p.conns[nodeName] = conn
	log.Info("Opened gRPC connection to node agent", "node", nodeName, "addr", addr)
	return agentpb.NewMigrationAgentServiceClient(conn), nil
}

// Close tears down all pooled connections.
func (p *AgentClientPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for node, conn := range p.conns {
		if err := conn.Close(); err != nil {
			log.Error(err, "Failed to close agent connection", "node", node)
		}
	}
	p.conns = make(map[string]*grpc.ClientConn)
}

func (p *AgentClientPool) dial(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30,
			Timeout:             10,
			PermitWithoutStream: true,
		}),
	}

	if p.tlsCfg != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(p.tlsCfg)))
	} else {
		// Insecure is only permitted when no TLS config is provided (dev/test mode).
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	//nolint:staticcheck // grpc.DialContext deprecated in newer grpc but kept for controller-runtime compat
	return grpc.DialContext(ctx, addr, opts...)
}

// NewAgentClient is a convenience function for callers that manage their own connection.
func NewAgentClient(addr string, tlsCfg *tls.Config) (agentpb.MigrationAgentServiceClient, *grpc.ClientConn, error) {
	pool := NewAgentClientPool("", tlsCfg)
	// Extract just host for nodeName key; addr is already host:port form here
	conn, err := pool.dial(context.Background(), addr)
	if err != nil {
		return nil, nil, err
	}
	return agentpb.NewMigrationAgentServiceClient(conn), conn, nil
}
