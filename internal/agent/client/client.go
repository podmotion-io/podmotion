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
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

var log = logf.Log.WithName("agent-client")

const agentNamespace = "podmotion-system"

// AgentClientPool manages one gRPC connection per node name.
// Thread-safe; safe to use from multiple reconciler goroutines.
type AgentClientPool struct {
	mu        sync.Mutex
	conns     map[string]*grpc.ClientConn
	port      string
	tlsCfg    *tls.Config
	k8sClient client.Client
}

// NewAgentClientPool creates a pool.
// k8sClient is used to resolve node name → agent pod IP via label selector.
// port is the agent listen port (default "9090").
// tlsCfg may be nil for insecure connections (dev mode).
func NewAgentClientPool(k8sClient client.Client, port string, tlsCfg *tls.Config) *AgentClientPool {
	if port == "" {
		port = "9090"
	}
	return &AgentClientPool{
		conns:     make(map[string]*grpc.ClientConn),
		port:      port,
		tlsCfg:    tlsCfg,
		k8sClient: k8sClient,
	}
}

// ForNode returns (or creates) the MigrationAgentServiceClient for the named node.
// It resolves the agent pod IP via the k8s API using label selectors, then dials
// <podIP>:<port>. This is necessary in kind clusters where node names are not
// DNS-resolvable from operator pods.
func (p *AgentClientPool) ForNode(ctx context.Context, nodeName string) (agentpb.MigrationAgentServiceClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, ok := p.conns[nodeName]; ok {
		return agentpb.NewMigrationAgentServiceClient(conn), nil
	}

	podIP, err := p.resolveAgentPodIP(ctx, nodeName)
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s:%s", podIP, p.port)
	conn, err := p.dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial agent on node %q (%s): %w", nodeName, addr, err)
	}

	p.conns[nodeName] = conn
	log.Info("Opened gRPC connection to node agent", "node", nodeName, "addr", addr)
	return agentpb.NewMigrationAgentServiceClient(conn), nil
}

// resolveAgentPodIP finds the Running agent pod for the given node and returns its PodIP.
// It lists pods in agentNamespace with label app=podmotion-agent and field selector
// spec.nodeName=<nodeName>, then picks the first Running pod.
func (p *AgentClientPool) resolveAgentPodIP(ctx context.Context, nodeName string) (string, error) {
	if p.k8sClient == nil {
		return "", fmt.Errorf("k8sClient is nil; cannot resolve agent pod IP for node %q", nodeName)
	}

	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(agentNamespace),
		client.MatchingLabels{"app": "podmotion-agent"},
		client.MatchingFields{"spec.nodeName": nodeName},
	}

	if err := p.k8sClient.List(ctx, podList, listOpts...); err != nil {
		return "", fmt.Errorf("list agent pods for node %q: %w", nodeName, err)
	}

	for i := range podList.Items {
		pod := &podList.Items[i]
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			return pod.Status.PodIP, nil
		}
	}

	return "", fmt.Errorf("no running agent pod found for node %q in namespace %q", nodeName, agentNamespace)
}

// InvalidateNode drops a cached connection for the given node so the next ForNode
// call will re-resolve the pod IP and re-dial. Call this when a gRPC call fails.
func (p *AgentClientPool) InvalidateNode(nodeName string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, ok := p.conns[nodeName]; ok {
		if err := conn.Close(); err != nil {
			log.Error(err, "Failed to close agent connection during invalidation", "node", nodeName)
		}
		delete(p.conns, nodeName)
		log.Info("Invalidated cached gRPC connection for node", "node", nodeName)
	}
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
	pool := NewAgentClientPool(nil, "", tlsCfg)
	// Extract just host for nodeName key; addr is already host:port form here
	conn, err := pool.dial(context.Background(), addr)
	if err != nil {
		return nil, nil, err
	}
	return agentpb.NewMigrationAgentServiceClient(conn), conn, nil
}
