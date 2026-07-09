/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package client

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// SourceRollbackClient adapts the pooled MigrationAgentServiceClient to the
// interface the rollback pipeline's StubComputeRollback expects
// (Abort(ctx, migrationName, reason string) error).
//
// Wired into cmd/main.go per ADR-0248 D2 to close the nil-SourceAgentClient gap:
// on a mid-checkpoint abort, the controller's rollback pipeline now drives the
// source agent's Abort RPC directly (which reaches thawFrozenSource), instead of
// relying solely on an agent restart (ReconcileOrphanedFrozenSources) or a
// coincidental independent Abort caller. The RPC signature the agent exposes takes
// an *AbortRequest and returns (*AbortResponse, error); this adapter maps the
// rollback interface's (migrationName, reason) onto that request and resolves the
// source node the Abort must be dispatched to.
//
// The Abort RPC must target the SOURCE node's agent (that is where the frozen PID
// lives), which the rollback interface does not carry in its signature — so this
// adapter resolves it from the PodMigration's Status.SourceNodeName.
type SourceRollbackClient struct {
	// Pool resolves and dials the per-node agent gRPC client.
	Pool *AgentClientPool
	// K8sClient resolves the migration name to its source node (Status.SourceNodeName).
	K8sClient client.Client
}

// NewSourceRollbackClient constructs the adapter. Both fields are required; if
// either is nil the returned client's Abort will error rather than silently no-op.
func NewSourceRollbackClient(pool *AgentClientPool, k8sClient client.Client) *SourceRollbackClient {
	return &SourceRollbackClient{Pool: pool, K8sClient: k8sClient}
}

// Abort resolves the source node for the named migration, obtains that node's agent
// client from the pool, and issues the Abort RPC. The agent's Abort handler calls
// thawFrozenSource first and idempotently (a no-op if nothing is frozen), so this is
// safe under re-queues and safe when no LeaveStopped freeze ever occurred.
func (c *SourceRollbackClient) Abort(ctx context.Context, migrationName, reason string) error {
	if c.Pool == nil || c.K8sClient == nil {
		return fmt.Errorf("SourceRollbackClient not fully wired (pool or k8sClient nil)")
	}

	sourceNode, err := c.resolveSourceNode(ctx, migrationName)
	if err != nil {
		return fmt.Errorf("resolve source node for migration %q: %w", migrationName, err)
	}
	if sourceNode == "" {
		return fmt.Errorf("migration %q has no Status.SourceNodeName; cannot target source agent Abort", migrationName)
	}

	agent, err := c.Pool.ForNode(ctx, sourceNode)
	if err != nil {
		return fmt.Errorf("connect to source agent on node %q: %w", sourceNode, err)
	}

	if _, err := agent.Abort(ctx, &agentpb.AbortRequest{
		MigrationName: migrationName,
		Reason:        reason,
	}); err != nil {
		return fmt.Errorf("source agent Abort RPC on node %q failed: %w", sourceNode, err)
	}
	return nil
}

// resolveSourceNode finds the PodMigration by name and returns its
// Status.SourceNodeName. The rollback interface passes only the migration name;
// PodMigration names are not namespace-unique in the API, so this lists across all
// namespaces and matches by metadata.name. In practice the rollback pipeline drives
// one migration at a time; if more than one PodMigration shares the name, the first
// match with a non-empty source node is used.
func (c *SourceRollbackClient) resolveSourceNode(ctx context.Context, migrationName string) (string, error) {
	list := &pmv1.PodMigrationList{}
	if err := c.K8sClient.List(ctx, list); err != nil {
		return "", fmt.Errorf("list PodMigrations: %w", err)
	}
	for i := range list.Items {
		pm := &list.Items[i]
		if pm.Name == migrationName && pm.Status.SourceNodeName != "" {
			return pm.Status.SourceNodeName, nil
		}
	}
	return "", fmt.Errorf("no PodMigration named %q with a resolved Status.SourceNodeName found", migrationName)
}
