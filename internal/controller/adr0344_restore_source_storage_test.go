/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

// TestRestoreSourceStorageIfNeeded is the ADR-0344 Decision A.2 / verification
// table-driven unit test over (tier, priorHandoffState): Tier0 requires the
// source-agent-reachability precondition (fails closed, condition set False)
// before ConditionSourceStorageWriteRestored can be set True; all other
// tiers set it True immediately with no agent RPC/connection attempt. Also
// covers idempotency: once the condition is already True, the function is a
// no-op regardless of tier/AgentPool wiring.
func TestRestoreSourceStorageIfNeeded(t *testing.T) {
	tier0 := int32(storage.TierRWX)
	tierOther := int32(storage.TierRWX + 1)

	tests := []struct {
		name             string
		storageTier      *int32
		agentPool        *agentclient.AgentClientPool
		sourceNode       string
		priorTrue        bool
		allowNilFailOpen bool
		wantErr          bool
		wantStatus       metav1.ConditionStatus
		wantReason       string
	}{
		{
			name:        "non-Tier0 sets condition True immediately, no agent needed",
			storageTier: &tierOther,
			agentPool:   nil,
			sourceNode:  "",
			wantErr:     false,
			wantStatus:  metav1.ConditionTrue,
			wantReason:  "NonTier0NoOp",
		},
		{
			name:        "nil StorageTier treated as non-Tier0 (no-op True)",
			storageTier: nil,
			agentPool:   nil,
			sourceNode:  "",
			wantErr:     false,
			wantStatus:  metav1.ConditionTrue,
			wantReason:  "NonTier0NoOp",
		},
		{
			name:        "Tier0 with no AgentPool wired fails CLOSED by default (sign-off 2026-07-12)",
			storageTier: &tier0,
			agentPool:   nil,
			sourceNode:  "node-a",
			wantErr:     true,
			wantStatus:  metav1.ConditionFalse,
			wantReason:  "AgentTransportNotConfigured",
		},
		{
			name:             "Tier0 with no AgentPool wired fails open to True only when explicitly authorized",
			storageTier:      &tier0,
			agentPool:        nil,
			sourceNode:       "node-a",
			allowNilFailOpen: true,
			wantErr:          false,
			wantStatus:       metav1.ConditionTrue,
			wantReason:       "NoAgentPoolConfigured",
		},
		{
			name:        "Tier0 with AgentPool but empty SourceNodeName fails CLOSED by default",
			storageTier: &tier0,
			agentPool:   agentclient.NewAgentClientPool(fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(), "9090", nil),
			sourceNode:  "",
			wantErr:     true,
			wantStatus:  metav1.ConditionFalse,
			wantReason:  "AgentTransportNotConfigured",
		},
		{
			name:             "Tier0 with AgentPool but empty SourceNodeName fails open to True only when explicitly authorized",
			storageTier:      &tier0,
			agentPool:        agentclient.NewAgentClientPool(fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(), "9090", nil),
			sourceNode:       "",
			allowNilFailOpen: true,
			wantErr:          false,
			wantStatus:       metav1.ConditionTrue,
			wantReason:       "NoAgentPoolConfigured",
		},
		{
			name:        "Tier0 with AgentPool wired but source agent unreachable fails closed to False",
			storageTier: &tier0,
			agentPool:   agentclient.NewAgentClientPool(fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(), "9090", nil),
			sourceNode:  "node-a",
			wantErr:     true,
			wantStatus:  metav1.ConditionFalse,
			wantReason:  "SourceAgentUnreachable",
		},
		{
			name:        "already True is idempotent no-op even for Tier0 with no agent wired",
			storageTier: &tier0,
			agentPool:   nil,
			sourceNode:  "",
			priorTrue:   true,
			wantErr:     false,
			wantStatus:  metav1.ConditionTrue,
			wantReason:  "TestSeeded",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &pmv1.PodMigration{
				Status: pmv1.PodMigrationStatus{
					StorageTier:    tc.storageTier,
					SourceNodeName: tc.sourceNode,
				},
			}
			if tc.priorTrue {
				meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
					Type:    pmv1.ConditionSourceStorageWriteRestored,
					Status:  metav1.ConditionTrue,
					Reason:  "TestSeeded",
					Message: "seeded already-restored state",
				})
			}

			r := &PodMigrationReconciler{AgentPool: tc.agentPool, TestOnlyAllowNilAgentPoolFailOpen: tc.allowNilFailOpen}

			err := r.restoreSourceStorageIfNeeded(context.Background(), pm)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			c := meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionSourceStorageWriteRestored)
			if c == nil {
				t.Fatalf("ConditionSourceStorageWriteRestored not set")
			}
			if c.Status != tc.wantStatus {
				t.Errorf("status = %v, want %v", c.Status, tc.wantStatus)
			}
			if c.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", c.Reason, tc.wantReason)
			}

			if !tc.priorTrue && tc.storageTier != nil && *tc.storageTier != tier0 {
				// non-Tier0 path must never touch the agent pool.
				if tc.agentPool != nil {
					t.Errorf("non-Tier0 path should not require an AgentPool to be exercised")
				}
			}
		})
	}
}
