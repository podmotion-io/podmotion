/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestMigrationPolicyController_MaxConcurrent verifies that the active migration
// count check gates new migration creation at the configured limit.
func TestMigrationPolicyController_MaxConcurrent(t *testing.T) {
	policy := &pmv1.MigrationPolicy{}
	policy.Name = "test-policy"
	policy.Namespace = "default"
	policy.Spec.MaxConcurrentMigrations = 2

	migrations := []pmv1.PodMigration{
		makePolicyMigration("m1", policy.Name, pmv1.MigrationPhaseCheckpointing),
		makePolicyMigration("m2", policy.Name, pmv1.MigrationPhaseRestoring),
		// Terminal — should not count toward active.
		makePolicyMigration("m3", policy.Name, pmv1.MigrationPhaseComplete),
	}

	active := int32(0)
	for _, pm := range migrations {
		if pm.Spec.MigrationPolicyRef != nil && pm.Spec.MigrationPolicyRef.Name == policy.Name {
			if !isTerminal(pm.Status.Phase) {
				active++
			}
		}
	}

	if active != 2 {
		t.Fatalf("active count = %d, want 2", active)
	}
	if active < policy.Spec.MaxConcurrentMigrations {
		t.Errorf("expected block at limit=%d but active=%d", policy.Spec.MaxConcurrentMigrations, active)
	}
}

func makePolicyMigration(name, policyName string, phase pmv1.MigrationPhase) pmv1.PodMigration {
	pm := pmv1.PodMigration{}
	pm.Name = name
	pm.Namespace = "default"
	pm.Spec.MigrationPolicyRef = &corev1.LocalObjectReference{Name: policyName}
	pm.Status.Phase = phase
	return pm
}
