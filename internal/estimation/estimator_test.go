/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package estimation

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

func TestConvergencePredict(t *testing.T) {
	tests := []struct {
		initial   float64
		rounds    int
		threshold float64
		wantBelow float64
	}{
		{initial: 512, rounds: 5, threshold: 64, wantBelow: 64},
		{initial: 32, rounds: 5, threshold: 64, wantBelow: 64},    // already below — returns quickly
		{initial: 2048, rounds: 3, threshold: 64, wantBelow: 300}, // not converged in 3 rounds
	}
	for _, tc := range tests {
		result := convergencePredict(tc.initial, tc.rounds, tc.threshold)
		if result > tc.wantBelow {
			t.Errorf("convergencePredict(%v,%v,%v) = %v; want <= %v",
				tc.initial, tc.rounds, tc.threshold, result, tc.wantBelow)
		}
	}
}

func TestEstimator_Tier4Block(t *testing.T) {
	est := &DefaultEstimator{Prober: &StubProber{}}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "host", VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/data"},
				}},
			},
		},
	}
	nmc := &pmv1.NodeMigrationCapacity{}
	spec := pmv1.PodMigrationSpec{StorageStrategy: pmv1.StorageStrategyAuto}

	result, err := est.Estimate(context.Background(), pod, nmc, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Migratable {
		t.Error("expected Tier 4 pod to be not migratable")
	}
	if result.StorageTier != 4 {
		t.Errorf("expected StorageTier=4, got %d", result.StorageTier)
	}
}

func TestEstimator_Tier4SkipOverride(t *testing.T) {
	est := &DefaultEstimator{Prober: &StubProber{DirtyMB: 64, ElapseMs: 1000}}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "host", VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/data"},
				}},
			},
		},
	}
	nmc := &pmv1.NodeMigrationCapacity{}
	spec := pmv1.PodMigrationSpec{
		StorageStrategy:         pmv1.StorageStrategySkip,
		PreCopyMaxRounds:        5,
		PreCopyDirtyThresholdMB: 64,
		BandwidthLimitMbps:      1000,
	}

	result, err := est.Estimate(context.Background(), pod, nmc, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With Skip override, estimation proceeds past Tier 4 check.
	if !result.Migratable {
		t.Errorf("expected Migratable=true with StorageStrategy=Skip, got false: %s", result.BlockingReason)
	}
}

func TestEstimator_PostCopyRequiresUserfaultfd(t *testing.T) {
	est := &DefaultEstimator{Prober: &StubProber{}}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec:       corev1.PodSpec{},
	}
	nmc := &pmv1.NodeMigrationCapacity{
		Spec: pmv1.NodeMigrationCapacitySpec{
			KernelFeatures: pmv1.KernelFeatures{Userfaultfd: false},
		},
	}
	spec := pmv1.PodMigrationSpec{Mode: pmv1.MigrationModePostCopy}

	result, err := est.Estimate(context.Background(), pod, nmc, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Migratable {
		t.Error("expected PostCopy without userfaultfd to be not migratable")
	}
}

func TestEstimator_StatelessPod(t *testing.T) {
	est := &DefaultEstimator{Prober: &StubProber{DirtyMB: 32, ElapseMs: 500}}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx", Namespace: "default"},
		Spec:       corev1.PodSpec{},
	}
	nmc := &pmv1.NodeMigrationCapacity{}
	spec := pmv1.PodMigrationSpec{
		Mode:                    pmv1.MigrationModePreCopy,
		PreCopyMaxRounds:        5,
		PreCopyDirtyThresholdMB: 64,
		BandwidthLimitMbps:      1000,
	}

	result, err := est.Estimate(context.Background(), pod, nmc, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Migratable {
		t.Errorf("stateless pod should be migratable: %s", result.BlockingReason)
	}
	if result.StorageTier != 0 {
		t.Errorf("expected Tier 0 for stateless pod, got %d", result.StorageTier)
	}
}
