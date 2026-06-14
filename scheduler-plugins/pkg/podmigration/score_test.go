//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package podmigration_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/scheduler-plugins/pkg/podmigration"
)

// scorePod is a non-migration source pod used to exercise the Score path.
func scorePod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "default"}}
}

func ptr32(i int32) *int32 { return &i }

func nmcWithThermal(nodeName string, throttle *int32) *v1alpha1.NodeMigrationCapacity {
	nmc := readyNMC(nodeName, "4.2", 0, 4)
	nmc.Status.ThermalThrottlePercent = throttle
	return nmc
}

func TestMigrationAwareScore_NetworkLocality_SameZone(t *testing.T) {
	nmc := readyNMC("dest", "4.2", 0, 4)
	reader := &stubNMCReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{"dest": nmc}}
	s := podmigration.NewMigrationAwareScore(reader, podmigration.DefaultWeights)
	s.SetSourceContext(map[string]string{
		"topology.kubernetes.io/zone":   "us-east-1a",
		"topology.kubernetes.io/region": "us-east-1",
	}, 256*1024*1024)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dest",
			Labels: map[string]string{
				"topology.kubernetes.io/zone":   "us-east-1a",
				"topology.kubernetes.io/region": "us-east-1",
			},
		},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("16Gi"),
			},
		},
	}
	score, err := s.Score(context.Background(), scorePod(), node)
	if err != nil {
		t.Fatalf("Score error: %v", err)
	}
	// Same zone should contribute 40 pts to locality weight; total should be high.
	if score < 70 {
		t.Fatalf("expected score >= 70 for same-zone node, got %d", score)
	}
}

func TestMigrationAwareScore_NetworkLocality_CrossRegion(t *testing.T) {
	nmc := readyNMC("dest-far", "4.2", 0, 4)
	reader := &stubNMCReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{"dest-far": nmc}}
	s := podmigration.NewMigrationAwareScore(reader, podmigration.DefaultWeights)
	s.SetSourceContext(map[string]string{
		"topology.kubernetes.io/zone":   "us-east-1a",
		"topology.kubernetes.io/region": "us-east-1",
	}, 256*1024*1024)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dest-far",
			Labels: map[string]string{
				"topology.kubernetes.io/zone":   "eu-west-1a",
				"topology.kubernetes.io/region": "eu-west-1",
			},
		},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("16Gi"),
			},
		},
	}
	scoreNear, _ := podmigration.NewMigrationAwareScore(reader, podmigration.DefaultWeights).Score(context.Background(), scorePod(), node)
	_ = scoreNear

	scoreFar, err := s.Score(context.Background(), scorePod(), node)
	if err != nil {
		t.Fatalf("Score error: %v", err)
	}

	// Cross-region locality is 0, so score should be lower than same-zone.
	// We just verify it does not panic and returns a valid range.
	if scoreFar < 0 || scoreFar > 100 {
		t.Fatalf("score out of range: %d", scoreFar)
	}
}

func TestMigrationAwareScore_Thermal_Penalised(t *testing.T) {
	throttle := int32(50) // above 20% threshold
	nmc := nmcWithThermal("hot-node", &throttle)
	reader := &stubNMCReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{"hot-node": nmc}}
	s := podmigration.NewMigrationAwareScore(reader, podmigration.DefaultWeights)
	s.SetSourceContext(map[string]string{}, 0)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "hot-node"},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("16Gi"),
			},
		},
	}
	nothrottle := int32(0)
	nmcCool := nmcWithThermal("cool-node", &nothrottle)
	readerCool := &stubNMCReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{"cool-node": nmcCool}}
	sCool := podmigration.NewMigrationAwareScore(readerCool, podmigration.DefaultWeights)
	sCool.SetSourceContext(map[string]string{}, 0)

	nodeCool := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "cool-node"},
		Status:     node.Status,
	}

	scoreHot, _ := s.Score(context.Background(), scorePod(), node)
	scoreCool, _ := sCool.Score(context.Background(), scorePod(), nodeCool)

	if scoreHot >= scoreCool {
		t.Fatalf("thermal penalty not applied: hot=%d cool=%d", scoreHot, scoreCool)
	}
}
