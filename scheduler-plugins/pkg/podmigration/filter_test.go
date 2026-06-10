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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/scheduler-plugins/pkg/podmigration"
)

// stubNMCReader satisfies NMCReader by serving a static NMC from a map keyed on node name.
type stubNMCReader struct {
	nmcs map[string]*v1alpha1.NodeMigrationCapacity
}

func (s *stubNMCReader) Get(_ context.Context, key types.NamespacedName, obj client.Object, _ ...client.GetOption) error {
	nmc, ok := s.nmcs[key.Name]
	if !ok {
		return &notFoundError{name: key.Name}
	}
	if target, ok := obj.(*v1alpha1.NodeMigrationCapacity); ok {
		*target = *nmc
	}
	return nil
}

type notFoundError struct{ name string }

func (e *notFoundError) Error() string { return "not found: " + e.name }

func readyNMC(nodeName, criuVersion string, active, max int32) *v1alpha1.NodeMigrationCapacity {
	return &v1alpha1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Spec: v1alpha1.NodeMigrationCapacitySpec{
			NodeName:                           nodeName,
			CRIUVersion:                        criuVersion,
			MaxConcurrentMigrationsDestination: max,
		},
		Status: v1alpha1.NodeMigrationCapacityStatus{
			Ready:                       true,
			ActiveDestinationMigrations: active,
		},
	}
}

func TestMigrationAwareFilter_DrainedNode(t *testing.T) {
	reader := &stubNMCReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{
		"node-a": readyNMC("node-a", "4.2", 0, 2),
	}}
	f := podmigration.NewMigrationAwareFilter(reader, runtime.NewScheme())

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-a",
			Labels: map[string]string{podmigration.LabelDraining: "true"},
		},
	}
	result := f.Filter(context.Background(), node)
	if result.Allowed {
		t.Fatalf("expected draining node to be filtered out, got allowed")
	}
}

func TestMigrationAwareFilter_AtCapacity(t *testing.T) {
	reader := &stubNMCReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{
		"node-b": readyNMC("node-b", "4.2", 2, 2), // active == max
	}}
	f := podmigration.NewMigrationAwareFilter(reader, runtime.NewScheme())

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-b"},
	}
	result := f.Filter(context.Background(), node)
	if result.Allowed {
		t.Fatalf("expected at-capacity node to be filtered out, got allowed")
	}
}

func TestMigrationAwareFilter_NoCRIU(t *testing.T) {
	reader := &stubNMCReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{
		"node-c": readyNMC("node-c", "", 0, 2), // empty criu version
	}}
	f := podmigration.NewMigrationAwareFilter(reader, runtime.NewScheme())

	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-c"}}
	result := f.Filter(context.Background(), node)
	if result.Allowed {
		t.Fatalf("expected node without CRIU to be filtered out, got allowed")
	}
}

func TestMigrationAwareFilter_NotReady(t *testing.T) {
	nmc := readyNMC("node-d", "4.2", 0, 2)
	nmc.Status.Ready = false
	reader := &stubNMCReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{"node-d": nmc}}
	f := podmigration.NewMigrationAwareFilter(reader, runtime.NewScheme())

	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-d"}}
	result := f.Filter(context.Background(), node)
	if result.Allowed {
		t.Fatalf("expected not-ready node to be filtered out, got allowed")
	}
}

func TestMigrationAwareFilter_Allow(t *testing.T) {
	reader := &stubNMCReader{nmcs: map[string]*v1alpha1.NodeMigrationCapacity{
		"node-e": readyNMC("node-e", "4.2", 1, 2),
	}}
	f := podmigration.NewMigrationAwareFilter(reader, runtime.NewScheme())

	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-e"}}
	result := f.Filter(context.Background(), node)
	if !result.Allowed {
		t.Fatalf("expected node to pass filter, got reason: %s", result.Reason)
	}
}
