/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package spotreclaim_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/spotimds"
	"github.com/podmotion-io/podmotion/internal/controller/spotreclaim"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = pmv1.AddToScheme(s)
	return s
}

func spotNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				spotimds.SpotInterruptAnnotation: "true",
			},
		},
	}
}

func runningPod(name, namespace, nodeName string, memMi int64, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: "nginx",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: *resource.NewMilliQuantity(memMi*1024*1024*1000, resource.BinarySI),
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}
}

func spotPolicy(name, namespace string) *pmv1.MigrationPolicy {
	spotReclaim := true
	return &pmv1.MigrationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: pmv1.MigrationPolicySpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			Triggers: pmv1.MigrationTrigger{
				SpotReclaim: &spotReclaim,
			},
			MaxConcurrentMigrations: 10,
		},
	}
}

// buildReconciler creates a fake-backed SpotReclaimReconciler with a pre-seeded
// field index for spec.nodeName so List(MatchingFields{...}) works.
func buildReconciler(t *testing.T, objs ...client.Object) (*spotreclaim.SpotReclaimReconciler, client.Client) {
	t.Helper()
	s := newScheme(t)
	kc := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithIndex(&corev1.Pod{}, spotreclaim.NodeFieldIndexName, spotreclaim.PodNodeNameIndexer).
		Build()
	r := &spotreclaim.SpotReclaimReconciler{
		Client: kc,
		Scheme: s,
	}
	return r, kc
}

func TestSpotReclaimController_CreatesMigrationsOnAnnotation(t *testing.T) {
	node := spotNode("spot-worker-1")
	pod := runningPod("web-abc", "default", "spot-worker-1", 256, map[string]string{"app": "web"})
	policy := spotPolicy("spot-policy", "default")

	r, kc := buildReconciler(t, node, pod, policy)

	req := ctrl.Request{NamespacedName: client.ObjectKey{Name: "spot-worker-1"}}
	_, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile error: %v", err)
	}

	var pmList pmv1.PodMigrationList
	if err := kc.List(context.Background(), &pmList); err != nil {
		t.Fatalf("list migrations: %v", err)
	}
	if len(pmList.Items) != 1 {
		t.Fatalf("expected 1 PodMigration, got %d", len(pmList.Items))
	}
	pm := pmList.Items[0]
	if pm.Spec.PodName != "web-abc" {
		t.Errorf("expected pod name web-abc, got %s", pm.Spec.PodName)
	}
	if pm.Spec.CompletionTimeoutSeconds != spotreclaim.SpotReclaimTimeout {
		t.Errorf("expected timeout %d, got %d", spotreclaim.SpotReclaimTimeout, pm.Spec.CompletionTimeoutSeconds)
	}
}

func TestSpotReclaimController_RespectsMigrationPolicy(t *testing.T) {
	node := spotNode("spot-worker-2")
	// pod-a matches policy selector; pod-b does not
	podA := runningPod("pod-a", "default", "spot-worker-2", 128, map[string]string{"app": "web"})
	podB := runningPod("pod-b", "default", "spot-worker-2", 64, map[string]string{"app": "db"})
	policy := spotPolicy("spot-policy", "default")

	r, kc := buildReconciler(t, node, podA, podB, policy)

	req := ctrl.Request{NamespacedName: client.ObjectKey{Name: "spot-worker-2"}}
	_, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile error: %v", err)
	}

	var pmList pmv1.PodMigrationList
	_ = kc.List(context.Background(), &pmList)

	if len(pmList.Items) != 1 {
		t.Fatalf("expected 1 migration (only pod-a matches policy), got %d", len(pmList.Items))
	}
	if pmList.Items[0].Spec.PodName != "pod-a" {
		t.Errorf("expected pod-a, got %s", pmList.Items[0].Spec.PodName)
	}
}

func TestSpotReclaimController_IdempotentOnReReconcile(t *testing.T) {
	node := spotNode("spot-worker-3")
	pod := runningPod("web-xyz", "default", "spot-worker-3", 128, map[string]string{"app": "web"})
	policy := spotPolicy("spot-policy", "default")

	r, kc := buildReconciler(t, node, pod, policy)
	req := ctrl.Request{NamespacedName: client.ObjectKey{Name: "spot-worker-3"}}

	// Reconcile twice — should only create 1 migration.
	_, _ = r.Reconcile(context.Background(), req)

	// Re-read the node (it now has the processed annotation) and reconcile again.
	var updatedNode corev1.Node
	_ = kc.Get(context.Background(), client.ObjectKey{Name: "spot-worker-3"}, &updatedNode)
	_, _ = r.Reconcile(context.Background(), req)

	var pmList pmv1.PodMigrationList
	_ = kc.List(context.Background(), &pmList)
	if len(pmList.Items) != 1 {
		t.Errorf("expected idempotent: 1 migration, got %d", len(pmList.Items))
	}
}

func TestSpotReclaimController_NoMigrationsWhenNoPolicyMatches(t *testing.T) {
	node := spotNode("spot-worker-4")
	// Pod has no labels that match any policy selector.
	pod := runningPod("orphan-pod", "default", "spot-worker-4", 64, map[string]string{"tier": "cache"})
	policy := spotPolicy("spot-policy", "default")

	r, kc := buildReconciler(t, node, pod, policy)
	req := ctrl.Request{NamespacedName: client.ObjectKey{Name: "spot-worker-4"}}
	_, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile error: %v", err)
	}

	var pmList pmv1.PodMigrationList
	_ = kc.List(context.Background(), &pmList)
	if len(pmList.Items) != 0 {
		t.Errorf("expected 0 migrations, got %d", len(pmList.Items))
	}
}
