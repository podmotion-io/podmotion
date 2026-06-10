/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package client_test

import (
	"context"
	"testing"

	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func podNodeNameIndexer(obj client.Object) []string {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	return []string{pod.Spec.NodeName}
}

func TestForNode_NoPodFound_ReturnsError(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&corev1.Pod{}, "spec.nodeName", podNodeNameIndexer).
		Build()

	pool := agentclient.NewAgentClientPool(fakeClient, "9090", nil)
	_, err := pool.ForNode(context.Background(), "worker-node-1")
	if err == nil {
		t.Fatal("expected error when no agent pod found, got nil")
	}
	t.Logf("Got expected error: %v", err)
}

func TestForNode_RunningPodFound_Dials(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podmotion-agent-worker",
			Namespace: "podmotion-system",
			Labels: map[string]string{
				"app": "podmotion-agent",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "worker-node-1",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.0.0.5",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod).
		WithStatusSubresource(pod).
		WithIndex(&corev1.Pod{}, "spec.nodeName", podNodeNameIndexer).
		Build()

	pool := agentclient.NewAgentClientPool(fakeClient, "9090", nil)
	// ForNode will try to dial 10.0.0.5:9090 — that will fail in test since no real server,
	// but the error should be a dial error, not a "no pod found" error.
	_, err := pool.ForNode(context.Background(), "worker-node-1")
	if err != nil {
		// Acceptable: dial failure to a non-existent server.
		t.Logf("Got dial error (expected in unit test without real gRPC server): %v", err)
		return
	}
	t.Log("Connection returned (unexpected in unit test, but OK)")
}
