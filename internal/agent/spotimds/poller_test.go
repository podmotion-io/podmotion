/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package spotimds_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/podmotion-io/podmotion/internal/agent/spotimds"
)

// fakeIMDS implements spotimds.IMDSClient and returns a configurable status code.
type fakeIMDS struct {
	statusCode int
}

func (f *fakeIMDS) Get(_ string) (*http.Response, error) {
	return &http.Response{
		StatusCode: f.statusCode,
		Body:       http.NoBody,
	}, nil
}

func TestSpotIMDSPoller_AnnotatesNodeOnInterrupt(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker-spot-1",
		},
	}
	kc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build()

	poller := &spotimds.Poller{
		NodeName:   "worker-spot-1",
		KubeClient: kc,
		IMDS:       &fakeIMDS{statusCode: http.StatusOK},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := poller.Run(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated corev1.Node
	if err := kc.Get(ctx, client.ObjectKey{Name: "worker-spot-1"}, &updated); err != nil {
		t.Fatalf("get node: %v", err)
	}
	if updated.Annotations[spotimds.SpotInterruptAnnotation] != "true" {
		t.Errorf("expected annotation %q=true, got %q",
			spotimds.SpotInterruptAnnotation,
			updated.Annotations[spotimds.SpotInterruptAnnotation])
	}
}

func TestSpotIMDSPoller_NoAnnotationWhenNoInterrupt(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-on-demand"}}
	kc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build()

	poller := &spotimds.Poller{
		NodeName:   "worker-on-demand",
		KubeClient: kc,
		IMDS:       &fakeIMDS{statusCode: http.StatusNotFound},
	}

	// Cancel quickly — no interruption should mean no annotation.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_ = poller.Run(ctx)

	var updated corev1.Node
	_ = kc.Get(context.Background(), client.ObjectKey{Name: "worker-on-demand"}, &updated)
	if updated.Annotations[spotimds.SpotInterruptAnnotation] == "true" {
		t.Error("annotation should not be set when IMDS returns 404")
	}
}
