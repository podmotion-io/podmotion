/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package utils provides shared helpers for E2E and integration tests.
package utils

import (
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// NewPMClient builds a controller-runtime client with the PodMotion scheme registered.
// Uses KUBECONFIG env or in-cluster config.
func NewPMClient() (client.Client, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = clientcmd.RecommendedHomeFile
	}

	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("building rest config: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := pmv1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	return client.New(restCfg, client.Options{Scheme: scheme})
}
