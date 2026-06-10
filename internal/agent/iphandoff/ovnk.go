/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package iphandoff implements CNI-specific IP mobility strategies used to preserve
// a pod's IP address when it moves to a different node.
//
// Each strategy implements IPHandoffStrategy. The CNIMobilitySelector in selector.go
// picks the right implementation based on the detected CNI plugin reported in the NMC.
package iphandoff

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// ovnIPAMClaimGVR is the GroupVersionResource for ovn-kubernetes IPAMClaim.
// The CRD is registered by the OVN-Kubernetes operator; we reference it via the
// dynamic client to avoid importing the ovn-kubernetes module (which pulls in heavy deps).
var ovnIPAMClaimGVR = schema.GroupVersionResource{
	Group:    "k8s.ovn.org",
	Version:  "v1",
	Resource: "ipamclaims",
}

// OVNKHandoff implements IPHandoffStrategy for OVN-Kubernetes clusters.
// It creates an IPAMClaim for the destination pod using the source pod's IP,
// then deletes the source claim after traffic is verified.
//
// IPAMClaim is a v0.5+ OVN-Kubernetes feature that lets a pod request a specific
// IP allocation. We create the claim before the destination pod exists so the IP
// is reserved.
type OVNKHandoff struct {
	DynamicClient dynamic.Interface
}

// Reserve creates an IPAMClaim in the given namespace that pins podIP to destPodName.
// This must be called before the destination pod is created so the IP is held.
func (o *OVNKHandoff) Reserve(ctx context.Context, namespace, destPodName, podIP string) error {
	claim := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "k8s.ovn.org/v1",
			"kind":       "IPAMClaim",
			"metadata": map[string]interface{}{
				"name":      destPodName,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"network":   "default",
				"interface": "eth0",
				// requestedIP pins the specific address to satisfy IP mobility requirement.
				"requestedIP": podIP,
			},
		},
	}

	_, err := o.DynamicClient.Resource(ovnIPAMClaimGVR).Namespace(namespace).Create(ctx, claim, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create IPAMClaim %s/%s for IP %s: %w", namespace, destPodName, podIP, err)
	}
	return nil
}

// ReleaseSource deletes the source pod's IPAMClaim after TrafficVerified=true.
// Deletion after verification ensures the source IP is only freed once the
// destination has confirmed live traffic receipt (ADR-0012).
func (o *OVNKHandoff) ReleaseSource(ctx context.Context, namespace, sourcePodName string) error {
	err := o.DynamicClient.Resource(ovnIPAMClaimGVR).Namespace(namespace).Delete(ctx, sourcePodName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("delete source IPAMClaim %s/%s: %w", namespace, sourcePodName, err)
	}
	return nil
}

func (o *OVNKHandoff) Name() string { return "ovnk-ipamclaim" }
