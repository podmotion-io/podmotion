//go:build aws_e2e

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package e2e contains end-to-end tests requiring a live cluster.
// Tests in this file require an AWS EKS cluster with ALB controller installed.
// They are gated by the aws_e2e build tag so they never run in standard CI.
package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/podmotion-io/podmotion/internal/agent/traffic"
)

var _ = Describe("AWS ALB/NLB traffic verification", func() {
	Context("AWSLBStubVerifier", func() {
		It("returns nil after ~500ms simulating healthy target", func() {
			v := &traffic.AWSLBStubVerifier{}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			start := time.Now()
			err := v.Verify(ctx, traffic.VerifyRequest{
				SourcePodIP: "10.0.1.1",
				DestPodIP:   "10.0.1.2",
				Mode:        traffic.VerificationModeAWSALB,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(time.Since(start)).To(BeNumerically(">=", 400*time.Millisecond))
		})

		It("respects context cancellation", func() {
			v := &traffic.AWSLBStubVerifier{}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			err := v.Verify(ctx, traffic.VerifyRequest{
				SourcePodIP: "10.0.1.1",
				DestPodIP:   "10.0.1.2",
				Mode:        traffic.VerificationModeAWSALB,
			})
			Expect(err).To(HaveOccurred())
		})
	})

	Context("CompositeVerifier with AWSALB slot", func() {
		It("routes AWSALB mode to AWSLBStubVerifier", func() {
			cv := &traffic.CompositeVerifier{
				EndpointSliceVerifier: &traffic.StubVerifier{},
				AWSALBVerifier:        &traffic.AWSLBStubVerifier{},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := cv.Verify(ctx, traffic.VerifyRequest{
				Mode: traffic.VerificationModeAWSALB,
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
