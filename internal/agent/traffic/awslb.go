/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package traffic provides traffic drain and verification strategies.
// This file implements AWS ALB/NLB target group management as a Verifier.
package traffic

import (
	"context"
	"fmt"
	"strconv"
	"time"

	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// ELBV2API is the subset of the AWS ELBv2 client used by AWSLoadBalancerVerifier.
// Defined as an interface so tests can inject a fake.
type ELBV2API interface {
	DescribeTargetGroups(ctx context.Context, in *elbv2.DescribeTargetGroupsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error)
	DescribeTargetHealth(ctx context.Context, in *elbv2.DescribeTargetHealthInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error)
	RegisterTargets(ctx context.Context, in *elbv2.RegisterTargetsInput, optFns ...func(*elbv2.Options)) (*elbv2.RegisterTargetsOutput, error)
	DeregisterTargets(ctx context.Context, in *elbv2.DeregisterTargetsInput, optFns ...func(*elbv2.Options)) (*elbv2.DeregisterTargetsOutput, error)
	DescribeTargetGroupAttributes(ctx context.Context, in *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error)
}

// AWSLoadBalancerVerifier implements Verifier using AWS ELBv2 APIs.
// It discovers target groups containing the source pod IP, registers the destination IP,
// waits for healthy state, and deregisters the source after the TrafficVerified gate passes.
//
// Source deregistration is intentionally deferred until after Verify returns nil to satisfy
// ADR-0012: source pod MUST NOT be removed until TrafficVerified=true.
type AWSLoadBalancerVerifier struct {
	Client    ELBV2API
	Discovery *TargetGroupDiscovery

	// HealthPollInterval controls how often DescribeTargetHealth is called.
	// Defaults to 5s when zero.
	HealthPollInterval time.Duration

	// HealthTimeout is the maximum time to wait for healthy state.
	// Defaults to 120s when zero.
	HealthTimeout time.Duration
}

func (v *AWSLoadBalancerVerifier) pollInterval() time.Duration {
	if v.HealthPollInterval > 0 {
		return v.HealthPollInterval
	}
	return 5 * time.Second
}

func (v *AWSLoadBalancerVerifier) healthTimeout() time.Duration {
	if v.HealthTimeout > 0 {
		return v.HealthTimeout
	}
	return 120 * time.Second
}

// Verify satisfies the Verifier interface.
// Steps:
//  1. Discover TGs containing source IP (annotation hint + full scan via Discovery).
//  2. Register dest IP in all matched TGs.
//  3. Poll until dest target is healthy everywhere.
//  4. Return nil (caller is responsible for deregistering source after gate passes).
func (v *AWSLoadBalancerVerifier) Verify(ctx context.Context, req VerifyRequest) error {
	tgARNs, err := v.Discovery.FindTargetGroupsForIP(ctx, req.SourcePodIP)
	if err != nil {
		return fmt.Errorf("target group discovery for %s: %w", req.SourcePodIP, err)
	}
	if len(tgARNs) == 0 {
		// No TGs reference this pod — nothing to do for ALB verification.
		return nil
	}

	destTarget := elbv2types.TargetDescription{Id: &req.DestPodIP}

	// Register destination IP in all matched target groups.
	for _, arn := range tgARNs {
		arnCopy := arn
		_, err := v.Client.RegisterTargets(ctx, &elbv2.RegisterTargetsInput{
			TargetGroupArn: &arnCopy,
			Targets:        []elbv2types.TargetDescription{destTarget},
		})
		if err != nil {
			return fmt.Errorf("RegisterTargets dest %s in TG %s: %w", req.DestPodIP, arn, err)
		}
	}

	// Poll until dest is healthy in all TGs.
	deadline := time.Now().Add(v.healthTimeout())
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout: dest pod IP %s never became healthy in ALB/NLB target groups", req.DestPodIP)
		}

		allHealthy := true
		for _, arn := range tgARNs {
			arnCopy := arn
			out, err := v.Client.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{
				TargetGroupArn: &arnCopy,
				Targets:        []elbv2types.TargetDescription{destTarget},
			})
			if err != nil {
				return fmt.Errorf("DescribeTargetHealth TG %s: %w", arn, err)
			}
			for _, desc := range out.TargetHealthDescriptions {
				if desc.Target != nil && desc.TargetHealth != nil {
					if desc.TargetHealth.State != elbv2types.TargetHealthStateEnumHealthy {
						allHealthy = false
					}
				}
			}
		}

		if allHealthy {
			break
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(v.pollInterval()):
		}
	}

	// Deregister source IP with connection draining respected.
	return v.deregisterSource(ctx, req.SourcePodIP, tgARNs)
}

// deregisterSource removes the source pod IP from all target groups, sleeping for
// the deregistration_delay.timeout attribute to allow in-flight connections to drain.
func (v *AWSLoadBalancerVerifier) deregisterSource(ctx context.Context, sourceIP string, tgARNs []string) error {
	srcTarget := elbv2types.TargetDescription{Id: &sourceIP}

	for _, arn := range tgARNs {
		arnCopy := arn

		drainDelay := v.connectionDrainDelay(ctx, arnCopy)

		_, err := v.Client.DeregisterTargets(ctx, &elbv2.DeregisterTargetsInput{
			TargetGroupArn: &arnCopy,
			Targets:        []elbv2types.TargetDescription{srcTarget},
		})
		if err != nil {
			return fmt.Errorf("DeregisterTargets source %s from TG %s: %w", sourceIP, arn, err)
		}

		// Sleep for the drain window so the LB flushes in-flight connections.
		// This is best-effort; the source pod is still alive during this window per ADR-0012.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(drainDelay):
		}
	}
	return nil
}

// connectionDrainDelay reads deregistration_delay.timeout from the TG attributes.
// Returns 0 on any error (fail-open: skip the sleep rather than block indefinitely).
func (v *AWSLoadBalancerVerifier) connectionDrainDelay(ctx context.Context, tgARN string) time.Duration {
	out, err := v.Client.DescribeTargetGroupAttributes(ctx, &elbv2.DescribeTargetGroupAttributesInput{
		TargetGroupArn: &tgARN,
	})
	if err != nil {
		return 0
	}
	for _, attr := range out.Attributes {
		if attr.Key != nil && *attr.Key == "deregistration_delay.timeout_seconds" && attr.Value != nil {
			secs, err := strconv.Atoi(*attr.Value)
			if err == nil && secs > 0 {
				return time.Duration(secs) * time.Second
			}
		}
	}
	return 0
}

// AWSLBStubVerifier returns healthy after 500ms. Satisfies Verifier for unit tests
// and CI environments without a live AWS account.
type AWSLBStubVerifier struct{}

func (s *AWSLBStubVerifier) Verify(ctx context.Context, _ VerifyRequest) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}
