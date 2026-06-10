/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package traffic

import (
	"context"
	"fmt"
	"time"
)

// VerificationMode determines how traffic arrival is confirmed on the destination pod.
// +kubebuilder:validation:Enum=EndpointSlice;AWSALB;Metrics;Hook;None
type VerificationMode string

const (
	VerificationModeEndpointSlice VerificationMode = "EndpointSlice"
	VerificationModeAWSALB        VerificationMode = "AWSALB"
	VerificationModeMetrics       VerificationMode = "Metrics"
	VerificationModeHook          VerificationMode = "Hook"
	VerificationModeMeshSidecar   VerificationMode = "MeshSidecar" // reserved, ADR-0021
	VerificationModeNone          VerificationMode = "None"
)

// VerifyRequest carries everything the verifier needs for one verification attempt.
type VerifyRequest struct {
	Namespace     string
	SourcePodName string
	SourcePodIP   string
	DestPodName   string
	DestPodIP     string
	DestNodeName  string
	// TimeoutSeconds is how long to poll before declaring failure.
	TimeoutSeconds int
	// PollIntervalSeconds controls how often to re-check.
	PollIntervalSeconds int
	// Mode selects the verification strategy.
	Mode VerificationMode
}

// Verifier confirms that live traffic is arriving at the destination pod.
// Source pod MUST NOT be deleted until Verify returns nil.
type Verifier interface {
	Verify(ctx context.Context, req VerifyRequest) error
}

// CompositeVerifier runs EndpointSlice verification always, then the requested
// mode on top. In M3 only EndpointSlice mode is fully implemented.
type CompositeVerifier struct {
	EndpointSliceVerifier Verifier
	AWSALBVerifier        Verifier // nil until M9
	MetricsVerifier       Verifier // nil until M12
	HookVerifier          Verifier // nil until M12
}

func (c *CompositeVerifier) Verify(ctx context.Context, req VerifyRequest) error {
	// EndpointSlice verification always runs first.
	if err := c.EndpointSliceVerifier.Verify(ctx, req); err != nil {
		return fmt.Errorf("EndpointSlice verification failed: %w", err)
	}

	// Mode-specific verification (may be nil stub in early milestones).
	switch req.Mode {
	case VerificationModeAWSALB:
		if c.AWSALBVerifier != nil {
			return c.AWSALBVerifier.Verify(ctx, req)
		}
		return fmt.Errorf("AWSALB verifier not configured (available in M9)")
	case VerificationModeMetrics:
		if c.MetricsVerifier != nil {
			return c.MetricsVerifier.Verify(ctx, req)
		}
		return fmt.Errorf("Metrics verifier not configured (available in M12)")
	case VerificationModeHook:
		if c.HookVerifier != nil {
			return c.HookVerifier.Verify(ctx, req)
		}
		return fmt.Errorf("Hook verifier not configured (available in M12)")
	case VerificationModeNone:
		return nil
	case VerificationModeEndpointSlice, "":
		return nil // already ran above
	default:
		return fmt.Errorf("unknown verification mode %q", req.Mode)
	}
}

// EndpointSliceVerifierImpl polls the EndpointSlice for the destination IP to appear
// with Ready=true. This is the M3 implementation — sufficient for cold migration.
//
// In M5+ the eBPF packet counter verifier supplements this with real traffic counting.
type EndpointSliceVerifierImpl struct {
	Manager *EndpointSliceManager
}

func (e *EndpointSliceVerifierImpl) Verify(ctx context.Context, req VerifyRequest) error {
	timeout := req.TimeoutSeconds
	if timeout <= 0 {
		timeout = 60
	}
	pollInterval := req.PollIntervalSeconds
	if pollInterval <= 0 {
		pollInterval = 3
	}

	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout after %ds: destination pod %q (IP %s) never became Ready in EndpointSlices",
				timeout, req.DestPodName, req.DestPodIP)
		}

		slices, err := e.Manager.findSlicesWithIP(ctx, req.Namespace, req.DestPodIP)
		if err != nil {
			return err
		}
		for _, sl := range slices {
			for _, ep := range sl.Endpoints {
				for _, addr := range ep.Addresses {
					if addr == req.DestPodIP {
						if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
							return nil // destination is endpoint-ready
						}
					}
				}
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(pollInterval) * time.Second):
		}
	}
}

// StubVerifier always succeeds. Used in unit tests and M3 cold migration dry-run.
type StubVerifier struct {
	ReturnError error
	Delay       time.Duration
}

func (s *StubVerifier) Verify(ctx context.Context, _ VerifyRequest) error {
	if s.Delay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.Delay):
		}
	}
	return s.ReturnError
}
