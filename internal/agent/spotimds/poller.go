/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package spotimds polls the AWS Instance Metadata Service for spot termination
// notices and relays them to the operator via a node annotation.
//
// Architecture rationale (ADR-0035): the operator cannot access per-node IMDS endpoints
// directly. The agent runs on the node and is the only process that can reach
// 169.254.169.254. Annotating the Node object is the simplest relay mechanism that
// avoids an EventBridge dependency and keeps the operator decoupled from AWS APIs.
package spotimds

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// IMDSTerminationURL is the AWS IMDS v1 endpoint that returns a timestamp when
	// the instance is scheduled for termination. A 404 means no interruption pending.
	IMDSTerminationURL = "http://169.254.169.254/latest/meta-data/spot/termination-time"

	// SpotInterruptAnnotation is the node annotation set by the agent when it detects
	// a spot termination notice. The SpotReclaimReconciler watches for this annotation.
	SpotInterruptAnnotation = "eks.amazonaws.com/spot-interrupt"

	// PollInterval is the IMDS polling cadence. The 2-minute notice window and
	// 5-second polling gives at least 23 poll attempts before termination.
	PollInterval = 5 * time.Second
)

// IMDSClient is the HTTP interface used to query IMDS, separated so tests can
// inject a fake without binding to a real network.
type IMDSClient interface {
	Get(url string) (*http.Response, error)
}

// Poller polls IMDS and annotates the node on interruption detection.
type Poller struct {
	NodeName   string
	KubeClient client.Client
	IMDS       IMDSClient
}

// NewPoller constructs a Poller with a real HTTP client.
// The IMDS client uses a short timeout: IMDS is link-local and must not block
// the polling loop if the metadata service is temporarily unresponsive.
func NewPoller(nodeName string, kc client.Client) *Poller {
	return &Poller{
		NodeName:   nodeName,
		KubeClient: kc,
		IMDS: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

// Run polls IMDS on PollInterval until ctx is cancelled or interruption is detected.
// After annotating the node it exits — the operator takes over from there.
func (p *Poller) Run(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("spotimds")
	ticker := time.NewTicker(PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			interrupted, err := p.checkIMDS()
			if err != nil {
				log.V(1).Info("IMDS poll error (transient)", "err", err)
				continue
			}
			if interrupted {
				log.Info("Spot interruption notice detected via IMDS", "node", p.NodeName)
				if err := p.annotateNode(ctx); err != nil {
					return fmt.Errorf("annotate node: %w", err)
				}
				return nil
			}
		}
	}
}

// checkIMDS returns true when IMDS reports a pending termination time.
// A 404 response means the instance is not being reclaimed.
func (p *Poller) checkIMDS() (bool, error) {
	resp, err := p.IMDS.Get(IMDSTerminationURL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// annotateNode patches the Node with the spot-interrupt annotation so the
// cluster-scoped SpotReclaimReconciler can react without needing IMDS access.
func (p *Poller) annotateNode(ctx context.Context) error {
	var node corev1.Node
	if err := p.KubeClient.Get(ctx, client.ObjectKey{Name: p.NodeName}, &node); err != nil {
		return err
	}
	patch := client.MergeFrom(node.DeepCopy())
	if node.Annotations == nil {
		node.Annotations = make(map[string]string)
	}
	node.Annotations[SpotInterruptAnnotation] = "true"
	return p.KubeClient.Patch(ctx, &node, patch)
}

// SpotIMDSPollerStub never fires an interruption event. Used when the binary
// runs outside AWS or when IMDS polling is disabled via --enable-spot-reclaim=false.
type SpotIMDSPollerStub struct{}

// Run blocks until ctx is cancelled.
func (s *SpotIMDSPollerStub) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
