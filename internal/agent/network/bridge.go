/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package network

import (
	"context"
	"fmt"
	"net"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/orchestration"
)

const (
	// ConditionNetworkBridgeArmed is set on PodMigration when the eBPF zero-window
	// hold and XDP bridge are both active (or when TIER_4 fast-path bypasses them).
	// It is the third keystone alongside MemorySynced and StorageReadyForFreeze.
	// See ADR-0028.
	ConditionNetworkBridgeArmed = "NetworkBridgeArmed"

	// defaultFreezePollInterval is how often NetworkBridgeAgent polls for the
	// MemorySynced condition before disarming the zero-window hold.
	defaultFreezePollInterval = 500 * time.Millisecond
)

// BridgeConfig holds the runtime parameters needed to arm/disarm the bridge.
// All string IPs are standard dotted-decimal or IPv6 text notation.
type BridgeConfig struct {
	// SourceVethIfname is the veth interface name of the source pod on the node
	// (e.g. "veth1a2b3c").  Required for zero-window hold.
	SourceVethIfname string
	// SourcePodIP is the source pod's primary IP address.
	SourcePodIP string
	// DestPodIP is the destination pod's primary IP address (pre-assigned).
	DestPodIP string
	// GenevePort is the UDP port for the GENEVE tunnel (host byte order).
	// Defaults to 6081 (IANA-assigned GENEVE port).
	GenevePort uint16
	// NetworkContinuity mirrors PodMigrationSpec.NetworkContinuity.
	// False → TIER_4 fast-path: NetworkBridgeArmed is set immediately without
	// loading any eBPF programs. (ADR-0028)
	NetworkContinuity bool
}

// NetworkBridgeAgent implements orchestration.NetworkPipeline for v0.1/v0.2.
// In v0.1 (TIER_4, NetworkContinuity=false) all eBPF operations are bypassed and
// NetworkBridgeArmed is set immediately so the gate proceeds to Checkpointing.
// In v0.2 (NetworkContinuity=true) the agent arms zero-window hold, waits for
// the freeze signal from the compute pipeline, then arms the XDP bridge.
type NetworkBridgeAgent struct {
	Client    client.Client
	eBPF      eBPFManager
	Config    BridgeConfig
	Migration *pmv1.PodMigration
}

// NewNetworkBridgeAgent constructs a NetworkBridgeAgent.
// In production the caller passes nil for mgr and it defaults to eBPFManagerStub.
func NewNetworkBridgeAgent(c client.Client, pm *pmv1.PodMigration, cfg BridgeConfig, mgr eBPFManager) *NetworkBridgeAgent {
	if mgr == nil {
		mgr = &eBPFManagerStub{}
	}
	return &NetworkBridgeAgent{
		Client:    c,
		eBPF:      mgr,
		Config:    cfg,
		Migration: pm,
	}
}

// ArmBridge satisfies orchestration.NetworkPipeline.
//
// v0.1 fast-path: immediately sets NetworkBridgeArmed=True and closes the status
// channel without touching any eBPF programs.
//
// v0.2 path: arms zero-window hold on the source veth, waits for the compute
// pipeline to signal freeze (MemorySynced=True), then arms the XDP bridge and
// sets NetworkBridgeArmed=True.
func (a *NetworkBridgeAgent) ArmBridge(ctx context.Context) (<-chan orchestration.BridgeStatus, error) {
	ch := make(chan orchestration.BridgeStatus, 1)

	if !a.Config.NetworkContinuity {
		// ADR-0028: TIER_4 fast-path — cold migration, no TCP preservation needed.
		go func() {
			defer close(ch)
			if err := a.setNetworkBridgeArmed(ctx, true, "TIER4_NOOP"); err != nil {
				ch <- orchestration.BridgeStatus{Armed: false, Error: err, Mode: "TIER4_NOOP"}
				return
			}
			ch <- orchestration.BridgeStatus{Armed: true, Mode: "TIER4_NOOP"}
		}()
		return ch, nil
	}

	// v0.2 path — run as a goroutine so ArmBridge returns immediately.
	go func() {
		defer close(ch)
		if err := a.runBridgeArm(ctx, ch); err != nil {
			ch <- orchestration.BridgeStatus{Armed: false, Error: err, Mode: "GENEVE"}
		}
	}()
	return ch, nil
}

func (a *NetworkBridgeAgent) runBridgeArm(ctx context.Context, ch chan<- orchestration.BridgeStatus) error {
	log := logf.FromContext(ctx)

	ifindex, err := resolveIfindex(a.Config.SourceVethIfname)
	if err != nil {
		return fmt.Errorf("bridge arm: %w", err)
	}

	log.Info("arming zero-window hold", "ifindex", ifindex)
	if err := a.eBPF.ArmZeroWindowHold(ctx, ifindex); err != nil {
		return fmt.Errorf("arm zero-window hold: %w", err)
	}

	// Wait for the compute pipeline to set MemorySynced=True before we arm the
	// XDP bridge — the bridge should only redirect once the pod is frozen so that
	// in-flight packets that arrive after freeze are forwarded to the destination.
	if err := a.waitForFreeze(ctx); err != nil {
		// Disarm the hold before returning so we don't leave senders blocked.
		_ = a.eBPF.DisarmZeroWindowHold(ctx, ifindex)
		return fmt.Errorf("wait for freeze: %w", err)
	}

	srcIP := net.ParseIP(a.Config.SourcePodIP)
	dstIP := net.ParseIP(a.Config.DestPodIP)
	if srcIP == nil || dstIP == nil {
		_ = a.eBPF.DisarmZeroWindowHold(ctx, ifindex)
		return fmt.Errorf("invalid IP: src=%q dst=%q", a.Config.SourcePodIP, a.Config.DestPodIP)
	}

	port := a.Config.GenevePort
	if port == 0 {
		port = 6081
	}

	log.Info("arming XDP bridge", "srcIP", srcIP, "dstIP", dstIP, "genevePort", port)
	if err := a.eBPF.ArmXDPBridge(ctx, srcIP, dstIP, port); err != nil {
		_ = a.eBPF.DisarmZeroWindowHold(ctx, ifindex)
		return fmt.Errorf("arm XDP bridge: %w", err)
	}

	if err := a.setNetworkBridgeArmed(ctx, true, "GENEVE"); err != nil {
		return err
	}
	ch <- orchestration.BridgeStatus{Armed: true, Mode: "GENEVE"}
	return nil
}

// waitForFreeze polls the PodMigration conditions until MemorySynced=True or ctx expires.
func (a *NetworkBridgeAgent) waitForFreeze(ctx context.Context) error {
	log := logf.FromContext(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultFreezePollInterval):
		}

		pm := &pmv1.PodMigration{}
		if err := a.Client.Get(ctx, client.ObjectKeyFromObject(a.Migration), pm); err != nil {
			log.Error(err, "waitForFreeze: Get failed")
			continue
		}
		if meta.IsStatusConditionTrue(pm.Status.Conditions, "MemorySynced") {
			return nil
		}
	}
}

// Handoff satisfies orchestration.NetworkPipeline.
// Updates routing (gARP / CNI API) so that traffic reaches the destination pod.
// In v0.1 this is a no-op because the EndpointSlice manager in Agent 12 handles routing.
func (a *NetworkBridgeAgent) Handoff(ctx context.Context) error {
	logf.FromContext(ctx).Info("NetworkBridgeAgent.Handoff", "networkContinuity", a.Config.NetworkContinuity)
	// gARP / BGP /32 host-route announcement deferred to v0.2.
	return nil
}

// Teardown satisfies orchestration.NetworkPipeline.
// Disarms both eBPF programs.  Non-fatal — retried via finalizer if it fails.
func (a *NetworkBridgeAgent) Teardown(ctx context.Context) error {
	log := logf.FromContext(ctx)
	if !a.Config.NetworkContinuity {
		return nil
	}

	ifindex, err := resolveIfindex(a.Config.SourceVethIfname)
	if err != nil {
		log.Error(err, "Teardown: resolveIfindex failed — interface may already be gone")
		// Interface gone is expected after pod deletion — treat as success.
		return nil
	}

	var errs []error
	if err := a.eBPF.DisarmZeroWindowHold(ctx, ifindex); err != nil {
		errs = append(errs, fmt.Errorf("disarm zero-window: %w", err))
	}
	srcIP := net.ParseIP(a.Config.SourcePodIP)
	if srcIP != nil {
		if err := a.eBPF.DisarmXDPBridge(ctx, srcIP); err != nil {
			errs = append(errs, fmt.Errorf("disarm XDP bridge: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Teardown errors: %v", errs)
	}
	return nil
}

// Rollback satisfies orchestration.NetworkPipeline.
// Must run BEFORE compute rollback (ADR-0014) to restore routing before unfreezing.
func (a *NetworkBridgeAgent) Rollback(ctx context.Context) error {
	logf.FromContext(ctx).Info("NetworkBridgeAgent.Rollback")
	return a.Teardown(ctx)
}

// setNetworkBridgeArmed patches the NetworkBridgeArmed condition on the PodMigration CR.
func (a *NetworkBridgeAgent) setNetworkBridgeArmed(ctx context.Context, armed bool, mode string) error {
	pm := &pmv1.PodMigration{}
	if err := a.Client.Get(ctx, client.ObjectKeyFromObject(a.Migration), pm); err != nil {
		return fmt.Errorf("setNetworkBridgeArmed: Get: %w", err)
	}

	status := metav1.ConditionTrue
	reason := "BridgeArmed"
	msg := fmt.Sprintf("eBPF bridge armed (mode=%s)", mode)
	if !armed {
		status = metav1.ConditionFalse
		reason = "BridgeArmFailed"
		msg = fmt.Sprintf("eBPF bridge arm failed (mode=%s)", mode)
	}

	meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
		Type:               ConditionNetworkBridgeArmed,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: metav1.Now(),
	})
	return a.Client.Status().Update(ctx, pm)
}
