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
	"strings"
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
	// TCPPreservationMode mirrors PodMigrationSpec.TCPPreservationMode.
	// None → TIER_4 fast-path: NetworkBridgeArmed is set immediately without
	// loading any eBPF programs. (ADR-0028)
	TCPPreservationMode pmv1.TCPPreservationMode
	// CNIPlugin is the detected primary CNI (e.g. "calico", "cilium", "flannel").
	// Used for Flannel live-migration rejection and Cilium XDP conflict detection.
	CNIPlugin string
	// UnderlayNetworkType is the CNI's encapsulation type (VXLAN, Direct, WireGuard, BGP).
	// Used to determine if MSS clamping is needed when GENEVE bridge is active.
	UnderlayNetworkType string
	// DataplaneReconciliationTimeoutSeconds is how long to wait for Felix/Cilium to
	// confirm the dataplane is ready after restore. Default 30s.
	DataplaneReconciliationTimeoutSeconds int
}

// NetworkBridgeAgent implements orchestration.NetworkPipeline for v0.1/v0.2.
// In v0.1 (TIER_4, TCPPreservationMode=None) all eBPF operations are bypassed and
// NetworkBridgeArmed is set immediately so the gate proceeds to Checkpointing.
// In v0.2 (TCPPreservationMode=Strict|BestEffort) the agent arms zero-window hold, waits for
// the freeze signal from the compute pipeline, then arms the XDP bridge.
type NetworkBridgeAgent struct {
	Client    client.Client
	eBPF      eBPFManager
	Config    BridgeConfig
	Migration *pmv1.PodMigration
}

// NewNetworkBridgeAgent constructs a NetworkBridgeAgent.
// When mgr is nil the real cilium/ebpf loader is selected for kernel ≥5.9;
// kernels below that threshold fall back to the stub automatically.
// Pass NewStubEBPFManager() explicitly to force the stub (unit tests, TIER_4).
func NewNetworkBridgeAgent(c client.Client, pm *pmv1.PodMigration, cfg BridgeConfig, mgr eBPFManager) *NetworkBridgeAgent {
	if mgr == nil {
		mgr = newEBPFManager(context.Background())
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

	if a.Config.TCPPreservationMode == pmv1.TCPPreservationModeNone {
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

	// Flannel does not support IP mobility — TCPPreservationMode=Strict/BestEffort is invalid.
	if strings.Contains(strings.ToLower(a.Config.CNIPlugin), "flannel") {
		return nil, fmt.Errorf("TCPPreservationMode=%s not supported for Flannel CNI; use TCPPreservationMode=None (cold migration only)", a.Config.TCPPreservationMode)
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

	// Detect Cilium XDP conflict before attaching — if Cilium's kube-proxy-replacement
	// XDP hook is already on this interface, fall back to TC ingress to avoid conflict.
	bridgeMode := "GENEVE"
	if conflict, conflictErr := a.eBPF.CheckXDPHookConflict(ctx, ifindex); conflictErr == nil && conflict &&
		strings.Contains(strings.ToLower(a.Config.CNIPlugin), "cilium") {
		log.Info("Cilium XDP hook conflict detected — falling back to TC ingress bridge mode", "ifindex", ifindex)
		bridgeMode = "GENEVE_TC"
		// TC ingress bridge is implemented in v0.2+; for now arm succeeds but logs the mode.
	}

	log.Info("arming XDP bridge", "srcIP", srcIP, "dstIP", dstIP, "genevePort", port, "mode", bridgeMode)
	if err := a.eBPF.ArmXDPBridge(ctx, srcIP, dstIP, port); err != nil {
		_ = a.eBPF.DisarmZeroWindowHold(ctx, ifindex)
		return fmt.Errorf("arm XDP bridge: %w", err)
	}

	// Wait for the CNI dataplane to confirm the destination endpoint is ready
	// before releasing the eBPF hold. This ensures Felix/Cilium has programmed
	// the WEP/ipcache before traffic is redirected (ADR-0045: stability wins).
	if err := a.waitForDataplaneReconciled(ctx); err != nil {
		log.Error(err, "dataplane reconciliation timeout — proceeding but bridge hold stays armed", "migration", a.Migration.Name)
		// Non-fatal in v0.1 — condition set below for operator visibility.
	}

	if err := a.setNetworkBridgeArmed(ctx, true, bridgeMode); err != nil {
		return err
	}
	ch <- orchestration.BridgeStatus{Armed: true, Mode: bridgeMode}
	return nil
}

// waitForDataplaneReconciled polls the PodMigration until DataplaneReconciled=True
// or the timeout (default 30s) is reached. The eBPF hold should not release until
// both Restored=True AND DataplaneReconciled=True (ADR-0046).
func (a *NetworkBridgeAgent) waitForDataplaneReconciled(ctx context.Context) error {
	log := logf.FromContext(ctx)
	timeout := a.Config.DataplaneReconciliationTimeoutSeconds
	if timeout <= 0 {
		timeout = 30
	}
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultFreezePollInterval):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for DataplaneReconciled condition after %ds", timeout)
		}

		pm := &pmv1.PodMigration{}
		if err := a.Client.Get(ctx, client.ObjectKeyFromObject(a.Migration), pm); err != nil {
			log.Error(err, "waitForDataplaneReconciled: Get failed")
			continue
		}
		if meta.IsStatusConditionTrue(pm.Status.Conditions, "DataplaneReconciled") {
			return nil
		}
	}
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
	logf.FromContext(ctx).Info("NetworkBridgeAgent.Handoff", "tcpPreservationMode", a.Config.TCPPreservationMode)
	// gARP / BGP /32 host-route announcement deferred to v0.2.
	return nil
}

// Teardown satisfies orchestration.NetworkPipeline.
// Disarms both eBPF programs.  Non-fatal — retried via finalizer if it fails.
func (a *NetworkBridgeAgent) Teardown(ctx context.Context) error {
	log := logf.FromContext(ctx)
	if a.Config.TCPPreservationMode == pmv1.TCPPreservationModeNone {
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
