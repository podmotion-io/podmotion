// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package network implements ADR-0143: CNI-agnostic NetworkProvider seam for IP-handoff datapath.
package network

import (
	"context"
	"fmt"
)

// NetworkProvider is the ADR-0143 CNI-agnostic seam for IP-handoff datapath.
// Six core operations are defined by ADR-0143; InjectHostRoute, RemoveHostRoute,
// and InjectGratuitousARP are additional helpers required by ADR-0158.
// WireDestinationVeth is required by ADR-0167 (C1 provider-layer placement).
type NetworkProvider interface {
	CanPreserveIP(ctx context.Context, podIP string) (bool, string, error)
	ArmHold(ctx context.Context, podIP string) error
	InjectDestinationRoutes(ctx context.Context, podIP, nodeIP string) error
	InjectSourceRedirect(ctx context.Context, podIP, destNodeIP string) error
	ProbeConnectivity(ctx context.Context, podIP string) error
	DisarmAndCleanup(ctx context.Context, podIP string) error
	// Additional helpers used by ADR-0158:
	InjectHostRoute(ctx context.Context, podIP, nodeIP string) error
	RemoveHostRoute(ctx context.Context, podIP string) error
	InjectGratuitousARP(ctx context.Context, podIP, ifaceName string) error
	// WireDestinationVeth wires the host-side veth (hostVeth) to the substrate-appropriate
	// upstream on the destination node (ADR-0167 C1 provider-layer placement).
	// On bridge-mode substrates (Flannel, Calico): enslaves hostVeth to bridgeName.
	// On ptp/host-local substrates (kindnet): detects EOPNOTSUPP from enslave attempt,
	// validates the interface is not a degraded bridge (C3), then injects a /32 host route
	// for podIP via hostVeth (C4 structured log on every fall-through).
	// bridgeName is the runtime-discovered host interface name (ADR-0154 Decision 3).
	// migrationName is used only for C4 structured log fields.
	// bringUpFn must be called by the implementation BEFORE injecting the host route so the
	// device is up when RTM_NEWROUTE is issued.
	WireDestinationVeth(ctx context.Context, hostVeth, bridgeName, podIP, migrationName string) error
}

// NoOpCNI implements NetworkProvider with no-ops — for tcpPreservationMode=None.
type NoOpCNI struct{}

func (n *NoOpCNI) CanPreserveIP(_ context.Context, _ string) (bool, string, error) {
	return false, "IP handoff not required for tcpPreservationMode=None", nil
}
func (n *NoOpCNI) ArmHold(_ context.Context, _ string) error                             { return nil }
func (n *NoOpCNI) InjectDestinationRoutes(_ context.Context, _, _ string) error          { return nil }
func (n *NoOpCNI) InjectSourceRedirect(_ context.Context, _, _ string) error             { return nil }
func (n *NoOpCNI) ProbeConnectivity(_ context.Context, _ string) error                   { return nil }
func (n *NoOpCNI) DisarmAndCleanup(_ context.Context, _ string) error                    { return nil }
func (n *NoOpCNI) InjectHostRoute(_ context.Context, _, _ string) error                  { return nil }
func (n *NoOpCNI) RemoveHostRoute(_ context.Context, _ string) error                     { return nil }
func (n *NoOpCNI) InjectGratuitousARP(_ context.Context, _, _ string) error              { return nil }
func (n *NoOpCNI) WireDestinationVeth(_ context.Context, _, _, _, _ string) error        { return nil }

// KindnetProvider implements NetworkProvider for kind/kindnet clusters.
// It discovers the host interface at runtime (ADR-0154 Decision 3) and never
// hardcodes "cni0" (ADR-0158 Decision 5).
type KindnetProvider struct {
	// BridgeIfname is the runtime-discovered host interface name (e.g. "eth0" on kind nodes).
	// If empty, InjectHostRoute and InjectGratuitousARP will return an error.
	BridgeIfname string
}

func (k *KindnetProvider) CanPreserveIP(_ context.Context, _ string) (bool, string, error) {
	return false, "", fmt.Errorf("KindnetProvider: not yet implemented")
}
func (k *KindnetProvider) ArmHold(_ context.Context, _ string) error {
	return fmt.Errorf("KindnetProvider: not yet implemented")
}
func (k *KindnetProvider) InjectDestinationRoutes(_ context.Context, _, _ string) error {
	return fmt.Errorf("KindnetProvider: not yet implemented")
}
func (k *KindnetProvider) InjectSourceRedirect(_ context.Context, _, _ string) error {
	return fmt.Errorf("KindnetProvider: not yet implemented")
}
func (k *KindnetProvider) ProbeConnectivity(_ context.Context, _ string) error {
	return fmt.Errorf("KindnetProvider: not yet implemented")
}
func (k *KindnetProvider) DisarmAndCleanup(_ context.Context, _ string) error {
	return fmt.Errorf("KindnetProvider: not yet implemented")
}

// FlannelProvider is a stub for Flannel — the existing InjectIPHandoff logic will be hoisted here.
type FlannelProvider struct{}

func (f *FlannelProvider) CanPreserveIP(_ context.Context, _ string) (bool, string, error) {
	return false, "", fmt.Errorf("FlannelProvider: not yet implemented")
}
func (f *FlannelProvider) ArmHold(_ context.Context, _ string) error {
	return fmt.Errorf("FlannelProvider: not yet implemented")
}
func (f *FlannelProvider) InjectDestinationRoutes(_ context.Context, _, _ string) error {
	return fmt.Errorf("FlannelProvider: not yet implemented")
}
func (f *FlannelProvider) InjectSourceRedirect(_ context.Context, _, _ string) error {
	return fmt.Errorf("FlannelProvider: not yet implemented")
}
func (f *FlannelProvider) ProbeConnectivity(_ context.Context, _ string) error {
	return fmt.Errorf("FlannelProvider: not yet implemented")
}
func (f *FlannelProvider) DisarmAndCleanup(_ context.Context, _ string) error {
	return fmt.Errorf("FlannelProvider: not yet implemented")
}
func (f *FlannelProvider) InjectHostRoute(_ context.Context, _, _ string) error {
	return fmt.Errorf("FlannelProvider: not yet implemented")
}
func (f *FlannelProvider) RemoveHostRoute(_ context.Context, _ string) error {
	return fmt.Errorf("FlannelProvider: not yet implemented")
}
func (f *FlannelProvider) InjectGratuitousARP(_ context.Context, _, _ string) error {
	return fmt.Errorf("FlannelProvider: not yet implemented")
}
func (f *FlannelProvider) WireDestinationVeth(_ context.Context, hostVeth, bridgeName, _, _ string) error {
	// FlannelProvider: bridge-enslave path — enslaveVethToBridge is the bridge-mode wiring.
	// On bridge-mode substrates EOPNOTSUPP never fires (the target IS a bridge), so the
	// EOPNOTSUPP→host-route fall-through (ADR-0167 C1) is a no-op here.
	return enslaveVethToBridge(hostVeth, bridgeName)
}
