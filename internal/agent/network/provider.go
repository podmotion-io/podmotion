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
// Six core operations are defined by ADR-0143; InjectHostRoute and RemoveHostRoute
// are additional helpers required by ADR-0158.
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
}

// NoOpCNI implements NetworkProvider with no-ops — for tcpPreservationMode=None.
type NoOpCNI struct{}

func (n *NoOpCNI) CanPreserveIP(_ context.Context, _ string) (bool, string, error) {
	return false, "IP handoff not required for tcpPreservationMode=None", nil
}
func (n *NoOpCNI) ArmHold(_ context.Context, _ string) error                           { return nil }
func (n *NoOpCNI) InjectDestinationRoutes(_ context.Context, _, _ string) error        { return nil }
func (n *NoOpCNI) InjectSourceRedirect(_ context.Context, _, _ string) error           { return nil }
func (n *NoOpCNI) ProbeConnectivity(_ context.Context, _ string) error                 { return nil }
func (n *NoOpCNI) DisarmAndCleanup(_ context.Context, _ string) error                  { return nil }
func (n *NoOpCNI) InjectHostRoute(_ context.Context, _, _ string) error                { return nil }
func (n *NoOpCNI) RemoveHostRoute(_ context.Context, _ string) error                   { return nil }

// KindnetProvider implements NetworkProvider for kind/kindnet clusters.
type KindnetProvider struct{}

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
func (k *KindnetProvider) InjectHostRoute(_ context.Context, _, _ string) error {
	return fmt.Errorf("KindnetProvider: not yet implemented")
}
func (k *KindnetProvider) RemoveHostRoute(_ context.Context, _ string) error {
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
