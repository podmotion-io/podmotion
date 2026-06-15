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

//go:build !linux

// Package network provides stubs for non-Linux platforms (ADR-0158 KindnetProvider).
package network

import (
	"context"
	"fmt"
)

func (k *KindnetProvider) InjectHostRoute(_ context.Context, _, _ string) error {
	return fmt.Errorf("KindnetProvider.InjectHostRoute: only supported on Linux")
}

func (k *KindnetProvider) RemoveHostRoute(_ context.Context, _ string) error {
	return fmt.Errorf("KindnetProvider.RemoveHostRoute: only supported on Linux")
}

func (k *KindnetProvider) InjectGratuitousARP(_ context.Context, _, _ string) error {
	return fmt.Errorf("KindnetProvider.InjectGratuitousARP: only supported on Linux")
}

func (k *KindnetProvider) WireDestinationVeth(_ context.Context, _, _, _, _ string) error {
	return fmt.Errorf("KindnetProvider.WireDestinationVeth: only supported on Linux")
}

// SendGratuitousARP is a no-op stub on non-Linux platforms.
func SendGratuitousARP(_ context.Context, _, _ string) error {
	return fmt.Errorf("SendGratuitousARP: only supported on Linux")
}
