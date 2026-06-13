/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build !linux

package network

import (
	"context"
	"fmt"
	"net"
)

// SetPodIPHostRoute is a no-op on non-Linux builds (ADR-0135 handoff route stub).
func SetPodIPHostRoute(_ context.Context, _ string, _ net.IP) error { return nil }

// DeletePodIPHostRoute is a no-op on non-Linux builds (ADR-0135 source cleanup stub).
func DeletePodIPHostRoute(_ context.Context, _ string, _ net.IP) error { return nil }

func InjectMigrationHostRoute(_ net.IP, _ string) error {
	return fmt.Errorf("WireGuard host route injection not supported on non-Linux")
}

func CleanupMigrationHostRoute(_ net.IP, _ string) error {
	return fmt.Errorf("WireGuard host route cleanup not supported on non-Linux")
}

func ConfirmLocalDeliveryRoute(_ net.IP, _ int) (bool, error) {
	return false, fmt.Errorf("route confirmation not supported on non-Linux")
}

func DetectWireGuardInterface(_ *net.IPNet) (string, error) { return "", nil }

func DetectIPSecModeCNI(_ *net.IPNet) (bool, error) { return false, nil }
