/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build linux

package nmcregistrar

import (
	"net"

	"github.com/podmotion-io/podmotion/internal/agent/network"
)

func detectWireGuardInterface(podCIDR *net.IPNet) (string, error) {
	return network.DetectWireGuardInterface(podCIDR)
}

func detectIPSecModeCNI(podCIDR *net.IPNet) (bool, error) {
	return network.DetectIPSecModeCNI(podCIDR)
}
