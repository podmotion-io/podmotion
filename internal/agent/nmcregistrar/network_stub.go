/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build !linux

package nmcregistrar

import "net"

func detectWireGuardInterface(_ *net.IPNet) (string, error) { return "", nil }
func detectIPSecModeCNI(_ *net.IPNet) (bool, error)         { return false, nil }
