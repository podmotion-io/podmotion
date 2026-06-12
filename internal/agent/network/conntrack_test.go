// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network

import (
	"context"
	"testing"
)

func TestArmConntrackNotrack_EmptyPodIP(t *testing.T) {
	err := ArmConntrackNotrack(context.Background(), ConntrackNotrackRule{PodIP: ""})
	if err == nil {
		t.Fatal("expected error for empty PodIP, got nil")
	}
}

func TestDisarmConntrackNotrack_EmptyPodIP(t *testing.T) {
	err := DisarmConntrackNotrack(context.Background(), ConntrackNotrackRule{PodIP: ""})
	if err == nil {
		t.Fatal("expected error for empty PodIP, got nil")
	}
}

func TestIsIptablesNotFound(t *testing.T) {
	if !isIptablesNotFound("No rule matching specified criteria") {
		t.Error("expected true for 'No rule matching'")
	}
	if isIptablesNotFound("") {
		t.Error("expected false for empty string")
	}
}
