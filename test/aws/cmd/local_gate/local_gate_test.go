//go:build local_gate

package main

import "testing"

func TestLocalGateConfig_Defaults(t *testing.T) {
	cfg := LocalGateConfig{}
	if cfg.ClusterName == "" {
		cfg.ClusterName = "podmotion-gate"
	}
	if cfg.ClusterName != "podmotion-gate" {
		t.Error("default cluster name wrong")
	}
}
