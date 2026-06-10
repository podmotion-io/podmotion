/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package featuregate provides opt-in feature gating for experimental PodMotion capabilities.
// Gates are configured via --feature-gates=<Gate>=true on the operator binary.
// No gate is enabled by default — experimental features require explicit operator opt-in.
package featuregate

import (
	"fmt"
	"strings"
	"sync"
)

// FeatureGate names an experimental feature that must be explicitly enabled.
type FeatureGate string

const (
	// GPUMigration gates NVIDIA CUDA checkpoint/restore support.
	// Permanently disabled by default — CUDA checkpoint is an experimental NVIDIA feature
	// with driver constraints (525+) and potential instability under workload. See ADR-0032.
	GPUMigration FeatureGate = "GPUMigration"
)

// DefaultGates defines the default enabled state for each gate.
// All experimental gates default to false — explicit operator opt-in required.
var DefaultGates = map[FeatureGate]bool{
	GPUMigration: false,
}

var (
	mu      sync.RWMutex
	enabled = copyDefaults()
)

func copyDefaults() map[FeatureGate]bool {
	m := make(map[FeatureGate]bool, len(DefaultGates))
	for k, v := range DefaultGates {
		m[k] = v
	}
	return m
}

// IsEnabled returns true if the given gate is currently enabled.
func IsEnabled(gate FeatureGate) bool {
	mu.RLock()
	defer mu.RUnlock()
	return enabled[gate]
}

// Set enables or disables a single gate. Called during operator flag parsing.
func Set(gate FeatureGate, value bool) error {
	mu.Lock()
	defer mu.Unlock()
	if _, known := DefaultGates[gate]; !known {
		return fmt.Errorf("unknown feature gate %q", gate)
	}
	enabled[gate] = value
	return nil
}

// ParseFlags parses a comma-separated list of Key=value pairs (e.g. "GPUMigration=true").
// Suitable for use as a flag.Value implementation target.
func ParseFlags(s string) error {
	for _, token := range strings.Split(s, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid feature gate %q: expected Key=true|false", token)
		}
		gate := FeatureGate(strings.TrimSpace(parts[0]))
		switch strings.TrimSpace(parts[1]) {
		case "true":
			if err := Set(gate, true); err != nil {
				return err
			}
		case "false":
			if err := Set(gate, false); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid feature gate value %q: must be true or false", parts[1])
		}
	}
	return nil
}

// Reset restores all gates to their defaults. Primarily for test isolation.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	enabled = copyDefaults()
}
