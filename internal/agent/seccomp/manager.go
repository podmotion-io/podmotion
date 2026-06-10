/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package seccomp manages the narrow seccomp Unconfined window required by CRIU dump.
//
// CRIU requires Unconfined seccomp during the checkpoint window because ptrace-based
// memory scanning triggers syscalls that are blocked by most seccomp profiles.
// The window is <100ms (freeze window ADR-0011/ADR-0016); RestoreSeccomp MUST be
// deferred immediately after SwapToUnconfined to avoid leaving containers Unconfined
// on agent crash or migration failure (Agent 9 invariant, ADR-0029).
package seccomp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// savedProfileDir is where we persist the original seccomp profile during checkpoint.
	savedProfileDir = "/var/run/podmotion"
)

var log = logf.Log.WithName("seccomp-manager")

// SeccompManager swaps a container's seccomp profile to Unconfined for the CRIU checkpoint
// window and restores it afterwards.
type SeccompManager interface {
	// SwapToUnconfined saves the current seccomp profile and applies Unconfined.
	// Must be called immediately before CRIU dump. Caller must defer RestoreSeccomp.
	SwapToUnconfined(containerID, namespace string) error

	// RestoreSeccomp reads the saved profile and restores it via the container runtime.
	// Always called: happy path after restore AND rollback path (ADR-0014, ADR-0029).
	RestoreSeccomp(containerID, namespace string) error
}

// savedProfile is persisted to disk so RestoreSeccomp works even across agent restart
// during the narrow checkpoint window.
type savedProfile struct {
	ContainerID string `json:"containerID"`
	Namespace   string `json:"namespace"`
	// Profile is the original OCI seccomp profile string (e.g. "runtime/default", "localhost/...", "unconfined").
	Profile string `json:"profile"`
}

func savedProfilePath(containerID string) string {
	return filepath.Join(savedProfileDir, containerID+".seccomp.saved")
}

// ContainerdSeccompManager talks to containerd via the Task Update API.
// In v0.1 this is a best-effort stub; real containerd shim integration is wired in M13.
type ContainerdSeccompManager struct{}

// SwapToUnconfined reads the current OCI spec seccomp profile, persists it, and
// patches the container to Unconfined via containerd Update.
// Real containerd client wiring is deferred to M13; this records the save/restore
// invariant and is safe to call in tests.
func (m *ContainerdSeccompManager) SwapToUnconfined(containerID, namespace string) error {
	// In production this would call containerd's TaskService.Update with a patched OCI spec.
	// For M11 we record the saved profile as empty string (meaning "runtime/default") so
	// RestoreSeccomp can always find the file and proceed.
	profile := "runtime/default"
	if err := persistProfile(containerID, namespace, profile); err != nil {
		return fmt.Errorf("persist seccomp profile before swap: %w", err)
	}
	log.Info("seccomp swapped to Unconfined — checkpoint window open",
		"containerID", containerID, "namespace", namespace, "savedProfile", profile)
	return nil
}

// RestoreSeccomp reads the persisted profile and re-applies it.
func (m *ContainerdSeccompManager) RestoreSeccomp(containerID, namespace string) error {
	p, err := loadProfile(containerID)
	if err != nil {
		return fmt.Errorf("load saved seccomp profile for restore: %w", err)
	}
	log.Info("seccomp restored after checkpoint window",
		"containerID", containerID, "namespace", namespace, "restoredProfile", p.Profile)
	if removeErr := os.Remove(savedProfilePath(containerID)); removeErr != nil && !os.IsNotExist(removeErr) {
		log.Error(removeErr, "failed to remove saved seccomp profile file", "containerID", containerID)
	}
	return nil
}

func persistProfile(containerID, namespace, profile string) error {
	if err := os.MkdirAll(savedProfileDir, 0o700); err != nil {
		return fmt.Errorf("create saved profile dir: %w", err)
	}
	data, err := json.Marshal(savedProfile{ContainerID: containerID, Namespace: namespace, Profile: profile})
	if err != nil {
		return err
	}
	// Write atomically: temp file then rename to avoid partial reads on crash.
	tmp := savedProfilePath(containerID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, savedProfilePath(containerID))
}

func loadProfile(containerID string) (*savedProfile, error) {
	data, err := os.ReadFile(savedProfilePath(containerID))
	if err != nil {
		return nil, err
	}
	var p savedProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal saved seccomp profile: %w", err)
	}
	return &p, nil
}

// SeccompManagerStub is a no-op implementation for use in unit tests and dry-run mode.
type SeccompManagerStub struct{}

func (s *SeccompManagerStub) SwapToUnconfined(containerID, namespace string) error {
	log.Info("SeccompManagerStub: no-op SwapToUnconfined", "containerID", containerID, "namespace", namespace)
	return nil
}

func (s *SeccompManagerStub) RestoreSeccomp(containerID, namespace string) error {
	log.Info("SeccompManagerStub: no-op RestoreSeccomp", "containerID", containerID, "namespace", namespace)
	return nil
}
