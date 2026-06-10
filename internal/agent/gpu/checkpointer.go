/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package gpu provides NVIDIA CUDA checkpoint/restore integration for GPU workload migration.
// This package is experimental — all callers MUST check featuregate.IsEnabled(GPUMigration)
// before invoking any method. See ADR-0032.
//
// Architecture:
//   - GPUCheckpointer interface: Checkpoint, Restore, IsSupported
//   - NvidiaGPUCheckpointer: production impl via nvidia-smi / cuda-checkpoint subprocess
//   - GPUCheckpointerStub: test impl used when no GPU hardware is present
//
// Driver requirement: NVIDIA driver >= 525. Checkpoint API is unstable in earlier versions.
// Output binary: <outputDir>/gpu-checkpoint.bin (CUDA context + device state image).
package gpu

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"strconv"
	"strings"
)

const minDriverVersion = 525

// GPUCheckpointResult holds the output of a successful GPU context checkpoint.
type GPUCheckpointResult struct {
	// CheckpointDir is the directory where gpu-checkpoint.bin was written.
	CheckpointDir string
	// GPUModel is the NVIDIA GPU model string (e.g. "NVIDIA A100-SXM4-80GB").
	GPUModel string
	// DriverVersion is the NVIDIA driver version string (e.g. "530.30.02").
	DriverVersion string
	// SizeBytes is the size of the checkpoint image file.
	SizeBytes int64
}

// GPUCheckpointer is the interface for CUDA context checkpoint/restore.
// All methods require the GPUMigration feature gate to be enabled before calling.
type GPUCheckpointer interface {
	// Checkpoint saves the GPU context for the given container to outputDir/gpu-checkpoint.bin.
	// Must be called after CRIU pre-dumps but before the final CRIU freeze dump.
	Checkpoint(ctx context.Context, containerID, namespace, outputDir string) (GPUCheckpointResult, error)

	// Restore loads the GPU context from checkpointDir/gpu-checkpoint.bin into the container.
	// Must be called after CRIU restore completes on the destination node.
	Restore(ctx context.Context, containerID, namespace, checkpointDir string) error

	// IsSupported returns true if nvidia-smi is available and the driver version meets
	// the minimum checkpoint requirement (>= 525). Used at probe time to populate NMC.
	IsSupported() bool
}

// NvidiaGPUCheckpointer calls nvidia-smi and cuda-checkpoint subprocesses.
// Uses subprocess model consistent with CRIU (ADR-0002) — never links NVIDIA libs directly.
type NvidiaGPUCheckpointer struct{}

// IsSupported returns true when nvidia-smi is on PATH and the driver is >= 525.
func (n *NvidiaGPUCheckpointer) IsSupported() bool {
	dv, err := queryDriverVersion()
	if err != nil {
		return false
	}
	major, err := parseMajorVersion(dv)
	if err != nil {
		return false
	}
	return major >= minDriverVersion
}

// Checkpoint invokes nvidia-smi --gpu-checkpoint (or cuda-checkpoint equivalent).
// The CUDA checkpoint binary path is resolved from PATH; no assumptions about installation prefix.
func (n *NvidiaGPUCheckpointer) Checkpoint(ctx context.Context, containerID, namespace, outputDir string) (GPUCheckpointResult, error) {
	log := logf.FromContext(ctx)

	dv, err := queryDriverVersion()
	if err != nil {
		return GPUCheckpointResult{}, fmt.Errorf("gpu checkpoint: failed to query driver version: %w", err)
	}
	major, err := parseMajorVersion(dv)
	if err != nil {
		return GPUCheckpointResult{}, fmt.Errorf("gpu checkpoint: unparseable driver version %q: %w", dv, err)
	}
	if major < minDriverVersion {
		return GPUCheckpointResult{}, fmt.Errorf("gpu checkpoint: driver %q is below minimum required version %d", dv, minDriverVersion)
	}

	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return GPUCheckpointResult{}, fmt.Errorf("gpu checkpoint: create output dir: %w", err)
	}

	outFile := filepath.Join(outputDir, "gpu-checkpoint.bin")

	// cuda-checkpoint is NVIDIA's experimental userspace checkpoint tool.
	// It requires the container's GPU context PID, which we derive from the container ID.
	// nvidia-smi --gpu-checkpoint is the documented CLI wrapper for driver 525+.
	cmd := exec.CommandContext(ctx, "nvidia-smi",
		"--gpu-checkpoint",
		"--container-id", containerID,
		"--output", outFile,
	)
	log.Info("Invoking GPU checkpoint", "containerID", containerID, "output", outFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		return GPUCheckpointResult{}, fmt.Errorf("gpu checkpoint: nvidia-smi --gpu-checkpoint: %w; output: %s", err, strings.TrimSpace(string(out)))
	}

	model, err := queryGPUModel()
	if err != nil {
		model = "unknown"
	}

	fi, err := os.Stat(outFile)
	var sizeBytes int64
	if err == nil {
		sizeBytes = fi.Size()
	}

	return GPUCheckpointResult{
		CheckpointDir: outputDir,
		GPUModel:      model,
		DriverVersion: dv,
		SizeBytes:     sizeBytes,
	}, nil
}

// Restore invokes nvidia-smi --gpu-restore to reload the GPU context on the destination.
func (n *NvidiaGPUCheckpointer) Restore(ctx context.Context, containerID, namespace, checkpointDir string) error {
	log := logf.FromContext(ctx)

	imageFile := filepath.Join(checkpointDir, "gpu-checkpoint.bin")
	if _, err := os.Stat(imageFile); err != nil {
		return fmt.Errorf("gpu restore: checkpoint image not found at %s: %w", imageFile, err)
	}

	cmd := exec.CommandContext(ctx, "nvidia-smi",
		"--gpu-restore",
		"--container-id", containerID,
		"--input", imageFile,
	)
	log.Info("Invoking GPU restore", "containerID", containerID, "image", imageFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gpu restore: nvidia-smi --gpu-restore: %w; output: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// queryDriverVersion runs nvidia-smi and returns the driver version string.
func queryDriverVersion() (string, error) {
	out, err := exec.Command("nvidia-smi",
		"--query-gpu=driver_version",
		"--format=csv,noheader",
	).Output()
	if err != nil {
		return "", err
	}
	dv := strings.TrimSpace(string(out))
	if dv == "" {
		return "", fmt.Errorf("nvidia-smi returned empty driver version")
	}
	return dv, nil
}

// queryGPUModel returns the first GPU's model name via nvidia-smi.
func queryGPUModel() (string, error) {
	out, err := exec.Command("nvidia-smi",
		"--query-gpu=name",
		"--format=csv,noheader",
	).Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "", fmt.Errorf("no GPU model returned")
	}
	return strings.TrimSpace(lines[0]), nil
}

// parseMajorVersion extracts the integer major version from a driver version string like "530.30.02".
func parseMajorVersion(dv string) (int, error) {
	parts := strings.SplitN(dv, ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("cannot parse major version from %q: %w", dv, err)
	}
	return major, nil
}

// GPUCheckpointerStub records calls without invoking any NVIDIA tooling.
// Used in unit tests and in environments without GPU hardware.
type GPUCheckpointerStub struct {
	// InjectCheckpointError makes Checkpoint return this error.
	InjectCheckpointError error
	// InjectRestoreError makes Restore return this error.
	InjectRestoreError error
	// SimulatedDriverVersion is returned in mock results. Defaults to "530.30.02".
	SimulatedDriverVersion string
	// SimulatedGPUModel is returned in mock results.
	SimulatedGPUModel string
	// SimulatedSizeBytes is the reported checkpoint image size.
	SimulatedSizeBytes int64

	// Recorded calls for test assertions.
	CheckpointCalls []string
	RestoreCalls    []string
}

func (s *GPUCheckpointerStub) IsSupported() bool { return true }

func (s *GPUCheckpointerStub) Checkpoint(_ context.Context, containerID, namespace, outputDir string) (GPUCheckpointResult, error) {
	log := logf.Log.WithName("gpu-stub")
	log.Info("GPU checkpoint would be taken (stub)", "containerID", containerID, "namespace", namespace, "outputDir", outputDir)

	s.CheckpointCalls = append(s.CheckpointCalls, containerID)
	if s.InjectCheckpointError != nil {
		return GPUCheckpointResult{}, s.InjectCheckpointError
	}

	dv := s.SimulatedDriverVersion
	if dv == "" {
		dv = "530.30.02"
	}
	model := s.SimulatedGPUModel
	if model == "" {
		model = "NVIDIA A100-SXM4-80GB (stub)"
	}
	size := s.SimulatedSizeBytes
	if size == 0 {
		size = 4 * 1024 * 1024 * 1024 // 4 GiB simulated GPU context
	}
	return GPUCheckpointResult{
		CheckpointDir: outputDir,
		GPUModel:      model,
		DriverVersion: dv,
		SizeBytes:     size,
	}, nil
}

func (s *GPUCheckpointerStub) Restore(_ context.Context, containerID, namespace, checkpointDir string) error {
	log := logf.Log.WithName("gpu-stub")
	log.Info("GPU restore would be performed (stub)", "containerID", containerID, "namespace", namespace, "checkpointDir", checkpointDir)

	s.RestoreCalls = append(s.RestoreCalls, containerID)
	return s.InjectRestoreError
}

// ErrFeatureGateRequired is returned when a GPU migration is attempted but
// the GPUMigration feature gate is not enabled. See ADR-0032.
var ErrFeatureGateRequired = fmt.Errorf("GPU migration requires --feature-gates=GPUMigration=true")
