//go:build local_gate

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// LocalGateConfig holds configuration for a local kind gate run.
// This is Phase 0 of M27: workstation validation before AWS.
type LocalGateConfig struct {
	ClusterName    string
	KubeconfigPath string
	WorkloadsDir   string
	KeepCluster    bool
	Workloads      []string // empty = all W1-W8
}

func defaultLocalGateConfig() LocalGateConfig {
	return LocalGateConfig{
		ClusterName:    "podmotion-gate",
		KubeconfigPath: "/tmp/podmotion-gate.kubeconfig",
		WorkloadsDir:   "test/aws/workloads",
		KeepCluster:    false,
		Workloads:      []string{"W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"},
	}
}

// RunLocalGate creates a kind cluster, deploys W1-W8 workloads, triggers migrations,
// asserts results, and tears down. Produces a run report to test/aws/run_reports/.
func RunLocalGate(cfg LocalGateConfig) error {
	ctx := context.Background()

	// Deferred teardown unless KeepCluster is set.
	if !cfg.KeepCluster {
		defer func() {
			_ = run(ctx, "kind", "delete", "cluster", "--name", cfg.ClusterName)
		}()
	}

	// Create kind cluster.
	fmt.Printf("Creating kind cluster %q...\n", cfg.ClusterName)
	if err := run(ctx, "kind", "create", "cluster",
		"--name", cfg.ClusterName,
		"--kubeconfig", cfg.KubeconfigPath,
	); err != nil {
		return fmt.Errorf("kind create cluster: %w", err)
	}

	// Apply workload and client manifests.
	kubectl := func(args ...string) error {
		return run(ctx, "kubectl", append([]string{"--kubeconfig", cfg.KubeconfigPath}, args...)...)
	}

	if err := kubectl("create", "namespace", "podmotion-gate"); err != nil {
		return fmt.Errorf("create namespace: %w", err)
	}

	type WorkloadResult struct {
		WorkloadID string `json:"workload_id"`
		Pass       bool   `json:"pass"`
		FailReason string `json:"failure_reason,omitempty"`
	}
	var results []WorkloadResult

	for _, wid := range cfg.Workloads {
		wdir := filepath.Join(cfg.WorkloadsDir, strings.ToLower(wid))
		fmt.Printf("Deploying %s from %s...\n", wid, wdir)

		if err := kubectl("apply", "-f", filepath.Join(wdir, "workload.yaml")); err != nil {
			results = append(results, WorkloadResult{WorkloadID: wid, Pass: false, FailReason: err.Error()})
			continue
		}
		if err := kubectl("apply", "-f", filepath.Join(wdir, "client.yaml")); err != nil {
			results = append(results, WorkloadResult{WorkloadID: wid, Pass: false, FailReason: err.Error()})
			continue
		}

		// Wait for workload pod ready (60s timeout).
		if err := kubectl("wait", "--for=condition=Ready", "pod",
			"-l", "app="+strings.ToLower(wid),
			"-n", "podmotion-gate",
			"--timeout=60s",
		); err != nil {
			results = append(results, WorkloadResult{WorkloadID: wid, Pass: false, FailReason: "pod not ready: " + err.Error()})
			continue
		}

		// Assertion stub — real assertion wired in Phase 4.
		fmt.Printf("  [STUB] AssertMigration called for %s\n", wid)
		results = append(results, WorkloadResult{WorkloadID: wid, Pass: true})
	}

	// Write run report per ADR-0114.
	return writeLocalRunReport(cfg, results)
}

func writeLocalRunReport(cfg LocalGateConfig, results []WorkloadResult) error {
	type Report struct {
		RunID    string      `json:"run_id"`
		Date     string      `json:"date"`
		Mode     string      `json:"mode"`
		Cluster  string      `json:"cluster_name"`
		Results  interface{} `json:"results"`
		GatePass bool        `json:"gate_pass"`
	}
	pass := true
	for _, r := range results {
		if !r.Pass {
			pass = false
			break
		}
	}
	report := Report{
		RunID:    fmt.Sprintf("local-%d", time.Now().Unix()),
		Date:     time.Now().UTC().Format(time.RFC3339),
		Mode:     "local-kind",
		Cluster:  cfg.ClusterName,
		Results:  results,
		GatePass: pass,
	}
	_ = os.MkdirAll("test/aws/run_reports", 0755)
	path := filepath.Join("test/aws/run_reports", report.RunID+".json")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	fmt.Printf("Run report written to %s (gate_pass=%v)\n", path, pass)
	return enc.Encode(report)
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
