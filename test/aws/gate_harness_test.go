// Package aws_test exercises the AWS gate harness.
//
// Run with:
//
//	go test ./test/aws/... -run TestAWSGateHarness
//
// No AWS credentials are required — tests run in DryRun mode and skip
// automatically when AWS credentials are absent.
package aws

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestAWSGateHarness validates the gate harness structure and adjudication logic.
// It runs in DryRun mode so no AWS credentials are required.
func TestAWSGateHarness(t *testing.T) {
	t.Run("DryRun_SingleGateRun_AllWorkloadsPass", func(t *testing.T) {
		dir := t.TempDir()
		cfg := GateRunConfig{
			ProjectRoot:         dir,
			DryRun:              true,
			MaxRetryPerWorkload: 1,
		}

		// Create the expected directory structure.
		for _, sub := range []string{"test/aws/run_reports", "test/aws/flakiness_log", "internal/controller"} {
			if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", sub, err)
			}
		}

		ctx := context.Background()
		report, err := RunGate(ctx, cfg)
		if err != nil {
			t.Fatalf("RunGate returned error: %v", err)
		}
		if report == nil {
			t.Fatal("RunGate returned nil report")
		}
		if !report.Pass {
			t.Errorf("expected gate run to pass in DryRun mode, got fail: %s",
				report.InvalidationReason)
		}
		if report.RunID == "" {
			t.Error("RunID must not be empty")
		}
		if report.RandomSeed == 0 {
			t.Error("RandomSeed must not be zero")
		}
		if len(report.Assignment) != len(allWorkloads) {
			t.Errorf("expected %d workload assignments, got %d",
				len(allWorkloads), len(report.Assignment))
		}
		if len(report.Results) != len(allWorkloads) {
			t.Errorf("expected %d workload results, got %d",
				len(allWorkloads), len(report.Results))
		}
	})

	t.Run("DryRun_ReportPersistedToDisk", func(t *testing.T) {
		dir := t.TempDir()
		cfg := GateRunConfig{
			ProjectRoot:         dir,
			DryRun:              true,
			MaxRetryPerWorkload: 1,
		}
		for _, sub := range []string{"test/aws/run_reports", "test/aws/flakiness_log", "internal/controller"} {
			if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", sub, err)
			}
		}

		ctx := context.Background()
		report, err := RunGate(ctx, cfg)
		if err != nil {
			t.Fatalf("RunGate: %v", err)
		}

		reportPath := filepath.Join(dir, "test", "aws", "run_reports", report.RunID+".json")
		data, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("report file not found at %s: %v", reportPath, err)
		}

		var loaded RunReport
		if err := json.Unmarshal(data, &loaded); err != nil {
			t.Fatalf("report JSON invalid: %v", err)
		}
		if loaded.RunID != report.RunID {
			t.Errorf("RunID mismatch: got %s want %s", loaded.RunID, report.RunID)
		}
		if !loaded.Pass {
			t.Error("loaded report should be passing")
		}
	})

	t.Run("Adjudication_RSTFailure", func(t *testing.T) {
		results := []WorkloadResult{
			{WorkloadID: W1StatelessWeb, Pass: true, RSTCount: 0},
			{WorkloadID: W2SQLDatabase, Pass: true, RSTCount: 1}, // RST observed → fail
			{WorkloadID: W3RedisKV, Pass: true, RSTCount: 0},
			{WorkloadID: W4MessageBroker, Pass: true, RSTCount: 0},
			{WorkloadID: W5GRPCStreaming, Pass: true, RSTCount: 0},
			{WorkloadID: W6WebSocket, Pass: true, RSTCount: 0},
			{WorkloadID: W7MixedMultiContainer, Pass: true, RSTCount: 0, ConvergenceWindowMs: 200},
			{WorkloadID: W8LongRunningCompute, Pass: true, RSTCount: 0},
		}
		pass, reasons := adjudicateRun(results)
		if pass {
			t.Error("expected adjudication to fail when RST observed")
		}
		found := false
		for _, r := range reasons {
			if containsStr(r, "RST") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected RST reason in fail reasons, got: %v", reasons)
		}
	})

	t.Run("Adjudication_SeqDeltaFailure", func(t *testing.T) {
		results := []WorkloadResult{
			{WorkloadID: W1StatelessWeb, Pass: true, RSTCount: 0, SeqDeltaMax: 42},
			{WorkloadID: W2SQLDatabase, Pass: true, RSTCount: 0},
			{WorkloadID: W3RedisKV, Pass: true, RSTCount: 0},
			{WorkloadID: W4MessageBroker, Pass: true, RSTCount: 0},
			{WorkloadID: W5GRPCStreaming, Pass: true, RSTCount: 0},
			{WorkloadID: W6WebSocket, Pass: true, RSTCount: 0},
			{WorkloadID: W7MixedMultiContainer, Pass: true, RSTCount: 0, ConvergenceWindowMs: 200},
			{WorkloadID: W8LongRunningCompute, Pass: true, RSTCount: 0},
		}
		pass, reasons := adjudicateRun(results)
		if pass {
			t.Error("expected adjudication to fail when seq_delta != 0")
		}
		found := false
		for _, r := range reasons {
			if containsStr(r, "seq_delta") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected seq_delta reason, got: %v", reasons)
		}
	})

	t.Run("Adjudication_W7EnvoyConvergenceExceeded", func(t *testing.T) {
		results := make([]WorkloadResult, len(allWorkloads))
		for i, wid := range allWorkloads {
			results[i] = WorkloadResult{WorkloadID: wid, Pass: true}
		}
		// Set W7 convergence to 1500ms (> 1000ms limit).
		for i := range results {
			if results[i].WorkloadID == W7MixedMultiContainer {
				results[i].ConvergenceWindowMs = 1500
			}
		}
		pass, reasons := adjudicateRun(results)
		if pass {
			t.Error("expected adjudication to fail when W7 convergence exceeds 1s")
		}
		found := false
		for _, r := range reasons {
			if containsStr(r, "Envoy") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected Envoy reason, got: %v", reasons)
		}
	})

	t.Run("Adjudication_MissingWorkload", func(t *testing.T) {
		// Omit W8 — gate must reject a run with missing workloads.
		results := []WorkloadResult{
			{WorkloadID: W1StatelessWeb, Pass: true},
			{WorkloadID: W2SQLDatabase, Pass: true},
			{WorkloadID: W3RedisKV, Pass: true},
			{WorkloadID: W4MessageBroker, Pass: true},
			{WorkloadID: W5GRPCStreaming, Pass: true},
			{WorkloadID: W6WebSocket, Pass: true},
			{WorkloadID: W7MixedMultiContainer, Pass: true, ConvergenceWindowMs: 200},
			// W8 missing
		}
		pass, _ := adjudicateRun(results)
		if pass {
			t.Error("expected adjudication to fail when a workload is missing")
		}
	})

	t.Run("Randomization_CoverageGuarantee", func(t *testing.T) {
		// Run buildAssignment 10 times and verify all 4 instance families
		// and all 3 K8s versions appear in each run.
		for run := 0; run < 10; run++ {
			assignments := buildAssignment()
			ifSeen := map[string]bool{}
			k8sSeen := map[string]bool{}
			for _, a := range assignments {
				ifSeen[a.InstanceFamily] = true
				k8sSeen[a.K8sVersion] = true
			}
			for _, if_ := range instanceFamilies {
				if !ifSeen[if_] {
					t.Errorf("run %d: instance family %s not covered", run, if_)
				}
			}
			for _, k8s := range k8sVersions {
				if !k8sSeen[k8s] {
					t.Errorf("run %d: K8s version %s not covered", run, k8s)
				}
			}
		}
	})

	t.Run("SkipIfAWSCredsAbsent_LiveMode", func(t *testing.T) {
		if os.Getenv("AWS_ACCESS_KEY_ID") == "" && os.Getenv("AWS_PROFILE") == "" {
			t.Skip("skipping live AWS gate run: no AWS credentials in environment")
		}
		// Live mode test is a compile/structure check only in this file.
		// Full live execution requires M27 sprint AWS infrastructure.
		t.Log("AWS credentials present — live gate run would execute here")
	})

	t.Run("ConvergenceWindowConstants_ADR0109", func(t *testing.T) {
		// Validate that convergence window p99 values match ADR-0109 §1.
		cases := map[CNIMode]struct {
			minMs, maxMs int64
		}{
			CNIModeVPCCNI:       {minMs: 5000, maxMs: 5000},
			CNIModeFlannelVXLAN: {minMs: 100, maxMs: 100},
			CNIModeCalicoBGP:    {minMs: 10000, maxMs: 10000},
			CNIModeCiliumENI:    {minMs: 5000, maxMs: 5000},
			CNIModeCiliumTunnel: {minMs: 100, maxMs: 100},
		}
		for cni, expect := range cases {
			got := convergenceWindowP99[cni]
			if got.Milliseconds() != expect.minMs {
				t.Errorf("CNI %s: expected p99=%dms, got %dms", cni, expect.minMs, got.Milliseconds())
			}
		}
	})
}

// containsStr is a helper used instead of strings.Contains to avoid import bloat.
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
