// Package aws implements the AWS gate run harness for PodMotion NS5-Beta.
//
// This harness orchestrates the M27 qualification gate run and is built to
// M28 standards (80-run scored gate) per ADR-0110. It covers:
//   - EKS managed and self-managed EC2 cluster topology
//   - Randomized axes: AZ, instance family, K8s version, CNI
//   - 8 workload types (W1–W8)
//   - Pass/fail adjudication per ADR-0110 §4
//   - Run report serialization to test/aws/run_reports/
//   - Flakiness log to test/aws/flakiness_log/
//
// ADR references: ADR-0109 (EKS routing convergence), ADR-0110 (gate topology/adjudication)
package aws

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ─── Topology constants ────────────────────────────────────────────────────────

// ClusterType identifies the cluster provisioning model.
type ClusterType string

const (
	ClusterTypeEKS         ClusterType = "eks"
	ClusterTypeSelfManaged ClusterType = "self-managed"
)

// CNIMode identifies the active CNI plugin per ADR-0109.
type CNIMode string

const (
	CNIModeVPCCNI      CNIMode = "aws-vpc-cni"
	CNIModeFlannelVXLAN CNIMode = "flannel-vxlan"
	CNIModeCalicoBGP   CNIMode = "calico-bgp"
	CNIModeCiliumENI   CNIMode = "cilium-eni"
	CNIModeCiliumTunnel CNIMode = "cilium-tunnel"
)

// Convergence window p99 per ADR-0109 §1.
var convergenceWindowP99 = map[CNIMode]time.Duration{
	CNIModeVPCCNI:       5 * time.Second,
	CNIModeFlannelVXLAN: 100 * time.Millisecond,
	CNIModeCalicoBGP:    10 * time.Second,
	CNIModeCiliumENI:    5 * time.Second,
	CNIModeCiliumTunnel: 100 * time.Millisecond,
}

// ─── Randomization axes (ADR-0110 §2) ─────────────────────────────────────────

var (
	availabilityZones = []string{"us-east-1a", "us-east-1b", "us-east-1c"}
	instanceFamilies  = []string{"m7g.large", "c7g.large", "m7i.large", "c7i.large"}
	k8sVersions       = []string{"1.32", "1.31", "1.30"} // N, N-1, N-2
	cniModes          = []CNIMode{CNIModeVPCCNI, CNIModeFlannelVXLAN, CNIModeCalicoBGP}
	clusterTypes      = []ClusterType{ClusterTypeEKS, ClusterTypeSelfManaged}
)

// ─── Workload registry (ADR-0110 §3) ──────────────────────────────────────────

// WorkloadID identifies a workload type.
type WorkloadID string

const (
	W1StatelessWeb      WorkloadID = "W1"
	W2SQLDatabase       WorkloadID = "W2"
	W3RedisKV           WorkloadID = "W3"
	W4MessageBroker     WorkloadID = "W4"
	W5GRPCStreaming      WorkloadID = "W5"
	W6WebSocket         WorkloadID = "W6"
	W7MixedMultiContainer WorkloadID = "W7"
	W8LongRunningCompute WorkloadID = "W8"
)

// allWorkloads is the ordered list of all 8 required workload IDs.
var allWorkloads = []WorkloadID{
	W1StatelessWeb, W2SQLDatabase, W3RedisKV, W4MessageBroker,
	W5GRPCStreaming, W6WebSocket, W7MixedMultiContainer, W8LongRunningCompute,
}

// workloadDescriptions maps each workload ID to its human description.
var workloadDescriptions = map[WorkloadID]string{
	W1StatelessWeb:        "HTTP/1.1 or HTTP/2 server; continuous GET during migration",
	W2SQLDatabase:         "PostgreSQL with active read+write transactions; persistent TCP",
	W3RedisKV:             "Redis GET/SET pipeline; persistent TCP",
	W4MessageBroker:       "NATS/RabbitMQ persistent subscriber/publisher; messages in flight",
	W5GRPCStreaming:       "Bidirectional gRPC stream; zero gap assertion",
	W6WebSocket:           "WebSocket server; long-lived connections; frame count assertion",
	W7MixedMultiContainer: "App + Envoy sidecar; Envoy resumes within 1s of restore",
	W8LongRunningCompute:  "CPU-bound; in-memory state hash verified pre/post migration",
}

// ─── Report types (ADR-0110 §5) ───────────────────────────────────────────────

// WorkloadAssignment records the randomized axis values for a single workload slot.
type WorkloadAssignment struct {
	WorkloadID     WorkloadID  `json:"workloadID"`
	AZ             string      `json:"az"`
	InstanceFamily string      `json:"instanceFamily"`
	K8sVersion     string      `json:"k8sVersion"`
	CNI            CNIMode     `json:"cni"`
	ClusterType    ClusterType `json:"clusterType"`
}

// WorkloadResult records the outcome of a single workload migration.
type WorkloadResult struct {
	WorkloadID          WorkloadID `json:"workloadID"`
	Pass                bool       `json:"pass"`
	RSTCount            int        `json:"rstCount"`
	SeqDeltaMax         int64      `json:"seqDeltaMax"`
	MigrationDurationMs int64      `json:"migrationDurationMs"`
	FreezeWindowMs      int64      `json:"freezeWindowMs"`
	ConvergenceWindowMs int64      `json:"convergenceWindowMs"`
	ErrorMessage        string     `json:"errorMessage,omitempty"`
}

// FlakEvent records a transient failure that was retried and passed.
type FlakEvent struct {
	WorkloadID   WorkloadID `json:"workloadID"`
	AttemptNum   int        `json:"attemptNum"`
	ErrorMessage string     `json:"errorMessage"`
	RetriedAt    time.Time  `json:"retriedAt"`
}

// RunReport is the full artifact for one gate run (ADR-0110 §5).
type RunReport struct {
	RunID       string               `json:"runID"`
	StartTime   time.Time            `json:"startTime"`
	EndTime     time.Time            `json:"endTime"`
	RandomSeed  int64                `json:"randomSeed"`
	Assignment  []WorkloadAssignment `json:"assignment"`
	Results     []WorkloadResult     `json:"results"`
	FlakinesLog []FlakEvent          `json:"flakinessLog"`
	// Pass is true iff all 8 workloads passed with no RST and seq_delta==0.
	Pass bool `json:"pass"`
	// InvalidationReason is non-empty if the run is auto-invalidated per §6.
	InvalidationReason string `json:"invalidationReason,omitempty"`
}

// ─── Adjudication (ADR-0110 §4) ───────────────────────────────────────────────

// adjudicateRun inspects all WorkloadResults and applies M27/M28 pass criteria:
//   - All 8 workload types present and passed.
//   - For each workload: RSTCount == 0 and SeqDeltaMax == 0 (TCP workloads W1–W7).
//   - For W8: pass flag set (state hash check).
//   - For W7: ConvergenceWindowMs <= 1000 (Envoy resumes within 1s).
func adjudicateRun(results []WorkloadResult) (pass bool, failReasons []string) {
	resultByID := make(map[WorkloadID]WorkloadResult, len(results))
	for _, r := range results {
		resultByID[r.WorkloadID] = r
	}

	for _, wid := range allWorkloads {
		r, ok := resultByID[wid]
		if !ok {
			failReasons = append(failReasons,
				fmt.Sprintf("%s: missing — workload was skipped (gate invalidated)", wid))
			continue
		}
		if !r.Pass {
			msg := fmt.Sprintf("%s: failed", wid)
			if r.ErrorMessage != "" {
				msg += " — " + r.ErrorMessage
			}
			failReasons = append(failReasons, msg)
		}
		if r.RSTCount != 0 {
			failReasons = append(failReasons,
				fmt.Sprintf("%s: RST observed (count=%d)", wid, r.RSTCount))
		}
		// SeqDelta check applies to TCP workloads W1–W7.
		if wid != W8LongRunningCompute && r.SeqDeltaMax != 0 {
			failReasons = append(failReasons,
				fmt.Sprintf("%s: seq_delta != 0 (max=%d)", wid, r.SeqDeltaMax))
		}
		// W7: Envoy must resume within 1s.
		if wid == W7MixedMultiContainer && r.ConvergenceWindowMs > 1000 {
			failReasons = append(failReasons,
				fmt.Sprintf("W7: Envoy proxy convergence exceeded 1s (%dms)", r.ConvergenceWindowMs))
		}
	}

	return len(failReasons) == 0, failReasons
}

// ─── Invalidation check (ADR-0110 §6) ─────────────────────────────────────────

// validateGatePrerequisites checks the static invalidation conditions that can be
// evaluated without AWS access. Returns a non-empty reason string if invalid.
func validateGatePrerequisites(projectRoot string) string {
	// Check: controller package must not contain unwired RPC stubs.
	controllerDir := filepath.Join(projectRoot, "internal", "controller")
	if count := grepCount(controllerDir, "RPCNotWired"); count > 0 {
		return fmt.Sprintf("controller package contains %d RPCNotWired stub(s)", count)
	}
	return ""
}

// grepCount returns the number of lines in Go files under dir that contain substr.
func grepCount(dir, substr string) int {
	count := 0
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, substr) {
				count++
			}
		}
		return nil
	})
	return count
}

// ─── Randomization helpers ─────────────────────────────────────────────────────

// cryptoRandInt64 returns a cryptographically random int64 seed.
func cryptoRandInt64() int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		// Fallback: use nanosecond timestamp — still unpredictable in practice.
		return time.Now().UnixNano()
	}
	return n.Int64()
}

// randomIndex returns a pseudo-random index into [0, n) using crypto/rand.
func randomIndex(n int) int {
	if n <= 1 {
		return 0
	}
	r, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(r.Int64())
}

// buildAssignment generates a randomized WorkloadAssignment for each workload.
// Each axis is drawn independently per ADR-0110 §2. The assignment ensures that
// all 4 instance families and all 3 K8s versions appear at least once across the
// 8 workload slots (pigeonhole: 8 slots >= max(4,3)).
func buildAssignment() []WorkloadAssignment {
	// Shuffle instance families and K8s versions to ensure full coverage.
	ifCopy := make([]string, len(instanceFamilies))
	copy(ifCopy, instanceFamilies)
	k8sCopy := make([]string, len(k8sVersions))
	copy(k8sCopy, k8sVersions)

	shuffleStrings(ifCopy)
	shuffleStrings(k8sCopy)

	assignments := make([]WorkloadAssignment, len(allWorkloads))
	for i, wid := range allWorkloads {
		az := availabilityZones[randomIndex(len(availabilityZones))]
		instanceFamily := ifCopy[i%len(ifCopy)]
		k8sVersion := k8sCopy[i%len(k8sCopy)]
		cni := cniModes[randomIndex(len(cniModes))]
		ct := clusterTypes[randomIndex(len(clusterTypes))]

		// aws-vpc-cni is only valid on EKS clusters; self-managed uses Flannel or Calico.
		if ct == ClusterTypeSelfManaged && cni == CNIModeVPCCNI {
			cni = CNIModeFlannelVXLAN
		}
		if ct == ClusterTypeEKS && (cni == CNIModeFlannelVXLAN || cni == CNIModeCalicoBGP) {
			cni = CNIModeVPCCNI
		}

		assignments[i] = WorkloadAssignment{
			WorkloadID:     wid,
			AZ:             az,
			InstanceFamily: instanceFamily,
			K8sVersion:     k8sVersion,
			CNI:            cni,
			ClusterType:    ct,
		}
	}
	return assignments
}

// shuffleStrings performs an in-place Fisher-Yates shuffle using crypto/rand.
func shuffleStrings(s []string) {
	for i := len(s) - 1; i > 0; i-- {
		j := randomIndex(i + 1)
		s[i], s[j] = s[j], s[i]
	}
}

// ─── Report persistence ────────────────────────────────────────────────────────

// projectRoot returns the absolute path to the podmotion module root.
// Determined at compile time via runtime.Caller.
func detectProjectRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	// file is <root>/test/aws/gate_harness.go — root is 3 levels up.
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// saveReport writes the RunReport as JSON to test/aws/run_reports/<runID>.json.
func saveReport(report *RunReport, projectRoot string) error {
	dir := filepath.Join(projectRoot, "test", "aws", "run_reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir run_reports: %w", err)
	}
	path := filepath.Join(dir, report.RunID+".json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// saveFlakLog writes flak events as JSON to test/aws/flakiness_log/<runID>.json.
func saveFlakLog(runID string, events []FlakEvent, projectRoot string) error {
	if len(events) == 0 {
		return nil
	}
	dir := filepath.Join(projectRoot, "test", "aws", "flakiness_log")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir flakiness_log: %w", err)
	}
	path := filepath.Join(dir, runID+".json")
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal flak log: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// ─── Gate run orchestration ────────────────────────────────────────────────────

// GateRunConfig holds configuration for a gate run.
type GateRunConfig struct {
	// ProjectRoot is the absolute path to the podmotion module root.
	// If empty, detectProjectRoot() is used.
	ProjectRoot string

	// DryRun skips actual AWS API calls and cluster operations.
	// Workload results are synthesized with Pass=true for harness validation.
	DryRun bool

	// MaxRetryPerWorkload is the number of times a failing workload is retried
	// before being recorded as a hard failure. Default 1 (no retry).
	MaxRetryPerWorkload int

	// M28Mode enables M28 scored gate adjudication. In M28 mode, any single
	// workload failure causes the entire run to fail with no partial credit.
	M28Mode bool
}

// RunGate executes one complete gate run per ADR-0110 and returns the RunReport.
// It is the single entry point for both M27 and M28 gate runs.
func RunGate(ctx context.Context, cfg GateRunConfig) (*RunReport, error) {
	projectRoot := cfg.ProjectRoot
	if projectRoot == "" {
		projectRoot = detectProjectRoot()
	}
	if cfg.MaxRetryPerWorkload < 1 {
		cfg.MaxRetryPerWorkload = 1
	}

	report := &RunReport{
		RunID:      uuid.New().String(),
		StartTime:  time.Now().UTC(),
		RandomSeed: cryptoRandInt64(),
	}

	// ── Invalidation pre-check (ADR-0110 §6) ──────────────────────────────────
	if reason := validateGatePrerequisites(projectRoot); reason != "" {
		report.InvalidationReason = reason
		report.EndTime = time.Now().UTC()
		return report, fmt.Errorf("gate run invalidated: %s", reason)
	}

	// ── Randomized assignment ──────────────────────────────────────────────────
	report.Assignment = buildAssignment()

	// ── Execute workloads ──────────────────────────────────────────────────────
	var results []WorkloadResult
	var flakEvents []FlakEvent

	for _, assignment := range report.Assignment {
		result, flaks, err := runWorkloadWithRetry(ctx, assignment, cfg)
		if err != nil {
			// Non-retriable infrastructure failure → invalidate run.
			report.EndTime = time.Now().UTC()
			report.InvalidationReason = fmt.Sprintf(
				"infrastructure failure during %s: %v", assignment.WorkloadID, err)
			return report, fmt.Errorf("gate run invalidated: %w", err)
		}
		results = append(results, result)
		flakEvents = append(flakEvents, flaks...)
	}

	report.Results = results
	report.FlakinesLog = flakEvents

	// ── Adjudication (ADR-0110 §4) ────────────────────────────────────────────
	pass, failReasons := adjudicateRun(results)
	report.Pass = pass
	if !pass {
		report.InvalidationReason = strings.Join(failReasons, "; ")
	}

	report.EndTime = time.Now().UTC()

	// ── Persist artifacts ──────────────────────────────────────────────────────
	if err := saveReport(report, projectRoot); err != nil {
		return report, fmt.Errorf("save run report: %w", err)
	}
	if err := saveFlakLog(report.RunID, flakEvents, projectRoot); err != nil {
		return report, fmt.Errorf("save flakiness log: %w", err)
	}

	return report, nil
}

// runWorkloadWithRetry executes a single workload migration, retrying transient
// failures up to cfg.MaxRetryPerWorkload times. Flak events are recorded for
// each failed attempt that was subsequently retried and passed.
func runWorkloadWithRetry(
	ctx context.Context,
	assignment WorkloadAssignment,
	cfg GateRunConfig,
) (WorkloadResult, []FlakEvent, error) {
	var lastResult WorkloadResult
	var flaks []FlakEvent

	for attempt := 1; attempt <= cfg.MaxRetryPerWorkload; attempt++ {
		result, infraErr := executeWorkload(ctx, assignment, cfg.DryRun)
		if infraErr != nil {
			// Infrastructure failure (node termination, API server unavailability) —
			// propagate upward to invalidate the entire run per ADR-0110 §4.
			return WorkloadResult{}, flaks, infraErr
		}

		lastResult = result

		if result.Pass && result.RSTCount == 0 {
			// Success — if this was a retry, record the prior attempt as a flak.
			if attempt > 1 {
				flaks = append(flaks, FlakEvent{
					WorkloadID:   assignment.WorkloadID,
					AttemptNum:   attempt,
					ErrorMessage: "retried and passed",
					RetriedAt:    time.Now().UTC(),
				})
			}
			return result, flaks, nil
		}

		// Transient failure on a non-final attempt → record as flak and retry.
		if attempt < cfg.MaxRetryPerWorkload {
			flaks = append(flaks, FlakEvent{
				WorkloadID:   assignment.WorkloadID,
				AttemptNum:   attempt,
				ErrorMessage: result.ErrorMessage,
				RetriedAt:    time.Now().UTC(),
			})
		}
	}

	return lastResult, flaks, nil
}

// executeWorkload runs a single workload migration against AWS infrastructure.
//
// In DryRun mode it synthesizes a passing result for harness validation.
// In live mode it:
//  1. Provisions (or reuses) a cluster matching the assignment's ClusterType.
//  2. Deploys the workload pod and client on separate nodes.
//  3. Starts the client load generator.
//  4. Triggers a PodMigration CR and waits for completion.
//  5. Collects eBPF ring buffer RST counts and tcpdump seq_delta.
//  6. For W8: verifies in-memory state hash.
//  7. For W7: verifies Envoy convergence within 1s.
//  8. Tears down the workload (cluster teardown happens at gate level).
//
// TODO(M27): implement live AWS execution path — stub returns DryRun results.
func executeWorkload(
	ctx context.Context,
	assignment WorkloadAssignment,
	dryRun bool,
) (WorkloadResult, error) {
	if dryRun {
		return synthesizeDryRunResult(assignment), nil
	}

	// ── Live AWS execution path ─────────────────────────────────────────────
	// Phase 1: cluster provisioning / selection.
	// Phase 2: workload deployment.
	// Phase 3: client load generation start.
	// Phase 4: PodMigration trigger.
	// Phase 5: migration wait + metric collection.
	// Phase 6: workload-specific assertions.
	// Phase 7: workload teardown.
	//
	// This path requires AWS credentials and EKS/EC2 permissions.
	// The live implementation is scaffolded here and will be filled in
	// during the M27 gate run execution sprint.
	return WorkloadResult{
		WorkloadID:   assignment.WorkloadID,
		Pass:         false,
		ErrorMessage: "live AWS execution not yet implemented — re-run with DryRun=true or implement M27 execution path",
	}, nil
}

// synthesizeDryRunResult returns a plausible passing WorkloadResult for harness
// validation and CI compile checks.
func synthesizeDryRunResult(assignment WorkloadAssignment) WorkloadResult {
	// Simulate realistic timing ranges per CNI convergence windows (ADR-0109).
	convWindow := convergenceWindowP99[assignment.CNI]
	convMs := convWindow.Milliseconds() / 3 // simulate ~p50

	result := WorkloadResult{
		WorkloadID:          assignment.WorkloadID,
		Pass:                true,
		RSTCount:            0,
		SeqDeltaMax:         0,
		MigrationDurationMs: 750 + convMs,
		FreezeWindowMs:      85, // target <100ms (ADR-0049)
		ConvergenceWindowMs: convMs,
	}

	// W7: Envoy convergence must be <= 1000ms — synthesize 250ms.
	if assignment.WorkloadID == W7MixedMultiContainer {
		result.ConvergenceWindowMs = 250
	}

	return result
}

// ─── M28 Scored Gate (80-run) ──────────────────────────────────────────────────

// M28GateResult is the aggregate result of the M28 80-run scored gate.
type M28GateResult struct {
	TotalRuns    int
	PassedRuns   int
	FailedRuns   int
	PassCounter  int // current consecutive pass streak (resets to 0 on any failure)
	RunReports   []*RunReport
	GatePassed   bool // true iff PassCounter reaches 80
}

// RunM28Gate executes the M28 scored 80-run gate per ADR-0110 §4.
// Any single run failure resets the pass counter to zero.
// The gate passes only when 80 consecutive runs pass.
//
// This is a long-running operation (estimated 20–40 hours wall time).
// It respects ctx cancellation for early termination.
func RunM28Gate(ctx context.Context, cfg GateRunConfig) (*M28GateResult, error) {
	const requiredConsecutivePasses = 80
	cfg.M28Mode = true

	agg := &M28GateResult{}

	for agg.PassCounter < requiredConsecutivePasses {
		select {
		case <-ctx.Done():
			return agg, ctx.Err()
		default:
		}

		report, err := RunGate(ctx, cfg)
		agg.TotalRuns++

		if err != nil {
			// Infrastructure failure — do not count; log and continue.
			agg.FailedRuns++
			agg.PassCounter = 0
			continue
		}

		agg.RunReports = append(agg.RunReports, report)

		if report.Pass && report.InvalidationReason == "" {
			agg.PassedRuns++
			agg.PassCounter++
		} else {
			agg.FailedRuns++
			agg.PassCounter = 0
		}
	}

	agg.GatePassed = agg.PassCounter >= requiredConsecutivePasses
	return agg, nil
}
