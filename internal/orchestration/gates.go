// Package orchestration defines the inter-agent interface contracts for PodMotion.
// All pipelines communicate through this package — domain agents never import each other.
// See ADR-0008 (orchestration owns interfaces) and ADR-0016 (gate runner order).
package orchestration

import (
	"context"
	"time"

	migrationv1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

// GateOutcome is the result of a single readiness gate check.
// +kubebuilder:validation:Enum=Pass;Warn;DegradeMode;Block
type GateOutcome string

const (
	GateOutcomePass        GateOutcome = "Pass"
	GateOutcomeWarn        GateOutcome = "Warn"
	GateOutcomeDegradeMode GateOutcome = "DegradeMode" // migration proceeds in degraded mode
	GateOutcomeBlock       GateOutcome = "Block"       // hard stop — migration cannot proceed
)

// GateCategory groups gates by execution cost (see ADR-0016).
type GateCategory string

const (
	GateCategoryNode    GateCategory = "Node"    // microseconds — CR reads
	GateCategoryCompute GateCategory = "Compute" // 2-10s — CRIU probe + /proc
	GateCategoryNetwork GateCategory = "Network" // up to 10s — gRPC pings + CNI API
	GateCategoryStorage GateCategory = "Storage" // up to 30s — Ceph/Longhorn API
)

// GateResult is the result of evaluating a single gate.
type GateResult struct {
	GateID  string
	Outcome GateOutcome
	Message string
	Checked time.Time
	// Degraded fields are set when Outcome==DegradeMode.
	DegradedMigrationMode migrationv1alpha1.MigrationMode
	DegradedNetworkTier   string
}

// Gate is the interface every readiness gate must implement.
// Domain agents register their gates with the GateRunner at startup.
type Gate interface {
	// ID returns a stable identifier for this gate (e.g. "CG-01-CRIU-VERSION").
	ID() string
	// Category determines execution ordering and cost class.
	Category() GateCategory
	// Check evaluates the gate for the given pod, source node, and destination node.
	// Must be context-aware — respect cancellation.
	Check(ctx context.Context, pod *corev1.Pod, sourceNode, destNode string) GateResult
}

// GateSummary is the aggregated result of running all gates.
type GateSummary struct {
	Results               []GateResult
	Blocked               bool
	BlockingGateID        string
	BlockingReason        string
	ResolvedMigrationMode migrationv1alpha1.MigrationMode
	ResolvedNetworkTier   string // TIER_1_FULL | TIER_2_BRIEF_DISRUPTION | TIER_3_GRACEFUL_DRAIN | TIER_4_COLD_MIGRATION
	ResolvedStorageTier   int32  // 0-4
}

// GateRunner executes all registered gates in category order with intra-category parallelism.
// See ADR-0016 for execution order rationale.
type GateRunner interface {
	Register(gates ...Gate)
	Run(ctx context.Context, pod *corev1.Pod, sourceNode, destNode string) GateSummary
}

// ─── Pipeline interfaces ─────────────────────────────────────────────────────
// See ADR-0011 (two-pipeline model) and ADR-0014 (rollback order).

// PipelinePhase is a named phase within a pipeline for crash-safe persistence.
// See ADR-0018 (phase persistence).
type PipelinePhase string

// ComputePipeline is implemented by Agent 1 (CRIU primitives) and Agent 11 (replication loop).
// It owns the memory migration path: iterative pre-copy, freeze, transfer, restore, verify.
type ComputePipeline interface {
	// Checkpoint runs iterative pre-copy rounds then performs final freeze + dump.
	// Writes pipelineConditions: ComputePreCopyComplete, ComputeFrozen.
	Checkpoint(ctx context.Context, opts CheckpointOptions) (CheckpointResult, error)
	// Transfer copies the checkpoint artifact to the destination node.
	// Writes pipelineCondition: CheckpointTransferred.
	Transfer(ctx context.Context, opts TransferOptions) error
	// Restore performs CRIU restore on the destination node.
	// Writes pipelineCondition: ComputeRestored.
	Restore(ctx context.Context, opts RestoreOptions) error
	// Verify checks that the restored pod is healthy.
	// On failure after Handoff: Warn only (ADR-0019).
	Verify(ctx context.Context, podName, namespace string) error
	// Rollback unfreezes/restarts the source pod. Idempotent.
	Rollback(ctx context.Context) error
}

// StoragePipeline is implemented by Agent 3.
// It owns the PVC data migration path, independent of compute (ADR-0011).
type StoragePipeline interface {
	// PreStage begins the async storage mirror (tier-dependent).
	// Tier 0: no-op. Tier 1: Longhorn dual-engine. Tier 2: rbd migrate. Tier 3: snapshot+rsync.
	// Returns immediately; progress reported via SyncStatus channel.
	PreStage(ctx context.Context) (<-chan SyncStatus, error)
	// Sync flushes the final dirty delta after compute freeze.
	Sync(ctx context.Context, targetPercent float64) error
	// Cutover performs the atomic PV binding flip to the destination.
	// Writes pipelineCondition: StorageCutoverComplete.
	Cutover(ctx context.Context) error
	// Cleanup removes source-side mirror artifacts. Non-fatal if it fails — retried via finalizer.
	Cleanup(ctx context.Context) error
	// Rollback abandons the mirror and restores source PV binding. Idempotent.
	Rollback(ctx context.Context) error
}

// NetworkPipeline is implemented by Agent 2 (v0.2+; v0.1 is TIER_4 no-op).
type NetworkPipeline interface {
	// ArmBridge begins async GENEVE tunnel and IP mobility preparation.
	// Returns immediately; status reported via BridgeStatus channel.
	ArmBridge(ctx context.Context) (<-chan BridgeStatus, error)
	// Handoff updates routing rules (gARP / BGP / CNI API) so traffic reaches destination.
	// Writes pipelineCondition: NetworkHandoffComplete.
	Handoff(ctx context.Context) error
	// Teardown removes source-side bridge entries. Non-fatal — retried via finalizer.
	Teardown(ctx context.Context) error
	// Rollback restores source-side routing. Must run BEFORE compute rollback (ADR-0014).
	Rollback(ctx context.Context) error
}

// TrafficPipeline is implemented by Agent 12.
type TrafficPipeline interface {
	// PrepareEndpoints adds the new pod IP to EndpointSlices before removing the old one.
	PrepareEndpoints(ctx context.Context) error
	// Verify waits for traffic to arrive at the new pod (eBPF counter / ALB health / metrics / hook).
	// Returns when TrafficVerified=true or timeoutSeconds exceeded.
	Verify(ctx context.Context, timeoutSeconds int32) error
	// DrainOld stops new connections to the source pod; lets in-flight complete up to drainSeconds.
	DrainOld(ctx context.Context, drainSeconds int32) error
	// DeregisterOld removes the old node from external LB target groups (AWS ALB/NLB).
	DeregisterOld(ctx context.Context) error
}

// ─── Supporting types ────────────────────────────────────────────────────────

type CheckpointOptions struct {
	MigrationName      string
	MaxRounds          int32
	DirtyThresholdMB   int32
	BandwidthLimitMbps int32
	UseTCPRepair       bool // v0.2+
}

type CheckpointResult struct {
	RoundsCompleted     int32
	FinalDirtyPagesMB   int32
	FreezeDurationMs    int64
	CheckpointSHA256    string
	CheckpointSizeBytes int64
}

type TransferOptions struct {
	Mode          string // DirectP2P | Registry
	DestNodeAddr  string
	RegistryRef   string
	BandwidthMbps int32
}

type RestoreOptions struct {
	CheckpointRef string
	DestNodeName  string
	NetworkTier   string
}

type SyncStatus struct {
	Tier              int32
	Phase             string
	SyncPercent       float64
	BytesTotal        int64
	BytesSynced       int64
	EstimatedSecsLeft int32
	Error             error
}

type BridgeStatus struct {
	Armed bool
	Error error
	Mode  string // GENEVE | BGP | GARP | TIER4_NOOP
}

// ─── Condition names ─────────────────────────────────────────────────────────
// These are the three keystone conditions that gate the PreMigrating → Checkpointing
// transition.  They are defined here (orchestration package) so every consumer
// can import a single canonical source of truth without creating import cycles.

const (
	// ConditionMemorySynced is set True by Agent 11 (replication) when dirty pages
	// have converged below the threshold.
	ConditionMemorySynced = "MemorySynced"

	// ConditionStorageReadyForFreeze is set True by Agent 3 (storage) when the PVC
	// mirror has reached ≥95% sync (ADR-0011).
	ConditionStorageReadyForFreeze = "StorageReadyForFreeze"

	// ConditionNetworkBridgeArmed is the third keystone (ADR-0028).
	// In v0.1 (TIER_4, NetworkContinuity=false) it is set True immediately by the
	// controller without loading any eBPF programs.
	// In v0.2+ it is set True by NetworkBridgeAgent after ArmBridge completes.
	ConditionNetworkBridgeArmed = "NetworkBridgeArmed"

	// ── Reserve-before-delete gates (ADR-0046 rev) ─────────────────────────────

	// ConditionCapacityReserved is set True when the destination node has confirmed
	// it can accept the replacement pod (NodeMigrationCapacity slot pre-reserved).
	// Must be True before the source pod is deleted.
	ConditionCapacityReserved = "CapacityReserved"

	// ConditionDestinationVolumeReady is set True when VolumeAttachment.Status.Attached
	// is confirmed for all RWO PVCs on the destination node. For RWX/emptyDir-free pods
	// this is set True immediately. Source pod must not be finally removed until this
	// and TrafficVerified are both True.
	ConditionDestinationVolumeReady = "DestinationVolumeReady"

	// ConditionSchedulingGateRemoved is set True when the controller has removed the
	// "podmotion.io/awaiting-checkpoint" PodSchedulingGate from the replacement pod,
	// unblocking the scheduler to place the pod on the destination node.
	// Only removed after images are staged AND CapacityReserved is True.
	ConditionSchedulingGateRemoved = "SchedulingGateRemoved"

	// ConditionSecurityContextVerified is set True after restore when the restored
	// process's capability sets, seccomp mode, and AppArmor label match the source
	// pod's security context manifest captured at checkpoint time.
	ConditionSecurityContextVerified = "SecurityContextVerified"

	// ConditionDataplaneReconciled is set True when the CNI's data-plane has confirmed
	// the destination pod's endpoint is ready: Calico Felix WEP ActivelyUsed, or
	// CiliumEndpoint.Status.State=="ready". For non-IP-mobility CNIs set immediately.
	// The eBPF hold must not be released until both this and TrafficVerified are True.
	ConditionDataplaneReconciled = "DataplaneReconciled"

	// ConditionAffinityConflict is set True (with reason) when the source pod's owning
	// workload controller has hard nodeAffinity or nodeSelector targeting the source node
	// AND affinityMode=strict. Migration is blocked at Validating with this condition.
	ConditionAffinityConflict = "AffinityConflict"

	// ConditionAntiAffinityConflict is set True when the destination node already hosts
	// a pod that violates the migrating pod's requiredDuringScheduling podAntiAffinity.
	// Migration is blocked at PreMigrating before source pod deletion.
	ConditionAntiAffinityConflict = "AntiAffinityConflict"

	// ConditionPDBAllowsDeletion is set False when a matching PodDisruptionBudget has
	// DisruptionsAllowed==0 and blocks source pod deletion. Set True when all PDBs allow it.
	ConditionPDBAllowsDeletion = "PDBAllowsDeletion"

	// ConditionResourceQuotaCapacity is set False when the namespace's pod ResourceQuota
	// is at capacity and source pod deletion must be deferred to avoid a race window.
	ConditionResourceQuotaCapacity = "ResourceQuotaCapacity"

	// ConditionGitOpsDriftWarning is set True at phase=Complete when the migration
	// succeeded but the owning workload controller's affinity/nodeSelector still targets
	// the source node (affinityMode=strict or affinityMode=ignore). The next rollout or
	// GitOps sync will re-land pods on the original node unless the user updates the spec.
	// Surfaces in kubectl podmotion status as a post-migration warning.
	ConditionGitOpsDriftWarning = "GitOpsDriftWarning"
)

// CutoverCoordinator orchestrates the synchronized cutover across all three pipelines.
// See ADR-0011. Owned by Agent 0A.
type CutoverCoordinator interface {
	// Coordinate blocks until all three pipeline gates are ready, then executes the
	// synchronized freeze → storage cutover → network handoff → restore sequence.
	Coordinate(ctx context.Context, opts CutoverOptions) error
}

type CutoverOptions struct {
	SyncThresholdPercent  float64 // default 95.0
	FreezeTimeoutSeconds  int32   // default 30
	CutoverTimeoutSeconds int32   // default 120
	StorageTier           int32
	NetworkTier           string
}
