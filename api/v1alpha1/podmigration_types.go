/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TCPPreservationMode controls how the operator handles active TCP connections during migration.
// +kubebuilder:validation:Enum=Strict;BestEffort;None
type TCPPreservationMode string

const (
	// TCPPreservationModeStrict requires full TCP sequence continuity. If
	// TCPSequenceContinuityVerified=False after restore, the operator triggers hard rollback.
	// See ADR-0019 Amendment A.
	TCPPreservationModeStrict TCPPreservationMode = "Strict"
	// TCPPreservationModeBestEffort attempts TCP preservation but emits a warning condition
	// instead of rolling back when TCPSequenceContinuityVerified=False.
	TCPPreservationModeBestEffort TCPPreservationMode = "BestEffort"
	// TCPPreservationModeNone skips the TCPVerifying phase entirely. Stateless workloads only.
	TCPPreservationModeNone TCPPreservationMode = "None"
)

// ApplicationProbeProtocol selects the liveness/readiness probe used by ApplicationProbeSpec.
// +kubebuilder:validation:Enum=SQL;HTTP;gRPC;TCP
type ApplicationProbeProtocol string

const (
	ApplicationProbeProtocolSQL  ApplicationProbeProtocol = "SQL"
	ApplicationProbeProtocolHTTP ApplicationProbeProtocol = "HTTP"
	ApplicationProbeProtocolGRPC ApplicationProbeProtocol = "gRPC"
	ApplicationProbeProtocolTCP  ApplicationProbeProtocol = "TCP"
)

// ApplicationProbeSpec defines a post-restore application-level health check.
type ApplicationProbeSpec struct {
	// Protocol selects the probe type.
	// +kubebuilder:validation:Required
	Protocol ApplicationProbeProtocol `json:"protocol"`

	// Port is the target port for HTTP, gRPC, and TCP probes.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty"`

	// Path is the HTTP path for HTTP probes (e.g. "/healthz").
	// +optional
	Path string `json:"path,omitempty"`

	// Query is the SQL query for SQL probes (e.g. "SELECT 1").
	// +optional
	Query string `json:"query,omitempty"`

	// GRPCService is the fully-qualified gRPC service name for gRPC probes.
	// +optional
	GRPCService string `json:"grpcService,omitempty"`

	// TimeoutSeconds is the probe deadline. Defaults to 5.
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	// +optional
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`
}

// MigrationMode controls the memory transfer strategy.
// +kubebuilder:validation:Enum=PreCopy;PostCopy;Cold
type MigrationMode string

const (
	// MigrationModePreCopy iteratively copies dirty memory pages while the pod
	// continues running, resulting in a short final freeze window (<100ms).
	MigrationModePreCopy MigrationMode = "PreCopy"
	// MigrationModePostCopy freezes the pod immediately, transfers a minimal
	// checkpoint, then faults pages on-demand at the destination. Requires
	// CONFIG_USERFAULTFD=y on the destination node kernel.
	MigrationModePostCopy MigrationMode = "PostCopy"
	// MigrationModeCold freezes the pod for the entire checkpoint-and-transfer
	// sequence. Simplest migration path but incurs the highest downtime.
	MigrationModeCold MigrationMode = "Cold"
)

// StorageStrategy overrides automatic storage tier selection.
// +kubebuilder:validation:Enum=Auto;Skip;Sync;SnapshotClone;DualEngine
type StorageStrategy string

const (
	// StorageStrategyAuto detects the storage class and selects the appropriate
	// tier (0–4) automatically. This is the default strategy.
	StorageStrategyAuto StorageStrategy = "Auto"
	// StorageStrategySkip re-attaches RWX volumes on the destination node without
	// migrating volume data. No data movement occurs.
	StorageStrategySkip StorageStrategy = "Skip"
	// StorageStrategySync migrates data via rsync over SSH for non-CSI storage
	// classes (tier 3).
	StorageStrategySync StorageStrategy = "Sync"
	// StorageStrategySnapshotClone migrates data using a CSI VolumeSnapshot
	// followed by a volume clone (tier 2).
	StorageStrategySnapshotClone StorageStrategy = "SnapshotClone"
	// StorageStrategyDualEngine migrates data using Longhorn dual-engine live
	// replication, enabling live volume migration with no I/O interruption (tier 1).
	StorageStrategyDualEngine StorageStrategy = "DualEngine"
)

// MigrationPhase represents the current phase of a PodMigration.
// The 12-phase pipeline replaces the earlier 8-phase pipeline per ADR-0047.
// +kubebuilder:validation:Enum=Pending;SocketInventory;Validating;DestinationPrewarm;PreCopyMemory;ZeroWindowArm;FinalFreezeStateCapture;OverlayHandoff;RestoreSocketReattach;DisengageHold;TCPVerifying;ServiceVerifying;CutoverComplete;Complete;Failed;RollingBack;DryRunComplete
type MigrationPhase string

const (
	MigrationPhasePending        MigrationPhase = "Pending"
	MigrationPhaseValidating     MigrationPhase = "Validating"
	MigrationPhasePreMigrating   MigrationPhase = "PreMigrating"
	MigrationPhaseCheckpointing  MigrationPhase = "Checkpointing"
	MigrationPhaseTransferring   MigrationPhase = "Transferring"
	MigrationPhaseRestoring      MigrationPhase = "Restoring"
	MigrationPhaseVerifying      MigrationPhase = "Verifying"
	MigrationPhaseComplete       MigrationPhase = "Complete"
	MigrationPhaseFailed         MigrationPhase = "Failed"
	MigrationPhaseRollingBack    MigrationPhase = "RollingBack"
	MigrationPhaseDryRunComplete MigrationPhase = "DryRunComplete"

	// 12-phase pipeline phases per ADR-0047 (TCP-first migration architecture).
	// These replace the 8-phase pipeline for TCPPreservationMode=Strict/BestEffort.
	// TCPPreservationMode=None degenerates through the subset of phases that apply
	// to stateless workloads (SocketInventory and TCPVerifying are skipped).
	MigrationPhaseSocketInventory        MigrationPhase = "SocketInventory"
	MigrationPhaseDestinationPrewarm     MigrationPhase = "DestinationPrewarm"
	MigrationPhasePreCopyMemory          MigrationPhase = "PreCopyMemory"
	MigrationPhaseZeroWindowArm          MigrationPhase = "ZeroWindowArm"
	MigrationPhaseFinalFreezeStateCapture MigrationPhase = "FinalFreezeStateCapture"
	MigrationPhaseOverlayHandoff         MigrationPhase = "OverlayHandoff"
	MigrationPhaseRestoreSocketReattach  MigrationPhase = "RestoreSocketReattach"
	MigrationPhaseDisengageHold          MigrationPhase = "DisengageHold"
	MigrationPhaseTCPVerifying           MigrationPhase = "TCPVerifying"
	MigrationPhaseServiceVerifying       MigrationPhase = "ServiceVerifying"
	MigrationPhaseCutoverComplete        MigrationPhase = "CutoverComplete"
)

// AffinityMode controls how PodMotion handles hard nodeAffinity and nodeSelector rules
// that pin the source pod to its current node.
// +kubebuilder:validation:Enum=strict;patch;ignore
type AffinityMode string

const (
	// AffinityModeStrict rejects the migration at admission if the owning workload controller
	// has requiredDuringSchedulingIgnoredDuringExecution nodeAffinity or nodeSelector targeting
	// the source node. The user must clear the affinity before migrating. Default.
	AffinityModeStrict AffinityMode = "strict"

	// AffinityModePatch allows migration to proceed and patches the owning workload controller's
	// affinity/nodeSelector at phase=Complete to reflect the destination node.
	// Requires affinityMode=patch AND GitOpsAwareness.enabled=true (the patch fires inside
	// the GitOps suspension window). See ADR-0046-C1. Post-beta only.
	AffinityModePatch AffinityMode = "patch"

	// AffinityModeIgnore proceeds without patching. The workload spec remains dirty — use
	// only for statically-owned pods with no GitOps controller and no future rollouts.
	AffinityModeIgnore AffinityMode = "ignore"
)

// PodMigrationSpec defines the desired state of PodMigration.
type PodMigrationSpec struct {
	// PodName is the name of the source pod to migrate.
	// +kubebuilder:validation:Required
	PodName string `json:"podName"`

	// PodNamespace is the namespace of the source pod.
	// +kubebuilder:validation:Required
	PodNamespace string `json:"podNamespace"`

	// SourcePodUID pins the migration to a specific pod UID to prevent races.
	// +optional
	SourcePodUID string `json:"sourcePodUID,omitempty"`

	// TargetNodeName pins the destination node. If empty, the scheduler plugin selects.
	// +optional
	TargetNodeName string `json:"targetNodeName,omitempty"`

	// MigrationPolicyRef is the owning MigrationPolicy (may be empty for manual migrations).
	// +optional
	MigrationPolicyRef *corev1.LocalObjectReference `json:"migrationPolicyRef,omitempty"`

	// Mode controls the memory transfer strategy.
	// +kubebuilder:default=PreCopy
	Mode MigrationMode `json:"mode,omitempty"`

	// PreCopyMaxRounds is the maximum number of iterative pre-dump rounds before forced final freeze.
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=20
	PreCopyMaxRounds int32 `json:"preCopyMaxRounds,omitempty"`

	// PreCopyDirtyThresholdMB triggers the final freeze when remaining dirty pages drop below this value.
	// +kubebuilder:default=64
	// +kubebuilder:validation:Minimum=1
	PreCopyDirtyThresholdMB int32 `json:"preCopyDirtyThresholdMB,omitempty"`

	// BandwidthLimitMbps caps per-migration transfer bandwidth. 0 means unlimited.
	// +kubebuilder:default=0
	// +kubebuilder:validation:Minimum=0
	BandwidthLimitMbps int32 `json:"bandwidthLimitMbps,omitempty"`

	// CompletionTimeoutSeconds aborts the migration if not complete within this window.
	// +kubebuilder:default=600
	// +kubebuilder:validation:Minimum=30
	CompletionTimeoutSeconds int32 `json:"completionTimeoutSeconds,omitempty"`

	// StorageStrategy overrides automatic storage tier classification.
	// +kubebuilder:default=Auto
	StorageStrategy StorageStrategy `json:"storageStrategy,omitempty"`

	// TCPPreservationMode controls TCP connection continuity behavior during migration.
	// Strict triggers hard rollback if TCPSequenceContinuityVerified=False (ADR-0019 Amendment A).
	// BestEffort emits a warning condition only.
	// None skips the TCPVerifying phase entirely (stateless workloads).
	// +kubebuilder:default=None
	TCPPreservationMode TCPPreservationMode `json:"tcpPreservationMode,omitempty"`

	// FreezeWindowBudgetMs is the maximum allowed wall-clock milliseconds for the full
	// ZW-arm-to-ZW-disarm critical path (ADR-0049). Migrations that exceed this budget
	// are aborted and the source pod is thawed.
	// +kubebuilder:default=500
	// +kubebuilder:validation:Minimum=50
	// +kubebuilder:validation:Maximum=10000
	FreezeWindowBudgetMs int32 `json:"freezeWindowBudgetMs,omitempty"`

	// ApplicationProbe is an optional post-restore application-level health check.
	// When set, the operator executes this probe before declaring phase=Complete.
	// +optional
	ApplicationProbe *ApplicationProbeSpec `json:"applicationProbe,omitempty"`

	// DryRun runs the estimation pipeline only; does not touch the running pod.
	// +kubebuilder:default=false
	DryRun bool `json:"dryRun,omitempty"`

	// RollbackOnFailure unfreezes and restarts the source pod if migration fails post-checkpoint.
	// +kubebuilder:default=true
	RollbackOnFailure bool `json:"rollbackOnFailure,omitempty"`

	// DestinationCluster is reserved for future multi-cluster migration (post-v1.0).
	// Leave empty for intra-cluster migrations (the only supported mode in v0.x and v1.x).
	// +optional
	DestinationCluster string `json:"destinationCluster,omitempty"`

	// DestinationNode is the pre-selected destination node for the replacement pod.
	// Set by the controller after capacity reservation; read by the scheduler plugin
	// and MutatingAdmissionWebhook to enforce exclusive node placement.
	// +optional
	DestinationNode string `json:"destinationNode,omitempty"`

	// SourcePodIP is the original IP of the source pod. Injected as a CNI IPAM
	// annotation on the replacement pod at admission so the original IP is pinned
	// at CNI ADD time (Calico / Cilium only; Flannel does not support IP mobility).
	// +optional
	SourcePodIP string `json:"sourcePodIP,omitempty"`

	// AffinityMode controls how PodMotion handles hard nodeAffinity / nodeSelector rules
	// on the owning workload controller that pin pods to the source node.
	// strict: reject at admission (default, safe for GitOps environments).
	// patch: patch the Deployment/StatefulSet affinity at phase=Complete (requires M19 Part B).
	// ignore: proceed without patching (standalone pods, no GitOps).
	// +kubebuilder:default=strict
	// +optional
	AffinityMode AffinityMode `json:"affinityMode,omitempty"`
}

// Operator-facing status condition type constants for PodMigration.
// These are set on PodMigrationStatus.Conditions by the network and TCP reconcile phases.
// Authoritative vocabulary (all 11 types, CamelCase Reasons per K8s conventions):
// docs/adr/conditions-vocabulary.md
const (
	// ConditionSocketInventoryComplete is True when the source pod socket table has
	// been fully enumerated and all TCP 4-tuples recorded.
	ConditionSocketInventoryComplete = "SocketInventoryComplete"
	// ConditionDestinationNetnsReady is True when the pre-staged migration netns on
	// the destination node is configured with the correct IP and routing (ADR-0048).
	ConditionDestinationNetnsReady = "DestinationNetnsReady"
	// ConditionZeroWindowArmed is True when the TC-BPF zero-window hold program has
	// been loaded and armed on the source pod's veth (ADR-0049).
	ConditionZeroWindowArmed = "ZeroWindowArmed"
	// ConditionZeroWindowDisarmed is True when the TC-BPF zero-window hold has been
	// successfully disarmed after FinalFreeze. The condition message carries the
	// arm-to-disarm hold duration in milliseconds for budget verification (ADR-0049).
	ConditionZeroWindowDisarmed = "ZeroWindowDisarmed"
	// ConditionVXLANFDBUpdated is True when the two-sided AF_BRIDGE FDB and AF_INET
	// neighbor entries have been injected on both nodes (ADR-0048).
	ConditionVXLANFDBUpdated = "VXLANFDBUpdated"
	// ConditionTCPSequenceContinuityVerified is True when all migrated connections
	// have been confirmed to have seq_delta=0 post-restore (ADR-0049).
	ConditionTCPSequenceContinuityVerified = "TCPSequenceContinuityVerified"
	// ConditionConnectionCountParity is True when the destination pod reports the same
	// number of ESTABLISHED connections as were inventoried on the source pod.
	ConditionConnectionCountParity = "ConnectionCountParity"
	// ConditionRelayProgramsLoaded is True when all TC-BPF relay programs (PM_SEQ_XLAT
	// maps included) have been loaded and attached on the destination node (ADR-0049).
	ConditionRelayProgramsLoaded = "RelayProgramsLoaded"
	// ConditionRelayArmed is True when the 6-predicate ARM barrier is satisfied and the
	// TC-BPF relay has transitioned from STANDBY to ARMED (ADR-0049).
	ConditionRelayArmed = "RelayArmed"
	// ConditionOverlayReady is True when FDB injection, conntrack NOTRACK, and probe
	// traversal through the VXLAN tunnel are all confirmed (ADR-0048).
	ConditionOverlayReady = "OverlayReady"
	// ConditionTCPVerified is the aggregate TCP verification result. True only when
	// TCPSequenceContinuityVerified=True and ConnectionCountParity=True.
	// False triggers hard rollback when TCPPreservationMode=Strict (ADR-0019 Amendment A).
	ConditionTCPVerified = "TCPVerified"
	// ConditionServiceVerified is True when the application-level probe configured in
	// spec.applicationProbe returns healthy from the destination pod post-restore.
	ConditionServiceVerified = "ServiceVerified"
	// ConditionSocketsLive is True when the restore driver has confirmed that the
	// restored TCP sockets are accepting data on the destination (CRIU --tcp-established
	// restore completed and the sockets are in ESTABLISHED state). Set before SIGCONT
	// is delivered to the restored process tree (M23 ordering invariant).
	ConditionSocketsLive = "SocketsLive"
	// ConditionProcessResumedAfterSocketsLive is True when the restored process tree
	// received SIGCONT only after SocketsLive=True was confirmed. The condition
	// LastTransitionTime must be strictly after the SocketsLive LastTransitionTime
	// (M23 ordering invariant: no process resumption before sockets are live).
	ConditionProcessResumedAfterSocketsLive = "ProcessResumedAfterSocketsLive"
)

// PreCopyStats records metrics from the iterative pre-copy phase.
type PreCopyStats struct {
	// RoundsCompleted is the number of pre-dump rounds completed.
	RoundsCompleted int32 `json:"roundsCompleted"`
	// FinalDirtyPagesMB is the dirty page delta at the start of the final freeze.
	FinalDirtyPagesMB int32 `json:"finalDirtyPagesMB"`
	// FreezeDurationMs is the wall-clock time the pod was frozen for final dump.
	FreezeDurationMs int64 `json:"freezeDurationMs"`
}

// DryRunEstimate records results from a dry-run migration estimation.
type DryRunEstimate struct {
	// EstimatedFreezeDurationMs is the predicted freeze duration based on dirty page sampling.
	EstimatedFreezeDurationMs int64 `json:"estimatedFreezeDurationMs"`
	// DirtyPageRateMBps is the observed dirty page write rate during sampling.
	DirtyPageRateMBps string `json:"dirtyPageRateMBps"`
	// StorageTier is the detected storage migration tier (0-4).
	StorageTier int32 `json:"storageTier"`
	// Migratable indicates whether the pod is estimated to be migratable within policy constraints.
	Migratable bool `json:"migratable"`
	// BlockingReason explains why migration is not feasible, if Migratable is false.
	// +optional
	BlockingReason string `json:"blockingReason,omitempty"`
}

// PodMigrationStatus defines the observed state of PodMigration.
type PodMigrationStatus struct {
	// Phase is the current migration phase.
	// +kubebuilder:default=Pending
	Phase MigrationPhase `json:"phase,omitempty"`

	// Conditions provides detailed status conditions.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// SourceNodeName is the node the pod was migrated from.
	// +optional
	SourceNodeName string `json:"sourceNodeName,omitempty"`

	// DestinationNodeName is the node the pod was migrated to.
	// +optional
	DestinationNodeName string `json:"destinationNodeName,omitempty"`

	// ReplacementPodName is the name of the replacement pod created by the operator
	// during live migration to receive the CRIU-restored process.
	// Stored in Status (not Spec) because it is controller-derived runtime state,
	// not user intent. Written once at Checkpointing and read by subsequent phases.
	// +optional
	ReplacementPodName string `json:"replacementPodName,omitempty"`

	// CheckpointRef references the MigrationCheckpoint holding the checkpoint artifact.
	// +optional
	CheckpointRef *corev1.LocalObjectReference `json:"checkpointRef,omitempty"`

	// PreCopyStats records metrics from the iterative pre-copy phase.
	// +optional
	PreCopyStats *PreCopyStats `json:"preCopyStats,omitempty"`

	// DryRunEstimate is populated when spec.dryRun is true.
	// +optional
	DryRunEstimate *DryRunEstimate `json:"dryRunEstimate,omitempty"`

	// StartTime is when the migration was first admitted.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the migration reached Complete, Failed, or DryRunComplete.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// StorageTier is the detected storage migration tier (0=RWX, 1=Longhorn, 2=CephRBD, 3=SnapshotRsync, 4=Blocked).
	// +optional
	StorageTier *int32 `json:"storageTier,omitempty"`

	// TCPConnectionsPreserved is the number of TCP connections successfully migrated.
	// +optional
	TCPConnectionsPreserved *int32 `json:"tcpConnectionsPreserved,omitempty"`

	// CNIProvider is the detected CNI plugin on the source node (e.g. "calico", "cilium",
	// "flannel"). Set during Validating phase and read by the webhook's IPAM annotation logic.
	// +optional
	CNIProvider string `json:"cniProvider,omitempty"`

	// CheckpointTransferred is set true after the checkpoint tar has been durably written
	// to the destination agent and the status has been persisted. Used as an idempotency
	// marker: if the controller crashes after the Put but before transitioning to Restoring,
	// the next reconcile skips the Get/Put and proceeds directly to gate removal + Restoring.
	// +optional
	CheckpointTransferred bool `json:"checkpointTransferred,omitempty"`

	// SourceFreezeTimestampNs is CLOCK_REALTIME nanoseconds at the exact freeze instant,
	// captured by the source agent after the CRIU dump completes with --leave-stopped.
	// Passed as source_freeze_timestamp_ns in the RestoreRequest so the destination agent
	// can compute the PAWS ts_delta for PM_SEQ_XLAT (ADR-0049).
	// +optional
	SourceFreezeTimestampNs int64 `json:"sourceFreezeTimestampNs,omitempty"`

	// TCPSeqSnapshots holds the per-connection TCP sequence state captured at the exact
	// freeze instant. Persisted across the Checkpoint→Restore phase boundary so the
	// controller can pass it in RestoreRequest.seq_snapshots for PM_SEQ_XLAT seeding.
	// +optional
	TCPSeqSnapshots []TCPSeqSnapshot `json:"tcpSeqSnapshots,omitempty"`

	// DestNetnsPath is the /proc/<pid>/fd/<n> path to the pre-staged migration netns on
	// the destination node, returned by PrepareDestinationNetns. Passed as dest_netns_fd
	// in RestoreRequest so the CRIU restore re-enters the correct netns (ADR-0048).
	// +optional
	DestNetnsPath string `json:"destNetnsPath,omitempty"`

	// DestVtepMac is the VTEP MAC for the destination overlay interface, returned by
	// PrepareDestinationNetns. Used to inject the AF_BRIDGE FDB entry on the source node
	// and passed to ConfirmOverlayReady (ADR-0048).
	// +optional
	DestVtepMac string `json:"destVtepMac,omitempty"`

	// SourcePodMac is the MAC address of the source pod's primary interface, populated
	// during the DestinationPrewarm phase from the source pod annotation or netlink query.
	// Used in AF_BRIDGE FDB lookups by ConfirmOverlayReady (ADR-0048).
	// +optional
	SourcePodMac string `json:"sourcePodMac,omitempty"`

	// OverlayFdbIfname is the overlay interface name on both nodes (e.g. "flannel.1") used
	// for FDB and neighbor entry injection and RTM_GETNEIGH confirmation. Populated once
	// during DestinationPrewarm and reused by ConfirmOverlayReady (ADR-0048).
	// +optional
	OverlayFdbIfname string `json:"overlayFdbIfname,omitempty"`

	// SourceConntrackArmed indicates that the NOTRACK conntrack rule is confirmed on the
	// source node. Set by the OverlayHandoff phase before calling ConfirmOverlayReady.
	// +optional
	SourceConntrackArmed bool `json:"sourceConntrackArmed,omitempty"`

	// SourceClockNs is CLOCK_MONOTONIC nanoseconds captured on the source node at freeze
	// time, returned in CheckpointResponse. Passed to ConfirmOverlayReady so the destination
	// can compute the PAWS ts_delta for PM_SEQ_XLAT (ADR-0049).
	// +optional
	SourceClockNs int64 `json:"sourceClockNs,omitempty"`
}

// TCPSeqSnapshot captures the TCP sequence state for a single ESTABLISHED connection
// at the exact freeze instant. Mirrors proto SeqSnapshot but stored in CRD status for
// cross-phase persistence.
type TCPSeqSnapshot struct {
	SrcIP    string `json:"srcIP"`
	SrcPort  uint32 `json:"srcPort"`
	DstIP    string `json:"dstIP"`
	DstPort  uint32 `json:"dstPort"`
	SndNxt   uint32 `json:"sndNxt"`
	RcvNxt   uint32 `json:"rcvNxt"`
	TsRecent uint32 `json:"tsRecent,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=pm,categories=podmotion
// +kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.spec.podName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="TCPMode",type=string,JSONPath=`.spec.tcpPreservationMode`
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.status.sourceNodeName`
// +kubebuilder:printcolumn:name="Dest",type=string,JSONPath=`.status.destinationNodeName`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PodMigration is the work object for a single live pod migration operation.
// Each migration is a discrete, auditable record with full rollback semantics.
type PodMigration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PodMigrationSpec   `json:"spec,omitempty"`
	Status PodMigrationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PodMigrationList contains a list of PodMigration.
type PodMigrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodMigration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PodMigration{}, &PodMigrationList{})
}
