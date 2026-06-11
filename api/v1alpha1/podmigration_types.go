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

// MigrationMode controls the memory transfer strategy.
// +kubebuilder:validation:Enum=PreCopy;PostCopy;Cold
type MigrationMode string

const (
	MigrationModePreCopy  MigrationMode = "PreCopy"
	MigrationModePostCopy MigrationMode = "PostCopy"
	MigrationModeCold     MigrationMode = "Cold"
)

// StorageStrategy overrides automatic storage tier selection.
// +kubebuilder:validation:Enum=Auto;Skip;Sync;SnapshotClone;DualEngine
type StorageStrategy string

const (
	StorageStrategyAuto          StorageStrategy = "Auto"
	StorageStrategySkip          StorageStrategy = "Skip"
	StorageStrategySync          StorageStrategy = "Sync"
	StorageStrategySnapshotClone StorageStrategy = "SnapshotClone"
	StorageStrategyDualEngine    StorageStrategy = "DualEngine"
)

// MigrationPhase represents the current phase of a PodMigration.
// +kubebuilder:validation:Enum=Pending;Validating;PreMigrating;Checkpointing;Transferring;Restoring;Verifying;Complete;Failed;RollingBack;DryRunComplete
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

	// NetworkContinuity enables TCP connection preservation via eBPF bridge and IP handoff.
	// Requires CNI support — see NodeMigrationCapacity.status.cniIPMobilitySupported.
	// Defaults to false; eBPF bridge is not yet implemented (use TIER_4 cold migration path).
	// +kubebuilder:default=false
	NetworkContinuity bool `json:"networkContinuity,omitempty"`

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

	// ReplacementPodName is the name of the replacement pod created by the workload
	// controller after source pod deletion. Tracked by the PodMotion controller.
	// +optional
	ReplacementPodName string `json:"replacementPodName,omitempty"`

	// SourcePodIP is the original IP of the source pod. Injected as a CNI IPAM
	// annotation on the replacement pod at admission so the original IP is pinned
	// at CNI ADD time (Calico / Cilium only; Flannel does not support IP mobility).
	// +optional
	SourcePodIP string `json:"sourcePodIP,omitempty"`
}

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
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=pm,categories=podmotion
// +kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.spec.podName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
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
