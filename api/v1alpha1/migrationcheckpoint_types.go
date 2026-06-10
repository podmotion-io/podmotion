/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CheckpointTransferMode describes how the checkpoint was or will be transferred.
// +kubebuilder:validation:Enum=DirectP2P;Registry
type CheckpointTransferMode string

const (
	CheckpointTransferModeDirectP2P CheckpointTransferMode = "DirectP2P"
	CheckpointTransferModeRegistry  CheckpointTransferMode = "Registry"
)

// MigrationCheckpointSpec holds metadata about a checkpoint artifact.
type MigrationCheckpointSpec struct {
	// PodMigrationRef is the owning PodMigration.
	// +kubebuilder:validation:Required
	PodMigrationRef string `json:"podMigrationRef"`

	// SourceNodeName is the node the checkpoint was taken on.
	SourceNodeName string `json:"sourceNodeName"`

	// TransferMode describes how the checkpoint artifact is staged.
	// +kubebuilder:default=DirectP2P
	TransferMode CheckpointTransferMode `json:"transferMode,omitempty"`

	// RegistryRef is the OCI image reference for registry-staged checkpoints (e.g. registry.local/pm-checkpoint/pod-abc:latest).
	// +optional
	RegistryRef string `json:"registryRef,omitempty"`

	// ContentSHA256 is the SHA256 digest of the checkpoint archive for integrity verification.
	// +optional
	ContentSHA256 string `json:"contentSHA256,omitempty"`

	// SizeBytes is the total checkpoint size in bytes.
	// +optional
	SizeBytes *int64 `json:"sizeBytes,omitempty"`

	// ExpiresAt is when this checkpoint should be garbage-collected.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// Encrypted indicates the checkpoint OCI layers are encrypted.
	// +optional
	Encrypted bool `json:"encrypted,omitempty"`
}

// MigrationCheckpointStatus reflects the lifecycle of the checkpoint artifact.
type MigrationCheckpointStatus struct {
	// Phase is the checkpoint lifecycle phase: Capturing, Available, Consumed, Expired, Failed.
	// +kubebuilder:validation:Enum=Capturing;Available;Consumed;Expired;Failed
	Phase string `json:"phase,omitempty"`

	// CapturedAt is when the checkpoint was completed.
	// +optional
	CapturedAt *metav1.Time `json:"capturedAt,omitempty"`

	// ConsumedAt is when the checkpoint was used for a successful restore.
	// +optional
	ConsumedAt *metav1.Time `json:"consumedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=mcp,categories=podmotion
// +kubebuilder:printcolumn:name="Migration",type=string,JSONPath=`.spec.podMigrationRef`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Transfer",type=string,JSONPath=`.spec.transferMode`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MigrationCheckpoint holds metadata and lifecycle for a single checkpoint artifact.
type MigrationCheckpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MigrationCheckpointSpec   `json:"spec,omitempty"`
	Status MigrationCheckpointStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MigrationCheckpointList contains a list of MigrationCheckpoint.
type MigrationCheckpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MigrationCheckpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MigrationCheckpoint{}, &MigrationCheckpointList{})
}
