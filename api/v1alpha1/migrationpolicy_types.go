/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MigrationTrigger defines what causes a MigrationPolicy to create PodMigration CRs.
type MigrationTrigger struct {
	// NodeCPUPressurePercent triggers migration when node CPU usage exceeds this threshold.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +optional
	NodeCPUPressurePercent *int32 `json:"nodeCPUPressurePercent,omitempty"`

	// NodeMemoryPressurePercent triggers migration when node memory usage exceeds this threshold.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +optional
	NodeMemoryPressurePercent *int32 `json:"nodeMemoryPressurePercent,omitempty"`

	// NodeDrain triggers migration for all eligible pods when the node is cordoned.
	// +optional
	NodeDrain *bool `json:"nodeDrain,omitempty"`

	// SpotReclaim triggers migration when the node receives a spot/preemptible termination notice.
	// +optional
	SpotReclaim *bool `json:"spotReclaim,omitempty"`
}

// MigrationWindow restricts when migrations are allowed to run.
type MigrationWindow struct {
	// AllowedCron is a cron expression defining when migrations are permitted.
	// Example: "0 2 * * 1-5" (weekdays at 2am)
	// +optional
	AllowedCron string `json:"allowedCron,omitempty"`

	// BlockedCron is a cron expression defining when migrations are explicitly forbidden.
	// Takes precedence over AllowedCron.
	// +optional
	BlockedCron string `json:"blockedCron,omitempty"`
}

// MigrationPolicySpec defines the desired state of MigrationPolicy.
type MigrationPolicySpec struct {
	// Selector selects pods this policy applies to.
	// +kubebuilder:validation:Required
	Selector metav1.LabelSelector `json:"selector"`

	// Triggers defines conditions that cause this policy to initiate migrations.
	Triggers MigrationTrigger `json:"triggers,omitempty"`

	// MigrationDefaults provides default PodMigrationSpec values for migrations created by this policy.
	// +optional
	MigrationDefaults *PodMigrationSpec `json:"migrationDefaults,omitempty"`

	// Window restricts when this policy may create migrations.
	// +optional
	Window *MigrationWindow `json:"window,omitempty"`

	// MaxConcurrentMigrations is the maximum number of simultaneous migrations this policy may manage.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	MaxConcurrentMigrations int32 `json:"maxConcurrentMigrations,omitempty"`

	// BlockedNamespaces lists namespaces this policy will never target, regardless of selector.
	// +optional
	BlockedNamespaces []string `json:"blockedNamespaces,omitempty"`
}

// MigrationPolicyStatus defines the observed state of MigrationPolicy.
type MigrationPolicyStatus struct {
	// ActiveMigrations is the count of in-flight PodMigration CRs owned by this policy.
	ActiveMigrations int32 `json:"activeMigrations"`

	// TotalMigrations is the lifetime count of migrations created by this policy.
	TotalMigrations int32 `json:"totalMigrations"`

	// LastTriggerTime is when this policy last created a PodMigration CR.
	// +optional
	LastTriggerTime *metav1.Time `json:"lastTriggerTime,omitempty"`

	// Conditions provides status conditions including WindowBlocked, TriggerActive.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=mp,categories=podmotion
// +kubebuilder:printcolumn:name="Active",type=integer,JSONPath=`.status.activeMigrations`
// +kubebuilder:printcolumn:name="Total",type=integer,JSONPath=`.status.totalMigrations`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MigrationPolicy defines trigger rules and constraints for automated pod migration.
type MigrationPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MigrationPolicySpec   `json:"spec,omitempty"`
	Status MigrationPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MigrationPolicyList contains a list of MigrationPolicy.
type MigrationPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MigrationPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MigrationPolicy{}, &MigrationPolicyList{})
}
