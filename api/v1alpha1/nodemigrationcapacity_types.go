/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KernelFeatures captures kernel capabilities required for specific migration modes.
type KernelFeatures struct {
	// CheckpointRestore indicates CONFIG_CHECKPOINT_RESTORE is enabled.
	CheckpointRestore bool `json:"checkpointRestore"`
	// MemSoftDirty indicates CONFIG_MEM_SOFT_DIRTY is enabled (required for iterative pre-copy).
	MemSoftDirty bool `json:"memSoftDirty"`
	// Userfaultfd indicates CONFIG_USERFAULTFD is enabled (required for post-copy lazy pages).
	Userfaultfd bool `json:"userfaultfd"`
	// BPFEnabled indicates CONFIG_BPF_SYSCALL is enabled (required for eBPF packet bridge).
	BPFEnabled bool `json:"bpfEnabled"`
	// XDPSupported indicates XDP on veth is supported (kernel 4.19+).
	XDPSupported bool `json:"xdpSupported"`
	// TCClsactSupported indicates the node can attach a clsact qdisc to a veth-class
	// interface (RTM_NEWQDISC for clsact returns success, not EOPNOTSUPP). Required for
	// tcpPreservationMode=Strict zero-window hold. Set by an ACTIVE runtime probe at
	// registration, NOT inferred from CONFIG_BPF_SYSCALL — BPFEnabled is not a reliable
	// proxy for clsact-on-veth support (ADR-0169).
	TCClsactSupported bool `json:"tcClsactSupported"`
	// KernelVersion is the full kernel version string reported by uname -r.
	KernelVersion string `json:"kernelVersion"`
}

// StorageCapability describes supported storage migration tiers on this node.
type StorageCapability struct {
	// CephRBDAvailable indicates the Ceph RBD live migration API is reachable.
	CephRBDAvailable bool `json:"cephRBDAvailable"`
	// LonghornAvailable indicates Longhorn is deployed and the node hosts engine replicas.
	LonghornAvailable bool `json:"longhornAvailable"`
	// LocalPVMigratable indicates pv-migrate rsync is available for local PV migration.
	LocalPVMigratable bool `json:"localPVMigratable"`
}

// NetworkCapability describes the node's ability to support network continuity.
type NetworkCapability struct {
	// CNIPlugin is the detected primary CNI plugin (e.g. ovn-kubernetes, calico, cilium, flannel).
	CNIPlugin string `json:"cniPlugin"`
	// IPMobilitySupported indicates the CNI can preserve pod IPs across node moves.
	IPMobilitySupported bool `json:"ipMobilitySupported"`
	// IPMobilityMode describes the mechanism (e.g. IPAMClaim, BGPHostRoute, L2Announce).
	// +optional
	IPMobilityMode string `json:"ipMobilityMode,omitempty"`
	// XDPBridgeCapable indicates the node can run the XDP packet bridge program.
	XDPBridgeCapable bool `json:"xdpBridgeCapable"`
	// LiveMigrationEligible is false when the CNI does not support IP mobility
	// (e.g. Flannel). Pods on nodes where this is false can only use cold migration
	// (NetworkContinuity=false). Defaults to true for CNIs that support IPAM pinning.
	// +kubebuilder:default=true
	LiveMigrationEligible bool `json:"liveMigrationEligible"`
	// CNIUnderlayType captures the dataplane encapsulation type (e.g. VXLAN, Direct,
	// WireGuard, BGP). Used for MSS clamping calculations when GENEVE bridge is active.
	// +optional
	CNIUnderlayType string `json:"cniUnderlayType,omitempty"`
	// WireGuardInterface is the name of the WireGuard tunnel interface on this node's
	// primary CNI encryption path (e.g. "wireguard.cali", "cilium_wg0", "wg0").
	// Empty string if WireGuard is not in use (ADR-0102).
	// +optional
	WireGuardInterface string `json:"wireGuardInterface,omitempty"`
}

// NodeMigrationCapacitySpec is set by the node agent at startup and updated periodically.
type NodeMigrationCapacitySpec struct {
	// NodeName is the Kubernetes node this capacity record describes.
	// +kubebuilder:validation:Required
	NodeName string `json:"nodeName"`

	// AgentEndpoint is the gRPC endpoint of the agent on this node, in the form "ip:port".
	// Set by the agent at startup so that the operator can reach systemd-based agents that
	// do not run as Kubernetes pods and therefore have no pod IP discoverable via label selector.
	// +optional
	AgentEndpoint string `json:"agentEndpoint,omitempty"`

	// CRIUVersion is the version of CRIU installed on the node (e.g. "4.2").
	CRIUVersion string `json:"criuVersion"`

	// NRIEnabled indicates containerd NRI is enabled on this node.
	NRIEnabled bool `json:"nriEnabled"`

	// KernelFeatures describes kernel capability flags verified at agent startup.
	KernelFeatures KernelFeatures `json:"kernelFeatures"`

	// StorageCapability describes supported storage migration tiers.
	StorageCapability StorageCapability `json:"storageCapability"`

	// NetworkCapability describes network continuity support.
	NetworkCapability NetworkCapability `json:"networkCapability"`

	// GPUMigrationSupported indicates NVIDIA cuda-checkpoint is available.
	// +optional
	GPUMigrationSupported bool `json:"gpuMigrationSupported,omitempty"`

	// GPUDriverVersion is the NVIDIA driver version if GPU migration is supported.
	// +optional
	GPUDriverVersion string `json:"gpuDriverVersion,omitempty"`

	// MaxConcurrentMigrationsSource is the maximum simultaneous migrations this node can serve as source.
	// +kubebuilder:default=2
	MaxConcurrentMigrationsSource int32 `json:"maxConcurrentMigrationsSource,omitempty"`

	// MaxConcurrentMigrationsDestination is the maximum simultaneous migrations this node can receive.
	// +kubebuilder:default=2
	MaxConcurrentMigrationsDestination int32 `json:"maxConcurrentMigrationsDestination,omitempty"`
}

// NodeMigrationCapacityStatus reflects real-time node state.
// IPFamilySupport describes the IP address families detected on the node's primary
// network interface (ADR-0081).
// +kubebuilder:validation:Enum=IPv4Only;IPv6Only;DualStack;Unknown
type IPFamilySupport string

const (
	IPFamilySupportIPv4Only  IPFamilySupport = "IPv4Only"
	IPFamilySupportIPv6Only  IPFamilySupport = "IPv6Only"
	IPFamilySupportDualStack IPFamilySupport = "DualStack"
	IPFamilySupportUnknown   IPFamilySupport = "Unknown"
)

type NodeMigrationCapacityStatus struct {
	// ActiveSourceMigrations is the number of migrations currently sourced from this node.
	ActiveSourceMigrations int32 `json:"activeSourceMigrations"`
	// ActiveDestinationMigrations is the number of migrations currently targeting this node.
	ActiveDestinationMigrations int32 `json:"activeDestinationMigrations"`
	// ThermalThrottlePercent is the current CPU thermal throttle percentage (0 = no throttling).
	// +optional
	ThermalThrottlePercent *int32 `json:"thermalThrottlePercent,omitempty"`
	// LastHeartbeat is when the agent last updated this record.
	// +optional
	LastHeartbeat *metav1.Time `json:"lastHeartbeat,omitempty"`
	// Ready indicates the agent is running and all required features are available.
	Ready bool `json:"ready"`
	// ClusterIPFamily reports the IP address family support detected on this node's
	// primary interface. Used by the admission webhook to reject IPv6-primary migrations
	// (ADR-0081). Populated by the NMC probe on startup and on each resync.
	// +optional
	ClusterIPFamily IPFamilySupport `json:"clusterIPFamily,omitempty"`
	// IPSecEncryption is true when CNI-managed IPSec (XFRM pod-CIDR policies) is
	// detected on this node. Migrations are rejected at admission for IPSec clusters
	// (ADR-0102).
	// +optional
	IPSecEncryption bool `json:"ipSecEncryption,omitempty"`

	// Conditions provides status conditions including CNICompatible (ADR-0313).
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ADR-0313: CNICompatible condition Type/Reason constants for NodeMigrationCapacity.
// Written by the agent registrar via meta.SetStatusCondition — no call-site literals
// (same freeform status.conditions discipline as PodMigration's condition constants).
const (
	// ConditionCNICompatible is True when the detected CNI plugin is fully supported
	// by PodMotion's live-migration datapath; False when the CNI is structurally
	// incompatible (e.g. Cilium — no IP-mobility handoff implemented, ADR-0082/ADR-0313).
	ConditionCNICompatible = "CNICompatible"

	// ReasonCNIUnsupported is the Reason used when ConditionCNICompatible is False
	// because the detected CNI plugin lacks an IP-mobility handoff implementation.
	ReasonCNIUnsupported = "CNIUnsupported"

	// ReasonCNISupported is the Reason used when ConditionCNICompatible is True.
	ReasonCNISupported = "CNISupported"
)

// ADR-0366: CRIUDetected condition Type/Reason constants for NodeMigrationCapacity.
// Written by the agent registrar via meta.SetStatusCondition (same freeform
// status.conditions discipline as ConditionCNICompatible above) — the real,
// genuinely-observable signal for a CRIU-detection failure, not just a log line: the
// original bug (spec.criuVersion silently empty fleet-wide) went unnoticed for weeks
// specifically because nothing surfaced it anywhere an operator or dashboard would see it.
const (
	// ConditionCRIUDetected is True when detectCRIU successfully resolved a CRIU version
	// string (Spec.CRIUVersion populated); False when detection failed — either the
	// netns-broker was unreachable after the bounded startup retry, or the host CRIU
	// exec itself ran and failed/exited nonzero.
	ConditionCRIUDetected = "CRIUDetected"

	// ReasonCRIUVersionDetected is the Reason used when ConditionCRIUDetected is True.
	ReasonCRIUVersionDetected = "CRIUVersionDetected"

	// ReasonCRIUBrokerUnreachable is the Reason used when ConditionCRIUDetected is False
	// because the netns-broker could not be reached after the bounded (3-attempt,
	// 500ms-backoff) startup retry — a startup race, not a deterministic CRIU failure.
	ReasonCRIUBrokerUnreachable = "CRIUBrokerUnreachable"

	// ReasonCRIUExecFailed is the Reason used when ConditionCRIUDetected is False because
	// the CRIU exec itself (direct in-container fallback, or via the broker) ran and
	// failed or exited nonzero — a genuine, deterministic CRIU/host problem, not a
	// startup race, and therefore not retried.
	ReasonCRIUExecFailed = "CRIUExecFailed"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=nmc,categories=podmotion
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.nodeName`
// +kubebuilder:printcolumn:name="CRIU",type=string,JSONPath=`.spec.criuVersion`
// +kubebuilder:printcolumn:name="IPMobility",type=boolean,JSONPath=`.spec.networkCapability.ipMobilitySupported`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// NodeMigrationCapacity is a cluster-scoped record advertising a node's migration capabilities.
// One record per node, named after the node. Created and maintained by the podmotion-agent DaemonSet.
type NodeMigrationCapacity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeMigrationCapacitySpec   `json:"spec,omitempty"`
	Status NodeMigrationCapacityStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NodeMigrationCapacityList contains a list of NodeMigrationCapacity.
type NodeMigrationCapacityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeMigrationCapacity `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NodeMigrationCapacity{}, &NodeMigrationCapacityList{})
}
