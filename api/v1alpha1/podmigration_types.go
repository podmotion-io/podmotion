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
	// ADR-0352 D1.4: Strict guarantees Kubernetes Service-level continuity (ClusterIP +
	// Ready EndpointSlice membership) — it does NOT guarantee the replacement pod retains
	// the source pod's IP address or MAC (cluster-pool IPAM assigns a fresh dest-local IP).
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
// +kubebuilder:validation:Enum=Pending;SocketInventory;Validating;PreMigrating;Checkpointing;Transferring;Restoring;Verifying;DestinationPrewarm;PreCopyMemory;ZeroWindowArm;FinalFreezeStateCapture;OverlayHandoff;RestoreSocketReattach;DisengageHold;TCPVerifying;ServiceVerifying;CutoverComplete;Complete;Failed;RollingBack;DryRunComplete
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
	MigrationPhaseSocketInventory         MigrationPhase = "SocketInventory"
	MigrationPhaseDestinationPrewarm      MigrationPhase = "DestinationPrewarm"
	MigrationPhasePreCopyMemory           MigrationPhase = "PreCopyMemory"
	MigrationPhaseZeroWindowArm           MigrationPhase = "ZeroWindowArm"
	MigrationPhaseFinalFreezeStateCapture MigrationPhase = "FinalFreezeStateCapture"
	MigrationPhaseOverlayHandoff          MigrationPhase = "OverlayHandoff"
	MigrationPhaseRestoreSocketReattach   MigrationPhase = "RestoreSocketReattach"
	MigrationPhaseDisengageHold           MigrationPhase = "DisengageHold"
	MigrationPhaseTCPVerifying            MigrationPhase = "TCPVerifying"
	MigrationPhaseServiceVerifying        MigrationPhase = "ServiceVerifying"
	MigrationPhaseCutoverComplete         MigrationPhase = "CutoverComplete"
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
	// ConditionStorageCutoverComplete is True when the StorageMigrationManager's
	// Cutover (detach source / attach destination) and AwaitSingleOwner (block
	// until the migrated volume is in a single-owner, mountable state) have both
	// completed successfully BEFORE CRIU restore is triggered on the destination.
	// Gated in reconcileOverlayHandoff (gateStorageCutoverBeforeRestore), at the
	// end of that phase, immediately before the phase transition into
	// RestoreSocketReattach — the first phase in the NRI StartContainer hook's
	// restore accept-set (nri/plugin.go verifyPhaseInAcceptSet). That is
	// deliberately AFTER scheduling-gate removal (end of reconcileTransferring):
	// tiers like Longhorn whose dual-engine collapse only begins once the
	// destination pod is scheduled and kubelet mounts the volume would deadlock
	// forever if gated any earlier (sprint49 finding — a prior placement before
	// scheduling-gate removal produced exactly that deadlock live). This is what
	// prevents CRIU restore from racing ahead of the destination storage engine
	// actually being present/ready — a dual-attached/dual-owner volume (e.g.
	// Longhorn's live-migration dual engine, Ceph RBD's prepare/execute pair)
	// must collapse to a single owner on the destination node before restore is
	// allowed to begin, not merely before the destination pod's volume mounts.
	// Reason=CutoverFailed or AwaitSingleOwnerTimeout on False.
	ConditionStorageCutoverComplete = "StorageCutoverComplete"
	// ConditionTier1EarlySourceRelease is True when the source pod was deleted BEFORE
	// TrafficVerified as the narrow, Tier1-Longhorn-only exception to ADR-0012 documented in
	// ADR-0356. Longhorn's real single-owner collapse is driven by the Kubernetes CSI
	// attacher, which only releases the source node's VolumeAttachment once no pod on that
	// node references the PVC — for a Longhorn-classified (TierLonghorn) volume this
	// functionally requires the source pod to be gone before the destination pod's own
	// volume mount can ever succeed, which in turn gates restore and therefore
	// TrafficVerified itself (ADR-0012's normal gate). ADR-0356 breaks that cycle for this
	// tier ONLY by releasing the source pod immediately after CheckpointTransferred=True
	// (a cryptographically-verified, durable checkpoint on the destination node — ADR-SEC-B)
	// and a fresh destination-NMC-Ready check, in exchange for narrowing this tier's
	// rollback guarantee from zero-downtime live-resume to checkpoint-guaranteed
	// bounded-downtime recovery. Every other storage tier is untouched and keeps ADR-0012's
	// full guarantee. Reason=Tier1LonghornEarlyRelease when True.
	ConditionTier1EarlySourceRelease = "Tier1EarlySourceRelease"
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
	// ConditionStrictCapabilitySatisfied is False when tcpPreservationMode=Strict cannot
	// be honored because the resolved destination node does not support TC clsact
	// (tcClsactSupported=false). Set by the pre-prewarm controller re-check (ADR-0169).
	ConditionStrictCapabilitySatisfied = "StrictCapabilitySatisfied"
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
	// ConditionDataplaneReachabilityVerified is set True when a CROSS-NODE probe
	// (originated by the SOURCE-node agent — a node ≠ destination) confirms the
	// preserved pod IP is reachable via the real overlay/host-route datapath, and
	// the destination echoes back a controller-issued correlation nonce. This is the
	// ADR-0210 gate for source-pod deletion under tcpPreservationMode=Strict. It
	// replaces the ADR-0200/0201 in-netns self-probe (a tautology: the dial and the
	// lo/32 alias lived in the same netns, so the local kernel always answered RST).
	// The CONTROLLER is the authority that flips this condition, based on the nonce
	// round-trip — never a self-asserted ProbeOk boolean from a single agent.
	ConditionDataplaneReachabilityVerified = "DataplaneReachabilityVerified"
	// ConditionServiceContinuityVerified (ADR-0352) is the authoritative Service-continuity
	// signal, produced from two source-of-truth reads (not inference): the replacement
	// endpoint is a Ready member of the target Service's EndpointSlice (D1.1, made real by
	// the D0.1 write-back — traffic.EndpointSliceManager.MarkDestinationReady), AND a real
	// client round-trip to the Service ClusterIP succeeds (D1.2). True only when both hold.
	// Absent/Unknown MUST NOT veto (no probe has run yet, or None mode, which never produces
	// this condition). False is set only affirmatively — workload is live yet the replacement
	// is not Ready-enrolled after a bounded window, or the round-trip affirmatively failed.
	// Replaces ConditionDataplaneReachabilityVerified as the Strict-mode source-teardown
	// discharge signal on the Strict completion path only (api/v1alpha1/source_teardown.go);
	// DataplaneReachabilityVerified is preserved as the live cross-mode fail-closed veto for
	// BestEffort/None (ADR-0352 D2.2 option b).
	// ADR-0352 D1.4: Strict now guarantees Kubernetes Service-level continuity (ClusterIP +
	// Ready EndpointSlice membership) — it does NOT guarantee the replacement pod retains the
	// source pod's IP address or MAC (cluster-pool IPAM assigns a fresh dest-local IP).
	ConditionServiceContinuityVerified = "ServiceContinuityVerified"
	// Note (ADR-0352 B8-DR-8a): the legacy status.conditions entry named "TrafficVerified" is
	// a control-flow token on the NRI/legacy Strict completion path ONLY — it is NOT a Strict
	// teardown-safety predicate. The Strict source-teardown gate keys exclusively on
	// {ServiceContinuityVerified, TCPSequenceContinuityVerified, WorkloadLivenessVerified}
	// (api/v1alpha1/source_teardown.go:SourceTeardownBlockReason). Do not read
	// TrafficVerified=True as "teardown-safe" under Strict.
	// ConditionWorkloadLivenessVerified is set by reconcileServiceVerifying (ADR-0325) from a
	// real wire-protocol application probe (Postgres v3 handshake+SELECT, Redis RESP PING/PONG,
	// HTTP GET requiring a genuine [200,300) response with redirect-refusal) issued via
	// VerifyTCP(AppProbeOnly=true) against the DESTINATION pod. Reason vocabulary is CLOSED:
	// True/{NoKnownProtocol, ExplicitProbePassed, DefaultedProbePassed};
	// False/{ExplicitProbeFailed, DefaultedProbeFailed, AmbiguousProbeDefault}.
	// Consumed additively by sourcePodDeletionBlockReason for ALL TCPPreservationMode values.
	ConditionWorkloadLivenessVerified = "WorkloadLivenessVerified"
	// ConditionWorkloadLivenessFirstPass is a staging condition set True the instant the FIRST
	// real application probe (the same VerifyTCP(AppProbeOnly=true) call that produces
	// ConditionWorkloadLivenessVerified) passes. ConditionWorkloadLivenessVerified is deliberately
	// NOT set True on this first pass alone: a workload that dies shortly after CRIU restore (the
	// documented gap — the restore process can crash 40-60s after an apparently-successful
	// restore, e.g. Postgres killed by a subsequent internal fault) can still be alive during this
	// narrow first-probe window, producing a false-positive liveness pass. reconcileServiceVerifying
	// requires a SECOND real probe, issued no sooner than workloadLivenessStabilizationWindow after
	// this condition's LastTransitionTime, to actually pass before ConditionWorkloadLivenessVerified
	// is set True — a genuine second point-in-time health confirmation against the live workload,
	// not a longer single wait. A failure on the second pass resets this condition to False so a
	// later recovery must re-earn both passes. Reason vocabulary mirrors
	// ConditionWorkloadLivenessVerified's {ExplicitProbePassed, DefaultedProbePassed} on True and
	// {ReconfirmationFailed} on False.
	ConditionWorkloadLivenessFirstPass = "WorkloadLivenessFirstPass"
	// ConditionCni0CleanupVerified is set by reconcileVerifying after CleanupSourceIPHandoff
	// (ADR-0241 item 1 / NR-BLOCK-1 CUTOVER_COMPLETE scope). True once VerifyCleanup confirms
	// the cni0 neigh and cni0 host route for the OLD pod IP are both absent, within the
	// 3-attempt/2s-4s-8s retry budget. False (reason CleanupLeakExhausted) if the retry budget
	// is exhausted with an object still present — a fail-open, non-blocking outcome; the
	// migration still completes, and pmmetrics.DatapathCleanupLeakTotal plus a
	// DatapathCleanupLeak Kubernetes Event are also emitted on that branch. Scoped only to the
	// two cutover-complete objects — it does NOT cover the dest tc/FORWARD-ACCEPT/NOTRACK or
	// source flannel.1/NOTRACK objects, which remain unaddressed pending NR-BLOCK-2.
	ConditionCni0CleanupVerified = "Cni0CleanupVerified"
	// ConditionZeroWindowRuleFlushDetected is set by the agent-owned idempotent reconcile
	// loop (ADR-0240 / R4) when it observes the FORWARD ACCEPT or NOTRACK rules backing an
	// active zero-window hold missing (flushed by an external actor) and self-heals by
	// reasserting them. Purely observational — never blocks reconcileDisengageHold or any
	// phase transition (self-heal already prevents the outage). Once set, it persists on the
	// PodMigration status after disarm and is never cleared (ADR-0240 D4/D4a), matching the
	// existing WatchdogFired-style permanent-record convention.
	ConditionZeroWindowRuleFlushDetected = "ZeroWindowRuleFlushDetected"
	// ConditionIPReclaimDestTornDown is True once the destination-side tc-ingress redirect,
	// FORWARD ACCEPT pair, and NOTRACK rules for the relocated OLD pod IP have been removed
	// via DisarmTCRedirect during the IP-reclaim sweep (ADR-0244 / NR-BLOCK-2).
	ConditionIPReclaimDestTornDown = "IPReclaimDestTornDown"
	// ConditionIPReclaimSourceTornDown is True once the source-side flannel.1 redirect
	// (route/neigh/FDB) and NOTRACK rules for the relocated OLD pod IP have been removed
	// via TeardownSourceRedirect during the IP-reclaim sweep (ADR-0244 / NR-BLOCK-2).
	ConditionIPReclaimSourceTornDown = "IPReclaimSourceTornDown"
	// ConditionIPReclaimComplete is True only once BOTH ConditionIPReclaimDestTornDown and
	// ConditionIPReclaimSourceTornDown are True (ADR-0244 / NR-BLOCK-2). Distinct from
	// ConditionCni0CleanupVerified, which is scoped only to CUTOVER_COMPLETE objects.
	ConditionIPReclaimComplete = "IPReclaimComplete"
	// ConditionSourceStorageWriteRestored: NAME IS ASPIRATIONAL — READ THIS BEFORE
	// TREATING True AS A STORAGE GUARANTEE (ADR-0344 sign-off finding, 2026-07-12).
	//
	// As implemented today this condition is CONNECTIVITY-ONLY. For Tier0 (RWX)
	// migrations it is set True once the source agent's gRPC connection is
	// reachable (restoreSourceStorageIfNeeded, internal/controller/podmigration_controller.go).
	// There is no remount-rw RPC on the wire for the rollback direction, so
	// True here does NOT confirm the source volume is actually writable, does
	// NOT confirm the destination volume is unmounted, and does NOT by itself
	// close the concurrent-writer/split-brain window described in ADR-0344
	// Context §1/§2 (two backends able to write the same PGDATA mount). See
	// docs/security/SECURITY-DEBT-LEDGER.md for the full tracked-debt
	// writeup and resolution path.
	//
	// BINDING RULE: no consumer — including ADR-0344 Decision A's deferred
	// second-SIGCONT gate in ReconcileOrphanedFrozenSources — may treat
	// ConditionSourceStorageWriteRestored=True as proof the concurrent-writer
	// window is closed until a real remount-rw RPC exists on the wire and
	// restoreSourceStorageIfNeeded actually calls it and awaits confirmation.
	// Until then, treat True as "source agent reachable, remount state
	// unverified" only (reason SourceAgentReachableRemountUnverified).
	//
	// The RollingBack phase handler observes this condition before resuming
	// (SIGCONT-ing) the frozen source process (ADR-0007 remount-handoff
	// protocol, ADR-0344 Decision A.2). For non-Tier0 migrations this is set
	// True immediately (same-reconcile no-op) since there is no shared-mount
	// hazard to guard against.
	ConditionSourceStorageWriteRestored = "SourceStorageWriteRestored"
	// ConditionIPReclaimVerified records the VerifyCleanup(IP_RECLAIM) bounded-retry outcome
	// (3 attempts, 2s/4s/8s), same fail-open posture as ConditionCni0CleanupVerified
	// (ADR-0241 item 1 precedent). False (reason CleanupLeakExhausted) on retry-budget
	// exhaustion emits DatapathCleanupLeakTotal + a DatapathCleanupLeak Event but never
	// blocks or reverts reclaim (ADR-0244 / NR-BLOCK-2).
	ConditionIPReclaimVerified = "IPReclaimVerified"
	// ConditionReclaimObjectsInstalled is a durable PROVENANCE record: it is set True the moment
	// the destination-agent InjectIPHandoff RPC confirms the reclaim datapath objects (OLD-IP
	// NOTRACK, FORWARD ACCEPT, tc-ingress redirect, and — best-effort — the source-side redirect)
	// were physically installed, and is persisted IMMEDIATELY, BEFORE any cross-node reachability
	// probe runs. It exists because the reclaim sweep must ALWAYS run VerifyCleanup once objects
	// exist on the wire — even when cross-node/cross-subnet/cross-AZ old-IP reachability never
	// converges (a legitimate, permanent outcome on AWS VPC CNI where a pod IP is a subnet/AZ-bound
	// ENI address). Keying the sweep's "NothingToReclaim" short-circuit off IPHandoffInjected was a
	// leak: that condition is dropped when injectIPHandoff returns done=false on a reachability
	// requeue, so real orphaned objects were silently left behind (Sprint 42 FS-048). This
	// provenance condition is never cleared once set and is the authoritative sweep predicate.
	ConditionReclaimObjectsInstalled = "ReclaimObjectsInstalled"
	// ConditionRolledBack is True when the source pod has been resumed to live state after a
	// failed/aborted migration and — as of ADR-0350 — only after every reaped replacement
	// pod's endpoint has been confirmed absent from all EndpointSlices in the namespace (the
	// happens-before split-brain guard). Single-sited write at podmigration_controller.go:4658.
	ConditionRolledBack = "RolledBack"
	// ConditionFailed is True when the migration has terminated in hard failure
	// (podmigration_controller.go:4888, failMigration). Distinct from ConditionRolledBack —
	// failMigration reaps the replacement pod best-effort but does NOT gate on or set
	// ConditionRolledBack (ADR-0350 arch_b finding: the two deleteReplacementPod call sites
	// terminate in different conditions).
	ConditionFailed = "Failed"
	// ConditionReplacementEndpointsRemoved is the ADR-0350 D6 observability signal for the
	// removal-confirm state. True (reason ReplacementEndpointsAbsent) records the audited
	// happens-before predecessor of RolledBack=True, set from the same in-memory confirm
	// result in the same reconcile. False on retry-budget exhaustion (D3), with a
	// mode-distinguishing reason: ReplacementPodUndeletable (any reaped pod's delete was not
	// confirmed — a stuck finalizer/rejecting webhook, actionable) or
	// ReplacementEndpointRemovalContended (transient EndpointSlice CAS contention, normally
	// self-clearing). The exhaustion path is fail-CLOSED: RolledBack=True is withheld and the
	// reconcile requeues (mirrors, but inverts the disposition of, CleanupLeakExhausted at
	// podmigration_controller.go:3700-3714, which is fail-open).
	ConditionReplacementEndpointsRemoved = "ReplacementEndpointsRemoved"
)

// Reason vocabulary for the ADR-0322 Cilium ipcache/CiliumEndpoint handoff branch,
// inserted into injectIPHandoff immediately before verifyDataplaneReachability.
// These gate ConditionDataplaneReachabilityVerified=False under tcpPreservationMode=Strict
// on a Cilium destination; all three are fail-closed (block/requeue, never silently skip).
const (
	// ReasonCiliumEndpointLookupError: the CiliumEndpoint dynamic-client Get/lookup itself
	// returned an error (not "not found" as a terminal state, but a transient/API error).
	ReasonCiliumEndpointLookupError = "CiliumEndpointLookupError"
	// ReasonCiliumEndpointNotReady: the CiliumEndpoint was found but status.state != "ready"
	// or status.identity.id == 0 (ipcache programming not yet confirmed).
	ReasonCiliumEndpointNotReady = "CiliumEndpointNotReady"
	// ReasonCNISignalUnresolved: destNMC.Spec.NetworkCapability.CNIPlugin could not be
	// resolved (fetch error or empty value) on a destination that must be treated as
	// Cilium-capable; fail-closed rather than silently skipping the readiness check.
	ReasonCNISignalUnresolved = "CNISignalUnresolved"
	// ReasonCiliumDataplaneProgrammed: POSITIVE reason. cilium-agent's own CiliumEndpoint
	// status write-back confirms the replacement endpoint on the destination node is
	// state=="ready" with a non-zero identity AND its status.networking.addressing
	// advertises the preserved SourcePodIP. This is the AUTHORITATIVE cross-node dataplane
	// fact read directly from the CNI's source of truth (ADR-0322 primitive), and it RETIRES
	// the ADR-0210 source-node nonce round-trip on the Cilium cross-node path — that probe is
	// structurally blind while ADR-0012 holds the source pod alive with the same IP on the
	// source node (the source node delivers the preserved IP to its own local held pod, never
	// across the overlay to the destination), so it can never converge and is not a valid
	// signal. See injectIPHandoff.
	ReasonCiliumDataplaneProgrammed = "CiliumDataplaneProgrammed"
	// ReasonPreservedIPNotOnEndpoint: the replacement pod's CiliumEndpoint reached ready with
	// an identity, but cilium-agent's status.networking.addressing does NOT advertise the
	// preserved SourcePodIP — the ipam.cilium.io/ip pin was not honored (e.g. cluster-pool
	// per-node /24 blocks reject a foreign IP; ADR-0324 P-VERIFY-C). Fail-closed: the IP did
	// not actually move to the destination, so the cross-node dataplane gate must NOT be
	// credited. Surfaced as a specific, actionable condition instead of a silent wedge.
	ReasonPreservedIPNotOnEndpoint = "PreservedIPNotOnCiliumEndpoint"
	// ReasonCalicoWorkloadEndpointNotReady: the destination pod's Calico WorkloadEndpoint did
	// not reach the ready predicate (CalicoHandoff.WaitForWorkloadEndpointReady timed out) —
	// Felix has not confirmed the dataplane has been programmed for the preserved IP within
	// the poll deadline. Fail-closed: block/requeue rather than crediting an unconfirmed
	// endpoint. See tryEstablishDataplaneReachability.
	ReasonCalicoWorkloadEndpointNotReady = "CalicoWorkloadEndpointNotReady"
	// ReasonCalicoDataplaneProgrammed: POSITIVE reason. CalicoHandoff.WaitForWorkloadEndpointReady
	// confirmed the replacement pod's Calico WorkloadEndpoint is active, the analogous
	// authoritative signal to ReasonCiliumDataplaneProgrammed for a Calico cross-node
	// destination. See tryEstablishDataplaneReachability.
	ReasonCalicoDataplaneProgrammed = "CalicoDataplaneProgrammed"
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

// PVCTierClassification is the CRD-status mirror of internal/agent/storage.TierClassification
// for a single PVC, persisted so later phases (Cutover/AwaitSingleOwner) can use a classification
// computed while the source pod still existed, instead of re-fetching a pod that ADR-0356's
// Tier1-Longhorn early release may have already deleted. Field values and meaning are identical
// to internal/agent/storage.TierClassification (Tier: 0=RWX, 1=Longhorn, 2=CephRBD,
// 3=SnapshotRsync, 4=Blocked) — kept as a separate type here rather than importing the storage
// package to avoid an api/v1alpha1 -> internal/agent/storage dependency.
type PVCTierClassification struct {
	// Tier is the storage migration tier for this PVC (0=RWX, 1=Longhorn, 2=CephRBD, 3=SnapshotRsync, 4=Blocked).
	Tier int32 `json:"tier"`
	// Reason explains why this PVC was classified into Tier.
	// +optional
	Reason string `json:"reason,omitempty"`
	// PVCName is the volume name as it appears in the pod's Spec.Volumes list, or the PVC
	// claim name for volumes backed by a PersistentVolumeClaim.
	PVCName string `json:"pvcName"`
	// StorageClass is the PVC's storage class name, if any.
	// +optional
	StorageClass string `json:"storageClass,omitempty"`
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

	// DataIntact is set to true when post-restore application-level data integrity
	// is confirmed (e.g. Redis key survives, Postgres row count matches).
	// Set by the reconciler after the post-restore integrity gate passes.
	// +optional
	DataIntact *bool `json:"dataIntact,omitempty"`

	// CRIURestoreConfirmed is set to true by the destination agent's
	// AgentServer.ReportRestoreConfirmed (internal/agent/server/server.go), which persists it
	// via a Status().Patch after a successful CRIU restore, confirming memory images were
	// replayed. NOT set directly by the NRI plugin (ADR-0352 DR-13-class correction).
	// +optional
	CRIURestoreConfirmed *bool `json:"criuRestoreConfirmed,omitempty"`

	// RestoredPID is the root PID of the restored container process tree,
	// set by the NRI plugin after successful CRIU restore.
	// +optional
	RestoredPID int32 `json:"restoredPID,omitempty"`

	// ReplVethMAC is the replacement pod's eth0 MAC address inside the pod netns,
	// collected by the NRI plugin at restore time and threaded through
	// ReportRestoreConfirmed. The controller passes it to InjectIPHandoff on the
	// destination agent so the OLD pod IP resolves to the replacement veth (ADR-0133 D3).
	// +optional
	ReplVethMAC string `json:"replVethMAC,omitempty"`

	// StorageTier is the detected storage migration tier (0=RWX, 1=Longhorn, 2=CephRBD, 3=SnapshotRsync, 4=Blocked).
	// +optional
	StorageTier *int32 `json:"storageTier,omitempty"`

	// ClassifiedVolumes caches the per-PVC storage tier classification computed by
	// StorageMigrationManager.RunPreStage while the source pod is still guaranteed to
	// exist (PreMigrating phase). StorageMigrationManager.Cutover and AwaitSingleOwner
	// (called later, from reconcileOverlayHandoff's gateStorageCutoverBeforeRestore) MUST
	// read this cache instead of re-fetching and re-classifying the live source pod: for
	// Tier1-Longhorn, ADR-0356 deliberately deletes the source pod right after
	// CheckpointTransferred=True — well before Cutover runs — so a live re-fetch at Cutover
	// time 404s every time (sprint49 live-proof finding: migration permanently stuck in
	// OverlayHandoff with reason CutoverFailed / "get source pod: ... not found"). The PVC
	// objects themselves are not deleted by ADR-0356 (only the pod is), so classification
	// computed once from the live pod's volume list remains valid for the rest of the
	// migration.
	// +optional
	ClassifiedVolumes []PVCTierClassification `json:"classifiedVolumes,omitempty"`

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
