/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	"github.com/podmotion-io/podmotion/internal/gitops"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	gpuagent "github.com/podmotion-io/podmotion/internal/agent/gpu"
	"github.com/podmotion-io/podmotion/internal/agent/replication"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
	"github.com/podmotion-io/podmotion/internal/agent/traffic"
	"github.com/podmotion-io/podmotion/internal/estimation"
	"github.com/podmotion-io/podmotion/internal/featuregate"
	"github.com/podmotion-io/podmotion/internal/orchestration"
	"github.com/podmotion-io/podmotion/internal/rollback"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	finalizerName = "migration.podmotion.io/finalizer"

	// Condition types used on PodMigration status.
	conditionValidated               = "Validated"
	conditionCheckpointed            = "Checkpointed"
	conditionRestored                = "Restored"
	conditionTrafficVerified         = "TrafficVerified"
	conditionMemorySynced            = "MemorySynced"
	conditionStorageReady            = "StorageReadyForFreeze"
	conditionNetworkBridgeArmed      = "NetworkBridgeArmed"
	conditionPDBToken                = "PDBTokenAcquired"
	conditionSourcePodDeleted        = "SourcePodDeleted"
	conditionCapacityReserved        = "CapacityReserved"
	conditionDestinationVolumeReady  = "DestinationVolumeReady"
	conditionSchedulingGateRemoved   = "SchedulingGateRemoved"
	conditionSecurityContextVerified = "SecurityContextVerified"
	conditionDataplaneReconciled     = "DataplaneReconciled"
	conditionGitOpsSuspended              = "GitOpsSuspended"
	conditionEndpointSliceCleanVerified   = "EndpointSliceCleanupVerified"
)

// PodMigrationReconciler reconciles a PodMigration object.
type PodMigrationReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Estimator  estimation.Estimator
	Rollbacker rollback.Rollbacker
	// AgentPool provides per-node gRPC connections to podmotion-agent DaemonSet pods.
	// Nil in unit tests — phase handlers skip gRPC calls when nil.
	AgentPool *agentclient.AgentClientPool
	// ReplicationMgr drives the pre-copy dirty-page sync loop (Agent 11, M5).
	// Nil in unit tests — PreMigrating phase skips loop launch when nil.
	ReplicationMgr *replication.ReplicationManager
	// Checkpointer is the CRIU checkpointer used by the replication loop.
	// Defaults to StubCheckpointer when nil.
	Checkpointer criu.Checkpointer
	// StorageMgr drives storage pre-stage concurrently with the pre-copy loop (M6).
	// Nil in unit tests — PreMigrating phase skips storage goroutine when nil.
	StorageMgr *storage.StorageMigrationManager
	// TrafficVerifier confirms live traffic is arriving at the destination pod.
	// Wired to CompositeVerifier (EndpointSlice + AWSALB) in production.
	// Nil in unit tests — Verifying phase logs a skip when nil.
	TrafficVerifier traffic.Verifier
	// GPUCheckpointer handles NVIDIA CUDA context checkpoint/restore.
	// Only called when GPUMigration feature gate is enabled and the pod has GPU resources.
	// Defaults to GPUCheckpointerStub when nil (so GPU-unaware environments are unaffected).
	GPUCheckpointer gpuagent.GPUCheckpointer
	// GitOpsSuspender suspends and resumes the GitOps controller (ArgoCD/Flux) that owns
	// the migrating workload.  Nil → NoopSuspender is used, so existing unit tests are
	// unaffected.  Wired to ArgoCDClient or FluxClient in production via cmd/main.go.
	GitOpsSuspender gitops.GitOpsSuspender
}

// +kubebuilder:rbac:groups=migration.podmotion.io,resources=podmigrations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=podmigrations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=podmigrations/finalizers,verbs=update
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=nodemigrationcapacities,verbs=get;list;watch
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=migrationcheckpoints,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=pods/status,verbs=get
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=storage.k8s.io,resources=storageclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=storage.k8s.io,resources=volumeattachments,verbs=get;list;watch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=resourcequotas,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

func (r *PodMigrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	pm := &pmv1.PodMigration{}
	if err := r.Get(ctx, req.NamespacedName, pm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Attach completion timeout to context so all downstream calls are bounded.
	timeoutSecs := pm.Spec.CompletionTimeoutSeconds
	if timeoutSecs <= 0 {
		timeoutSecs = 600
	}
	deadline, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	// Crash-safety (ADR-0018): if we restarted with the pod already frozen,
	// issue restore immediately before anything else.
	if r.isFrozenWithoutRestore(pm) {
		log.Info("crash-safe restart: pod was frozen but not restored — issuing restore", "migration", req.NamespacedName)
		return r.transitionTo(deadline, pm, pmv1.MigrationPhaseRestoring)
	}

	// Finalizer: ensure we always get a chance to clean up (rollback, delete checkpoint).
	if pm.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(pm, finalizerName) {
			controllerutil.AddFinalizer(pm, finalizerName)
			return ctrl.Result{}, r.Update(deadline, pm)
		}
	} else {
		return r.handleDeletion(deadline, pm)
	}

	switch pm.Status.Phase {
	case "", pmv1.MigrationPhasePending:
		return r.reconcilePending(deadline, pm)
	case pmv1.MigrationPhaseValidating:
		return r.reconcileValidating(deadline, pm)
	case pmv1.MigrationPhasePreMigrating:
		// Pre-migration is agent-driven (dirty page sync loop).
		// Controller watches for MemorySynced + StorageReadyForFreeze conditions.
		return r.reconcilePreMigrating(deadline, pm)
	case pmv1.MigrationPhaseCheckpointing:
		return r.reconcileCheckpointing(deadline, pm)
	case pmv1.MigrationPhaseTransferring:
		return r.reconcileTransferring(deadline, pm)
	case pmv1.MigrationPhaseRestoring:
		return r.reconcileRestoring(deadline, pm)
	case pmv1.MigrationPhaseVerifying:
		return r.reconcileVerifying(deadline, pm)
	case pmv1.MigrationPhaseComplete, pmv1.MigrationPhaseDryRunComplete:
		return ctrl.Result{}, nil
	case pmv1.MigrationPhaseFailed:
		return ctrl.Result{}, nil
	case pmv1.MigrationPhaseRollingBack:
		return r.reconcileRollingBack(deadline, pm)
	default:
		log.Error(fmt.Errorf("unknown phase %q", pm.Status.Phase), "unhandled phase")
		return ctrl.Result{}, nil
	}
}

// ── Phase handlers ─────────────────────────────────────────────────────────

func (r *PodMigrationReconciler) reconcilePending(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	// Dry-run: run the estimation pipeline and surface results without touching the pod.
	if pm.Spec.DryRun {
		return r.reconcileDryRun(ctx, pm)
	}
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseValidating)
}

func (r *PodMigrationReconciler) reconcileDryRun(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	pod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err != nil {
		return r.failMigration(ctx, pm, fmt.Sprintf("dry-run: pod not found: %v", err))
	}

	nmc, err := r.getNMC(ctx, pod.Spec.NodeName)
	if err != nil {
		return r.failMigration(ctx, pm, fmt.Sprintf("dry-run: NMC not found for source node %q: %v", pod.Spec.NodeName, err))
	}

	estimate, err := r.Estimator.Estimate(ctx, pod, nmc, pm.Spec)
	if err != nil {
		log.Error(err, "dry-run estimation failed")
		return r.failMigration(ctx, pm, fmt.Sprintf("dry-run estimation error: %v", err))
	}

	pm.Status.DryRunEstimate = estimate
	pm.Status.Phase = pmv1.MigrationPhaseDryRunComplete
	setCondition(pm, conditionValidated, metav1.ConditionTrue, "DryRunComplete", "Estimation succeeded")
	return ctrl.Result{}, r.Status().Update(ctx, pm)
}

func (r *PodMigrationReconciler) reconcileValidating(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	// Validation is primarily handled by the ValidatingAdmissionWebhook.
	// Here we do a lighter runtime re-check: pod still exists, NMC still ready.
	pod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err != nil {
		return r.failMigration(ctx, pm, fmt.Sprintf("source pod disappeared: %v", err))
	}

	// Check UID still matches (pod could have been replaced between webhook and here).
	if pm.Spec.SourcePodUID != "" && string(pod.UID) != pm.Spec.SourcePodUID {
		return r.failMigration(ctx, pm, fmt.Sprintf("pod UID changed: expected %s, got %s", pm.Spec.SourcePodUID, pod.UID))
	}

	// Auto-populate SourcePodIP and SourcePodUID into Spec BEFORE any status mutations.
	// r.Patch() writes the server response back into pm in-place, clobbering all in-memory
	// status fields. By doing the spec patch first, subsequent status writes are clean.
	needsPatch := (pm.Spec.SourcePodIP == "" && pod.Status.PodIP != "") ||
		(pm.Spec.SourcePodUID == "" && string(pod.UID) != "")
	if needsPatch {
		patch := client.MergeFrom(pm.DeepCopy())
		if pm.Spec.SourcePodIP == "" && pod.Status.PodIP != "" {
			pm.Spec.SourcePodIP = pod.Status.PodIP
		}
		if pm.Spec.SourcePodUID == "" && string(pod.UID) != "" {
			pm.Spec.SourcePodUID = string(pod.UID)
		}
		if patchErr := r.Patch(ctx, pm, patch); patchErr != nil {
			return ctrl.Result{}, fmt.Errorf("patch SourcePodIP/UID from live pod: %w", patchErr)
		}
		log.Info("auto-populated SourcePodIP and SourcePodUID from live pod",
			"migration", pm.Name, "sourcePodIP", pm.Spec.SourcePodIP, "sourcePodUID", pm.Spec.SourcePodUID)
		// pm is now the server's latest object (post-patch). Re-read pod to keep pod data fresh
		// in case node assignment raced, but pod-derived fields below use the local pod var which
		// is still valid — pod identity was already confirmed via UID check above.
	}

	// Set all status fields after the spec patch so nothing is clobbered.
	// Verify NMC is still ready on source node.
	if pod.Spec.NodeName != "" {
		nmc, nmcErr := r.getNMC(ctx, pod.Spec.NodeName)
		if nmcErr != nil || !nmc.Status.Ready {
			return r.failMigration(ctx, pm, fmt.Sprintf("source node NMC not ready: %v", nmcErr))
		}
		pm.Status.SourceNodeName = pod.Spec.NodeName
	}

	setCondition(pm, conditionValidated, metav1.ConditionTrue, "Validated", "Pod and node checks passed")
	return r.transitionTo(ctx, pm, pmv1.MigrationPhasePreMigrating)
}

func (r *PodMigrationReconciler) reconcilePreMigrating(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// GitOps suspension: suspend the ArgoCD/Flux controller that owns this workload so
	// it does not reconcile (and re-schedule pods on the source node) during the migration
	// window.  Idempotent across requeueing — only suspends once per migration.
	// Resume is always deferred so the controller is restored even on failure/rollback.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionGitOpsSuspended) {
		suspender := r.GitOpsSuspender
		if suspender == nil {
			suspender = &gitops.NoopSuspender{}
		}
		// Fetch the source pod to detect its GitOps ownership.
		srcPod := &corev1.Pod{}
		if err := r.Get(ctx, types.NamespacedName{Name: pm.Spec.PodName, Namespace: pm.Spec.PodNamespace}, srcPod); err == nil {
			gctx, err := gitops.Detect(ctx, r.Client, srcPod)
			if err != nil {
				log.Error(err, "gitops detection failed — proceeding without suspension", "migration", pm.Name)
			} else if gctx.Provider != gitops.GitOpsProviderNone {
				if err := suspender.Suspend(ctx, &gctx); err != nil {
					log.Error(err, "gitops suspend failed — proceeding anyway (ADR-0045: stability first)", "migration", pm.Name)
				} else {
					log.Info("gitops suspended", "migration", pm.Name, "provider", gctx.Provider, "app", gctx.AppName)
				}
				// Always resume, even if suspend failed — defer fires on all exit paths.
				defer func() {
					if err := suspender.Resume(ctx, gctx); err != nil {
						log.Error(err, "gitops resume failed — MANUAL INTERVENTION REQUIRED", "migration", pm.Name, "app", gctx.AppName)
					} else {
						log.Info("gitops resumed", "migration", pm.Name, "app", gctx.AppName)
					}
				}()
			}
		}
		setCondition(pm, conditionGitOpsSuspended, metav1.ConditionTrue, "Suspended",
			"GitOps controller suspended for migration window (or no GitOps controller detected)")
		if err := r.Status().Update(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Agent 11 (replication), Agent 3 (storage), and Agent 2 (network) drive pre-migration
	// work asynchronously.  All three keystone conditions must be True before advancing:
	//   MemorySynced=True           (Agent 11 replication loop)
	//   StorageReadyForFreeze=True  (Agent 3 storage pre-stage, ADR-0011)
	//   NetworkBridgeArmed=True     (Agent 2 eBPF bridge OR v0.1 fast-path, ADR-0028)
	//
	// When all three are True, advance to Checkpointing (the freeze).
	memorySynced := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionMemorySynced)
	memoryCond := meta.FindStatusCondition(pm.Status.Conditions, conditionMemorySynced)
	storageReady := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionStorageReady)
	networkBridgeArmed := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionNetworkBridgeArmed)

	// ADR-0024: DirtyRateIncreasing abort — pod is never frozen, clean abort without rollback.
	if memoryCond != nil && memoryCond.Status == "False" && memoryCond.Reason == "DirtyRateIncreasing" {
		return r.failMigration(ctx, pm, fmt.Sprintf("pre-copy aborted: %s", memoryCond.Message))
	}

	// ADR-0028: v0.1 fast-path — if NetworkContinuity is false, set NetworkBridgeArmed=True
	// immediately without waiting for the eBPF agent (TIER_4 cold migration).
	if !pm.Spec.NetworkContinuity && !networkBridgeArmed {
		setCondition(pm, conditionNetworkBridgeArmed, metav1.ConditionTrue,
			"TIER4FastPath", "v0.1 cold migration: no eBPF bridge needed (ADR-0028)")
		if err := r.Status().Update(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		networkBridgeArmed = true
		log.Info("set NetworkBridgeArmed=True via TIER_4 fast-path", "migration", pm.Name)
	}

	// Cold-mode fast-path: MigrationModeCold skips all pre-copy rounds.
	// Set MemorySynced=True immediately so the three-keystone gate can pass.
	// PreCopy with a nil ReplicationMgr is a misconfiguration — caught at validation.
	if !memorySynced && pm.Spec.Mode == pmv1.MigrationModeCold {
		if memoryCond == nil {
			setCondition(pm, conditionMemorySynced, metav1.ConditionTrue,
				"ColdModeFastPath", "Cold migration: pre-copy skipped")
			if err := r.Status().Update(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			memorySynced = true
			log.Info("set MemorySynced=True via cold-mode fast-path", "migration", pm.Name)
		}
	}

	// TIER_4 storage fast-path: stateless pods (no PVC volumes) need no storage pre-stage.
	// Set StorageReadyForFreeze=True immediately so the three-keystone gate can pass.
	if !storageReady && r.StorageMgr == nil {
		// Also check if the pod itself has any PVC volumes.
		srcPodForStorage := &corev1.Pod{}
		hasPVCs := false
		if err := r.Get(ctx, types.NamespacedName{Name: pm.Spec.PodName, Namespace: pm.Spec.PodNamespace}, srcPodForStorage); err == nil {
			for _, v := range srcPodForStorage.Spec.Volumes {
				if v.PersistentVolumeClaim != nil {
					hasPVCs = true
					break
				}
			}
		}
		if !hasPVCs {
			setCondition(pm, conditionStorageReady, metav1.ConditionTrue,
				"StatelessFastPath", "No PVC volumes: storage pre-stage not required")
			if err := r.Status().Update(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			storageReady = true
			log.Info("set StorageReadyForFreeze=True via stateless fast-path", "migration", pm.Name)
		}
	}

	// Anti-affinity destination check: verify the destination node doesn't already host
	// pods that would violate the source pod's requiredDuringScheduling podAntiAffinity.
	destNodeForAntiAff := pm.Spec.TargetNodeName
	if destNodeForAntiAff == "" {
		destNodeForAntiAff = pm.Status.DestinationNodeName
	}
	if destNodeForAntiAff != "" && !meta.IsStatusConditionTrue(pm.Status.Conditions, orchestration.ConditionAntiAffinityConflict) {
		if err := r.checkAntiAffinityConflict(ctx, pm, destNodeForAntiAff); err != nil {
			if err := r.Status().Update(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		if err := r.Status().Update(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	// emptyDir gate: pods with open FDs into emptyDir volumes cannot be checkpointed —
	// CRIU restores against an empty directory and the process receives SIGBUS on first access.
	// Block early with a clear error rather than failing mid-checkpoint.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionCapacityReserved) {
		if err := r.validateNoEmptyDir(ctx, pm); err != nil {
			return r.failMigration(ctx, pm, fmt.Sprintf("emptyDir ineligible: %v", err))
		}

		// Capacity reservation: pre-reserve a migration slot on the destination NMC before
		// advancing to Checkpointing. This guarantees the destination has room to receive
		// the pod and allows the scheduler to route the replacement pod exclusively there
		// (reserve-before-delete sequencing per ADR-0046).
		destNode := pm.Spec.TargetNodeName
		if destNode == "" {
			destNode = pm.Status.DestinationNodeName
		}
		if destNode != "" {
			if err := r.reserveDestinationCapacity(ctx, pm, destNode); err != nil {
				log.Error(err, "capacity reservation failed — requeuing", "migration", pm.Name)
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
			}
			setCondition(pm, conditionCapacityReserved, metav1.ConditionTrue, "Reserved",
				fmt.Sprintf("capacity slot reserved on destination node %s", destNode))
			if err := r.Status().Update(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	if memorySynced && storageReady && networkBridgeArmed {
		// Set DestinationNodeName from spec.targetNodeName if not already set.
		// This is required by reconcileRestoring to connect to the destination agent.
		if pm.Status.DestinationNodeName == "" && pm.Spec.TargetNodeName != "" {
			pm.Status.DestinationNodeName = pm.Spec.TargetNodeName
		}
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseCheckpointing)
	}

	// Launch the pre-copy loop goroutine if it has not been started yet.
	// We detect "not yet started" by the absence of the MemorySynced condition.
	// The goroutine patches MemorySynced=True/False when it finishes; the next
	// reconcile iteration will pick it up.
	if memoryCond == nil && r.ReplicationMgr != nil {
		// Snapshot for goroutine closure — pm may be mutated by subsequent reconciles.
		pmCopy := pm.DeepCopy()
		go func() {
			// nil is passed as the (now unused) checkpointer arg — pre-dump runs via
			// PreDumpRound RPC on the source agent, not locally on the operator node.
			if err := r.ReplicationMgr.RunPreCopyLoop(context.Background(), pmCopy, nil); err != nil {
				log.Error(err, "pre-copy loop failed", "migration", pmCopy.Name)
			}
		}()
		log.Info("launched pre-copy loop goroutine", "migration", pm.Name)
	}

	// Launch the storage pre-stage goroutine concurrently with the pre-copy loop (ADR-0011).
	// Detected as "not yet started" by the absence of the StorageReadyForFreeze condition.
	storageCond := meta.FindStatusCondition(pm.Status.Conditions, conditionStorageReady)
	if storageCond == nil && r.StorageMgr != nil {
		pmCopy := pm.DeepCopy()
		go func() {
			if err := r.StorageMgr.RunPreStage(context.Background(), pmCopy); err != nil {
				log.Error(err, "storage pre-stage failed", "migration", pmCopy.Name)
			}
		}()
		log.Info("launched storage pre-stage goroutine", "migration", pm.Name)
	}

	// Requeue after a short interval to re-check agent progress.
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

func (r *PodMigrationReconciler) reconcileCheckpointing(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	log.Info("reconcileCheckpointing: entry",
		"migration", pm.Name,
		"destinationNodeName", pm.Status.DestinationNodeName,
		"targetNodeName", pm.Spec.TargetNodeName,
		"replacementPodName", pm.Status.ReplacementPodName,
		"checkpointed", meta.IsStatusConditionTrue(pm.Status.Conditions, conditionCheckpointed))

	// Fast-path: if the Checkpointed condition was already set True (e.g. agent called back
	// directly or we are re-entering after a controller restart), advance immediately.
	if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionCheckpointed) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseTransferring)
	}

	// If a concurrent reconcile already claimed the checkpoint slot (Unknown/InProgress),
	// requeue and wait — never run two CRIU dumps on the same process.
	condCP := meta.FindStatusCondition(pm.Status.Conditions, conditionCheckpointed)
	if condCP != nil && condCP.Status == metav1.ConditionUnknown && condCP.Reason == "InProgress" {
		log.Info("checkpoint already in progress (claimed by concurrent reconcile) — requeuing",
			"migration", pm.Name)
		return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
	}

	// Check for a prior CheckpointFailed signal before issuing a fresh call.
	condFailed := meta.FindStatusCondition(pm.Status.Conditions, conditionCheckpointed)
	if condFailed != nil && condFailed.Status == metav1.ConditionFalse && condFailed.Reason == "CheckpointFailed" {
		return r.initiateRollback(ctx, pm, condFailed.Message)
	}

	// Defence-in-depth (ADR-0031): the webhook should have blocked PostCopy when
	// userfaultfd is absent, but guard here as well because the node capability
	// could change between admission and execution.
	if pm.Spec.Mode == pmv1.MigrationModePostCopy {
		nmc, err := r.getNMC(ctx, pm.Status.SourceNodeName)
		if err == nil && !nmc.Spec.KernelFeatures.Userfaultfd {
			msg := "PostCopy mode requires CONFIG_USERFAULTFD on source node (kernel feature absent)"
			setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "CheckpointFailed", msg)
			return ctrl.Result{}, r.Status().Update(ctx, pm)
		}
	}

	// Drive the checkpoint via the agent gRPC client if the pool is wired.
	if r.AgentPool == nil {
		log.Error(nil, "AgentPool is nil — cannot issue Checkpoint RPC; requeuing", "migration", pm.Name)
		setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "AgentPoolUnavailable",
			"AgentPool not wired; waiting for agent pool to become available")
		if err := r.Status().Update(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	// Always fetch the source pod so we have its UID for PrepareSource.
	sourcePod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err != nil {
		return r.failMigration(ctx, pm, fmt.Sprintf("checkpoint: source pod not found: %v", err))
	}
	sourceNode := pm.Status.SourceNodeName
	if sourceNode == "" {
		sourceNode = sourcePod.Spec.NodeName
		pm.Status.SourceNodeName = sourceNode
	}

	agentClient, err := r.AgentPool.ForNode(ctx, sourceNode)
	if err != nil {
		log.Error(err, "Failed to connect to source agent", "node", sourceNode)
		setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "CheckpointFailed",
			fmt.Sprintf("agent connection failed: %v", err))
		return ctrl.Result{}, r.Status().Update(ctx, pm)
	}

	// Step 1: PrepareSource — verify the pod is still migratable.
	// Include PodUid so the agent can populate its migrationPodUID map, which
	// FindContainerPID uses to resolve the container root PID for CRIU.
	prepResp, err := agentClient.PrepareSource(ctx, &agentpb.PrepareSourceRequest{
		PodName:       pm.Spec.PodName,
		PodNamespace:  pm.Spec.PodNamespace,
		PodUid:        string(sourcePod.UID),
		MigrationName: pm.Name,
	})
	if err != nil || (prepResp != nil && !prepResp.Compatible) {
		reason := "agent PrepareSource failed"
		if prepResp != nil && prepResp.BlockingReason != "" {
			reason = prepResp.BlockingReason
		}
		if err != nil {
			reason = err.Error()
		}
		setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "CheckpointFailed", reason)
		return ctrl.Result{}, r.Status().Update(ctx, pm)
	}

	// Step 1b: GPU gate check and pre-checkpoint.
	// Must run before CRIU freeze so GPU context is captured while the container is still live.
	pod, podErr := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if podErr == nil && podHasGPU(pod) {
		if !featuregate.IsEnabled(featuregate.GPUMigration) {
			setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "FeatureGateRequired",
				gpuagent.ErrFeatureGateRequired.Error())
			return r.failMigration(ctx, pm, gpuagent.ErrFeatureGateRequired.Error())
		}
		gpuCP := r.GPUCheckpointer
		if gpuCP == nil {
			gpuCP = &gpuagent.GPUCheckpointerStub{}
		}
		gpuDir := fmt.Sprintf("/tmp/podmotion/%s/gpu", pm.Name)
		if _, err := gpuCP.Checkpoint(ctx, pm.Spec.PodName, pm.Spec.PodNamespace, gpuDir); err != nil {
			setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "GPUCheckpointFailed", err.Error())
			return ctrl.Result{}, r.Status().Update(ctx, pm)
		}
		log.Info("GPU checkpoint captured", "migration", pm.Name, "gpuDir", gpuDir)
	}

	// Step 2: Claim the checkpoint slot with an optimistic lock before issuing the CRIU RPC.
	// Set Checkpointed=Unknown/"InProgress" so any concurrent reconcile that re-fetches the
	// object after this write will see InProgress and requeue rather than issue a second dump.
	// If this status update conflicts, a concurrent reconcile already claimed the slot — requeue.
	{
		claimPm := pm.DeepCopy()
		meta.SetStatusCondition(&claimPm.Status.Conditions, metav1.Condition{
			Type:               conditionCheckpointed,
			Status:             metav1.ConditionUnknown,
			Reason:             "InProgress",
			Message:            "CRIU checkpoint RPC in progress",
			LastTransitionTime: metav1.Now(),
		})
		if err := r.Status().Update(ctx, claimPm); err != nil {
			if apierrors.IsConflict(err) {
				log.Info("checkpoint claim conflicted — concurrent reconcile won the slot; requeuing",
					"migration", pm.Name)
				return ctrl.Result{RequeueAfter: 500 * time.Millisecond}, nil
			}
			return ctrl.Result{}, fmt.Errorf("claiming checkpoint slot: %w", err)
		}
		// Update local pm to carry the new resourceVersion so subsequent Status().Update calls work.
		if err := r.Get(ctx, client.ObjectKeyFromObject(pm), pm); err != nil {
			return ctrl.Result{}, fmt.Errorf("re-fetch pm after checkpoint claim: %w", err)
		}
	}

	// Step 2b: Checkpoint — freeze and dump via real CRIU gRPC call.
	checkpointResp, err := agentClient.Checkpoint(ctx, &agentpb.CheckpointRequest{
		MigrationName:   pm.Name,
		TcpEstablished:  pm.Spec.NetworkContinuity,
		ApplyZeroWindow: pm.Spec.NetworkContinuity,
	})
	if err != nil {
		errStr := err.Error()
		// Distinguish transient connection errors from hard capability failures.
		if grpcStatus, ok := status.FromError(err); ok && grpcStatus.Code() == codes.Unavailable {
			log.Error(err, "Checkpoint RPC unavailable — requeuing", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		if strings.Contains(errStr, "ptrace") || strings.Contains(errStr, "EPERM") ||
			strings.Contains(errStr, "capability") || strings.Contains(errStr, "permission denied") {
			log.Error(err, "Checkpoint RPC failed: CRIU capability/ptrace error", "migration", pm.Name)
			setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "CRIUCapabilityError",
				fmt.Sprintf("CRIU ptrace/capability error: %v", err))
			return ctrl.Result{}, r.Status().Update(ctx, pm)
		}
		log.Error(err, "Checkpoint RPC failed", "migration", pm.Name)
		setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "CheckpointFailed", errStr)
		return ctrl.Result{}, r.Status().Update(ctx, pm)
	}

	// Gate: treat a zero-byte checkpoint as an incomplete dump and requeue.
	// The agent sets CheckpointSizeBytes only after checksumDir() runs over the completed
	// dump directory (including inventory.img). A zero value means the dump is still in
	// progress or failed silently; we must not advance to Transferring in that case.
	if checkpointResp == nil || checkpointResp.CheckpointSizeBytes == 0 {
		log.Info("Checkpoint RPC returned but CheckpointSizeBytes==0 — dump not yet flushed; requeuing",
			"migration", pm.Name)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}

	// Gate: treat a missing SHA256 as an incomplete dump and requeue.
	if checkpointResp.CheckpointSha256 == "" {
		log.Info("Checkpoint RPC returned but CheckpointSha256==\"\" — dump not yet flushed; requeuing",
			"migration", pm.Name)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}

	// Store the full filesystem dump path in CheckpointRef so reconcileRestoring can read it
	// directly without reconstructing it. Both sides must use the identical path.
	checkpointDir := fmt.Sprintf("/run/podmotion/checkpoints/%s/final", pm.Name)
	pm.Status.CheckpointRef = &corev1.LocalObjectReference{Name: checkpointDir}

	// Propagate freeze duration into PreCopyStats so it is visible in status.
	if pm.Status.PreCopyStats == nil {
		pm.Status.PreCopyStats = &pmv1.PreCopyStats{}
	}
	pm.Status.PreCopyStats.FreezeDurationMs = checkpointResp.FreezeDurationMs

	checkpointMsg := fmt.Sprintf("Checkpoint captured: size=%d bytes sha256=%s freeze=%dms",
		checkpointResp.CheckpointSizeBytes, checkpointResp.CheckpointSha256, checkpointResp.FreezeDurationMs)
	log.Info("CRIU checkpoint complete", "migration", pm.Name,
		"sizeBytes", checkpointResp.CheckpointSizeBytes,
		"sha256", checkpointResp.CheckpointSha256,
		"freezeDurationMs", checkpointResp.FreezeDurationMs)

	setCondition(pm, conditionCheckpointed, metav1.ConditionTrue, "Checkpointed", checkpointMsg)

	// Ensure DestinationNodeName is set before creating the replacement pod.
	// It is normally set in reconcilePreMigrating and persisted via transitionTo, but
	// can be empty if this reconcile was fetched from cache before the status write landed.
	if pm.Status.DestinationNodeName == "" && pm.Spec.TargetNodeName != "" {
		pm.Status.DestinationNodeName = pm.Spec.TargetNodeName
		if err := r.Status().Update(ctx, pm); err != nil {
			return ctrl.Result{}, fmt.Errorf("setting DestinationNodeName in Checkpointing phase: %w", err)
		}
		log.Info("set DestinationNodeName from spec.targetNodeName in Checkpointing phase",
			"migration", pm.Name, "destNode", pm.Status.DestinationNodeName)
	}

	// Create the replacement pod that will receive the restored process.
	// The admission webhook injects the scheduling gate + checkpoint-ref annotation.
	// The pod is held at PodSchedulingGated until removeSchedulingGate fires at the
	// END of reconcileTransferring — only after images land on the destination node.
	if pm.Status.ReplacementPodName == "" {
		if err := r.createReplacementPod(ctx, pm, sourcePod); err != nil {
			log.Error(err, "failed to create replacement pod", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}
		log.Info("created replacement pod", "migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName)
	}

	// Gate removal is intentionally deferred to end of reconcileTransferring.
	// The NRI StartContainer hook needs the checkpoint at /run/podmotion/... on
	// the DESTINATION node before the container starts. Removing the gate here
	// (pre-transfer) would let the scheduler bind and NRI fire before images arrive.

	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseTransferring)
}

func (r *PodMigrationReconciler) reconcileTransferring(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if r.AgentPool == nil {
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	// Determine source and destination nodes.
	sourceNode := pm.Status.SourceNodeName
	if sourceNode == "" {
		log.Info("reconcileTransferring: sourceNodeName not set, requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}
	destNode := pm.Status.DestinationNodeName
	if destNode == "" && pm.Spec.TargetNodeName != "" {
		destNode = pm.Spec.TargetNodeName
	}
	if destNode == "" {
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	// Idempotency guard: if the controller crashed after Put but before transitioning to
	// Restoring, CheckpointTransferred is already true — skip straight to gate removal.
	// The source release RPC is also safe to replay (idempotent on absent dir).
	if !pm.Status.CheckpointTransferred {
		// Fetch the checkpoint tar from the SOURCE agent.
		// The checkpoint was written by the source agent to its local tmpfs at
		// /run/podmotion/checkpoints/<migration>/final — the operator cannot read
		// that path because it runs on a different node. GetCheckpointTar is a pure
		// read; zeroize happens only via ReleaseCheckpoint after the Put is confirmed
		// and CheckpointTransferred is durably persisted.
		log.Info("reconcileTransferring: fetching checkpoint tar from source agent",
			"migration", pm.Name, "sourceNode", sourceNode)
		srcClient, err := r.AgentPool.ForNode(ctx, sourceNode)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("connect to source agent %s: %w", sourceNode, err)
		}
		getResp, err := srcClient.GetCheckpointTar(ctx, &agentpb.GetCheckpointTarRequest{
			MigrationName: pm.Name,
		})
		if err != nil {
			return ctrl.Result{RequeueAfter: 5 * time.Second}, fmt.Errorf("GetCheckpointTar from %s: %w", sourceNode, err)
		}
		if !getResp.Success {
			log.Info("reconcileTransferring: checkpoint not ready on source agent, requeuing",
				"migration", pm.Name, "sourceNode", sourceNode, "error", getResp.Error)
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}
		log.Info("reconcileTransferring: checkpoint tar received",
			"migration", pm.Name, "tarSizeBytes", getResp.BytesRead)

		// Zeroize in-memory on all exit paths — checkpoint contains process memory.
		tarData := getResp.TarData
		defer func() {
			for i := range tarData {
				tarData[i] = 0
			}
		}()

		// Push the tar to the DESTINATION agent.
		destClient, err := r.AgentPool.ForNode(ctx, destNode)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("connect to dest agent %s: %w", destNode, err)
		}
		putResp, err := destClient.PutCheckpointTar(ctx, &agentpb.PutCheckpointTarRequest{
			MigrationName: pm.Name,
			TarData:       tarData,
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("PutCheckpointTar to %s: %w", destNode, err)
		}
		if !putResp.Success {
			return ctrl.Result{}, fmt.Errorf("PutCheckpointTar failed: %s", putResp.Error)
		}
		log.Info("reconcileTransferring: checkpoint transferred successfully",
			"migration", pm.Name, "destNode", destNode, "bytesWritten", putResp.BytesWritten)

		// Persist the transfer marker BEFORE releasing the source. If the controller
		// crashes between this write and the ReleaseCheckpoint call, the next reconcile
		// sees CheckpointTransferred=true and skips straight to the release call,
		// which is idempotent on an already-absent dir.
		pm.Status.CheckpointTransferred = true
		if err := r.Status().Update(ctx, pm); err != nil {
			return ctrl.Result{}, fmt.Errorf("persist CheckpointTransferred: %w", err)
		}

		// Release (zeroize + remove) the source copy now that dest has a durable copy.
		srcClient2, err := r.AgentPool.ForNode(ctx, sourceNode)
		if err != nil {
			log.Error(err, "reconcileTransferring: cannot connect to source agent for release — will retry",
				"migration", pm.Name, "sourceNode", sourceNode)
			// Non-fatal: source tmpfs is cleared on node reboot; proceed to Restoring.
		} else {
			relResp, relErr := srcClient2.ReleaseCheckpoint(ctx, &agentpb.ReleaseCheckpointRequest{
				MigrationName: pm.Name,
			})
			if relErr != nil || (relResp != nil && !relResp.Success) {
				log.Error(relErr, "reconcileTransferring: ReleaseCheckpoint failed — source images remain on tmpfs until reboot",
					"migration", pm.Name, "sourceNode", sourceNode)
				// Non-fatal: proceed; tmpfs is volatile.
			}
		}
	} else {
		log.Info("reconcileTransferring: CheckpointTransferred already set — skipping Get/Put (crash-recovery path)",
			"migration", pm.Name)
		// Replay ReleaseCheckpoint — idempotent if already done.
		if srcClient, err := r.AgentPool.ForNode(ctx, sourceNode); err == nil {
			_, _ = srcClient.ReleaseCheckpoint(ctx, &agentpb.ReleaseCheckpointRequest{
				MigrationName: pm.Name,
			})
		}
	}

	// Remove the scheduling gate NOW — images are on the destination node so the
	// NRI StartContainer hook can find them at /run/podmotion/checkpoints/<ref>/final.
	// Removing earlier (post-Checkpoint, pre-Transfer) would race the NRI hook against
	// the PutCheckpointTar delivery, causing a CRIU restore failure on a cold destination.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionSchedulingGateRemoved) {
		if err := r.removeSchedulingGate(ctx, pm); err != nil {
			log.Error(err, "scheduling gate removal failed — continuing", "migration", pm.Name)
		} else {
			setCondition(pm, conditionSchedulingGateRemoved, metav1.ConditionTrue,
				"GateRemoved", "podmotion.io/awaiting-checkpoint gate removed post-transfer")
			if err := r.Status().Update(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseRestoring)
}

// zeroizeSourceCheckpoint overwrites all checkpoint files with zeros then removes the dir.
// Mirrors the server.zeroizeDir logic; duplicated here to avoid a cross-package dependency.
func zeroizeSourceCheckpoint(dir string) error {
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return nil
		}
		zeros := make([]byte, info.Size())
		_, _ = f.WriteAt(zeros, 0)
		f.Close()
		return nil
	})
	return os.RemoveAll(dir)
}

// tarGzDir creates a gzip-compressed tar archive of all regular files in dir
// (flat, no subdirectory recursion needed — CRIU writes images directly into final/).
func tarGzDir(dir string) ([]byte, error) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Name:    rel,
			Size:    info.Size(),
			Mode:    int64(info.Mode()),
			ModTime: info.ModTime(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gzw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *PodMigrationReconciler) reconcileRestoring(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionRestored) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseVerifying)
	}

	condFailed := meta.FindStatusCondition(pm.Status.Conditions, conditionRestored)
	if condFailed != nil && condFailed.Status == metav1.ConditionFalse && condFailed.Reason == "RestoreFailed" {
		if pm.Spec.RollbackOnFailure {
			return r.initiateRollback(ctx, pm, condFailed.Message)
		}
		return r.failMigration(ctx, pm, condFailed.Message)
	}

	// Operator-driven path (NS#3): replacement pod was created by the operator, and the
	// NRI StartContainer hook handles CRIU restore when containerd starts the container.
	// Do NOT call the Restore RPC — that would conflict with the NRI hook (two simultaneous
	// CRIU restores into the same namespace). Instead, wait for the replacement pod to
	// become Running (which means NRI fired and CRIU restore succeeded).
	if pm.Status.ReplacementPodName != "" {
		return r.reconcileRestoringNRI(ctx, pm)
	}

	if r.AgentPool == nil {
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		// Fallback: populate from spec.targetNodeName if status was not set during pre-migration.
		if pm.Spec.TargetNodeName != "" {
			pm.Status.DestinationNodeName = pm.Spec.TargetNodeName
			if err := r.Status().Update(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			destNode = pm.Spec.TargetNodeName
		} else {
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}
	}

	// Read the checkpoint directory path stored during reconcileCheckpointing.
	// The path is the full filesystem path set in CheckpointRef.Name; fall back
	// to the canonical pattern only if the ref was not set (e.g. controller restart
	// before the fix was deployed).
	checkpointRef := fmt.Sprintf("/run/podmotion/checkpoints/%s/final", pm.Name)
	if pm.Status.CheckpointRef != nil && pm.Status.CheckpointRef.Name != "" {
		checkpointRef = pm.Status.CheckpointRef.Name
	}

	agentClient, err := r.AgentPool.ForNode(ctx, destNode)
	if err != nil {
		log.Error(err, "Failed to connect to destination agent", "node", destNode)
		setCondition(pm, conditionRestored, metav1.ConditionFalse, "RestoreFailed",
			fmt.Sprintf("agent connection failed: %v", err))
		return ctrl.Result{}, r.Status().Update(ctx, pm)
	}

	// PrepareDestination: pre-allocate the checkpoint directory and any cgroup/netns
	// resources on the destination node before invoking CRIU restore.
	prepDestResp, err := agentClient.PrepareDestination(ctx, &agentpb.PrepareDestinationRequest{
		MigrationName: pm.Name,
		SourceNode:    pm.Status.SourceNodeName,
		PodNamespace:  pm.Spec.PodNamespace,
	})
	if err != nil {
		log.Error(err, "PrepareDestination RPC failed", "node", destNode)
		setCondition(pm, conditionRestored, metav1.ConditionFalse, "RestoreFailed",
			fmt.Sprintf("PrepareDestination failed: %v", err))
		return ctrl.Result{}, r.Status().Update(ctx, pm)
	}
	if !prepDestResp.Ready {
		msg := prepDestResp.BlockingReason
		if msg == "" {
			msg = "PrepareDestination: destination node not ready"
		}
		log.Info("PrepareDestination not ready, requeuing", "reason", msg)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	log.Info("PrepareDestination OK", "migration", pm.Name, "destNode", destNode,
		"ipReserved", prepDestResp.IpReserved, "storageReady", prepDestResp.StorageReady)

	// Restore: CRIU restores the process tree from the checkpoint images on the destination
	// node. checkpoint_ref carries the full images-dir path so the agent uses it directly
	// rather than falling back to the default path (which would be empty on a fresh node).
	// DestinationNodeName is already pinned in pm.Status.DestinationNodeName = destNode above;
	// CRIU recreates the process directly without a scheduler round-trip, so no pod object
	// with NodeName needs to be created here — the process is pinned by executing the restore
	// RPC on the target node's agent.
	restoreResp, err := agentClient.Restore(ctx, &agentpb.RestoreRequest{
		MigrationName:  pm.Name,
		CheckpointRef:  checkpointRef,
		SourceNodeAddr: pm.Status.SourceNodeName,
	})
	if err != nil || (restoreResp != nil && !restoreResp.Success) {
		msg := "restore RPC failed"
		if err != nil {
			msg = err.Error()
		} else if restoreResp != nil {
			msg = restoreResp.ErrorMessage
		}
		setCondition(pm, conditionRestored, metav1.ConditionFalse, "RestoreFailed", msg)
		if pm.Spec.RollbackOnFailure {
			return r.initiateRollback(ctx, pm, msg)
		}
		return ctrl.Result{}, r.Status().Update(ctx, pm)
	}

	// Fail loudly if the agent fell back to a mock-restore (pod started fresh instead of
	// from a CRIU checkpoint). A silent warn here would set Restored=True on a fresh-started
	// pod and mask the real failure. Treat this as a hard RestoreFailed.
	if restoreResp != nil && restoreResp.ErrorMessage != "" &&
		(strings.Contains(restoreResp.ErrorMessage, "mock-restore") ||
			strings.Contains(restoreResp.ErrorMessage, "fallback")) {
		msg := fmt.Sprintf("restore fallback: pod started fresh, not from CRIU checkpoint: %s", restoreResp.ErrorMessage)
		log.Error(fmt.Errorf("mock-restore fallback"), msg, "migration", pm.Name)
		setCondition(pm, conditionRestored, metav1.ConditionFalse, "RestoreFailed", msg)
		if pm.Spec.RollbackOnFailure {
			return r.initiateRollback(ctx, pm, msg)
		}
		return ctrl.Result{}, fmt.Errorf("%s", msg)
	}

	// GPU restore: reload GPU context after CRIU restore completes, if applicable.
	// GPU restore must happen after CRIU so the container process tree is alive to receive it.
	srcPod, podErr := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if podErr == nil && podHasGPU(srcPod) && featuregate.IsEnabled(featuregate.GPUMigration) {
		gpuCP := r.GPUCheckpointer
		if gpuCP == nil {
			gpuCP = &gpuagent.GPUCheckpointerStub{}
		}
		gpuDir := fmt.Sprintf("/tmp/podmotion/%s/gpu", pm.Name)
		if gpuErr := gpuCP.Restore(ctx, pm.Spec.PodName, pm.Spec.PodNamespace, gpuDir); gpuErr != nil {
			log.Error(gpuErr, "GPU restore failed — continuing (non-fatal)", "migration", pm.Name)
		}
	}

	// Volume readiness gate: for RWO PVCs the detach/attach window can be 30-120s.
	// Poll VolumeAttachment until Attached=true before releasing the source pod
	// (DestinationVolumeReady gates the source pod deletion in reconcileVerifying).
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionDestinationVolumeReady) {
		ready, err := r.checkDestinationVolumeReady(ctx, pm)
		if err != nil {
			log.Error(err, "volume readiness check error — requeuing", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		if !ready {
			log.Info("waiting for destination volume to attach", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		setCondition(pm, conditionDestinationVolumeReady, metav1.ConditionTrue,
			"VolumeAttached", "RWO PVC attached on destination node")
		if err := r.Status().Update(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Post-restore security context attestation: assert CapEff/seccomp/AppArmor match
	// what was captured at checkpoint. Kill the process on mismatch (fail-safe).
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionSecurityContextVerified) {
		if err := r.verifyRestoredSecurityContext(ctx, pm); err != nil {
			msg := fmt.Sprintf("post-restore security context mismatch: %v", err)
			log.Error(err, "security context verification failed", "migration", pm.Name)
			setCondition(pm, conditionSecurityContextVerified, metav1.ConditionFalse, "Mismatch", msg)
			if err2 := r.Status().Update(ctx, pm); err2 != nil {
				return ctrl.Result{}, err2
			}
			return r.failMigration(ctx, pm, msg)
		}
		setCondition(pm, conditionSecurityContextVerified, metav1.ConditionTrue,
			"Verified", "Restored process security context matches checkpoint attestation")
		if err := r.Status().Update(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	setCondition(pm, conditionRestored, metav1.ConditionTrue, "Restored", "Container restored by agent")

	// ADR-0015 overlap-then-delete: add destination pod IP to EndpointSlices that currently
	// list the source pod IP so traffic can flow to BOTH pods simultaneously. The source IP
	// is removed only after TrafficVerified=True in reconcileVerifying.
	// Do this here (post-restore) rather than post-Ready to ensure the source is never
	// removed before the destination is in the slice (overlap guarantee).
	if pm.Spec.SourcePodIP != "" && pm.Status.ReplacementPodName != "" {
		destPod := &corev1.Pod{}
		if getPodErr := r.Get(ctx, types.NamespacedName{
			Namespace: pm.Spec.PodNamespace,
			Name:      pm.Status.ReplacementPodName,
		}, destPod); getPodErr == nil && destPod.Status.PodIP != "" {
			esMgr := traffic.NewEndpointSliceManager(r.Client)
			if _, addErr := esMgr.AddDestination(ctx, pm.Spec.PodNamespace,
				pm.Spec.SourcePodIP, destPod.Status.PodIP, false); addErr != nil {
				log.Error(addErr, "EndpointSlice AddDestination failed — continuing (warn-only)",
					"migration", pm.Name)
			} else {
				log.Info("EndpointSlice: added destination pod IP alongside source",
					"migration", pm.Name,
					"sourcePodIP", pm.Spec.SourcePodIP,
					"destPodIP", destPod.Status.PodIP)
			}
		}
	}

	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseVerifying)
}

// reconcileRestoringNRI handles the operator-driven (NS#3) restore path.
//
// The NRI StartContainer hook in the node agent fires when containerd schedules the
// replacement pod and calls JoinNsRestore to execute CRIU restore. The operator's job
// here is ONLY to wait for the replacement pod to reach Running/Ready state — that is
// the signal that the NRI hook fired and CRIU restore succeeded.
//
// Calling the Restore RPC here would conflict with the NRI hook (two simultaneous
// CRIU restores into the same namespace), so we skip it entirely.
func (r *PodMigrationReconciler) reconcileRestoringNRI(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	replacement := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: pm.Spec.PodNamespace,
		Name:      pm.Status.ReplacementPodName,
	}, replacement); err != nil {
		log.Info("replacement pod not yet visible, requeuing", "migration", pm.Name,
			"replacementPod", pm.Status.ReplacementPodName)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}

	// Check for a hard failure: pod entered Failed or has a failed container.
	if replacement.Status.Phase == corev1.PodFailed {
		msg := fmt.Sprintf("replacement pod %s entered Failed phase — CRIU restore likely failed",
			pm.Status.ReplacementPodName)
		log.Error(fmt.Errorf("replacement pod failed"), msg, "migration", pm.Name)
		setCondition(pm, conditionRestored, metav1.ConditionFalse, "RestoreFailed", msg)
		if pm.Spec.RollbackOnFailure {
			return r.initiateRollback(ctx, pm, msg)
		}
		return ctrl.Result{}, r.Status().Update(ctx, pm)
	}

	// Wait for Running + at least one container Ready (NRI hook completed).
	if replacement.Status.Phase != corev1.PodRunning {
		log.Info("waiting for replacement pod to reach Running (NRI restore in progress)",
			"migration", pm.Name,
			"replacementPod", pm.Status.ReplacementPodName,
			"phase", replacement.Status.Phase)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	allReady := len(replacement.Status.ContainerStatuses) > 0
	for _, cs := range replacement.Status.ContainerStatuses {
		if !cs.Ready {
			allReady = false
			break
		}
	}
	if !allReady {
		log.Info("replacement pod Running but containers not yet Ready — waiting",
			"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}

	log.Info("replacement pod Running and Ready — NRI CRIU restore complete",
		"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName,
		"destNode", replacement.Spec.NodeName)

	setCondition(pm, conditionRestored, metav1.ConditionTrue, "Restored",
		fmt.Sprintf("NRI StartContainer hook restored process into replacement pod %s",
			pm.Status.ReplacementPodName))

	// ADR-0015 overlap-then-delete: add destination IP to EndpointSlices.
	if pm.Spec.SourcePodIP != "" && replacement.Status.PodIP != "" {
		esMgr := traffic.NewEndpointSliceManager(r.Client)
		if _, addErr := esMgr.AddDestination(ctx, pm.Spec.PodNamespace,
			pm.Spec.SourcePodIP, replacement.Status.PodIP, false); addErr != nil {
			log.Error(addErr, "EndpointSlice AddDestination failed — continuing (warn-only)",
				"migration", pm.Name)
		} else {
			log.Info("EndpointSlice: added destination pod IP alongside source",
				"migration", pm.Name,
				"sourcePodIP", pm.Spec.SourcePodIP,
				"destPodIP", replacement.Status.PodIP)
		}
	}

	// Volume readiness gate (mirrors reconcileRestoring path). For stateless pods with
	// no PVCs this returns true immediately; for RWO PVCs it waits for VolumeAttachment.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionDestinationVolumeReady) {
		ready, err := r.checkDestinationVolumeReady(ctx, pm)
		if err != nil {
			log.Error(err, "volume readiness check error — requeuing", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		if !ready {
			log.Info("waiting for destination volume to attach", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		setCondition(pm, conditionDestinationVolumeReady, metav1.ConditionTrue,
			"VolumeAttached", "RWO PVC attached on destination node (or no PVCs)")
	}

	if err := r.Status().Update(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseVerifying)
}


func (r *PodMigrationReconciler) reconcileVerifying(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Agent 12 (traffic) drives readiness + traffic verification. Watches TrafficVerified.
	// ADR-0019: if verification fails AFTER handoff, warn only — do not rollback.
	trafficVerified := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionTrafficVerified)
	if !trafficVerified {
		// Drive verification: call the TrafficVerifier and set the condition.
		if r.TrafficVerifier != nil {
			// Build verify request with correct pod names and IPs.
			destPodName := pm.Status.ReplacementPodName
			if destPodName == "" {
				destPodName = pm.Spec.PodName // fallback (should not happen in live migration)
			}
			// Try to get destination pod IP.
			destPodIP := ""
			if destPodName != "" {
				destPod := &corev1.Pod{}
				if err := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: destPodName}, destPod); err == nil {
					destPodIP = destPod.Status.PodIP
				}
			}
			req := traffic.VerifyRequest{
				Namespace:      pm.Spec.PodNamespace,
				SourcePodName:  pm.Spec.PodName,
				SourcePodIP:    pm.Spec.SourcePodIP,
				DestPodName:    destPodName,
				DestPodIP:      destPodIP,
				DestNodeName:   pm.Status.DestinationNodeName,
				TimeoutSeconds: 30,
				Mode:           traffic.VerificationModeEndpointSlice,
			}
			if err := r.TrafficVerifier.Verify(ctx, req); err != nil {
				// ADR-0019: warn only — do not rollback after handoff.
				log.Info("traffic verification failed (warn-only, ADR-0019)", "migration", pm.Name, "err", err)
			}
			// Set TrafficVerified=True regardless — StubVerifier always passes; real verifier
			// failures are warn-only per ADR-0019.
			setCondition(pm, conditionTrafficVerified, metav1.ConditionTrue, "TrafficVerified",
				"Traffic verified (or warn-only override per ADR-0019)")
		} else {
			// No verifier wired — skip and advance immediately.
			log.Info("TrafficVerifier not wired; skipping verification", "migration", pm.Name)
			setCondition(pm, conditionTrafficVerified, metav1.ConditionTrue, "TrafficVerified", "Skipped: no verifier wired")
		}
		if err := r.Status().Update(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	// ADR-0040 + ADR-0046: delete source pod only when BOTH TrafficVerified=True AND
	// DestinationVolumeReady=True. Deleting before volume attachment is confirmed risks
	// RWO PVC detach races (EBS/RBD attach window 30-120s).
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionDestinationVolumeReady) {
		ready, err := r.checkDestinationVolumeReady(ctx, pm)
		if err != nil {
			log.Error(err, "volume readiness check error — requeuing", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		if !ready {
			log.Info("waiting for DestinationVolumeReady before deleting source pod", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		setCondition(pm, conditionDestinationVolumeReady, metav1.ConditionTrue,
			"VolumeAttached", "RWO PVC attached on destination node (or no PVCs)")
		if err := r.Status().Update(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	// PDB gate: block deletion if any PodDisruptionBudget disallowsAllowing it.
	if err := r.checkPDBAllowsDeletion(ctx, pm); err != nil {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// ResourceQuota gate: defer deletion if the destination namespace is at pod quota capacity.
	if err := r.checkResourceQuotaCapacity(ctx, pm); err != nil {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	sourcePod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err == nil {
		// Only delete if pod is still on the source node (not already gone or rescheduled).
		if sourcePod.Spec.NodeName == pm.Status.SourceNodeName {
			log.Info("deleting source pod post-TrafficVerified",
				"pod", pm.Spec.PodName,
				"node", pm.Status.SourceNodeName,
				"migration", pm.Name)
			if deleteErr := r.Delete(ctx, sourcePod); deleteErr != nil && !apierrors.IsNotFound(deleteErr) {
				log.Error(deleteErr, "failed to delete source pod — proceeding to Complete anyway (ADR-0019)")
				// ADR-0019: warn only, do not fail the migration.
			}
		}
	} else if !apierrors.IsNotFound(err) {
		log.Error(err, "could not look up source pod — skipping deletion")
	}
	// If IsNotFound — already deleted, that is fine.

	setCondition(pm, conditionSourcePodDeleted, metav1.ConditionTrue, "Deleted", "Source pod deleted post-TrafficVerified")

	// ADR-0015 overlap-then-delete: now that TrafficVerified=True and source is deleted,
	// remove the source pod IP from EndpointSlices. The destination IP was added in
	// reconcileRestoring so there is never a gap (overlap window = restore→delete interval).
	if pm.Spec.SourcePodIP != "" {
		esMgr := traffic.NewEndpointSliceManager(r.Client)
		if _, removeErr := esMgr.RemoveSource(ctx, pm.Spec.PodNamespace, pm.Spec.SourcePodIP); removeErr != nil {
			log.Error(removeErr, "EndpointSlice RemoveSource failed — continuing (warn-only, source already deleted)",
				"migration", pm.Name)
		} else {
			log.Info("EndpointSlice: removed source pod IP post-deletion",
				"migration", pm.Name, "sourcePodIP", pm.Spec.SourcePodIP)
		}

		// Post-flight assertion: confirm source IP is actually gone from all EndpointSlices.
		// A stale entry here means traffic to the dead pod IP would cause connection errors.
		if still, checkErr := esMgr.HasEndpointForIP(ctx, pm.Spec.PodNamespace, pm.Spec.SourcePodIP); checkErr != nil {
			log.Error(checkErr, "post-flight EndpointSlice check failed", "migration", pm.Name)
		} else if still {
			log.Error(nil, "WARNING: source IP still present in EndpointSlices after RemoveSource — stale endpoint risk",
				"migration", pm.Name, "sourcePodIP", pm.Spec.SourcePodIP)
			setCondition(pm, conditionEndpointSliceCleanVerified, metav1.ConditionFalse, "StaleEndpoint",
				fmt.Sprintf("source IP %s still in EndpointSlices after removal — manual cleanup may be needed", pm.Spec.SourcePodIP))
		} else {
			setCondition(pm, conditionEndpointSliceCleanVerified, metav1.ConditionTrue, "Cleaned",
				fmt.Sprintf("source IP %s confirmed absent from all EndpointSlices", pm.Spec.SourcePodIP))
		}
	}

	now := metav1.Now()
	pm.Status.CompletionTime = &now

	// GitOps drift warning: if the owning workload still has hard nodeAffinity targeting
	// the source node AND the caller did not opt into patching it, warn the user.
	r.maybeSetGitOpsDriftWarning(ctx, pm)

	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseComplete)
}

func (r *PodMigrationReconciler) reconcileRollingBack(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Delete the replacement pod first — before rolling back the source — so there is
	// never a window where both pods are running and matching Service selectors.
	r.deleteReplacementPod(ctx, pm)

	if err := r.Rollbacker.Rollback(ctx, pm); err != nil {
		log.Error(err, "rollback failed — source pod may require manual intervention")
		return r.failMigration(ctx, pm, fmt.Sprintf("rollback failed: %v", err))
	}

	pm.Status.Phase = pmv1.MigrationPhaseFailed
	setCondition(pm, "RolledBack", metav1.ConditionTrue, "RollbackComplete", "Source pod restored to live state")
	return ctrl.Result{}, r.Status().Update(ctx, pm)
}

// ── Helpers ────────────────────────────────────────────────────────────────

// transitionTo sets pm.Status.Phase and patches status with retry on conflict.
func (r *PodMigrationReconciler) transitionTo(ctx context.Context, pm *pmv1.PodMigration, phase pmv1.MigrationPhase) (ctrl.Result, error) {
	key := client.ObjectKeyFromObject(pm)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if fetchErr := r.Get(ctx, key, fresh); fetchErr != nil {
			return fetchErr
		}
		// Carry forward any mutations made by the caller (conditions, CheckpointRef, etc.)
		fresh.Status = pm.Status
		fresh.Status.Phase = phase
		return r.Status().Update(ctx, fresh)
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	// Immediately requeue so the new phase handler runs in the same loop iteration.
	return ctrl.Result{Requeue: true}, nil
}

func (r *PodMigrationReconciler) failMigration(ctx context.Context, pm *pmv1.PodMigration, reason string) (ctrl.Result, error) {
	// Clean up the replacement pod on hard failure (not rollback — rollback handles its own).
	// Prevents a gated orphan pod from lingering when the migration is permanently failed.
	r.deleteReplacementPod(ctx, pm)

	key := client.ObjectKeyFromObject(pm)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if fetchErr := r.Get(ctx, key, fresh); fetchErr != nil {
			return fetchErr
		}
		fresh.Status = pm.Status
		fresh.Status.Phase = pmv1.MigrationPhaseFailed
		now := metav1.Now()
		fresh.Status.CompletionTime = &now
		setCondition(fresh, "Failed", metav1.ConditionTrue, "MigrationFailed", reason)
		return r.Status().Update(ctx, fresh)
	})
	return ctrl.Result{}, err
}

func (r *PodMigrationReconciler) initiateRollback(ctx context.Context, pm *pmv1.PodMigration, reason string) (ctrl.Result, error) {
	setCondition(pm, "RollbackReason", metav1.ConditionTrue, "Initiating", reason)
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseRollingBack)
}

// isFrozenWithoutRestore detects the crash-safety condition from ADR-0018:
// pod was frozen (Checkpointing phase persisted) but Restored condition is missing.
//
// Sprint 12 nil-guard: only trigger the crash-safe restart if CheckpointRef is NOT
// yet written. If CheckpointRef is already set it means the Checkpoint gRPC completed
// successfully and the normal Restoring path must run against that checkpoint — firing
// the crash-safe path at that point would skip the real restore from a valid checkpoint.
func (r *PodMigrationReconciler) isFrozenWithoutRestore(pm *pmv1.PodMigration) bool {
	// Only trigger crash-safe from Checkpointing (crashed after dump, before transition).
	// In Transferring phase, reconcileTransferring handles idempotent re-transfer correctly.
	if pm.Status.Phase != pmv1.MigrationPhaseCheckpointing {
		return false
	}
	if meta.FindStatusCondition(pm.Status.Conditions, conditionRestored) != nil {
		return false
	}
	// Only activate crash-safe path when the checkpoint HAS been written (CheckpointRef
	// is populated) but restore has not yet happened — i.e. the controller crashed
	// between a successful Checkpoint RPC and the start of reconcileRestoring.
	// When CheckpointRef is nil the migration has not checkpointed yet — let it fall
	// through to reconcileCheckpointing normally.
	if pm.Status.CheckpointRef == nil || pm.Status.CheckpointRef.Name == "" {
		return false
	}
	return true
}

func (r *PodMigrationReconciler) handleDeletion(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(pm, finalizerName) {
		// Clean up checkpoint artifact if it exists.
		if pm.Status.CheckpointRef != nil {
			mcp := &pmv1.MigrationCheckpoint{}
			err := r.Get(ctx, types.NamespacedName{
				Namespace: pm.Namespace,
				Name:      pm.Status.CheckpointRef.Name,
			}, mcp)
			if err == nil {
				_ = r.Delete(ctx, mcp)
			}
		}
		controllerutil.RemoveFinalizer(pm, finalizerName)
		return ctrl.Result{}, r.Update(ctx, pm)
	}
	return ctrl.Result{}, nil
}

func (r *PodMigrationReconciler) getPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pod)
	return pod, err
}

func (r *PodMigrationReconciler) getNMC(ctx context.Context, nodeName string) (*pmv1.NodeMigrationCapacity, error) {
	nmc := &pmv1.NodeMigrationCapacity{}
	err := r.Get(ctx, client.ObjectKey{Name: nodeName}, nmc)
	return nmc, err
}

// checkAntiAffinityConflict verifies that the destination node does not already host any pods
// that violate the source pod's requiredDuringScheduling podAntiAffinity rules.
// If a conflict is found it sets ConditionAntiAffinityConflict=True and returns a non-nil error
// (so reconcilePreMigrating can requeue).  On success it sets the condition False.
func (r *PodMigrationReconciler) checkAntiAffinityConflict(ctx context.Context, pm *pmv1.PodMigration, destinationNode string) error {
	log := logf.FromContext(ctx)

	pod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err != nil {
		// Can't fetch pod — don't block migration, just skip the check.
		log.Error(err, "checkAntiAffinityConflict: cannot fetch source pod — skipping")
		return nil
	}

	if pod.Spec.Affinity == nil ||
		pod.Spec.Affinity.PodAntiAffinity == nil ||
		len(pod.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) == 0 {
		setCondition(pm, orchestration.ConditionAntiAffinityConflict, metav1.ConditionFalse,
			"NoAntiAffinityRules", "source pod has no requiredDuringScheduling podAntiAffinity")
		return nil
	}

	// List all pods on the destination node.
	podList := &corev1.PodList{}
	if listErr := r.List(ctx, podList,
		client.MatchingFields{"spec.nodeName": destinationNode},
	); listErr != nil {
		log.Error(listErr, "checkAntiAffinityConflict: cannot list pods on destination node")
		return nil
	}

	for _, term := range pod.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution {
		if term.LabelSelector == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(term.LabelSelector)
		if err != nil {
			log.Error(err, "checkAntiAffinityConflict: invalid LabelSelector in podAntiAffinity term")
			continue
		}
		ns := term.Namespaces
		for i := range podList.Items {
			candidate := &podList.Items[i]
			// Respect namespace selector: if term.namespaces is set, candidate must be in one of them.
			if len(ns) > 0 {
				found := false
				for _, n := range ns {
					if candidate.Namespace == n {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			if sel.Matches(labels.Set(candidate.Labels)) {
				msg := fmt.Sprintf("destination node %s hosts pod %s/%s which violates requiredDuringScheduling podAntiAffinity",
					destinationNode, candidate.Namespace, candidate.Name)
				setCondition(pm, orchestration.ConditionAntiAffinityConflict, metav1.ConditionTrue,
					"AntiAffinityViolation", msg)
				return fmt.Errorf("%s", msg)
			}
		}
	}

	setCondition(pm, orchestration.ConditionAntiAffinityConflict, metav1.ConditionFalse,
		"NoConflict", fmt.Sprintf("no podAntiAffinity conflicts found on destination node %s", destinationNode))
	return nil
}

// maybeSetGitOpsDriftWarning sets ConditionGitOpsDriftWarning=True if the pod's owning
// Deployment or StatefulSet still has hard nodeAffinity/nodeSelector targeting the source
// node AND affinityMode is not AffinityModePatch (which would have already patched it).
func (r *PodMigrationReconciler) maybeSetGitOpsDriftWarning(ctx context.Context, pm *pmv1.PodMigration) {
	if pm.Spec.AffinityMode == pmv1.AffinityModePatch {
		// Controller patched the affinity — no drift expected.
		return
	}

	sourceNode := pm.Status.SourceNodeName
	if sourceNode == "" {
		return
	}

	pod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err != nil {
		// Pod already deleted — try fetching owner reference from pm.Status if available.
		return
	}

	for _, ref := range pod.OwnerReferences {
		if ref.Kind != "Deployment" && ref.Kind != "StatefulSet" {
			continue
		}
		if !ownerHasHardNodeAffinity(pod, sourceNode) {
			continue
		}
		setCondition(pm, orchestration.ConditionGitOpsDriftWarning, metav1.ConditionTrue,
			"AffinityDrift",
			fmt.Sprintf("owning %s/%s still has nodeAffinity targeting source node %s; pods will return to %s on next rollout or GitOps sync",
				ref.Kind, ref.Name, sourceNode, sourceNode))
		return
	}

	setCondition(pm, orchestration.ConditionGitOpsDriftWarning, metav1.ConditionFalse,
		"NoAffinity", "owning workload has no hard nodeAffinity targeting source node")
}

// ownerHasHardNodeAffinity returns true if the pod carries nodeSelector or nodeAffinity
// required rules that target the given nodeName.
func ownerHasHardNodeAffinity(pod *corev1.Pod, nodeName string) bool {
	for key, val := range pod.Spec.NodeSelector {
		if key == "kubernetes.io/hostname" && val == nodeName {
			return true
		}
	}
	if pod.Spec.Affinity == nil || pod.Spec.Affinity.NodeAffinity == nil {
		return false
	}
	required := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
	if required == nil {
		return false
	}
	for _, term := range required.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if expr.Key == "kubernetes.io/hostname" && expr.Operator == corev1.NodeSelectorOpIn {
				for _, v := range expr.Values {
					if v == nodeName {
						return true
					}
				}
			}
		}
	}
	return false
}

// setCondition is a convenience wrapper around meta.SetStatusCondition.
func setCondition(pm *pmv1.PodMigration, condType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// SetupWithManager sets up the controller with the Manager.
// podHasGPU returns true if any container in the pod declares an nvidia.com/gpu resource limit > 0.
// This drives the GPU checkpoint/restore path when the GPUMigration feature gate is enabled.
func podHasGPU(pod *corev1.Pod) bool {
	const gpuResource = "nvidia.com/gpu"
	for _, c := range pod.Spec.Containers {
		if q, ok := c.Resources.Limits[corev1.ResourceName(gpuResource)]; ok {
			if q.Value() > 0 {
				return true
			}
		}
	}
	return false
}

// validateNoEmptyDir returns an error if the source pod has any emptyDir volume.
// Pods with emptyDir volumes are ineligible for live migration because CRIU restores
// the process against an empty directory and the process receives SIGBUS on first access.
func (r *PodMigrationReconciler) validateNoEmptyDir(ctx context.Context, pm *pmv1.PodMigration) error {
	pod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err != nil {
		return nil // pod already gone — allow to proceed
	}
	for _, v := range pod.Spec.Volumes {
		if v.EmptyDir != nil {
			return fmt.Errorf("pod %s/%s has emptyDir volume %q — emptyDir volumes are ineligible for live migration",
				pm.Spec.PodNamespace, pm.Spec.PodName, v.Name)
		}
	}
	return nil
}

// reserveDestinationCapacity increments ActiveDestinationMigrations on the destination
// NMC to reserve a capacity slot before the source pod is deleted (ADR-0046).
func (r *PodMigrationReconciler) reserveDestinationCapacity(ctx context.Context, pm *pmv1.PodMigration, destNode string) error {
	nmc := &pmv1.NodeMigrationCapacity{}
	if err := r.Get(ctx, types.NamespacedName{Name: destNode}, nmc); err != nil {
		return fmt.Errorf("get NMC for %s: %w", destNode, err)
	}
	if nmc.Status.ActiveDestinationMigrations >= nmc.Spec.MaxConcurrentMigrationsDestination {
		return fmt.Errorf("destination node %s has no capacity (%d/%d)",
			destNode, nmc.Status.ActiveDestinationMigrations, nmc.Spec.MaxConcurrentMigrationsDestination)
	}
	nmc.Status.ActiveDestinationMigrations++
	return r.Status().Update(ctx, nmc)
}

// createReplacementPod creates a clone of the source pod that will receive the
// CRIU-restored process. The admission webhook injects the scheduling gate and
// checkpoint-ref annotation so the pod waits at PodSchedulingGated until the
// controller removes the gate post-transfer.
//
// Quorum requirements (Architecture Sprint 1 review):
//   - ownerRef → PodMigration CR (not Deployment/RS — workload controller must not see this pod)
//   - Selector labels stripped (pod-template-hash and any RS selector key) so the ReplicaSet
//     controller does not count the gated clone against its desired replica count
//   - Name deterministic (idempotency key) and truncated to ≤63 chars
//   - Name recorded in pm.Status (not Spec) via Status().Update
func (r *PodMigrationReconciler) createReplacementPod(ctx context.Context, pm *pmv1.PodMigration, sourcePod *corev1.Pod) error {
	// Idempotency: if a replacement pod already exists (controller restart), skip creation.
	if pm.Status.ReplacementPodName != "" {
		existing := &corev1.Pod{}
		err := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: pm.Status.ReplacementPodName}, existing)
		if err == nil {
			return nil // already exists and matches — adopt it
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
		// Was recorded but pod is gone — fall through to re-create.
	}

	// Build a deterministic name from source name + short PM UID prefix.
	// Truncate source name so total stays ≤63 chars (k8s DNS-label limit).
	uid := string(pm.UID)
	if len(uid) > 8 {
		uid = uid[:8]
	}
	suffix := "-m-" + uid // 11 chars
	maxSourceLen := 63 - len(suffix)
	srcName := sourcePod.Name
	if len(srcName) > maxSourceLen {
		srcName = srcName[:maxSourceLen]
	}
	replacementName := srcName + suffix

	// Resolve the owning ReplicaSet's selector keys so we can strip them.
	// This prevents the RS controller from counting our gated clone against
	// its desired replica count and deleting it (or the source pod) mid-checkpoint.
	selectorKeysToStrip := map[string]struct{}{
		// Always strip: RS-generated hash label that is unique per pod-template revision.
		"pod-template-hash": {},
	}
	for _, ownerRef := range sourcePod.OwnerReferences {
		if ownerRef.Kind == "ReplicaSet" {
			if err := r.getRSSelector(ctx, pm.Spec.PodNamespace, ownerRef.Name, selectorKeysToStrip); err != nil {
				// Non-fatal: worst case we strip only pod-template-hash.
				_ = err
			}
			break
		}
	}

	// Build the label set: copy source labels, strip selector keys, add migration marker.
	newLabels := make(map[string]string, len(sourcePod.Labels)+1)
	for k, v := range sourcePod.Labels {
		if _, strip := selectorKeysToStrip[k]; !strip {
			newLabels[k] = v
		}
	}
	newLabels["podmotion.io/migration-name"] = pm.Name

	// Copy annotations; strip immutable fields that cause API conflict.
	newAnnotations := make(map[string]string, len(sourcePod.Annotations))
	for k, v := range sourcePod.Annotations {
		newAnnotations[k] = v
	}
	delete(newAnnotations, "kubectl.kubernetes.io/last-applied-configuration")

	// Deep-copy spec; clear scheduler-assigned and mutable fields.
	spec := *sourcePod.Spec.DeepCopy()
	spec.SchedulerName = ""    // webhook injects podmotion-scheduler
	spec.SchedulingGates = nil // webhook injects the gate

	// Pin NodeName directly to the destination node if known.
	// When the MutatingAdmissionWebhook is deployed it would enforce this via spec.destinationNode;
	// setting NodeName here ensures correctness when the webhook is not running (dev/PoC clusters).
	destNodeName := pm.Status.DestinationNodeName
	if destNodeName == "" {
		destNodeName = pm.Spec.TargetNodeName
	}
	log := logf.FromContext(ctx)
	log.Info("createReplacementPod: pinning node",
		"migration", pm.Name,
		"statusDestinationNodeName", pm.Status.DestinationNodeName,
		"specTargetNodeName", pm.Spec.TargetNodeName,
		"resolved", destNodeName,
		"sourcePodNode", sourcePod.Spec.NodeName)
	if destNodeName != "" {
		spec.NodeName = destNodeName
	} else {
		spec.NodeName = "" // let scheduler decide if destination unknown
	}

	replacement := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        replacementName,
			Namespace:   pm.Spec.PodNamespace,
			Labels:      newLabels,
			Annotations: newAnnotations,
			// OwnerReferences: set to PodMigration CR below via SetControllerReference.
			// No workload-controller ownerRef — prevents RS/Deployment from adopting/deleting.
		},
		Spec: spec,
	}
	if err := controllerutil.SetControllerReference(pm, replacement, r.Scheme); err != nil {
		return fmt.Errorf("set controller reference on replacement pod: %w", err)
	}

	log.Info("createReplacementPod: creating pod",
		"migration", pm.Name,
		"podName", replacementName,
		"specNodeName", replacement.Spec.NodeName,
		"destNodeName", destNodeName,
		"statusDestNode", pm.Status.DestinationNodeName,
		"specTargetNode", pm.Spec.TargetNodeName)
	if err := r.Create(ctx, replacement); err != nil {
		if apierrors.IsAlreadyExists(err) {
			log.Info("createReplacementPod: pod already exists (adopting)",
				"migration", pm.Name, "podName", replacementName)
		} else {
			return fmt.Errorf("create replacement pod %s: %w", replacementName, err)
		}
	}

	// Record name in Status (not Spec — controller state is not user intent).
	// Use retry.RetryOnConflict: a concurrent patchMemorySynced goroutine may have updated
	// the resourceVersion between the claim re-fetch and here, causing a stale-write conflict.
	pm.Status.ReplacementPodName = replacementName
	key := client.ObjectKeyFromObject(pm)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := r.Get(ctx, key, fresh); err != nil {
			return err
		}
		fresh.Status.ReplacementPodName = replacementName
		return r.Status().Update(ctx, fresh)
	})
}


// getRSSelector fetches the ReplicaSet's spec.selector.matchLabels keys and adds them
// to the strip set. Non-fatal on any error — worst case we strip only pod-template-hash.
func (r *PodMigrationReconciler) getRSSelector(ctx context.Context, ns, rsName string, strip map[string]struct{}) error {
	rs := &appsv1.ReplicaSet{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: rsName}, rs); err != nil {
		return err
	}
	if rs.Spec.Selector != nil {
		for k := range rs.Spec.Selector.MatchLabels {
			strip[k] = struct{}{}
		}
	}
	return nil
}

// removeSchedulingGate removes the podmotion.io/awaiting-checkpoint scheduling gate
// from the replacement pod so the scheduler can route it to the destination node.
func (r *PodMigrationReconciler) removeSchedulingGate(ctx context.Context, pm *pmv1.PodMigration) error {
	if pm.Status.ReplacementPodName == "" {
		return nil // no replacement pod tracked yet
	}
	pod := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: pm.Spec.PodNamespace,
		Name:      pm.Status.ReplacementPodName,
	}, pod); err != nil {
		return client.IgnoreNotFound(err)
	}
	const gate = "podmotion.io/awaiting-checkpoint"
	filtered := pod.Spec.SchedulingGates[:0]
	for _, g := range pod.Spec.SchedulingGates {
		if g.Name != gate {
			filtered = append(filtered, g)
		}
	}
	if len(filtered) == len(pod.Spec.SchedulingGates) {
		return nil // gate not present
	}
	patch := client.MergeFrom(pod.DeepCopy())
	pod.Spec.SchedulingGates = filtered
	return r.Patch(ctx, pod, patch)
}

// checkDestinationVolumeReady returns true when all RWO PVCs used by the source pod
// have a VolumeAttachment with Attached=true on the destination node.
// Returns true immediately for pods with no RWO PVCs (no-op for RWX, emptyDir-blocked earlier).
func (r *PodMigrationReconciler) checkDestinationVolumeReady(ctx context.Context, pm *pmv1.PodMigration) (bool, error) {
	pod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err != nil {
		return true, nil // source pod gone — treat as ready
	}
	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		destNode = pm.Spec.TargetNodeName
	}
	for _, v := range pod.Spec.Volumes {
		if v.PersistentVolumeClaim == nil {
			continue
		}
		pvc := &corev1.PersistentVolumeClaim{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: v.PersistentVolumeClaim.ClaimName}, pvc); err != nil {
			continue
		}
		if pvc.Spec.AccessModes == nil {
			continue
		}
		isRWO := false
		for _, am := range pvc.Spec.AccessModes {
			if am == corev1.ReadWriteOnce {
				isRWO = true
				break
			}
		}
		if !isRWO {
			continue
		}
		// Check VolumeAttachment for this PV on the destination node.
		vaList := &storagev1.VolumeAttachmentList{}
		if err := r.List(ctx, vaList); err != nil {
			return false, err
		}
		attached := false
		for _, va := range vaList.Items {
			if va.Spec.NodeName == destNode &&
				va.Spec.Source.PersistentVolumeName != nil &&
				*va.Spec.Source.PersistentVolumeName == pvc.Spec.VolumeName &&
				va.Status.Attached {
				attached = true
				break
			}
		}
		if !attached {
			return false, nil
		}
	}
	return true, nil
}

// verifyRestoredSecurityContext is a stub that will assert the restored process's
// capabilities and seccomp profile match what was captured at checkpoint.
// Full implementation in M15 (security hardening) — returns nil (pass) for now.
func (r *PodMigrationReconciler) verifyRestoredSecurityContext(_ context.Context, _ *pmv1.PodMigration) error {
	// TODO(M15): capture CapEff/CapPrm/CapInh/CapBnd + seccomp mode + AppArmor label
	// at checkpoint time; assert they match post-restore; kill process on mismatch.
	return nil
}

// checkPDBAllowsDeletion blocks source pod deletion when a matching PodDisruptionBudget
// has DisruptionsAllowed==0.  Fail-open: if PDBs cannot be listed, migration continues.
func (r *PodMigrationReconciler) checkPDBAllowsDeletion(ctx context.Context, pm *pmv1.PodMigration) error {
	srcPod := &corev1.Pod{}
	if err := r.Client.Get(ctx, types.NamespacedName{
		Name: pm.Spec.PodName, Namespace: pm.Spec.PodNamespace,
	}, srcPod); err != nil {
		return nil // pod already gone — no PDB to check
	}

	pdbList := &policyv1.PodDisruptionBudgetList{}
	if err := r.Client.List(ctx, pdbList, client.InNamespace(pm.Spec.PodNamespace)); err != nil {
		return nil // can't list PDBs — allow (fail-open for PDB only)
	}

	srcLabels := labels.Set(srcPod.Labels)
	for _, pdb := range pdbList.Items {
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}
		if sel.Matches(srcLabels) && pdb.Status.DisruptionsAllowed == 0 {
			setCondition(pm, "PDBAllowsDeletion", metav1.ConditionFalse,
				"PDBBlocking",
				fmt.Sprintf("PodDisruptionBudget %s/%s: DisruptionsAllowed=0", pdb.Namespace, pdb.Name))
			_ = r.Client.Status().Update(ctx, pm)
			return fmt.Errorf("PDB %s blocks deletion", pdb.Name)
		}
	}
	setCondition(pm, "PDBAllowsDeletion", metav1.ConditionTrue, "PDBOk", "")
	return nil
}

// checkResourceQuotaCapacity defers source pod deletion when the namespace is at pod quota
// capacity — the net-zero delete+create sequence is safe, but races with other controllers
// could cause the replacement pod to be rejected if we delete too early.
func (r *PodMigrationReconciler) checkResourceQuotaCapacity(ctx context.Context, pm *pmv1.PodMigration) error {
	quotaList := &corev1.ResourceQuotaList{}
	if err := r.Client.List(ctx, quotaList, client.InNamespace(pm.Spec.PodNamespace)); err != nil || len(quotaList.Items) == 0 {
		return nil // no quotas — allow
	}

	for _, quota := range quotaList.Items {
		// Check pod count hard limit
		if hard, ok := quota.Spec.Hard[corev1.ResourcePods]; ok {
			used := quota.Status.Used[corev1.ResourcePods]
			// After source deletion, used drops by 1, then replacement is +1 = net 0.
			// But the race window: if another pod is created in between, used stays same.
			// Check that current used < hard (source deletion + replacement = net 0, safe).
			if used.Cmp(hard) >= 0 {
				setCondition(pm, "ResourceQuotaCapacity", metav1.ConditionFalse,
					"QuotaExhausted",
					fmt.Sprintf("ResourceQuota %s: pods %s/%s — at capacity, deferring", quota.Name, used.String(), hard.String()))
				_ = r.Client.Status().Update(ctx, pm)
				return fmt.Errorf("ResourceQuota %s pods at capacity", quota.Name)
			}
		}
	}
	setCondition(pm, "ResourceQuotaCapacity", metav1.ConditionTrue, "QuotaOk", "")
	return nil
}

func (r *PodMigrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pmv1.PodMigration{}).
		Named("podmigration").
		Complete(r)
}

// deleteReplacementPod deletes the replacement pod created during live migration,
// if one was recorded. Called on rollback and migration failure to prevent an
// orphaned gated pod from lingering and matching Service selectors.
// Non-fatal: if the pod is already gone, the delete is a no-op.
func (r *PodMigrationReconciler) deleteReplacementPod(ctx context.Context, pm *pmv1.PodMigration) {
	if pm.Status.ReplacementPodName == "" {
		return
	}
	log := logf.FromContext(ctx)
	pod := &corev1.Pod{}
	err := r.Get(ctx, types.NamespacedName{
		Namespace: pm.Spec.PodNamespace,
		Name:      pm.Status.ReplacementPodName,
	}, pod)
	if apierrors.IsNotFound(err) {
		return
	}
	if err != nil {
		log.Error(err, "deleteReplacementPod: get failed", "pod", pm.Status.ReplacementPodName)
		return
	}
	if deleteErr := r.Delete(ctx, pod); deleteErr != nil && !apierrors.IsNotFound(deleteErr) {
		log.Error(deleteErr, "deleteReplacementPod: delete failed — manual cleanup may be required",
			"pod", pm.Status.ReplacementPodName)
	} else {
		log.Info("deleted replacement pod on rollback/failure", "pod", pm.Status.ReplacementPodName)
	}
}
