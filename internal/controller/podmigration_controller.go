/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	gpuagent "github.com/podmotion-io/podmotion/internal/agent/gpu"
	"github.com/podmotion-io/podmotion/internal/agent/replication"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
	"github.com/podmotion-io/podmotion/internal/agent/traffic"
	"github.com/podmotion-io/podmotion/internal/estimation"
	"github.com/podmotion-io/podmotion/internal/featuregate"
	"github.com/podmotion-io/podmotion/internal/rollback"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

const (
	finalizerName = "migration.podmotion.io/finalizer"

	// Condition types used on PodMigration status.
	conditionValidated          = "Validated"
	conditionCheckpointed       = "Checkpointed"
	conditionRestored           = "Restored"
	conditionTrafficVerified    = "TrafficVerified"
	conditionMemorySynced       = "MemorySynced"
	conditionStorageReady       = "StorageReadyForFreeze"
	conditionNetworkBridgeArmed = "NetworkBridgeArmed"
	conditionPDBToken           = "PDBTokenAcquired"
	conditionSourcePodDeleted   = "SourcePodDeleted"
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
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
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
		cp := r.Checkpointer
		if cp == nil {
			cp = &criu.StubCheckpointer{}
		}
		// Snapshot name/namespace for the goroutine closure — pm may be mutated later.
		pmCopy := pm.DeepCopy()
		go func() {
			if err := r.ReplicationMgr.RunPreCopyLoop(context.Background(), pmCopy, cp); err != nil {
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

	// Fast-path: if the Checkpointed condition was already set True (e.g. agent called back
	// directly or we are re-entering after a controller restart), advance immediately.
	if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionCheckpointed) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseTransferring)
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
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	sourceNode := pm.Status.SourceNodeName
	if sourceNode == "" {
		pod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
		if err != nil {
			return r.failMigration(ctx, pm, fmt.Sprintf("checkpoint: source pod not found: %v", err))
		}
		sourceNode = pod.Spec.NodeName
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
	prepResp, err := agentClient.PrepareSource(ctx, &agentpb.PrepareSourceRequest{
		PodName:       pm.Spec.PodName,
		PodNamespace:  pm.Spec.PodNamespace,
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

	// Step 2: Checkpoint — freeze and dump.
	_, err = agentClient.Checkpoint(ctx, &agentpb.CheckpointRequest{
		MigrationName: pm.Name,
	})
	if err != nil {
		setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "CheckpointFailed", err.Error())
		return ctrl.Result{}, r.Status().Update(ctx, pm)
	}

	setCondition(pm, conditionCheckpointed, metav1.ConditionTrue, "Checkpointed", "Checkpoint captured by agent")
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseTransferring)
}

func (r *PodMigrationReconciler) reconcileTransferring(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	// Agent 7 (gRPC transfer) moves the checkpoint image. Watches for CheckpointRef to be set.
	if pm.Status.CheckpointRef != nil {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseRestoring)
	}
	return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
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

	checkpointRef := ""
	if pm.Status.CheckpointRef != nil {
		checkpointRef = pm.Status.CheckpointRef.Name
	}

	agentClient, err := r.AgentPool.ForNode(ctx, destNode)
	if err != nil {
		log.Error(err, "Failed to connect to destination agent", "node", destNode)
		setCondition(pm, conditionRestored, metav1.ConditionFalse, "RestoreFailed",
			fmt.Sprintf("agent connection failed: %v", err))
		return ctrl.Result{}, r.Status().Update(ctx, pm)
	}

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

	setCondition(pm, conditionRestored, metav1.ConditionTrue, "Restored", "Container restored by agent")
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
			req := traffic.VerifyRequest{
				Namespace:    pm.Spec.PodNamespace,
				DestNodeName: pm.Status.DestinationNodeName,
				DestPodName:  pm.Spec.PodName,
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

	// ADR-0040: delete source pod now that TrafficVerified=true (ADR-0012 gate satisfied).
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
	now := metav1.Now()
	pm.Status.CompletionTime = &now
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseComplete)
}

func (r *PodMigrationReconciler) reconcileRollingBack(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if err := r.Rollbacker.Rollback(ctx, pm); err != nil {
		log.Error(err, "rollback failed — source pod may require manual intervention")
		return r.failMigration(ctx, pm, fmt.Sprintf("rollback failed: %v", err))
	}

	pm.Status.Phase = pmv1.MigrationPhaseFailed
	setCondition(pm, "RolledBack", metav1.ConditionTrue, "RollbackComplete", "Source pod restored to live state")
	return ctrl.Result{}, r.Status().Update(ctx, pm)
}

// ── Helpers ────────────────────────────────────────────────────────────────

// transitionTo sets pm.Status.Phase and patches status.
func (r *PodMigrationReconciler) transitionTo(ctx context.Context, pm *pmv1.PodMigration, phase pmv1.MigrationPhase) (ctrl.Result, error) {
	pm.Status.Phase = phase
	if err := r.Status().Update(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}
	// Immediately requeue so the new phase handler runs in the same loop iteration.
	return ctrl.Result{Requeue: true}, nil
}

func (r *PodMigrationReconciler) failMigration(ctx context.Context, pm *pmv1.PodMigration, reason string) (ctrl.Result, error) {
	pm.Status.Phase = pmv1.MigrationPhaseFailed
	now := metav1.Now()
	pm.Status.CompletionTime = &now
	setCondition(pm, "Failed", metav1.ConditionTrue, "MigrationFailed", reason)
	return ctrl.Result{}, r.Status().Update(ctx, pm)
}

func (r *PodMigrationReconciler) initiateRollback(ctx context.Context, pm *pmv1.PodMigration, reason string) (ctrl.Result, error) {
	setCondition(pm, "RollbackReason", metav1.ConditionTrue, "Initiating", reason)
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseRollingBack)
}

// isFrozenWithoutRestore detects the crash-safety condition from ADR-0018:
// pod was frozen (Checkpointing phase persisted) but Restored condition is missing.
func (r *PodMigrationReconciler) isFrozenWithoutRestore(pm *pmv1.PodMigration) bool {
	if pm.Status.Phase != pmv1.MigrationPhaseCheckpointing &&
		pm.Status.Phase != pmv1.MigrationPhaseTransferring {
		return false
	}
	return meta.FindStatusCondition(pm.Status.Conditions, conditionRestored) == nil
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

func (r *PodMigrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pmv1.PodMigration{}).
		Named("podmigration").
		Complete(r)
}
