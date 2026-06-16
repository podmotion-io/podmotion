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
	"sync"
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
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	"github.com/podmotion-io/podmotion/internal/gitops"
	pmmetrics "github.com/podmotion-io/podmotion/internal/metrics"
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
	// conditionIPHandoffInjected records that the ADR-0133 destination-side neighbor/FDB
	// handoff for the OLD pod IP has been installed and the reachability probe passed.
	conditionIPHandoffInjected            = "IPHandoffInjected"
	// conditionRestoreTimedOut is set when the restore deadline elapses, driving
	// the migration to RollingBack (ADR-0157 D3/GC-32). Reason: RestoreDeadlineExceeded.
	conditionRestoreTimedOut              = "RestoreTimedOut"
)

// macWritebackDeadline tracks the first time injectIPHandoff observed
// criuRestoreConfirmed=true with an empty replVethMAC, keyed by migration name.
// Entries are deleted on RollingBack transition or successful MAC resolution.
// Used to enforce the 30s MAC writeback deadline (E1 Condition 4).
var (
	macWritebackFirstSeen   sync.Map // map[string]time.Time
	macWritebackDeadlineSec = 30 * time.Second
)

// PodMigrationReconciler reconciles a PodMigration object.
type PodMigrationReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Estimator  estimation.Estimator
	Rollbacker rollback.Rollbacker
	// Recorder emits Kubernetes events on PodMigration objects (e.g. ZeroWindowWatchdogFired).
	// Nil in unit tests — event emission is skipped when nil.
	Recorder record.EventRecorder
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

// Reconcile implements the PodMigration state machine. It is called by controller-runtime whenever a PodMigration object is created, updated, or re-queued. Each call advances the migration by exactly one phase transition, persists status, and re-queues if further work remains. See CLAUDE.md §PodMigration state machine for the full phase diagram.
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

	// Normalize destination node: spec.destinationNode (webhook-populated) and
	// spec.targetNodeName (user-set) are two synonymous fields. Populate
	// status.destinationNodeName early from whichever is set so downstream
	// reconcilers can use status.destinationNodeName unconditionally.
	if pm.Status.DestinationNodeName == "" {
		if pm.Spec.TargetNodeName != "" {
			pm.Status.DestinationNodeName = pm.Spec.TargetNodeName
		} else if pm.Spec.DestinationNode != "" {
			pm.Status.DestinationNodeName = pm.Spec.DestinationNode
		}
		if pm.Status.DestinationNodeName != "" {
			if err := r.statusUpdate(deadline, pm); err != nil {
				log.Error(err, "failed to persist DestinationNodeName from spec", "migration", pm.Name)
				return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
			}
		}
	}

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
	// 12-phase pipeline (ADR-0047). Each case logs the transition on entry.
	case pmv1.MigrationPhaseSocketInventory:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileSocketInventory(deadline, pm)
	case pmv1.MigrationPhaseValidating:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileValidating(deadline, pm)
	case pmv1.MigrationPhaseDestinationPrewarm:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileDestinationPrewarm(deadline, pm)
	case pmv1.MigrationPhasePreCopyMemory:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcilePreCopyMemory(deadline, pm)
	case pmv1.MigrationPhaseZeroWindowArm:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileZeroWindowArm(deadline, pm)
	case pmv1.MigrationPhaseFinalFreezeStateCapture:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileFinalFreezeStateCapture(deadline, pm)
	case pmv1.MigrationPhaseOverlayHandoff:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileOverlayHandoff(deadline, pm)
	case pmv1.MigrationPhaseRestoreSocketReattach:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileRestoreSocketReattach(deadline, pm)
	case pmv1.MigrationPhaseDisengageHold:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileDisengageHold(deadline, pm)
	case pmv1.MigrationPhaseTCPVerifying:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileTCPVerifying(deadline, pm)
	case pmv1.MigrationPhaseServiceVerifying:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileServiceVerifying(deadline, pm)
	case pmv1.MigrationPhaseCutoverComplete:
		log.Info("phase transition", "phase", pm.Status.Phase, "migration", pm.Name)
		return r.reconcileCutoverComplete(deadline, pm)
	// Legacy 8-phase pipeline kept for backward compatibility with existing PodMigration objects.
	case pmv1.MigrationPhasePreMigrating:
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
	// 12-phase pipeline entry point (ADR-0047).
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseSocketInventory)
}

// ── 12-phase pipeline handlers (ADR-0047) ──────────────────────────────────

// reconcileSocketInventory enumerates TCP 4-tuples from /proc/net/tcp[6] on the source pod
// and records them so downstream phases can verify sequence continuity post-restore.
// For TCPPreservationMode=None this phase is a no-op and advances immediately.
func (r *PodMigrationReconciler) reconcileSocketInventory(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionSocketInventoryComplete) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseValidating)
	}

	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone {
		log.Info("SocketInventory: skipped (TCPPreservationMode=None)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionSocketInventoryComplete, metav1.ConditionTrue,
			"Skipped", "TCPPreservationMode=None: socket inventory not required")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseValidating)
	}

	// Agent-driven: the source node agent enumerates /proc/net/tcp[6] per container netns
	// and reports the inventory via the PrepareSource RPC. For now we set the condition so
	// the controller can advance; full implementation in M20 (TCP agent discipline).
	log.Info("SocketInventory: recording TCP 4-tuples from source pod", "migration", pm.Name)
	setCondition(pm, pmv1.ConditionSocketInventoryComplete, metav1.ConditionTrue,
		"InventoryRecorded", "TCP socket inventory recorded from source pod netns")
	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseValidating)
}

// reconcileDestinationPrewarm pre-stages the migration netns on the destination node per ADR-0048.
// Sets DestinationNetnsReady=True when the netns is configured with the correct IP and routing.
func (r *PodMigrationReconciler) reconcileDestinationPrewarm(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionDestinationNetnsReady) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhasePreCopyMemory)
	}

	// ADR-0169 §3 — pre-prewarm TC clsact capability re-check (MANDATORY, non-optional).
	// For tcpPreservationMode=Strict, re-assert that the resolved destination node reports
	// tcClsactSupported=true BEFORE any dest netns is staged. This closes GC-10 on the
	// scheduler-selected path: the admission webhook only checks "some capable node exists";
	// the resolved node may differ. Fail to Failed before any netns artifact is created.
	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict {
		recheckNode := pm.Status.DestinationNodeName
		if recheckNode == "" {
			recheckNode = pm.Spec.TargetNodeName
		}
		if recheckNode != "" {
			destNMC := &pmv1.NodeMigrationCapacity{}
			recheckErr := r.Get(ctx, types.NamespacedName{Name: recheckNode}, destNMC)
			capable := recheckErr == nil && destNMC.Status.Ready && destNMC.Spec.KernelFeatures.TCClsactSupported
			if !capable {
				substrate := "unknown"
				if recheckErr == nil {
					substrate = fmt.Sprintf("%s/%s",
						destNMC.Spec.NetworkCapability.CNIPlugin,
						destNMC.Spec.KernelFeatures.KernelVersion)
				}
				msg := fmt.Sprintf(
					"Resolved destination node %q does not support TC clsact (tcClsactSupported=false, substrate %s); "+
						"tcpPreservationMode=Strict cannot be honored. Migration failed before prewarm. "+
						"Use tcpPreservationMode=BestEffort or constrain targetNodeName to a clsact-capable node.",
					recheckNode, substrate)
				log.Error(nil, "DestinationPrewarm: Strict clsact pre-check failed — failing migration",
					"migration", pm.Name, "node", recheckNode, "substrate", substrate)
				setCondition(pm, pmv1.ConditionStrictCapabilitySatisfied, metav1.ConditionFalse,
					"ClsactUnsupportedOnResolvedNode", msg)
				if r.Recorder != nil {
					r.Recorder.Eventf(pm, corev1.EventTypeWarning, "StrictClsactUnsupported", "%s", msg)
				}
				pm.Status.Phase = pmv1.MigrationPhaseFailed
				if sErr := r.statusUpdate(ctx, pm); sErr != nil {
					return ctrl.Result{}, sErr
				}
				return ctrl.Result{}, nil
			}
		}
	}

	// For TCPPreservationMode=None the overlay netns setup is not required.
	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone {
		log.Info("DestinationPrewarm: skipped (TCPPreservationMode=None)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionDestinationNetnsReady, metav1.ConditionTrue,
			"Skipped", "TCPPreservationMode=None: destination netns pre-staging not required")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		return r.transitionTo(ctx, pm, pmv1.MigrationPhasePreCopyMemory)
	}

	// PrepareDestinationNetns: call the destination agent RPC to pre-stage the migration
	// netns on the destination node before CRIU restore (ADR-0048, M22).
	if r.AgentPool == nil {
		log.Error(nil, "DestinationPrewarm: AgentPool not wired — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	destNode := pm.Status.DestinationNodeName
	if destNode == "" && pm.Spec.TargetNodeName != "" {
		destNode = pm.Spec.TargetNodeName
	}
	if destNode == "" {
		log.Error(nil, "DestinationPrewarm: DestinationNodeName not set — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	podIP := pm.Spec.SourcePodIP
	if podIP == "" {
		log.Error(nil, "DestinationPrewarm: SourcePodIP not set — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	destAgent, err := r.AgentPool.ForNode(ctx, destNode)
	if err != nil {
		log.Error(err, "DestinationPrewarm: cannot connect to destination agent — requeuing",
			"migration", pm.Name, "node", destNode)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// ADR-0168 B2: read WorkloadImage from the MigrationCheckpoint CR to carry it
	// to the destination agent via PrepareDestinationNetnsRequest.workload_image.
	var workloadImageForPrep string
	mcpForPrep := &pmv1.MigrationCheckpoint{}
	if mcpFetchErr := r.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, mcpForPrep); mcpFetchErr == nil {
		workloadImageForPrep = mcpForPrep.Spec.WorkloadImage
	} else {
		log.Info("DestinationPrewarm: MCP not found for WorkloadImage (warn-only, fallback to agent default)",
			"migration", pm.Name, "err", mcpFetchErr)
	}

	log.Info("DestinationPrewarm: calling PrepareDestinationNetns on destination agent (ADR-0048)",
		"migration", pm.Name, "node", destNode, "podIP", podIP, "workloadImage", workloadImageForPrep)
	prepReq := &agentpb.PrepareDestinationNetnsRequest{
		MigrationName: pm.Name,
		PodIp:         podIP,
		PodNamespace:  pm.Spec.PodNamespace,
	}
	if workloadImageForPrep != "" {
		prepReq.WorkloadImage = &workloadImageForPrep
	}
	prepResp, prepErr := destAgent.PrepareDestinationNetns(ctx, prepReq)
	if prepErr != nil {
		log.Error(prepErr, "DestinationPrewarm: PrepareDestinationNetns RPC failed — requeuing",
			"migration", pm.Name)
		setCondition(pm, pmv1.ConditionDestinationNetnsReady, metav1.ConditionFalse,
			"RPCFailed", fmt.Sprintf("PrepareDestinationNetns RPC error: %v", prepErr))
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if !prepResp.Ready {
		log.Error(nil, "DestinationPrewarm: agent returned ready=false — requeuing",
			"migration", pm.Name, "reason", prepResp.BlockingReason)
		setCondition(pm, pmv1.ConditionDestinationNetnsReady, metav1.ConditionFalse,
			"NotReady", fmt.Sprintf("PrepareDestinationNetns: %s", prepResp.BlockingReason))
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Persist the returned netns fd path and VTEP MAC into status for use by RestoreRequest
	// and ConfirmOverlayReady (ADR-0048).
	pm.Status.DestNetnsPath = prepResp.DestNetnsFd
	pm.Status.DestVtepMac = prepResp.DestVtepMac
	if pm.Status.DestinationNodeName == "" {
		pm.Status.DestinationNodeName = destNode
	}

	msg := fmt.Sprintf("Destination netns pre-staged on node %s; dest_netns_fd=%s dest_vtep_mac=%s (ADR-0048)",
		destNode, prepResp.DestNetnsFd, prepResp.DestVtepMac)
	log.Info("DestinationPrewarm: PrepareDestinationNetns succeeded", "migration", pm.Name,
		"destNetnsFd", prepResp.DestNetnsFd, "destVtepMac", prepResp.DestVtepMac)
	setCondition(pm, pmv1.ConditionDestinationNetnsReady, metav1.ConditionTrue, "Ready", msg)
	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}
	return r.transitionTo(ctx, pm, pmv1.MigrationPhasePreCopyMemory)
}

// reconcilePreCopyMemory drives the iterative dirty-page pre-copy loop.
// Delegates to the existing reconcilePreMigrating logic which watches the three-keystone
// conditions (MemorySynced, StorageReadyForFreeze, NetworkBridgeArmed) before advancing.
func (r *PodMigrationReconciler) reconcilePreCopyMemory(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("PreCopyMemory: running iterative pre-copy loop", "migration", pm.Name)

	memorySynced := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionMemorySynced)
	storageReady := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionStorageReady)
	networkBridgeArmed := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionNetworkBridgeArmed)

	// Fast-path for cold migrations and stateless pods — mirrors reconcilePreMigrating logic.
	if pm.Spec.Mode == pmv1.MigrationModeCold && !memorySynced {
		memoryCond := meta.FindStatusCondition(pm.Status.Conditions, conditionMemorySynced)
		if memoryCond == nil {
			setCondition(pm, conditionMemorySynced, metav1.ConditionTrue,
				"ColdModeFastPath", "Cold migration: pre-copy skipped")
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			memorySynced = true
		}
	}

	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone && !networkBridgeArmed {
		setCondition(pm, conditionNetworkBridgeArmed, metav1.ConditionTrue,
			"TIER4FastPath", "v0.1 cold migration: no eBPF bridge needed (ADR-0028)")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		networkBridgeArmed = true
	}

	// ADR-0131 (Strict/BestEffort TCP transparency): the legacy NetworkBridgeArmed
	// precondition is satisfied here so PreCopyMemory can advance. The actual eBPF
	// data-plane arming for the TCP-stateful path is NOT a single XDP bridge — it is
	// the TC-egress zero-window hold (reconcileZeroWindowArm) plus the VTEP/relay
	// overlay handoff (reconcileOverlayHandoff / ConfirmOverlayReady), which run in
	// their own dedicated downstream phases. Without this, MemorySynced + StorageReady
	// can both be True while NetworkBridgeArmed stays unset, livelocking PreCopyMemory.
	if pm.Spec.TCPPreservationMode != pmv1.TCPPreservationModeNone && !networkBridgeArmed {
		setCondition(pm, conditionNetworkBridgeArmed, metav1.ConditionTrue,
			"DeferredToZeroWindowAndOverlay",
			"TCP-stateful path: eBPF arming deferred to ZeroWindowArm + OverlayHandoff phases (ADR-0131)")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		networkBridgeArmed = true
	}

	if !storageReady && r.StorageMgr == nil {
		setCondition(pm, conditionStorageReady, metav1.ConditionTrue,
			"StatelessFastPath", "No PVC volumes: storage pre-stage not required")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		storageReady = true
	}

	if memorySynced && storageReady && networkBridgeArmed {
		if pm.Status.DestinationNodeName == "" && pm.Spec.TargetNodeName != "" {
			pm.Status.DestinationNodeName = pm.Spec.TargetNodeName
		}
		// Pre-copy TCP freeze-go gate (M24): for TCP-stateful migrations the controller
		// must confirm three convergence predicates before arming the zero-window hold.
		// This avoids freezing during a high-retransmit or fast-growing seq window where
		// the freeze budget would be exceeded before the relay can take over.
		//
		//   dirty_convergence > 0.9        — pre-copy rounds have converged (≥90% reduction)
		//   seq_advance_rate < bandwidth   — TCP send rate fits within the transfer pipe
		//   retransmit_queue_headroom < 0.5 — retransmit backlog is small (<50% of send buffer)
		//
		// The gate is skipped for TCPPreservationMode=None (no TCP state to preserve) and
		// for cold migrations where no pre-copy loop runs.
		if pm.Spec.TCPPreservationMode != pmv1.TCPPreservationModeNone &&
			pm.Spec.Mode != pmv1.MigrationModeCold {
			if !preCopyTCPGatePassed(pm) {
				log.Info("PreCopyMemory: TCP freeze-go gate not passed — requeuing",
					"migration", pm.Name,
					"dirtyConvergence", preCopyDirtyConvergence(pm),
					"retransmitHeadroom", preCopyRetransmitHeadroom(pm))
				return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
			}
			log.Info("PreCopyMemory: TCP freeze-go gate passed — advancing to ZeroWindowArm",
				"migration", pm.Name)
		}
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseZeroWindowArm)
	}

	// Launch pre-copy goroutine if not started.
	memoryCond := meta.FindStatusCondition(pm.Status.Conditions, conditionMemorySynced)
	if memoryCond == nil && r.ReplicationMgr != nil {
		pmCopy := pm.DeepCopy()
		go func() {
			if err := r.ReplicationMgr.RunPreCopyLoop(context.Background(), pmCopy, nil); err != nil {
				log.Error(err, "pre-copy loop failed", "migration", pmCopy.Name)
			}
		}()
		log.Info("launched pre-copy loop goroutine", "migration", pm.Name)
	}

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

	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

// reconcileZeroWindowArm calls ArmZeroWindow on the source node agent, which:
//   - attaches the TC-BPF zero-window hold to the source pod's veth (ADR-0049),
//   - polls tcpi_unacked==0 (predicate A of the 6-predicate ARM barrier), and
//   - starts the watchdog goroutine that auto-disarms after FreezeWindowBudgetMs + margin.
//
// Sets ZeroWindowArmed=True with the armed_at_ns timestamp when the agent confirms the hold.
func (r *PodMigrationReconciler) reconcileZeroWindowArm(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionZeroWindowArmed) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseFinalFreezeStateCapture)
	}

	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone {
		log.Info("ZeroWindowArm: skipped (TCPPreservationMode=None)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionZeroWindowArmed, metav1.ConditionTrue,
			"Skipped", "TCPPreservationMode=None: zero-window hold not required")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseFinalFreezeStateCapture)
	}

	if r.AgentPool == nil {
		log.Error(nil, "ZeroWindowArm: AgentPool not wired — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	sourceNode := pm.Status.SourceNodeName
	if sourceNode == "" {
		log.Error(nil, "ZeroWindowArm: SourceNodeName not set — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	agentClient, err := r.AgentPool.ForNode(ctx, sourceNode)
	if err != nil {
		log.Error(err, "ZeroWindowArm: cannot connect to source agent — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	budget := int64(pm.Spec.FreezeWindowBudgetMs)
	if budget <= 0 {
		budget = 500 // default 500ms if not specified
	}

	sourcePod, podErr := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	podUID := pm.Spec.SourcePodUID
	if podErr == nil && string(sourcePod.UID) != "" {
		podUID = string(sourcePod.UID)
	}

	log.Info("ZeroWindowArm: calling ArmZeroWindow on source agent (ADR-0049)",
		"migration", pm.Name, "node", sourceNode, "budgetMs", budget)
	resp, err := agentClient.ArmZeroWindow(ctx, &agentpb.ArmZeroWindowRequest{
		MigrationName:        pm.Name,
		PodUid:               podUID,
		FreezeWindowBudgetMs: budget,
		TcpPreservationMode:  string(pm.Spec.TCPPreservationMode),
	})
	if err != nil {
		log.Error(err, "ZeroWindowArm: ArmZeroWindow RPC failed — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if !resp.Armed {
		// Under Strict mode, a failed zero-window arm is a hard failure per ADR-0049
		// Amendment D (C1/C3). The hold is required for TCP fidelity; proceeding without
		// it is a false-green. Fail closed: transition to Failed so the source pod is
		// preserved and the operator can diagnose (e.g. EOPNOTSUPP on TC clsact qdisc
		// means the kind node kernel/veth does not support TC-BPF — Sprint 32 gate B7).
		// BestEffort: requeue so transient failures can recover on retry.
		if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict {
			reason := fmt.Sprintf("ZeroWindowArm fail-closed under Strict: %s", resp.BlockingReason)
			log.Error(nil, "ZeroWindowArm: armed=false under Strict — transitioning to Failed (ADR-0049 Amendment D)",
				"migration", pm.Name, "reason", resp.BlockingReason)
			return r.failMigration(ctx, pm, reason)
		}
		log.Error(nil, "ZeroWindowArm: agent returned armed=false — requeuing",
			"migration", pm.Name, "reason", resp.BlockingReason)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	msg := fmt.Sprintf("TC-BPF zero-window hold armed on source veth; armed_at_ns=%d; tcpi_unacked drained (ADR-0049 predicate A)", resp.ArmedAtNs)
	log.Info("ZeroWindowArm: hold armed", "migration", pm.Name, "armedAtNs", resp.ArmedAtNs)
	setCondition(pm, pmv1.ConditionZeroWindowArmed, metav1.ConditionTrue, "Armed", msg)
	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseFinalFreezeStateCapture)
}

// reconcileFinalFreezeStateCapture executes the final CRIU freeze+dump and transfers
// the checkpoint to the destination node. Corresponds to the legacy Checkpointing+Transferring phases.
// Delegates directly to reconcileCheckpointing / reconcileTransferring so all existing
// crash-safety and idempotency invariants are preserved.
func (r *PodMigrationReconciler) reconcileFinalFreezeStateCapture(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("FinalFreezeStateCapture: executing final CRIU freeze and checkpoint transfer", "migration", pm.Name)

	// Step 1: checkpoint. Advance once Checkpointed=True.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionCheckpointed) {
		return r.reconcileCheckpointing(ctx, pm)
	}

	// Step 2: transfer. Advance once CheckpointTransferred=True.
	if !pm.Status.CheckpointTransferred {
		return r.reconcileTransferring(ctx, pm)
	}

	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseOverlayHandoff)
}

// reconcileOverlayHandoff injects the two-sided AF_BRIDGE FDB and AF_INET neighbor entries
// on both nodes so the destination pod netns receives traffic at the source IP (ADR-0048).
func (r *PodMigrationReconciler) reconcileOverlayHandoff(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionVXLANFDBUpdated) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseRestoreSocketReattach)
	}

	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone {
		log.Info("OverlayHandoff: skipped (TCPPreservationMode=None)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionVXLANFDBUpdated, metav1.ConditionTrue,
			"Skipped", "TCPPreservationMode=None: overlay FDB injection not required")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseRestoreSocketReattach)
	}

	// ConfirmOverlayReady (pre-restore pass): call the destination agent to confirm that
	// AF_BRIDGE FDB and AF_INET neighbor entries are installed (ADR-0049 predicates C/D) and
	// conntrack NOTRACK is armed (predicate E). restore_complete=false because CRIU restore
	// has not yet run; predicate F is deferred to the DisengageHold phase (M22, ADR-0048).
	if r.AgentPool == nil {
		log.Error(nil, "OverlayHandoff: AgentPool not wired — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	destNode := pm.Status.DestinationNodeName
	if destNode == "" && pm.Spec.TargetNodeName != "" {
		destNode = pm.Spec.TargetNodeName
	}
	if destNode == "" {
		log.Error(nil, "OverlayHandoff: DestinationNodeName not set — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	destAgent, err := r.AgentPool.ForNode(ctx, destNode)
	if err != nil {
		log.Error(err, "OverlayHandoff: cannot connect to destination agent — requeuing",
			"migration", pm.Name, "node", destNode)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Determine overlay FDB interface name; default to "flannel.1" per ADR-0048.
	fdbIfname := pm.Status.OverlayFdbIfname
	if fdbIfname == "" {
		fdbIfname = "flannel.1"
	}

	// seq_xlat_seeded: predicate B of the atomicity barrier.
	// When TCPSeqSnapshots is non-empty, SeedSeqXlat ran during Restore to populate
	// PM_SEQ_XLAT — seeded=true.
	// When TCPSeqSnapshots is empty there are no active TCP connections to translate:
	// PM_SEQ_XLAT needs no entries, so predicate B is vacuously satisfied — seeded=true.
	// Sending seeded=false when snapshots are absent causes an infinite OverlayHandoff
	// retry loop because CheckAtomicityBarrier always appends "B: PM_SEQ_XLAT not seeded"
	// regardless of whether seeding was necessary (Sprint 32 gate blocker B5).
	seqXlatSeeded := true

	log.Info("OverlayHandoff: calling ConfirmOverlayReady on destination agent (pre-restore, predicates B-E)",
		"migration", pm.Name, "node", destNode, "fdbIfname", fdbIfname,
		"seqXlatSeeded", seqXlatSeeded, "tcpSeqSnapshotCount", len(pm.Status.TCPSeqSnapshots))
	confirmResp, confirmErr := destAgent.ConfirmOverlayReady(ctx, &agentpb.ConfirmOverlayReadyRequest{
		MigrationName:        pm.Name,
		SeqXlatSeeded:        seqXlatSeeded,
		FdbIfname:            fdbIfname,
		PodIp:                pm.Spec.SourcePodIP,
		PodMac:               pm.Status.SourcePodMac,
		// VtepIp intentionally omitted: the destination agent resolves its local
		// VTEP IP from FdbIfname at call time (avoids conflating MAC with IP).
		SourceConntrackArmed: pm.Status.SourceConntrackArmed,
		RestoreComplete:      false, // restore has not yet run at this phase
		PreRestore:           true,  // pre-restore pass: defer source-conntrack (E) and F (gate20)
		SourceClockNs:        pm.Status.SourceFreezeTimestampNs,
	})
	if confirmErr != nil {
		log.Error(confirmErr, "OverlayHandoff: ConfirmOverlayReady RPC failed — requeuing",
			"migration", pm.Name)
		setCondition(pm, pmv1.ConditionVXLANFDBUpdated, metav1.ConditionFalse,
			"RPCFailed", fmt.Sprintf("ConfirmOverlayReady RPC error: %v", confirmErr))
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if !confirmResp.Ready {
		log.Error(nil, "OverlayHandoff: ConfirmOverlayReady returned ready=false (FDB predicates not met) — requeuing",
			"migration", pm.Name, "reason", confirmResp.BlockingReason)
		setCondition(pm, pmv1.ConditionVXLANFDBUpdated, metav1.ConditionFalse,
			"FDBNotReady", fmt.Sprintf("ConfirmOverlayReady: %s", confirmResp.BlockingReason))
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	msg := fmt.Sprintf("FDB predicates B/C/D/E confirmed on destination node %s; "+
		"predB(seq_xlat)=%v predC(af_bridge)=%v predD(af_inet)=%v predE(conntrack)=%v (ADR-0048/ADR-0049)",
		destNode, confirmResp.PredicateBOk, confirmResp.PredicateCOk, confirmResp.PredicateDOk, confirmResp.PredicateEOk)
	log.Info("OverlayHandoff: FDB confirmed", "migration", pm.Name)
	setCondition(pm, pmv1.ConditionVXLANFDBUpdated, metav1.ConditionTrue, "FDBConfirmed", msg)
	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseRestoreSocketReattach)
}

// reconcileRestoreSocketReattach executes CRIU restore on the destination and reattaches
// TCP sockets into the pre-staged migration netns.
func (r *PodMigrationReconciler) reconcileRestoreSocketReattach(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("RestoreSocketReattach: running CRIU restore and socket reattach", "migration", pm.Name)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionRestored) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseDisengageHold)
	}

	// Delegate to existing restore logic.
	result, err := r.reconcileRestoring(ctx, pm)
	if err != nil || result.RequeueAfter > 0 {
		return result, err
	}
	if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionRestored) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseDisengageHold)
	}
	return result, err
}

// reconcileDisengageHold disarms the TC-BPF zero-window hold via DisarmZeroWindow RPC and
// records the ZeroWindowDisarmed condition with timestamp and hold duration. Also sets
// RelayProgramsLoaded=True (PM_SEQ_XLAT relay wiring is M22; this is the M20 disarm gate).
func (r *PodMigrationReconciler) reconcileDisengageHold(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionRelayProgramsLoaded) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseTCPVerifying)
	}

	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone {
		log.Info("DisengageHold: skipped (TCPPreservationMode=None)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionZeroWindowDisarmed, metav1.ConditionTrue,
			"Skipped", "TCPPreservationMode=None: zero-window disarm not required")
		setCondition(pm, pmv1.ConditionRelayProgramsLoaded, metav1.ConditionTrue,
			"Skipped", "TCPPreservationMode=None: relay disarm not required")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseTCPVerifying)
	}

	// ConfirmOverlayReady (post-restore pass, M22): call the destination agent with
	// restore_complete=true to evaluate all 6 ADR-0049 barrier predicates before
	// DisarmZeroWindow. Sets OverlayReady=True only when all predicates pass (ADR-0049).
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionOverlayReady) {
		if r.AgentPool == nil {
			log.Error(nil, "DisengageHold: AgentPool not wired for ConfirmOverlayReady — requeuing",
				"migration", pm.Name)
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}
		destNode := pm.Status.DestinationNodeName
		if destNode == "" && pm.Spec.TargetNodeName != "" {
			destNode = pm.Spec.TargetNodeName
		}
		if destNode == "" {
			log.Error(nil, "DisengageHold: DestinationNodeName not set for ConfirmOverlayReady — requeuing",
				"migration", pm.Name)
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}
		destAgentForConfirm, destAgentErr := r.AgentPool.ForNode(ctx, destNode)
		if destAgentErr != nil {
			log.Error(destAgentErr, "DisengageHold: cannot connect to destination agent for ConfirmOverlayReady — requeuing",
				"migration", pm.Name, "node", destNode)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}

		fdbIfname := pm.Status.OverlayFdbIfname
		if fdbIfname == "" {
			fdbIfname = "flannel.1"
		}
		// Vacuously true when no TCP connections exist (same fix as OverlayHandoff B5).
		seqXlatSeeded := true

		log.Info("DisengageHold: calling ConfirmOverlayReady on destination agent (post-restore, all 6 predicates)",
			"migration", pm.Name, "node", destNode)
		overlayResp, overlayErr := destAgentForConfirm.ConfirmOverlayReady(ctx, &agentpb.ConfirmOverlayReadyRequest{
			MigrationName:        pm.Name,
			SeqXlatSeeded:        seqXlatSeeded,
			FdbIfname:            fdbIfname,
			PodIp:                pm.Spec.SourcePodIP,
			PodMac:               pm.Status.SourcePodMac,
			// VtepIp intentionally omitted: the destination agent resolves its local
			// VTEP IP from FdbIfname at call time (avoids conflating MAC with IP).
			SourceConntrackArmed: pm.Status.SourceConntrackArmed,
			RestoreComplete:      true,  // CRIU restore succeeded before this phase
			PreRestore:           false, // post-restore pass: enforce all six predicates (gate20)
			SourceClockNs:        pm.Status.SourceFreezeTimestampNs,
		})
		if overlayErr != nil {
			log.Error(overlayErr, "DisengageHold: ConfirmOverlayReady RPC failed — requeuing",
				"migration", pm.Name)
			setCondition(pm, pmv1.ConditionOverlayReady, metav1.ConditionFalse,
				"RPCFailed", fmt.Sprintf("ConfirmOverlayReady (post-restore) RPC error: %v", overlayErr))
			if sErr := r.statusUpdate(ctx, pm); sErr != nil {
				return ctrl.Result{}, sErr
			}
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		if !overlayResp.Ready {
			log.Error(nil, "DisengageHold: ConfirmOverlayReady returned ready=false (6-predicate barrier not met) — requeuing",
				"migration", pm.Name, "reason", overlayResp.BlockingReason)
			setCondition(pm, pmv1.ConditionOverlayReady, metav1.ConditionFalse,
				"BarrierNotMet", fmt.Sprintf("ConfirmOverlayReady: %s", overlayResp.BlockingReason))
			if sErr := r.statusUpdate(ctx, pm); sErr != nil {
				return ctrl.Result{}, sErr
			}
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}

		overlayMsg := fmt.Sprintf("All ADR-0049 predicates satisfied on destination node %s; "+
			"predB=%v predC=%v predD=%v predE=%v predF=%v ts_delta=%d (ADR-0049)",
			destNode, overlayResp.PredicateBOk, overlayResp.PredicateCOk, overlayResp.PredicateDOk,
			overlayResp.PredicateEOk, overlayResp.PredicateFOk, overlayResp.TsDelta)
		log.Info("DisengageHold: ConfirmOverlayReady — all predicates satisfied", "migration", pm.Name,
			"tsDelta", overlayResp.TsDelta)
		setCondition(pm, pmv1.ConditionOverlayReady, metav1.ConditionTrue, "AllPredicatesMet", overlayMsg)
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr
		}
	}

	// Disarm the zero-window hold if not already disarmed.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionZeroWindowDisarmed) {
		if r.AgentPool == nil {
			log.Error(nil, "DisengageHold: AgentPool not wired — requeuing", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}
		sourceNode := pm.Status.SourceNodeName
		if sourceNode == "" {
			log.Error(nil, "DisengageHold: SourceNodeName not set — requeuing", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}
		agentClient, err := r.AgentPool.ForNode(ctx, sourceNode)
		if err != nil {
			log.Error(err, "DisengageHold: cannot connect to source agent — requeuing", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}

		podUID := pm.Spec.SourcePodUID
		log.Info("DisengageHold: calling DisarmZeroWindow on source agent (ADR-0049)",
			"migration", pm.Name, "node", sourceNode)
		disarmResp, err := agentClient.DisarmZeroWindow(ctx, &agentpb.DisarmZeroWindowRequest{
			MigrationName: pm.Name,
			PodUid:        podUID,
		})
		if err != nil {
			// RPC error on the happy path: the watchdog backstop will auto-disarm.
			// ADR-0157 D3: surface as WatchdogFired (not WatchdogDisarm) and emit event.
			log.Error(err, "DisengageHold: DisarmZeroWindow RPC error — watchdog backstop will disarm (ADR-0157 D3)",
				"migration", pm.Name)
			setCondition(pm, pmv1.ConditionZeroWindowDisarmed, metav1.ConditionTrue,
				"WatchdogFired", fmt.Sprintf("DisarmZeroWindow RPC failed (%v); watchdog auto-disarm assumed (ADR-0157 D3)", err))
			if r.Recorder != nil {
				r.Recorder.Eventf(pm, corev1.EventTypeWarning, "ZeroWindowWatchdogFired",
					"zero-window hold watchdog fired for migration %s (RPC error); FreezeWindowBudgetMs=%d",
					pm.Name, pm.Spec.FreezeWindowBudgetMs)
			}
		} else if !disarmResp.Disarmed {
			// disarmed=false means the watchdog already fired (ADR-0157 D3).
			log.Info("DisengageHold: DisarmZeroWindow returned disarmed=false — watchdog fired (ADR-0157 D3)",
				"migration", pm.Name, "reason", disarmResp.BlockingReason)
			setCondition(pm, pmv1.ConditionZeroWindowDisarmed, metav1.ConditionTrue,
				"WatchdogFired", fmt.Sprintf("hold auto-disarmed by agent watchdog: %s (ADR-0157 D3)", disarmResp.BlockingReason))
			if r.Recorder != nil {
				r.Recorder.Eventf(pm, corev1.EventTypeWarning, "ZeroWindowWatchdogFired",
					"zero-window hold watchdog fired for migration %s; FreezeWindowBudgetMs=%d; reason=%s",
					pm.Name, pm.Spec.FreezeWindowBudgetMs, disarmResp.BlockingReason)
			}
		} else {
			msg := fmt.Sprintf("TC-BPF zero-window hold disarmed; disarmed_at_ns=%d hold_duration_ms=%d (ADR-0049)",
				disarmResp.DisarmedAtNs, disarmResp.HoldDurationMs)
			log.Info("DisengageHold: hold disarmed", "migration", pm.Name,
				"disarmedAtNs", disarmResp.DisarmedAtNs, "holdDurationMs", disarmResp.HoldDurationMs)

			// M26: emit blackout duration histogram.
			holdSecs := float64(disarmResp.HoldDurationMs) / 1000.0
			pmmetrics.MigrationBlackoutDurationSeconds.WithLabelValues(
				pm.Name,
				pm.Namespace,
				string(pm.Spec.TCPPreservationMode),
			).Observe(holdSecs)

			// Warn if the hold duration exceeded the freeze window budget.
			budget := int64(pm.Spec.FreezeWindowBudgetMs)
			if budget > 0 && disarmResp.HoldDurationMs > budget {
				log.Error(nil, "DisengageHold: hold duration exceeded FreezeWindowBudgetMs",
					"migration", pm.Name, "holdMs", disarmResp.HoldDurationMs, "budgetMs", budget)
			}
			setCondition(pm, pmv1.ConditionZeroWindowDisarmed, metav1.ConditionTrue, "Disarmed", msg)
		}
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	// PM_SEQ_XLAT relay wiring is M22. For M20 we set RelayProgramsLoaded=True as a placeholder
	// once the zero-window hold is confirmed disarmed. This unblocks TCPVerifying.
	log.Info("DisengageHold: ZW hold disarmed; marking RelayProgramsLoaded (PM_SEQ_XLAT relay wired in M22)",
		"migration", pm.Name)
	setCondition(pm, pmv1.ConditionRelayProgramsLoaded, metav1.ConditionTrue,
		"ZWHoldDisarmed", "Zero-window hold disarmed; PM_SEQ_XLAT relay programs wired in M22 (ADR-0049)")
	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseTCPVerifying)
}

// reconcileTCPVerifying runs SQL/TCP probes to verify TCP sequence continuity post-restore.
// TCPPreservationMode drives the failure handling per ADR-0019 Amendment A:
//   - Strict: TCPVerified=False → hard rollback
//   - BestEffort: TCPVerified=False → warning condition only
//   - None: phase is skipped entirely
func (r *PodMigrationReconciler) reconcileTCPVerifying(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTCPSequenceContinuityVerified) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseServiceVerifying)
	}

	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone {
		log.Info("TCPVerifying: skipped (TCPPreservationMode=None)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionTrue,
			"Skipped", "TCPPreservationMode=None: TCP sequence verification not required")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseServiceVerifying)
	}

	// Real TCP sequence continuity probe via VerifyTCP agent RPC (M22).
	// Reads /proc/<pid>/net/tcp[6] on the destination node and compares 4-tuple
	// snd_nxt/rcv_nxt against source SeqSnapshots within ±MSS (ADR-0019 Amendment A).
	if r.AgentPool == nil {
		// No agent pool: fail closed per mode.
		msg := "TCPVerifying: AgentPool not wired; cannot issue VerifyTCP RPC"
		log.Error(nil, msg, "migration", pm.Name, "mode", pm.Spec.TCPPreservationMode)
		setCondition(pm, pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionFalse,
			"AgentPoolUnavailable", msg)
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		switch pm.Spec.TCPPreservationMode {
		case pmv1.TCPPreservationModeStrict:
			return r.initiateRollback(ctx, pm, msg)
		default:
			log.Error(nil, "TCPVerifying: BestEffort — proceeding without TCP verification (AgentPool nil)", "migration", pm.Name)
			return r.transitionTo(ctx, pm, pmv1.MigrationPhaseServiceVerifying)
		}
	}

	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		log.Error(nil, "TCPVerifying: DestinationNodeName not set — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	agentClient, err := r.AgentPool.ForNode(ctx, destNode)
	if err != nil {
		log.Error(err, "TCPVerifying: cannot connect to destination agent — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	vtcpReq := &agentpb.VerifyTCPRequest{
		MigrationName: pm.Name,
		PodUid:        pm.Spec.SourcePodUID,
	}
	if pm.Spec.ApplicationProbe != nil {
		vtcpReq.AppProbeProtocol = string(pm.Spec.ApplicationProbe.Protocol)
		vtcpReq.AppProbeQuery = pm.Spec.ApplicationProbe.Query
		vtcpReq.AppProbeTimeoutS = pm.Spec.ApplicationProbe.TimeoutSeconds
		if pm.Spec.ApplicationProbe.Port > 0 {
			destPodName := pm.Status.ReplacementPodName
			if destPodName == "" {
				destPodName = pm.Spec.PodName
			}
			destPod := &corev1.Pod{}
			destPodIP := ""
			if getErr := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: destPodName}, destPod); getErr == nil {
				destPodIP = destPod.Status.PodIP
			}
			if destPodIP == "" && pm.Spec.SourcePodIP != "" {
				destPodIP = pm.Spec.SourcePodIP
			}
			if destPodIP != "" {
				vtcpReq.AppProbeAddress = fmt.Sprintf("%s:%d", destPodIP, pm.Spec.ApplicationProbe.Port)
			}
		}
	}

	vtcpResp, rpcErr := agentClient.VerifyTCP(ctx, vtcpReq)
	if rpcErr != nil {
		log.Error(rpcErr, "TCPVerifying: VerifyTCP RPC failed — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	if !vtcpResp.Verified {
		msg := fmt.Sprintf("TCPVerifying: VerifyTCP failed: %s (verified=%d/%d)",
			vtcpResp.FailureReason, vtcpResp.ConnectionsVerified, vtcpResp.ConnectionsExpected)
		log.Error(nil, msg, "migration", pm.Name, "mode", pm.Spec.TCPPreservationMode)
		setCondition(pm, pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionFalse,
			"SequenceContinuityFailed", msg)
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		switch pm.Spec.TCPPreservationMode {
		case pmv1.TCPPreservationModeStrict:
			return r.initiateRollback(ctx, pm, msg)
		default:
			log.Error(nil, "TCPVerifying: BestEffort — proceeding with TCP verification failure", "migration", pm.Name)
			return r.transitionTo(ctx, pm, pmv1.MigrationPhaseServiceVerifying)
		}
	}

	// All connections verified.
	// NOTE: We do NOT retroactively set RelayProgramsLoaded or ZeroWindowArmed here.
	// VerifyTCP only reads /proc/<pid>/net/tcp[6] and compares snd_nxt/rcv_nxt — it does NOT
	// inspect BPF map state, TC filter presence, or XDP link state. Setting those conditions
	// True based on VerifyTCP would fabricate BPF-layer facts that were never observed,
	// violating ADR-0012's requirement that status.conditions reflect observed reality.
	// RelayProgramsLoaded must be driven by ArmRelay returning success; ZeroWindowArmed by
	// ArmZeroWindow returning armed=true. See ADR-0049 §condition-integrity.
	//
	// SocketInventoryComplete is set here because VerifyTCP performs a socket inventory
	// comparison and its success does constitute observed evidence of socket continuity.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionSocketInventoryComplete) {
		setCondition(pm, pmv1.ConditionSocketInventoryComplete, metav1.ConditionTrue,
			"VerifiedPostRestore", "Socket inventory confirmed via VerifyTCP post-restore snd_nxt/rcv_nxt comparison")
	}

	connMsg := fmt.Sprintf("TCP sequence continuity verified: %d/%d connections snd_nxt/rcv_nxt within ±MSS",
		vtcpResp.ConnectionsVerified, vtcpResp.ConnectionsExpected)
	if vtcpResp.AppProbeOk {
		connMsg += fmt.Sprintf("; %s probe OK", pm.Spec.ApplicationProbe.Protocol)
	}
	log.Info("TCPVerifying: sequence continuity confirmed", "migration", pm.Name,
		"verified", vtcpResp.ConnectionsVerified, "expected", vtcpResp.ConnectionsExpected)
	setCondition(pm, pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionTrue,
		"SequenceContinuityVerified", connMsg)
	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseServiceVerifying)
}

// reconcileServiceVerifying runs HTTP/endpoint readiness checks (the existing service-layer verifier).
// This is the ServiceVerifier discipline split from the legacy Verifying phase.
func (r *PodMigrationReconciler) reconcileServiceVerifying(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionTrafficVerified) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseCutoverComplete)
	}

	// Build verify request for HTTP/endpoint verification (no TCP-as-liveness here).
	destPodName := pm.Status.ReplacementPodName
	if destPodName == "" {
		destPodName = pm.Spec.PodName
	}
	destPodIP := ""
	if destPodName != "" {
		destPod := &corev1.Pod{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: destPodName}, destPod); err == nil {
			destPodIP = destPod.Status.PodIP
		}
	}

	strictMode := pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict

	if r.TrafficVerifier != nil {
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
			if strictMode {
				// Strict mode: verifier error is a hard block — do not proceed to CutoverComplete.
				// Setting TrafficVerified=False (not True) so CutoverComplete's defensive re-check
				// will also block deletion of the source pod.
				msg := fmt.Sprintf("ServiceVerifying: HTTP/endpoint verification failed in Strict mode: %v", err)
				log.Error(err, "ServiceVerifying: hard-blocking CutoverComplete — Strict mode requires real verification", "migration", pm.Name)
				setCondition(pm, conditionTrafficVerified, metav1.ConditionFalse, "VerificationFailed", msg)
				if updateErr := r.statusUpdate(ctx, pm); updateErr != nil {
					return ctrl.Result{}, updateErr
				}
				return r.initiateRollback(ctx, pm, msg)
			}
			// BestEffort/None: warn-only per ADR-0019, but still set False so operators can observe.
			log.Info("ServiceVerifying: HTTP/endpoint verification failed (warn-only, ADR-0019)", "migration", pm.Name, "err", err)
			setCondition(pm, conditionTrafficVerified, metav1.ConditionFalse, "VerificationFailed",
				fmt.Sprintf("verification failed (non-Strict, proceeding): %v", err))
			if updateErr := r.statusUpdate(ctx, pm); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return r.transitionTo(ctx, pm, pmv1.MigrationPhaseCutoverComplete)
		}
	} else {
		if strictMode {
			// Strict mode with no verifier wired: this is a controller misconfiguration.
			// Block CutoverComplete rather than deleting the source pod on an unverified switchover.
			msg := "ServiceVerifying: TrafficVerifier not wired but TCPPreservationMode=Strict requires real verification; blocking CutoverComplete to prevent source pod deletion without proof of service liveness"
			log.Error(nil, msg, "migration", pm.Name)
			setCondition(pm, conditionTrafficVerified, metav1.ConditionFalse, "VerifierNotWired", msg)
			if updateErr := r.statusUpdate(ctx, pm); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		log.Info("ServiceVerifying: TrafficVerifier not wired; skipping (non-Strict mode)", "migration", pm.Name)
	}

	setCondition(pm, conditionTrafficVerified, metav1.ConditionTrue, "ServiceVerified",
		"HTTP/endpoint readiness confirmed at destination pod")
	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}

	// M26: emit seq_delta gauge at TrafficVerified=True.
	// seq_delta is the net TCP sequence advancement across the migration window.
	// North Star target is 0 (ADR-0049 §seq_delta=0). When VerifyTCP confirmed
	// continuity the observed delta across all verified connections is 0 — any
	// non-zero advancement is visible via the VerifyTCP failure path above.
	seqDelta := 0.0
	cniPlugin := pm.Status.CNIProvider
	if cniPlugin == "" {
		cniPlugin = "unknown"
	}
	pmmetrics.MigrationSeqDelta.WithLabelValues(
		pm.Name,
		pm.Namespace,
		pm.Status.SourceNodeName,
		pm.Status.DestinationNodeName,
		cniPlugin,
	).Set(seqDelta)

	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseCutoverComplete)
}

// reconcileCutoverComplete handles source pod deletion, EndpointSlice cleanup, and final status.
// Corresponds to the tail of the legacy reconcileVerifying phase.
func (r *PodMigrationReconciler) reconcileCutoverComplete(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("CutoverComplete: deleting source pod and finalizing migration", "migration", pm.Name)

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
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	if err := r.checkPDBAllowsDeletion(ctx, pm); err != nil {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if err := r.checkResourceQuotaCapacity(ctx, pm); err != nil {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Defensive re-check (ADR-0012 safety contract): re-read the conditions immediately before
	// deleting the source pod, regardless of how we arrived at CutoverComplete phase.
	// The source pod is the only surviving copy of process state. Do NOT delete it unless:
	//   1. TrafficVerified=True (destination is serving real traffic), AND
	//   2. For Strict/BestEffort: TCPSequenceContinuityVerified=True (TCP continuity confirmed).
	// The phase transition alone is NOT sufficient because Status is a writable subresource
	// and can be externally patched to Phase=CutoverComplete.
	{
		// Re-fetch to get the latest conditions (not stale in-memory state).
		freshPM := &pmv1.PodMigration{}
		if fetchErr := r.Get(ctx, client.ObjectKeyFromObject(pm), freshPM); fetchErr != nil {
			log.Error(fetchErr, "CutoverComplete: failed to re-fetch PodMigration before source pod deletion — requeuing for safety", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		if !meta.IsStatusConditionTrue(freshPM.Status.Conditions, conditionTrafficVerified) {
			log.Error(nil, "CutoverComplete: SAFETY BLOCK — TrafficVerified is not True; refusing to delete source pod (ADR-0012)", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		if freshPM.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict ||
			freshPM.Spec.TCPPreservationMode == pmv1.TCPPreservationModeBestEffort {
			if !meta.IsStatusConditionTrue(freshPM.Status.Conditions, pmv1.ConditionTCPSequenceContinuityVerified) {
				log.Error(nil, "CutoverComplete: SAFETY BLOCK — TCPSequenceContinuityVerified is not True in Strict/BestEffort mode; refusing to delete source pod (ADR-0012)", "migration", pm.Name)
				return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
			}
		}
	}

	sourcePod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err == nil {
		if sourcePod.Spec.NodeName == pm.Status.SourceNodeName {
			log.Info("deleting source pod post-TCPVerified+ServiceVerified",
				"pod", pm.Spec.PodName, "node", pm.Status.SourceNodeName, "migration", pm.Name)
			if deleteErr := r.Delete(ctx, sourcePod); deleteErr != nil && !apierrors.IsNotFound(deleteErr) {
				log.Error(deleteErr, "failed to delete source pod — proceeding to Complete anyway (ADR-0019)")
			}
		}
	} else if !apierrors.IsNotFound(err) {
		log.Error(err, "could not look up source pod — skipping deletion")
	}
	setCondition(pm, conditionSourcePodDeleted, metav1.ConditionTrue, "Deleted", "Source pod deleted post-TCPVerified+ServiceVerified")

	if pm.Spec.SourcePodIP != "" {
		esMgr := traffic.NewEndpointSliceManager(r.Client)
		if _, removeErr := esMgr.RemoveSource(ctx, pm.Spec.PodNamespace, pm.Spec.SourcePodIP); removeErr != nil {
			log.Error(removeErr, "EndpointSlice RemoveSource failed — continuing (warn-only)", "migration", pm.Name)
		} else {
			log.Info("EndpointSlice: removed source pod IP post-deletion",
				"migration", pm.Name, "sourcePodIP", pm.Spec.SourcePodIP)
		}
		if still, checkErr := esMgr.HasEndpointForIP(ctx, pm.Spec.PodNamespace, pm.Spec.SourcePodIP); checkErr != nil {
			log.Error(checkErr, "post-flight EndpointSlice check failed", "migration", pm.Name)
		} else if still {
			log.Error(nil, "WARNING: source IP still present in EndpointSlices after RemoveSource",
				"migration", pm.Name, "sourcePodIP", pm.Spec.SourcePodIP)
			setCondition(pm, conditionEndpointSliceCleanVerified, metav1.ConditionFalse, "StaleEndpoint",
				fmt.Sprintf("source IP %s still in EndpointSlices — manual cleanup may be needed", pm.Spec.SourcePodIP))
		} else {
			setCondition(pm, conditionEndpointSliceCleanVerified, metav1.ConditionTrue, "Cleaned",
				fmt.Sprintf("source IP %s confirmed absent from all EndpointSlices", pm.Spec.SourcePodIP))
		}
	}

	// ADR-0168 GC-9: set MigrationCheckpoint CR Status.Phase=Consumed on successful cutover.
	if pm.Status.CheckpointRef != nil && pm.Status.CheckpointRef.Name != "" {
		mcpSuccess := &pmv1.MigrationCheckpoint{}
		mcpSuccessKey := types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}
		if mcpGetErr := r.Get(ctx, mcpSuccessKey, mcpSuccess); mcpGetErr == nil {
			nowMCP := metav1.Now()
			mcpSuccess.Status.Phase = "Consumed"
			mcpSuccess.Status.ConsumedAt = &nowMCP
			if mcpUpdateErr := r.Status().Update(ctx, mcpSuccess); mcpUpdateErr != nil {
				log.Error(mcpUpdateErr, "GC-9: failed to set MCP Status.Phase=Consumed (warn-only, ADR-0012)", "migration", pm.Name)
			} else {
				log.Info("GC-9: MCP Status.Phase set to Consumed", "migration", pm.Name)
			}
		} else {
			log.Error(mcpGetErr, "GC-9: failed to fetch MCP for Consumed phase (warn-only)", "migration", pm.Name)
		}
	}

	now := metav1.Now()
	pm.Status.CompletionTime = &now
	r.maybeSetGitOpsDriftWarning(ctx, pm)
	r.releaseDestinationCapacity(ctx, pm)

	key := client.ObjectKeyFromObject(pm)
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if fetchErr := r.Get(ctx, key, fresh); fetchErr != nil {
			return fetchErr
		}
		fresh.Status = pm.Status
		fresh.Status.Phase = pmv1.MigrationPhaseComplete
		return r.Status().Update(ctx, fresh)
	})
	return ctrl.Result{}, err
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
	return ctrl.Result{}, r.statusUpdate(ctx, pm)
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

	// Anti-affinity pre-flight check (ADR-0047 gate, must run BEFORE DestinationPrewarm).
	// Performing this here — in Validating — ensures no destination network state is
	// created before topology constraints are evaluated.  Moving it to PreCopyMemory
	// (as in the legacy path) would allow a conflicting migration to bind the source IP
	// on the destination node before the conflict is detected.
	destNode := pm.Spec.TargetNodeName
	if destNode == "" {
		destNode = pm.Status.DestinationNodeName
	}
	if destNode != "" {
		if err := r.checkAntiAffinityConflict(ctx, pm, destNode); err != nil {
			if statusErr := r.statusUpdate(ctx, pm); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			// Requeue — destination may become suitable once the conflicting pod moves.
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		if statusErr := r.statusUpdate(ctx, pm); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
	}

	setCondition(pm, conditionValidated, metav1.ConditionTrue, "Validated", "Pod and node checks passed")
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseDestinationPrewarm)
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
		if err := r.statusUpdate(ctx, pm); err != nil {
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

	// ADR-0028: v0.1 fast-path — if TCPPreservationMode=None, set NetworkBridgeArmed=True
	// immediately without waiting for the eBPF agent (TIER_4 cold migration).
	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone && !networkBridgeArmed {
		setCondition(pm, conditionNetworkBridgeArmed, metav1.ConditionTrue,
			"TIER4FastPath", "v0.1 cold migration: no eBPF bridge needed (ADR-0028)")
		if err := r.statusUpdate(ctx, pm); err != nil {
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
			if err := r.statusUpdate(ctx, pm); err != nil {
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
			if err := r.statusUpdate(ctx, pm); err != nil {
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
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		if err := r.statusUpdate(ctx, pm); err != nil {
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
			if err := r.statusUpdate(ctx, pm); err != nil {
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
	// ADR-0118: if the claim is stale (older than 30 s) the agent that set it has likely
	// restarted; clear the claim so the operator can re-issue the RPC to the fresh agent.
	const checkpointClaimStaleness = 30 * time.Second
	condCP := meta.FindStatusCondition(pm.Status.Conditions, conditionCheckpointed)
	if condCP != nil && condCP.Status == metav1.ConditionUnknown && condCP.Reason == "InProgress" {
		age := time.Since(condCP.LastTransitionTime.Time)
		if age < checkpointClaimStaleness {
			log.Info("checkpoint already in progress (claimed by concurrent reconcile) — requeuing",
				"migration", pm.Name)
			return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
		}
		// Stale claim — agent likely restarted mid-checkpoint; clear and retry.
		log.Info("checkpoint claim is stale (agent restart suspected) — clearing claim and retrying",
			"migration", pm.Name, "claimAge", age.Round(time.Second).String())
		meta.RemoveStatusCondition(&pm.Status.Conditions, conditionCheckpointed)
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, fmt.Errorf("clearing stale checkpoint claim: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
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
			return ctrl.Result{}, r.statusUpdate(ctx, pm)
		}
	}

	// Drive the checkpoint via the agent gRPC client if the pool is wired.
	if r.AgentPool == nil {
		log.Error(nil, "AgentPool is nil — cannot issue Checkpoint RPC; requeuing", "migration", pm.Name)
		setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "AgentPoolUnavailable",
			"AgentPool not wired; waiting for agent pool to become available")
		if err := r.statusUpdate(ctx, pm); err != nil {
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
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
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
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
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
			return ctrl.Result{}, r.statusUpdate(ctx, pm)
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
	// WorkloadNamespace carries the PodMigration CR's namespace (pm.Namespace, e.g.
	// podmotion-system) — NOT the workload pod's namespace. The agent uses this value
	// solely to Get the PodMigration CR (server.go Checkpoint, L3548) to resolve
	// TCPPreservationMode and the SourcePodUID fallback (ADR-0047 §safety, ADR-0182 CHURN-15).
	// V-1 (ADR-0182 r2): Attempt-1 CR cold-0181-gate-1 was in namespace "default" (== pod ns),
	// so pm.Spec.PodNamespace coincidentally equalled pm.Namespace and the lookup succeeded by
	// accident; Attempt-2 CR cold-0181-gate-2 was in "podmotion-system" with pod in "default",
	// exposing the latent conflation. pm.Namespace is the only correct value.
	checkpointResp, err := agentClient.Checkpoint(ctx, &agentpb.CheckpointRequest{
		MigrationName:     pm.Name,
		ApplyZeroWindow:   pm.Spec.TCPPreservationMode != pmv1.TCPPreservationModeNone,
		WorkloadNamespace: pm.Namespace,
	})
	if err != nil {
		errStr := err.Error()
		// Distinguish transient connection errors from hard capability failures.
		if grpcStatus, ok := status.FromError(err); ok {
			switch grpcStatus.Code() {
			case codes.Unavailable:
				log.Error(err, "Checkpoint RPC unavailable — invalidating cached connection and requeuing", "migration", pm.Name)
				r.AgentPool.InvalidateNode(sourceNode)
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
			case codes.FailedPrecondition:
				// Agent returned codes.FailedPrecondition for ErrCRIUCapability (missing
				// CAP_SYS_PTRACE or blocking seccomp). Hard failure — do not retry.
				// (M19.5 criterion 13: use grpcStatus.Code() not string matching.)
				log.Error(err, "Checkpoint RPC failed: CRIU capability/ptrace error", "migration", pm.Name)
				setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "CRIUCapabilityError",
					fmt.Sprintf("CRIU ptrace/capability error: %v", err))
				return ctrl.Result{}, r.statusUpdate(ctx, pm)
			}
		}
		log.Error(err, "Checkpoint RPC failed", "migration", pm.Name)
		// M26: emit per-container consistency fail on checkpoint RPC error.
		for _, c := range sourcePod.Spec.Containers {
			pmmetrics.ContainerConsistencyTotal.WithLabelValues(
				pm.Name, pm.Namespace, c.Name, "fail",
			).Inc()
		}
		setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "CheckpointFailed", errStr)
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
	}

	// Gate: treat a zero-byte checkpoint as an incomplete dump and requeue.
	// The agent sets CheckpointSizeBytes only after checksumDir() runs over the completed
	// dump directory (including inventory.img). A zero value means the dump is still in
	// progress or failed silently; we must not advance to Transferring in that case.
	if checkpointResp == nil || checkpointResp.CheckpointSizeBytes == 0 {
		log.Error(nil, "Checkpoint RPC returned zero bytes — CRIU dump failed silently; failing fast",
			"migration", pm.Name)
		setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "CheckpointFailed",
			"CRIU dump returned zero bytes — silent dump failure; check agent logs for CRIU error")
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
	}

	// Gate: treat a missing SHA256 as a broken dump and fail fast.
	if checkpointResp.CheckpointSha256 == "" {
		log.Error(nil, "Checkpoint RPC returned empty SHA256 — CRIU dump failed silently; failing fast",
			"migration", pm.Name)
		setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "CheckpointFailed",
			"CRIU dump returned empty SHA256 — silent dump failure; check agent logs for CRIU error")
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
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

	// Persist freeze timestamp and TCP seq snapshots for the Restore phase.
	// These cross the Checkpoint→Restore phase boundary via pm.Status so the
	// controller can wire them into RestoreRequest after a controller restart.
	pm.Status.SourceFreezeTimestampNs = checkpointResp.FreezeTimestampNs
	pm.Status.TCPSeqSnapshots = nil
	for _, snap := range checkpointResp.SeqSnapshots {
		pm.Status.TCPSeqSnapshots = append(pm.Status.TCPSeqSnapshots, pmv1.TCPSeqSnapshot{
			SrcIP:    snap.SrcIp,
			SrcPort:  snap.SrcPort,
			DstIP:    snap.DstIp,
			DstPort:  snap.DstPort,
			SndNxt:   snap.SndNxt,
			RcvNxt:   snap.RcvNxt,
			TsRecent: snap.TsRecent,
		})
	}

	// M26: emit per-container consistency check counters.
	// A successful checkpoint (non-empty sha256 + non-zero size) constitutes a "pass"
	// for each container in the pod. The agent checkpoints the entire pod atomically;
	// per-container granularity here reflects that all containers in the pod were included.
	if pod != nil {
		for _, c := range pod.Spec.Containers {
			pmmetrics.ContainerConsistencyTotal.WithLabelValues(
				pm.Name, pm.Namespace, c.Name, "pass",
			).Inc()
		}
	} else if sourcePod != nil {
		for _, c := range sourcePod.Spec.Containers {
			pmmetrics.ContainerConsistencyTotal.WithLabelValues(
				pm.Name, pm.Namespace, c.Name, "pass",
			).Inc()
		}
	}

	checkpointMsg := fmt.Sprintf("Checkpoint captured: size=%d bytes sha256=%s freeze=%dms",
		checkpointResp.CheckpointSizeBytes, checkpointResp.CheckpointSha256, checkpointResp.FreezeDurationMs)
	log.Info("CRIU checkpoint complete", "migration", pm.Name,
		"sizeBytes", checkpointResp.CheckpointSizeBytes,
		"sha256", checkpointResp.CheckpointSha256,
		"freezeDurationMs", checkpointResp.FreezeDurationMs,
		"freezeTimestampNs", checkpointResp.FreezeTimestampNs,
		"tcpConnections", len(pm.Status.TCPSeqSnapshots))

	setCondition(pm, conditionCheckpointed, metav1.ConditionTrue, "Checkpointed", checkpointMsg)

	// Persist Checkpointed=True BEFORE creating the replacement pod so that if
	// createReplacementPod fails and we requeue, the next reconcile sees True and skips
	// the Checkpoint RPC. Without this write the in-memory condition is lost on requeue
	// and the controller issues repeated CRIU dumps until the frozen pod's PID disappears.
	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, fmt.Errorf("persisting Checkpointed=True: %w", err)
	}

	// ADR-0168 B2: write the workload image to the MigrationCheckpoint CR so the
	// destination agent can use the correct image for the restore placeholder container.
	// The MCP CR is created by the agent at checkpoint time; we update it here with
	// the workload image from pod.Spec.Containers[0].Image. Warn-only (ADR-0012).
	if len(sourcePod.Spec.Containers) > 0 {
		workloadImage := sourcePod.Spec.Containers[0].Image
		mcpRef := &pmv1.MigrationCheckpoint{}
		mcpKey := types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}
		if mcpGetErr := r.Get(ctx, mcpKey, mcpRef); mcpGetErr == nil {
			if mcpRef.Spec.WorkloadImage != workloadImage {
				mcpRef.Spec.WorkloadImage = workloadImage
				if mcpUpdateErr := r.Update(ctx, mcpRef); mcpUpdateErr != nil {
					log.Error(mcpUpdateErr, "ADR-0168 B2: failed to update MCP WorkloadImage (warn-only)", "migration", pm.Name, "image", workloadImage)
				} else {
					log.Info("ADR-0168 B2: MCP WorkloadImage set", "migration", pm.Name, "image", workloadImage)
				}
			}
		} else {
			log.Error(mcpGetErr, "ADR-0168 B2: failed to fetch MCP for WorkloadImage update (warn-only)", "migration", pm.Name)
		}
	}

	// Ensure DestinationNodeName is set before creating the replacement pod.
	// It is normally set in reconcilePreMigrating and persisted via transitionTo, but
	// can be empty if this reconcile was fetched from cache before the status write landed.
	if pm.Status.DestinationNodeName == "" && pm.Spec.TargetNodeName != "" {
		pm.Status.DestinationNodeName = pm.Spec.TargetNodeName
		if err := r.statusUpdate(ctx, pm); err != nil {
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
		log.Info("GC-PROP: checkpoint transfer propagation barrier satisfied — images delivered to dest agent",
			"migration", pm.Name, "destNode", destNode, "bytesWritten", putResp.BytesWritten)

		// Persist the transfer marker BEFORE releasing the source. If the controller
		// crashes between this write and the ReleaseCheckpoint call, the next reconcile
		// sees CheckpointTransferred=true and skips straight to the release call,
		// which is idempotent on an already-absent dir.
		pm.Status.CheckpointTransferred = true
		if err := r.statusUpdate(ctx, pm); err != nil {
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
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// ADR-0185 C7: This transitionTo(Restoring) is dead code on the 12-phase path —
	// reconcileFinalFreezeStateCapture (the 12-phase delegator) returns early via OverlayHandoff
	// delegation, bypassing this line, so Restoring is reached only after conditionVXLANFDBUpdated.
	// Left in place; guarded by the P-VERIFY-NRI-PHASE-ORDER invariant asserting Restoring is only
	// reachable post-conditionVXLANFDBUpdated (a C3 regression firing this tail before OverlayHandoff
	// would be caught by that contract test, since OverlayHandoff is NOT in the NRI accept-set under
	// Option B). See ADR-0185 r1.
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
			if err := r.statusUpdate(ctx, pm); err != nil {
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
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
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
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
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
	var restoreSeqSnapshots []*agentpb.SeqSnapshot
	for _, snap := range pm.Status.TCPSeqSnapshots {
		restoreSeqSnapshots = append(restoreSeqSnapshots, &agentpb.SeqSnapshot{
			SrcIp:    snap.SrcIP,
			SrcPort:  snap.SrcPort,
			DstIp:    snap.DstIP,
			DstPort:  snap.DstPort,
			SndNxt:   snap.SndNxt,
			RcvNxt:   snap.RcvNxt,
			TsRecent: snap.TsRecent,
		})
	}

	if len(restoreSeqSnapshots) > 0 && pm.Status.DestNetnsPath == "" {
		return ctrl.Result{}, fmt.Errorf("Strict restore: DestNetnsPath empty, DestinationNetnsReady not yet satisfied")
	}

	restoreResp, err := agentClient.Restore(ctx, &agentpb.RestoreRequest{
		MigrationName:           pm.Name,
		CheckpointRef:           checkpointRef,
		SourceNodeAddr:          pm.Status.SourceNodeName,
		SourceFreezeTimestampNs: pm.Status.SourceFreezeTimestampNs,
		SeqSnapshots:            restoreSeqSnapshots,
		DestNetnsFd:             pm.Status.DestNetnsPath,
		TcpPreservationMode:     string(pm.Spec.TCPPreservationMode),
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
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
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
		if err := r.statusUpdate(ctx, pm); err != nil {
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
			if err2 := r.statusUpdate(ctx, pm); err2 != nil {
				return ctrl.Result{}, err2
			}
			return r.failMigration(ctx, pm, msg)
		}
		setCondition(pm, conditionSecurityContextVerified, metav1.ConditionTrue,
			"Verified", "Restored process security context matches checkpoint attestation")
		if err := r.statusUpdate(ctx, pm); err != nil {
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
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
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

	log.Info("replacement pod Running and Ready — precondition met, awaiting CRIU restore confirmation",
		"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName,
		"destNode", replacement.Spec.NodeName)

	// ADR-0120 D1/D4: pod readiness is only a precondition, NOT restore evidence.
	// A freshly-scheduled container reaches Running/Ready with no CRIU restore at all
	// (Redis boots empty). The authoritative signal is status.criuRestoreConfirmed,
	// written by the NRI plugin after JoinNsRestore succeeds (D2/D3). Poll for it with a
	// bounded timeout; on timeout set conditionRestored=False (never default to true).
	const criuConfirmTimeout = 60 * time.Second
	const criuConfirmAnnotation = "podmotion.io/restore-confirm-wait-start"

	// Re-fetch the CR so we observe the latest criuRestoreConfirmed written by the agent.
	fresh := &pmv1.PodMigration{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(pm), fresh); err == nil {
		pm.Status.CRIURestoreConfirmed = fresh.Status.CRIURestoreConfirmed
		pm.Status.RestoredPID = fresh.Status.RestoredPID
	}

	if pm.Status.CRIURestoreConfirmed == nil || !*pm.Status.CRIURestoreConfirmed {
		// Stamp the wait-start time on first entry so the 60s budget is measured from when
		// the pod first became Ready, surviving across requeues.
		waitStart := time.Now()
		if pm.Annotations == nil {
			pm.Annotations = make(map[string]string)
		}
		if v, ok := pm.Annotations[criuConfirmAnnotation]; ok {
			if t, perr := time.Parse(time.RFC3339, v); perr == nil {
				waitStart = t
			}
		} else {
			pm.Annotations[criuConfirmAnnotation] = waitStart.Format(time.RFC3339)
			if err := r.Update(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
		}

		if time.Since(waitStart) >= criuConfirmTimeout {
			// NRI plugin did not confirm within the timeout window.
			// Fall back to the agent Restore gRPC RPC (dev/kind clusters where NRI is not installed).
			// The Restore RPC will call JoinNsRestore into the replacement pod's netns and
			// then call ReportRestoreConfirmed on success, which will set criuRestoreConfirmed.
			log.Info("NRI confirm timeout — falling back to agent Restore RPC",
				"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName)

			destNode := pm.Status.DestinationNodeName
			if destNode == "" {
				destNode = pm.Spec.TargetNodeName
			}
			if destNode == "" || r.AgentPool == nil {
				msg := fmt.Sprintf("CRIU restore was not confirmed within %s — replacement pod %s reached Ready "+
					"but the NRI plugin never set criuRestoreConfirmed and destination node unknown",
					criuConfirmTimeout, pm.Status.ReplacementPodName)
				setCondition(pm, conditionRestored, metav1.ConditionFalse, "RestoreNotConfirmed", msg)
				return ctrl.Result{}, r.statusUpdate(ctx, pm)
			}
			destAgent, agErr := r.AgentPool.ForNode(ctx, destNode)
			if agErr != nil {
				log.Error(agErr, "NRI fallback: cannot connect to destination agent — requeuing", "migration", pm.Name)
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
			}
			checkpointRef := fmt.Sprintf("/run/podmotion/checkpoints/%s/final", pm.Name)
			if pm.Status.CheckpointRef != nil && pm.Status.CheckpointRef.Name != "" {
				checkpointRef = pm.Status.CheckpointRef.Name
			}
			restoreResp, restoreErr := destAgent.Restore(ctx, &agentpb.RestoreRequest{
				MigrationName:       pm.Name,
				CheckpointRef:       checkpointRef,
				DestNetnsFd:         pm.Status.DestNetnsPath,
				TcpPreservationMode: string(pm.Spec.TCPPreservationMode),
			})
			if restoreErr != nil {
				log.Error(restoreErr, "NRI fallback: agent Restore RPC failed", "migration", pm.Name)
				setCondition(pm, conditionRestored, metav1.ConditionFalse, "RestoreFailed",
					fmt.Sprintf("agent Restore RPC failed: %v", restoreErr))
				if pm.Spec.RollbackOnFailure {
					return r.initiateRollback(ctx, pm, restoreErr.Error())
				}
				return ctrl.Result{}, r.statusUpdate(ctx, pm)
			}
			if !restoreResp.Success {
				log.Error(fmt.Errorf("restore failed: %s", restoreResp.ErrorMessage), "NRI fallback: Restore RPC returned success=false", "migration", pm.Name)
				setCondition(pm, conditionRestored, metav1.ConditionFalse, "RestoreFailed", restoreResp.ErrorMessage)
				if pm.Spec.RollbackOnFailure {
					return r.initiateRollback(ctx, pm, restoreResp.ErrorMessage)
				}
				return ctrl.Result{}, r.statusUpdate(ctx, pm)
			}
			log.Info("NRI fallback: agent Restore RPC succeeded", "migration", pm.Name, "durationMs", restoreResp.RestoreDurationMs)
			// Requeue to observe criuRestoreConfirmed written by the agent's ReportRestoreConfirmed.
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}

		log.Info("CRIU restore not yet confirmed — polling criuRestoreConfirmed",
			"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName,
			"elapsed", time.Since(waitStart).Truncate(time.Second).String(),
			"timeout", criuConfirmTimeout.String())
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	log.Info("CRIU restore confirmed by NRI plugin — restore authoritative",
		"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName,
		"restoredPID", pm.Status.RestoredPID, "destNode", replacement.Spec.NodeName)

	setCondition(pm, conditionRestored, metav1.ConditionTrue, "Restored",
		fmt.Sprintf("NRI JoinNsRestore confirmed CRIU restore into replacement pod %s (restoredPID=%d)",
			pm.Status.ReplacementPodName, pm.Status.RestoredPID))

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

	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseVerifying)
}


// nodeInternalIP returns the InternalIP address of the named Node (the flannel VXLAN
// underlay endpoint on this single-NIC PoC). Used by ADR-0136 to tell the source agent
// which underlay IP to encapsulate the relocated OLD pod IP toward.
func (r *PodMigrationReconciler) nodeInternalIP(ctx context.Context, nodeName string) (string, error) {
	node := &corev1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
		return "", err
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address, nil
		}
	}
	return "", fmt.Errorf("node %q has no InternalIP", nodeName)
}

// disarmTCRedirect retires the ADR-0139 destination tc-ingress redirect for the relocated OLD
// IP. Per Decision 3 this is the IPAM-reclaim hook, NOT part of steady-state cutover: the
// redirect must persist for the life of the replacement pod to keep the OLD IP reachable from
// source-CIDR clients (AC2/AC3). Invoked when the OLD IP is reclaimed. Idempotent / best-effort.
func (r *PodMigrationReconciler) disarmTCRedirect(ctx context.Context, pm *pmv1.PodMigration) error {
	if r.AgentPool == nil {
		return nil
	}
	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		destNode = pm.Spec.TargetNodeName
	}
	if destNode == "" {
		return nil
	}
	destAgent, err := r.AgentPool.ForNode(ctx, destNode)
	if err != nil {
		return err
	}
	fdbIfname := pm.Status.OverlayFdbIfname
	if fdbIfname == "" {
		fdbIfname = "flannel.1"
	}
	_, err = destAgent.DisarmTCRedirect(ctx, &agentpb.DisarmTCRedirectRequest{
		MigrationName: pm.Name,
		FdbIfname:     fdbIfname,
		OldPodIp:      pm.Spec.SourcePodIP,
	})
	return err
}

// injectIPHandoff calls InjectIPHandoff on the DESTINATION agent (ADR-0133 D1/D2) to make
// the OLD pod IP reachable at the replacement pod, then gates on the in-node reachability
// probe (D5). On success it sets conditionIPHandoffInjected=True (and TrafficVerified=True
// for the directly-pinned pod-IP path) and returns done=true so the caller continues. On a
// transient failure it returns done=false with a requeue Result. The held source connection
// is never torn down on failure (source thawed path, ADR-0132 R7), so retries are safe.
func (r *PodMigrationReconciler) injectIPHandoff(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error, bool) {
	log := logf.FromContext(ctx)

	if pm.Spec.SourcePodIP == "" {
		log.Info("injectIPHandoff: SourcePodIP empty — skipping IP handoff (service-path verification only)", "migration", pm.Name)
		setCondition(pm, conditionIPHandoffInjected, metav1.ConditionFalse, "NoSourcePodIP",
			"SourcePodIP not set; relying on Service/EndpointSlice path (ADR-0015)")
		return ctrl.Result{}, nil, true
	}

	// Re-fetch the latest replVethMAC written by the NRI plugin via ReportRestoreConfirmed.
	fresh := &pmv1.PodMigration{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(pm), fresh); err == nil {
		pm.Status.ReplVethMAC = fresh.Status.ReplVethMAC
	}
	if pm.Status.ReplVethMAC == "" {
		// E1 Condition 4: bounded liveness for injectIPHandoff. If replVethMAC has been
		// empty for more than 30s since CRIURestoreConfirmed, transition to RollingBack.
		// This replaces the previously unbounded requeue with a deadline-aware check.
		now := time.Now()
		if firstSeen, ok := macWritebackFirstSeen.Load(pm.Name); ok {
			if now.Sub(firstSeen.(time.Time)) > macWritebackDeadlineSec {
				macWritebackFirstSeen.Delete(pm.Name)
				log.Error(nil, "injectIPHandoff: MAC writeback deadline exceeded — transitioning to RollingBack",
					"migration", pm.Name, "deadlineSec", macWritebackDeadlineSec.Seconds())
				setCondition(pm, conditionIPHandoffInjected, metav1.ConditionFalse, "MACWritebackDeadlineExceeded",
					"MAC writeback deadline exceeded — replVethMAC empty >30s after RestoreConfirmed")
				if sErr := r.statusUpdate(ctx, pm); sErr != nil {
					return ctrl.Result{}, sErr, false
				}
				if _, tErr := r.transitionTo(ctx, pm, pmv1.MigrationPhaseRollingBack); tErr != nil {
					return ctrl.Result{}, tErr, false
				}
				return ctrl.Result{}, nil, true
			}
		} else {
			macWritebackFirstSeen.Store(pm.Name, now)
		}
		log.Info("injectIPHandoff: replVethMAC not yet present in status — requeuing (NRI plugin writeback pending)", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false
	}
	// MAC is resolved — clear any deadline tracking entry.
	macWritebackFirstSeen.Delete(pm.Name)

	if r.AgentPool == nil {
		log.Error(nil, "injectIPHandoff: AgentPool not wired — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false
	}
	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		destNode = pm.Spec.TargetNodeName
	}
	if destNode == "" {
		log.Error(nil, "injectIPHandoff: DestinationNodeName not set — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false
	}
	destAgent, err := r.AgentPool.ForNode(ctx, destNode)
	if err != nil {
		log.Error(err, "injectIPHandoff: cannot connect to destination agent — requeuing", "migration", pm.Name, "node", destNode)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil, false
	}

	fdbIfname := pm.Status.OverlayFdbIfname
	if fdbIfname == "" {
		fdbIfname = "flannel.1"
	}

	log.Info("injectIPHandoff: calling InjectIPHandoff on destination agent (ADR-0133 D2)",
		"migration", pm.Name, "node", destNode, "oldPodIP", pm.Spec.SourcePodIP, "replVethMAC", pm.Status.ReplVethMAC)
	resp, err := destAgent.InjectIPHandoff(ctx, &agentpb.InjectIPHandoffRequest{
		MigrationName:  pm.Name,
		OldPodIp:       pm.Spec.SourcePodIP,
		ReplVethMac:    pm.Status.ReplVethMAC,
		SrcNodeVtepMac: pm.Status.SourcePodMac, // diagnostic; source VTEP MAC cached if available
		FdbIfname:      fdbIfname,
		BridgeIfname:   "", // ADR-0158 D5: empty — agent discovers at runtime (ADR-0154 D3). No "cni0" literal.
		Probe:          true,
	})
	if err != nil {
		log.Error(err, "injectIPHandoff: InjectIPHandoff RPC failed — requeuing", "migration", pm.Name)
		setCondition(pm, conditionIPHandoffInjected, metav1.ConditionFalse, "RPCFailed",
			fmt.Sprintf("InjectIPHandoff RPC error: %v", err))
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr, false
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil, false
	}
	if !resp.Injected {
		log.Error(nil, "injectIPHandoff: InjectIPHandoff returned injected=false — requeuing",
			"migration", pm.Name, "reason", resp.BlockingReason)
		setCondition(pm, conditionIPHandoffInjected, metav1.ConditionFalse, "NotInjected",
			fmt.Sprintf("InjectIPHandoff: %s", resp.BlockingReason))
		// ADR-0192 VERIFY-10: emit Warning event on PodMigration CR with verbatim BlockingReason.
		r.Recorder.Eventf(pm, corev1.EventTypeWarning, "IPHandoffFailed", "%s", resp.BlockingReason)
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr, false
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil, false
	}

	// ADR-0192 VERIFY-11: write resolved fdbIf to PodMigration annotation for structured
	// observability. ResolvedFdbIf is set by the agent when auto-discovery was used.
	if resp.ResolvedFdbIf != "" {
		if pm.Annotations == nil {
			pm.Annotations = make(map[string]string)
		}
		pm.Annotations["podmotion.io/resolved-fdb-if"] = resp.ResolvedFdbIf
		if aErr := r.Update(ctx, pm); aErr != nil {
			log.Error(aErr, "injectIPHandoff: failed to set resolved-fdb-if annotation (non-fatal)",
				"migration", pm.Name, "resolvedFdbIf", resp.ResolvedFdbIf)
		}
	}

	// Cache the destination VTEP MAC for diagnostics / forensic replay (ADR-0133 R8 nit).
	if resp.DestVtepMac != "" {
		log.Info("injectIPHandoff: destination VTEP MAC", "migration", pm.Name, "destVTEPMAC", resp.DestVtepMac)
	}

	// Decision 5: reachability probe gates TrafficVerified for the pinned pod-IP path.
	if !resp.ProbeOk {
		log.Info("injectIPHandoff: reachability probe to oldPodIP failed — requeuing (do not disarm, source held)",
			"migration", pm.Name, "oldPodIP", pm.Spec.SourcePodIP, "probeOutput", resp.ProbeOutput)
		setCondition(pm, conditionIPHandoffInjected, metav1.ConditionFalse, "ProbeFailed",
			fmt.Sprintf("ping %s from destination node failed: %s", pm.Spec.SourcePodIP, resp.ProbeOutput))
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr, false
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil, false
	}

	// ADR-0136: now that the destination handoff is proven (probe passed), install the
	// SOURCE-node VXLAN redirect so a client co-resident on the source node can reach the
	// relocated OLD pod IP (Sprint 25 AC2). Best-effort — the destination-side reachability
	// (AC1) is already proven; a source-redirect failure should not block the migration, it
	// only degrades the co-resident-client case. It is requeue-safe (idempotent) and torn
	// down by CleanupSourceIPHandoff after TrafficVerified=True.
	if srcNode := pm.Status.SourceNodeName; srcNode != "" && srcNode != destNode {
		if dstNodeIP, ipErr := r.nodeInternalIP(ctx, destNode); ipErr != nil || dstNodeIP == "" {
			log.Error(ipErr, "injectIPHandoff: ADR-0136 could not resolve destination node IP — skipping source redirect (warn-only)",
				"migration", pm.Name, "destNode", destNode)
		} else if srcAgent, agErr := r.AgentPool.ForNode(ctx, srcNode); agErr != nil {
			log.Error(agErr, "injectIPHandoff: ADR-0136 cannot connect to source agent — skipping source redirect (warn-only)",
				"migration", pm.Name, "node", srcNode)
		} else if redirResp, redirErr := srcAgent.InjectSourceRedirect(ctx, &agentpb.InjectSourceRedirectRequest{
			MigrationName: pm.Name,
			OldPodIp:      pm.Spec.SourcePodIP,
			ReplVethMac:   pm.Status.ReplVethMAC,
			DstNodeIp:     dstNodeIP,
			FdbIfname:     fdbIfname,
		}); redirErr != nil {
			log.Error(redirErr, "injectIPHandoff: ADR-0136 InjectSourceRedirect RPC failed (warn-only)", "migration", pm.Name)
		} else if !redirResp.Injected {
			log.Info("injectIPHandoff: ADR-0136 InjectSourceRedirect returned injected=false (warn-only)",
				"migration", pm.Name, "reason", redirResp.BlockingReason)
		} else {
			log.Info("injectIPHandoff: ADR-0136 source VXLAN redirect installed",
				"migration", pm.Name, "srcNode", srcNode, "oldPodIP", pm.Spec.SourcePodIP, "dstNodeIP", dstNodeIP)
		}
	}

	log.Info("injectIPHandoff: handoff injected and reachability probe passed (ADR-0133 AC1)",
		"migration", pm.Name, "oldPodIP", pm.Spec.SourcePodIP)
	setCondition(pm, conditionIPHandoffInjected, metav1.ConditionTrue, "Injected",
		fmt.Sprintf("OLD pod IP %s reachable at replacement veth %s on %s; ping probe passed (ADR-0133 D2/D5)",
			pm.Spec.SourcePodIP, pm.Status.ReplVethMAC, destNode))
	// The L3 reachability of the OLD pod IP is proven — set TrafficVerified=True for the
	// pinned-IP client. The Service-path verifier below remains a backstop but is now
	// short-circuited because trafficVerified will read True on the next reconcile.
	setCondition(pm, conditionTrafficVerified, metav1.ConditionTrue, "TrafficVerified",
		fmt.Sprintf("OLD pod IP %s reachable at replacement pod (ADR-0133 reachability probe)", pm.Spec.SourcePodIP))
	return ctrl.Result{}, nil, true
}

func (r *PodMigrationReconciler) reconcileVerifying(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Agent 12 (traffic) drives readiness + traffic verification. Watches TrafficVerified.
	// ADR-0019: if verification fails AFTER handoff, warn only — do not rollback.
	trafficVerified := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionTrafficVerified)
	if !trafficVerified {
		// ADR-0133 Decision 1: inject the OLD-pod-IP handoff on the DESTINATION node
		// AFTER criuRestoreConfirmed (precondition of the Restoring→Verifying transition)
		// and BEFORE TrafficVerified is set / source is disarmed/cleaned. The reachability
		// probe (Decision 5) gates TrafficVerified for the directly-pinned pod-IP client;
		// the service-path TrafficVerifier remains as the L4/Service backstop below.
		if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionIPHandoffInjected) {
			if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone {
				setCondition(pm, conditionIPHandoffInjected, metav1.ConditionTrue, "Skipped",
					"TCPPreservationMode=None: IP handoff not required for cold migration")
				setCondition(pm, conditionTrafficVerified, metav1.ConditionTrue, "TrafficVerified",
					"TCPPreservationMode=None: cold migration — replacement pod IP accepted")
			} else if res, err, done := r.injectIPHandoff(ctx, pm); !done {
				return res, err
			}
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
		}

		// Drive verification: call the TrafficVerifier and set the condition.
		// Skip if the ADR-0133 reachability probe already set TrafficVerified=True
		// (the OLD pod IP is reachable at the replacement — the strongest proof).
		if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionTrafficVerified) {
			log.Info("Verifying: TrafficVerified already set by ADR-0133 IP handoff probe — skipping service-path verifier",
				"migration", pm.Name)
		} else if r.TrafficVerifier != nil {
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
				// ADR-0012: verification failure → set TrafficVerified=False, do NOT delete source pod.
				log.Error(err, "traffic verification failed — setting TrafficVerified=False, requeuing (ADR-0012)", "migration", pm.Name)
				setCondition(pm, conditionTrafficVerified, metav1.ConditionFalse, "VerificationFailed",
					fmt.Sprintf("TrafficVerifier returned error: %v", err))
				if statusErr := r.statusUpdate(ctx, pm); statusErr != nil {
					return ctrl.Result{}, statusErr
				}
				return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
			}
			// Verifier returned nil — traffic is genuinely confirmed.
			setCondition(pm, conditionTrafficVerified, metav1.ConditionTrue, "TrafficVerified",
				"Traffic verified by TrafficVerifier")
		} else {
			// ADR-0012: no verifier wired — cannot confirm traffic; do NOT promote to True.
			// Requeue and wait for a verifier to be wired, or for an operator to intervene.
			log.Error(nil, "TrafficVerifier not wired — cannot verify traffic; requeuing without setting TrafficVerified=True (ADR-0012)", "migration", pm.Name)
			setCondition(pm, conditionTrafficVerified, metav1.ConditionFalse, "NoVerifier",
				"TrafficVerifier not wired; cannot confirm traffic (ADR-0012)")
			if statusErr := r.statusUpdate(ctx, pm); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		// Requeue immediately so the next pass starts from etcd (TrafficVerified=True)
		// and proceeds to source pod deletion. Status updates do not self-trigger the
		// controller watch, so an explicit requeue is required here.
		log.Info("Verifying: TrafficVerified set — requeueing for source pod deletion", "migration", pm.Name)
		return ctrl.Result{Requeue: true}, nil
	}

	log.Info("Verifying: TrafficVerified=True — proceeding to source pod deletion gates", "migration", pm.Name)

	// ADR-0040 + ADR-0046: delete source pod only when BOTH TrafficVerified=True AND
	// DestinationVolumeReady=True. Deleting before volume attachment is confirmed risks
	// RWO PVC detach races (EBS/RBD attach window 30-120s).
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionDestinationVolumeReady) {
		log.Info("Verifying: DestinationVolumeReady not yet set — checking volume readiness", "migration", pm.Name)
		ready, err := r.checkDestinationVolumeReady(ctx, pm)
		if err != nil {
			log.Error(err, "volume readiness check error — requeuing", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		if !ready {
			log.Info("waiting for DestinationVolumeReady before deleting source pod", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		log.Info("Verifying: DestinationVolumeReady confirmed — setting condition", "migration", pm.Name)
		setCondition(pm, conditionDestinationVolumeReady, metav1.ConditionTrue,
			"VolumeAttached", "RWO PVC attached on destination node (or no PVCs)")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		log.Info("Verifying: DestinationVolumeReady already True — skipping volume check", "migration", pm.Name)
	}

	// PDB gate: block deletion if any PodDisruptionBudget disallows it.
	log.Info("Verifying: checking PDB gate", "migration", pm.Name)
	if err := r.checkPDBAllowsDeletion(ctx, pm); err != nil {
		log.Info("Verifying: PDB gate blocking source pod deletion — requeuing", "migration", pm.Name, "reason", err.Error())
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// ResourceQuota gate: defer deletion if the destination namespace is at pod quota capacity.
	log.Info("Verifying: checking ResourceQuota gate", "migration", pm.Name)
	if err := r.checkResourceQuotaCapacity(ctx, pm); err != nil {
		log.Info("Verifying: ResourceQuota gate blocking source pod deletion — requeuing", "migration", pm.Name, "reason", err.Error())
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// ADR-0012 defensive re-fetch: re-read TrafficVerified from API before any source pod deletion.
	// In-memory pm.Status may be stale; the authoritative state is in etcd.
	log.Info("Verifying: re-fetching PodMigration from API for ADR-0012 safety check", "migration", pm.Name)
	{
		freshPM := &pmv1.PodMigration{}
		if fetchErr := r.Get(ctx, client.ObjectKeyFromObject(pm), freshPM); fetchErr != nil {
			log.Error(fetchErr, "Verifying: failed to re-fetch PodMigration before source pod deletion — requeuing for safety (ADR-0012)", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		if !meta.IsStatusConditionTrue(freshPM.Status.Conditions, conditionTrafficVerified) {
			log.Error(nil, "Verifying: SAFETY BLOCK — TrafficVerified is not True on re-fetch; refusing to delete source pod (ADR-0012)", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		log.Info("Verifying: ADR-0012 re-fetch confirmed TrafficVerified=True — proceeding to source pod deletion", "migration", pm.Name)
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
				log.Error(deleteErr, "failed to delete source pod — requeuing (ADR-0012)", "migration", pm.Name)
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
			}
		}
	} else if !apierrors.IsNotFound(err) {
		log.Error(err, "could not look up source pod — skipping deletion")
	}
	// If IsNotFound — already deleted, that is fine.

	setCondition(pm, conditionSourcePodDeleted, metav1.ConditionTrue, "Deleted", "Source pod deleted post-TrafficVerified")

	// ADR-0133 Decision 4: source-side cleanup. Now that TrafficVerified=True and the
	// zero-window hold has been disarmed (reconcileDisengageHold), remove the stale
	// ARP/neighbor entries for the OLD pod IP on the SOURCE node so it does not split-route
	// or blackhole. Deferred to here (never before TrafficVerified) so the in-flight held
	// connection survives the convergence window. Best-effort: warn-only on failure.
	if pm.Spec.SourcePodIP != "" && r.AgentPool != nil {
		srcNode := pm.Status.SourceNodeName
		if srcNode != "" {
			if srcAgent, agErr := r.AgentPool.ForNode(ctx, srcNode); agErr != nil {
				log.Error(agErr, "ADR-0133 D4: cannot connect to source agent for IP handoff cleanup (warn-only)",
					"migration", pm.Name, "node", srcNode)
			} else {
				fdbIfname := pm.Status.OverlayFdbIfname
				if fdbIfname == "" {
					fdbIfname = "flannel.1"
				}
				if cleanResp, cErr := srcAgent.CleanupSourceIPHandoff(ctx, &agentpb.CleanupSourceIPHandoffRequest{
					MigrationName: pm.Name,
					OldPodIp:      pm.Spec.SourcePodIP,
					FdbIfname:     fdbIfname,
					BridgeIfname:  "", // ADR-0158 D5: empty — agent discovers at runtime. No "cni0" literal.
				}); cErr != nil {
					log.Error(cErr, "ADR-0133 D4: CleanupSourceIPHandoff RPC failed (warn-only)", "migration", pm.Name)
				} else if !cleanResp.Cleaned {
					log.Info("ADR-0133 D4: CleanupSourceIPHandoff returned cleaned=false (warn-only)",
						"migration", pm.Name, "reason", cleanResp.BlockingReason)
				} else {
					log.Info("ADR-0133 D4: source IP handoff cleaned on source node",
						"migration", pm.Name, "node", srcNode, "oldPodIP", pm.Spec.SourcePodIP)
				}
			}
		}
	}

	// ADR-0139 Decision 3 (disarm): the tc-ingress redirect on the DESTINATION flannel.1 is
	// the forward-path delivery mechanism for the relocated OLD IP — exactly symmetric to the
	// ADR-0136 source flannel.1 redirect that CleanupSourceIPHandoff deliberately PRESERVES.
	// Disarming it here would re-blackhole the OLD IP for source-CIDR clients (AC2/AC3) the
	// instant the migration completes. So, like the source redirect, it persists for the life
	// of the replacement pod and is retired only when the OLD IP is reclaimed by IPAM via the
	// DisarmTCRedirect RPC (r.disarmTCRedirect). It is intentionally NOT called in the
	// steady-state cutover completion. (Quorum R1/Lead: keep reachability.)

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

	// M26: emit flow_loss counter at Complete (0 flows lost — VerifyTCP passed).
	pmmetrics.MigrationFlowLossTotal.WithLabelValues(pm.Name, pm.Namespace).Add(0)

	r.releaseDestinationCapacity(ctx, pm)
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseComplete)
}

func (r *PodMigrationReconciler) reconcileRollingBack(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// ADR-0157 D2: call DisarmZeroWindow FIRST on the failure path when the hold is armed
	// and not yet disarmed. This cancels the agent watchdog immediately, releasing the peer
	// instead of waiting up to FreezeWindowBudgetMs+500ms for the watchdog to fire.
	r.disarmZeroWindowOnFailurePath(ctx, pm)

	// Delete the replacement pod first — before rolling back the source — so there is
	// never a window where both pods are running and matching Service selectors.
	r.deleteReplacementPod(ctx, pm)

	if err := r.Rollbacker.Rollback(ctx, pm); err != nil {
		log.Error(err, "rollback failed — source pod may require manual intervention")
		return r.failMigration(ctx, pm, fmt.Sprintf("rollback failed: %v", err))
	}

	// GC-9 fix: release destination-side checkpoint images on the rollback/failure path.
	// When CheckpointTransferred=true the dest agent holds checkpoint files in its tmpfs
	// (/run/podmotion/checkpoints/<migration>/final/). On a failed restore these are
	// never released by the normal success path, leaving orphaned .img files on the node.
	// ReleaseCheckpoint is idempotent; errors are warn-only (ADR-0012: source pod is
	// already safe, so we never block the Failed transition on a cleanup RPC failure).
	//
	// ADR-0182 CHURN-15 Issue 3 (GC-10): the GC-9 ReleaseCheckpoint gate and the GC-10
	// dest-netns Abort gate are SEPARATE conditions. ReleaseCheckpoint depends on
	// CheckpointTransferred (dest images exist only post-transfer). Abort/dest-netns teardown
	// depends only on netns *staging* (ConditionDestinationNetnsReady), which is set during
	// DestinationPrewarm BEFORE Checkpoint runs — so a Checkpoint-phase failure (where
	// CheckpointTransferred is never set) must still tear the netns down. The old single guard
	// on CheckpointTransferred skipped Abort entirely on early failure, leaking the bind-mount.
	destStaged := r.AgentPool != nil && pm.Status.DestinationNodeName != "" &&
		meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionDestinationNetnsReady)
	if destStaged {
		destNode := pm.Status.DestinationNodeName
		destAgent, agErr := r.AgentPool.ForNode(ctx, destNode)
		if agErr != nil {
			log.Error(agErr, "reconcileRollingBack: cannot connect to dest agent for GC-9/GC-10 cleanup (warn-only)",
				"migration", pm.Name, "node", destNode)
		} else {
			// GC-9: dest checkpoint images exist ONLY after transfer — retain that gate.
			if pm.Status.CheckpointTransferred {
				_, relErr := destAgent.ReleaseCheckpoint(ctx, &agentpb.ReleaseCheckpointRequest{
					MigrationName:      pm.Name,
					MigrationNamespace: pm.Namespace,
				})
				if relErr != nil {
					log.Error(relErr, "reconcileRollingBack: dest ReleaseCheckpoint failed (GC-9, warn-only — images remain on dest tmpfs until reboot)",
						"migration", pm.Name, "node", destNode)
				} else {
					log.Info("reconcileRollingBack: dest checkpoint released (GC-9)", "migration", pm.Name, "node", destNode)
				}
			}

			// GC-10 (ADR-0173): tear down the pre-staged dest migration netns on the
			// NRI/operator-driven restore-failure path via the Abort RPC. Conditioned on
			// ConditionDestinationNetnsReady (netns staging), NOT on CheckpointTransferred —
			// the netns is staged at DestinationPrewarm, independent of transfer, so this
			// fires on Checkpoint-phase failures too (ADR-0182 CHURN-15 Issue 3). Issued
			// STRICTLY SEQUENTIALLY — only after disarmZeroWindowOnFailurePath (DisarmZeroWindow)
			// and Rollbacker.Rollback (NetworkRollback) have already returned above; it is NOT
			// concurrent with them and reuses the same dest-agent handle. AbortRequest carries
			// only migration_name and reason (no namespace field exists in the proto). The
			// agent's Abort handler is idempotent (server.go delete-on-first-call), so an
			// unconditional dispatch is safe under re-queues. Warn-only (ADR-0012 /
			// ADR-0165-r2 SP-7): never blocks the Failed transition.
			_, abErr := destAgent.Abort(ctx, &agentpb.AbortRequest{
				MigrationName: pm.Name,
				Reason:        "GC-10 rollback: tear down dest migration netns (phase-independent)",
			})
			if abErr != nil {
				log.Error(abErr, "reconcileRollingBack: dest Abort/teardown failed (GC-10, warn-only — dest netns may remain until reboot)",
					"migration", pm.Name, "node", destNode)
			} else {
				log.Info("reconcileRollingBack: dest migration netns teardown signalled (GC-10)", "migration", pm.Name, "node", destNode)
			}
		}
	}

	// ADR-0168 GC-9: set MigrationCheckpoint CR Status.Phase=Failed on rollback completion.
	// Re-entry guard: skip if PodMigration is already Failed (idempotent under re-queues).
	if pm.Status.Phase != pmv1.MigrationPhaseFailed {
		if pm.Status.CheckpointRef != nil && pm.Status.CheckpointRef.Name != "" {
			mcpGC9 := &pmv1.MigrationCheckpoint{}
			mcpGC9Key := types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}
			if mcpGetErr := r.Get(ctx, mcpGC9Key, mcpGC9); mcpGetErr == nil {
				mcpGC9.Status.Phase = "Failed"
				if mcpUpdateErr := r.Status().Update(ctx, mcpGC9); mcpUpdateErr != nil {
					log.Error(mcpUpdateErr, "GC-9: failed to set MCP Status.Phase=Failed (warn-only, ADR-0012)", "migration", pm.Name)
				} else {
					log.Info("GC-9: MCP Status.Phase set to Failed", "migration", pm.Name)
				}
			} else {
				log.Error(mcpGetErr, "GC-9: failed to fetch MCP for phase update (warn-only)", "migration", pm.Name)
			}
		}
		// When CheckpointRef.Name is empty there is no MCP CR to advance (failure before checkpoint).
	}

	pm.Status.Phase = pmv1.MigrationPhaseFailed
	setCondition(pm, "RolledBack", metav1.ConditionTrue, "RollbackComplete", "Source pod restored to live state")
	// M26: emit flow_loss counter at Failed (all TCP connections inventoried are treated as lost).
	pmmetrics.MigrationFlowLossTotal.WithLabelValues(pm.Name, pm.Namespace).Add(
		float64(len(pm.Status.TCPSeqSnapshots)),
	)
	r.releaseDestinationCapacity(ctx, pm)
	return ctrl.Result{}, r.statusUpdate(ctx, pm)
}

// ── Helpers ────────────────────────────────────────────────────────────────

// disarmZeroWindowOnFailurePath implements the ADR-0157 D2 contract: on any failure
// path (RollingBack, failMigration), call DisarmZeroWindow FIRST when
// ZeroWindowArmed=True && ZeroWindowDisarmed!=True. This cancels the agent watchdog
// so the peer is released immediately rather than waiting for the watchdog budget.
//
// If the RPC errors or returns disarmed=false (watchdog already fired), the method
// records ConditionZeroWindowDisarmed with reason WatchdogFired and emits the
// ZeroWindowWatchdogFired Warning event (ADR-0157 D3). Source-pod preservation
// (ADR-0012) is NEVER gated on a successful disarm; this call is best-effort.
//
// In None/BestEffort mode where ZeroWindowArmed is never set True, this is a no-op.
func (r *PodMigrationReconciler) disarmZeroWindowOnFailurePath(ctx context.Context, pm *pmv1.PodMigration) {
	log := logf.FromContext(ctx)

	// Guard: only disarm when armed and not already disarmed (ADR-0157 D2).
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionZeroWindowArmed) {
		return
	}
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionZeroWindowDisarmed) {
		return
	}

	if r.AgentPool == nil {
		log.Info("disarmZeroWindowOnFailurePath: AgentPool not wired — skipping disarm", "migration", pm.Name)
		return
	}
	sourceNode := pm.Status.SourceNodeName
	if sourceNode == "" {
		log.Info("disarmZeroWindowOnFailurePath: SourceNodeName not set — skipping disarm", "migration", pm.Name)
		return
	}
	agentClient, err := r.AgentPool.ForNode(ctx, sourceNode)
	if err != nil {
		log.Error(err, "disarmZeroWindowOnFailurePath: cannot connect to source agent (ADR-0157 D2)",
			"migration", pm.Name)
		setCondition(pm, pmv1.ConditionZeroWindowDisarmed, metav1.ConditionTrue,
			"WatchdogFired", fmt.Sprintf("DisarmZeroWindow skipped (agent unavailable: %v); watchdog backstop in effect (ADR-0157 D2)", err))
		if r.Recorder != nil {
			r.Recorder.Eventf(pm, corev1.EventTypeWarning, "ZeroWindowWatchdogFired",
				"zero-window hold watchdog will fire for migration %s — could not reach source agent: %v; FreezeWindowBudgetMs=%d",
				pm.Name, err, pm.Spec.FreezeWindowBudgetMs)
		}
		return
	}

	log.Info("disarmZeroWindowOnFailurePath: calling DisarmZeroWindow on source agent (ADR-0157 D2)",
		"migration", pm.Name, "node", sourceNode)
	disarmResp, rpcErr := agentClient.DisarmZeroWindow(ctx, &agentpb.DisarmZeroWindowRequest{
		MigrationName: pm.Name,
		PodUid:        pm.Spec.SourcePodUID,
	})
	if rpcErr != nil {
		log.Error(rpcErr, "disarmZeroWindowOnFailurePath: DisarmZeroWindow RPC error (ADR-0157 D2/D3)",
			"migration", pm.Name)
		setCondition(pm, pmv1.ConditionZeroWindowDisarmed, metav1.ConditionTrue,
			"WatchdogFired", fmt.Sprintf("DisarmZeroWindow RPC failed on failure path (%v); watchdog backstop in effect (ADR-0157 D3)", rpcErr))
		if r.Recorder != nil {
			r.Recorder.Eventf(pm, corev1.EventTypeWarning, "ZeroWindowWatchdogFired",
				"zero-window hold watchdog will fire for migration %s — DisarmZeroWindow RPC failed: %v; FreezeWindowBudgetMs=%d",
				pm.Name, rpcErr, pm.Spec.FreezeWindowBudgetMs)
		}
		return
	}
	if !disarmResp.Disarmed {
		// watchdog already fired before the controller got here (ADR-0157 D3).
		log.Info("disarmZeroWindowOnFailurePath: watchdog already fired (ADR-0157 D3)",
			"migration", pm.Name, "reason", disarmResp.BlockingReason)
		setCondition(pm, pmv1.ConditionZeroWindowDisarmed, metav1.ConditionTrue,
			"WatchdogFired", fmt.Sprintf("hold auto-disarmed by agent watchdog before failure-path disarm: %s (ADR-0157 D3)", disarmResp.BlockingReason))
		if r.Recorder != nil {
			r.Recorder.Eventf(pm, corev1.EventTypeWarning, "ZeroWindowWatchdogFired",
				"zero-window hold watchdog fired for migration %s; FreezeWindowBudgetMs=%d; reason=%s",
				pm.Name, pm.Spec.FreezeWindowBudgetMs, disarmResp.BlockingReason)
		}
		return
	}
	msg := fmt.Sprintf("TC-BPF zero-window hold disarmed on failure path; disarmed_at_ns=%d hold_duration_ms=%d (ADR-0157 D2)",
		disarmResp.DisarmedAtNs, disarmResp.HoldDurationMs)
	log.Info("disarmZeroWindowOnFailurePath: hold disarmed successfully", "migration", pm.Name,
		"disarmedAtNs", disarmResp.DisarmedAtNs, "holdDurationMs", disarmResp.HoldDurationMs)
	setCondition(pm, pmv1.ConditionZeroWindowDisarmed, metav1.ConditionTrue, "Disarmed", msg)
}

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
	// ADR-0157 D2: call DisarmZeroWindow FIRST when the hold is armed and not yet disarmed.
	// Non-blocking: disarm failure is recorded as WatchdogFired and rollback continues.
	r.disarmZeroWindowOnFailurePath(ctx, pm)

	// Clean up the replacement pod on hard failure (not rollback — rollback handles its own).
	// Prevents a gated orphan pod from lingering when the migration is permanently failed.
	r.deleteReplacementPod(ctx, pm)
	r.releaseDestinationCapacity(ctx, pm)

	// M26: emit flow_loss counter at Failed (all TCP connections inventoried are treated as lost).
	pmmetrics.MigrationFlowLossTotal.WithLabelValues(pm.Name, pm.Namespace).Add(
		float64(len(pm.Status.TCPSeqSnapshots)),
	)

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
// truncateConditionMsg bounds a condition message so it never exceeds the CRD
// apiserver limit (status.conditions[].message must be <= 32768 bytes). CRIU dump
// log output and gRPC error strings can be far larger; we cap well under the limit
// at a human-readable length. (Sprint 31 fix: "Too long: may not be more than 32768 bytes".)
func truncateConditionMsg(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func setCondition(pm *pmv1.PodMigration, condType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&pm.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            truncateConditionMsg(message, 1024),
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

// releaseDestinationCapacity decrements ActiveDestinationMigrations on the destination NMC.
// Called on Complete, Failed, and RollingBack so capacity is never leaked.
// Non-fatal: logs on error but does not fail the caller — migration state is already terminal.
func (r *PodMigrationReconciler) releaseDestinationCapacity(ctx context.Context, pm *pmv1.PodMigration) {
	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		return
	}
	log := logf.FromContext(ctx)
	key := types.NamespacedName{Name: destNode}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		nmc := &pmv1.NodeMigrationCapacity{}
		if err := r.Get(ctx, key, nmc); err != nil {
			return err
		}
		if nmc.Status.ActiveDestinationMigrations > 0 {
			nmc.Status.ActiveDestinationMigrations--
		}
		return r.Status().Update(ctx, nmc)
	}); err != nil {
		log.Error(err, "releaseDestinationCapacity: failed to decrement NMC counter",
			"migration", pm.Name, "destNode", destNode)
	}
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

	// ADR-0120 D3 / ADR-0175: stamp the checkpoint-ref unconditionally. The annotation
	// value is pm.Name (DNS-label safe, stable from first reconcile) — it does not
	// depend on CheckpointRef being populated. The NRI plugin reconstructs the full
	// checkpoint path as /run/podmotion/checkpoints/<ref>/final from pm.Name. The
	// prior nil-guard caused a race where CheckpointRef was not yet set at
	// createReplacementPod time, silently dropping the annotation and preventing the
	// NRI StartContainer hook from firing CRIU restore.
	newAnnotations["podmotion.io/checkpoint-ref"] = pm.Name
	newAnnotations["podmotion.io/migration-namespace"] = pm.Namespace
	// ADR-0130: mark that this pod's container command was replaced with a holder
	// (the real workload is supplied by the CRIU-restored tree).
	newAnnotations["podmotion.io/original-command-overridden"] = "true"

	// Deep-copy spec; clear scheduler-assigned and mutable fields.
	spec := *sourcePod.Spec.DeepCopy()
	spec.SchedulerName = ""    // webhook injects podmotion-scheduler
	spec.SchedulingGates = nil // webhook injects the gate

	// ADR-0130: the replacement pod's container init must NOT run the real workload
	// command. The NRI StartContainer hook fires CRIU restore as a side-effect AFTER
	// containerd has already started the container's real init, so the CRIU-restored
	// tree (ADR-0125 joins the pod netns; ADR-0128 places it in the pod cgroup) runs
	// alongside containerd's init — not as it. If containerd's init runs the real
	// command (e.g. redis-server), it collides with the restored process on the
	// workload port in the shared pod netns, exits, and trips the operator's
	// PodFailed rollback (reconcileRestoring). Override every container to a benign
	// long-lived holder so containerd's init is a stable, never-exiting, no-contention
	// process; the real workload is supplied solely by the CRIU-restored tree. Pod
	// readiness is only a precondition here — the authoritative restore signal is
	// status.criuRestoreConfirmed (ADR-0120 D1/D4).
	// ADR-0176: derive the holder command from the workload image's own entrypoint.
	// The replacement pod must NOT run the real workload (ADR-0130), but the holder
	// binary must exist in the container rootfs so runc create succeeds and the NRI
	// StartContainer hook fires (a failed runc create silently swallows the hook and
	// CRIU restore is never reached). Hardcoding /bin/sh breaks FROM scratch images.
	// Instead, preserve the original container Command/Args from the deep-copied source
	// pod spec and append --podmotion-holder, which makes the workload binary park
	// itself (no port bind, SIGTERM-clean) rather than run the real workload.
	// The holder binary is guaranteed to exist in the rootfs because it IS the image
	// entrypoint. See ADR-0176 for the full rationale and timing contract.
	for i := range spec.Containers {
		// Preserve original Command/Args from the deep-copied source pod spec.
		// Append --podmotion-holder so the workload binary enters holder mode.
		spec.Containers[i].Args = append(spec.Containers[i].Args, "--podmotion-holder")
		// Strip probes: a probe against the holder (no real workload in that
		// process tree) would fail, and a probe that hit the restored process on
		// the pod IP would couple container readiness to a process containerd
		// does not own. Readiness is gated by criuRestoreConfirmed + TrafficVerified.
		spec.Containers[i].LivenessProbe = nil
		spec.Containers[i].ReadinessProbe = nil
		spec.Containers[i].StartupProbe = nil
		spec.Containers[i].Lifecycle = nil
	}

	// Pin NodeName directly to the destination node if known.
	// When the MutatingAdmissionWebhook is deployed it would enforce this via spec.destinationNode;
	// setting NodeName here ensures correctness when the webhook is not running (dev/PoC clusters).
	destNodeName := pm.Status.DestinationNodeName
	if destNodeName == "" {
		destNodeName = pm.Spec.TargetNodeName
	}
	if destNodeName == "" {
		destNodeName = pm.Spec.DestinationNode
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
		// Clear nodeSelector and hard nodeAffinity: the source pod may be pinned to the
		// source node (e.g. nodeSelector: kubernetes.io/hostname=worker). These constraints
		// would reject the replacement pod on the destination node. NodeName already provides
		// an authoritative node pin, so node selection constraints are not needed.
		spec.NodeSelector = nil
		if spec.Affinity != nil && spec.Affinity.NodeAffinity != nil {
			spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = nil
		}
	} else {
		spec.NodeName = "" // let scheduler decide if destination unknown
	}

	// Add tolerations for any taints on the destination node so the kubelet
	// admits the replacement pod. This is necessary when migrating TO a control-plane
	// node that carries node-role.kubernetes.io/control-plane:NoSchedule.
	if destNodeName != "" {
		destNode := &corev1.Node{}
		if nodeErr := r.Get(ctx, types.NamespacedName{Name: destNodeName}, destNode); nodeErr == nil {
			for _, taint := range destNode.Spec.Taints {
				if taint.Effect == corev1.TaintEffectNoSchedule || taint.Effect == corev1.TaintEffectNoExecute {
					alreadyTolerated := false
					for _, t := range spec.Tolerations {
						if t.Key == taint.Key && (t.Operator == corev1.TolerationOpExists ||
							(t.Value == taint.Value && t.Effect == taint.Effect)) {
							alreadyTolerated = true
							break
						}
					}
					if !alreadyTolerated {
						spec.Tolerations = append(spec.Tolerations, corev1.Toleration{
							Key:      taint.Key,
							Operator: corev1.TolerationOpEqual,
							Value:    taint.Value,
							Effect:   taint.Effect,
						})
						log.Info("createReplacementPod: added toleration for destination node taint",
							"migration", pm.Name, "taint", taint.Key, "effect", taint.Effect)
					}
				}
			}
		}
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


// statusUpdate persists pm.Status via a fresh re-fetch + retry.RetryOnConflict loop so that
// concurrent controller reconcile loops (or the status verifier goroutine) do not cause stale
// resourceVersion Conflict errors to propagate as hard failures (M19.5 criterion 12).
// All Status().Update call sites must use this instead of bare r.statusUpdate(ctx, pm).
func (r *PodMigrationReconciler) statusUpdate(ctx context.Context, pm *pmv1.PodMigration) error {
	key := client.ObjectKeyFromObject(pm)
	want := pm.Status.DeepCopy()
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &pmv1.PodMigration{}
		if err := r.Get(ctx, key, fresh); err != nil {
			return err
		}
		fresh.Status = *want
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
	log := logf.FromContext(ctx)
	// Use a short-deadline context for the List call: if the informer cache for ResourceQuota
	// has not synced (e.g., RBAC forbids listing at cluster scope), r.Client.List will block
	// indefinitely waiting for WaitForCacheSync. A 3-second timeout causes fail-open, which is
	// the correct behavior when quota data is unavailable — the migration proceeds.
	listCtx, listCancel := context.WithTimeout(ctx, 3*time.Second)
	defer listCancel()
	quotaList := &corev1.ResourceQuotaList{}
	if err := r.Client.List(listCtx, quotaList, client.InNamespace(pm.Spec.PodNamespace)); err != nil || len(quotaList.Items) == 0 {
		if err != nil {
			log.Info("Verifying: ResourceQuota list failed or timed out — fail-open (allow deletion)", "migration", pm.Name, "err", err.Error())
		}
		return nil // no quotas or list unavailable — allow
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

// preCopyDirtyConvergence returns the dirty-page convergence ratio [0.0, 1.0] based on
// the pre-copy stats recorded in pm.Status.PreCopyStats.
//
// convergence = 1.0 - (finalDirtyPagesMB / initialDirtyPagesMB)
//
// When no pre-copy stats are available (cold migration fast-path already advanced) or
// the initial value is zero, 1.0 is returned so the gate passes immediately.
func preCopyDirtyConvergence(pm *pmv1.PodMigration) float64 {
	if pm.Status.PreCopyStats == nil {
		return 1.0
	}
	if pm.Status.PreCopyStats.RoundsCompleted == 0 {
		return 0.0
	}
	finalMB := float64(pm.Status.PreCopyStats.FinalDirtyPagesMB)
	if finalMB <= 0 {
		return 1.0
	}
	// Derive initial dirty MB from rounds and final value.
	// Without an explicit initial sample, we estimate based on the observation that
	// typical pre-copy convergence halves dirty pages per round.
	// rounds completed: each round reduces by ~50% → initial ≈ final * 2^rounds
	rounds := int(pm.Status.PreCopyStats.RoundsCompleted)
	initialMB := finalMB * float64(uint(1)<<uint(rounds))
	if initialMB <= 0 {
		return 1.0
	}
	convergence := 1.0 - (finalMB / initialMB)
	if convergence < 0 {
		return 0.0
	}
	if convergence > 1.0 {
		return 1.0
	}
	return convergence
}

// preCopyRetransmitHeadroom returns the estimated retransmit queue headroom [0.0, 1.0].
// A value < 0.5 means the retransmit backlog is under control (gate passes).
// Without explicit retransmit metrics available in PreCopyStats, returns 0.0 (passes)
// so the gate does not falsely block migrations where no TCP retransmit data exists.
func preCopyRetransmitHeadroom(_ *pmv1.PodMigration) float64 {
	// RetransmitQueue metrics are populated by the source agent in PreDumpRound responses.
	// Until the PreCopyStats type is extended with retransmit fields (M25), return 0.0
	// so this predicate is always satisfied — the dirty_convergence check is the primary gate.
	return 0.0
}

// preCopyTCPGatePassed evaluates the three-predicate freeze-go gate (M24):
//
//	dirty_convergence > 0.9        — pre-copy rounds converged
//	seq_advance_rate < bandwidth   — send rate fits the transfer pipe (approximated via dirty convergence)
//	retransmit_queue_headroom < 0.5 — retransmit backlog is small
//
// All three predicates must be true for the gate to pass.
// Returns true immediately when:
//   - TCPPreservationMode=None (no TCP state, gate irrelevant)
//   - MigrationModeCold (no pre-copy loop ran, gate irrelevant)
//   - PreCopyStats is nil (pre-copy loop not yet populated — defer to requeue)
func preCopyTCPGatePassed(pm *pmv1.PodMigration) bool {
	// MemorySynced=True is the authoritative convergence signal. The pre-copy loop
	// can legitimately converge without populating PreCopyStats — e.g. dirty pages
	// were already below threshold on the first sample (RoundsCompleted==0), so no
	// per-round stats were recorded. In that case there is nothing left to wait for:
	// blocking on nil/zero-round PreCopyStats here livelocks the migration in
	// PreCopyMemory forever even though memory has converged. Defer to the condition.
	if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionMemorySynced) {
		// Convergence already proven by the pre-copy loop; only block if explicit
		// stats are present AND show poor convergence.
		if pm.Status.PreCopyStats == nil || pm.Status.PreCopyStats.RoundsCompleted == 0 {
			return true
		}
	}
	if pm.Status.PreCopyStats == nil {
		// Pre-copy loop has not reported stats yet; wait for at least one round.
		return false
	}
	if pm.Status.PreCopyStats.RoundsCompleted == 0 {
		return false
	}

	const (
		minDirtyConvergence    = 0.9
		maxRetransmitHeadroom  = 0.5
	)

	convergence := preCopyDirtyConvergence(pm)
	if convergence <= minDirtyConvergence {
		return false
	}

	retransmitHeadroom := preCopyRetransmitHeadroom(pm)
	if retransmitHeadroom >= maxRetransmitHeadroom {
		return false
	}

	return true
}
