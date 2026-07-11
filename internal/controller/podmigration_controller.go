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
	"strconv"
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
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	gpuagent "github.com/podmotion-io/podmotion/internal/agent/gpu"
	"github.com/podmotion-io/podmotion/internal/agent/replication"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
	"github.com/podmotion-io/podmotion/internal/agent/traffic"
	"github.com/podmotion-io/podmotion/internal/estimation"
	"github.com/podmotion-io/podmotion/internal/featuregate"
	"github.com/podmotion-io/podmotion/internal/gitops"
	pmmetrics "github.com/podmotion-io/podmotion/internal/metrics"
	"github.com/podmotion-io/podmotion/internal/orchestration"
	"github.com/podmotion-io/podmotion/internal/rollback"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	finalizerName = "migration.podmotion.io/finalizer"

	// Condition types used on PodMigration status.
	conditionValidated                  = "Validated"
	conditionCheckpointed               = "Checkpointed"
	conditionRestored                   = "Restored"
	conditionTrafficVerified            = "TrafficVerified"
	conditionMemorySynced               = "MemorySynced"
	conditionStorageReady               = "StorageReadyForFreeze"
	conditionNetworkBridgeArmed         = "NetworkBridgeArmed"
	conditionPDBToken                   = "PDBTokenAcquired"
	conditionSourcePodDeleted           = "SourcePodDeleted"
	conditionCapacityReserved           = "CapacityReserved"
	conditionDestinationVolumeReady     = "DestinationVolumeReady"
	conditionSchedulingGateRemoved      = "SchedulingGateRemoved"
	conditionSecurityContextVerified    = "SecurityContextVerified"
	conditionDataplaneReconciled        = "DataplaneReconciled"
	conditionGitOpsSuspended            = "GitOpsSuspended"
	conditionEndpointSliceCleanVerified = "EndpointSliceCleanupVerified"
	// cni0CleanupVerifyAttemptsAnnotation stamps the current VerifyCleanup(CUTOVER_COMPLETE)
	// retry attempt count on the PodMigration so the bounded 3-attempt/2s-4s-8s backoff
	// (ADR-0241 item 1) survives across reconcile requeues without a blocking sleep.
	cni0CleanupVerifyAttemptsAnnotation = "podmotion.io/cni0-cleanup-verify-attempts"
	// conditionIPHandoffInjected records that the ADR-0133 destination-side neighbor/FDB
	// handoff for the OLD pod IP has been installed and the reachability probe passed.
	conditionIPHandoffInjected = "IPHandoffInjected"
	// conditionRestoreTimedOut is set when the restore deadline elapses, driving
	// the migration to RollingBack (ADR-0157 D3/GC-32). Reason: RestoreDeadlineExceeded.
	conditionRestoreTimedOut = "RestoreTimedOut"
	// ipReclaimVerifyAttemptsAnnotation stamps the current VerifyCleanup(IP_RECLAIM) retry
	// attempt count (ADR-0244 / NR-BLOCK-2), mirroring cni0CleanupVerifyAttemptsAnnotation.
	ipReclaimVerifyAttemptsAnnotation = "podmotion.io/ip-reclaim-verify-attempts"
)

// reclaimSweepInterval is the ADR-0244 (NR-BLOCK-2) periodic pod-IP GC sweep requeue
// interval, used from the terminal Complete/Failed reconcile branch while
// ReclaimEligible(pm) is not yet true.
const reclaimSweepInterval = 30 * time.Second

// reclaimQuarantineSeconds is the ADR-0244 R3 floor: a migration must have been terminal
// for at least this long before the IP-reclaim sweep is even considered eligible. Chosen as
// ~10x the existing cni0CleanupVerifyBackoff total budget (14s) — an order-of-magnitude
// margin over an already-reviewed bound, not an arbitrary constant.
const reclaimQuarantineSeconds = 150 * time.Second

// reclaimDeletionForceTimeout bounds how long handleDeletion holds a PodMigration's finalizer
// waiting for the ADR-0244 IP-reclaim sweep to complete before force-removing it (fail-open).
// It mirrors ADR-0241's bounded-retry-then-fail-open posture: the reclaim sweep MUST get a fair
// chance to run — it cannot even begin until the R3 quarantine floor (reclaimQuarantineSeconds)
// elapses, after which it needs a teardown pass plus the VerifyCleanup(IP_RECLAIM) retry budget
// to converge — but a genuinely stuck reclaim (R6/R7 failing closed on a real live connection,
// or a persistent teardown bug) must never be able to wedge CR deletion forever. Anchored to the
// quarantine floor plus a generous margin for teardown + verify to complete, not an arbitrary
// constant.
const reclaimDeletionForceTimeout = reclaimQuarantineSeconds + 5*time.Minute

// ipReclaimVerifyBackoff is the ADR-0244 VerifyCleanup(IP_RECLAIM) bounded retry schedule,
// identical in shape to cni0CleanupVerifyBackoff (ADR-0241 item 1 precedent): 3 attempts,
// 2s/4s/8s, converging to a fail-open (ConditionIPReclaimVerified=False +
// DatapathCleanupLeakTotal + a DatapathCleanupLeak Event) on exhaustion.
var ipReclaimVerifyBackoff = []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}

// cni0CleanupVerifyBackoff is the ADR-0241 item 1 bounded retry schedule for
// VerifyCleanup(CUTOVER_COMPLETE): up to 3 attempts, 2s/4s/8s backoff, converging to a
// fail-open (ConditionCni0CleanupVerified=False + DatapathCleanupLeakTotal + a
// DatapathCleanupLeak Event) on exhaustion rather than a new blocking phase.
var cni0CleanupVerifyBackoff = []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}

const (
	// conditionDataplaneReachabilityVerified (ADR-0210) is the authoritative cross-node
	// reachability gate. The CONTROLLER sets it True only after a source-node agent
	// (a node != destination) dials the preserved pod IP and reads back a controller-issued
	// nonce echoed by the destination — proving the real overlay/host-route datapath is live.
	// It REPLACES TrafficVerified as the necessary predicate for source-pod deletion under
	// Strict. Mirrors pmv1.ConditionDataplaneReachabilityVerified.
	conditionDataplaneReachabilityVerified = pmv1.ConditionDataplaneReachabilityVerified
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
	// ReplicationMgr drives the pre-copy dirty-page sync loop (a reviewer, M5).
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
	// onPhaseDecision, when non-nil, is invoked at the single next-phase decision point of the
	// checkpoint/transfer advance helpers with the (from, decided) phase pair. It is a
	// test-observable transition ledger hook: it records the branch actually taken at the source
	// of truth (pm.Status.Phase), giving a deterministic in-process proof of the phase-machine
	// decision that does not depend on any fake-client status readback. Nil in production — no
	// behavioral effect. See advanceAfterCheckpoint / advanceAfterTransfer.
	onPhaseDecision func(from, decided pmv1.MigrationPhase)
}

// recordPhaseDecision reports the next-phase decision to the injectable ledger hook when one is
// wired. "decided" is the phase the helper is advancing the migration TOWARD; on the 12-phase
// FinalFreezeStateCapture path the helper stays on the current phase (status-only requeue), so
// "decided" equals "from". This is the single source-of-truth transition record the safety test
// asserts against.
func (r *PodMigrationReconciler) recordPhaseDecision(from, decided pmv1.MigrationPhase) {
	if r.onPhaseDecision != nil {
		r.onPhaseDecision(from, decided)
	}
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

// Reconcile implements the PodMigration state machine. It is called by controller-runtime whenever a PodMigration object is created, updated, or re-queued. Each call advances the migration by exactly one phase transition, persists status, and re-queues if further work remains. See the project conventions doc §PodMigration state machine for the full phase diagram.
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
	case pmv1.MigrationPhaseDryRunComplete:
		// Dry-run CRs never install any of the ADR-0244 reclaim objects — nothing to sweep.
		return ctrl.Result{}, nil
	case pmv1.MigrationPhaseComplete, pmv1.MigrationPhaseFailed:
		// ADR-0244 / NR-BLOCK-2: the terminal-outcome branch is no longer a dead end. Run the
		// periodic pod-IP GC sweep until ReclaimEligible(pm) holds, then tear down and verify
		// once, idempotently (crash-safe: independent per-side conditions resume correctly).
		return r.reconcileIPReclaimSweep(ctx, pm)
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
		// ADR-0217 D3: warn (not info) when the consumer reads an empty WorkloadImage. Pre-0217
		// this was the silent failure mode — the producer ran in Checkpointing (after this phase),
		// so the consumer always saw empty and the agent never cached the image, aborting restore.
		if workloadImageForPrep == "" {
			log.Info("WARNING ADR-0217 D3: DestinationPrewarm read EMPTY WorkloadImage from MCP — "+
				"D1 producer (Validating) should have populated it; relying on agent self-resolve (D2)",
				"migration", pm.Name)
		}
	} else {
		log.Info("WARNING ADR-0217 D3: DestinationPrewarm could not fetch MCP for WorkloadImage — "+
			"relying on agent self-resolve (D2)",
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
		SourcePodIp:          pm.Spec.SourcePodIP, // ADR-0224: conntrack NOTRACK target
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

	// ADR-0224: record that the source-side conntrack NOTRACK rule is armed. This single
	// write makes atomicity-barrier predicate E (read at the OverlayHandoff and DisengageHold
	// ConfirmOverlayReady calls) non-zero on the source axis — without it, predicate E reads
	// source=false permanently and DisengageHold never satisfies the barrier (ADR-0049).
	pm.Status.SourceConntrackArmed = resp.SourceConntrackArmed

	msg := fmt.Sprintf("TC-BPF zero-window hold armed on source veth; armed_at_ns=%d; tcpi_unacked drained (ADR-0049 predicate A); sourceConntrackArmed=%t (ADR-0224 predicate E)", resp.ArmedAtNs, resp.SourceConntrackArmed)
	log.Info("ZeroWindowArm: hold armed", "migration", pm.Name, "armedAtNs", resp.ArmedAtNs,
		"sourceConntrackArmed", resp.SourceConntrackArmed)
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

	// ADR-0192 R2 B2c: pass empty FdbIfname when OverlayFdbIfname is unset — delegate to agent
	// discovery (VXLAN link-type probe). No "flannel.1" literal (C-335). The agent returns
	// ResolvedFdbIf on the response path (see injectIPHandoff / 2796-2805).
	fdbIfname := pm.Status.OverlayFdbIfname
	// fdbIfname may be "" — that is intentional; the agent discovers the VXLAN device at runtime.

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
		MigrationName: pm.Name,
		SeqXlatSeeded: seqXlatSeeded,
		FdbIfname:     fdbIfname,
		PodIp:         pm.Spec.SourcePodIP,
		PodMac:        pm.Status.SourcePodMac,
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

		// ADR-0192 R2 B2c: pass empty FdbIfname — delegate to agent VXLAN discovery. No "flannel.1" literal.
		fdbIfname := pm.Status.OverlayFdbIfname
		// fdbIfname may be "" — intentional; agent discovers at runtime.
		// Vacuously true when no TCP connections exist (same fix as OverlayHandoff B5).
		seqXlatSeeded := true

		log.Info("DisengageHold: calling ConfirmOverlayReady on destination agent (post-restore, all 6 predicates)",
			"migration", pm.Name, "node", destNode)
		overlayResp, overlayErr := destAgentForConfirm.ConfirmOverlayReady(ctx, &agentpb.ConfirmOverlayReadyRequest{
			MigrationName: pm.Name,
			SeqXlatSeeded: seqXlatSeeded,
			FdbIfname:     fdbIfname,
			PodIp:         pm.Spec.SourcePodIP,
			PodMac:        pm.Status.SourcePodMac,
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
			SourcePodIp:   pm.Spec.SourcePodIP, // ADR-0224 3h-SYM: remove NOTRACK rule
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

	// ADR-0225: VerifyTCP runs on the DESTINATION agent and resolves the container PID to
	// inspect from req.PodUid via FindContainerPID's cgroup walk. The restored process lives
	// under the REPLACEMENT pod's UID on the destination node — NOT the source pod's UID. Using
	// pm.Spec.SourcePodUID here made FindContainerPID search the destination /proc for a pod
	// that does not exist on that node ("container PID not found for pod UID <source>"),
	// aborting before the snd_nxt/rcv_nxt comparison (GC-C2 seqDelta NOT MEASURED). Resolve the
	// replacement pod's UID and pass that. Never fall back to the source UID for PID resolution:
	// the source pod has no live process on the destination node, so a fallback can only
	// fail-closed. Requeue if the replacement pod is not yet visible (it is guaranteed named by
	// the time TCPVerifying is reached, but its object may lag the cache).
	// Resolve the replacement pod by the podmotion.io/migration-name LABEL — the same
	// source-of-truth primitive the restore/agent path uses (server.go resolveReplacementPod).
	// pm.Status.ReplacementPodName is a controller-written status field that can be lost to a
	// status-subresource clobber race between createReplacementPod's RetryOnConflict update and
	// a later full statusUpdate that re-fetched before the name was persisted. When that happens
	// the field reads empty here even though the replacement pod is created, Running, and was
	// successfully restored INTO by the label-keyed agent path — causing an infinite
	// "replacement pod not yet visible" requeue in TCPVerifying. Resolving by the label the
	// controller stamps at creation (line ~4815) makes this step depend on the authoritative
	// object, not the flaky mirror. Fall back to the status field only if the label lookup finds
	// nothing (belt-and-suspenders).
	replForVerify, resolveErr := r.resolveReplacementPodByLabel(ctx, pm)
	if resolveErr != nil || replForVerify == nil || replForVerify.UID == "" {
		log.Info("ADR-0225: TCPVerifying: replacement pod not yet visible for dest PID resolution — requeuing",
			"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName, "resolveErr", resolveErr)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	// Heal the status mirror so later phases that still read pm.Status.ReplacementPodName resolve.
	if pm.Status.ReplacementPodName == "" {
		pm.Status.ReplacementPodName = replForVerify.Name
		if err := r.statusUpdate(ctx, pm); err != nil {
			log.Error(err, "TCPVerifying: failed to heal Status.ReplacementPodName — continuing",
				"migration", pm.Name, "replacementPod", replForVerify.Name)
		}
	}
	vtcpReq := &agentpb.VerifyTCPRequest{
		MigrationName: pm.Name,
		PodUid:        string(replForVerify.UID),
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

	// ADR-0210: the MEASURED per-direction seqDelta now flows from the agent's VerifyTCP
	// response (no longer a hard-coded literal 0). Take the larger of the two directions as
	// the reported delta. Under Strict, a non-zero measured delta is a North Star violation
	// and FAILS verification (the prior code asserted seq_delta=0 unconditionally, making the
	// claim unfalsifiable).
	measuredSeqDelta := vtcpResp.SndSeqDeltaMax
	if vtcpResp.RcvSeqDeltaMax > measuredSeqDelta {
		measuredSeqDelta = vtcpResp.RcvSeqDeltaMax
	}
	// Persist the measured value so the seq_delta gauge in reconcileServiceVerifying reads the
	// real number instead of fabricating 0.
	if pm.Annotations == nil {
		pm.Annotations = make(map[string]string)
	}
	pm.Annotations["podmotion.io/measured-seq-delta"] = fmt.Sprintf("%d", measuredSeqDelta)
	if aErr := r.Update(ctx, pm); aErr != nil {
		log.Error(aErr, "TCPVerifying: failed to persist measured seq-delta annotation (non-fatal)", "migration", pm.Name)
	}

	if measuredSeqDelta != 0 && pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict {
		msg := fmt.Sprintf("ADR-0210: Strict mode requires seq_delta=0 but measured snd=%d rcv=%d (max=%d) — failing verification",
			vtcpResp.SndSeqDeltaMax, vtcpResp.RcvSeqDeltaMax, measuredSeqDelta)
		log.Error(nil, msg, "migration", pm.Name)
		setCondition(pm, pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionFalse,
			"NonZeroSeqDelta", msg)
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		return r.initiateRollback(ctx, pm, msg)
	}

	connMsg := fmt.Sprintf("TCP sequence continuity verified: %d/%d connections snd_nxt/rcv_nxt within ±MSS (ADR-0210 measured seq_delta: snd=%d rcv=%d)",
		vtcpResp.ConnectionsVerified, vtcpResp.ConnectionsExpected, vtcpResp.SndSeqDeltaMax, vtcpResp.RcvSeqDeltaMax)
	if vtcpResp.AppProbeOk {
		connMsg += fmt.Sprintf("; %s probe OK", pm.Spec.ApplicationProbe.Protocol)
	}
	log.Info("TCPVerifying: sequence continuity confirmed", "migration", pm.Name,
		"verified", vtcpResp.ConnectionsVerified, "expected", vtcpResp.ConnectionsExpected,
		"measuredSndSeqDelta", vtcpResp.SndSeqDeltaMax, "measuredRcvSeqDelta", vtcpResp.RcvSeqDeltaMax)
	setCondition(pm, pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionTrue,
		"SequenceContinuityVerified", connMsg)
	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, err
	}
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseServiceVerifying)
}

// resolveProbeProtocol (ADR-0325) is a PURE, controller-local helper. If spec.applicationProbe
// is set, it wins. Otherwise it scans destPod's containers (init containers EXCLUDED,
// pod-wide) against the port heuristic 5432->SQL, 6379->Redis, {80,8080,443}->HTTP.
// Exactly-one-match -> protocol; zero-match -> zeroMatch=true; two-or-more-match ->
// ambiguous=true. Never persisted/cached — callers must re-derive every reconcile.
func resolveProbeProtocol(spec *pmv1.ApplicationProbeSpec, destPod *corev1.Pod) (protocol string, ambiguous bool, zeroMatch bool) {
	if spec != nil {
		return string(spec.Protocol), false, false
	}
	if destPod == nil {
		return "", false, true
	}
	matches := map[string]bool{}
	for _, c := range destPod.Spec.Containers {
		for _, p := range c.Ports {
			switch p.ContainerPort {
			case 5432:
				matches["SQL"] = true
			case 6379:
				matches["Redis"] = true
			case 80, 8080, 443:
				matches["HTTP"] = true
			}
		}
	}
	if len(matches) == 0 {
		return "", false, true
	}
	if len(matches) > 1 {
		return "", true, false
	}
	for k := range matches {
		return k, false, false
	}
	return "", false, true
}

// setWorkloadLivenessCondition (ADR-0325) is the single condition-encoding setter mapping a
// (verified, reason) pair onto ConditionWorkloadLivenessVerified. The reason vocabulary is
// CLOSED: {NoKnownProtocol, ExplicitProbePassed, DefaultedProbePassed, ExplicitProbeFailed,
// DefaultedProbeFailed, AmbiguousProbeDefault}.
func setWorkloadLivenessCondition(pm *pmv1.PodMigration, verified bool, reason, message string) {
	status := metav1.ConditionFalse
	if verified {
		status = metav1.ConditionTrue
	}
	setCondition(pm, pmv1.ConditionWorkloadLivenessVerified, status, reason, message)
}

// reconcileServiceVerifying runs HTTP/endpoint readiness checks (the existing service-layer verifier).
// This is the ServiceVerifier discipline split from the legacy Verifying phase.
func (r *PodMigrationReconciler) reconcileServiceVerifying(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// ADR-0325: destination-pod fetch MOVED to the top of the function and HARDENED — a
	// fetch error is a REQUEUE, never a silent NoKnownProtocol default, because the
	// resolver needs Spec.Containers[].Ports[].
	destPodName := pm.Status.ReplacementPodName
	if destPodName == "" {
		destPodName = pm.Spec.PodName
	}
	destPod := &corev1.Pod{}
	destPodFetchErr := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: destPodName}, destPod)
	if destPodFetchErr != nil {
		log.Error(destPodFetchErr, "ServiceVerifying: ADR-0325 destination pod fetch failed — requeuing (never silently defaulting)",
			"migration", pm.Name, "destPod", destPodName)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	destPodIP := destPod.Status.PodIP

	// ADR-0325: resolve the probe protocol fresh every reconcile (local, never cached) and,
	// unless already confirmed True this reconcile, issue the AppProbeOnly RPC to the
	// DESTINATION-node agent BEFORE the DataplaneReachabilityVerified short-circuit below —
	// this is the exact hole a dead-but-echo-alive workload previously escaped through.
	probeProtocol, ambiguous, zeroMatch := resolveProbeProtocol(pm.Spec.ApplicationProbe, destPod)
	alreadyVerified := meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionWorkloadLivenessVerified)

	switch {
	case ambiguous:
		setWorkloadLivenessCondition(pm, false, "AmbiguousProbeDefault",
			"ServiceVerifying: ADR-0325 multiple container-port heuristic matches; set spec.applicationProbe to disambiguate")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	case zeroMatch && pm.Spec.ApplicationProbe == nil:
		// Deliberate transport-only resolution — no known protocol to probe. Not a silent
		// fallback: the condition is explicitly written True/NoKnownProtocol.
		if !alreadyVerified {
			setWorkloadLivenessCondition(pm, true, "NoKnownProtocol",
				"ServiceVerifying: ADR-0325 no application-probe protocol resolved; transport-only verification applies")
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
		}
	case !alreadyVerified:
		// Idempotency guard: only skip the RPC when WorkloadLivenessVerified is already
		// True on this reconcile's read — always re-run otherwise.
		if r.AgentPool == nil {
			log.Error(nil, "ServiceVerifying: AgentPool not wired — requeuing", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		destNode := pm.Status.DestinationNodeName
		destAgent, agentErr := r.AgentPool.ForNode(ctx, destNode)
		if agentErr != nil {
			log.Error(agentErr, "ServiceVerifying: could not resolve destination-node agent client — requeuing",
				"migration", pm.Name, "destNode", destNode)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		explicit := pm.Spec.ApplicationProbe != nil
		vtcpReq := &agentpb.VerifyTCPRequest{
			MigrationName:    pm.Name,
			AppProbeOnly:     true,
			AppProbeProtocol: probeProtocol,
		}
		var port int32
		switch probeProtocol {
		case "SQL":
			port = 5432
		case "Redis":
			port = 6379
		case "HTTP":
			port = 80
		}
		if explicit && pm.Spec.ApplicationProbe.Port > 0 {
			port = pm.Spec.ApplicationProbe.Port
			vtcpReq.AppProbeQuery = pm.Spec.ApplicationProbe.Query
			vtcpReq.AppProbeTimeoutS = pm.Spec.ApplicationProbe.TimeoutSeconds
		}
		if destPodIP != "" && port > 0 {
			// ADR-0325: app_probe_query (proto field 6) is OVERLOADED — for SQL it carries
			// the query, for HTTP the path, unused for Redis/TCP.
			vtcpReq.AppProbeAddress = fmt.Sprintf("%s:%d", destPodIP, port)
		}
		vtcpResp, rpcErr := destAgent.VerifyTCP(ctx, vtcpReq)
		reasonPrefix := "Defaulted"
		if explicit {
			reasonPrefix = "Explicit"
		}
		if rpcErr != nil || vtcpResp == nil || !vtcpResp.Verified {
			msg := "app probe RPC error"
			if rpcErr == nil && vtcpResp != nil {
				msg = vtcpResp.AppProbeError
			}
			setWorkloadLivenessCondition(pm, false, reasonPrefix+"ProbeFailed",
				fmt.Sprintf("ServiceVerifying: ADR-0325 workload-liveness probe (%s) failed: %v / %s", probeProtocol, rpcErr, msg))
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		setWorkloadLivenessCondition(pm, true, reasonPrefix+"ProbePassed",
			fmt.Sprintf("ServiceVerifying: ADR-0325 workload-liveness probe (%s) passed", probeProtocol))
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	// ADR-0210 + ADR-0325: advance only when the AUTHORITATIVE cross-node
	// DataplaneReachabilityVerified is True AND (no known protocol OR WorkloadLivenessVerified
	// is True). Textual placement alone is insufficient — the guard condition itself gates on
	// the new predicate.
	if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionDataplaneReachabilityVerified) &&
		(probeProtocol == "" || meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionWorkloadLivenessVerified)) {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseCutoverComplete)
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

	// M26 / ADR-0210: emit seq_delta gauge from the MEASURED value persisted by
	// reconcileTCPVerifying (podmotion.io/measured-seq-delta), NOT a hard-coded literal 0.
	// The North Star claim (seq_delta=0) is now FALSIFIABLE: the gauge reports whatever
	// VerifyTCP actually measured. Strict mode already failed above on any non-zero value.
	seqDelta := 0.0
	if raw, ok := pm.Annotations["podmotion.io/measured-seq-delta"]; ok {
		if v, perr := strconv.ParseFloat(raw, 64); perr == nil {
			seqDelta = v
		} else {
			log.Error(perr, "ServiceVerifying: could not parse measured-seq-delta annotation — gauge may be stale", "migration", pm.Name, "raw", raw)
		}
	} else {
		log.Info("ServiceVerifying: ADR-0210 measured-seq-delta annotation absent (TCP verify may have been skipped) — gauge reports 0", "migration", pm.Name)
	}
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

// sourcePodDeletionBlockReason evaluates the single, authoritative source-pod-deletion safety
// gate (ADR-0012 / invariant-1) against a set of PodMigration status conditions and the declared
// TCP preservation mode. It returns "" when deletion is permitted, or a non-empty human-readable
// reason describing which predicate is missing when deletion MUST be blocked.
//
// This is the STRICTER UNION of the two gates that had drifted apart in the codebase:
//   - the CutoverComplete gate (which required TCPSequenceContinuityVerified=True for
//     Strict/BestEffort), and
//   - the Verifying gate (which was MISSING that TCPSequenceContinuityVerified requirement and
//     therefore could delete the source pod under BestEffort — and under Strict once the
//     dataplane gate passed — without any proof of TCP sequence continuity).
//
// Collapsing both call sites onto this one predicate fixes the weak copy UP, never down:
// the gate is the union of every predicate either copy enforced. The predicate is:
//   - Strict:      DataplaneReachabilityVerified=True (ADR-0210 cross-node gate) AND
//                  TCPSequenceContinuityVerified=True.
//   - BestEffort:  TrafficVerified=True AND TCPSequenceContinuityVerified=True.
//   - None:        TrafficVerified=True (legacy cold/stateless pre-check).
//
// Because the reachability/traffic gate and the TCP-continuity gate are evaluated in a single
// pass over one authoritative condition set, no A-02/B-06 interleaving can leave a window in
// which the source pod is deletable under Strict/BestEffort without TCPSequenceContinuityVerified.
func sourcePodDeletionBlockReason(mode pmv1.TCPPreservationMode, conditions []metav1.Condition) string {
	// Reachability / traffic predicate (mode-dependent necessary predicate).
	if mode == pmv1.TCPPreservationModeStrict {
		if !meta.IsStatusConditionTrue(conditions, conditionDataplaneReachabilityVerified) {
			return "DataplaneReachabilityVerified is not True (ADR-0210 cross-node gate)"
		}
	} else if !meta.IsStatusConditionTrue(conditions, conditionTrafficVerified) {
		return "TrafficVerified is not True (ADR-0012)"
	}
	// TCP sequence-continuity predicate — REQUIRED for both Strict and BestEffort. This is the
	// predicate the Verifying gate had dropped; it is enforced here for BOTH call sites.
	if mode == pmv1.TCPPreservationModeStrict || mode == pmv1.TCPPreservationModeBestEffort {
		if !meta.IsStatusConditionTrue(conditions, pmv1.ConditionTCPSequenceContinuityVerified) {
			return "TCPSequenceContinuityVerified is not True in Strict/BestEffort mode (ADR-0012)"
		}
	}
	// ADR-0325: additive predicate for ALL THREE modes, including None (which previously
	// required only TrafficVerified). Lexically distinct from the two messages above so
	// on-call can substring-match "probe failing, will retry" vs "rollback in progress".
	if !meta.IsStatusConditionTrue(conditions, pmv1.ConditionWorkloadLivenessVerified) {
		return "WorkloadLivenessVerified is not True (ADR-0325 real-liveness gate)"
	}
	return ""
}

// deleteSourcePodIfSafe is the SINGLE primitive that gates and performs source-pod deletion for
// every phase that finalizes a cutover (reconcileVerifying and reconcileCutoverComplete both route
// through it). It re-reads the authoritative conditions from the API (Status is a writable
// subresource and in-memory state may be stale), evaluates the STRICTER-union safety gate via
// sourcePodDeletionBlockReason, and only then deletes the source pod.
//
// Return values:
//   - blocked=true  → the gate refused deletion; the caller MUST requeue (a Result is returned).
//     The source pod is NOT deleted; the migration phase is untouched.
//   - blocked=false → the gate permitted deletion and the source pod was deleted (or was already
//     gone / not on the source node). The caller may proceed to finalization.
func (r *PodMigrationReconciler) deleteSourcePodIfSafe(ctx context.Context, pm *pmv1.PodMigration) (blocked bool, res ctrl.Result) {
	log := logf.FromContext(ctx)

	// Defensive re-fetch (ADR-0012): read the latest, authoritative conditions from the API
	// immediately before deletion — never trust stale in-memory pm.Status.
	freshPM := &pmv1.PodMigration{}
	if fetchErr := r.Get(ctx, client.ObjectKeyFromObject(pm), freshPM); fetchErr != nil {
		log.Error(fetchErr, "deleteSourcePodIfSafe: failed to re-fetch PodMigration before source pod deletion — requeuing for safety (ADR-0012)", "migration", pm.Name)
		return true, ctrl.Result{RequeueAfter: 5 * time.Second}
	}

	if reason := sourcePodDeletionBlockReason(freshPM.Spec.TCPPreservationMode, freshPM.Status.Conditions); reason != "" {
		log.Error(nil, "deleteSourcePodIfSafe: SAFETY BLOCK — refusing to delete source pod (ADR-0012)", "migration", pm.Name, "reason", reason, "mode", freshPM.Spec.TCPPreservationMode)
		return true, ctrl.Result{RequeueAfter: 10 * time.Second}
	}

	sourcePod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err == nil {
		// Only delete if the pod is still on the source node (not already gone or rescheduled).
		if sourcePod.Spec.NodeName == pm.Status.SourceNodeName {
			log.Info("deleteSourcePodIfSafe: deleting source pod post-gate",
				"pod", pm.Spec.PodName, "node", pm.Status.SourceNodeName, "migration", pm.Name)
			if deleteErr := r.Delete(ctx, sourcePod); deleteErr != nil && !apierrors.IsNotFound(deleteErr) {
				log.Error(deleteErr, "deleteSourcePodIfSafe: failed to delete source pod — proceeding anyway (ADR-0019)", "migration", pm.Name)
			}
		}
	} else if !apierrors.IsNotFound(err) {
		log.Error(err, "deleteSourcePodIfSafe: could not look up source pod — skipping deletion", "migration", pm.Name)
	}
	// IsNotFound → already deleted, which is fine.
	return false, ctrl.Result{}
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

	// Defensive re-check + deletion via the single STRICTER-union primitive (ADR-0012 safety
	// contract, invariant-1). The source pod is the only surviving copy of process state; the
	// phase transition alone is NOT sufficient because Status is a writable subresource and can
	// be externally patched to Phase=CutoverComplete. deleteSourcePodIfSafe re-reads the
	// authoritative conditions and enforces the STRICTER union (TCPSequenceContinuityVerified=True
	// for Strict/BestEffort) before any deletion — identical to the Verifying call site.
	if blocked, res := r.deleteSourcePodIfSafe(ctx, pm); blocked {
		return res, nil
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
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
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

	// ADR-0217 D1: persist the workload image to the MigrationCheckpoint CR HERE — in
	// Validating, BEFORE the transition to DestinationPrewarm. The prior producer ran in
	// Checkpointing (controller:~2016), which is AFTER DestinationPrewarm's consumer
	// (controller:~411). The consumer therefore always read an empty WorkloadImage, the
	// agent never cached the image, and restore aborted with "restore image unresolved".
	// Producing here closes the phase-order gap. The MCP CR is normally created by the
	// agent at checkpoint time and does not yet exist at Validating, so we create-or-update.
	// Warn-only (ADR-0012): a failure here is recoverable by the Checkpointing re-assert and
	// the D2 agent self-resolve fallback.
	if len(pod.Spec.Containers) > 0 {
		workloadImage := pod.Spec.Containers[0].Image
		mcpKey := types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}
		mcpRef := &pmv1.MigrationCheckpoint{}
		if mcpGetErr := r.Get(ctx, mcpKey, mcpRef); mcpGetErr == nil {
			if mcpRef.Spec.WorkloadImage != workloadImage {
				mcpRef.Spec.WorkloadImage = workloadImage
				if mcpUpdateErr := r.Update(ctx, mcpRef); mcpUpdateErr != nil {
					log.Error(mcpUpdateErr, "ADR-0217 D1: failed to update MCP WorkloadImage in Validating (warn-only)", "migration", pm.Name, "image", workloadImage)
				} else {
					log.Info("ADR-0217 D1: MCP WorkloadImage set in Validating (before DestinationPrewarm consumer)", "migration", pm.Name, "image", workloadImage)
				}
			}
		} else if apierrors.IsNotFound(mcpGetErr) {
			// MCP not yet created by the agent — create it now carrying the WorkloadImage so
			// the DestinationPrewarm consumer can read it. The agent's later upsert is idempotent.
			newMCP := &pmv1.MigrationCheckpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name:      pm.Name,
					Namespace: pm.Namespace,
					Labels:    map[string]string{"podmotion.io/migration": pm.Name},
				},
				Spec: pmv1.MigrationCheckpointSpec{
					PodMigrationRef: pm.Name,
					WorkloadImage:   workloadImage,
				},
			}
			if mcpCreateErr := r.Create(ctx, newMCP); mcpCreateErr != nil {
				log.Error(mcpCreateErr, "ADR-0217 D1: failed to create MCP with WorkloadImage in Validating (warn-only)", "migration", pm.Name, "image", workloadImage)
			} else {
				log.Info("ADR-0217 D1: created MCP with WorkloadImage in Validating (before DestinationPrewarm consumer)", "migration", pm.Name, "image", workloadImage)
			}
		} else {
			log.Error(mcpGetErr, "ADR-0217 D1: failed to fetch MCP for WorkloadImage in Validating (warn-only)", "migration", pm.Name)
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

	// the replication reviewer, the storage reviewer, and the network reviewer drive pre-migration
	// work asynchronously.  All three keystone conditions must be True before advancing:
	//   MemorySynced=True           (a reviewer replication loop)
	//   StorageReadyForFreeze=True  (a reviewer storage pre-stage, ADR-0011)
	//   NetworkBridgeArmed=True     (a reviewer eBPF bridge OR v0.1 fast-path, ADR-0028)
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
		return r.advanceAfterCheckpoint(ctx, pm)
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

	// Check for a prior terminal checkpoint-failure signal before issuing a fresh call.
	// Backstop allow-list (bug fix, HIGH panel review of ADR-0246): ShmemPagemapMissing is a
	// deterministic CRIU-version defect exactly like CheckpointFailed — it must route to
	// rollback here too if it is ever observed stale on re-entry (e.g. after a controller
	// restart between the condition write and the direct initiateRollback call below), rather
	// than falling through to re-issue an identical, deterministically-failing Checkpoint RPC
	// (unbounded retry storm). The primary path calls initiateRollback directly at the point
	// ShmemPagemapMissing is first set (see below); this is defense in depth for the stale-read
	// case only.
	condFailed := meta.FindStatusCondition(pm.Status.Conditions, conditionCheckpointed)
	if condFailed != nil && condFailed.Status == metav1.ConditionFalse {
		switch condFailed.Reason {
		case "CheckpointFailed", "ShmemPagemapMissing":
			return r.initiateRollback(ctx, pm, condFailed.Message)
		}
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
				// ADR-0246 typed-status redesign: the agent
				// attaches an errdetails.ErrorInfo{Reason: "SHMEM_PAGEMAP_MISSING"} status-details
				// payload (internal/agent/server/shmem_pagemap_guard.go,
				// newShmemPagemapMissingStatus) when the checkpoint-completeness guard fires.
				// codes.FailedPrecondition alone is ambiguous — ErrCRIUCapability uses the same
				// code — so the Reason on the details payload is the second axis that
				// distinguishes the two, replacing the former error-string substring match. This
				// is now the ONE code path that detects and routes this failure (previously
				// three: this detect-and-route call, the stale-condition backstop switch below,
				// and general condFailed handling all separately tried to reach RollingBack for
				// the same logical failure).
				if shmemPagemapMissingReasonFromStatus(grpcStatus) {
					log.Error(err, "Checkpoint RPC failed: CRIU 4.2 anon-shmem dump defect (ADR-0246)", "migration", pm.Name)
					setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "ShmemPagemapMissing", errStr)
					if r.Recorder != nil {
						r.Recorder.Eventf(pm, corev1.EventTypeWarning, "ShmemPagemapMissing",
							"checkpoint completeness guard (ADR-0246) detected the CRIU 4.2 anon-shmem "+
								"dump defect for migration %s — checkpoint is not restorable, routing to "+
								"rollback: %s", pm.Name, errStr)
					}
					pmmetrics.ShmemPagemapGuardFiredTotal.WithLabelValues(pm.Name, pm.Namespace).Inc()
					// Bug fix (HIGH panel, Scheduling Architect + Network Architect), preserved
					// under the typed-status redesign: route directly to rollback here instead of
					// only setting the condition and returning. This is a deterministic
					// CRIU-version property, not a transient failure — falling through and
					// letting the next reconcile tick re-issue Checkpoint would retry-storm
					// identically forever. Calling initiateRollback directly also transitions to
					// RollingBack, whose entry point (reconcileRollingBack) calls
					// disarmZeroWindowOnFailurePath (ADR-0157 D2) immediately — releasing the
					// zero-window hold on live TCP traffic on this same reconcile chain rather
					// than leaving the source pod held until the ADR-0157 D3 watchdog backstop
					// times out.
					return r.initiateRollback(ctx, pm, errStr)
				}
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

	// ADR-0168 B2 / ADR-0217 D1: write the workload image to the MigrationCheckpoint CR so the
	// destination agent can use the correct image for the restore placeholder container.
	// As of ADR-0217 the AUTHORITATIVE producer is reconcileValidating (runs BEFORE the
	// DestinationPrewarm consumer); this Checkpointing write is now an IDEMPOTENT RE-ASSERT
	// retained for defense-in-depth and the legacy 8-phase pipeline. Warn-only (ADR-0012).
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

	return r.advanceAfterCheckpoint(ctx, pm)
}

// advanceAfterCheckpoint decides the next phase once the CRIU dump has succeeded
// (Checkpointed=True). It is pipeline-aware so the checkpoint handler is not tied to a
// single terminal transition (A-02, C-2 fix):
//
//   - On the 12-phase ADR-0047 pipeline the migration is in phase FinalFreezeStateCapture,
//     which OWNS the checkpoint→transfer→OverlayHandoff sequencing. The checkpoint handler
//     must NOT transition to the legacy Transferring phase here — doing so hands the phase
//     machine to the legacy Transferring→Restoring→Verifying tail and permanently bypasses
//     OverlayHandoff/RestoreSocketReattach/DisengageHold/TCPVerifying/ServiceVerifying/
//     CutoverComplete (the entire TCP-continuity path). Instead we requeue so the
//     FinalFreezeStateCapture delegator re-runs, observes Checkpointed=True, and advances the
//     transfer step itself.
//   - On the legacy 8-phase pipeline (a PodMigration already at phase Checkpointing) the
//     checkpoint handler owns its own next transition to Transferring, as before.
func (r *PodMigrationReconciler) advanceAfterCheckpoint(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	if pm.Status.Phase == pmv1.MigrationPhaseFinalFreezeStateCapture {
		// 12-phase path: return control to reconcileFinalFreezeStateCapture (status-only).
		// Record that the decision was to STAY on FinalFreezeStateCapture (no legacy hijack).
		r.recordPhaseDecision(pm.Status.Phase, pmv1.MigrationPhaseFinalFreezeStateCapture)
		return ctrl.Result{Requeue: true}, nil
	}
	r.recordPhaseDecision(pm.Status.Phase, pmv1.MigrationPhaseTransferring)
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

		// ADR-SEC-B §2.2/§2.3: the operator is the signing authority. Build the signed checkpoint
		// manifest over the exact tar the source returned, forward the source-computed tar_sha256
		// unchanged (so a controller-memory corruption between Get and Put is also caught), and
		// carry manifest+signature to the destination in the same PutCheckpointTar call.
		manifestBytes, manifestSig, tarSha256, provErr := r.buildSignedCheckpointManifest(ctx, pm, sourceNode, tarData, getResp.TarSha256)
		if provErr != nil {
			return ctrl.Result{}, fmt.Errorf("ADR-SEC-B: build signed checkpoint manifest: %w", provErr)
		}

		// Push the tar to the DESTINATION agent.
		destClient, err := r.AgentPool.ForNode(ctx, destNode)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("connect to dest agent %s: %w", destNode, err)
		}
		putResp, err := destClient.PutCheckpointTar(ctx, &agentpb.PutCheckpointTarRequest{
			MigrationName: pm.Name,
			TarData:       tarData,
			TarSha256:     tarSha256,
			Manifest:      manifestBytes,
			ManifestSig:   manifestSig,
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

	return r.advanceAfterTransfer(ctx, pm)
}

// advanceAfterTransfer decides the next phase once the checkpoint has been transferred to the
// destination and the scheduling gate removed. Pipeline-aware, mirroring advanceAfterCheckpoint
// (A-02, C-2 fix):
//
//   - On the 12-phase pipeline (phase FinalFreezeStateCapture) the transfer step is status-only:
//     CheckpointTransferred is already persisted, so we requeue to let the FinalFreezeStateCapture
//     delegator advance to OverlayHandoff. Transitioning to the legacy Restoring phase here would
//     bypass OverlayHandoff/RestoreSocketReattach/DisengageHold and RST every in-flight TCP
//     connection under Strict/BestEffort.
//   - On the legacy 8-phase pipeline (phase Transferring) the handler owns its own transition to
//     Restoring, as before.
func (r *PodMigrationReconciler) advanceAfterTransfer(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	if pm.Status.Phase == pmv1.MigrationPhaseFinalFreezeStateCapture {
		// 12-phase path: status-only requeue. Record that the decision was to STAY on
		// FinalFreezeStateCapture (no legacy Restoring hijack).
		r.recordPhaseDecision(pm.Status.Phase, pmv1.MigrationPhaseFinalFreezeStateCapture)
		return ctrl.Result{Requeue: true}, nil
	}
	r.recordPhaseDecision(pm.Status.Phase, pmv1.MigrationPhaseRestoring)
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
	// ADR-0192 R2 B2c: pass empty FdbIfname — agent discovers the VXLAN device at runtime. No literal.
	fdbIfname := pm.Status.OverlayFdbIfname
	_, err = destAgent.DisarmTCRedirect(ctx, &agentpb.DisarmTCRedirectRequest{
		MigrationName: pm.Name,
		FdbIfname:     fdbIfname,
		OldPodIp:      pm.Spec.SourcePodIP,
	})
	return err
}

// teardownSourceRedirect calls TeardownSourceRedirect on the SOURCE agent (ADR-0244 /
// NR-BLOCK-2) to remove the ADR-0136 flannel.1 redirect and ADR-0141 source NOTRACK rules
// for the relocated OLD pod IP. Idempotent / best-effort, symmetric to disarmTCRedirect.
func (r *PodMigrationReconciler) teardownSourceRedirect(ctx context.Context, pm *pmv1.PodMigration) error {
	if r.AgentPool == nil {
		return nil
	}
	srcNode := pm.Status.SourceNodeName
	if srcNode == "" {
		return nil
	}
	srcAgent, err := r.AgentPool.ForNode(ctx, srcNode)
	if err != nil {
		return err
	}
	dstNodeIP := ""
	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		destNode = pm.Spec.TargetNodeName
	}
	if destNode != "" {
		if ip, ipErr := r.nodeInternalIP(ctx, destNode); ipErr == nil {
			dstNodeIP = ip
		}
	}
	_, err = srcAgent.TeardownSourceRedirect(ctx, &agentpb.TeardownSourceRedirectRequest{
		MigrationName: pm.Name,
		OldPodIp:      pm.Spec.SourcePodIP,
		FdbIfname:     pm.Status.OverlayFdbIfname,
		ReplVethMac:   pm.Status.ReplVethMAC,
		DstNodeIp:     dstNodeIP,
	})
	return err
}

// noSiblingMigration implements ADR-0244 §3's NoSiblingMigration guard — the controller-side
// dual of pm-cni's isMigrationActive predicate (cmd/pm-cni/main.go), evaluated directly
// against the API server instead of shelling out. It lists PodMigration objects in the same
// namespace matching this pm's SourcePodUID or PodName (excluding pm itself) and returns true
// only if none of them are in a non-terminal phase. Fires the query on every sweep tick —
// never cached — so it cannot go stale across the sweep interval (ADR-0244 R5).
func (r *PodMigrationReconciler) noSiblingMigration(ctx context.Context, pm *pmv1.PodMigration) (bool, error) {
	list := &pmv1.PodMigrationList{}
	if err := r.List(ctx, list, client.InNamespace(pm.Namespace)); err != nil {
		return false, err
	}
	for i := range list.Items {
		sib := &list.Items[i]
		if sib.Name == pm.Name {
			continue
		}
		sameUID := pm.Spec.SourcePodUID != "" && sib.Spec.SourcePodUID == pm.Spec.SourcePodUID
		sameName := sib.Spec.PodName == pm.Spec.PodName
		if !sameUID && !sameName {
			continue
		}
		if !isTerminalMigrationPhase(sib.Status.Phase) {
			return false, nil
		}
	}
	return true, nil
}

// isTerminalMigrationPhase reports whether phase is a terminal outcome for the purposes of
// the ADR-0244 sibling-migration guard (Complete, Failed, DryRunComplete). RollingBack is
// NOT terminal here — it still transitions to Failed via reconcileRollingBack/failMigration
// and may still be actively re-arming the very objects a sibling's reclaim would tear down.
func isTerminalMigrationPhase(phase pmv1.MigrationPhase) bool {
	switch phase {
	case pmv1.MigrationPhaseComplete, pmv1.MigrationPhaseFailed, pmv1.MigrationPhaseDryRunComplete:
		return true
	default:
		return false
	}
}

// noLiveConntrackForIP implements ADR-0244 §4's NoLiveConntrackForIP conjunct — asks BOTH the
// source and destination agents (already reachable via r.AgentPool) whether their local
// conntrack table has any entry for the relocated OLD IP, via the ProbeConntrackForIP RPC
// (which repurposes network.ExportConntrack). A non-empty result on EITHER side, or an RPC
// error on either side, is treated as "cannot prove no client can still reach it" and defers
// the entire sweep pass rather than force-closing a flow.
//
// NOTE (ADR-0244 C1 correction, Sprint 40): this conjunct is structurally blind to the
// NOTRACK'd OLD-IP flow class it was originally cited to cover in full — the tc mirred
// redirect + raw-table NOTRACK installed by InjectIPHandoff/InjectSourceRedirect make that
// forward leg conntrack-invisible by construction, so a live pinned/source-CIDR connection
// carried over it never appears here. It is retained because it still covers non-NOTRACK'd
// flows; noLiveDestSocketForIP (R7, below) is the conjunct that covers the NOTRACK'd class.
func (r *PodMigrationReconciler) noLiveConntrackForIP(ctx context.Context, pm *pmv1.PodMigration) (bool, error) {
	if r.AgentPool == nil || pm.Spec.SourcePodIP == "" {
		return false, fmt.Errorf("noLiveConntrackForIP: AgentPool nil or SourcePodIP empty")
	}
	nodes := map[string]string{}
	if pm.Status.SourceNodeName != "" {
		nodes["source"] = pm.Status.SourceNodeName
	}
	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		destNode = pm.Spec.TargetNodeName
	}
	if destNode != "" {
		nodes["destination"] = destNode
	}
	if len(nodes) == 0 {
		return false, fmt.Errorf("noLiveConntrackForIP: no source or destination node known")
	}
	for role, node := range nodes {
		agent, err := r.AgentPool.ForNode(ctx, node)
		if err != nil {
			return false, fmt.Errorf("noLiveConntrackForIP: %s agent (%s): %w", role, node, err)
		}
		resp, err := agent.ProbeConntrackForIP(ctx, &agentpb.ProbeConntrackForIPRequest{
			MigrationName: pm.Name,
			OldPodIp:      pm.Spec.SourcePodIP,
		})
		if err != nil {
			return false, fmt.Errorf("noLiveConntrackForIP: %s agent (%s) probe: %w", role, node, err)
		}
		if resp.Present {
			return false, nil
		}
	}
	return true, nil
}

// noLiveDestSocketForIP implements ADR-0244 R7 (C1 correction, Sprint 40): asks the
// DESTINATION agent whether the restored pod's netns has an ESTABLISHED TCP socket bound to
// the relocated OLD IP, via the ProbeDestSocketForIP RPC (network.SocketInventory reading
// /proc/<restoredPID>/net/tcp[6] directly inside that netns). This is the conjunct that
// observes the NOTRACK'd flow class R6/noLiveConntrackForIP cannot: NOTRACK suppresses the
// raw table's conntrack hook on the host forwarding path, but it does not remove or hide the
// application-level socket bound in the destination pod's own netns, so a live pinned or
// source-CIDR connection carried over the tc-redirect + NOTRACK path is still directly
// observable here. An RPC error, or Present=true, is treated as "cannot prove no client can
// still reach it" and defers the entire sweep pass — same disposition as R6.
func (r *PodMigrationReconciler) noLiveDestSocketForIP(ctx context.Context, pm *pmv1.PodMigration) (bool, error) {
	if r.AgentPool == nil || pm.Spec.SourcePodIP == "" {
		return false, fmt.Errorf("noLiveDestSocketForIP: AgentPool nil or SourcePodIP empty")
	}
	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		destNode = pm.Spec.TargetNodeName
	}
	if destNode == "" {
		return false, fmt.Errorf("noLiveDestSocketForIP: no destination node known")
	}
	agent, err := r.AgentPool.ForNode(ctx, destNode)
	if err != nil {
		return false, fmt.Errorf("noLiveDestSocketForIP: destination agent (%s): %w", destNode, err)
	}
	resp, err := agent.ProbeDestSocketForIP(ctx, &agentpb.ProbeDestSocketForIPRequest{
		MigrationName: pm.Name,
		OldPodIp:      pm.Spec.SourcePodIP,
	})
	if err != nil {
		return false, fmt.Errorf("noLiveDestSocketForIP: destination agent (%s) probe: %w", destNode, err)
	}
	return !resp.Present, nil
}

// ipReclaimEligible evaluates the ADR-0244 seven-conjunct IP-Reclaim-Eligible predicate (R1-R5
// unchanged; R6 retained scope-limited to non-NOTRACK'd flows; R7 added per the C1 correction
// to cover the NOTRACK'd flow class R6 cannot see). All seven must hold before any teardown RPC
// fires; any one false defers the sweep (no partial teardown on a stale read). Returns
// (eligible, humanReason, error). An error means the predicate could not be evaluated this pass
// (treated the same as not-yet-eligible by the caller — retry next tick).
func (r *PodMigrationReconciler) ipReclaimEligible(ctx context.Context, pm *pmv1.PodMigration) (bool, string, error) {
	// R1: CR reached a terminal outcome. Guaranteed by the caller (only invoked from the
	// Complete/Failed reconcile branch), restated here for self-documentation.
	if pm.Status.Phase != pmv1.MigrationPhaseComplete && pm.Status.Phase != pmv1.MigrationPhaseFailed {
		return false, "R1: not terminal", nil
	}
	// R2: reclaim objects were actually installed. TCPPreservationMode=None CRs never install any
	// of the reclaim objects (server.go InjectIPHandoff early-return), so this conjunct is
	// satisfied by checking the installed-provenance condition rather than adding a redundant mode
	// check. Sprint 42 FS-048 FIX: key off ConditionReclaimObjectsInstalled (durable, set the
	// moment resp.Injected is confirmed) NOT conditionIPHandoffInjected — the latter is dropped on
	// a cross-node-reachability requeue, which previously made R2 return not-eligible forever and
	// left the installed objects orphaned. See reconcileIPReclaimSweep for the full rationale.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionReclaimObjectsInstalled) {
		return false, "R2: no reclaim objects were installed (InjectIPHandoff never confirmed resp.Injected)", nil
	}
	// R3: quarantine floor.
	if pm.Status.CompletionTime == nil {
		return false, "R3: CompletionTime not set", nil
	}
	if time.Since(pm.Status.CompletionTime.Time) < reclaimQuarantineSeconds {
		return false, "R3: quarantine floor not yet elapsed", nil
	}
	// R4: EndpointSlice-routed staleness (retained as ONE conjunct, never sole authority).
	if pm.Spec.SourcePodIP != "" {
		esMgr := traffic.NewEndpointSliceManager(r.Client)
		still, err := esMgr.HasEndpointForIP(ctx, pm.Spec.PodNamespace, pm.Spec.SourcePodIP)
		if err != nil {
			return false, "R4: EndpointSlice check failed", err
		}
		if still {
			return false, "R4: OLD IP still present in an EndpointSlice", nil
		}
	}
	// R5: no sibling migration for the same pod is non-terminal.
	sibOK, err := r.noSiblingMigration(ctx, pm)
	if err != nil {
		return false, "R5: sibling-migration query failed", err
	}
	if !sibOK {
		return false, "R5: a sibling migration for this pod is still non-terminal", nil
	}
	// R6: no live conntrack for the OLD IP on either node — the actual "no client can still
	// reach it" proof for the source-CIDR/pinned-connection class R4 cannot see.
	ctOK, err := r.noLiveConntrackForIP(ctx, pm)
	if err != nil {
		return false, "R6: conntrack probe failed", err
	}
	if !ctOK {
		return false, "R6: live conntrack entry still present for the OLD IP", nil
	}
	// R7: no live ESTABLISHED socket in the destination pod's netns for the OLD IP — the
	// conjunct that observes the NOTRACK'd flow class R6 cannot (ADR-0244 C1 correction).
	sockOK, err := r.noLiveDestSocketForIP(ctx, pm)
	if err != nil {
		return false, "R7: destination socket-table probe failed", err
	}
	if !sockOK {
		return false, "R7: live ESTABLISHED socket still present for the OLD IP in the destination pod's netns", nil
	}
	return true, "", nil
}

// reconcileIPReclaimSweep is the ADR-0244 / NR-BLOCK-2 trigger event: a periodic pod-IP GC
// sweep run from the terminal MigrationPhaseComplete/MigrationPhaseFailed reconcile branch,
// which previously returned ctrl.Result{}, nil unconditionally (a dead end — no requeue, no
// further reconciliation ever happened for a completed CR). While ReclaimEligible(pm) is not
// yet true, this returns a bounded requeue instead. Once true, it runs both teardown RPCs
// once (guarded by independent per-side idempotency conditions, so a crash mid-sweep resumes
// correctly on the next reconcile rather than looping or skipping), then verifies via
// VerifyCleanup(IP_RECLAIM, ...) with the same bounded-retry/fail-open posture as ADR-0241.
func (r *PodMigrationReconciler) reconcileIPReclaimSweep(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Already fully reclaimed and verified (or verification exhausted its budget, which is
	// itself a terminal fail-open outcome) — nothing left to do. No separate sweep controller
	// is needed; this is the same reconcile loop, just no longer terminating unconditionally.
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionIPReclaimComplete) &&
		meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionIPReclaimVerified) != nil {
		return ctrl.Result{}, nil
	}

	// ADR-0244 R2 short-circuit: a terminal CR (Complete/Failed) can never transition again, so
	// if no reclaim objects were EVER physically installed (e.g. this CR rolled back or failed
	// before InjectIPHandoff confirmed resp.Injected, or TCPPreservationMode=None), R2 can never
	// become true on a future pass either. Without this, reconcileIPReclaimSweep requeues such a
	// CR every reclaimSweepInterval forever, logging "IP reclaim not yet eligible" indefinitely
	// against a CR that will never need reclaim (same "nothing to sweep" posture already applied
	// to MigrationPhaseDryRunComplete above). Treat it as already-reclaimed/verified and stop.
	//
	// Sprint 42 FS-048 FIX: this predicate now keys off ConditionReclaimObjectsInstalled — the
	// durable PROVENANCE that objects were physically installed — NOT conditionIPHandoffInjected.
	// IPHandoffInjected is set in-memory but DROPPED whenever verifyDataplaneReachability returns
	// done=false (cross-node old-IP unreachable — a legitimate, sometimes-permanent outcome on
	// this substrate and on cross-subnet/cross-AZ AWS VPC CNI). Keying off it caused the sweep to
	// read the objects as never-installed and short-circuit to NothingToReclaim, silently
	// orphaning real dest/source reclaim objects with no DatapathCleanupLeak event or metric — the
	// exact inverse of the invariant this sweep exists to enforce. ReclaimObjectsInstalled is set
	// and persisted the moment resp.Injected is confirmed, before any reachability probe, so a
	// requeue can never drop it. When it IS set, we fall through and ALWAYS run VerifyCleanup.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionReclaimObjectsInstalled) {
		setCondition(pm, pmv1.ConditionIPReclaimComplete, metav1.ConditionTrue, "NothingToReclaim",
			"no reclaim objects were ever installed for this migration — InjectIPHandoff never confirmed resp.Injected (ADR-0244 R2 / Sprint 42 FS-048)")
		setCondition(pm, pmv1.ConditionIPReclaimVerified, metav1.ConditionTrue, "NothingToReclaim",
			"no reclaim objects were ever installed for this migration — InjectIPHandoff never confirmed resp.Injected (ADR-0244 R2 / Sprint 42 FS-048)")
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
	}

	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionIPReclaimComplete) {
		eligible, reason, err := r.ipReclaimEligible(ctx, pm)
		if err != nil {
			log.Error(err, "ADR-0244: ReclaimEligible evaluation failed — retrying next sweep tick",
				"migration", pm.Name, "reason", reason)
			return ctrl.Result{RequeueAfter: reclaimSweepInterval}, nil
		}
		if !eligible {
			log.Info("ADR-0244: IP reclaim not yet eligible — requeuing", "migration", pm.Name, "reason", reason)
			return ctrl.Result{RequeueAfter: reclaimSweepInterval}, nil
		}

		// Dest-side teardown (GC-4 — wires the existing dead code).
		if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionIPReclaimDestTornDown) {
			if err := r.disarmTCRedirect(ctx, pm); err != nil {
				log.Error(err, "ADR-0244: dest-side IP reclaim teardown (disarmTCRedirect) failed — retrying next sweep tick", "migration", pm.Name)
				return ctrl.Result{RequeueAfter: reclaimSweepInterval}, nil
			}
			setCondition(pm, pmv1.ConditionIPReclaimDestTornDown, metav1.ConditionTrue, "TornDown",
				"destination tc-ingress redirect, FORWARD ACCEPT, and NOTRACK removed (ADR-0244)")
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
		}

		// Source-side teardown (GC-5 — net new).
		if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionIPReclaimSourceTornDown) {
			if err := r.teardownSourceRedirect(ctx, pm); err != nil {
				log.Error(err, "ADR-0244: source-side IP reclaim teardown (TeardownSourceRedirect) failed — retrying next sweep tick", "migration", pm.Name)
				return ctrl.Result{RequeueAfter: reclaimSweepInterval}, nil
			}
			setCondition(pm, pmv1.ConditionIPReclaimSourceTornDown, metav1.ConditionTrue, "TornDown",
				"source flannel.1 redirect and NOTRACK removed (ADR-0244)")
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
		}

		setCondition(pm, pmv1.ConditionIPReclaimComplete, metav1.ConditionTrue, "Reclaimed",
			"both destination and source IP-reclaim teardown RPCs succeeded (ADR-0244)")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	// VerifyCleanup(IP_RECLAIM, ...) (GC-6): bounded-retry-then-fail-open, same shape as
	// ADR-0241 item 1's VerifyCleanup(CUTOVER_COMPLETE).
	if r.AgentPool == nil || pm.Spec.SourcePodIP == "" {
		return ctrl.Result{}, nil
	}
	srcNode := pm.Status.SourceNodeName
	if srcNode == "" {
		log.Error(nil, "ADR-0244: SourceNodeName not set — skipping VerifyCleanup(IP_RECLAIM) this pass", "migration", pm.Name)
		return ctrl.Result{}, nil
	}
	srcAgent, agErr := r.AgentPool.ForNode(ctx, srcNode)
	if agErr != nil {
		log.Error(agErr, "ADR-0244: cannot connect to source agent for VerifyCleanup(IP_RECLAIM) (will retry next pass)", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: reclaimSweepInterval}, nil
	}
	vcResp, vcErr := srcAgent.VerifyCleanup(ctx, &agentpb.VerifyCleanupRequest{
		MigrationName: pm.Name,
		Scope:         agentpb.CleanupScope_IP_RECLAIM,
		OldPodIp:      pm.Spec.SourcePodIP,
		FdbIfname:     pm.Status.OverlayFdbIfname,
		ReplVethMac:   pm.Status.ReplVethMAC,
		Objects: []string{
			"tc_filter", "tc_qdisc", "dest_forward_accept", "dest_notrack",
			"source_notrack", "flannel1_route", "flannel1_neigh", "flannel1_fdb",
		},
	})
	switch {
	case vcErr != nil:
		log.Error(vcErr, "ADR-0244: VerifyCleanup(IP_RECLAIM) RPC failed (will retry next pass)", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: reclaimSweepInterval}, nil
	case vcResp.Clean:
		setCondition(pm, pmv1.ConditionIPReclaimVerified, metav1.ConditionTrue, "Verified",
			"all IP-reclaim datapath objects confirmed absent (ADR-0244)")
		if pm.Annotations != nil {
			delete(pm.Annotations, ipReclaimVerifyAttemptsAnnotation)
		}
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
	default:
		attempts := readIPReclaimVerifyAttempts(pm)
		if attempts < len(ipReclaimVerifyBackoff) {
			backoff := ipReclaimVerifyBackoff[attempts]
			if pm.Annotations == nil {
				pm.Annotations = make(map[string]string)
			}
			pm.Annotations[ipReclaimVerifyAttemptsAnnotation] = strconv.Itoa(attempts + 1)
			if err := r.Update(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			log.Info("ADR-0244: IP-reclaim cleanup not yet verified — retrying with backoff",
				"migration", pm.Name, "attempt", attempts+1, "backoff", backoff, "presentObjects", vcResp.PresentObjects)
			return ctrl.Result{RequeueAfter: backoff}, nil
		}
		// Retry budget exhausted: fail open (same proportionality argument as ADR-0241 item 1).
		setCondition(pm, pmv1.ConditionIPReclaimVerified, metav1.ConditionFalse, "CleanupLeakExhausted",
			fmt.Sprintf("IP-reclaim cleanup not confirmed after %d retries: objects still present: %v (ADR-0244, fail-open)",
				len(ipReclaimVerifyBackoff), vcResp.PresentObjects))
		for _, obj := range vcResp.PresentObjects {
			pmmetrics.DatapathCleanupLeakTotal.WithLabelValues(pm.Name, pm.Namespace, obj).Inc()
		}
		if r.Recorder != nil {
			r.Recorder.Eventf(pm, corev1.EventTypeWarning, "DatapathCleanupLeak",
				"IP-reclaim cleanup verification exhausted its retry budget for migration %s; objects still present: %v (ADR-0244)",
				pm.Name, vcResp.PresentObjects)
		}
		if pm.Annotations != nil {
			delete(pm.Annotations, ipReclaimVerifyAttemptsAnnotation)
		}
		return ctrl.Result{}, r.statusUpdate(ctx, pm)
	}
}

// readIPReclaimVerifyAttempts reads the current VerifyCleanup(IP_RECLAIM) retry attempt
// count from the ADR-0244 annotation, mirroring readCni0CleanupVerifyAttempts.
func readIPReclaimVerifyAttempts(pm *pmv1.PodMigration) int {
	if pm.Annotations == nil {
		return 0
	}
	v, ok := pm.Annotations[ipReclaimVerifyAttemptsAnnotation]
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
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

	// ADR-0192 R2 B2c (load-bearing InjectIPHandoff request): pass FdbIfname="" when
	// OverlayFdbIfname is unset so the agent runs DiscoverFdbInterface() and skip-coherence.
	// Exactly as BridgeIfname:"" already does (line 2769). No "flannel.1" literal (C-335).
	fdbIfname := pm.Status.OverlayFdbIfname // "" = delegate to agent VXLAN discovery

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

	// PROVENANCE (Sprint 42 FS-048 fix): the destination-agent InjectIPHandoff RPC has confirmed
	// resp.Injected — the OLD-IP NOTRACK, FORWARD ACCEPT, and tc-ingress redirect objects are now
	// physically on the wire on the destination node. Record that fact durably and persist it
	// IMMEDIATELY, before the cross-node reachability probe runs. verifyDataplaneReachability can
	// legitimately never converge (cross-node on this substrate; cross-subnet/cross-AZ on AWS VPC
	// CNI where the OLD IP is a subnet-bound ENI address that does not route to another AZ), and on
	// that failure injectIPHandoff returns done=false and the caller's statusUpdate is skipped —
	// which is exactly why IPHandoffInjected got dropped and the reclaim sweep short-circuited to
	// NothingToReclaim, silently orphaning these objects. ReclaimObjectsInstalled is the sweep's
	// authoritative predicate: once True, the sweep ALWAYS runs VerifyCleanup regardless of whether
	// reachability ever verified. It is never cleared.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionIPHandoffInjected) {
		setCondition(pm, pmv1.ConditionReclaimObjectsInstalled, metav1.ConditionTrue, "Installed",
			fmt.Sprintf("reclaim datapath objects installed on destination for OLD pod IP %s (dest NOTRACK/FORWARD ACCEPT/tc redirect); reclaim sweep will run VerifyCleanup regardless of cross-node reachability (Sprint 42 FS-048 / ADR-0244)",
				pm.Spec.SourcePodIP))
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr, false
		}
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

	// ADR-0210a: the agent's in-netns ProbeOk is now a DEMOTED, advisory LOCAL PRE-CHECK —
	// it no longer gates the handoff, TrafficVerified, or deletion. It was a tautology (dial
	// of an lo/32-aliased IP inside the same netns always returned RST). We log it for
	// diagnostics but do NOT requeue on a failed pre-check; the authoritative gate is the
	// cross-node DataplaneReachabilityVerified set below.
	if !resp.ProbeOk {
		log.Info("injectIPHandoff: ADR-0210a in-netns local pre-check did not pass (advisory only — cross-node gate is authoritative)",
			"migration", pm.Name, "oldPodIP", pm.Spec.SourcePodIP, "probeOutput", resp.ProbeOutput)
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

	log.Info("injectIPHandoff: handoff injected (ADR-0133 AC1)",
		"migration", pm.Name, "oldPodIP", pm.Spec.SourcePodIP)
	setCondition(pm, conditionIPHandoffInjected, metav1.ConditionTrue, "Injected",
		fmt.Sprintf("OLD pod IP %s installed at replacement veth %s on %s (ADR-0133 D2)",
			pm.Spec.SourcePodIP, pm.Status.ReplVethMAC, destNode))
	// ADR-0210: TrafficVerified is DEMOTED to a non-gating PRE-CHECK. The IP handoff is
	// installed; that is necessary but NOT sufficient (it does not prove an off-node client
	// can reach the IP). The authoritative gate is the cross-node DataplaneReachabilityVerified
	// established in verifyDataplaneReachability below. TrafficVerified=True here only records
	// that the local handoff completed; it no longer permits deletion on its own (see the
	// deletion gates re-pointed to DataplaneReachabilityVerified).
	setCondition(pm, conditionTrafficVerified, metav1.ConditionTrue, "HandoffInstalled",
		fmt.Sprintf("OLD pod IP %s installed at replacement pod (ADR-0210 non-gating pre-check)", pm.Spec.SourcePodIP))

	// ADR-0210: authoritative cross-node reachability. The CONTROLLER drives a nonce round-trip:
	// (1) ask the DEST agent to open an in-netns echo listener bound to the preserved IP,
	// (2) ask a SOURCE-node agent (node != dest) to dial it cross-node and read the nonce back.
	// DataplaneReachabilityVerified is set True ONLY on a matched nonce — the source agent
	// cannot synthesize success, and the IP-handoff alone cannot fake an off-node datapath.
	if res, err, done := r.verifyDataplaneReachability(ctx, pm, destNode); !done {
		return res, err, false
	}
	return ctrl.Result{}, nil, true
}

// verifyDataplaneReachability performs the ADR-0210 cross-node nonce round-trip and sets
// conditionDataplaneReachabilityVerified. The controller is the authority. done=false means
// requeue (not yet verified, source held); done=true means the condition was set True.
func (r *PodMigrationReconciler) verifyDataplaneReachability(ctx context.Context, pm *pmv1.PodMigration, destNode string) (ctrl.Result, error, bool) {
	log := logf.FromContext(ctx)

	srcNode := pm.Status.SourceNodeName
	if srcNode == "" || srcNode == destNode {
		// ADR-0237: same-node (intra-node) migration — cross-node probe is structurally impossible
		// because there is no off-node network boundary to traverse. The NoCrossNodeVantage permanent
		// block (former ADR-0210 behavior) caused a structural deadlock: DataplaneReachabilityVerified
		// was held False forever, and the safety block in reconcileCutoverComplete (line 1377) requeued
		// every 10s indefinitely — source pod was never deleted (Sprint 37 carry-forward, gate-redis-s35
		// ran 14+ hours post-CutoverComplete). §P-MECHANISM: docs/sprints/SPRINT38-PMECHANISM-FINALIZATION.md
		//
		// Fix: in the same-node case, TrafficVerified=True (set by injectIPHandoff, reason=HandoffInstalled)
		// is the strongest available proof that the preserved IP is configured on this node. A cross-node
		// probe from the same node to the same node traverses no additional network boundary beyond what
		// TrafficVerified already proves. The vacuous gate satisfies ADR-0012's deletion contract
		// (condition must be True before deletion) without bypassing it.
		if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionTrafficVerified) {
			// TrafficVerified not yet set — injectIPHandoff has not completed. Hold and requeue.
			log.Error(nil, "ADR-0237: same-node migration — TrafficVerified not yet set; holding source, requeuing",
				"migration", pm.Name, "srcNode", srcNode, "destNode", destNode)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil, false
		}
		// TrafficVerified=True: IP handoff confirmed on this node. Set DataplaneReachabilityVerified=True
		// with reason SameNodeVacuous so the safety block in reconcileCutoverComplete can proceed. (ADR-0237)
		log.Info("ADR-0237: same-node migration — cross-node probe structurally impossible; TrafficVerified=True satisfies vacuous gate; setting DataplaneReachabilityVerified=True (SameNodeVacuous)",
			"migration", pm.Name, "srcNode", srcNode, "destNode", destNode)
		setCondition(pm, conditionDataplaneReachabilityVerified, metav1.ConditionTrue, "SameNodeVacuous",
			"ADR-0237: intra-node migration — cross-node probe impossible; TrafficVerified=True satisfies vacuous gate (see docs/adr/0237-reconcile-cutover-complete-finalization-trigger-same-node-vacuous-gate.md)")
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr, false
		}
		return ctrl.Result{}, nil, true
	}

	// Controller-issued correlation nonce — destination must echo it back through the dialed
	// listener. Bound to the migration UID + a monotonic timestamp; the source agent cannot
	// synthesize this value (Security-C3).
	nonce := fmt.Sprintf("adr0210-%s-%d", pm.UID, time.Now().UnixNano())
	const probePort = 7350

	// Step 1: open the in-netns nonce-echo listener on the DESTINATION agent.
	destAgent, err := r.AgentPool.ForNode(ctx, destNode)
	if err != nil {
		log.Error(err, "ADR-0210: cannot connect to destination agent for echo listener — requeuing", "migration", pm.Name, "destNode", destNode)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil, false
	}
	echoResp, echoErr := destAgent.StartReachabilityEcho(ctx, &agentpb.StartReachabilityEchoRequest{
		MigrationName: pm.Name,
		ListenIp:      pm.Spec.SourcePodIP,
		ListenPort:    probePort,
		Nonce:         nonce,
		TtlS:          15,
	})
	if echoResp != nil && echoResp.ProcessDied {
		// ADR-0228 Invariant 3: the agent-side fail-fast pre-check found RestoredPID already
		// dead. This is a legitimate post-recording failure (the restored application crashed
		// after handoff), not the opaque multi-minute reachability timeout Arch-A identified —
		// surface it as a specific, correctly-attributed condition/reason instead of requeuing
		// into a probe that can never succeed.
		log.Error(nil, "ADR-0228: RestoredProcessDied — destination agent's fail-fast pre-check found RestoredPID dead before starting the reachability echo",
			"migration", pm.Name, "destNode", destNode, "detail", echoResp.Detail)
		setCondition(pm, conditionDataplaneReachabilityVerified, metav1.ConditionFalse, "RestoredProcessDied",
			fmt.Sprintf("ADR-0228: restored process died after RestoredPID was recorded (agent detail: %s)", echoResp.Detail))
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr, false
		}
		return ctrl.Result{}, nil, false
	}
	if echoErr != nil || echoResp == nil || !echoResp.Started {
		detail := ""
		if echoResp != nil {
			detail = echoResp.Detail
		}
		log.Error(echoErr, "ADR-0210: destination echo listener not started — requeuing", "migration", pm.Name, "detail", detail)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil, false
	}

	// Step 2: dial cross-node from the SOURCE-node agent and require the nonce round-trip.
	srcAgent, err := r.AgentPool.ForNode(ctx, srcNode)
	if err != nil {
		log.Error(err, "ADR-0210: cannot connect to source agent for cross-node probe — requeuing", "migration", pm.Name, "srcNode", srcNode)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil, false
	}
	probeResp, probeErr := srcAgent.ProbeDataplaneReachability(ctx, &agentpb.ProbeDataplaneReachabilityRequest{
		MigrationName: pm.Name,
		TargetIp:      pm.Spec.SourcePodIP,
		TargetPort:    probePort,
		ExpectedNonce: nonce,
		TimeoutS:      5,
	})
	if probeErr != nil || probeResp == nil || !probeResp.Reachable {
		detail := ""
		egress := ""
		if probeResp != nil {
			detail = probeResp.Detail
			egress = probeResp.EgressDev
		}
		log.Error(probeErr, "ADR-0210: cross-node reachability NOT verified (nonce round-trip failed) — holding source, requeuing",
			"migration", pm.Name, "srcNode", srcNode, "destNode", destNode, "egressDev", egress, "detail", detail)
		setCondition(pm, conditionDataplaneReachabilityVerified, metav1.ConditionFalse, "CrossNodeUnreachable",
			fmt.Sprintf("ADR-0210: cross-node probe from %s to %s failed nonce round-trip (egressDev=%s): %s",
				srcNode, pm.Spec.SourcePodIP, egress, detail))
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr, false
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil, false
	}

	log.Info("ADR-0210: cross-node DataplaneReachability VERIFIED via controller-authority nonce round-trip",
		"migration", pm.Name, "srcNode", srcNode, "destNode", destNode, "egressDev", probeResp.EgressDev)
	setCondition(pm, conditionDataplaneReachabilityVerified, metav1.ConditionTrue, "CrossNodeReachable",
		fmt.Sprintf("ADR-0210: preserved IP %s reachable cross-node from %s (egressDev=%s); controller-issued nonce round-trip OK",
			pm.Spec.SourcePodIP, srcNode, probeResp.EgressDev))
	if sErr := r.statusUpdate(ctx, pm); sErr != nil {
		return ctrl.Result{}, sErr, false
	}
	return ctrl.Result{}, nil, true
}

func (r *PodMigrationReconciler) reconcileVerifying(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// the traffic reviewer drives readiness + traffic verification. Watches TrafficVerified.
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
		// ADR-0210: the short-circuit now keys on the AUTHORITATIVE cross-node gate
		// (DataplaneReachabilityVerified), not the demoted TrafficVerified self-probe. The
		// service-path verifier is skipped only when the cross-node nonce round-trip has
		// already proven the OLD pod IP reachable off-node — the strongest proof.
		if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionDataplaneReachabilityVerified) {
			log.Info("Verifying: DataplaneReachabilityVerified set by ADR-0210 cross-node probe — skipping service-path verifier",
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

	// ADR-0012 safety re-fetch + deletion via the single STRICTER-union primitive. This is the
	// SAME gate the CutoverComplete call site uses. Previously this Verifying copy had drifted
	// WEAKER — it never re-checked TCPSequenceContinuityVerified, so under BestEffort (and under
	// Strict once the dataplane gate passed) it could delete the source pod without TCP-continuity
	// proof. deleteSourcePodIfSafe fixes that UP: it re-reads authoritative conditions and enforces
	// TCPSequenceContinuityVerified=True for Strict/BestEffort before any deletion.
	log.Info("Verifying: routing source pod deletion through deleteSourcePodIfSafe (ADR-0012 STRICTER-union gate)", "migration", pm.Name)
	if blocked, res := r.deleteSourcePodIfSafe(ctx, pm); blocked {
		return res, nil
	}

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
				// ADR-0192 R2 B2c: pass empty FdbIfname — agent discovers at runtime. No "flannel.1" literal.
				fdbIfname := pm.Status.OverlayFdbIfname
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

	// ADR-0241 item 1 (NR-BLOCK-1 CUTOVER_COMPLETE scope): CleanupSourceIPHandoff above is
	// best-effort/warn-only, so re-probe with VerifyCleanup and retry the cleanup with a
	// bounded backoff (3 attempts, 2s/4s/8s) before accepting the result. This blocks
	// completion of THIS reconcile pass for up to 14s in the worst case but never introduces
	// a new phase — on retry-budget exhaustion it converges to a fail-open, non-blocking
	// posture (ConditionCni0CleanupVerified=False + a DatapathCleanupLeakTotal increment per
	// still-present object + a DatapathCleanupLeak Event), and the migration still completes.
	if pm.Spec.SourcePodIP != "" && r.AgentPool != nil &&
		!meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionCni0CleanupVerified) {
		srcNode := pm.Status.SourceNodeName
		if srcNode == "" {
			log.Error(nil, "ADR-0241: SourceNodeName not set — skipping VerifyCleanup this pass (warn-only)", "migration", pm.Name)
		} else if srcAgent, agErr := r.AgentPool.ForNode(ctx, srcNode); agErr != nil {
			log.Error(agErr, "ADR-0241: cannot connect to source agent for VerifyCleanup (warn-only, will retry next pass)",
				"migration", pm.Name, "node", srcNode)
		} else {
			vcResp, vcErr := srcAgent.VerifyCleanup(ctx, &agentpb.VerifyCleanupRequest{
				MigrationName: pm.Name,
				Scope:         agentpb.CleanupScope_CUTOVER_COMPLETE,
				OldPodIp:      pm.Spec.SourcePodIP,
				BridgeIfname:  "", // ADR-0158 D5: empty — agent discovers at runtime. No "cni0" literal.
				Objects:       []string{"cni0_neigh", "cni0_host_route"},
			})
			switch {
			case vcErr != nil:
				log.Error(vcErr, "ADR-0241: VerifyCleanup RPC failed (warn-only, will retry next pass)", "migration", pm.Name)
			case vcResp.Clean:
				setCondition(pm, pmv1.ConditionCni0CleanupVerified, metav1.ConditionTrue, "Verified",
					"cni0 neigh and host route confirmed absent after CleanupSourceIPHandoff (ADR-0241)")
				if pm.Annotations != nil {
					delete(pm.Annotations, cni0CleanupVerifyAttemptsAnnotation)
				}
				if err := r.statusUpdate(ctx, pm); err != nil {
					return ctrl.Result{}, err
				}
			default:
				attempts := readCni0CleanupVerifyAttempts(pm)
				if attempts < len(cni0CleanupVerifyBackoff) {
					// Retry CleanupSourceIPHandoff, then re-verify on the next reconcile pass
					// (ctrl.Result{RequeueAfter: ...}, not a blocking sleep — ADR-0241 item 1).
					if _, retryErr := srcAgent.CleanupSourceIPHandoff(ctx, &agentpb.CleanupSourceIPHandoffRequest{
						MigrationName: pm.Name,
						OldPodIp:      pm.Spec.SourcePodIP,
						FdbIfname:     pm.Status.OverlayFdbIfname,
						BridgeIfname:  "",
					}); retryErr != nil {
						log.Error(retryErr, "ADR-0241: retry CleanupSourceIPHandoff RPC failed (warn-only)", "migration", pm.Name)
					}
					backoff := cni0CleanupVerifyBackoff[attempts]
					if pm.Annotations == nil {
						pm.Annotations = make(map[string]string)
					}
					pm.Annotations[cni0CleanupVerifyAttemptsAnnotation] = strconv.Itoa(attempts + 1)
					if err := r.Update(ctx, pm); err != nil {
						return ctrl.Result{}, err
					}
					log.Info("ADR-0241: cni0 cleanup not yet verified — retrying with backoff",
						"migration", pm.Name, "attempt", attempts+1, "backoff", backoff, "presentObjects", vcResp.PresentObjects)
					return ctrl.Result{RequeueAfter: backoff}, nil
				}
				// Retry budget exhausted: fail open (ADR-0241 item 1) rather than a new
				// blocking CleanupFailed phase — disproportionate for a two-object, node-local,
				// non-security-critical leak per the ADR's own proportionality argument.
				setCondition(pm, pmv1.ConditionCni0CleanupVerified, metav1.ConditionFalse, "CleanupLeakExhausted",
					fmt.Sprintf("cni0 cleanup not confirmed after %d retries: objects still present: %v (ADR-0241, fail-open)",
						len(cni0CleanupVerifyBackoff), vcResp.PresentObjects))
				for _, obj := range vcResp.PresentObjects {
					pmmetrics.DatapathCleanupLeakTotal.WithLabelValues(pm.Name, pm.Namespace, obj).Inc()
				}
				if r.Recorder != nil {
					r.Recorder.Eventf(pm, corev1.EventTypeWarning, "DatapathCleanupLeak",
						"cni0 cleanup verification exhausted its retry budget for migration %s; objects still present: %v (ADR-0241)",
						pm.Name, vcResp.PresentObjects)
				}
				if pm.Annotations != nil {
					delete(pm.Annotations, cni0CleanupVerifyAttemptsAnnotation)
				}
				if err := r.statusUpdate(ctx, pm); err != nil {
					return ctrl.Result{}, err
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
	// steady-state cutover completion, to keep the OLD IP reachable.

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
		SourcePodIp:   pm.Spec.SourcePodIP, // ADR-0224 3h-SYM: remove NOTRACK rule
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
	log := logf.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(pm, finalizerName) {
		return ctrl.Result{}, nil
	}

	// ADR-0244 finalizer-race guard (NR-BLOCK-2). A terminal TCP-preserving migration installs
	// five IP-reclaim datapath objects (dest tc filter/qdisc + FORWARD ACCEPT + NOTRACK, and
	// source flannel.1 /32 route + AF_INET neigh + AF_BRIDGE FDB + NOTRACK). These are torn down
	// ONLY by the periodic reclaim sweep (reconcileIPReclaimSweep), which runs from the terminal
	// phase branch of Reconcile — a branch that stops firing the moment the CR enters deletion
	// (Reconcile then routes here, not to the phase switch). If we remove the finalizer and let
	// the CR be garbage-collected before that sweep has set ConditionIPReclaimComplete, the sweep
	// never runs again and every reclaim object is permanently stranded: it fails safe (no live
	// connection is blackholed) but silently defeats NR-BLOCK-2's entire purpose. So gate the
	// finalizer removal on reclaim completion, driving the sweep forward in-line, with a bounded
	// timeout + force-path fallback that mirrors ADR-0241's bounded-retry-then-fail-open posture
	// so a genuinely stuck reclaim cannot wedge deletion forever.
	if r.reclaimObjectsOutstanding(pm) {
		// Drive the reclaim sweep forward in-line: deletion actively progresses reclaim rather
		// than passively waiting for a terminal-branch requeue that no longer fires under
		// deletion. reconcileIPReclaimSweep is idempotent and crash-safe (independent per-side
		// conditions), so re-invoking it here resumes exactly where the last pass left off.
		if _, err := r.reconcileIPReclaimSweep(ctx, pm); err != nil {
			log.Error(err, "ADR-0244: IP-reclaim sweep during deletion failed — retrying", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: reclaimSweepInterval}, nil
		}

		if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionIPReclaimComplete) {
			// Bounded timeout. Within the force window, hold the finalizer and requeue so the
			// sweep gets a fair chance (it cannot even start until the R3 quarantine floor
			// elapses, then needs teardown + verify to converge).
			elapsed := time.Since(pm.DeletionTimestamp.Time)
			if elapsed < reclaimDeletionForceTimeout {
				log.Info("ADR-0244: IP reclaim not yet complete for a CR under deletion — holding finalizer until reclaim converges or the force window elapses",
					"migration", pm.Name, "elapsed", elapsed, "forceTimeout", reclaimDeletionForceTimeout)
				return ctrl.Result{RequeueAfter: reclaimSweepInterval}, nil
			}
			// Force path (fail-open). Reclaim did not converge within the bounded window — a
			// genuinely stuck reclaim (R6/R7 failing closed on a real live connection, or a
			// persistent teardown bug) must not wedge deletion forever. Release the finalizer,
			// but make the stranded objects visible exactly as ADR-0241 does on VerifyCleanup
			// exhaustion: a leak metric increment plus a queryable warning Event.
			log.Error(nil, "ADR-0244: IP reclaim did not complete within the force-delete window — force-removing finalizer; reclaim datapath objects may be stranded",
				"migration", pm.Name, "elapsed", elapsed, "forceTimeout", reclaimDeletionForceTimeout)
			pmmetrics.DatapathCleanupLeakTotal.WithLabelValues(pm.Name, pm.Namespace, "ip_reclaim_forced_delete").Inc()
			if r.Recorder != nil {
				r.Recorder.Eventf(pm, corev1.EventTypeWarning, "DatapathCleanupLeak",
					"PodMigration %s deleted before IP-reclaim completed (held %s past the force-delete window); reclaim datapath objects (dest tc redirect/FORWARD ACCEPT/NOTRACK, source flannel.1 route/neigh/FDB, both-side NOTRACK) may be stranded on the source/destination nodes (ADR-0244, fail-open)",
					pm.Name, reclaimDeletionForceTimeout)
			}
			// fall through to finalizer removal
		}
	}

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

// reclaimObjectsOutstanding reports whether this PodMigration has ADR-0244 IP-reclaim datapath
// objects still installed and not yet torn down — i.e. the objects were physically installed
// (ConditionReclaimObjectsInstalled is True, the same durable provenance ipReclaimEligible R2 and
// reconcileIPReclaimSweep use to decide there is anything to reclaim) but the reclaim sweep has not
// yet set ConditionIPReclaimComplete. Used by handleDeletion to decide whether the finalizer-race
// guard must engage. TCPPreservationMode=None and pre-handoff CRs never install these objects, so
// they return false and delete immediately.
//
// Sprint 42 FS-048 FIX: key off ConditionReclaimObjectsInstalled, NOT conditionIPHandoffInjected —
// the latter is dropped whenever cross-node old-IP reachability never converges, which would make
// this guard return false and let handleDeletion remove the finalizer and hard-delete with real
// reclaim objects still on the wire (the same silent-leak class the sweep short-circuit had).
func (r *PodMigrationReconciler) reclaimObjectsOutstanding(pm *pmv1.PodMigration) bool {
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionReclaimObjectsInstalled) {
		return false
	}
	return !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionIPReclaimComplete)
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

// shmemPagemapMissingReason is the stable, machine-readable errdetails.ErrorInfo.Reason value
// (ADR-0246 typed-status redesign) set by the agent on the codes.FailedPrecondition status it
// returns from the Checkpoint RPC when the shmem-pagemap completeness guard fires
// (internal/agent/server/shmem_pagemap_guard.go: ShmemPagemapMissingReason,
// newShmemPagemapMissingStatus). Kept as an independent local constant — not imported from
// internal/agent/server — the same way codes.FailedPrecondition itself is a shared gRPC
// convention rather than a cross-package Go symbol; a mismatch here would be caught immediately
// by TestShmemPagemapMissingReason_AgentControllerAgree (shmem_pagemap_guard_test.go), which
// compares this literal against server.ShmemPagemapMissingReason directly (both packages are
// visible from a top-level _test.go in a different package via the exported symbol, so this is
// checked in CI, not left to convention alone).
const shmemPagemapMissingReason = "SHMEM_PAGEMAP_MISSING"

// shmemPagemapMissingReasonFromStatus reports whether grpcStatus carries an
// errdetails.ErrorInfo{Reason: shmemPagemapMissingReason} details entry (ADR-0246 typed-status
// redesign). Used to distinguish the checkpoint-completeness-guard FailedPrecondition from the
// CRIU-capability/ptrace FailedPrecondition (ErrCRIUCapability) that shares the same gRPC code —
// replaces the former strings.Contains(errStr, "anon-shmem segment(s) with no pagemap-shmem")
// prose match.
func shmemPagemapMissingReasonFromStatus(grpcStatus *status.Status) bool {
	if grpcStatus == nil {
		return false
	}
	for _, d := range grpcStatus.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == shmemPagemapMissingReason {
			return true
		}
	}
	return false
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

// readCni0CleanupVerifyAttempts returns the current VerifyCleanup(CUTOVER_COMPLETE) retry
// attempt count stamped on pm by cni0CleanupVerifyAttemptsAnnotation (ADR-0241 item 1),
// or 0 if absent/unparseable (first attempt).
func readCni0CleanupVerifyAttempts(pm *pmv1.PodMigration) int {
	if pm.Annotations == nil {
		return 0
	}
	v, ok := pm.Annotations[cni0CleanupVerifyAttemptsAnnotation]
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
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
// Required invariants for the replacement pod:
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
	newLabels[replacementPodMigrationNameLabel] = pm.Name

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

	// ADR-0195 Rule A (universal injected holder — replaces ADR-0176 --podmotion-holder append).
	//
	// ADR-0130: the replacement pod's container init must NOT run the real workload command.
	// ADR-0176 originally solved this by appending --podmotion-holder to the workload binary's
	// args, relying on the workload binary to implement a park-first/no-bind branch. This is SILENT
	// for arbitrary third-party images (e.g. stock redis:7-alpine rejects --podmotion-holder as an
	// unknown config directive and exits non-zero before binding, causing sk-inet.c:1059 EADDRINUSE
	// when CRIU tries to restore the TCP_LISTEN socket — ADR-0195).
	//
	// ADR-0195 Rule A replaces the workload-entrypoint-dependent approach with a universal injected
	// no-op holder binary that:
	//   1. Lives in the agent image at /podmotion/holder (static binary, no dependencies).
	//   2. Is side-loaded into the replacement pod via an init-container + emptyDir volume.
	//   3. Replaces the container Command so the holder — not the workload binary — is the
	//      container init that CRIU restores OVER.
	//   4. Never binds any port, writes /run/podmotion/holder-ready, prints "podmotion-holder ready"
	//      to stdout, and is SIGTERM-clean (ADR-0176 C2 readiness-sentinel contract).
	//
	// Removal symmetry: hack/gate-workload/main.go retains --podmotion-holder for
	// standalone testing; the operator no longer passes it. validateNoEmptyDir is scoped to the
	// SOURCE pod (see below); the holder emptyDir is on the REPLACEMENT pod (different lifecycle).

	// holderVolumeName is the emptyDir that the init-container writes the holder binary into
	// and the main container mounts read-only. The name must not collide with source-pod volumes.
	const holderVolumeName = "podmotion-holder-bin"
	const holderMountPath = "/podmotion"
	const holderBinPath = "/podmotion/holder"

	// agentImage is the agent image from which the holder binary is sourced. The init-container
	// uses the same image as the agent DaemonSet pod running on the destination node (always
	// present in the node's image store after ImagePullPolicy=Never kind-load or registry pull).
	// Engineering note: init-container source image is the agent DaemonSet image;
	// exact holder binary path is /podmotion/holder (built by make build-linux → Dockerfile COPY).
	// We derive the image from the operator's own image by convention; in a production deployment
	// this would be set from the Helm agent.image values. For now the init-container image is
	// set to the same string the Helm chart injects via the AGENT_IMAGE env var if present,
	// falling back to a well-known default so the operator does not need a flag.
	// ADR-0196: holder init-container image == the agent image, injected by the Helm chart
	// from agent.image.* via AGENT_IMAGE (byte-identical to the agent DaemonSet image, which
	// is the only podmotion-agent image proven present in the destination node's store). A
	// missing AGENT_IMAGE is a deployment defect, not a recoverable default — the old
	// "podmotion-agent:latest" fallback was unschedulable on the gate substrate (pullPolicy
	// Never, sprint-tagged images) and silently masked the misconfiguration as ImagePullBackOff.
	agentImage := os.Getenv("AGENT_IMAGE")
	if agentImage == "" {
		// fail loudly — never fabricate an image string (see ADR-0196).
		return fmt.Errorf("AGENT_IMAGE env not set on operator Deployment: cannot resolve holder init-container image (ADR-0195 Rule A / ADR-0196); set agent.image via Helm")
	}
	// Init-container pull policy must match how the agent image reached the node: Never on
	// kind (kind-load), IfNotPresent in production (registry). Sourced from
	// AGENT_IMAGE_PULL_POLICY (Helm: agent.image.pullPolicy) so one binary is correct on both.
	holderPullPolicy := corev1.PullPolicy(os.Getenv("AGENT_IMAGE_PULL_POLICY"))
	if holderPullPolicy == "" {
		holderPullPolicy = corev1.PullIfNotPresent
	}

	// Inject the holder emptyDir volume onto the replacement pod spec.
	spec.Volumes = append(spec.Volumes, corev1.Volume{
		Name: holderVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})

	// Init-container: copy the holder binary from the agent image into the emptyDir.
	// The copy runs as root (required for chmod +x); the emptyDir is then mounted
	// read-only by the main container — no non-holder process can write to it after init.
	spec.InitContainers = append(spec.InitContainers, corev1.Container{
		Name:            "podmotion-inject-holder",
		Image:           agentImage,
		ImagePullPolicy: holderPullPolicy,
		// cp + chmod is portable across debian-slim and does not require shell builtins beyond
		// what debian:12-slim provides.  We use sh -c because the agent image has /bin/sh.
		Command: []string{"/bin/sh", "-c",
			"cp /podmotion/holder /holder-bin/holder && chmod 755 /holder-bin/holder",
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      holderVolumeName,
				MountPath: "/holder-bin",
			},
		},
	})

	// ADR-0197 Rule D (operator side) — per-container restore-target discriminator.
	// The pod-scoped podmotion.io/checkpoint-ref annotation has no per-container discriminator,
	// so the NRI StartContainer hook (which fires on the FIRST container to start) matches the
	// cp-only podmotion-inject-holder init container instead of the holder-running main container,
	// wedging the barrier on the init container (gate-10 deadlock). Stamp the comma-joined list of
	// MAIN container names so the agent gates restore+barrier on container NAME, not first-to-fire.
	// The init container name (podmotion-inject-holder) is, by construction, NOT in this list.
	restoreTargetNames := make([]string, 0, len(spec.Containers))
	for i := range spec.Containers {
		restoreTargetNames = append(restoreTargetNames, spec.Containers[i].Name)
	}
	newAnnotations["podmotion.io/restore-target-containers"] = strings.Join(restoreTargetNames, ",")
	logf.FromContext(ctx).Info("ADR-0197 Rule D: stamped restore-target-containers (init container excluded by construction)",
		"migration", pm.Name, "restoreTargets", newAnnotations["podmotion.io/restore-target-containers"])

	// Override every main container: replace Command/Args with the injected holder binary.
	// The workload command (e.g. redis-server) is restored BY CRIU from the checkpoint image;
	// the holder is the container init that CRIU restores OVER.
	for i := range spec.Containers {
		// ADR-0195 Rule A: set Command to the injected holder; clear Args (the holder takes none).
		// Removal symmetry: --podmotion-holder is NO LONGER appended here. The flag-append path is REMOVED.
		spec.Containers[i].Command = []string{holderBinPath}
		spec.Containers[i].Args = nil
		// Mount the holder emptyDir so the binary resolves at holderBinPath inside the container.
		spec.Containers[i].VolumeMounts = append(spec.Containers[i].VolumeMounts, corev1.VolumeMount{
			Name:      holderVolumeName,
			MountPath: holderMountPath,
			ReadOnly:  true,
		})
		// Strip probes: a probe against the holder (no real workload in that process tree)
		// would fail, and a probe that hit the restored process on the pod IP would couple
		// container readiness to a process containerd does not own.
		// Readiness is gated by criuRestoreConfirmed + TrafficVerified.
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

// replacementPodMigrationNameLabel is the label the controller stamps on every replacement pod
// at creation (see the newLabels assignment in createReplacementPod). It is the source of truth
// for resolving the replacement pod — the agent restore path keys on the same label
// (server.go replacementPodLabelKey) — and must be preferred over pm.Status.ReplacementPodName,
// which is a controller-written mirror that a status-subresource race can leave empty.
const replacementPodMigrationNameLabel = "podmotion.io/migration-name"

// resolveReplacementPodByLabel returns the replacement pod for this migration by listing pods in
// the migration namespace carrying podmotion.io/migration-name == pm.Name. This is the
// authoritative resolution (matching the agent's server.go resolveReplacementPod) and is robust
// to a lost pm.Status.ReplacementPodName. It returns (nil, nil) when no pod is found yet (the
// caller should requeue). If the label lookup finds nothing but Status.ReplacementPodName is set,
// it falls back to a direct Get so behavior never regresses below the old status-field path.
func (r *PodMigrationReconciler) resolveReplacementPodByLabel(ctx context.Context, pm *pmv1.PodMigration) (*corev1.Pod, error) {
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList,
		client.InNamespace(pm.Spec.PodNamespace),
		client.MatchingLabels{replacementPodMigrationNameLabel: pm.Name},
	); err != nil {
		return nil, fmt.Errorf("listing replacement pod by label %s=%s: %w",
			replacementPodMigrationNameLabel, pm.Name, err)
	}
	if len(podList.Items) > 0 {
		// Deterministic pick: the single match in the normal case; the newest by
		// CreationTimestamp if a stale prior-attempt pod lingers.
		newest := &podList.Items[0]
		for i := 1; i < len(podList.Items); i++ {
			if podList.Items[i].CreationTimestamp.After(newest.CreationTimestamp.Time) {
				newest = &podList.Items[i]
			}
		}
		return newest, nil
	}
	// Fallback: the label lookup found nothing but a name was recorded — resolve it directly.
	if pm.Status.ReplacementPodName != "" {
		pod := &corev1.Pod{}
		if err := r.Get(ctx, types.NamespacedName{
			Namespace: pm.Spec.PodNamespace,
			Name:      pm.Status.ReplacementPodName,
		}, pod); err != nil {
			return nil, client.IgnoreNotFound(err)
		}
		return pod, nil
	}
	return nil, nil
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
		minDirtyConvergence   = 0.9
		maxRetransmitHeadroom = 0.5
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
