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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/dynamic"

	"github.com/podmotion-io/podmotion/internal/agent/iphandoff"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
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
	"github.com/podmotion-io/podmotion/internal/placement"
	"github.com/podmotion-io/podmotion/internal/podlineage"
	"github.com/podmotion-io/podmotion/internal/rollback"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	finalizerName = "migration.podmotion.io/finalizer"

	// workloadLivenessStabilizationWindow is the minimum gap enforced between the FIRST passing
	// application-liveness probe (staged on ConditionWorkloadLivenessFirstPass) and the SECOND,
	// confirming probe that is required before ConditionWorkloadLivenessVerified is set True. It
	// exists to catch a workload that dies shortly (observed live: 40-60s) after an apparently
	// successful CRIU restore, which a single probe issued right after restore can miss entirely.
	// This is a real second measurement point, not a longer single timeout.
	workloadLivenessStabilizationWindow = 45 * time.Second

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
	// conditionDestinationPlacementValid is set False with reason "SameNodePlacement" when the
	// destination node backfilled from the already-bound replacement pod (degraded no-scheduler
	// substrate, see reconcileTransferring) resolves to the SAME node as the source pod. A
	// same-node placement is a degenerate, non-migration and must not be silently advanced as if
	// it were a valid cross-node transfer; the reconcile requeues instead of proceeding.
	conditionDestinationPlacementValid = "DestinationPlacementValid"
	// conditionDestinationResolvable (ADR-0365 packaging resolution) records the outcome of
	// resolveEarlyDestinationNode: True when the early destination decision picked a node (or the
	// migration is pinned/already resolved and the step was a no-op), False with a
	// human-actionable reason when no candidate node passed Filter (e.g. no capacity anywhere) —
	// set BEFORE any storage pre-stage work is dispatched, so the completion budget (invariant #8)
	// is spent waiting on a diagnosable, reported condition instead of an invisible wedge. Also
	// used by the Condition-1 staleness re-validation (revalidateDestinationBeforeReplacementPod)
	// when a previously-resolved destination goes stale between the early decision and actual
	// replacement-pod creation.
	conditionDestinationResolvable = "DestinationResolvable"
	// The VerifyCleanup(CUTOVER_COMPLETE) retry attempt count (ADR-0241 item 1) previously
	// lived here as cni0CleanupVerifyAttemptsAnnotation, a spec/metadata annotation written via
	// r.Update. Later revised (Verifying-phase wedge fix): it is now
	// pm.Status.Cni0CleanupVerifyAttempts, a typed status field written exclusively via
	// r.statusUpdate (status subresource) — see readCni0CleanupVerifyAttempts. The annotation
	// constant is removed; nothing reads or writes that annotation key any more.
	//
	// sameNodeRecoveryAttemptsAnnotation stamps the current same-node placement recovery
	// (delete-and-reschedule) attempt count on the PodMigration so the bounded
	// maxSameNodeRecoveryDeletes budget in resolveAndValidateReplacementPlacement survives across
	// reconcile requeues. NOTE: this and ipReclaimVerifyAttemptsAnnotation / disarmZeroWindowRetryAttemptsAnnotation
	// below are other annotation-based retry counters using the pre-Finding-3a pattern; they are not
	// implicated in the reported Verifying-phase wedge and are out of scope for this fix (the webhook
	// fix already makes their r.Update calls harmless regardless, since no premigration gate can
	// fire on any UPDATE any more). Worth a follow-up ADR for consistency, not required here.
	sameNodeRecoveryAttemptsAnnotation = "podmotion.io/samenode-recovery-attempts"
	// conditionIPHandoffInjected records that the ADR-0133 destination-side neighbor/FDB
	// handoff for the OLD pod IP has been installed and the reachability probe passed.
	conditionIPHandoffInjected = "IPHandoffInjected"
	// conditionRestoreTimedOut is set when the restore deadline elapses, driving
	// the migration to RollingBack (ADR-0157 D3/GC-32). Reason: RestoreDeadlineExceeded.
	conditionRestoreTimedOut = "RestoreTimedOut"
	// ipReclaimVerifyAttemptsAnnotation stamps the current VerifyCleanup(IP_RECLAIM) retry
	// attempt count (ADR-0244 / NR-BLOCK-2), using the same annotation-based retry-counter
	// pattern the removed cni0-cleanup-verify annotation used before its Finding-3a rework
	// into a status field (see the sameNodeRecoveryAttemptsAnnotation comment above).
	ipReclaimVerifyAttemptsAnnotation = "podmotion.io/ip-reclaim-verify-attempts"
	// disarmZeroWindowRetryAttemptsAnnotation stamps the current DisarmZeroWindow RPC-error
	// retry attempt count (fail-closed phase-gate item 5). Mirrors ipReclaimVerifyAttemptsAnnotation.
	disarmZeroWindowRetryAttemptsAnnotation = "podmotion.io/disarm-zero-window-retry-attempts"
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

// disarmZeroWindowRetryBackoff (fail-closed phase-gate item 5) bounds how many times reconcileDisengageHold
// retries the DisarmZeroWindow RPC after a transport/connect error before giving up and
// surfacing a real, visible error condition. ADR-0157's watchdog auto-disarms the BPF hold
// independently after FreezeWindowBudgetMs + margin regardless of RPC reachability — so the
// real risk being guarded against here is only "the controller declares success before it has
// ANY evidence," not the hold itself running open-ended. Same 3-attempt/2s-4s-8s shape as the
// other bounded-retry schedules in this file (ipReclaimVerifyBackoff, cni0CleanupVerifyBackoff).
var disarmZeroWindowRetryBackoff = []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}

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
	// APIReader is an UNCACHED apiserver reader (mgr.GetAPIReader), used ONLY for the ADR-0393/0410
	// capture read-back gate. The informer cache is NOT read-after-write consistent with the direct
	// Status().Patch that persists the snapshot one line earlier, so a cached read-back can return the
	// pre-patch object (SourcePodSpecSnapshot == nil) until the watch delivers the write — a
	// read-your-own-write blip, worst at cold-start. The uncached read grounds the fail-closed "refuse
	// source kill" gate in authoritative server state, exactly as the eviction webhook (ADR-0401) and
	// the agent bridge reconciler (ADR-0400 D2) already do. Nil in unit tests → the read-back falls
	// back to r.Client via readBackReader() (the fake client is read-after-write consistent, so there
	// is no cache-lag to defend against there).
	APIReader  client.Reader
	Scheme     *runtime.Scheme
	Estimator  estimation.Estimator
	Rollbacker rollback.Rollbacker
	// Recorder emits Kubernetes events on PodMigration objects (e.g. ZeroWindowWatchdogFired).
	// Nil in unit tests — event emission is skipped when nil.
	Recorder record.EventRecorder
	// AgentPool provides per-node gRPC connections to podmotion-agent DaemonSet pods.
	// Nil in unit tests — phase handlers skip gRPC calls when nil.
	AgentPool *agentclient.AgentClientPool
	// ReplicationMgr drives the pre-copy dirty-page sync loop (one of the parallel pre-migration workers).
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
	// DynamicClient is used by the ADR-0322 Cilium CiliumEndpoint readiness check
	// (injectIPHandoff, immediately before verifyDataplaneReachability) to poll the
	// cilium.io/v2 CiliumEndpoint CRD directly, and is threaded into CiliumHandoff via
	// CNIMobilitySelector. Nil in unit tests — the Cilium-readiness branch is skipped
	// (fail-closed at the call site, not here) when nil.
	DynamicClient dynamic.Interface
	// KubeClient is the typed clientset threaded into CNIMobilitySelector for handoff
	// strategies that need it (currently CalicoHandoff.WaitForWorkloadEndpointReady polls
	// the destination pod via the typed Pods().Get API). Nil in unit tests — the
	// Calico-readiness branch is skipped (fail-closed at the call site, not here) when nil.
	KubeClient kubernetes.Interface
	// GPUCheckpointer handles NVIDIA CUDA context checkpoint/restore.
	// Only called when GPUMigration feature gate is enabled and the pod has GPU resources.
	// Defaults to GPUCheckpointerStub when nil (so GPU-unaware environments are unaffected).
	GPUCheckpointer gpuagent.GPUCheckpointer
	// GitOpsSuspender suspends and resumes the GitOps controller (ArgoCD/Flux) that owns
	// the migrating workload.  Nil → NoopSuspender is used, so existing unit tests are
	// unaffected.  Wired to ArgoCDClient or FluxClient in production via cmd/main.go.
	GitOpsSuspender gitops.GitOpsSuspender
	// TestOnlyAllowNilAgentPoolFailOpen must be explicitly set true by a test to let
	// restoreSourceStorageIfNeeded fail OPEN (set ConditionSourceStorageWriteRestored=True)
	// when AgentPool/SourceNodeName are unavailable. It defaults to false, so a production
	// reconciler (or any test that forgets to set it) fails CLOSED on this specific
	// safety-critical condition instead of silently inferring "restored" from a nil pointer
	// (ADR-0344, 2026-07-12; see SECURITY-DEBT-LEDGER.md). This flag
	// governs ONLY restoreSourceStorageIfNeeded — it has no effect on any other AgentPool-nil
	// check in this reconciler.
	TestOnlyAllowNilAgentPoolFailOpen bool
	// onPhaseDecision, when non-nil, is invoked at the single next-phase decision point of the
	// checkpoint/transfer advance helpers with the (from, decided) phase pair. It is a
	// test-observable transition ledger hook: it records the branch actually taken at the source
	// of truth (pm.Status.Phase), giving a deterministic in-process proof of the phase-machine
	// decision that does not depend on any fake-client status readback. Nil in production — no
	// behavioral effect. See advanceAfterCheckpoint / advanceAfterTransfer.
	onPhaseDecision func(from, decided pmv1.MigrationPhase)
	// readoptConfirmIntervalOverride, when non-zero, replaces
	// replacementPodReadoptConfirmInterval for readoptReplacementPodIntoOwningReplicaSet's
	// bounded confirm poll (ADR-0371 §2). Test-only — lets a test exercise the poll-exhausted
	// (timeout) path deterministically without a multi-second real-time sleep. Zero (the
	// default) in production — no behavioral effect.
	readoptConfirmIntervalOverride time.Duration

	// snapshotHMACKeyMu/snapshotHMACKeyCache cache the operator-only HMAC key that signs
	// ADR-0393 SourcePodSpecSnapshots. In production the key is loaded-or-created lazily from a
	// Secret in the operator's own namespace that the node agent SA has no RBAC to read (see
	// snapshotHMACKey). Caching avoids a per-migration Secret round-trip.
	snapshotHMACKeyMu    sync.Mutex
	snapshotHMACKeyCache []byte

	// testOnlySnapshotHMACKey, when non-nil, is used directly as the ADR-0393 snapshot HMAC key,
	// bypassing the operator-namespace Secret load/create. Test-only; nil in production.
	testOnlySnapshotHMACKey []byte
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
// ADR-0361 sprint56B finding: getRSSelector (below) reads appsv1.ReplicaSet to resolve and strip
// the owning ReplicaSet's selector labels off a replacement pod, but no RBAC marker for it existed
// anywhere in this codebase — a pre-existing, cross-substrate bug (not kind-specific) that silently
// stalls FinalFreezeStateCapture forever for every ReplicaSet-owned (Deployment-backed) source pod,
// confirmed live: "replicasets.apps is forbidden ... at the cluster scope" from the controller-runtime
// cache reflector, checkpoint captured but no replacement pod ever created.
// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch
// ADR-0361 sprint56B finding: ensureReplacementPodBound (ADR-0360) removes the
// podmotion.io/awaiting-checkpoint scheduling gate via a direct `patch` on the replacement pod —
// `patch` was missing from this marker (and from the chart's hand-maintained ClusterRole), so the
// gate could never be lifted and every gated migration replacement pod stalled forever. Confirmed
// live: "pods ... is forbidden ... cannot patch resource \"pods\"" from ensureReplacementPodBound.
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;delete;create;update;patch
// +kubebuilder:rbac:groups="",resources=pods/status,verbs=get
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
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

	// Normalize destination node (SINGLE SOURCE OF TRUTH): spec.destinationNode (webhook-populated)
	// and spec.targetNodeName (user-set) are two synonymous fields that seed the
	// status.destinationNodeName observability cache so downstream reconcilers can read it. This
	// seed-from-spec and the live-pod binding read in reconcileTransferring are the ONLY two producers
	// of Status.DestinationNodeName, and BOTH route through resolveAndValidateReplacementPlacement so
	// no producer can latch a same-node destination that would wedge the migration (the same-node
	// wedge case — an operator targeting a pod's own current node). Seed mode (correctInvalid=false) caches
	// the declared target only when it is distinct from the source and NEVER deletes a pod or fails
	// the migration; the authoritative valid-vs-needs-correcting decision (and real recovery) is made
	// once, in reconcileTransferring's correct-mode call. Skipped while the CR is being deleted (the
	// finalizer path below owns that).
	if pm.DeletionTimestamp.IsZero() {
		if _, err := r.resolveAndValidateReplacementPlacement(deadline, pm, pm.Status.SourceNodeName, false); err != nil {
			log.Error(err, "normalize: replacement-placement resolve failed — requeuing", "migration", pm.Name)
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
	}

	// Crash-safety (ADR-0018): if we restarted with the pod already frozen,
	// issue restore immediately before anything else.
	if r.isFrozenWithoutRestore(pm) {
		log.Info("crash-safe restart: pod was frozen but not restored — issuing restore", "migration", req.NamespacedName)
		return r.transitionTo(deadline, pm, pmv1.MigrationPhaseRestoring)
	}

	// Finalizer: ensure we always get a chance to clean up (rollback, delete checkpoint).
	//
	// ADR-0381: this write is wrapped in a re-fetch + retry.RetryOnConflict loop, matching this
	// file's standing conflict-safe-write pattern (statusUpdate at :7488, releaseDestinationCapacity
	// at :6958, etc.) instead of a bare r.Update(deadline, pm) against the in-memory pm above. The
	// normalize step just above (resolveAndValidateReplacementPlacement, :343) can, on a fresh CR in
	// seed mode, persist a Status update via r.statusUpdate — a real write against the API server
	// that bumps the object's actual resourceVersion — without updating this reconcile's in-memory
	// pm copy. A bare r.Update(deadline, pm) here then carries the now-stale resourceVersion from the
	// original r.Get at :319, guaranteeing a 409 Conflict ("the object has been modified; please
	// apply your changes to the latest version and try again") on effectively every fresh CR's first
	// reconcile. controller-runtime auto-requeues on that error so it was self-healing and never
	// caused an incorrect outcome, but it is pure avoidable noise on the single hottest code path in
	// the controller (every reconcile of every migration passes through here before DeletionTimestamp
	// is ever set). Re-fetching immediately before the write closes the race outright.
	if pm.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(pm, finalizerName) {
			key := client.ObjectKeyFromObject(pm)
			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				fresh := &pmv1.PodMigration{}
				if err := r.Get(deadline, key, fresh); err != nil {
					return err
				}
				if controllerutil.ContainsFinalizer(fresh, finalizerName) {
					// Lost the race to a concurrent reconcile that already added it — nothing left
					// to persist; the next natural reconcile (triggered by that other write) will
					// see the finalizer present and proceed past this block.
					return nil
				}
				controllerutil.AddFinalizer(fresh, finalizerName)
				return r.Update(deadline, fresh)
			}); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
	} else {
		return r.handleDeletion(deadline, pm)
	}

	// ADR-0012 / invariant #8 — AUTHORITATIVE completion-deadline primitive (single source-of-truth
	// gate over the WHOLE phase machine). A live migration that never reaches a terminal phase is the
	// exact forever-wedge invariant #8 forbids: the sprint46B3 live-proof cycle-2 migration wedged in
	// phase=Verifying past the 120s cap with its finalizer intact and the namespace stuck Terminating
	// (docs/sprints/sprint46B3/live-proof-c2-transcript.txt: DisengageHold→Verifying→…→watch rc=124 at
	// 125s, MIG1_FINAL_PHASE=Verifying), because NO phase on that path enforced a wall-clock terminal
	// bound. The pre-existing bound in reconcileServiceVerifying is phase-LOCAL and never runs here —
	// the live Strict path (fresh CRs) is DisengageHold→TCPVerifying→ServiceVerifying
	// (reconcileServiceVerifying); DisengageHold→Verifying (reconcileVerifying) is the
	// LEGACY backward-compat topology for pre-existing CRs (ADR-0352).
	// Stamping the same deadline check into every phase handler is the brittle-chain anti-pattern
	// (invariant #10). Instead enforce it ONCE, at the dispatch, keyed on the CR's OWN source of truth:
	// creationTimestamp + spec.completionTimeoutSeconds — values already on the object, NOT an inferred
	// or polled timer. The per-reconcile context.WithTimeout at :250 only bounds downstream RPCs; every
	// requeue derives a fresh timer, so it can never advance the CR to a terminal phase on its own. If a
	// NON-terminal, non-rolling-back migration has burned its entire declared completion budget without
	// reaching Complete, fail closed to RollingBack (source is never deleted — ADR-0012; the replacement
	// pod is torn down by the rollback path). This BOUNDS the wedge to a terminal decision; it does NOT
	// itself establish dataplane reachability — that remains the authoritative substrate gate. Guarded
	// on a non-zero creationTimestamp so it is inert for unit CRs that carry none.
	if !pm.CreationTimestamp.IsZero() && !isTerminalOrRollingBackPhase(pm.Status.Phase) {
		budgetSecs := pm.Spec.CompletionTimeoutSeconds
		if budgetSecs <= 0 {
			budgetSecs = 600
		}
		if time.Now().After(pm.CreationTimestamp.Add(time.Duration(budgetSecs) * time.Second)) {
			// Verifying-phase wedge fix: a completion-budget expiry does
			// NOT always mean the migration failed. If the source pod has already been
			// legitimately deleted (ADR-0012 gate satisfied, verified fresh) the migration
			// actually SUCCEEDED — only some non-fatal post-deletion straggler kept it from
			// reaching Complete. Rolling back in that case would thaw a nonexistent source and
			// delete the healthy replacement: a real availability regression, not a safety net.
			// Close out to Complete directly instead. Every other case (source never deleted)
			// still fails closed to RollingBack exactly as before.
			if r.sourceAlreadyDeletedLegitimately(deadline, pm) {
				return r.closeOutAfterLegitimateSourceDeletion(deadline, pm,
					fmt.Sprintf("completion budget (%ds) exceeded, but source pod deletion was already legitimate and verified (ADR-0012) — closing out instead of destructive rollback", budgetSecs))
			}
			log.Error(nil, "completion budget exceeded before reaching a terminal phase — failing closed to RollingBack (invariant #8; source never deleted, ADR-0012)",
				"migration", pm.Name, "phase", pm.Status.Phase, "budgetSeconds", budgetSecs)
			return r.initiateRollback(deadline, pm,
				fmt.Sprintf("completion budget (%ds) exceeded before reaching a terminal phase (invariant #8); failing closed to rollback rather than wedging past the cap (source never deleted — ADR-0012)", budgetSecs))
		}
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

	// fail-closed phase-gate (item 3): the source node agent enumerates /proc/net/tcp[6] per container
	// netns and reports the inventory via a REAL PrepareSource RPC round trip — the
	// condition may only go True after that RPC actually succeeds, carrying the real
	// observed count. This used to set the condition unconditionally with no RPC call at
	// all ("full implementation in M20"); the RPC, the agent-side socket scan, and the
	// PrepareSourceResponse.TcpConnectionCount field all already existed end-to-end but were
	// dead on both ends until now.
	log.Info("SocketInventory: recording TCP 4-tuples from source pod", "migration", pm.Name)

	if r.AgentPool == nil {
		log.Error(nil, "SocketInventory: AgentPool not wired — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	sourcePod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// ADR-0409: the source pod named by spec.podName does not exist at the FIRST pipeline
			// phase — before any agent RPC, source mutation, or Status.SourceNodeName resolution
			// (SourceNodeName is set only below, AFTER this getPod succeeds). This is NOT a transient
			// condition: a valid migration target is a long-lived Running pod that pre-exists its own
			// trigger (the migration never creates the source), and the dominant cause here is a
			// migrate-then-renamed reference a PRIOR completed migration already invalidated
			// (ADR-0012: the original pod is deleted and a "<name>-m-<hash>" successor lands).
			// Requeuing rides the shared 600s completion budget (invariant #8) and then fails into a
			// rollback whose source-agent Abort RPC has no resolved Status.SourceNodeName. Nothing has
			// been mutated (0 agent RPCs — same fast-fail primitive reconcileValidating already uses
			// one phase later when the source pod is absent), so there is nothing to roll back:
			// clean-abort terminally, fast, with an attributed reason.
			//
			// getPod reads the controller-runtime CACHED client, so a cache-lag NotFound (pod exists
			// in etcd but is not yet reflected in the informer cache) is IsNotFound-indistinguishable
			// from a genuine absence. Before clean-aborting, do ONE confirmatory uncached live read:
			// if the pod is found live, this was cache lag — bounded requeue and let the cache catch
			// up (no valid migration is fast-failed). Only a live-confirmed (or unconfirmable) absence
			// clean-aborts. This closes the "create-then-immediately-migrate" false-terminal window,
			// at the cost of one API call on the failure path only.
			if r.sourcePodPresentLive(ctx, pm.Spec.PodNamespace, pm.Spec.PodName) {
				log.Info("SocketInventory: source pod absent from cache but present on a live read — informer cache lag, requeuing",
					"migration", pm.Name, "pod", pm.Spec.PodName)
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
			}
			reason := fmt.Sprintf(
				"SocketInventory: source pod %s/%s does not exist at the first pipeline phase — nothing was "+
					"migrated (no agent contacted); the pod was most likely already migrated and renamed "+
					"(ADR-0012), so spec.podName is stale%s. Failing fast (no rollback: nothing to unwind).",
				pm.Spec.PodNamespace, pm.Spec.PodName, r.describeLiveSuccessorHint(ctx, pm))
			log.Error(err, "SocketInventory: source pod unresolvable at first phase — clean-abort terminal (no rollback)",
				"migration", pm.Name, "pod", pm.Spec.PodName)
			return r.failMigration(ctx, pm, reason)
		}
		// Genuinely transient (API unreachable, throttled, server timeout, etc.): keep a bounded
		// requeue. This still rides the 600s budget, but a transient API fault is exactly what the
		// budget's fail-closed rollback exists for, and — unlike NotFound — it is not deterministic,
		// so a retry can legitimately succeed and populate SourceNodeName, after which the
		// budget->rollback path is well-formed.
		log.Error(err, "SocketInventory: transient error resolving source pod — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	sourceNode := pm.Status.SourceNodeName
	if sourceNode == "" {
		sourceNode = sourcePod.Spec.NodeName
		pm.Status.SourceNodeName = sourceNode
	}

	agentClient, err := r.AgentPool.ForNode(ctx, sourceNode)
	if err != nil {
		log.Error(err, "SocketInventory: cannot connect to source agent — requeuing", "migration", pm.Name, "node", sourceNode)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	prepResp, err := agentClient.PrepareSource(ctx, &agentpb.PrepareSourceRequest{
		PodName:       pm.Spec.PodName,
		PodNamespace:  pm.Spec.PodNamespace,
		PodUid:        string(sourcePod.UID),
		MigrationName: pm.Name,
	})
	if err != nil {
		log.Error(err, "SocketInventory: PrepareSource RPC failed — requeuing (fail-closed phase-gate, no fabricated pass)", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if !prepResp.Compatible {
		reason := prepResp.BlockingReason
		if reason == "" {
			reason = "agent reported source pod incompatible"
		}
		setCondition(pm, pmv1.ConditionSocketInventoryComplete, metav1.ConditionFalse, "PrepareSourceIncompatible", reason)
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr
		}
		return r.initiateRollback(ctx, pm, reason)
	}

	// ADR-0388 (corrects ADR-0379): Strict-mode zero-connection precondition, now a VACUOUS PASS
	// rather than a fail-fast rollback. ADR-0379 originally read prepResp.TcpConnectionCount here
	// (this same PrepareSource RPC, same source-of-truth SocketInventory read the freeze-time
	// SeqSnapshot capture is built from) and rolled back any Strict migration observing zero
	// ESTABLISHED connections at inventory time, reasoning that TCPVerifying's non-vacuity gate
	// (ADR-0352 B8-DR-2) would inevitably fail the same migration later anyway. Chad's standing
	// direction (2026-07-23, this sprint) corrects that premise: a pod with zero connections has
	// nothing to preserve, so Strict is trivially satisfied, not unprovable — the earlier gate at
	// TCPVerifying (below) is corrected the same way, in the same commit. This is Strict-only;
	// BestEffort/None never required a held connection and are unaffected.
	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict && prepResp.TcpConnectionCount == 0 {
		log.Info("SocketInventory: Strict mode — no active connections to preserve at inventory time — "+
			"Strict trivially satisfied, proceeding", "migration", pm.Name, "tcpConnectionCount", prepResp.TcpConnectionCount)
	}

	setCondition(pm, pmv1.ConditionSocketInventoryComplete, metav1.ConditionTrue,
		"InventoryRecorded", fmt.Sprintf("recorded %d TCP socket(s) from source pod %s/%s netns via PrepareSource",
			prepResp.TcpConnectionCount, pm.Spec.PodNamespace, pm.Spec.PodName))
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

	// ADR-0365 Decision §2.1 (fail-closed hardening #1): the destNode-required gate now runs for
	// EVERY TCPPreservationMode, including None, BEFORE any mode-specific branch below (the Strict
	// clsact pre-check and the None fast path both used to run first, and None's fast path used to
	// transition straight to PreCopyMemory without ever reaching this check). This closes the one
	// path that could reach PreCopyMemory — and, from there, storage pre-stage — with an empty
	// destination even after Decision §1's early-decision step lands (e.g. a future caller invoking
	// this phase for a migration that skipped reconcileValidating's new step through some other
	// entry path). Fail closed: requeue with a diagnosable reason rather than silently proceeding.
	destNode := pm.Status.DestinationNodeName
	if destNode == "" && pm.Spec.TargetNodeName != "" {
		destNode = pm.Spec.TargetNodeName
	}
	if destNode == "" {
		log.Error(nil, "DestinationPrewarm: DestinationNodeName not set — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	// ADR-0169 §3 — pre-prewarm TC clsact capability re-check (MANDATORY, non-optional).
	// For tcpPreservationMode=Strict, re-assert that the resolved destination node reports
	// tcClsactSupported=true BEFORE any dest netns is staged. This closes GC-10 on the
	// scheduler-selected path: the admission webhook only checks "some capable node exists";
	// the resolved node may differ. Fail to Failed before any netns artifact is created.
	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict {
		recheckNode := destNode
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

	// destNode was already resolved (and gated non-empty) at the top of this function.

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
	// Cache via the shared validated seed so a same-node destination can never be latched here
	// (the same-node wedge case); the authoritative placement decision remains reconcileTransferring's.
	cacheDestinationNodeFromSpec(pm, destNode, pm.Status.SourceNodeName)

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

// preStageMinDispatchTimeout floors preStageDispatchTimeout so a very short (or zero/negative,
// pre-validation) Spec.CompletionTimeoutSeconds can never collapse the inner storage pre-stage
// bound to something unreasonably small.
const preStageMinDispatchTimeout = 30 * time.Second

// preStageDispatchTimeout bounds the storage pre-stage goroutine dispatch (ADR-0365 Decision
// §2.2) with an inner timeout derived from, and strictly shorter than, the migration's own
// completion budget (invariant #8, this file's Reconcile entrypoint, default 600s) — so a stuck
// pre-stage call (a wedged Longhorn API call, or a transient-error retry loop that never resolves)
// surfaces as its own diagnosable, phase-attributable PreStageTimeout failure well before the
// outer completion-budget kill fires. This does NOT change invariant #8's own authority as the
// outer bound; it only adds an inner one so the failure is legible instead of an indistinguishable
// global wedge.
func preStageDispatchTimeout(pm *pmv1.PodMigration) time.Duration {
	budgetSecs := pm.Spec.CompletionTimeoutSeconds
	if budgetSecs <= 0 {
		budgetSecs = 600
	}
	inner := time.Duration(budgetSecs) * time.Second / 2
	if inner < preStageMinDispatchTimeout {
		inner = preStageMinDispatchTimeout
	}
	return inner
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

	// ADR-0380: StorageReadyForFreeze=False is not one signal, it's two, and this loop used to
	// treat them identically. "Not yet computed" (condition absent, or a transient
	// classify/dispatch error) is genuinely worth requeuing on — the storage pre-stage goroutine
	// below is still in flight and may still flip it True. "BlockedVolume" was ADR-0380's terminal
	// verdict.
	//
	// ADR-0398 D3 (corrects/supersedes-partial ADR-0380): ADR-0380's premise — "nothing about the
	// pod's volumes changes between reconciles, so BlockedVolume is terminal" — became FALSE after
	// ADR-0396 made the bare-Longhorn classification a function of a per-dispatch coldRecreateArmed
	// argument, not of the pod's volumes. So a BlockedVolume observed while the single authoritative
	// dispatch is still in flight, absent, or contradicted by a recorded ColdRecreateArmed==true is NOT
	// terminal. Gate the fail-fast on the durable StoragePreStageDispatch verdict (written by exactly
	// one dispatch BEFORE the goroutine writes the condition), not on the momentary, asynchronously
	// raced condition value.
	if storageCond := meta.FindStatusCondition(pm.Status.Conditions, conditionStorageReady); storageCond != nil &&
		storageCond.Status == metav1.ConditionFalse && storageCond.Reason == "BlockedVolume" {

		d := pm.Status.StoragePreStageDispatch
		switch {
		case d == nil || d.Phase != pmv1.StoragePreStageComplete:
			// The single authoritative dispatch has not completed. A BlockedVolume here is not yet a
			// terminal verdict — it is not-yet-authoritative or in flight. Requeue; do NOT fail.
			log.Info("PreCopyMemory: BlockedVolume observed before the authoritative storage dispatch completed — requeuing, not failing (ADR-0398 D3)",
				"migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		case d.ColdRecreateArmed:
			// Invariant violation: the one completed dispatch armed true, so it cannot have written a
			// terminal BlockedVolume. This is a stray/forged/legacy write. Log loudly and requeue; the
			// armed dispatch's StorageReady=True is the truth and will reassert.
			log.Error(nil, "PreCopyMemory: BlockedVolume contradicts a Complete/armed dispatch verdict — not failing; requeuing (ADR-0398 D3 invariant)",
				"migration", pm.Name)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		default:
			// Phase==Complete && !ColdRecreateArmed: the single authoritative dispatch genuinely could
			// not migrate this pod's volume. THIS is a terminal BlockedVolume — ADR-0380 fail-fast is
			// correct here (fail fast instead of waiting out the completion budget).
			log.Error(nil, "PreCopyMemory: StorageReadyForFreeze is permanently blocked (authoritative dispatch complete, unarmed) — failing fast (ADR-0380 as corrected by ADR-0398)",
				"migration", pm.Name, "message", storageCond.Message)
			return r.failMigration(ctx, pm, fmt.Sprintf("storage precondition permanently unmet: %s", storageCond.Message))
		}
	}

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
		cacheDestinationNodeFromSpec(pm, pm.Spec.TargetNodeName, pm.Status.SourceNodeName)
		// Pre-copy TCP freeze-go gate (M24): for TCP-stateful migrations the controller
		// must confirm three convergence predicates before arming the zero-window hold.
		// This avoids freezing during a high-retransmit or fast-growing seq window where
		// the freeze budget would be exceeded before the relay can take over.
		//
		//   dirty_convergence               — latest round's real DirtyPagesMB < freeze budget (absolute)
		//   seq_advance_rate < bandwidth    — TCP send rate fits within the transfer pipe
		//   retransmit_queue_headroom < 0.5 — retransmit backlog is small (<50% of send buffer)
		//
		// The gate is skipped for TCPPreservationMode=None (no TCP state to preserve) and
		// for cold migrations where no pre-copy loop runs.
		if pm.Spec.TCPPreservationMode != pmv1.TCPPreservationModeNone &&
			pm.Spec.Mode != pmv1.MigrationModeCold {
			if !preCopyTCPGatePassed(pm) {
				var finalDirtyMB int32
				var dirtyStatsValid bool
				var roundsCompleted int32
				if stats := pm.Status.PreCopyStats; stats != nil {
					finalDirtyMB = stats.FinalDirtyPagesMB
					dirtyStatsValid = stats.DirtyStatsValid
					roundsCompleted = stats.RoundsCompleted
				}
				// FinalDirtyPagesMB and DirtyStatsValid are logged explicitly
				// (for observability) — without them this line prints
				// identically whether the block is "genuinely still dirty, will converge"
				// or "no validated measurement, fail-closed and stuck until the
				// completion-timeout backstop," with no way for an operator to tell them
				// apart from this log alone.
				log.Info("PreCopyMemory: TCP freeze-go gate not passed — requeuing",
					"migration", pm.Name,
					"dirtyConverged", preCopyDirtyConverged(pm),
					"retransmitHeadroom", preCopyRetransmitHeadroom(pm),
					"finalDirtyPagesMB", finalDirtyMB,
					"dirtyStatsValid", dirtyStatsValid,
					"roundsCompleted", roundsCompleted)
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

	// ADR-0398 D1: dispatch the storage pre-stage AT MOST ONCE per migration via a durable,
	// fenced compare-and-swap marker (StoragePreStageDispatch), not the non-idempotent
	// `storageCond == nil` guard (whose deciding condition is written asynchronously, later, inside
	// the dispatched goroutine — a TOCTOU that fanned one migration out into concurrent dispatches).
	if requeue, err := r.dispatchStoragePreStageOnce(ctx, pm); err != nil {
		return ctrl.Result{}, err
	} else if requeue {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

// storagePreStageInFlightLease bounds ONLY the pre-launch InFlight window: claim → synchronous arm
// (a handful of bounded K8s Gets + one operator-keyed-HMAC snapshot capture + read-back) → fenced
// Complete-mark. The long RunPreStage work (sized to preStageDispatchTimeout, ~completion-budget/2) is
// launched only AFTER the marker is stamped Complete, and a Complete marker permanently stops every
// re-claim (dispatchStoragePreStageOnce short-circuits on Phase==Complete). So the lease guarding the
// InFlight window must exceed worst-case synchronous ARMING wall-time, NOT the RunPreStage completion
// budget. 30s gives comfortable margin over the few serial API round-trips arming performs.
const storagePreStageInFlightLease = 30 * time.Second

// storagePreStageDispatchLease bounds how long an InFlight claim is honored before a later reconcile
// may re-claim it (ADR-0398). Because ClaimToken fences finalization (a superseded holder cannot stamp
// Complete or write a terminal verdict) and RunPreStage is launched only after a fenced Complete-mark a
// superseded holder cannot pass, this is a LIVENESS knob — how fast an ABANDONED claim (holder crashed,
// lost leadership, or exhausted its fenced finalize retry without stamping Complete) frees for re-claim —
// NOT a safety bound. An over-short value at worst triggers a redundant, token-fenced (harmless) re-arm;
// it can never cause a double dispatch.
//
// It is therefore sized to comfortably exceed worst-case synchronous arming (storagePreStageInFlightLease),
// DECOUPLED from the RunPreStage completion budget. Binding it to the budget (preStageDispatchTimeout, ~300s
// by default) was the defect behind the "PreCopyMemory stall after MemorySynced/Converged" symptom: an
// abandoned PRE-LAUNCH InFlight claim wedged the migration for the entire budget with StorageReadyForFreeze
// never set, even though the window this lease actually guards (arming) completes in sub-second-to-seconds.
// Clamped to the completion budget so a pathologically small budget can never yield a lease longer than the
// work itself (strictly no worse than the prior budget-scaled value).
func storagePreStageDispatchLease(pm *pmv1.PodMigration) time.Duration {
	if budget := preStageDispatchTimeout(pm); budget < storagePreStageInFlightLease {
		return budget
	}
	return storagePreStageInFlightLease
}

// armStoragePreStageOutcome is the three-way arming classification (ADR-0398 D2), replacing ADR-0396's
// binary armed/disarmed collapse. It distinguishes a transient (retryable) arming failure from a
// pod-intrinsic no-op, so a transient infrastructure fault is NEVER baked into a terminal disarmed
// dispatch (which would write a false BlockedVolume).
type armStoragePreStageOutcome int

const (
	// armOutcomeArmed: eligible bare-Longhorn pod, operator-keyed-HMAC snapshot captured+verified.
	armOutcomeArmed armStoragePreStageOutcome = iota
	// armOutcomeNoOp: arming is inapplicable by a pod-intrinsic fact (owned pod, or non-Longhorn bare
	// pod). Dispatch proceeds disarmed; these pods classify by their own tier and coldRecreateArmed is
	// irrelevant to them.
	armOutcomeNoOp
	// armOutcomeTransient: eligible bare-Longhorn pod whose snapshot capture failed for a retryable
	// reason (lost-update read-back nil, status-write conflict, transiently-unreadable signing key) OR
	// whose source pod was momentarily unreadable. Do NOT dispatch, do NOT record a verdict — release
	// the claim and requeue so a later reconcile re-arms. Bounded by the completion budget; if arming
	// never succeeds, the migration fails via the honest budget-expiry backstop, never a fabricated
	// BlockedVolume.
	armOutcomeTransient
)

// dispatchStoragePreStageOnce is the single-implementation ADR-0398 D1/D2 claim-then-dispatch step,
// shared by the live reconcilePreCopyMemory path and the (currently dead) reconcilePreMigrating mirror
// so there is exactly ONE dispatch implementation and no byte-duplicated non-idempotent latch. It
// returns requeue=true when the caller should requeue without advancing (claim lost, in-flight, or a
// transient arming failure). A false return with nil error means "no dispatch needed this pass"
// (already Complete, or StorageMgr unset).
func (r *PodMigrationReconciler) dispatchStoragePreStageOnce(ctx context.Context, pm *pmv1.PodMigration) (bool, error) {
	log := logf.FromContext(ctx)
	if r.StorageMgr == nil {
		return false, nil
	}

	// Inspect the durable marker. nil ⇒ claimable; Complete ⇒ done; InFlight ⇒ owned unless the
	// liveness lease has expired (only then may a later reconcile re-claim).
	if d := pm.Status.StoragePreStageDispatch; d != nil {
		switch d.Phase {
		case pmv1.StoragePreStageComplete:
			return false, nil // the single authoritative dispatch already ran; idempotent no-op.
		case pmv1.StoragePreStageInFlight:
			if time.Since(d.ClaimedAt.Time) < storagePreStageDispatchLease(pm) {
				// Another reconcile (this lifetime, another replica) owns an in-flight dispatch.
				return true, nil
			}
			log.Info("ADR-0398: prior storage pre-stage claim exceeded its liveness lease — re-claiming",
				"migration", pm.Name, "claimedAt", d.ClaimedAt.Time)
		}
	}

	// Claim by fenced CAS: mint a fresh token, patch {InFlight, token, now} with an optimistic-lock
	// precondition on the object's resourceVersion. Exactly one concurrent reconcile lands the claim;
	// every other gets 409 Conflict and requeues without dispatching.
	token := uuid.NewString()
	base := pm.DeepCopy()
	pm.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
		Phase:             pmv1.StoragePreStageInFlight,
		ClaimToken:        token,
		ClaimedAt:         metav1.Now(),
		HolderReconcileID: token, // diagnostics only; correctness comes from the CAS + ClaimToken.
	}
	if err := r.Status().Patch(ctx, pm, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
		if apierrors.IsConflict(err) {
			log.V(1).Info("ADR-0398: lost the storage pre-stage claim CAS — requeuing without dispatch",
				"migration", pm.Name)
			return true, nil
		}
		return false, err
	}

	// Arm synchronously (ADR-0396 mechanics, ADR-0398 D2 taxonomy). armed is an in-process fact the
	// operator computes here from an operator-keyed-HMAC-verified capture — never a status field, so
	// nothing on the wire is forgeable.
	outcome := r.armStoragePreStage(ctx, pm)
	if outcome == armOutcomeTransient {
		// Do NOT dispatch and do NOT record a verdict. Release the claim (fenced) so a later reconcile
		// re-arms promptly rather than waiting out the lease. No disarmed dispatch is launched, so no
		// BlockedVolume is written from a transient fact.
		r.releaseStoragePreStageClaim(ctx, pm, token)
		log.Info("ADR-0398: storage pre-stage arming hit a transient failure — released claim, requeuing to re-arm (no disarmed dispatch, no BlockedVolume written)",
			"migration", pm.Name)
		return true, nil
	}
	armed := outcome == armOutcomeArmed

	// Fenced Complete-mark BEFORE launch: this is the single serialization point. Only the reconcile
	// that still holds ClaimToken can finalize; a superseded holder fails here and never dispatches, so
	// RunPreStage is launched AT MOST ONCE (a second dispatch is impossible because a re-claim requires
	// the marker to still be InFlight, and InFlight is only left via Complete, which strictly precedes
	// launch).
	completed, err := r.completeStoragePreStageDispatch(ctx, pm, token, outcome == armOutcomeArmed, armed)
	if err != nil {
		if apierrors.IsConflict(err) {
			// ADR-0407: the storm-sized finalize retry was exhausted while STILL holding the token
			// (§RESIDUAL — pathological, far beyond the measured ~1s / ~10-writer burst). Benign: leave the
			// marker InFlight and requeue so a later reconcile re-finalizes. Do NOT surface a hard error —
			// that would re-open the lease-bounded wedge this ADR closes.
			log.Info("ADR-0407: storage pre-stage finalize conflict storm outlasted the in-place retry — marker left InFlight, requeuing to re-finalize",
				"migration", pm.Name)
			return true, nil
		}
		// ADR-0407: a genuine NON-conflict Get/Patch error (API fault, or CR mid-deletion). NOT the storm
		// scenario and NOT a supersession — surface it exactly as pre-fix so it stays visible and backed off.
		return false, err
	}
	if !completed {
		// ADR-0398/0407: now provably true — a re-fetched object shows a DIFFERENT valid claimant.
		log.Info("ADR-0398/0407: storage pre-stage claim was genuinely superseded before Complete — a different valid claimant now owns it; not dispatching",
			"migration", pm.Name)
		return true, nil
	}

	pmCopy := pm.DeepCopy()
	go func() {
		// ADR-0365 Decision §2.2: bounded, not context.Background() — see preStageDispatchTimeout.
		preStageCtx, cancel := context.WithTimeout(context.Background(), preStageDispatchTimeout(pmCopy))
		defer cancel()
		if err := r.StorageMgr.RunPreStage(preStageCtx, pmCopy, armed, token); err != nil {
			log.Error(err, "storage pre-stage failed", "migration", pmCopy.Name)
		}
	}()
	log.Info("ADR-0398: launched storage pre-stage goroutine (single-dispatch)", "migration", pm.Name, "coldRecreateArmed", armed)
	return false, nil
}

// armStoragePreStage runs ADR-0396's in-process arming and maps its outcome onto ADR-0398's three-way
// taxonomy (armed / no-op / transient-retryable). A source pod that is momentarily unreadable is
// classified transient (retry), NOT a disarmed dispatch.
func (r *PodMigrationReconciler) armStoragePreStage(ctx context.Context, pm *pmv1.PodMigration) armStoragePreStageOutcome {
	log := logf.FromContext(ctx)
	armSourcePod := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: pm.Spec.PodName}, armSourcePod); err != nil {
		log.Info("ADR-0398: source pod unreadable at arming site — treating as transient (requeue to re-arm), not a disarmed dispatch",
			"migration", pm.Name, "err", err.Error())
		return armOutcomeTransient
	}
	return r.armTier1ColdRecreateIfEligible(ctx, pm, armSourcePod)
}

// storagePreStageFinalizeBackoff (ADR-0407) sizes the in-place finalize retry to OUTLAST the
// creation-instant status-write storm the mechanism map measured (~10 concurrent reconcile writers
// landing in a single second on an idle, instantly-converging pod). This is intentionally NOT
// retry.DefaultRetry (5 steps / ~50ms): that budget can be shorter than the storm, and the caller's
// InFlight-owned guard (dispatchStoragePreStageOnce) blocks any re-finalize until the lease expires — so
// exhausting the retry too early re-opens the wedge. The retry must internally span the storm; this
// backoff is therefore load-bearing for correctness, not tuning. Worst-case cumulative wait
// (25+50+100+200+400+800+1600+2000 ms) ~= 5.2s, comfortably past a 1s creation burst and still far below
// the 300s lease and 600s completion budget, so it cannot itself cause a timeout.
var storagePreStageFinalizeBackoff = wait.Backoff{
	Steps:    8,
	Duration: 25 * time.Millisecond,
	Factor:   2.0,
	Jitter:   0.2,
	Cap:      2 * time.Second,
}

// completeStoragePreStageDispatch finalizes the marker to Complete, fenced by ClaimToken. It re-reads
// the live marker and refuses (returns completed=false) if the token no longer matches — i.e. a later
// reconcile re-claimed after a lease expiry. Returns completed=true only when THIS holder's verdict was
// durably recorded.
//
// ADR-0407: a 409 on the finalize Patch is a TRANSIENT optimistic-concurrency conflict from an unrelated
// concurrent status writer (the holder still owns the token — re-verified at the top of every pass), NOT a
// supersession. It is retried in place via retry.RetryOnConflict: each pass re-Gets the live object,
// re-verifies the claim token, and re-Patches. Genuine supersession (a re-fetched object whose marker is
// nil or carries a DIFFERENT token) sets completed=false and returns a nil error, so the retry machinery
// does not loop — it short-circuits exactly as the pre-fix code did. Only a real 409 on the Patch is
// returned to RetryOnConflict; a genuine non-conflict Get/Patch error is surfaced to the caller unchanged.
func (r *PodMigrationReconciler) completeStoragePreStageDispatch(ctx context.Context, pm *pmv1.PodMigration, token string, armAttempted, armed bool) (bool, error) {
	key := client.ObjectKeyFromObject(pm)
	var completed bool
	err := retry.RetryOnConflict(storagePreStageFinalizeBackoff, func() error {
		fresh := &pmv1.PodMigration{}
		if err := r.Get(ctx, key, fresh); err != nil {
			return err
		}
		d := fresh.Status.StoragePreStageDispatch
		if d == nil || d.ClaimToken != token {
			// GENUINE supersession: the live object shows a DIFFERENT valid claimant (or a cleared
			// marker) now owns the record. This is NOT a conflict — stop, report not-completed, no retry.
			completed = false
			return nil
		}
		if d.Phase == pmv1.StoragePreStageComplete {
			completed = true // already finalized by an equivalent retry of this same holder.
			return nil
		}
		base := fresh.DeepCopy()
		d.Phase = pmv1.StoragePreStageComplete
		d.ArmAttempted = armAttempted
		d.ColdRecreateArmed = armed
		if err := r.Status().Patch(ctx, fresh, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			// A 409 here is a transient resourceVersion collision with an UNRELATED writer — this holder
			// STILL owns the token (re-verified above this pass). Return it so RetryOnConflict re-Gets,
			// re-verifies the token, and re-Patches. Genuine supersession is caught by the token check on
			// the NEXT iteration's fresh Get, not inferred from the conflict itself. A non-conflict error
			// is returned as-is and surfaced by RetryOnConflict to the caller.
			return err
		}
		pm.Status.StoragePreStageDispatch = fresh.Status.StoragePreStageDispatch
		completed = true
		return nil
	})
	if err != nil {
		// Either the storm-sized backoff was exhausted while still holding the token (err IsConflict — the
		// caller soft-requeues, marker stays InFlight, §RESIDUAL) or a genuine non-conflict Get/Patch error
		// occurred (the caller surfaces it). Not a supersession in either case.
		return false, err
	}
	return completed, nil
}

// releaseStoragePreStageClaim clears the marker back to nil (fenced by ClaimToken) so a transient
// arming failure frees the claim for a prompt re-claim instead of waiting out the lease. A mismatched
// or already-advanced token is left untouched.
//
// ADR-0407 (extended to the release path): the release Patch races the SAME creation-instant
// status-write storm that the finalize path (completeStoragePreStageDispatch) was storm-hardened
// against — unrelated concurrent status writers such as the pre-copy goroutine's MemorySynced write and
// condition updates. A single-shot release that abandoned the clear on the first 409 left the marker
// InFlight; because the liveness lease is budget-scaled (preStageDispatchTimeout, ~300s by default), that
// wedged the migration in PreCopyMemory for MINUTES — StorageReadyForFreeze is never set, no reconcile
// may re-claim until the lease expires, and to an operator (or a stall monitor) it looks like a permanent
// PreCopyMemory stall even though memory pre-copy has already converged. This is the mirror image of the
// idle-pod finalize livelock ADR-0407 closed, on the sibling path that was never hardened. Retry in place
// with the SAME storm-sized backoff, re-verifying the token every pass so a superseded or already-advanced
// claim is never clobbered. On genuine exhaustion the marker is left InFlight and the liveness lease is the
// (slower) backstop — strictly no worse than the pre-hardening single-shot behavior, never a double dispatch
// (a re-claim mints a fresh token and this holder's stale token can no longer finalize).
func (r *PodMigrationReconciler) releaseStoragePreStageClaim(ctx context.Context, pm *pmv1.PodMigration, token string) {
	log := logf.FromContext(ctx)
	key := client.ObjectKeyFromObject(pm)
	var released bool
	err := retry.RetryOnConflict(storagePreStageFinalizeBackoff, func() error {
		fresh := &pmv1.PodMigration{}
		if err := r.Get(ctx, key, fresh); err != nil {
			return err
		}
		d := fresh.Status.StoragePreStageDispatch
		if d == nil || d.ClaimToken != token || d.Phase != pmv1.StoragePreStageInFlight {
			// Superseded, already released, or already advanced by this holder — nothing to clear. Not a
			// conflict; the retry machinery short-circuits (returns nil) exactly as the pre-fix code did.
			return nil
		}
		base := fresh.DeepCopy()
		fresh.Status.StoragePreStageDispatch = nil
		if err := r.Status().Patch(ctx, fresh, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			// A 409 here is a transient resourceVersion collision with an UNRELATED writer — this holder
			// still owns the token (re-verified above this pass). Return it so RetryOnConflict re-Gets,
			// re-verifies the token, and re-Patches. A non-conflict error is returned as-is.
			return err
		}
		released = true
		return nil
	})
	if err != nil {
		log.V(1).Info("ADR-0398/0407: releasing transient storage pre-stage claim conflicted past the storm-sized retry — marker left InFlight, a later reconcile re-claims after the liveness lease", "migration", pm.Name, "err", err.Error())
		return
	}
	if released {
		pm.Status.StoragePreStageDispatch = nil
	}
}

// armTier1ColdRecreateIfEligible implements ADR-0396 D1 as corrected by ADR-0398 D2: the operator-side,
// in-process arming step for the bare-pod Tier1-Longhorn classifier gate. Called immediately BEFORE the
// storage pre-stage dispatch, it returns an armStoragePreStageOutcome the caller threads into RunPreStage
// (as coldRecreateArmed = armed) — NEVER a status field, so there is nothing on the wire for the
// co-writing agent SA to forge.
//
// It returns armOutcomeArmed IFF the pod is eligible (bare AND mounts a Longhorn-backed PVC) AND the
// operator successfully captured and read-back-verified ADR-0393's operator-keyed-HMAC recovery snapshot
// for THIS migration (captureSourcePodSpecSnapshot, hardened by ADR-0396 D-KILL-FIX). armOutcomeArmed is
// therefore, by construction, an operator-keyed-HMAC-verified fact about a durable recovery artifact —
// exactly what the downstream irreversible early-source-release must be authorized on.
//
// armOutcomeNoOp is returned for a pod-intrinsic non-eligibility (owned pod, or bare non-Longhorn pod);
// dispatch proceeds disarmed and the pod classifies by its own tier. armOutcomeTransient is returned when
// the pod IS eligible but capture failed for a retryable reason (ADR-0398 D2) — the caller must NOT
// dispatch and must NOT record a verdict, so no transient infrastructure fault is ever baked into a
// terminal disarmed dispatch (which would write a false BlockedVolume). The soundness of
// armed := (capture == nil) depends on D-KILL-FIX being in this same binary (see ADR-0396 "Atomicity"
// precondition): without it, capture returns nil on a forged present snapshot and armed becomes forgeable.
func (r *PodMigrationReconciler) armTier1ColdRecreateIfEligible(ctx context.Context, pm *pmv1.PodMigration, sourcePod *corev1.Pod) armStoragePreStageOutcome {
	log := logf.FromContext(ctx)

	// Eligibility (cheap): only a BARE pod (no owning controller — the SAME exported predicate the
	// classifier's gate uses, so arming-time and classification-time cannot disagree on "bare") that
	// mounts at least one Longhorn-backed PVC is eligible. Owned pods recover via their controller;
	// bare non-Longhorn pods never enter the Tier1-Longhorn early-release datapath. Either is a NO-OP
	// (a pod-intrinsic fact, not a failure) — dispatch proceeds disarmed for these.
	if storage.PodHasControllerOwner(sourcePod) {
		return armOutcomeNoOp
	}
	if !r.podMountsLonghornPVC(ctx, sourcePod) {
		return armOutcomeNoOp
	}

	// Arm by ACTUALLY capturing (reuse ADR-0393's capture — do not re-implement). Its success exercises
	// every dependency of the recovery path for this pod's spec (source readable, spec serializable,
	// operator-only signing key loadable, status write succeeds, read-back HMAC verification passes) and
	// is an operator-keyed-HMAC-verified fact.
	//
	// ADR-0398 D2: an eligible bare-Longhorn pod whose capture FAILS is TRANSIENT/retryable, NOT a
	// terminal disarm. The live defect (map §3) was exactly this — a podmigrations/status lost update
	// makes the read-back Get return nil for a perfectly armable pod. Because from inside a single
	// reconcile "key unreadable this instant" is indistinguishable from "key never deployed", we do not
	// re-introduce a fast terminal BlockedVolume here; all capture failures resolve via bounded
	// re-arm-then-honest-budget-expiry (the caller releases the claim and requeues). This removes the
	// disarmed-writer entirely from the race.
	if err := r.captureSourcePodSpecSnapshot(ctx, pm, sourcePod); err != nil {
		log.Info("ADR-0398: cold-recreate could not be armed for this eligible bare-Longhorn pod (transient) — will re-arm; NOT dispatching disarmed, NOT writing BlockedVolume",
			"migration", pm.Name, "err", err.Error())
		return armOutcomeTransient
	}
	return armOutcomeArmed
}

// podMountsLonghornPVC reports whether pod mounts at least one PVC backed by a Longhorn StorageClass,
// using the SAME storage.IsLonghornStorageClass rule the classifier uses (never a second, drift-prone
// re-derivation of "what is Longhorn"). It is a cheap eligibility pre-check for arming; a PVC/StorageClass
// that cannot be resolved is treated as "not Longhorn" (conservative — a non-Longhorn read error must not
// arm). The authoritative tier decision is still the classifier's; this only gates whether arming is even
// attempted, so an over-broad true here at worst captures an unneeded (still operator-signed) snapshot,
// and a false here simply leaves the pod on ADR-0391's unconditional-refuse default.
func (r *PodMigrationReconciler) podMountsLonghornPVC(ctx context.Context, pod *corev1.Pod) bool {
	for i := range pod.Spec.Volumes {
		pvcRef := pod.Spec.Volumes[i].PersistentVolumeClaim
		if pvcRef == nil {
			continue
		}
		pvc := &corev1.PersistentVolumeClaim{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: pvcRef.ClaimName}, pvc); err != nil {
			continue
		}
		if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName == "" {
			continue
		}
		sc := &storagev1.StorageClass{}
		if err := r.Get(ctx, types.NamespacedName{Name: *pvc.Spec.StorageClassName}, sc); err != nil {
			continue
		}
		if storage.IsLonghornStorageClass(sc) {
			return true
		}
	}
	return false
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
		// ConditionZeroWindowArmed is NOT a mere phase-completion marker like the other
		// None-mode "Skipped" conditions (SocketInventoryComplete, DestinationNetnsReady,
		// VXLANFDBUpdated, IPHandoffInjected) — it is ALSO the fail-closed antecedent of the
		// single source-teardown gate (SourceTeardownBlockReason / disarmZeroWindowOnFailurePath):
		// "if a real TC-BPF hold was armed, teardown is blocked until it is confirmed disarmed."
		// In None mode NO hold is ever armed (there is no frozen source socket to protect), so
		// the honest value is FALSE, not True-with-reason-Skipped. Recording True here was a
		// convention-collision bug: it made the teardown gate's antecedent fire on a mode that
		// never arms a hold, and the ONLY producer of ZeroWindowDisarmed=True is
		// reconcileDisengageHold — which the None-mode legacy completion tail
		// (reconcileRestoringNRI -> MigrationPhaseVerifying -> reconcileVerifying, which routes
		// only Strict onward to DisengageHold) never traverses. The result was a permanent
		// deleteSourcePodIfSafe SAFETY BLOCK ("ZeroWindowArmed=True but ZeroWindowDisarmed is not
		// True") that wedged phase=Verifying past the completion budget into a fail-closed
		// rollback, even though the restore, traffic, and liveness had all verified. Setting
		// FALSE makes the antecedent honest so the gate is vacuously satisfied for None on EVERY
		// route (modern DisengageHold spine AND legacy Verifying tail) with no papering-over
		// disarm marker required — matching the contract the gate and its falsifiable test
		// (source_teardown_test.go "None_ArmedFalse_Allowed") already assume. The doc comments on
		// SourceTeardownBlockReason and disarmZeroWindowOnFailurePath ("in None/BestEffort mode
		// where ZeroWindowArmed is never set True") are now accurate rather than aspirational.
		log.Info("ZeroWindowArm: skipped (TCPPreservationMode=None) — recording ZeroWindowArmed=False (no hold armed; keeps the source-teardown gate antecedent honest)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionZeroWindowArmed, metav1.ConditionFalse,
			"Skipped", "TCPPreservationMode=None: no zero-window hold armed — nothing to disarm; source-teardown gate antecedent stays False")
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

	// Step 2: transfer + scheduling-gate removal. Advance once conditionSchedulingGateRemoved=True
	// — the true terminal state of reconcileTransferring — not merely CheckpointTransferred.
	//
	// sprint49 finding: gating on CheckpointTransferred alone is a real durability bug.
	// reconcileTransferring persists CheckpointTransferred=true partway through its own body
	// (before earlyReleaseSourceForTier1Longhorn and scheduling-gate removal run), and can then
	// return early (e.g. ADR-0356's early-release-not-yet-safe requeue) without ever reaching
	// removeSchedulingGate on that same call. On the NEXT reconcile, checking only
	// CheckpointTransferred here would see it already true and skip calling
	// reconcileTransferring again entirely — silently abandoning the migration with the
	// scheduling gate still in place and the destination pod stuck at PodSchedulingGated
	// forever, while this function nonetheless advances the phase past it. Checking
	// conditionSchedulingGateRemoved instead keeps re-entering reconcileTransferring (which is
	// already idempotent — see its own CheckpointTransferred branch — so this costs nothing)
	// until it has actually reached and completed gate removal.
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionSchedulingGateRemoved) {
		return r.reconcileTransferring(ctx, pm)
	}

	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseOverlayHandoff)
}

// gateStorageCutoverBeforeRestore blocks the phase transition into RestoreSocketReattach —
// the first phase in the NRI hook's restore accept-set (nri/plugin.go verifyPhaseInAcceptSet:
// exactly {Restoring, RestoreSocketReattach, DisengageHold}) — until the destination storage
// engine has actually collapsed to a single owner (StorageMgr.Cutover + AwaitSingleOwner).
//
// This must run and complete BEFORE transitionTo(RestoreSocketReattach) persists the new phase
// to the API server, not merely before this function returns control to the controller-runtime
// work queue: the NRI StartContainer hook is driven by an independent kubelet event and reads
// pm.Status.Phase straight from the API server the instant the write lands — it does not wait
// for, or care about, whether the controller's own next reconcile (reconcileRestoreSocketReattach
// / reconcileRestoring) has even started running. A gate placed inside reconcileRestoring is
// therefore too late (sprint49 live finding): phase is already RestoreSocketReattach by the time
// that function runs, so the NRI hook's phase check already passes and restore may already be
// racing ahead on a separate goroutine driven entirely by kubelet/containerd. This call site —
// the last moment before that phase write — is the only place that actually gates the NRI path.
//
// Ordering: this MUST run after scheduling-gate removal (unconditional, end of
// reconcileTransferring), never before. Longhorn's real dual-engine collapse
// (tier1.go AwaitSingleOwner) only begins once the destination pod is actually SCHEDULED and
// kubelet issues NodeStageVolume there — that is what makes longhorn-manager populate
// spec.migrationNodeID and start the second engine. Gating AwaitSingleOwner before the
// scheduling gate is removed is a permanent deadlock: it polls for a collapse that can never
// start because the pod it needs mounted on the destination node was never allowed to schedule.
// (This is exactly what the sprint49 live-proof run hit: a 2-minute AwaitSingleOwner timeout
// with the destination Longhorn volume still "detached"/"unknown" — it never had a chance to
// attach.) reconcileOverlayHandoff runs strictly after reconcileTransferring/scheduling-gate
// removal in the phase graph, so by the time this gate runs the destination pod has had the
// full OverlayHandoff phase's worth of time to schedule and mount.
//
// Returns ready=true once ConditionStorageCutoverComplete is True (including the case where
// r.StorageMgr is nil — no storage manager wired, e.g. some unit tests — treated as a no-op
// pass-through rather than a permanent block). ready=false means the caller must return the
// given ctrl.Result (a bounded requeue) without transitioning the phase.
func (r *PodMigrationReconciler) gateStorageCutoverBeforeRestore(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, bool, error) {
	log := logf.FromContext(ctx)

	if r.StorageMgr == nil {
		return ctrl.Result{}, true, nil
	}
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionStorageCutoverComplete) {
		return ctrl.Result{}, true, nil
	}

	if err := r.StorageMgr.Cutover(ctx, pm); err != nil {
		log.Error(err, "OverlayHandoff: storage cutover failed — requeuing before allowing the restore-eligible phase",
			"migration", pm.Name)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, false, nil
	}
	if err := r.StorageMgr.AwaitSingleOwner(ctx, pm); err != nil {
		log.Error(err, "OverlayHandoff: await-single-owner failed — requeuing before allowing the restore-eligible phase",
			"migration", pm.Name)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, false, nil
	}

	// Cutover/AwaitSingleOwner patch ConditionStorageCutoverComplete on their own
	// freshly-fetched copy of the CR (StorageMigrationManager.patchStorageCutover), not on
	// this reconcile's in-memory pm. Re-fetch conditions here so the caller's subsequent
	// statusUpdate/transitionTo calls — full Status replaces, not merges — don't clobber that
	// just-written condition with the stale in-memory copy.
	fresh := &pmv1.PodMigration{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(pm), fresh); err != nil {
		return ctrl.Result{}, false, fmt.Errorf("re-fetch PodMigration after storage cutover: %w", err)
	}
	pm.Status.Conditions = fresh.Status.Conditions
	return ctrl.Result{}, true, nil
}

// reconcileOverlayHandoff injects the two-sided AF_BRIDGE FDB and AF_INET neighbor entries
// on both nodes so the destination pod netns receives traffic at the source IP (ADR-0048).
func (r *PodMigrationReconciler) reconcileOverlayHandoff(ctx context.Context, pm *pmv1.PodMigration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionVXLANFDBUpdated) {
		if res, ready, err := r.gateStorageCutoverBeforeRestore(ctx, pm); err != nil || !ready {
			return res, err
		}
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseRestoreSocketReattach)
	}

	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone {
		log.Info("OverlayHandoff: skipped (TCPPreservationMode=None)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionVXLANFDBUpdated, metav1.ConditionTrue,
			"Skipped", "TCPPreservationMode=None: overlay FDB injection not required")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		if res, ready, err := r.gateStorageCutoverBeforeRestore(ctx, pm); err != nil || !ready {
			return res, err
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
	//
	// ADR-0357 D1/D1.1 CORRECTION: this value is now VACUOUS/IGNORED on the agent side. This
	// call is PreRestore:true — CRIU restore has not run yet on either path, so seeding
	// categorically cannot have happened, and no client-supplied bool sent here can make
	// predicate B real. The stale comment this replaces described a *conditional* rule
	// ("non-empty TCPSeqSnapshots means SeedSeqXlat ran during Restore") that the code never
	// actually implemented — it sent `true` unconditionally in both branches, which is exactly
	// the "trust a client-supplied bool pre-restore" defect ADR-0357 exists to close (Context
	// item 2). The real fix lives in network.CheckAtomicityBarrier: when BarrierPredicates.
	// PreRestore is true, predicate B is explicitly DEFERRED (vacuous pass, same idiom as
	// predicates E-source/F below it) rather than evaluated against whatever bool arrives here.
	// Predicate B becomes real post-restore, gated on pm.Status.SeqXlatSeeded — see
	// reconcileDisengageHold (D1.3). The field is still sent (proto requires a value; the agent
	// ignores it in PreRestore mode) so as not to change the wire shape.
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
	if res, ready, err := r.gateStorageCutoverBeforeRestore(ctx, pm); err != nil || !ready {
		return res, err
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

	// OverlayReady post-restore gate — ADR-0352 / invariant #10 (primitives over brittle chains).
	// The ADR-0049 6-predicate atomicity barrier is NOT re-derived here by re-issuing a live
	// ConfirmOverlayReady RPC to the destination agent. Every predicate the post-restore pass
	// would check has already been written to CR status as a source-of-truth condition by an
	// upstream phase, and the pure read of those write-backs IS the primitive:
	//   B/C/D (PM_SEQ_XLAT seeded + AF_BRIDGE/AF_INET FDB confirmed on the destination) and the
	//     destination-conntrack axis of E  ->  VXLANFDBUpdated=True (reconcileOverlayHandoff,
	//     pre-restore pass; the RPC already ran once there and recorded the result).
	//   E source-conntrack axis (deferred pre-restore per ADR-0049 §gate20)  ->
	//     Status.SourceConntrackArmed (written by reconcileZeroWindowArm).
	//   F (CRIU restore complete)  ->  Restored=True (reconcileRestoreSocketReattach).
	// Re-deriving this via a remote RPC that can transiently fail (agent-connection blip, netlink
	// re-probe, status-update conflict) is the brittle chain that wedged the live redis Strict
	// migration at phase=DisengageHold for the full 120s cap in sprint46B4 live-proof cycle 2:
	// the barrier's own inputs were already True in status (VXLANFDBUpdated=True, Restored=True,
	// SourceConntrackArmed=true — see live-proof-c2-transcript.txt) while the re-check requeued
	// every 5s and never advanced. Read the write-backs directly; fail CLOSED to rollback if an
	// upstream invariant is somehow absent (these conditions gate entry to this phase, so their
	// absence is a real defect, never a wait condition — infinite requeue would trip invariant #8).
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionOverlayReady) {
		fdbConfirmed := meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionVXLANFDBUpdated)
		restoreComplete := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionRestored)
		if !fdbConfirmed || !restoreComplete || !pm.Status.SourceConntrackArmed {
			msg := fmt.Sprintf("post-restore overlay barrier inputs not all present in status: "+
				"VXLANFDBUpdated=%v Restored=%v SourceConntrackArmed=%v (ADR-0049 predicates B–F) — failing closed",
				fdbConfirmed, restoreComplete, pm.Status.SourceConntrackArmed)
			log.Error(nil, "DisengageHold: "+msg, "migration", pm.Name)
			setCondition(pm, pmv1.ConditionOverlayReady, metav1.ConditionFalse, "BarrierInputsAbsent", msg)
			if sErr := r.statusUpdate(ctx, pm); sErr != nil {
				return ctrl.Result{}, sErr
			}
			return r.initiateRollback(ctx, pm, msg)
		}
		overlayMsg := "All ADR-0049 barrier predicates satisfied from source-of-truth status " +
			"write-backs (VXLANFDBUpdated=B/C/D+dest-E, SourceConntrackArmed=source-E, Restored=F); " +
			"post-restore live re-probe RPC retired per invariant #10 (ADR-0352)"
		log.Info("DisengageHold: overlay ready from status conditions — no live re-probe (ADR-0352)",
			"migration", pm.Name)
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
			// fail-closed phase-gate (item 5): an RPC error means the controller has NO signal at all about
			// the actual hold state — it is not evidence the watchdog fired, and the
			// ConditionZeroWindowDisarmed=True this branch used to set on error was a
			// fabricated pass. Retry (bounded) so the next reconcile gets a real
			// DisarmZeroWindowResponse once the agent is reachable again — matching the
			// established local idiom for "can't reach the agent right now" (AgentPool==nil /
			// connect-failure branches above). ADR-0157's watchdog auto-disarms the BPF hold
			// independently on its own timer regardless of RPC reachability, so bounding the
			// retry here only bounds "how long before the controller gives up waiting for
			// real evidence" — it does not affect hold safety.
			attempts := readDisarmZeroWindowRetryAttempts(pm)
			if attempts < len(disarmZeroWindowRetryBackoff) {
				backoff := disarmZeroWindowRetryBackoff[attempts]
				if pm.Annotations == nil {
					pm.Annotations = make(map[string]string)
				}
				pm.Annotations[disarmZeroWindowRetryAttemptsAnnotation] = strconv.Itoa(attempts + 1)
				if updErr := r.Update(ctx, pm); updErr != nil {
					return ctrl.Result{}, updErr
				}
				log.Error(err, "DisengageHold: DisarmZeroWindow RPC error — retrying for a real answer (fail-closed phase-gate)",
					"migration", pm.Name, "attempt", attempts+1, "backoff", backoff)
				return ctrl.Result{RequeueAfter: backoff}, nil
			}
			// Retry budget exhausted: surface a real, visible failure — never a fabricated
			// True. The migration cannot safely be declared to have a disarmed hold when the
			// controller has never once observed a real DisarmZeroWindowResponse.
			msg := fmt.Sprintf("DisarmZeroWindow RPC failed after %d retries (last error: %v); "+
				"no verified hold-disarm signal obtained (fail-closed phase-gate)", len(disarmZeroWindowRetryBackoff), err)
			log.Error(err, "DisengageHold: "+msg, "migration", pm.Name)
			setCondition(pm, pmv1.ConditionZeroWindowDisarmed, metav1.ConditionFalse,
				"DisarmVerificationExhausted", msg)
			if r.Recorder != nil {
				r.Recorder.Eventf(pm, corev1.EventTypeWarning, "ZeroWindowDisarmVerificationFailed",
					"DisarmZeroWindow RPC retry budget exhausted for migration %s: %v", pm.Name, err)
			}
			if pm.Annotations != nil {
				delete(pm.Annotations, disarmZeroWindowRetryAttemptsAnnotation)
			}
			if sErr := r.statusUpdate(ctx, pm); sErr != nil {
				return ctrl.Result{}, sErr
			}
			return r.initiateRollback(ctx, pm, msg)
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

	// ADR-0357 D1.3: PM_SEQ_XLAT relay wiring is real (D1/D2), not an M20 placeholder. Read the
	// destination agent's write-back (pm.Status.SeqXlatSeeded, a plain bool set only after
	// EBPFManager.LookupSeqXlat confirms the PM_SEQ_XLAT entry is actually resident in the
	// kernel map — D1.2) as a bare bool, the same read style as the pm.Status.SourceConntrackArmed
	// check above (predicate E-source), never meta.IsStatusConditionTrue. When TCPSeqSnapshots is
	// empty there is nothing to seed — predicate B is vacuously satisfied (D1.4). When
	// TCPSeqSnapshots is non-empty but SeqXlatSeeded was never confirmed, fail closed to
	// rollback rather than silently reporting RelayProgramsLoaded=True — the exact defect this
	// ADR closes (a live Strict migration reporting success while PM_SEQ_XLAT was categorically
	// absent from the kernel).
	if len(pm.Status.TCPSeqSnapshots) > 0 && !pm.Status.SeqXlatSeeded {
		msg := fmt.Sprintf("PM_SEQ_XLAT seeding required (%d TCP sequence snapshot(s)) but "+
			"Status.SeqXlatSeeded is not set — the destination agent never confirmed a verified "+
			"bpf_map_lookup write-back (ADR-0357 D1/D2); failing closed rather than reporting "+
			"relay-programs-loaded on an unverified/absent seq translation", len(pm.Status.TCPSeqSnapshots))
		log.Error(nil, "DisengageHold: "+msg, "migration", pm.Name)
		setCondition(pm, pmv1.ConditionRelayProgramsLoaded, metav1.ConditionFalse, "SeqXlatNotSeeded", msg)
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr
		}
		return r.initiateRollback(ctx, pm, msg)
	}
	relayMsg := fmt.Sprintf("Zero-window hold disarmed; PM_SEQ_XLAT relay verified via destination "+
		"bpf_map_lookup write-back (seqXlatSeeded=%v, tcpSeqSnapshotCount=%d) (ADR-0357 D1/D2)",
		pm.Status.SeqXlatSeeded, len(pm.Status.TCPSeqSnapshots))
	log.Info("DisengageHold: ZW hold disarmed; PM_SEQ_XLAT relay verified (ADR-0357 D1/D2)",
		"migration", pm.Name, "seqXlatSeeded", pm.Status.SeqXlatSeeded, "tcpSeqSnapshotCount", len(pm.Status.TCPSeqSnapshots))
	setCondition(pm, pmv1.ConditionRelayProgramsLoaded, metav1.ConditionTrue, "SeqXlatVerified", relayMsg)
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
	// Thread the source-freeze TCP sequence snapshots (captured at Checkpoint and persisted in
	// pm.Status.TCPSeqSnapshots) into the VerifyTCP request. Without this the destination agent's
	// VerifyTCP fails closed with "source SeqSnapshots absent": it resolves the source snapshots
	// from its per-migration migrationSeqSnapshots map, but that map is written ONLY on the gRPC
	// join-ns Restore path (server.go). The live North Star restore runs through the NRI
	// JoinNsRestore hook (cmd/agent/main.go) — and any gRPC Restore that follows takes the
	// ADR-0228 idempotent-confirm early return — so on the live path the map is NEVER populated
	// and VerifyTCP has no source snapshots to compare against even though this controller holds
	// them in status. pm.Status is the restart-durable source of truth and is populated identically
	// for the NRI and gRPC restore paths, so passing it via SourceSeqSnapshots (which VerifyTCP
	// already consults as a fallback when its stored map is empty, server.go) makes verification
	// restore-path-agnostic. This does NOT weaken the fail-closed guard: if no connection was
	// inventoried at freeze, TCPSeqSnapshots is empty and the guard still fires for a live dest
	// connection.
	// ADR-0406: route through the single-authority conversion helper so this site cannot
	// drift from the restore call sites on the TCPSeqSnapshot -> SeqSnapshot field mapping.
	vtcpReq.SourceSeqSnapshots = buildRestoreSeqSnapshots(pm)
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

	// ADR-0388 (corrects ADR-0352 B8-DR-2 / D6(i) / DR-23) — Strict NON-VACUITY guard
	// (source-of-truth read, not inferred continuity). Under Strict, preserving active TCP
	// connections IS the guarantee. VerifyTCP legitimately returns Verified=true with
	// ConnectionsExpected=0 for the STATELESS fast path (server.go: no source SeqSnapshots AND
	// no destination ESTABLISHED sockets). For None/BestEffort that is a real pass. B8-DR-2
	// originally treated that ConnectionsExpected==0 case as a VACUOUS proof for Strict too and
	// failed closed. Chad's standing direction (2026-07-23, this sprint) corrects that: a
	// genuine zero — nothing was held, nothing needed to be preserved — is a TRIVIAL PASS, not
	// an unprovable one; "vacuous" no longer applies to an honest zero. A real MISMATCH
	// (ConnectionsVerified != ConnectionsExpected, i.e. some but not all expected connections
	// verified) remains a hard failure — that is not vacuity, it is a connection that was
	// expected to survive and did not. This reads vtcpResp.ConnectionsExpected/
	// ConnectionsVerified directly, the same source-of-truth field this ADR has always used —
	// only the disposition on a confirmed zero has changed.
	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict {
		switch {
		case vtcpResp.ConnectionsExpected == 0:
			// Nothing to preserve — Strict trivially satisfied. Skip the mismatch/app-probe
			// checks below: both are evidence about a held connection that does not exist here.
			log.Info("TCPVerifying: Strict — no active connections to preserve — Strict trivially satisfied",
				"migration", pm.Name)
		case vtcpResp.ConnectionsVerified != vtcpResp.ConnectionsExpected:
			msg := fmt.Sprintf("ADR-0352 B8-DR-2: Strict mode requires ConnectionsVerified==ConnectionsExpected "+
				"but VerifyTCP returned verified=%d/expected=%d — a genuine connection that was expected to "+
				"survive did not verify; failing closed",
				vtcpResp.ConnectionsVerified, vtcpResp.ConnectionsExpected)
			log.Error(nil, msg, "migration", pm.Name)
			setCondition(pm, pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionFalse,
				"VacuousTCPProof", msg)
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			return r.initiateRollback(ctx, pm, msg)
		default:
			// The application-probe result was previously computed but never gated (decorative). When a
			// probe IS configured, its outcome is authoritative liveness evidence for the held connection
			// and must be OK for a Strict pass; a probe-less Strict migration is not forced to invent one.
			if pm.Spec.ApplicationProbe != nil && !vtcpResp.AppProbeOk {
				msg := fmt.Sprintf("ADR-0352 B8-DR-2: Strict mode with a configured %s application probe requires "+
					"AppProbeOk=true but VerifyTCP returned AppProbeOk=false (%s) — the held connection is not "+
					"provably alive post-restore; failing closed",
					pm.Spec.ApplicationProbe.Protocol, vtcpResp.AppProbeError)
				log.Error(nil, msg, "migration", pm.Name)
				setCondition(pm, pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionFalse,
					"AppProbeFailed", msg)
				if err := r.statusUpdate(ctx, pm); err != nil {
					return ctrl.Result{}, err
				}
				return r.initiateRollback(ctx, pm, msg)
			}
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

	// ADR-0388 (corrects ADR-0352 B8-DR-2 / D6(i) / DR-23) — NON-VACUITY GATE (invariant #10
	// substrate primitive). This gate now fails closed ONLY on the negative missing-snapshot
	// sentinel (ConnectionsExpected<0, internal/agent/server/server.go — source SeqSnapshots
	// absent but destination has live ESTABLISHED connections: an infra/proto problem, not a
	// genuine zero — absence of evidence is still not proof of continuity). A genuine zero
	// (ConnectionsExpected==0, the agent stateless fast-path) is no longer vacuous under Chad's
	// standing direction (2026-07-23, this sprint): nothing was held, so Strict is trivially
	// satisfied and TCPSequenceContinuityVerified=True may be certified. No-op for BestEffort/
	// None, which legitimately preserve nothing.
	if reason := strictTCPContinuityVacuityReason(pm.Spec.TCPPreservationMode, vtcpResp); reason != "" {
		msg := fmt.Sprintf("ADR-0352 DR-23 non-vacuity gate: %s — refusing to certify TCPSequenceContinuityVerified; rolling back rather than tearing down the source on a vacuous proof", reason)
		log.Error(nil, msg, "migration", pm.Name)
		setCondition(pm, pmv1.ConditionTCPSequenceContinuityVerified, metav1.ConditionFalse,
			"VacuousZeroConnectionProof", msg)
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

// strictTCPContinuityVacuityReason implements the ADR-0388 (corrects ADR-0352 B8-DR-2 / D6(i) /
// DR-23) NON-VACUITY primitive as a PURE, source-of-truth predicate (invariant #10: an
// authoritative read that fails closed, not a control-flow/harness inference).
//
// A SUCCESSFUL VerifyTCP response (Verified=true) can report ConnectionsExpected==0 via the
// agent's stateless fast-path (internal/agent/server/server.go, "no source SeqSnapshots and no
// destination ESTABLISHED sockets" branch) when ZERO ESTABLISHED connections were snapshotted at
// the source freeze. Prior to ADR-0388 this was treated as a VACUOUS proof under Strict and failed
// closed (the sprint46B "0/0 connections" cycle-2 finding, DR-23). Chad's standing direction
// (2026-07-23, this sprint) corrects that: a genuine zero means there was nothing to preserve, so
// Strict is TRIVIALLY SATISFIED, not unprovable — TCPSequenceContinuityVerified=True may be
// certified on an honest zero.
//
// What remains vacuous (still fails closed): the NEGATIVE sentinel ConnectionsExpected<0
// (internal/agent/server/server.go — source SeqSnapshots were absent but the destination reports
// live ESTABLISHED connections; an infra/proto problem, not a confirmed zero). Absence of evidence
// is still not proof of continuity for that case (ADR-0049) — only a *positive, observed* zero is
// trivially satisfied, never an unknown/error state. Returns a non-empty reason ONLY for Strict
// with ConnectionsExpected<0. BestEffort/None legitimately preserve nothing, so they are never
// vacuous here. (ConnectionsVerified==ConnectionsExpected and seq_delta==0 for a real held count
// are already enforced upstream: any unmatched 4-tuple or over-MSS drift sets Verified=false or
// trips the mismatch/seq_delta gates above.)
func strictTCPContinuityVacuityReason(mode pmv1.TCPPreservationMode, vtcpResp *agentpb.VerifyTCPResponse) string {
	if mode != pmv1.TCPPreservationModeStrict {
		return ""
	}
	if vtcpResp.GetConnectionsExpected() >= 0 {
		return ""
	}
	return fmt.Sprintf("Strict requires source snapshots to be present but VerifyTCP reported ConnectionsExpected=%d ConnectionsVerified=%d (missing-snapshot sentinel, not a genuine zero — infra/proto problem, not vacuity)",
		vtcpResp.GetConnectionsExpected(), vtcpResp.GetConnectionsVerified())
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

// ensureWorkloadLivenessVerified drives the ADR-0325 real-liveness probe against the DESTINATION
// pod's CURRENT IP and sets ConditionWorkloadLivenessVerified accordingly. It is the shared
// mechanism used by BOTH the newer ServiceVerifying phase and the legacy Verifying phase so that
// the ADR-0325 gate — which sourcePodDeletionBlockReason enforces for ALL modes (including None) —
// is actually PRODUCED on whichever verification path a migration takes. Without this, the legacy
// live-migration path (…→RestoreSocketReattach→Verifying) reached the deletion gate that requires
// WorkloadLivenessVerified but never ran the phase that sets it, deadlocking None migrations.
//
// The probe targets the replacement pod's real, current IP (NOT the old source IP) — exactly the
// new-IP liveness this gate is meant to confirm. Returns:
//   - verified=true  → WorkloadLivenessVerified is now True (probe passed or NoKnownProtocol).
//   - verified=false → the condition was set False (probe failed / ambiguous / not yet ready);
//     res carries the requeue the caller should return.
func (r *PodMigrationReconciler) ensureWorkloadLivenessVerified(ctx context.Context, pm *pmv1.PodMigration) (verified bool, res ctrl.Result) {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionWorkloadLivenessVerified) {
		return true, ctrl.Result{}
	}

	destPodName := pm.Status.ReplacementPodName
	if destPodName == "" {
		destPodName = pm.Spec.PodName
	}
	destPod := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: destPodName}, destPod); err != nil {
		log.Error(err, "ensureWorkloadLivenessVerified: ADR-0325 destination pod fetch failed — requeuing", "migration", pm.Name, "destPod", destPodName)
		return false, ctrl.Result{RequeueAfter: 5 * time.Second}
	}
	destPodIP := destPod.Status.PodIP

	probeProtocol, ambiguous, zeroMatch := resolveProbeProtocol(pm.Spec.ApplicationProbe, destPod)
	switch {
	case ambiguous:
		setWorkloadLivenessCondition(pm, false, "AmbiguousProbeDefault",
			"ADR-0325: multiple container-port heuristic matches; set spec.applicationProbe to disambiguate")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return false, ctrl.Result{}
		}
		return false, ctrl.Result{RequeueAfter: 30 * time.Second}
	case zeroMatch && pm.Spec.ApplicationProbe == nil:
		setWorkloadLivenessCondition(pm, true, "NoKnownProtocol",
			"ADR-0325: no application-probe protocol resolved; transport-only verification applies")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return false, ctrl.Result{}
		}
		return true, ctrl.Result{}
	}

	// Second-pass gate (fixes the false-positive Complete gap found this sprint — see
	// ConditionWorkloadLivenessFirstPass's doc comment and reconcileServiceVerifying's mirror of
	// this same logic): a single passing probe is not sufficient proof of a stable, still-alive
	// workload, since a workload can crash 40-60s after an apparently successful CRIU restore. Only
	// set ConditionWorkloadLivenessVerified True after a SECOND real probe, issued no sooner than
	// workloadLivenessStabilizationWindow after the first passing probe, also passes.
	firstPass := meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionWorkloadLivenessFirstPass)
	awaitingSecondPass := firstPass != nil && firstPass.Status == metav1.ConditionTrue
	if awaitingSecondPass {
		elapsed := time.Since(firstPass.LastTransitionTime.Time)
		if elapsed < workloadLivenessStabilizationWindow {
			return false, ctrl.Result{RequeueAfter: workloadLivenessStabilizationWindow - elapsed}
		}
	}

	if r.AgentPool == nil {
		log.Error(nil, "ensureWorkloadLivenessVerified: AgentPool not wired — requeuing", "migration", pm.Name)
		return false, ctrl.Result{RequeueAfter: 30 * time.Second}
	}
	destNode := pm.Status.DestinationNodeName
	destAgent, agentErr := r.AgentPool.ForNode(ctx, destNode)
	if agentErr != nil {
		log.Error(agentErr, "ensureWorkloadLivenessVerified: could not resolve destination-node agent client — requeuing", "migration", pm.Name, "destNode", destNode)
		return false, ctrl.Result{RequeueAfter: 30 * time.Second}
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
		if awaitingSecondPass {
			setCondition(pm, pmv1.ConditionWorkloadLivenessFirstPass, metav1.ConditionFalse, "ReconfirmationFailed",
				fmt.Sprintf("ADR-0325: second-pass workload-liveness probe (%s) against destination pod IP %s failed after the first pass had succeeded — workload died post-restore: %v / %s", probeProtocol, destPodIP, rpcErr, msg))
		}
		setWorkloadLivenessCondition(pm, false, reasonPrefix+"ProbeFailed",
			fmt.Sprintf("ADR-0325: workload-liveness probe (%s) against destination pod IP %s failed: %v / %s", probeProtocol, destPodIP, rpcErr, msg))
		if err := r.statusUpdate(ctx, pm); err != nil {
			return false, ctrl.Result{}
		}
		return false, ctrl.Result{RequeueAfter: 15 * time.Second}
	}
	if awaitingSecondPass {
		setWorkloadLivenessCondition(pm, true, reasonPrefix+"ProbePassed",
			fmt.Sprintf("ADR-0325: workload-liveness probe (%s) against destination pod IP %s passed on second, stabilization-window-delayed confirmation", probeProtocol, destPodIP))
		if err := r.statusUpdate(ctx, pm); err != nil {
			return false, ctrl.Result{}
		}
		return true, ctrl.Result{}
	}
	setCondition(pm, pmv1.ConditionWorkloadLivenessFirstPass, metav1.ConditionTrue, reasonPrefix+"ProbePassed",
		fmt.Sprintf("ADR-0325: workload-liveness probe (%s) against destination pod IP %s passed first pass; awaiting second confirmation in %s", probeProtocol, destPodIP, workloadLivenessStabilizationWindow))
	if err := r.statusUpdate(ctx, pm); err != nil {
		return false, ctrl.Result{}
	}
	return false, ctrl.Result{RequeueAfter: workloadLivenessStabilizationWindow}
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
		//
		// Second-pass gate (fixes the false-positive Complete gap found this sprint): a workload
		// can crash 40-60s AFTER a genuinely successful CRIU restore (observed live: Postgres
		// killed by an internal fault shortly after restore, while this exact single SQL/TCP probe
		// happened to catch it in its narrow alive window). A single passing probe is therefore not
		// sufficient proof of a stable, still-alive workload. ConditionWorkloadLivenessFirstPass
		// stages the first pass; ConditionWorkloadLivenessVerified (the condition every downstream
		// teardown/completion gate keys on) is only set True after a SECOND real probe, issued no
		// sooner than workloadLivenessStabilizationWindow after the first pass, ALSO passes. This is
		// a second genuine health confirmation against the live workload — not a longer wait/sleep
		// that merely narrows the odds of catching a death (CLAUDE.md SUBSTRATE-PRIMITIVE BIAS).
		firstPass := meta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionWorkloadLivenessFirstPass)
		awaitingSecondPass := firstPass != nil && firstPass.Status == metav1.ConditionTrue
		if awaitingSecondPass {
			elapsed := time.Since(firstPass.LastTransitionTime.Time)
			if elapsed < workloadLivenessStabilizationWindow {
				// Do not re-probe yet: the point of the gate is a probe issued LATER in time, not
				// more frequent probing now — re-probing early would just re-observe the same
				// narrow alive window the first pass already did.
				return ctrl.Result{RequeueAfter: workloadLivenessStabilizationWindow - elapsed}, nil
			}
		}
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
			if awaitingSecondPass {
				// The second, later probe is what actually caught the death: reset the staged
				// first pass so a later recovery must re-earn BOTH passes, and keep
				// WorkloadLivenessVerified False/never-set so no downstream gate reads a
				// false-positive Complete.
				setCondition(pm, pmv1.ConditionWorkloadLivenessFirstPass, metav1.ConditionFalse, "ReconfirmationFailed",
					fmt.Sprintf("ServiceVerifying: ADR-0325 second-pass workload-liveness probe (%s) failed after the first pass had succeeded — workload died post-restore: %v / %s", probeProtocol, rpcErr, msg))
			}
			setWorkloadLivenessCondition(pm, false, reasonPrefix+"ProbeFailed",
				fmt.Sprintf("ServiceVerifying: ADR-0325 workload-liveness probe (%s) failed: %v / %s", probeProtocol, rpcErr, msg))
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		if awaitingSecondPass {
			// Second real probe, issued after the stabilization window, also passed: the workload
			// has now been independently confirmed alive at two distinct points in time. Only now
			// is ConditionWorkloadLivenessVerified — the condition every teardown/completion gate
			// keys on — set True.
			setWorkloadLivenessCondition(pm, true, reasonPrefix+"ProbePassed",
				fmt.Sprintf("ServiceVerifying: ADR-0325 workload-liveness probe (%s) passed on second, stabilization-window-delayed confirmation", probeProtocol))
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			break
		}
		// First pass: stage it and require the second, later, independent confirmation above
		// before ConditionWorkloadLivenessVerified is ever set True.
		setCondition(pm, pmv1.ConditionWorkloadLivenessFirstPass, metav1.ConditionTrue, reasonPrefix+"ProbePassed",
			fmt.Sprintf("ServiceVerifying: ADR-0325 workload-liveness probe (%s) passed first pass; awaiting second confirmation in %s", probeProtocol, workloadLivenessStabilizationWindow))
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: workloadLivenessStabilizationWindow}, nil
	}

	// ADR-0352 D0.1: WorkloadLivenessVerified has just been (re-)established above (or was
	// already True) — this is the ADR-specified landing point: both convergence signals
	// (liveness + CRIURestoreConfirmed) are simultaneously observable here for the first
	// time this reconcile. Warn-only / idempotent — see markDestinationReadyIfConverged.
	r.markDestinationReadyIfConverged(ctx, pm, destPodIP)

	// ADR-0210 + ADR-0325: advance only when the AUTHORITATIVE cross-node
	// DataplaneReachabilityVerified is True AND (no known protocol OR WorkloadLivenessVerified
	// is True). Textual placement alone is insufficient — the guard condition itself gates on
	// the new predicate.
	//
	// Mode=None (ADR-0325): None deliberately accepts the replacement pod's NEW IP and does not
	// preserve the OLD source pod IP, so the ADR-0210 old-IP cross-node nonce probe
	// (DataplaneReachabilityVerified) is structurally inapplicable — injectIPHandoff is skipped
	// for None (see reconcileVerifying) and DataplaneReachabilityVerified is never set. For None
	// the AUTHORITATIVE liveness proof is WorkloadLivenessVerified against the replacement pod's
	// current IP (ADR-0325). Advance when the workload is verified alive on the new IP (or no
	// known protocol resolved, in which case transport-only verification applies). Strict and
	// BestEffort are unchanged: they still require the old-IP DataplaneReachabilityVerified gate.
	//
	// ADR-0352 D3: the two pod-IP-preservation inference producers
	// (tryEstablishCiliumDataplaneReachability, verifyDataplaneReachability — reached via
	// injectIPHandoff) are RETIRED from the Strict completion path. They could never
	// converge on some substrates (the never-converging Cilium-ipcache wedge the ADR-0352
	// Context documents), which is exactly the invariant-#10 brittle chain this ADR
	// replaces. D1's establishServiceContinuity (EndpointSlice-Ready enrollment + real
	// ClusterIP round-trip, both source-of-truth reads) is the replacement primitive — not
	// a stacked fallback tier. BestEffort/None are unaffected: their teardown gate remains
	// TrafficVerified via the service-path verifier below, and the legacy DataplaneReachability-
	// Verified veto (source_teardown.go D2.2b) still protects them via reconcileVerifying.
	//
	// ADR-0352 D4: the completion-deadline backstop's STRUCTURE is preserved byte-for-byte
	// from the retired ADR-0210 block — only the condition identifier changed
	// (DataplaneReachabilityVerified -> ServiceContinuityVerified) and the producer call
	// (injectIPHandoff -> establishServiceContinuity). Invariant #8 terminal bound
	// (fail-closed, source-of-truth deadline): without it the migration requeues here
	// forever once 2/3 of spec.completionTimeoutSeconds has elapsed since creation without
	// ServiceContinuityVerified converging — fail closed to RollingBack rather than wedging
	// past the 120s cap (source never deleted — ADR-0012).
	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict &&
		!meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionServiceContinuityVerified) {
		budgetSecs := pm.Spec.CompletionTimeoutSeconds
		if budgetSecs <= 0 {
			budgetSecs = 600
		}
		reachDeadline := pm.CreationTimestamp.Add(time.Duration(budgetSecs) * time.Second * 2 / 3)
		if !pm.CreationTimestamp.IsZero() && time.Now().After(reachDeadline) {
			log.Error(nil, "ServiceVerifying: ServiceContinuityVerified (ADR-0352 Service-continuity gate) not established within completion budget — failing closed to RollingBack (source never deleted, ADR-0012)",
				"migration", pm.Name, "budgetSeconds", budgetSecs)
			setCondition(pm, pmv1.ConditionServiceContinuityVerified, metav1.ConditionFalse, "ServiceContinuityDeadlineExceeded",
				fmt.Sprintf("ADR-0352: ServiceContinuityVerified not established within %ds completion budget; failing closed to rollback rather than wedging past the cap (source never deleted — ADR-0012)", budgetSecs))
			if sErr := r.statusUpdate(ctx, pm); sErr != nil {
				return ctrl.Result{}, sErr
			}
			return r.initiateRollback(ctx, pm, "ServiceContinuityVerified (ADR-0352) not established within completion budget")
		}
		if res, err, done := r.establishServiceContinuity(ctx, pm, destPodIP); !done {
			return res, err
		}
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
	}

	noneMode := pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeNone
	livenessOK := probeProtocol == "" || meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionWorkloadLivenessVerified)

	// Bugfix (found live this sprint): these three fast-path branches transition straight to
	// CutoverComplete on their respective liveness/reachability predicate WITHOUT ever running
	// the service-path verifier block below that actually sets conditionTrafficVerified=True.
	// deleteSourcePodIfSafe (ADR-0012) requires TrafficVerified=True before it will delete the
	// source pod, so taking one of these branches on the FIRST reconcile where the predicate
	// becomes true — before TrafficVerified has ever been set — wedges CutoverComplete forever
	// (source pod never deleted, migration never reaches phase=Complete). Each branch now sets
	// conditionTrafficVerified=True itself, recording the real predicate that justified skipping
	// the redundant verifier call, before transitioning.
	if noneMode {
		if livenessOK {
			setCondition(pm, conditionTrafficVerified, metav1.ConditionTrue, "WorkloadLivenessVerified",
				"TCPPreservationMode=None: WorkloadLivenessVerified (ADR-0325) is the authoritative liveness proof; service-path verifier skipped")
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			return r.transitionTo(ctx, pm, pmv1.MigrationPhaseCutoverComplete)
		}
	} else if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict {
		// ADR-0352 D2.1: Strict now advances on ServiceContinuityVerified, not the retired
		// DataplaneReachabilityVerified.
		if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionServiceContinuityVerified) && livenessOK {
			setCondition(pm, conditionTrafficVerified, metav1.ConditionTrue, "ServiceContinuityVerified",
				"TCPPreservationMode=Strict: ServiceContinuityVerified (ADR-0352 D1) established; service-path verifier skipped")
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			return r.transitionTo(ctx, pm, pmv1.MigrationPhaseCutoverComplete)
		}
	} else if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionDataplaneReachabilityVerified) && livenessOK {
		setCondition(pm, conditionTrafficVerified, metav1.ConditionTrue, "DataplaneReachabilityVerified",
			"TCPPreservationMode=BestEffort: DataplaneReachabilityVerified already established; service-path verifier skipped")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
		}
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

	// ADR-0352 D4 (re-pointed, structure unchanged from the retired ADR-0210 guard). The
	// service-path verifier above establishes TrafficVerified, which is a sufficient
	// teardown gate for BestEffort/None but NOT for Strict, whose SourceTeardownBlockReason
	// gate requires ServiceContinuityVerified=True (D2.1). Strict must reach CutoverComplete
	// ONLY through the authoritative gate above (the `ServiceContinuityVerified && livenessOK`
	// branch); advancing here on TrafficVerified alone is the exact bypass that wedged the
	// live redis Strict migration at CutoverComplete previously. The producer above normally
	// makes this unreachable for Strict (it exits once the gate converges, or holds until it
	// does); this guard fail-closes the residual edge — hold in ServiceVerifying (bounded
	// requeue; source never deleted — ADR-0012) rather than cutting over unproven.
	if strictMode && !meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionServiceContinuityVerified) {
		log.Info("ServiceVerifying: Strict — holding until ServiceContinuityVerified (ADR-0352 Service-continuity gate) is established; not advancing to CutoverComplete on TrafficVerified alone",
			"migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

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
// The predicate itself lives in exactly one place — pmv1.SourceTeardownBlockReason
// (api/v1alpha1/source_teardown.go) — and this function DELEGATES to it rather than
// hand-keeping a second copy. Prior to this fix this function was a byte-for-byte-identical
// but independently maintained duplicate: pmv1.SourceTeardownBlockReason's doc comment claimed
// "both call sites delegating to this one function is what makes their parity true BY
// CONSTRUCTION," but this call site never actually called it, and the traffic-package call site
// that did (traffic.EndpointSliceManager.RemoveSourceIfVerified) is dead code with no production
// caller — so the "by construction" parity claim was false. Delegating here makes it true for
// the live gate, and a drift-guard test
// (internal/controller/adr0344_restore_source_storage_test.go /
// internal/agent/traffic/remove_source_if_verified_test.go) asserts the two entry points agree.
// The predicate is:
//   - Strict:      ServiceContinuityVerified=True (ADR-0352 Service-continuity gate) AND
//     TCPSequenceContinuityVerified=True.
//   - BestEffort:  TrafficVerified=True AND TCPSequenceContinuityVerified=True.
//   - None:        TrafficVerified=True (legacy cold/stateless pre-check), AND
//   - ALL modes:   additionally WorkloadLivenessVerified=True (ADR-0325).
func sourcePodDeletionBlockReason(mode pmv1.TCPPreservationMode, conditions []metav1.Condition) string {
	return pmv1.SourceTeardownBlockReason(mode, conditions)
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
//
// earlyReleaseSourceForTier1Longhorn is the narrow, Tier1-Longhorn-only exception to ADR-0012
// documented in ADR-0356 (docs/adr/0356-tier1-longhorn-early-source-release.md). It does
// nothing for every other storage tier — ADR-0012's normal "never delete the source pod
// before TrafficVerified=True" rule is completely unchanged for TierRWX, TierCephRBD,
// TierSnapshotRsync, and pods with no PVCs at all.
//
// Why this exists: Longhorn's real collapse-to-single-owner mechanism for a
// TierLonghorn-classified volume is driven by Kubernetes' own CSI attacher, which only
// releases the source node's VolumeAttachment once no pod on that node references the PVC.
// For this tier that functionally requires the source pod to be gone BEFORE the destination
// pod can ever mount its volume — which gates CRIU restore, which gates TrafficVerified,
// which is exactly the condition ADR-0012 says must be true before the source pod is
// deleted. Neither side of that cycle can go first under ADR-0012's normal ordering; this
// function is the one place that breaks it, for this tier only.
//
// Replacement safety guarantee (ADR-0356), checked immediately before deletion — not a
// sleep/timeout guess, but two real, independently-verifiable substrate signals:
//  1. pm.Status.CheckpointTransferred=True: the checkpoint has already passed the full
//     ADR-SEC-B chain (sha256 wire-integrity hash, operator-signed manifest, exact
//     per-file digest match on the destination node — internal/agent/server/server.go
//     PutCheckpointTar) AND CRIU's own dump-time inventory.img presence check
//     (internal/agent/criu/criu_checkpointer.go) already ran on the source before the tar
//     was ever built. This proves a complete, intact, tamper-evident checkpoint is durably
//     present on the destination node — the source pod is no longer the only copy of the
//     process's state.
//  2. The destination node's NodeMigrationCapacity.Status.Ready is re-read fresh (not
//     stale scheduling-time data): the destination agent is alive and has itself already
//     probed its own CRIU binary/kernel features successfully (internal/agent/nmcregistrar)
//     right now, not merely at some earlier point in the migration.
//
// What this does NOT prove — stated plainly, not glossed over: neither signal proves the
// destination pod is actually serving traffic, because that is causally impossible to prove
// before the volume this function unblocks has even been mounted. ADR-0356 accepts this
// explicitly: a Tier1-Longhorn migration that fails restore AFTER this point can no longer
// live-resume the frozen source (it is deleted, and — verified against
// internal/rollback/rollback.go's StubComputeRollback — the only rollback primitive is an
// Abort RPC that SIGCONTs a still-running frozen PID, which no longer exists here). Recovery
// becomes "recreate from the durably-verified checkpoint," a real but bounded-downtime path,
// not zero-downtime live rollback. This narrows ADR-0012's guarantee for THIS TIER ONLY.
//
// ADR-0387 (docs/adr/0387-longhorn-tier-requires-rwx.md): the "recreate from the
// durably-verified checkpoint" recovery path above is only actually executed by SOMETHING
// when the source pod has a supported owning controller (ReplicaSet/Deployment) that
// notices the shortfall and recreates a replacement — it is not a recovery PodMotion itself
// performs. For a standalone pod (no owning controller, currently the ONLY pod shape this
// project supports), nothing ever recreates it, so that guarantee was structurally unmet
// exactly for the workloads that can reach this function. Rather than let this function
// keep running for a case its own safety story cannot cover, the real fix closes the gap
// one level up: internal/agent/storage/classifier.go's classifyPVC now only classifies a
// Longhorn-backed PVC as TierLonghorn (reachable here) when the PVC is ReadWriteMany
// (genuinely migratable Longhorn — the only mode where its dual-engine mechanism is real,
// per docs live-verified 2026-07-23). A ReadWriteOnce Longhorn PVC — the cluster's default
// single-attach StorageClass, which is what actually forced this early-release exception to
// be invented in the first place — is now classified TierBlocked and refused at
// StorageReadyForFreeze before checkpoint ever starts, so this function is never reached for
// it. This function's own logic is otherwise unchanged; it remains reachable (correctly) for
// a genuinely RWX/migratable Longhorn PVC, where source-node CSI VolumeAttachment release is
// still required ahead of destination mount for the reasons stated above.
func (r *PodMigrationReconciler) earlyReleaseSourceForTier1Longhorn(ctx context.Context, pm *pmv1.PodMigration) error {
	log := logf.FromContext(ctx)

	if pm.Status.StorageTier == nil || storage.StorageTier(*pm.Status.StorageTier) != storage.TierLonghorn {
		return nil // not this tier — ADR-0012's normal ordering applies untouched.
	}
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
		return nil // already done — idempotent no-op on every subsequent reconcile.
	}
	if !pm.Status.CheckpointTransferred {
		// Should never be reached — the caller (reconcileTransferring) only invokes this
		// after the CheckpointTransferred block above has run — but guard defensively
		// rather than ever releasing the source without a durably-verified checkpoint.
		return fmt.Errorf("ADR-0356: refusing early source release before CheckpointTransferred=True")
	}

	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		destNode = pm.Spec.TargetNodeName
	}
	destNMC, nmcErr := r.getNMC(ctx, destNode)
	if nmcErr != nil {
		return fmt.Errorf("ADR-0356: fetch destination NMC %s: %w", destNode, nmcErr)
	}
	if !destNMC.Status.Ready {
		return fmt.Errorf("ADR-0356: destination NMC %s not Ready — refusing early source release", destNode)
	}

	sourcePod, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err == nil {
		if sourcePod.Spec.NodeName == pm.Status.SourceNodeName {
			// The source process is left in SIGSTOP after the final freeze dump
			// (LeaveStopped=true, internal/agent/server/server.go) specifically so it is
			// fully recoverable rather than killed-and-kubelet-restarted. A plain
			// Kubernetes pod delete does NOT safely tear down a stopped container: the
			// container runtime's own stop sequence resumes (SIGCONT) a stopped init
			// process before signalling it — even with GracePeriodSeconds(0), SIGTERM is
			// still delivered and the now-running process gets a real (if short) window
			// to execute its OWN application-level shutdown code before the follow-up
			// SIGKILL lands. For a workload that manages its own on-disk lock/state file
			// in PGDATA (e.g. PostgreSQL's postmaster.pid), that graceful shutdown
			// unlinks the lock file as its last act — and because this tier's PGDATA is
			// the SAME Longhorn volume the destination is about to (or has already
			// started to) mount, that unlink lands on the shared volume out from under
			// the CRIU-restored destination process, which resumes expecting the lock
			// file to still exist exactly as it was at checkpoint time. PostgreSQL treats
			// a missing postmaster.pid as an external "please shut down now" signal and
			// immediately, cleanly self-terminates — with zero OOM/signal/dmesg trace,
			// since nothing external killed it (confirmed live: sprint49 Tier1-Longhorn
			// postgres proof — the restored destination postmaster logged "could not open
			// file postmaster.pid" / "data directory lock file is invalid" and
			// self-terminated seconds after a clean CRIU restore).
			//
			// The correct primitive is KillFrozenSource: deliver SIGKILL directly to the
			// STILL-STOPPED source PID via the source agent's broker (mirrors the
			// existing thaw-on-rollback SIGCONT primitive, but kills instead of resuming).
			// SIGKILL is fatal to a stopped task without ever resuming it to userspace, so
			// the source's own shutdown/cleanup code never runs at all — not a narrower
			// race window, a real elimination of the race. Only fall back to a plain pod
			// delete (best-effort object cleanup) if the source agent is unreachable or
			// the kill RPC itself fails; in that case surface the error so the caller
			// requeues and retries rather than silently deleting a possibly-still-live
			// source pod through the unsafe path.

			// ADR-0387: capture the source pod's owning-controller Kind (if any) NOW —
			// sourcePod is the only place this is authoritatively available, and it is
			// about to be deleted below. reconcileRollingBack reads this back from
			// pm.Status (not sourcePod, which will 404 by then) to report the true
			// recovery story: a controller recreates the pod only if one actually owns
			// it. Any Controller=true ownerRef counts, not just ReplicaSet — this is
			// deliberately broader than ADR-0371's rsOwnerRef (which only recognizes
			// ReplicaSet, for its own narrower re-adopt purpose).
			for i := range sourcePod.OwnerReferences {
				ref := sourcePod.OwnerReferences[i]
				if ref.Controller != nil && *ref.Controller {
					pm.Status.Tier1EarlyReleaseSourceOwnerKind = ref.Kind
					break
				}
			}

			// ADR-0393: fail-closed durable spec-snapshot capture gate. For a bare (no owning
			// controller) source pod, capture and DURABLY PERSIST a recovery snapshot from the live
			// source pod object NOW — before KillFrozenSource / source-pod delete below make the
			// spec unrecoverable. If the snapshot cannot be captured and confirmed persisted, return
			// an error so the source is NOT killed and the migration requeues: no confirmed snapshot,
			// no source kill. This is a structural no-op for an owned pod (its controller recreates
			// it), so it changes nothing about the existing kill/delete ordering for owned targets.
			if snapErr := r.captureSourcePodSpecSnapshot(ctx, pm, sourcePod); snapErr != nil {
				return fmt.Errorf("ADR-0393: fail-closed snapshot capture gate (source NOT killed): %w", snapErr)
			}

			// ADR-0371: immediately before the source pod is deleted, re-adopt the
			// replacement pod into its owning ReplicaSet's bookkeeping (restore stripped
			// selector labels + swap OwnerReferences back to the RS) and CONFIRM that
			// re-adopt held via a bounded, real re-read — never an assumed pass. This closes
			// the ADR-0356 gap-fill deadlock: without it, the RS's own reconcile observes a
			// shortfall the instant the source is deleted and creates a competing,
			// uncoordinated pod that can win the volume race against PodMotion's own gated
			// replacement. Fail-closed (zero-tech-debt pillar): on anything short of a
			// confirmed re-adopt, this returns an error and the source pod is NOT deleted —
			// there is no fall-through that proceeds to delete on an unconfirmed re-adopt.
			// Scoped to ReplicaSet-owned targets only; a structural no-op for bare pods,
			// StatefulSet-, and DaemonSet-owned targets (see ADR-0371 §5 — tracked
			// separately, not silently left broken).
			// rsOwnerRef/selectorKeys are non-nil ONLY when re-adopt was attempted AND
			// confirmed (a ReplicaSet-owned target). They are threaded into every failure
			// path below so a failure between confirmed-re-adopt and actual source delete
			// (ADR-0371 §2 step 4 / §3's rollback-symmetry requirement) re-strips the
			// replacement pod back to CR-owned/label-stripped before the error is returned —
			// never leaving the dangerous two-RS-owned-pods state parked across a retry.
			//
			// ADR-0371 amendment (review-identified gap, closed this sprint): this initial
			// confirm alone is NOT sufficient to gate the source pod delete — see the final
			// pre-delete re-check immediately before r.Delete(ctx, sourcePod, ...) below, added
			// specifically because the KillFrozenSource RPC between this point and that delete
			// has non-trivial, uncontrolled latency the RS's surplus-deletion reconcile can act
			// within.
			rsOwnerRef, selectorKeys, readoptErr := r.readoptReplacementPodIntoOwningReplicaSet(ctx, pm, sourcePod)
			if readoptErr != nil {
				return fmt.Errorf("ADR-0371: re-adopt replacement pod before early source release: %w", readoptErr)
			}

			srcAgent, agentErr := r.AgentPool.ForNode(ctx, pm.Status.SourceNodeName)
			if agentErr != nil {
				return r.failReleaseAfterReadopt(ctx, pm, rsOwnerRef, selectorKeys,
					fmt.Errorf("ADR-0356: connect to source agent %s for KillFrozenSource: %w", pm.Status.SourceNodeName, agentErr))
			}
			killResp, killErr := srcAgent.KillFrozenSource(ctx, &agentpb.KillFrozenSourceRequest{
				MigrationName: pm.Name,
				// PodUid: explicit fallback target for the (common) case where Checkpoint
				// used the containerd-native "ctr tasks checkpoint" fast path, which never
				// registers a frozen-source record. Passed explicitly (not left to the
				// agent's own in-memory migrationPodUID cache alone) so this still works
				// across an agent restart between checkpoint and this call.
				PodUid: string(sourcePod.UID),
			})
			if killErr != nil || killResp == nil || !killResp.Success {
				return r.failReleaseAfterReadopt(ctx, pm, rsOwnerRef, selectorKeys,
					fmt.Errorf("ADR-0356: KillFrozenSource on source agent %s failed: %v / %v", pm.Status.SourceNodeName, killErr, killResp))
			}
			log.Info("ADR-0356: frozen source process killed (SIGKILL, still-stopped) before deleting source pod",
				"pod", pm.Spec.PodName, "node", pm.Status.SourceNodeName, "migration", pm.Name, "killed", killResp.Killed)

			// ADR-0371 amendment (review-identified gap, closed this sprint): the initial
			// confirm inside readoptReplacementPodIntoOwningReplicaSet only proves the re-adopt
			// held AT THAT MOMENT — it does not, by itself, cover the window between that
			// confirm and the source pod delete below, and KillFrozenSource above is a real RPC
			// to the source agent with non-trivial, uncontrolled latency sitting squarely in
			// that window. If the owning ReplicaSet's surplus-deletion reconcile fires and
			// deletes the still-gated replacement pod during that RPC (or during the delete call
			// itself), proceeding on the strength of the earlier confirm alone would delete the
			// source pod object too — leaving both the replacement (RS-deleted) and the source
			// (process already killed, object now also gone) unrecoverable, exactly the failure
			// mode this amendment closes. Only relevant when a re-adopt was actually attempted
			// and confirmed (rsOwnerRef != nil) — a nil rsOwnerRef means no ReplicaSet owner
			// exists (bare pod), so there is no RS surplus-deletion race to re-check for.
			//
			// This re-check is a single fresh, real Get — never a cached value (zero-tech-debt,
			// no fail-open) — reusing the exact same identity-check primitive
			// (checkReplacementPodStillRSOwned) the bounded confirm poll above already uses, not
			// a new mechanism. KillFrozenSource has already run and unconditionally,
			// irreversibly killed the frozen source process by this point — that action cannot
			// be undone here, and this check does not attempt to. What it protects is narrower
			// but still load-bearing: the SOURCE POD OBJECT itself must not be deleted if the
			// replacement has been lost in this window, because the surviving source pod object
			// is what lets the normal rollback/recovery path re-observe the situation and act —
			// the exact "there is still a path back" property the
			// original design lost.
			if rsOwnerRef != nil {
				replPodKey := types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: pm.Status.ReplacementPodName}
				finalConfirmed, finalLost, finalCheckErr := r.checkReplacementPodStillRSOwned(ctx, replPodKey, rsOwnerRef)
				switch {
				case finalCheckErr != nil:
					return r.failReleaseAfterReadopt(ctx, pm, rsOwnerRef, selectorKeys,
						fmt.Errorf("ADR-0371: final pre-source-delete re-adopt re-check on replacement pod %s failed (source process already killed via KillFrozenSource, source pod object NOT deleted): %w", pm.Status.ReplacementPodName, finalCheckErr))
				case finalLost:
					return r.failReleaseAfterReadopt(ctx, pm, rsOwnerRef, selectorKeys,
						fmt.Errorf("ADR-0371: final pre-source-delete re-check lost the race — owning ReplicaSet %s deleted (or is deleting) replacement pod %s after KillFrozenSource ran; source pod object NOT deleted", rsOwnerRef.Name, pm.Status.ReplacementPodName))
				case !finalConfirmed:
					return r.failReleaseAfterReadopt(ctx, pm, rsOwnerRef, selectorKeys,
						fmt.Errorf("ADR-0371: final pre-source-delete re-check found replacement pod %s no longer confirmed RS-owned; source pod object NOT deleted", pm.Status.ReplacementPodName))
				}
				log.Info("ADR-0371: final pre-source-delete re-adopt re-check confirmed — proceeding to source pod delete",
					"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName, "replicaSet", rsOwnerRef.Name)
			}

			log.Info("ADR-0356: deleting source pod early (Tier1-Longhorn) to release the CSI VolumeAttachment blocking destination mount",
				"pod", pm.Spec.PodName, "node", pm.Status.SourceNodeName, "migration", pm.Name)
			if delErr := r.Delete(ctx, sourcePod, client.GracePeriodSeconds(0)); delErr != nil && !apierrors.IsNotFound(delErr) {
				return r.failReleaseAfterReadopt(ctx, pm, rsOwnerRef, selectorKeys,
					fmt.Errorf("ADR-0356: delete source pod: %w", delErr))
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("ADR-0356: get source pod: %w", err)
	}

	setCondition(pm, pmv1.ConditionTier1EarlySourceRelease, metav1.ConditionTrue, "Tier1LonghornEarlyRelease",
		"ADR-0356: source pod released pre-restore (CheckpointTransferred verified durable+intact, destination NMC fresh-Ready) to unblock Longhorn's single-owner collapse; rollback for this migration is now checkpoint-recreate, not live-resume")
	setCondition(pm, conditionSourcePodDeleted, metav1.ConditionTrue, "Tier1LonghornEarlyRelease",
		"ADR-0356: source pod deleted early for Tier1-Longhorn storage cutover, ahead of TrafficVerified")
	return r.statusUpdate(ctx, pm)
}

// replacementPodReadoptConfirmAttempts / replacementPodReadoptConfirmInterval bound the
// re-adopt confirm poll (ADR-0371 §2): a small fixed number of short-interval attempts,
// sized to complete inside one reconcile invocation. 10 attempts * 300ms = 3s worst case,
// well inside this function's existing synchronous, single-reconcile execution style.
const (
	replacementPodReadoptConfirmAttempts = 10
	replacementPodReadoptConfirmInterval = 300 * time.Millisecond
)

// readoptReplacementPodIntoOwningReplicaSet implements ADR-0371's Decision: immediately
// before earlyReleaseSourceForTier1Longhorn deletes the source pod, re-adopt the
// replacement pod into the source pod's owning ReplicaSet's bookkeeping (restore its
// stripped selector labels, swap OwnerReferences from the PodMigration CR back to the RS)
// and CONFIRM — via a bounded, real re-read of the replacement pod object itself, never
// the RS's aggregate status.replicas — that the re-adopt held before the caller is allowed
// to proceed to source-pod delete. This closes the ADR-0356 gap-fill deadlock: without it,
// the RS's own reconcile observes a replica shortfall the instant the source is deleted
// (createReplacementPod's replacement pod is deliberately invisible to the RS while gated)
// and creates a competing, uncoordinated pod that can win the destination volume's
// single-owner race against PodMotion's own still-gated replacement.
//
// Scope (ADR-0371 §5, Consequences): ReplicaSet-owned (Deployment-backed) targets ONLY.
// This is a structural no-op — returns nil immediately, no condition ever set — for a bare
// pod (no owning controller) and for StatefulSet-/DaemonSet-owned targets, because
// createReplacementPod's own strip logic only ever fires (and therefore only ever has
// anything to restore) when sourcePod carries a ReplicaSet controller ownerRef
// (podmigration_controller.go createReplacementPod, `if ownerRef.Kind == "ReplicaSet"`).
// StatefulSet and DaemonSet are explicitly NOT fixed by this function — see ADR-0371 §5 for
// why that is a tracked scope decision, not an oversight.
//
// Fail-closed (ADR-0371 §3, the project's zero-tech-debt pillar): every return path ends in
// exactly one of: (a) (rsOwnerRef, selectorKeys, nil) — re-adopt confirmed True, safe to
// proceed to source delete, with rsOwnerRef/selectorKeys threaded back to the caller so a
// LATER failure (between this confirmed re-adopt and the actual source pod delete) can still
// re-strip via failReleaseAfterReadopt; (b) (nil, nil, nil) — no ReplicaSet owner, a
// structural no-op; or (c) (nil, nil, err) — source pod must NOT be deleted, and the
// replacement pod has already been re-stripped back to its original CR-owned/label-stripped
// state (or is confirmed gone and will self-heal via createReplacementPod's existing
// idempotent recreate). There is no fourth branch that returns a nil error on an unconfirmed
// or assumed-successful re-adopt.
func (r *PodMigrationReconciler) readoptReplacementPodIntoOwningReplicaSet(ctx context.Context, pm *pmv1.PodMigration, sourcePod *corev1.Pod) (*metav1.OwnerReference, map[string]struct{}, error) {
	log := logf.FromContext(ctx)

	// §1: the RS controller OwnerReference to restore is copied verbatim from the source
	// pod's own OwnerReferences — this is already the exact, correctly-populated reference
	// the RS controller itself set; no new RS Get is needed to construct it.
	var rsOwnerRef *metav1.OwnerReference
	for i := range sourcePod.OwnerReferences {
		ref := sourcePod.OwnerReferences[i]
		if ref.Kind == "ReplicaSet" && ref.Controller != nil && *ref.Controller {
			rsOwnerRef = &ref
			break
		}
	}
	if rsOwnerRef == nil {
		// No ReplicaSet owner: bare pod, StatefulSet-owned, or DaemonSet-owned source.
		// createReplacementPod never stripped anything for these shapes, so there is nothing
		// to re-adopt. No-op per ADR-0371 §5/Consequences.
		return nil, nil, nil
	}

	if pm.Status.ReplacementPodName == "" {
		return nil, nil, fmt.Errorf("ADR-0371: no replacement pod recorded on pm.Status — cannot re-adopt before early source release")
	}
	replPodKey := types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: pm.Status.ReplacementPodName}

	// §1: resolve the same selector key set createReplacementPod stripped, via the same,
	// unmodified getRSSelector helper — reusing it means the two call sites can never
	// disagree about which keys are selector-significant.
	selectorKeys := map[string]struct{}{"pod-template-hash": {}}
	if err := r.getRSSelector(ctx, pm.Spec.PodNamespace, rsOwnerRef.Name, selectorKeys); err != nil {
		return nil, nil, fmt.Errorf("ADR-0371: resolve owning ReplicaSet %s selector for re-adopt: %w", rsOwnerRef.Name, err)
	}

	// §1: single atomic patch — OwnerReferences swapped to the copied RS ref; labels for the
	// resolved key set merged in from the source pod's CURRENT values (sourcePod is still
	// present in the API at this point — we are about to delete it, not after — so it
	// definitionally carries the correct current values, including the current
	// pod-template-hash). retry.RetryOnConflict matches this file's existing pattern for
	// status/object writes under concurrent reconcile.
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &corev1.Pod{}
		if getErr := r.Get(ctx, replPodKey, fresh); getErr != nil {
			return getErr
		}
		fresh.OwnerReferences = []metav1.OwnerReference{*rsOwnerRef}
		if fresh.Labels == nil {
			fresh.Labels = make(map[string]string, len(selectorKeys))
		}
		for k := range selectorKeys {
			if v, ok := sourcePod.Labels[k]; ok {
				fresh.Labels[k] = v
			}
		}
		return r.Update(ctx, fresh)
	}); err != nil {
		return nil, nil, fmt.Errorf("ADR-0371: re-adopt patch on replacement pod %s failed: %w", pm.Status.ReplacementPodName, err)
	}

	// §2: confirm via a bounded, REAL re-read of the replacement pod object itself — the
	// RS's own status.replicas counter cannot tell us WHICH pod survived a surplus
	// resolution, only re-Getting the specific replacement pod by name can. This is the
	// load-bearing correctness mechanism, not an assumption-smoothing nicety: the moment the
	// re-adopt patch lands, the RS's filteredPods view briefly contains two pods against a
	// desired count of one, and the still-gated (unassigned/Pending/not-Ready) replacement
	// pod sorts to the FRONT of the RS's surplus-deletion priority ordering — i.e. it is the
	// RS's preferred deletion target, not the source pod.
	confirmInterval := replacementPodReadoptConfirmInterval
	if r.readoptConfirmIntervalOverride > 0 {
		confirmInterval = r.readoptConfirmIntervalOverride
	}

	var (
		confirmed bool
		raceLost  bool
		lastErr   error
	)
	for attempt := 0; attempt < replacementPodReadoptConfirmAttempts; attempt++ {
		var checkErr error
		confirmed, raceLost, checkErr = r.checkReplacementPodStillRSOwned(ctx, replPodKey, rsOwnerRef)
		if checkErr != nil {
			lastErr = checkErr
		}
		if confirmed || raceLost {
			break
		}
		if attempt < replacementPodReadoptConfirmAttempts-1 {
			time.Sleep(confirmInterval)
		}
	}

	if confirmed {
		setCondition(pm, pmv1.ConditionReplacementPodReadopted, metav1.ConditionTrue, "ReadoptConfirmed",
			"ADR-0371: replacement pod re-adopted into owning ReplicaSet bookkeeping, confirmed present with the RS OwnerReference intact, immediately before source pod delete")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return nil, nil, fmt.Errorf("ADR-0371: persist ReadoptConfirmed condition before source delete: %w", err)
		}
		log.Info("ADR-0371: replacement pod re-adopt confirmed — proceeding to source pod delete",
			"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName, "replicaSet", rsOwnerRef.Name)
		return rsOwnerRef, selectorKeys, nil
	}

	// §3 (fail-closed, zero-tech-debt pillar): not confirmed. Either the RS's own
	// surplus-deletion reconcile won the race (raceLost), or the bounded poll exhausted
	// without ever observing a definitive state either way (timeout) — an inconclusive read
	// is treated as a loss, never as a silent pass. This is a detected, NAMED failure, not a
	// silent one — surfaced via the condition below before this function returns an error.
	reason := "ReadoptConfirmTimeout"
	msg := "ADR-0371: bounded re-adopt confirm poll exhausted without a definitive read of the replacement pod's state"
	if raceLost {
		reason = "ReadoptRaceLost"
		msg = "ADR-0371: the owning ReplicaSet's surplus-deletion reconcile won the race and deleted (or is deleting) the re-adopted replacement pod"
	}
	if lastErr != nil {
		msg = fmt.Sprintf("%s (last confirm-read error: %v)", msg, lastErr)
	}
	setCondition(pm, pmv1.ConditionReplacementPodReadopted, metav1.ConditionFalse, reason, msg)
	if updErr := r.statusUpdate(ctx, pm); updErr != nil {
		log.Error(updErr, "ADR-0371: failed to persist re-adopt failure condition", "migration", pm.Name)
	}

	if raceLost {
		// §2 sub-bullet: the replacement pod itself is gone (or going) — there is nothing
		// left to re-strip. createReplacementPod's existing idempotency check ("Was recorded
		// but pod is gone — fall through to re-create") naturally rebuilds a fresh,
		// correctly-stripped, RS-invisible replacement pod on the next reconcile: this makes
		// a lost race self-healing and bounded, never a silent stall.
		log.Error(nil, "ADR-0371: re-adopt race lost — owning ReplicaSet deleted the replacement pod; source pod NOT deleted, will self-heal via createReplacementPod on retry",
			"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName, "replicaSet", rsOwnerRef.Name)
		return nil, nil, fmt.Errorf("ADR-0371: re-adopt race lost — ReplicaSet %s deleted replacement pod %s before confirm; source pod NOT deleted", rsOwnerRef.Name, pm.Status.ReplacementPodName)
	}

	// §4/§3: timeout, or a transient read error that never resolved to a definitive answer —
	// re-strip immediately, before returning, so the dangerous two-RS-owned-pods window
	// never survives past this single reconcile. If the re-strip patch itself fails, that is
	// a hard, loud failure (see reStripReplacementPodOwnership), never swallowed or retried
	// silently — exactly the case the project's zero-tech-debt fail-closed handling exists
	// for.
	if stripErr := r.reStripReplacementPodOwnership(ctx, pm, replPodKey, selectorKeys); stripErr != nil {
		setCondition(pm, pmv1.ConditionReplacementPodReadopted, metav1.ConditionFalse, "ReadoptReStripFailed",
			fmt.Sprintf("ADR-0371: re-strip after an unconfirmed re-adopt ALSO failed — replacement pod may be left straddling both ownership states, requires investigation: %v", stripErr))
		_ = r.statusUpdate(ctx, pm)
		log.Error(stripErr, "ADR-0371: CRITICAL — re-strip after an unconfirmed re-adopt failed; replacement pod may straddle both ownership states, migration stopped for investigation",
			"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName)
		return nil, nil, fmt.Errorf("ADR-0371: re-strip after unconfirmed re-adopt failed (%s): %w", reason, stripErr)
	}
	log.Info("ADR-0371: re-adopt not confirmed — replacement pod re-stripped back to CR-owned/label-stripped state; source pod NOT deleted",
		"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName, "reason", reason)
	return nil, nil, fmt.Errorf("ADR-0371: re-adopt not confirmed (%s) — source pod NOT deleted, replacement pod re-stripped, will retry", reason)
}

// failReleaseAfterReadopt implements ADR-0371 §2 step 4 / §3's rollback-symmetry
// requirement: if anything between a successfully CONFIRMED re-adopt and the source pod's
// actual delete fails — the source agent being unreachable, the KillFrozenSource RPC itself
// failing, or the delete call failing — the replacement pod is immediately re-stripped back
// to its original CR-owned/label-stripped state BEFORE cause is returned to the caller.
// Without this, a transient failure in that window (e.g. KillFrozenSource failing because
// the source agent is momentarily unreachable — an existing, already-handled error path)
// would leave the dangerous two-RS-owned-pods state parked across every retry for as long as
// the underlying failure persists, repeatedly re-exposing the RS's surplus-deletion race.
//
// rsOwnerRef == nil means readoptReplacementPodIntoOwningReplicaSet never confirmed a
// re-adopt (no ReplicaSet owner, or it already failed and re-stripped itself) — nothing to
// re-strip here, cause is returned unchanged. cause is always returned (wrapped on a
// re-strip failure), never swallowed — this function only ever adds a re-strip side effect
// and a condition, it never changes whether the caller treats the outcome as an error.
func (r *PodMigrationReconciler) failReleaseAfterReadopt(ctx context.Context, pm *pmv1.PodMigration, rsOwnerRef *metav1.OwnerReference, selectorKeys map[string]struct{}, cause error) error {
	log := logf.FromContext(ctx)
	if rsOwnerRef == nil || pm.Status.ReplacementPodName == "" {
		return cause
	}
	replPodKey := types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: pm.Status.ReplacementPodName}
	if stripErr := r.reStripReplacementPodOwnership(ctx, pm, replPodKey, selectorKeys); stripErr != nil {
		// §3: fail-closed, loud — a partially-applied patch here must stop the migration and
		// surface for investigation, never be retried silently.
		setCondition(pm, pmv1.ConditionReplacementPodReadopted, metav1.ConditionFalse, "ReadoptReStripFailed",
			fmt.Sprintf("ADR-0371: re-strip after a post-readopt failure (%v) ALSO failed — replacement pod may be left straddling both ownership states, requires investigation: %v", cause, stripErr))
		_ = r.statusUpdate(ctx, pm)
		log.Error(stripErr, "ADR-0371: CRITICAL — re-strip after a post-readopt failure failed; replacement pod may straddle both ownership states, migration stopped for investigation",
			"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName, "cause", cause)
		return fmt.Errorf("%w (ADR-0371: re-strip after failure ALSO failed: %v)", cause, stripErr)
	}
	setCondition(pm, pmv1.ConditionReplacementPodReadopted, metav1.ConditionFalse, "ReadoptRestrippedAfterFailure",
		fmt.Sprintf("ADR-0371: re-adopt had been confirmed, but a failure before source pod delete completed (%v) required re-stripping the replacement pod back to CR-owned/label-stripped state", cause))
	_ = r.statusUpdate(ctx, pm)
	log.Info("ADR-0371: re-stripped replacement pod after a post-readopt failure — source pod NOT deleted, migration will retry",
		"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName, "cause", cause)
	return cause
}

// replacementPodOwnedByRS reports whether ownerRefs contains a controller reference to the
// same object rsOwnerRef identifies (matched on Kind + Name + UID). Matching on UID as well
// as Kind/Name guards against the pathological case of the same-named RS having been
// deleted and recreated between the patch and this read.
func replacementPodOwnedByRS(ownerRefs []metav1.OwnerReference, rsOwnerRef *metav1.OwnerReference) bool {
	for i := range ownerRefs {
		ref := ownerRefs[i]
		if ref.Kind == "ReplicaSet" && ref.Controller != nil && *ref.Controller &&
			ref.Name == rsOwnerRef.Name && ref.UID == rsOwnerRef.UID {
			return true
		}
	}
	return false
}

// checkReplacementPodStillRSOwned performs exactly ONE fresh, uncached Get of the replacement
// pod and reports whether it is still confirmed RS-owned. This is the single load-bearing
// identity check ADR-0371's re-adopt confirm mechanism is built on — never a cached/assumed
// value. It has two call sites, both real reads, never a shared cached result between them:
//  1. readoptReplacementPodIntoOwningReplicaSet's bounded confirm poll (§2) — calls this
//     repeatedly, once per attempt, until it returns a definitive answer or the poll is
//     exhausted.
//  2. earlyReleaseSourceForTier1Longhorn's final pre-source-delete re-check (ADR-0371
//     amendment, review gap closure) — calls this exactly once, immediately before
//     r.Delete(ctx, sourcePod, ...), AFTER KillFrozenSource has already run. This closes the
//     window the initial confirm alone left open: KillFrozenSource is a real RPC with
//     non-trivial, uncontrolled latency, and the RS's surplus-deletion reconcile can fire and
//     delete the still-gated replacement pod during that RPC or during the delete call itself,
//     after the last successful confirm-poll read. Reusing this exact same check — not a new
//     mechanism, not a weaker one — as a final gate immediately before the source delete
//     removes that window.
//
// Return contract (three-way, matches the bounded poll's existing switch):
//   - confirmed=true: the pod is present, has no DeletionTimestamp, and its OwnerReferences
//     still shows the RS controller ref rsOwnerRef identifies — re-adopt holds, safe to
//     proceed.
//   - confirmed=false, lost=true: the pod is NotFound or has acquired a non-nil
//     DeletionTimestamp — a definitive, detected loss (the RS won the surplus race).
//   - confirmed=false, lost=false, err!=nil: the Get itself errored (e.g. a transient API
//     error) — an inconclusive read, never treated as a pass by either caller.
//   - confirmed=false, lost=false, err==nil: the pod was read successfully but its
//     OwnerReferences no longer matches rsOwnerRef — also inconclusive/lost-shaped, treated as
//     a race loss by both callers' fail-closed handling (matches the bounded poll's existing
//     "anything short of a definitive confirmed==true is not a pass" rule).
func (r *PodMigrationReconciler) checkReplacementPodStillRSOwned(ctx context.Context, replPodKey types.NamespacedName, rsOwnerRef *metav1.OwnerReference) (confirmed bool, lost bool, err error) {
	check := &corev1.Pod{}
	getErr := r.Get(ctx, replPodKey, check)
	switch {
	case apierrors.IsNotFound(getErr):
		return false, true, nil
	case getErr != nil:
		return false, false, getErr
	case check.DeletionTimestamp != nil:
		return false, true, nil
	case replacementPodOwnedByRS(check.OwnerReferences, rsOwnerRef):
		return true, false, nil
	default:
		return false, false, nil
	}
}

// reStripReplacementPodOwnership is the rollback-symmetry half of ADR-0371 §2/§4: reverts a
// replacement pod's OwnerReferences back to the PodMigration CR (mirroring
// createReplacementPod's own original SetControllerReference call) and removes the
// selectorKeys label set that the failed/unconfirmed re-adopt had just restored — collapsing
// the dangerous "two RS-owned pods" window back down to a single synchronous sequence of API
// calls within one reconcile, matching the blast radius the rest of
// earlyReleaseSourceForTier1Longhorn is already built around. Any error here is returned
// unchanged to the caller, which surfaces it as a hard, loud failure (ADR-0371 §3) — this
// function itself never retries silently or swallows an error.
func (r *PodMigrationReconciler) reStripReplacementPodOwnership(ctx context.Context, pm *pmv1.PodMigration, replPodKey types.NamespacedName, selectorKeys map[string]struct{}) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &corev1.Pod{}
		if getErr := r.Get(ctx, replPodKey, fresh); getErr != nil {
			if apierrors.IsNotFound(getErr) {
				// Already gone — nothing left to re-strip; treat as success (mirrors the
				// raceLost "nothing to re-strip" case in the caller).
				return nil
			}
			return getErr
		}
		for k := range selectorKeys {
			delete(fresh.Labels, k)
		}
		fresh.OwnerReferences = nil
		if err := controllerutil.SetControllerReference(pm, fresh, r.Scheme); err != nil {
			return fmt.Errorf("set controller reference back to PodMigration CR: %w", err)
		}
		return r.Update(ctx, fresh)
	})
}

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
		server := fresh.DeepCopy()
		fresh.Status = pm.Status
		preserveOperatorOwnedDurableStatus(server, &fresh.Status) // ADR-0398/0408: never blob-overwrite marker or snapshot
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

	// ADR-0365 Decision §1: for an unpinned migration whose Status.DestinationNodeName is still
	// empty, resolve the destination NOW — before the anti-affinity check below, and long before
	// PreCopyMemory's storage pre-stage dispatch — by calling the scheduler-plugin's
	// MigrationAwareFilter/MigrationAwareScore decision logic directly against the live node
	// list. This closes the gap where an unpinned migration previously reached storage pre-stage
	// (and, on the TCPPreservationMode=None fast path, PreCopyMemory itself) with an empty
	// DestinationNodeName and no producer ever having fired for it. Pinned migrations
	// (Spec.TargetNodeName / Spec.DestinationNode already set) are untouched — cacheDestinationNodeFromSpec's
	// existing seed-mode producers already handle them; this step is a strict no-op for them.
	if pm.Status.DestinationNodeName == "" && pm.Spec.TargetNodeName == "" && pm.Spec.DestinationNode == "" {
		winner, resolveErr := r.resolveEarlyDestinationNode(ctx, pm)
		if resolveErr != nil {
			log.Error(resolveErr, "ADR-0365: early destination-node resolution failed — requeuing",
				"migration", pm.Name)
			setCondition(pm, conditionDestinationResolvable, metav1.ConditionFalse,
				"NoEligibleDestination", resolveErr.Error())
			if r.Recorder != nil {
				r.Recorder.Eventf(pm, corev1.EventTypeWarning, "DestinationUnresolvable", "%v", resolveErr)
			}
			if statusErr := r.statusUpdate(ctx, pm); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		if winner != "" {
			setCondition(pm, conditionDestinationResolvable, metav1.ConditionTrue, "Resolved",
				fmt.Sprintf("ADR-0365 early destination decision: resolved to node %s", winner))
			if statusErr := r.statusUpdate(ctx, pm); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
		}
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

	// the replication worker, the storage worker, and the network worker drive pre-migration
	// work asynchronously.  All three keystone conditions must be True before advancing:
	//   MemorySynced=True           (the replication loop)
	//   StorageReadyForFreeze=True  (the storage pre-stage, ADR-0011)
	//   NetworkBridgeArmed=True     (the eBPF bridge OR v0.1 fast-path, ADR-0028)
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
		// Cache DestinationNodeName from spec.targetNodeName if not already set (required by
		// reconcileRestoring to connect to the destination agent), via the shared validated seed so a
		// same-node destination can never be latched here (the same-node wedge case).
		cacheDestinationNodeFromSpec(pm, pm.Spec.TargetNodeName, pm.Status.SourceNodeName)
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
	// ADR-0398 D1: this (currently dead — MigrationPhasePreMigrating is never set) legacy mirror now
	// routes through the SAME single-dispatch helper as the live reconcilePreCopyMemory path, so there
	// is exactly ONE dispatch implementation and no byte-duplicated non-idempotent latch to regress.
	if _, err := r.dispatchStoragePreStageOnce(ctx, pm); err != nil {
		return ctrl.Result{}, err
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
	// directly or we are re-entering after a controller restart), do NOT advance on that fact
	// alone (brittle-chain fix): Checkpointed=True says nothing about whether the
	// replacement pod was ever actually created — that is a separate, non-atomically-written
	// fact. ensureReplacementPodCreated performs a live, label-based lookup (the same
	// authoritative primitive resolveAndValidateReplacementPlacement already trusts) and creates
	// the pod if it is genuinely missing, so a prior partial failure between the Checkpointed
	// persist and createReplacementPod (status-write contention, transient error, controller
	// restart) is detected and retried here instead of being silently and permanently skipped.
	if meta.IsStatusConditionTrue(pm.Status.Conditions, conditionCheckpointed) {
		sourcePod, spErr := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
		if spErr != nil {
			log.Error(spErr, "checkpoint fast-path: source pod unreadable — cannot verify/create replacement pod; requeuing",
				"migration", pm.Name)
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}
		// ADR-0365 Condition 1: re-validate the resolved destination immediately before the call
		// that may create the replacement pod — this is a real entry point into createReplacementPod
		// (via ensureReplacementPodCreated) on the recovery/re-entry path, not just the primary one
		// below, so it needs the same staleness guard.
		if revalRes, proceed, revalErr := r.revalidateDestinationBeforeReplacementPod(ctx, pm); !proceed {
			return revalRes, revalErr
		}
		if _, err := r.ensureReplacementPodCreated(ctx, pm, sourcePod); err != nil {
			log.Error(err, "checkpoint fast-path: replacement pod not yet created — requeuing",
				"migration", pm.Name)
			// RequeueAfter (not Requeue:true / a bare error) so this transient condition is
			// Forget()'d by the workqueue rate limiter rather than compounding AddRateLimited
			// backoff from an unrelated prior error on this item toward the 1000s cap.
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}
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
	// Backstop allow-list (bug fix, ADR-0246): ShmemPagemapMissing is a
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
		case "CheckpointFailed", "ShmemPagemapMissing", "MountContentCaptureFailed":
			// MountContentCaptureFailed (ADR-0415 fail-closed capture gate) is a non-restorable checkpoint exactly
			// like ShmemPagemapMissing — route stale re-entries to rollback, not a Checkpoint retry.
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
					// Bug fix (scheduling/network correctness), preserved
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
				// ADR-0415 fail-closed capture gate (capture-everything-by-default fails CLOSED): the agent attaches
				// an errdetails.ErrorInfo{Reason: "MOUNT_CONTENT_CAPTURE_FAILED"} payload
				// (internal/agent/server/adr0415_mount_capture_gate.go, newMountContentCaptureFailedStatus)
				// when an owned pod-local mount's content could not be captured. Like the shmem-pagemap
				// defect this is a non-restorable checkpoint that must not ship — set the attributed
				// MountContentCaptureFailed reason and route to rollback (not a retry storm).
				if mountContentCaptureFailedReasonFromStatus(grpcStatus) {
					log.Error(err, "Checkpoint RPC failed: owned-mount content capture failed (ADR-0415 fail-closed capture gate fail-closed)", "migration", pm.Name)
					setCondition(pm, conditionCheckpointed, metav1.ConditionFalse, "MountContentCaptureFailed", errStr)
					if r.Recorder != nil {
						r.Recorder.Eventf(pm, corev1.EventTypeWarning, "MountContentCaptureFailed",
							"capture-everything gate (ADR-0415 fail-closed capture gate) could not capture an owned "+
								"pod-local mount's content for migration %s — checkpoint is not "+
								"restorable, routing to rollback: %s", pm.Name, errStr)
					}
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

	// ADR-0168 B2 / ADR-0217 D1: write the workload image to the MigrationCheckpoint CR so the
	// destination agent can use the correct image for the restore placeholder container.
	// As of ADR-0217 the AUTHORITATIVE producer is reconcileValidating (runs BEFORE the
	// DestinationPrewarm consumer); this Checkpointing write is now an IDEMPOTENT RE-ASSERT
	// retained for defense-in-depth and the legacy 8-phase pipeline. Warn-only (ADR-0012).
	//
	// Deliberately run BEFORE the Checkpointed=True persist below (moved here from after it):
	// this block's own comment already establishes it is a non-authoritative, idempotent
	// re-assert, so if it were to ever need to fail closed there is nothing lost by re-running
	// it on a fresh reconcile — whereas persisting Checkpointed=True first (the old order) would
	// let a failure downstream of that persist strand the migration past the point where the
	// normal (non-fast-path) body re-runs.
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

	// Ensure DestinationNodeName is cached before creating the replacement pod.
	// It is normally set in reconcilePreMigrating and persisted via transitionTo, but
	// can be empty if this reconcile was fetched from cache before the status write landed.
	// Routed through the shared validated seed so a same-node destination can never be latched
	// here (the same-node wedge case).
	//
	// Also moved ahead of the Checkpointed=True persist: if this statusUpdate fails, the function
	// returns here with Checkpointed still False in etcd (only set in-memory above), so the next
	// reconcile re-runs the full body from scratch instead of landing past the point of no return.
	if cacheDestinationNodeFromSpec(pm, pm.Spec.TargetNodeName, pm.Status.SourceNodeName) {
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, fmt.Errorf("caching DestinationNodeName in Checkpointing phase: %w", err)
		}
		log.Info("cached DestinationNodeName from spec.targetNodeName in Checkpointing phase (validated distinct from source)",
			"migration", pm.Name, "destNode", pm.Status.DestinationNodeName)
	}

	// Persist Checkpointed=True BEFORE creating the replacement pod so that if
	// ensureReplacementPodCreated fails and we requeue, the next reconcile sees True and skips
	// the Checkpoint RPC. Without this write the in-memory condition is lost on requeue
	// and the controller issues repeated CRIU dumps until the frozen pod's PID disappears.
	// This is safe against the historical bug (checkpoint persisted, replacement pod silently
	// never created) because every path that re-enters with Checkpointed=True already read —
	// the fast-path above and the call immediately below — funnels through
	// ensureReplacementPodCreated, which always re-verifies with a live lookup rather than
	// assuming completion from this condition alone.
	if err := r.statusUpdate(ctx, pm); err != nil {
		return ctrl.Result{}, fmt.Errorf("persisting Checkpointed=True: %w", err)
	}

	// ADR-0365 Condition 1: this is the point closest to actual replacement-pod creation in the
	// freeze/transfer phase code path — re-validate NMC readiness/capacity/drain-label for the
	// resolved destination right here, before createReplacementPod (via ensureReplacementPodCreated
	// below) commits to it. The early decision (resolveEarlyDestinationNode, reconcileValidating)
	// may be arbitrarily stale by now: the whole pre-copy loop and the checkpoint RPC above have run
	// since it was made. On staleness this fails closed — it never force-binds to a now-invalid
	// node — either re-running the early decision for an unpinned migration, or rolling back
	// (invariant #8/ADR-0012 pattern) for a pinned one. Checkpointed=True is already persisted
	// above, so a requeue here safely re-enters via this function's fast-path at the top.
	if revalRes, proceed, revalErr := r.revalidateDestinationBeforeReplacementPod(ctx, pm); !proceed {
		return revalRes, revalErr
	}

	// Create the replacement pod that will receive the restored process.
	// The admission webhook injects the scheduling gate + checkpoint-ref annotation.
	// The pod is held at PodSchedulingGated until removeSchedulingGate fires at the
	// END of reconcileTransferring — only after images land on the destination node.
	//
	// Brittle-chain fix: this no longer gates on pm.Status.ReplacementPodName == "" (a cached
	// flag that can be wrong). ensureReplacementPodCreated performs its own live check and is
	// idempotent, so it is always safe to call here.
	if _, err := r.ensureReplacementPodCreated(ctx, pm, sourcePod); err != nil {
		log.Error(err, "failed to create replacement pod", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
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
	// Placement authority (SINGLE SOURCE OF TRUTH). resolveAndValidateReplacementPlacement re-reads
	// the LIVE replacement pod every call, validates its ACTUAL binding (present, Ready, != source),
	// and — in correct mode — performs bounded, apiserver-legal REAL recovery: when the
	// migration-unaware default scheduler bound the replacement pod onto the source node it DELETES
	// that pod so the scheduler reschedules a fresh one (a bound pod's spec.nodeName is immutable — a
	// delete is the only legal correction), up to maxSameNodeRecoveryDeletes times before failing
	// closed. It, not a latched Status.DestinationNodeName, decides whether this migration may
	// proceed, so an operator/automation pin at the pod's own node (the same-node wedge case) can no longer
	// wedge the migration through any producer path. On success Status.DestinationNodeName is
	// refreshed to the validated destination.
	decision, err := r.resolveAndValidateReplacementPlacement(ctx, pm, sourceNode, true)
	if err != nil {
		return ctrl.Result{}, err
	}
	switch decision.Action {
	case replacementPlacementTerminal:
		// Same-node placement could not be corrected within the bound — fail closed to rollback
		// (source pod never deleted — ADR-0012; the replacement pod is torn down by the rollback
		// path). This is the honest terminal outcome, not an infinite silent retry.
		return r.initiateRollback(ctx, pm, decision.TerminalReason)
	case replacementPlacementRequeue:
		ra := decision.RequeueAfter
		if ra == 0 {
			ra = 3 * time.Second
		}
		return ctrl.Result{RequeueAfter: ra}, nil
	}
	// Proceed: placement is valid and distinct from the source; use it as the transfer destination.
	destNode := decision.DestNode

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

	// ADR-0356: for Tier1 (Longhorn) migratable volumes ONLY, release the source pod now —
	// before the scheduling gate below makes the destination pod schedulable — instead of
	// waiting for TrafficVerified (ADR-0012's normal rule). See earlyReleaseSourceForTier1Longhorn's
	// doc comment and ADR-0356 for the full rationale; every other tier is untouched.
	if err := r.earlyReleaseSourceForTier1Longhorn(ctx, pm); err != nil {
		log.Error(err, "reconcileTransferring: ADR-0356 Tier1-Longhorn early source release not yet safe — requeuing",
			"migration", pm.Name)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// sprint49 finding: the storage-cutover gate (StorageMgr.Cutover/AwaitSingleOwner) does
	// NOT belong here, before scheduling-gate removal. Longhorn's real dual-engine collapse
	// (tier1.go AwaitSingleOwner) can only begin once the destination pod is actually
	// SCHEDULED and kubelet issues NodeStageVolume there — that is what makes
	// longhorn-manager populate spec.migrationNodeID and start the second engine in the
	// first place. Removing the scheduling gate is the ONLY thing that lets the scheduler
	// bind the destination pod to its node. Gating AwaitSingleOwner before gate-removal is a
	// permanent deadlock: it polls forever for a collapse that can never start, because the
	// pod it needs mounted is still held at PodSchedulingGated. (Confirmed live: the gate
	// timed out at 2 minutes with the destination Longhorn volume still "detached"/"unknown"
	// — it never had a chance to attach.) The real gate now lives at the end of
	// reconcileOverlayHandoff, immediately before the phase transition into
	// RestoreSocketReattach — see gateStorageCutoverBeforeRestore's doc comment for why that
	// is the correct (and only correct) place: it is the exact boundary the NRI
	// StartContainer hook's own phase check (nri/plugin.go verifyPhaseInAcceptSet) enforces,
	// so gating there blocks BOTH the NRI-triggered restore and the direct/legacy RPC path
	// uniformly, without deadlocking the storage collapse this gate depends on.
	//
	// Remove the scheduling gate NOW — images are on the destination node, so the
	// NRI StartContainer hook can find the checkpoint at
	// /run/podmotion/checkpoints/<ref>/final once CRIU restore is actually permitted to run
	// (gated separately, later, in reconcileOverlayHandoff).
	// Removing earlier (post-Checkpoint, pre-Transfer) would race the NRI hook against
	// the PutCheckpointTar delivery, causing a CRIU restore failure on a cold destination.
	//
	// ADR-0360: no outer one-shot latch here. ensureReplacementPodBound is called
	// unconditionally every reconcile of Transferring and derives `bound` solely from a
	// fresh post-patch Get of the live pod object — never from removeSchedulingGate's old
	// nil return, which was compatible with "we never looked at the real pod at all." A
	// false-positive on any one call self-heals on the next reconcile instead of
	// permanently stranding the pod behind a latched condition.
	replPod, bound, err := r.ensureReplacementPodBound(ctx, pm)
	if err != nil {
		log.Error(err, "ensureReplacementPodBound: gate-removal/verification failed — requeuing",
			"migration", pm.Name)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	if !bound {
		podName := ""
		if replPod != nil {
			podName = replPod.Name
		}
		log.Info("ensureReplacementPodBound: replacement pod not yet bound (gate not verified absent) — requeuing",
			"migration", pm.Name, "pod", podName)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionSchedulingGateRemoved) {
		setCondition(pm, conditionSchedulingGateRemoved, metav1.ConditionTrue,
			"GateRemoved", "podmotion.io/awaiting-checkpoint gate removed and verified via fresh read")
		if err := r.statusUpdate(ctx, pm); err != nil {
			return ctrl.Result{}, err
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

// buildRestoreSeqSnapshots converts the restart-durable source-freeze TCP sequence snapshots
// held in pm.Status.TCPSeqSnapshots into the wire form the agent consumes (agentpb.SeqSnapshot).
//
// ADR-0406: this is the SINGLE authority for the pmv1.TCPSeqSnapshot -> agentpb.SeqSnapshot
// field mapping. Every controller call site that seeds PM_SEQ_XLAT — the primary restore
// (reconcileRestoring), the NRI-fallback restore (reconcileRestoringNRI), and the VerifyTCP
// source-snapshot thread (reconcileVerifyingContinuity) — MUST route through this helper so the
// mapping cannot silently drift between call sites. The root cause ADR-0406 corrects was exactly
// such drift: two call sites meant to be symmetric diverged on the SeqSnapshots field and the
// fallback path stopped seeding. Hand-copying the struct literal per call site re-arms that
// regression class (a future proto field must be added in N places, any miss invisible until a
// live seed fails), so the copy lives here once. Returns nil for an empty/None-mode migration,
// which correctly leaves the agent's `len(req.SeqSnapshots) > 0` seed guard false.
func buildRestoreSeqSnapshots(pm *pmv1.PodMigration) []*agentpb.SeqSnapshot {
	var out []*agentpb.SeqSnapshot
	for _, snap := range pm.Status.TCPSeqSnapshots {
		out = append(out, &agentpb.SeqSnapshot{
			SrcIp:    snap.SrcIP,
			SrcPort:  snap.SrcPort,
			DstIp:    snap.DstIP,
			DstPort:  snap.DstPort,
			SndNxt:   snap.SndNxt,
			RcvNxt:   snap.RcvNxt,
			TsRecent: snap.TsRecent,
		})
	}
	return out
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

	// Operator-driven path (NS#3): the replacement pod was created by the operator and the
	// NRI StartContainer hook drives CRIU restore when containerd starts the replacement
	// pod's holder container — that hook carries the AUTHORITATIVE pod-sandbox netns straight
	// from the container-start event (pod.GetId()). Route to it here instead of the direct
	// Restore RPC below: the direct path resolves the sandbox by racing `ctr` against
	// containerd sandbox creation (agent resolvePodNetnsSandbox -> sandboxIDForPodUID) and,
	// when it loses that race, fails closed at the ADR-0325 gate ("could not resolve
	// replacement pod sandbox netns … no sandbox container found for pod uid <uid>"), marking
	// the migration Failed in seconds — which then blocks the NRI hook, since it only restores
	// while the CR is still in the Restoring phase. This is the exact live-proof-cycle1
	// failure (pm-w2 agent log, 2026-07-13: sandboxIDForPodUID returned empty because the
	// replacement pod's containerd sandbox was not yet created when the direct RPC fired).
	//
	// Decide NRI-vs-direct on the AUTHORITATIVE podmotion.io/migration-name label the
	// controller stamps at replacement-pod creation (createReplacementPod), NOT on
	// pm.Status.ReplacementPodName. The status mirror is routinely lost to the
	// status-subresource clobber race (the same defect already fixed one phase later in
	// reconcileTCPVerifying, ~L1189, and named in ADR-0349 D3): when it reads empty here even
	// though the replacement pod exists, the old gate fell through to the sandbox-racing
	// direct path. Reading the label is reading the source of truth directly rather than
	// inferring the restore strategy from a flaky mirror (invariant #10 — primitive over
	// brittle chain). Heal the mirror so reconcileRestoringNRI's by-name reads resolve.
	replForRestore, resolveErr := r.resolveReplacementPodByLabel(ctx, pm)
	if resolveErr != nil {
		log.Info("reconcileRestoring: replacement-pod resolve errored — requeuing",
			"migration", pm.Name, "resolveErr", resolveErr)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	if replForRestore != nil {
		if pm.Status.ReplacementPodName == "" {
			pm.Status.ReplacementPodName = replForRestore.Name
			if err := r.statusUpdate(ctx, pm); err != nil {
				log.Error(err, "reconcileRestoring: failed to heal Status.ReplacementPodName — continuing",
					"migration", pm.Name, "replacementPod", replForRestore.Name)
			}
		}
		return r.reconcileRestoringNRI(ctx, pm)
	}

	if r.AgentPool == nil {
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		// Fallback: populate from spec.targetNodeName if status was not set during pre-migration,
		// via the shared validated seed so a same-node destination can never be latched here
		// (the same-node wedge case). A same-node or empty target yields no seed and requeues.
		if cacheDestinationNodeFromSpec(pm, pm.Spec.TargetNodeName, pm.Status.SourceNodeName) {
			if err := r.statusUpdate(ctx, pm); err != nil {
				return ctrl.Result{}, err
			}
			destNode = pm.Status.DestinationNodeName
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

	// No storage-cutover gate here (sprint49): by the time reconcileRestoring runs, phase is
	// already RestoreSocketReattach or later, which is EXACTLY the accept-set the NRI
	// StartContainer hook's own phase check enforces (nri/plugin.go verifyPhaseInAcceptSet) —
	// a gate placed here would be too late to block the NRI path (that hook fires from an
	// independent kubelet event the instant the phase write lands in etcd, not when this Go
	// function happens to run) and was in fact unreachable on the common NRI path anyway,
	// since the NRI branch above (replForRestore != nil) returns before reaching this point.
	// The real, single gate lives in reconcileOverlayHandoff — see
	// gateStorageCutoverBeforeRestore — which runs strictly before the phase transition into
	// RestoreSocketReattach, so ConditionStorageCutoverComplete is already True by the time
	// either this function or the NRI hook can trigger restore.

	// Restore: CRIU restores the process tree from the checkpoint images on the destination
	// node. checkpoint_ref carries the full images-dir path so the agent uses it directly
	// rather than falling back to the default path (which would be empty on a fresh node).
	// DestinationNodeName is already pinned in pm.Status.DestinationNodeName = destNode above;
	// CRIU recreates the process directly without a scheduler round-trip, so no pod object
	// with NodeName needs to be created here — the process is pinned by executing the restore
	// RPC on the target node's agent.
	// ADR-0406: single-authority conversion shared with the NRI-fallback call site below.
	restoreSeqSnapshots := buildRestoreSeqSnapshots(pm)

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
	if err != nil && status.Code(err) == codes.Aborted {
		// ADR-0353 R5/R6: this is reconcileRestoring's direct/primary Restore RPC call site — the
		// second reachable caller of the gRPC Restore RPC (the resolve-race fall-through documented
		// above, :2949-2951: this path only runs when resolveReplacementPodByLabel found no
		// replacement pod yet, so it can race the NRI async restore already driving CRIU on a
		// replacement pod that in fact exists/is starting). codes.Aborted means another owner (the
		// NRI async restore) currently holds the ADR-0353 single-owner in-flight claim for this
		// migration. TRANSIENT — the in-flight restore may still confirm. Do NOT mark RestoreFailed,
		// do NOT initiate rollback, do NOT touch checkpoint images (still owned by the in-flight
		// restore) — just requeue and let the criuRestoreConfirmed poll (reconcileRestoringNRI /
		// the :3247 branch) continue observing the in-flight owner's eventual confirm.
		log.Info("reconcileRestoring: gRPC Restore declined — another restore owner holds the in-flight claim (ADR-0353), requeuing",
			"migration", pm.Name)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
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
			// ADR-0406 D1: mirror the primary restore call site (reconcileRestoring, :4781) exactly
			// so the fallback path seeds PM_SEQ_XLAT identically to the primary. Before this fix the
			// fallback request omitted SeqSnapshots, so the agent's gRPC seeding block guard
			// `if len(req.SeqSnapshots) > 0` (server.go) was false, SeedRelayFromSnapshots never ran,
			// and reconcileDisengageHold later (correctly) failed closed with SeqXlatNotSeeded. The
			// three fields added here (SeqSnapshots, SourceNodeAddr, SourceFreezeTimestampNs) are the
			// exact three the primary sets that this site was missing. RelayIfname is deliberately
			// left unset — the agent self-resolves it via discoverHostInterface (ADR-0357 D1.5);
			// forcing a literal here would reintroduce the defect that ADR closed. SandboxId is set
			// by neither call site (agent self-resolves).
			fallbackSeqSnapshots := buildRestoreSeqSnapshots(pm)
			// ADR-0406 D2: mirror the primary's SeqSnapshots-present precondition (reconcileRestoring
			// :4777) — never fire a seeding restore with snapshots but an empty destination netns
			// path. Reaching this fallback normally implies the replacement pod's netns was staged,
			// so this is belt-and-suspenders relative to the D1.3 fail-closed, not a substitute.
			if len(fallbackSeqSnapshots) > 0 && pm.Status.DestNetnsPath == "" {
				setCondition(pm, conditionRestored, metav1.ConditionFalse, "RestoreNotConfirmed",
					"Strict NRI-fallback restore: DestNetnsPath empty, DestinationNetnsReady not yet satisfied")
				return ctrl.Result{}, r.statusUpdate(ctx, pm)
			}
			restoreResp, restoreErr := destAgent.Restore(ctx, &agentpb.RestoreRequest{
				MigrationName:           pm.Name,
				CheckpointRef:           checkpointRef,
				SourceNodeAddr:          pm.Status.SourceNodeName,
				SourceFreezeTimestampNs: pm.Status.SourceFreezeTimestampNs,
				SeqSnapshots:            fallbackSeqSnapshots,
				DestNetnsFd:             pm.Status.DestNetnsPath,
				TcpPreservationMode:     string(pm.Spec.TCPPreservationMode),
			})
			if restoreErr != nil {
				if status.Code(restoreErr) == codes.Aborted {
					// ADR-0353 R5/R6: another owner (the NRI async restore) currently holds the
					// single-owner in-flight claim for this migration. TRANSIENT — the in-flight
					// restore may still confirm. Do NOT mark RestoreFailed, do NOT initiate
					// rollback, do NOT touch checkpoint images (still owned by the in-flight
					// restore) — just requeue and let the existing criuRestoreConfirmed poll
					// above continue observing the in-flight owner's eventual confirm.
					log.Info("NRI fallback: gRPC Restore declined — another restore owner holds the in-flight claim (ADR-0353), requeuing",
						"migration", pm.Name)
					return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
				}
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
		if updated, addErr := esMgr.AddDestination(ctx, pm.Spec.PodNamespace,
			pm.Spec.SourcePodIP, replacement.Status.PodIP, false); addErr != nil {
			log.Error(addErr, "EndpointSlice AddDestination failed — continuing (warn-only)",
				"migration", pm.Name)
		} else if updated == 0 {
			// ADR-0390: AddDestination succeeding with zero EndpointSlices touched means no
			// EndpointSlice carried pm.Spec.SourcePodIP in the first place — i.e. no Service
			// ever selected this pod. Logging the same success-sounding message here (as
			// before this fix) masked exactly this condition: every downstream call on this
			// path (ServiceNameForIP, resolveTargetService, establishServiceContinuity) also
			// treats "no EndpointSlice" as an Info-level non-error, so this was the one place
			// that COULD have surfaced the permanent-vs-transient distinction early and didn't.
			log.Info("EndpointSlice: AddDestination touched zero slices — source pod IP was never enrolled in any EndpointSlice (likely no Service selects this pod)",
				"migration", pm.Name,
				"sourcePodIP", pm.Spec.SourcePodIP,
				"destPodIP", replacement.Status.PodIP)
		} else {
			log.Info("EndpointSlice: added destination pod IP alongside source",
				"migration", pm.Name,
				"sourcePodIP", pm.Spec.SourcePodIP,
				"destPodIP", replacement.Status.PodIP,
				"slicesUpdated", updated)
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
	// ADR-0352 B8-D1/B8-D2 (corrected): a Strict CR routes onto the authoritative
	// DisengageHold -> TCPVerifying -> ServiceVerifying spine instead of the legacy 8-phase
	// Verifying tail (W1/W2). An earlier revision targeted MigrationPhaseTCPVerifying directly, which
	// DIVERGED from reconcileRestoreSocketReattach's post-delegate override target
	// (MigrationPhaseDisengageHold, :953-954): on a freshly-created CR the override fires in
	// the same reconcile and wins, but a process exit between this write and the override's
	// write durably persists phase=TCPVerifying. On restart the phase switch dispatches
	// straight to reconcileTCPVerifying, BYPASSING reconcileDisengageHold — the only phase
	// that disarms the source zero-window hold (DisarmZeroWindow, :1045) and enforces the
	// ADR-0049 overlay barrier — so VerifyTCP measures a still-frozen socket, seq_delta==0
	// vacuously satisfies the Strict gate, and Strict reaches Complete with the hold never
	// disarmed (invariant #1 violation via source_teardown.go's missing ZeroWindowDisarmed
	// predicate). Targeting MigrationPhaseDisengageHold instead converges BOTH cases (override
	// fires / override skipped by crash) on the disarm barrier: reconcileDisengageHold is
	// idempotent (:965-967 fast-paths straight to TCPVerifying once RelayProgramsLoaded=True,
	// so this costs nothing on the normal fresh-CR path) and still closes W1/W2 — its own
	// terminal transition (:1109) reaches TCPVerifying, which is the real
	// TCPSequenceContinuityVerified producer (:1229/:1308) B8-D2 required. Routing to
	// ServiceVerifying would remain INSUFFICIENT for the same reason B8-D2 already rejected it:
	// its advance primitive (:1652-1657) reads ServiceContinuityVerified, never produces
	// TCPSequenceContinuityVerified.
	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseDisengageHold)
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

// readDisarmZeroWindowRetryAttempts reads the current DisarmZeroWindow RPC-error retry attempt
// count (fail-closed phase-gate item 5), mirroring readIPReclaimVerifyAttempts.
func readDisarmZeroWindowRetryAttempts(pm *pmv1.PodMigration) int {
	if pm.Annotations == nil {
		return 0
	}
	v, ok := pm.Annotations[disarmZeroWindowRetryAttemptsAnnotation]
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

// resolveDestCNIPlugin (ADR-0322) fetches the destination NodeMigrationCapacity and
// returns the write-verified CNI signal (destNMC.Spec.NetworkCapability.CNIPlugin).
// This is the single source both the controller (injectIPHandoff, fail-closed) and the
// pod-mutating webhook (pod_webhook.go, fail-through) read from — never
// pm.Status.CNIProvider, which has zero writers. Each caller decides its own fail
// policy; this helper only resolves the signal.
func (r *PodMigrationReconciler) resolveDestCNIPlugin(ctx context.Context, node string) (string, error) {
	destNMC := &pmv1.NodeMigrationCapacity{}
	if err := r.Get(ctx, types.NamespacedName{Name: node}, destNMC); err != nil {
		return "", fmt.Errorf("resolveDestCNIPlugin: fetch NMC %s: %w", node, err)
	}
	return destNMC.Spec.NetworkCapability.CNIPlugin, nil
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

	// Cross-node dataplane reachability of the preserved IP — the Strict source-teardown gate
	// (api/v1alpha1/source_teardown.go: DataplaneReachabilityVerified=True). On a Cilium or
	// Calico cross-node destination this is established from the CNI's own authoritative
	// readiness signal (tryEstablishDataplaneReachability, dispatched via CNIMobilitySelector);
	// same-node or a CNI without an authoritative producer falls back to the ADR-0210 producer.
	if res, err, done, handled := r.tryEstablishDataplaneReachability(ctx, pm, destNode); handled {
		if !done {
			return res, err, false
		}
		return ctrl.Result{}, nil, true
	}

	// Same-node (ADR-0237 vacuous) or a CNI with no authoritative producer wired: fall back to
	// the ADR-0210 producer.
	if res, err, done := r.verifyDataplaneReachability(ctx, pm, destNode); !done {
		return res, err, false
	}
	return ctrl.Result{}, nil, true
}

// tryEstablishDataplaneReachability establishes the Strict cross-node source-teardown gate
// (DataplaneReachabilityVerified) from the destination CNI's own AUTHORITATIVE readiness
// write-back instead of the ADR-0210 source-node nonce round-trip.
//
// SUBSTRATE ROOT CAUSE (sprint46B2, decoded from source — see docs/sprints/sprint46B2/
// live-proof-cycle2.md): the ADR-0210 producer establishes the condition with a nonce round-trip
// dialed FROM the source-node agent (ProbeDataplaneReachability, server.go: net.Dialer.DialContext
// + `ip route get`) TO the preserved IP. But ADR-0012 holds the SOURCE pod alive on the SOURCE
// node with that exact IP until this very condition is True, so on the source node the preserved
// IP resolves to the still-alive LOCAL held pod (e.g. Cilium endpointRoutes installs a /32 to the
// local lxc veth), NOT across the overlay to the destination. The dial is delivered locally to the
// old pod (which is not the nonce echo listener), the round-trip can NEVER match, and the migration
// wedges at CutoverComplete forever (invariant #8 breach). This is structurally identical to the
// ADR-0237 same-node deadlock — the source-node vantage is blind to cross-node reachability of an
// IP it still hosts locally. It is not KVM flakiness; the ADR-0210 loopback corpus cannot exhibit it.
//
// FIX (invariant #10 / SUBSTRATE-PRIMITIVE BIAS: read the authoritative write-back, retire the
// inference chain). On a CROSS-node migration this dispatches through CNIMobilitySelector (rather
// than a hardcoded Cilium-only string check) to the destination CNI's own IPHandoffStrategy and, for
// the CNIs with an authoritative readiness producer wired today, establishes the gate from THAT
// CNI's source of truth:
//   - Cilium: cilium-agent's own CiliumEndpoint status (state=ready, identity!=0, AND
//     status.networking.addressing advertises the preserved IP — ConfirmEndpointOwnsPreservedIP).
//   - Calico: Felix's own WorkloadEndpoint readiness signal (WaitForWorkloadEndpointReady).
//
// Both are un-synthesizable by our agents (the same anti-spoof property the nonce round-trip
// reached for) and neither read is confounded by the held source pod. This ELEVATES those
// per-CNI primitives to be the gate producer and RETIRES the ADR-0210 source-node probe on these
// paths. Cilium's behavior is UNCHANGED by this generalization — same CNI match, same
// CiliumHandoff call, same reasons, same conditions — only the dispatch mechanism (selector
// instead of a hardcoded string check) and the function name differ.
//
// Returns handled=false for a same-node destination, OR a cross-node destination whose CNI has no
// authoritative producer wired yet (OVN-K, Flannel, unknown), signalling the caller to fall back to
// verifyDataplaneReachability (same-node vacuous per ADR-0237; non-authoritative CNI nonce
// round-trip — the source-node-vantage limitation applies to those CNIs as follow-up work).
// When handled=true the caller must honor (res,err,done): done=true means the gate was set True;
// done=false means fail-closed (condition set False, requeue, source held per ADR-0012).
func (r *PodMigrationReconciler) tryEstablishDataplaneReachability(ctx context.Context, pm *pmv1.PodMigration, destNode string) (ctrl.Result, error, bool, bool) {
	log := logf.FromContext(ctx)

	cniPlugin, cniErr := r.resolveDestCNIPlugin(ctx, destNode)
	if cniErr != nil {
		log.Error(cniErr, "injectIPHandoff: ADR-0322 unable to resolve destination CNI plugin — blocking (fail-closed)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionDataplaneReachabilityVerified, metav1.ConditionFalse, pmv1.ReasonCNISignalUnresolved,
			fmt.Sprintf("destNMC fetch error for node %s: %v", destNode, cniErr))
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr, false, true
		}
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false, true
	}

	crossNode := pm.Status.SourceNodeName != "" && pm.Status.SourceNodeName != destNode
	if !crossNode {
		// Same-node: caller falls back to verifyDataplaneReachability (ADR-0237 vacuous path).
		return ctrl.Result{}, nil, false, false
	}

	selector := &iphandoff.CNIMobilitySelector{KubeClient: r.KubeClient, DynamicClient: r.DynamicClient}
	switch h := selector.Select(ctx, cniPlugin).(type) {
	case *iphandoff.CiliumHandoff:
		return r.establishCiliumDataplaneReachability(ctx, pm, h)
	case *iphandoff.CalicoHandoff:
		return r.establishCalicoDataplaneReachability(ctx, pm, h)
	default:
		// OVN-K / Flannel / unknown: no authoritative producer wired yet. Caller falls back to
		// verifyDataplaneReachability.
		return ctrl.Result{}, nil, false, false
	}
}

// establishCiliumDataplaneReachability is the Cilium branch of tryEstablishDataplaneReachability,
// unchanged in behavior from the pre-generalization tryEstablishCiliumDataplaneReachability: same
// ConfirmEndpointOwnsPreservedIP call, same reason mapping, same conditions.
func (r *PodMigrationReconciler) establishCiliumDataplaneReachability(ctx context.Context, pm *pmv1.PodMigration, ch *iphandoff.CiliumHandoff) (ctrl.Result, error, bool, bool) {
	log := logf.FromContext(ctx)

	node, ceErr := ch.ConfirmEndpointOwnsPreservedIP(ctx, pm.Spec.PodNamespace, pm.Status.ReplacementPodName, pm.Spec.SourcePodIP)
	if ceErr != nil {
		reason := pmv1.ReasonCiliumEndpointNotReady
		switch {
		case strings.Contains(ceErr.Error(), "lookup error"):
			reason = pmv1.ReasonCiliumEndpointLookupError
		case strings.Contains(ceErr.Error(), "does not advertise preserved IP"):
			reason = pmv1.ReasonPreservedIPNotOnEndpoint
		}
		log.Error(ceErr, "injectIPHandoff: ADR-0322 authoritative CiliumEndpoint read did not confirm preserved IP on destination endpoint — blocking (fail-closed)", "migration", pm.Name, "reason", reason)
		setCondition(pm, pmv1.ConditionDataplaneReachabilityVerified, metav1.ConditionFalse, reason, ceErr.Error())
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr, false, true
		}
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false, true
	}

	// Authoritative source-of-truth read succeeded: cilium-agent programmed the preserved IP onto
	// the replacement endpoint on the destination node. No source-node probe (retired).
	log.Info("injectIPHandoff: cross-node DataplaneReachability established from authoritative CiliumEndpoint status (ADR-0322 primitive; ADR-0210 source-node probe retired)",
		"migration", pm.Name, "preservedIP", pm.Spec.SourcePodIP, "endpointNode", node)
	setCondition(pm, pmv1.ConditionDataplaneReachabilityVerified, metav1.ConditionTrue, pmv1.ReasonCiliumDataplaneProgrammed,
		fmt.Sprintf("cilium-agent programmed preserved IP %s onto replacement endpoint %s on node %s (authoritative CiliumEndpoint read; ADR-0322 primitive, ADR-0210 source-node nonce round-trip retired — structurally blind while source held per ADR-0012)",
			pm.Spec.SourcePodIP, pm.Status.ReplacementPodName, node))
	if sErr := r.statusUpdate(ctx, pm); sErr != nil {
		return ctrl.Result{}, sErr, false, true
	}
	return ctrl.Result{}, nil, true, true
}

// establishCalicoDataplaneReachability is the Calico branch of tryEstablishDataplaneReachability,
// mirroring establishCiliumDataplaneReachability's structure but backed by
// CalicoHandoff.WaitForWorkloadEndpointReady — the authoritative "Felix programmed the dataplane"
// read for a Calico destination (analogous to ConfirmEndpointOwnsPreservedIP for Cilium). Without
// this producer a cross-node Calico migration would fall through to the ADR-0210 nonce round-trip,
// which is structurally blind to cross-node reachability while the source pod is held (see the
// tryEstablishDataplaneReachability doc comment).
func (r *PodMigrationReconciler) establishCalicoDataplaneReachability(ctx context.Context, pm *pmv1.PodMigration, ch *iphandoff.CalicoHandoff) (ctrl.Result, error, bool, bool) {
	log := logf.FromContext(ctx)

	if wepErr := ch.WaitForWorkloadEndpointReady(ctx, pm.Spec.PodNamespace, pm.Status.ReplacementPodName); wepErr != nil {
		log.Error(wepErr, "injectIPHandoff: authoritative Calico WorkloadEndpoint read did not confirm the destination endpoint is active — blocking (fail-closed)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionDataplaneReachabilityVerified, metav1.ConditionFalse, pmv1.ReasonCalicoWorkloadEndpointNotReady, wepErr.Error())
		if sErr := r.statusUpdate(ctx, pm); sErr != nil {
			return ctrl.Result{}, sErr, false, true
		}
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false, true
	}

	log.Info("injectIPHandoff: cross-node DataplaneReachability established from authoritative Calico WorkloadEndpoint readiness (ADR-0210 source-node probe retired on this path)",
		"migration", pm.Name, "preservedIP", pm.Spec.SourcePodIP, "replacementPod", pm.Status.ReplacementPodName)
	setCondition(pm, pmv1.ConditionDataplaneReachabilityVerified, metav1.ConditionTrue, pmv1.ReasonCalicoDataplaneProgrammed,
		fmt.Sprintf("Calico WorkloadEndpoint for replacement pod %s is active (authoritative WEP read; ADR-0210 source-node nonce round-trip retired — structurally blind while source held per ADR-0012)",
			pm.Status.ReplacementPodName))
	if sErr := r.statusUpdate(ctx, pm); sErr != nil {
		return ctrl.Result{}, sErr, false, true
	}
	return ctrl.Result{}, nil, true, true
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

	// ADR-0352 B8-D3 (corrected): a Strict CR reaching this legacy 8-phase completion
	// tail (a pre-existing CR already persisted at phase=Verifying, or a crash/restart in the
	// narrow window between reconcileRestoringNRI's DisengageHold-targeted write and
	// reconcileRestoreSocketReattach's :953-954 override — see this ADR's Context
	// "Composed-flow reachability") hands off to the authoritative
	// DisengageHold -> TCPVerifying -> ServiceVerifying spine instead of running the retired
	// parallel completion below. An earlier revision handed off directly to MigrationPhaseTCPVerifying,
	// which for THIS population is not a divergence-on-crash race (there is no downstream
	// override here) but the SAME underlying defect: a CR entering here has never traversed
	// reconcileDisengageHold, so it can reach TCPVerifying with the source zero-window hold
	// still armed and the ADR-0049 overlay barrier unchecked, letting VerifyTCP vacuously
	// satisfy seq_delta==0 against a frozen socket (invariant #1). Handing off to
	// MigrationPhaseDisengageHold instead routes through the one phase that disarms the hold
	// (DisarmZeroWindow, :1045) before ever reaching TCPVerifying (:1109 terminal transition)
	// — reconcileDisengageHold is idempotent if the hold was already disarmed by an earlier
	// pass. This still closes W1 (the gateTrueLegacy skip that never set TrafficVerified) and
	// W2 (the missing TCPSequenceContinuityVerified producer) as ONE fix — replace the
	// divergent tail, do not patch it (invariant #10).
	if pm.Spec.TCPPreservationMode == pmv1.TCPPreservationModeStrict {
		return r.transitionTo(ctx, pm, pmv1.MigrationPhaseDisengageHold)
	}

	// the traffic-verification worker drives readiness + traffic verification. Watches TrafficVerified.
	// ADR-0019: if verification fails AFTER handoff, warn only — do not rollback.
	trafficVerified := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionTrafficVerified)
	if !trafficVerified {
		// ADR-0133 Decision 1: inject the OLD-pod-IP handoff on the DESTINATION node
		// AFTER criuRestoreConfirmed (precondition of the Restoring→Verifying transition)
		// and BEFORE TrafficVerified is set / source is disarmed/cleaned. The reachability
		// probe (Decision 5) gates TrafficVerified for the directly-pinned pod-IP client;
		// the service-path TrafficVerifier remains as the L4/Service backstop below.
		// ADR-0352 B8-D3: Strict never reaches this point (handed off at the top of the
		// function), so the injectIPHandoff / establishServiceContinuity fork this comment
		// used to describe is retired — only BestEffort/None reach here now, byte-identical
		// to their pre-fix behavior (B8-DR-7).
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
		// ADR-0352 B8-D3: the Strict/ServiceContinuityVerified fork this comment used to
		// describe is retired — Strict is handed off at the top of the function, so this
		// gate is now unconditionally the legacy DataplaneReachabilityVerified cross-node
		// gate (D2.2b — preserved verbatim for BestEffort/None).
		gateSatisfiedLegacy := conditionDataplaneReachabilityVerified
		gateTrueLegacy := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionDataplaneReachabilityVerified)
		if gateTrueLegacy {
			log.Info("Verifying: authoritative reachability gate set — skipping service-path verifier",
				"migration", pm.Name, "gate", gateSatisfiedLegacy)
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
			// ADR-0352 B8-D5 (3a): this log used to fire unconditionally after the
			// gateTrueLegacy/TrafficVerifier/else chain, including on the gateTrueLegacy skip
			// branch that never set TrafficVerified=True. Moved into the branch that actually
			// sets it True so the log claim matches the write it describes.
			log.Info("Verifying: TrafficVerified set — requeueing for source pod deletion", "migration", pm.Name)
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
	// ADR-0325: the source-pod deletion gate (sourcePodDeletionBlockReason) requires
	// WorkloadLivenessVerified=True for ALL modes, including None. On this legacy
	// (…→RestoreSocketReattach→Verifying) path the newer ServiceVerifying phase — which is
	// where that condition is otherwise produced — is never entered, so we must run the
	// real-liveness probe HERE (against the replacement pod's current IP) before attempting
	// deletion. Without this the gate can never be satisfied and the migration deadlocks in
	// Verifying, refusing to delete the source pod forever.
	if verified, res := r.ensureWorkloadLivenessVerified(ctx, pm); !verified {
		log.Info("Verifying: ADR-0325 workload-liveness not yet verified on destination pod — holding source, requeuing", "migration", pm.Name)
		return res, nil
	}

	log.Info("Verifying: routing source pod deletion through deleteSourcePodIfSafe (ADR-0012 STRICTER-union gate)", "migration", pm.Name)
	if blocked, res := r.deleteSourcePodIfSafe(ctx, pm); blocked {
		return res, nil
	}

	setCondition(pm, conditionSourcePodDeleted, metav1.ConditionTrue, "Deleted", "Source pod deleted post-TrafficVerified+WorkloadLivenessVerified")

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
				pm.Status.Cni0CleanupVerifyAttempts = 0
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
					// Verifying-phase wedge fix: this counter is now a
					// status field persisted ONLY via r.statusUpdate (status subresource), never
					// via r.Update (spec/metadata). The validating webhook is registered only on
					// the "podmigrations" resource, not "podmigrations/status"
					// (config/webhook/manifests.yaml), so this write never invokes it — migration
					// completion progress no longer depends on repassing spec admission at all,
					// independent of and in addition to the §1 webhook fix.
					pm.Status.Cni0CleanupVerifyAttempts = int32(attempts + 1)
					if err := r.statusUpdate(ctx, pm); err != nil {
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
				pm.Status.Cni0CleanupVerifyAttempts = 0
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
	// ADR-0350 D1: capture the reaped UIDs — this is the source-of-truth handoff consumed
	// below by ensureReplacementEndpointsRemoved. Never re-resolved after this point.
	reapedPods := r.deleteReplacementPod(ctx, pm)

	// ADR-0344 Decision A.2: for Tier0 (RWX) migrations, the frozen source process
	// must not be resumed (SIGCONT'd) until its storage has been confirmed writable
	// again — otherwise the resumed source and a possibly-still-mounted destination
	// can both write the same PGDATA/pg_wal concurrently (Context §2 split-brain
	// hazard). r.Rollbacker.Rollback is what actually resumes the source, so this
	// gate MUST run before it.
	if err := r.restoreSourceStorageIfNeeded(ctx, pm); err != nil {
		log.Error(err, "restoreSourceStorageIfNeeded failed — refusing to resume source (ADR-0344 A.2)", "migration", pm.Name)
		return r.failMigration(ctx, pm, fmt.Sprintf("source storage write-restore failed: %v", err))
	}

	if err := r.Rollbacker.Rollback(ctx, pm); err != nil {
		log.Error(err, "rollback failed — source pod may require manual intervention")
		// ADR-0368 §6 item 3: the generic "rollback failed: rollback partial failure (1/3 steps
		// failed): [...]" string failMigration produces below is loud but undifferentiated — an
		// operator/alert rule cannot tell "Tier2 point-of-no-return, never retry, destination is
		// authoritative" apart from "Tier1 detach hit a transient timeout, a requeue might well
		// succeed" apart from "Tier3, nobody has built this yet." errors.Is correctly traverses
		// DefaultRollbacker.Rollback's %w-wrapped combined error (CONDITION 4's fix) down to
		// each step's sentinel, so check for the two ADR-0368 sentinels specifically and set a
		// distinct, human-actionable condition + Warning event before falling through to the
		// existing generic ConditionFailed/MigrationFailed terminal path (failMigration below) —
		// matching the existing setCondition+Recorder.Eventf pattern used throughout this
		// controller (e.g. :601, :1348, :2704).
		switch {
		case errors.Is(err, storage.ErrRollbackPointOfNoReturn):
			setCondition(pm, pmv1.ConditionStorageRollbackImpossible, metav1.ConditionTrue,
				"StorageRollbackImpossible", err.Error())
			if r.Recorder != nil {
				r.Recorder.Eventf(pm, corev1.EventTypeWarning, "StorageRollbackImpossible", "%v", err)
			}
		case errors.Is(err, storage.ErrRollbackNotImplemented):
			setCondition(pm, pmv1.ConditionStorageRollbackNotSupported, metav1.ConditionTrue,
				"StorageRollbackNotSupported", err.Error())
			if r.Recorder != nil {
				r.Recorder.Eventf(pm, corev1.EventTypeWarning, "StorageRollbackNotSupported", "%v", err)
			}
		}
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

	// ADR-0350 D1/D2: gate RolledBack=True on confirmed replacement-endpoint absence. Placed
	// here — after Rollbacker.Rollback has resumed the source, immediately before the 4548-4549
	// mutation — so the synchronous EndpointSlice round-trip is paid only on the path that
	// actually publishes RolledBack, and the pod Delete above has had the maximum possible
	// window to acquire its deletionTimestamp before the CAS runs (S-REORDER safety margin).
	if ok, mode, ensErr := r.ensureReplacementEndpointsRemoved(ctx, pm, reapedPods); !ok {
		reason := "ReplacementEndpointRemovalContended"
		if mode == "undeletable" {
			reason = "ReplacementPodUndeletable"
		}
		msg := fmt.Sprintf("replacement endpoint removal not confirmed (mode=%s): %v", mode, ensErr)
		setCondition(pm, pmv1.ConditionReplacementEndpointsRemoved, metav1.ConditionFalse, reason, msg)
		pmmetrics.ReplacementEndpointRemovalExhaustedTotal.WithLabelValues(pm.Name, pm.Namespace, reason).Inc()
		if r.Recorder != nil {
			r.Recorder.Eventf(pm, corev1.EventTypeWarning, "ReplacementEndpointRemovalExhausted",
				"replacement endpoint removal exhausted its retry budget for migration %s (mode=%s); RolledBack withheld",
				pm.Name, mode)
		}
		if ensErr != nil {
			log.Error(ensErr, "reconcileRollingBack: ensureReplacementEndpointsRemoved did not confirm absence — withholding RolledBack and requeuing (ADR-0350 D2/D3)",
				"migration", pm.Name, "mode", mode)
		}
		// Fail-closed: do NOT set Phase=Failed or RolledBack=True. Persist the False signal and
		// requeue so the next reconcile re-runs the idempotent removal from a fresh read.
		return ctrl.Result{RequeueAfter: 3 * time.Second}, r.statusUpdate(ctx, pm)
	}
	setCondition(pm, pmv1.ConditionReplacementEndpointsRemoved, metav1.ConditionTrue, "ReplacementEndpointsAbsent", "")

	// ADR-0393: durable-snapshot cold-recreate for a bare (no owning controller) pod whose source
	// was early-deleted (ADR-0356) and whose restore then failed — the ADR-0387 guaranteed-
	// unrecoverable outage. If a durable, operator-captured, HMAC-valid snapshot is present, convert
	// that outage into a ReplicaSet-parity cold restart. Absent/invalid snapshot ⇒ exactly today's
	// honest RollbackCompleteNoOwningController outage. This runs BEFORE Phase is set to Failed so a
	// requeue re-enters reconcileRollingBack (Phase stays RollingBack) across an operator crash
	// mid-recreate (D-ACCEPT). Honesty (binding): this recovers to a cold-recreated pod — fresh
	// container + on-disk/WAL recovery; in-memory and TCP connection state are lost — never a
	// zero-downtime rollback.
	coldRecreated := false
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) &&
		pm.Status.Tier1EarlyReleaseSourceOwnerKind == "" &&
		pm.Status.SourcePodSpecSnapshot != nil {
		outcome, res, rcErr := r.reconcileTier1ColdRecreateFromSnapshot(ctx, pm)
		if rcErr != nil {
			// A real error attempting the recreate (transient API error, admission rejection).
			// Withhold the terminal RolledBack and requeue — never fabricate/widen a pod, never
			// silently proceed to the unrecovered-outage report on a recreate that could still
			// succeed on retry.
			log.Error(rcErr, "reconcileRollingBack: ADR-0393 cold-recreate errored — withholding RolledBack and requeuing",
				"migration", pm.Name)
			return ctrl.Result{RequeueAfter: 3 * time.Second}, r.statusUpdate(ctx, pm)
		}
		switch outcome {
		case coldRecreatePending:
			// Recreate in flight; re-enter from persisted state on the next reconcile.
			return res, r.statusUpdate(ctx, pm)
		case coldRecreateSucceeded:
			coldRecreated = true
		case coldRecreateBlockedInvalid:
			// Fall through to the honest RollbackCompleteNoOwningController report below.
		}
	}

	pm.Status.Phase = pmv1.MigrationPhaseFailed
	// Status-honesty fix (sprint49): "Source pod restored to live state" is only true when
	// the source pod was still alive (frozen, never deleted — ADR-0012's normal guarantee) and
	// Rollbacker.Rollback thawed it in place. ADR-0356's Tier1-Longhorn early source release
	// deletes the source pod BEFORE this phase can ever be reached for that migration, so
	// r.Rollbacker.Rollback's ComputeRollback thaw step has nothing to thaw — Rollback()
	// returns success as a no-op, not because a live pod was resumed. Report that honestly:
	// this is a real bounded-downtime outage recovered via the source pod's owning controller
	// (e.g. a ReplicaSet) recreating a fresh replacement, not a live-resume.
	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionTier1EarlySourceRelease) {
		if coldRecreated {
			// ADR-0393: a bare pod's source was cold-recreated from the durable snapshot. Report
			// ReplicaSet-parity recovery honestly — a fresh container from on-disk state, NOT a
			// zero-downtime live-resume.
			setCondition(pm, pmv1.ConditionRolledBack, metav1.ConditionTrue, "RollbackCompleteColdRecreatedFromSnapshot",
				"ADR-0393: ADR-0356 Tier1-Longhorn early source release had already deleted the bare source pod "+
					"before rollback ran, and restore failed — but a durable operator-captured spec snapshot was "+
					"present, so the pod was cold-recreated from it. Recovery is ReplicaSet parity (fresh container + "+
					"on-disk/WAL state); in-memory state and live TCP connections are lost. This is NOT a "+
					"zero-downtime rollback.")
		} else {
			r.setRolledBackConditionForTier1EarlyRelease(pm)
		}
	} else {
		setCondition(pm, pmv1.ConditionRolledBack, metav1.ConditionTrue, "RollbackComplete", "Source pod restored to live state")
	}
	// M26: emit flow_loss counter at Failed (all TCP connections inventoried are treated as lost).
	pmmetrics.MigrationFlowLossTotal.WithLabelValues(pm.Name, pm.Namespace).Add(
		float64(len(pm.Status.TCPSeqSnapshots)),
	)
	r.releaseDestinationCapacity(ctx, pm)
	return ctrl.Result{}, r.statusUpdate(ctx, pm)
}

// setRolledBackConditionForTier1EarlyRelease implements ADR-0387: report the TRUE recovery
// story for a Tier1-Longhorn migration whose source pod was already deleted by
// earlyReleaseSourceForTier1Longhorn before rollback ran, rather than unconditionally
// asserting ADR-0356's generic "a controller recreates a fresh replacement" narrative.
//
// pm.Status.Tier1EarlyReleaseSourceOwnerKind was captured from the source pod's own
// OwnerReferences at the exact moment of early release (see earlyReleaseSourceForTier1Longhorn),
// before the source pod was deleted and that information became unrecoverable from the API. An
// empty value means the source pod had no owning controller at all — a bare/standalone pod,
// which is this project's ONLY currently-supported pod shape (CLAUDE.md standing scope note,
// 2026-07-23) — so nothing will ever recreate it: this is an unrecovered outage, not a
// bounded-downtime auto-recovery, and must be reported as such (distinct Reason + Warning
// event) so an operator/alert rule can tell the two apart.
func (r *PodMigrationReconciler) setRolledBackConditionForTier1EarlyRelease(pm *pmv1.PodMigration) {
	if pm.Status.Tier1EarlyReleaseSourceOwnerKind == "" {
		setCondition(pm, pmv1.ConditionRolledBack, metav1.ConditionTrue, "RollbackCompleteNoOwningController",
			"ADR-0356 Tier1-Longhorn early source release had already deleted the source pod before rollback "+
				"ran — no live pod existed to resume. The source pod had NO owning controller (a bare/standalone "+
				"pod), so ADR-0356's usual 'a controller recreates a fresh replacement' recovery does not apply "+
				"here: nothing will recreate this pod automatically. This is an unrecovered outage requiring "+
				"manual intervention (recreate the pod from its original spec / the durably-verified checkpoint), "+
				"not a bounded-downtime auto-recovery (ADR-0387).")
		if r.Recorder != nil {
			r.Recorder.Eventf(pm, corev1.EventTypeWarning, "Tier1EarlyReleaseUnrecoveredOutage",
				"migration %s: Tier1-Longhorn early source release deleted a standalone pod with no owning "+
					"controller; restore then failed and nothing will recreate it automatically — manual "+
					"intervention required", pm.Name)
		}
		return
	}
	setCondition(pm, pmv1.ConditionRolledBack, metav1.ConditionTrue, "RollbackCompleteBoundedDowntime",
		fmt.Sprintf("ADR-0356 Tier1-Longhorn early source release had already deleted the source pod before "+
			"rollback ran — no live pod existed to resume. Recovery is bounded-downtime (checkpoint-guaranteed "+
			"via the source pod's owning %s recreating a fresh replacement), not a zero-downtime live-resume.",
			pm.Status.Tier1EarlyReleaseSourceOwnerKind))
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
// restoreSourceStorageIfNeeded implements the structural scaffolding for ADR-0344
// Decision A.2, NOT yet the full remount-rw handoff it is named for.
//
// CORRECTED (ADR-0344 C2, 2026-07-12): for Tier0-classified (RWX)
// migrations this function today only confirms that the source agent's gRPC
// connection is reachable (r.AgentPool.ForNode succeeds) — it does NOT issue
// any remount-rw RPC and does NOT confirm the destination volume is
// unmounted. There is no `StorageHandoffReady`-class RPC for the rollback
// direction on the wire (see storage.StorageHandoffClient, which only covers
// the forward Cutover/remount-ro path). Setting
// ConditionSourceStorageWriteRestored=True here is therefore a connectivity
// check, not a storage-state confirmation — it does NOT close the
// concurrent-writer/split-brain window described in ADR-0344 Context §1/§2.
// That window remains open and is tracked as open security debt in
// docs/security/SECURITY-DEBT-LEDGER.md ("ADR-0344 Decision A.2 rollback
// remount-rw confirmation is connectivity-only"). No consumer may treat
// ConditionSourceStorageWriteRestored=True as proof the concurrent-writer
// window is closed until a real remount-rw RPC exists on the wire (see
// api/v1alpha1/podmigration_types.go doc comment on the condition).
//
// CORRECTED (ADR-0344, 2026-07-12): when r.AgentPool is nil (or
// SourceNodeName is unset) this now fails CLOSED by default — it only fails
// open when the caller has explicitly set TestOnlyAllowNilAgentPoolFailOpen,
// which production wiring (cmd/main.go) never sets. This closes the prior gap
// where a misconfigured production reconciler with a nil AgentPool would
// silently set a storage-named safety condition True having verified nothing.
//
// For all other tiers (no shared-mount hazard — Tier1/2/3 either have no
// concurrent destination writer or handle their own cutover atomically) this
// is a same-reconcile no-op that sets the condition True immediately,
// preserving pre-ADR-0344 behavior for every non-Tier0 migration.
//
// Idempotent under re-queues: if the condition is already True, it returns
// immediately without re-checking connectivity.
func (r *PodMigrationReconciler) restoreSourceStorageIfNeeded(ctx context.Context, pm *pmv1.PodMigration) error {
	log := logf.FromContext(ctx)

	if meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionSourceStorageWriteRestored) {
		return nil
	}

	isTier0 := pm.Status.StorageTier != nil && *pm.Status.StorageTier == int32(storage.TierRWX)
	if !isTier0 {
		// No shared-mount hazard for non-Tier0 tiers — set True immediately.
		setCondition(pm, pmv1.ConditionSourceStorageWriteRestored, metav1.ConditionTrue,
			"NonTier0NoOp", "storage tier does not require a write-restore handoff")
		return nil
	}

	if r.AgentPool == nil || pm.Status.SourceNodeName == "" {
		// CORRECTED (ADR-0344, 2026-07-12): a nil AgentPool/SourceNodeName is no
		// longer inferred as "test environment, safe to fail open." That inference let a
		// misconfigured production reconciler silently set a storage-named safety condition
		// True having verified nothing. Failing open now requires the caller to have
		// explicitly opted in via TestOnlyAllowNilAgentPoolFailOpen — set only by unit tests
		// (see adr0344_restore_source_storage_test.go) — so a production reconciler with a
		// nil AgentPool fails CLOSED on this condition instead.
		if !r.TestOnlyAllowNilAgentPoolFailOpen {
			setCondition(pm, pmv1.ConditionSourceStorageWriteRestored, metav1.ConditionFalse,
				"AgentTransportNotConfigured", "no agent transport wired and fail-open not explicitly authorized; refusing to confirm source storage restored")
			return fmt.Errorf("restoreSourceStorageIfNeeded: AgentPool/SourceNodeName unavailable and TestOnlyAllowNilAgentPoolFailOpen not set")
		}
		log.Info("restoreSourceStorageIfNeeded: AgentPool/SourceNodeName unavailable — treating as restored (fail-open, explicitly authorized by TestOnlyAllowNilAgentPoolFailOpen)", "migration", pm.Name)
		setCondition(pm, pmv1.ConditionSourceStorageWriteRestored, metav1.ConditionTrue,
			"NoAgentPoolConfigured", "no agent transport wired; write-restore handoff skipped (test-only fail-open explicitly authorized)")
		return nil
	}

	// Confirm the source agent's gRPC connection is reachable before allowing
	// the source process to resume. NOTE: this is a connectivity precondition
	// only — there is no remount-rw RPC on the wire yet (see the function doc
	// comment above / ADR-0344 C2), so reaching the agent
	// does NOT itself confirm the source's Tier0 volume is writable or that
	// the destination is unmounted. If the source agent cannot be reached at
	// all, resuming the process is refused (fails closed on unreachability),
	// but reachability succeeding does not mean storage state was verified.
	if _, err := r.AgentPool.ForNode(ctx, pm.Status.SourceNodeName); err != nil {
		setCondition(pm, pmv1.ConditionSourceStorageWriteRestored, metav1.ConditionFalse,
			"SourceAgentUnreachable", fmt.Sprintf("cannot reach source agent to confirm storage writable: %v", err))
		return fmt.Errorf("restoreSourceStorageIfNeeded: connect to source agent on %s: %w", pm.Status.SourceNodeName, err)
	}

	setCondition(pm, pmv1.ConditionSourceStorageWriteRestored, metav1.ConditionTrue,
		"SourceAgentReachableRemountUnverified",
		"source agent gRPC connectivity confirmed — NOTE: this does not yet verify actual remount-rw "+
			"storage state (no remount-rw RPC exists on the wire); see ADR-0344 sign-off finding C2 and "+
			"docs/security/SECURITY-DEBT-LEDGER.md")
	return nil
}

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
		server := fresh.DeepCopy()
		fresh.Status = pm.Status
		preserveOperatorOwnedDurableStatus(server, &fresh.Status) // ADR-0398/0408: never blob-overwrite marker or snapshot
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
		server := fresh.DeepCopy()
		fresh.Status = pm.Status
		preserveOperatorOwnedDurableStatus(server, &fresh.Status) // ADR-0398/0408: never blob-overwrite marker or snapshot
		fresh.Status.Phase = pmv1.MigrationPhaseFailed
		now := metav1.Now()
		fresh.Status.CompletionTime = &now
		setCondition(fresh, pmv1.ConditionFailed, metav1.ConditionTrue, "MigrationFailed", reason)
		return r.Status().Update(ctx, fresh)
	})
	return ctrl.Result{}, err
}

func (r *PodMigrationReconciler) initiateRollback(ctx context.Context, pm *pmv1.PodMigration, reason string) (ctrl.Result, error) {
	setCondition(pm, "RollbackReason", metav1.ConditionTrue, "Initiating", reason)
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseRollingBack)
}

// isTerminalOrRollingBackPhase reports whether a phase is a terminal outcome or already on the
// rollback path. The top-level completion-deadline primitive (Reconcile) must NOT re-fire on these:
// firing on RollingBack would loop the rollback it just initiated, and firing on Complete/Failed/
// DryRunComplete would fight the terminal-outcome handlers (ADR-0244 IP-reclaim sweep).
func isTerminalOrRollingBackPhase(p pmv1.MigrationPhase) bool {
	// ADR-0412 condition #4: delegate to the canonical shared classifier
	// (api/v1alpha1.IsTerminalOrRollingBackPhase) so this predicate and the NRI restore gate
	// share ONE definition of the {Complete, Failed, DryRunComplete, RollingBack} set instead of
	// each keeping a near-duplicate. Behavior is byte-identical to the prior local switch.
	return pmv1.IsTerminalOrRollingBackPhase(p)
}

// sourceAlreadyDeletedLegitimately reports whether the source pod is gone for a reason the
// controller itself already recorded and verified — i.e. deleteSourcePodIfSafe (ADR-0012,
// gated on TrafficVerified+WorkloadLivenessVerified) or the Tier1-Longhorn early release path
// already ran and set conditionSourcePodDeleted=True. This is controller-only-writable status
// state — never reachable from an admission request body — so trusting it here does not
// reintroduce the forgeable-status-field problem: this function is invoked
// entirely inside the controller's own Reconcile loop, never from the webhook, and reads the
// object's OWN persisted status plus a fresh live fetch, not anything carried on an incoming
// request.
//
// Both signals are required to agree before the caller may skip the destructive rollback: the
// persisted condition AND a fresh live-fetch confirmation that the named pod is actually gone.
// This is deliberately conservative — on ANY disagreement (condition True but a pod with that
// name/namespace exists again, e.g. name reuse after GC; or any fetch error other than
// NotFound) it returns false and the caller falls through to the existing destructive rollback
// path, which remains the correct behavior for a migration that has NOT genuinely succeeded
// (the actual invariant-#8 wedge this watchdog was built to catch).
func (r *PodMigrationReconciler) sourceAlreadyDeletedLegitimately(ctx context.Context, pm *pmv1.PodMigration) bool {
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionSourcePodDeleted) {
		return false
	}
	if pm.Spec.PodName == "" || pm.Spec.PodNamespace == "" {
		return true // nothing to corroborate against; trust the authoritative controller-set condition.
	}
	if _, err := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName); err == nil {
		return false // condition says deleted but a live pod with this name exists — fail closed.
	} else if !apierrors.IsNotFound(err) {
		return false // API error — fail closed rather than skip the safety net on uncertainty.
	}
	return true
}

// closeOutAfterLegitimateSourceDeletion is the safe terminal path for a migration whose
// completion budget expired ONLY because some non-fatal post-deletion straggler (e.g. the
// ADR-0241 cni0-cleanup-verify retry loop) could not converge — never because the migration
// failed. The source pod is already confirmed and verified gone
// (sourceAlreadyDeletedLegitimately). Unlike initiateRollback's path, this must NEVER call
// deleteReplacementPod or Rollbacker.Rollback (there is nothing to roll back to — thawing a
// nonexistent source and deleting the healthy replacement is exactly the destructive bug this
// closes). It mirrors the tail of reconcileVerifying's normal success path, minus the
// best-effort/idempotent cleanup steps (EndpointSlice RemoveSource, source-node ARP cleanup)
// that are optional polish, not correctness-required for a terminal Complete state, and can
// still complete on a later idempotent pass if needed.
func (r *PodMigrationReconciler) closeOutAfterLegitimateSourceDeletion(ctx context.Context, pm *pmv1.PodMigration, reason string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("completion budget exceeded but source pod was already legitimately deleted (ADR-0012 gate satisfied) — closing out to Complete instead of a destructive rollback (Finding 3b)",
		"migration", pm.Name, "phase", pm.Status.Phase, "reason", reason)
	if pm.Status.CompletionTime == nil {
		now := metav1.Now()
		pm.Status.CompletionTime = &now
	}
	r.releaseDestinationCapacity(ctx, pm)
	return r.transitionTo(ctx, pm, pmv1.MigrationPhaseComplete)
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

// sourcePodPresentLive performs ONE uncached (APIServer-direct) read of the named pod to
// disambiguate a cached-getPod NotFound from a genuine absence (ADR-0409). It returns true ONLY
// when the pod is confirmed to exist on a live read — meaning the cached NotFound was informer
// cache lag and the caller must NOT clean-abort. It returns false when the live read confirms the
// pod is genuinely gone (deterministic absence -> safe to clean-abort) OR when no uncached client
// is wired (unit tests: r.KubeClient is nil) OR the live read itself errors for any other reason:
// in those cases the caller falls back to the cached NotFound verdict rather than pretending the
// pod exists. It is best-effort and never itself blocks the terminal decision.
func (r *PodMigrationReconciler) sourcePodPresentLive(ctx context.Context, namespace, name string) bool {
	if r.KubeClient == nil {
		// No uncached client available (unit tests). Trust the cached NotFound verdict.
		return false
	}
	_, err := r.KubeClient.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		// NotFound (deterministic absence) or any other error: do not treat as present.
		return false
	}
	return true
}

// describeLiveSuccessorHint is a best-effort attribution helper (ADR-0409): when a source pod named
// spec.podName is unresolvable, it lists pods in spec.podNamespace carrying the lineage label that
// records THIS pod as their immediate predecessor and, if exactly one such live successor exists,
// returns a human-facing hint pointing the operator at it. It reads the predecessor LABEL rather
// than parsing successor pod names (which no longer encode lineage). On any list error, on zero
// candidates, or on ambiguity (more than one candidate) it returns "". It ONLY enriches the
// failMigration reason string — it is never a control-flow gate and its failure never blocks the
// clean-abort.
func (r *PodMigrationReconciler) describeLiveSuccessorHint(ctx context.Context, pm *pmv1.PodMigration) string {
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, client.InNamespace(pm.Spec.PodNamespace),
		client.MatchingLabels{podlineage.PredecessorPodNameLabel: pm.Spec.PodName}); err != nil {
		return ""
	}
	if len(podList.Items) != 1 {
		return ""
	}
	return fmt.Sprintf(" (a live successor pod %q exists — migrate that instead)", podList.Items[0].Name)
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

// mountContentCaptureFailedReason is the stable, machine-readable errdetails.ErrorInfo.Reason value
// (ADR-0415 fail-closed capture gate) set by the agent on the codes.FailedPrecondition status returned from the
// Checkpoint RPC when an owned pod-local mount's content could not be captured
// (internal/agent/server/adr0415_mount_capture_gate.go: MountContentCaptureFailedReason,
// newMountContentCaptureFailedStatus). Kept as an independent local constant — the same convention
// as shmemPagemapMissingReason above; TestMountContentCaptureFailedReason_AgentControllerAgree
// compares it against server.MountContentCaptureFailedReason so a drift is caught in CI.
const mountContentCaptureFailedReason = "MOUNT_CONTENT_CAPTURE_FAILED"

// mountContentCaptureFailedReasonFromStatus reports whether grpcStatus carries an
// errdetails.ErrorInfo{Reason: mountContentCaptureFailedReason} details entry (ADR-0415 fail-closed capture gate).
// Used to distinguish the owned-mount-capture FailedPrecondition from the shmem-pagemap and
// CRIU-capability FailedPreconditions that share the same gRPC code.
func mountContentCaptureFailedReasonFromStatus(grpcStatus *status.Status) bool {
	if grpcStatus == nil {
		return false
	}
	for _, d := range grpcStatus.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == mountContentCaptureFailedReason {
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
// attempt count for pm (ADR-0241 item 1). Later revised: this is now a typed
// int32 status field (pm.Status.Cni0CleanupVerifyAttempts) persisted exclusively via
// r.statusUpdate → r.Status().Update, never a spec/metadata annotation — no parsing needed.
func readCni0CleanupVerifyAttempts(pm *pmv1.PodMigration) int {
	return int(pm.Status.Cni0CleanupVerifyAttempts)
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

	// Build a deterministic, BOUNDED name from the STABLE ORIGINAL (root) workload
	// name + short PM UID — never from sourcePod.Name directly. sourcePod may itself
	// be a prior migration's replacement pod (a second/Nth migration of the same
	// workload); appending "-m-<uid>" to its already-suffixed name is what chained
	// the name without bound across cycles ("redis-m-aaaa" -> "redis-m-aaaa-m-bbbb"
	// -> ...). Deriving from podlineage.OriginalPodName (the root carried forward in
	// a label, or the canonicalized source name for a never-migrated pod) makes the
	// name a fixed-width function of (root, pm.UID): repeated cycles reuse the root
	// and never grow. See internal/podlineage.
	originalName := podlineage.OriginalPodName(sourcePod)
	replacementName := podlineage.DeterministicIncarnationName(originalName, podlineage.MigrateNameTag, string(pm.UID))

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

	// Record migration lineage in LABELS (not in the pod name): the stable root
	// name, this incarnation's generation depth, and the immediate predecessor's
	// name/UID. These carry forward the root across the chain (so the next
	// migration of THIS pod names its successor from the same root) and let any
	// consumer reconstruct lineage without parsing the name string. Fail closed:
	// an unrooted incarnation is a real error, never a silently unlabeled pod.
	if err := podlineage.StampLabels(newLabels, originalName, sourcePod.Name, string(sourcePod.UID),
		podlineage.PodGeneration(sourcePod)+1); err != nil {
		return fmt.Errorf("stamp lineage labels on replacement pod: %w", err)
	}

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
	// ADR-0359: sourcePod is not always pristine — for a live pod, sourcePod.Spec.NodeName
	// is populated to the SOURCE node. Explicitly zero it here rather than letting it fall
	// out of the (now-removed) destination-NodeName pin below: with the pin gone, a blind
	// deep copy would otherwise leave the replacement pod's spec.NodeName bound to the
	// source node — a NodeName-bound pod bypasses the scheduler entirely (kubelet on that
	// node picks it up via pod-watch regardless of SchedulingGates), which would strand the
	// replacement pod scheduling-gate-inert against the node the SOURCE workload is still
	// live on (ADR-0012: source is not deleted until TrafficVerified=True). This must be an
	// explicit, verified statement — not an implicit side effect of what got deleted.
	spec.NodeName = ""

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

	// Strip any PodMotion-injected holder artifacts already present on the DEEP-COPIED spec
	// before re-injecting fresh ones. sourcePod is not always a pristine, never-migrated pod:
	// on a SECOND (or later) migration of the same workload, sourcePod IS the previous
	// migration's replacement pod, which already carries the holderVolumeName emptyDir, the
	// "podmotion-inject-holder" init container, and the holderMountPath VolumeMount on every
	// main container from ITS OWN createReplacementPod call. Appending a second copy of each
	// on top produces a Pod spec the API server rejects outright:
	//   spec.volumes[N].name: Duplicate value: "podmotion-holder-bin"
	//   spec.initContainers[N].name: Duplicate value: "podmotion-inject-holder"
	//   spec.containers[0].volumeMounts[N].mountPath: Invalid value: "/podmotion": must be unique
	// which silently strands the migration with Status.ReplacementPodName never set (reproduced
	// live, sprint49: nginx-live-proof2-retry, operator log "failed to create replacement pod").
	// Stripping by name/mountPath here — mirroring the selector-label strip above — makes
	// replacement-pod creation idempotent regardless of how many times this workload has
	// already been migrated.
	filteredVolumes := make([]corev1.Volume, 0, len(spec.Volumes))
	for _, v := range spec.Volumes {
		if v.Name == holderVolumeName {
			continue
		}
		filteredVolumes = append(filteredVolumes, v)
	}
	spec.Volumes = filteredVolumes

	filteredInitContainers := make([]corev1.Container, 0, len(spec.InitContainers))
	for _, c := range spec.InitContainers {
		if c.Name == "podmotion-inject-holder" {
			continue
		}
		filteredInitContainers = append(filteredInitContainers, c)
	}
	spec.InitContainers = filteredInitContainers

	for i := range spec.Containers {
		filteredMounts := make([]corev1.VolumeMount, 0, len(spec.Containers[i].VolumeMounts))
		for _, m := range spec.Containers[i].VolumeMounts {
			if m.Name == holderVolumeName || m.MountPath == holderMountPath {
				continue
			}
			filteredMounts = append(filteredMounts, m)
		}
		spec.Containers[i].VolumeMounts = filteredMounts
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

	// ADR-0359: the controller no longer pins spec.NodeName to the destination node.
	// A NodeName-bound pod bypasses the scheduler and is picked up by kubelet directly via
	// its pod-watch, regardless of spec.SchedulingGates — so a direct NodeName assignment
	// here defeated the podmotion.io/awaiting-checkpoint gate (ADR-0046) the mutating webhook
	// injects, letting kubelet/CRIU-restore start before the checkpoint was staged. The
	// webhook's scheduling-gate injection plus the podmotion-scheduler custom scheduler
	// (MigrationAwareFilter/Score, ADR-0025) are now the sole, exclusive mechanism binding
	// the replacement pod to pm.Status.DestinationNodeName. destNodeName is still resolved
	// here (from status, falling back to spec) because it remains needed below for the
	// taint-toleration logic and is read by other reconcile call sites.
	destNodeName := pm.Status.DestinationNodeName
	if destNodeName == "" {
		destNodeName = pm.Spec.TargetNodeName
	}
	if destNodeName == "" {
		destNodeName = pm.Spec.DestinationNode
	}
	log := logf.FromContext(ctx)
	log.Info("createReplacementPod: resolved destination node (scheduling-gate + custom scheduler bind, no direct NodeName pin per ADR-0359)",
		"migration", pm.Name,
		"statusDestinationNodeName", pm.Status.DestinationNodeName,
		"specTargetNodeName", pm.Spec.TargetNodeName,
		"resolved", destNodeName,
		"sourcePodNode", sourcePod.Spec.NodeName)

	// ADR-0359 removal-symmetry: the NodeSelector/NodeAffinity clearing is
	// retained UNCONDITIONALLY, decoupled from the removed destNodeName-gated NodeName
	// assignment it was originally bundled with. This has independent justification: the
	// source pod may carry a nodeSelector/nodeAffinity pinning it to the source node (e.g.
	// nodeSelector: kubernetes.io/hostname=<source-node>), which would otherwise survive
	// into the replacement pod and make it Unschedulable at the destination — trading the
	// gate-bypass race this ADR fixes for a stuck-Pending regression instead. spec.NodeName
	// is no longer set here at all (zeroed explicitly above, right after the deep copy).
	spec.NodeSelector = nil
	if spec.Affinity != nil && spec.Affinity.NodeAffinity != nil {
		spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = nil
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

// ensureReplacementPodCreated is the single source-of-truth gate for "has the replacement pod been
// durably created for this migration." Brittle-chain fix: prior to this helper, the only
// callers of createReplacementPod gated on either the whole-function Checkpointing fast-path
// (which infers "replacement pod exists" from the unrelated fact "Checkpointed=True") or the
// cached pm.Status.ReplacementPodName == "" flag (which can silently desync from the cluster on a
// status-write race, transient error mid-createReplacementPod, or a controller restart between
// the Checkpointed persist and the createReplacementPod call). Both call sites now funnel through
// this one function so there is exactly one implementation of the question, and it is always
// re-answered from a live read rather than assumed from a sibling condition or a stale cache.
//
// It performs a live resolveReplacementPodByLabel lookup (a real List call against the API
// server) — the same authoritative primitive resolveAndValidateReplacementPlacement already
// treats as its own source of truth for this exact question — rather than trusting
// pm.Status.ReplacementPodName alone.
//
//   - If the live lookup finds the pod: self-heal pm.Status.ReplacementPodName if it drifted, and
//     report created=true. No pod is created.
//   - If the live lookup finds nothing: call the existing createReplacementPod (unchanged
//     internals; already idempotent via its deterministic name + IsAlreadyExists handling).
//
// Fail-closed guarantee: if the live lookup itself errors (e.g. a transient API-server hiccup), this fails
// closed — it returns an error and creates nothing, so the caller requeues and retries rather than
// advancing the phase on an unverified guess.
func (r *PodMigrationReconciler) ensureReplacementPodCreated(ctx context.Context, pm *pmv1.PodMigration, sourcePod *corev1.Pod) (bool, error) {
	log := logf.FromContext(ctx)

	replPod, err := r.resolveReplacementPodByLabel(ctx, pm)
	if err != nil {
		return false, fmt.Errorf("ensureReplacementPodCreated: live replacement-pod lookup failed: %w", err)
	}
	if replPod != nil {
		// Self-heal the cached name if it drifted (e.g. lost on a status-write race) so the rest
		// of the reconciler's other pm.Status.ReplacementPodName readers stay consistent with the
		// live cluster state this function just observed.
		if pm.Status.ReplacementPodName != replPod.Name {
			pm.Status.ReplacementPodName = replPod.Name
			if serr := r.statusUpdate(ctx, pm); serr != nil {
				return false, fmt.Errorf("ensureReplacementPodCreated: self-healing ReplacementPodName cache: %w", serr)
			}
			log.Info("ensureReplacementPodCreated: self-healed ReplacementPodName cache from live label lookup",
				"migration", pm.Name, "replacementPod", replPod.Name)
		}
		return true, nil
	}

	// No replacement pod exists yet by the live check — create it. createReplacementPod is
	// idempotent (deterministic name + IsAlreadyExists handling), so calling it again after a
	// prior partial failure (this migration's first attempt errored before or during creation) is
	// safe and is exactly the retry this fix exists to enable.
	if err := r.createReplacementPod(ctx, pm, sourcePod); err != nil {
		return false, fmt.Errorf("ensureReplacementPodCreated: createReplacementPod failed: %w", err)
	}
	log.Info("ensureReplacementPodCreated: created replacement pod",
		"migration", pm.Name, "replacementPod", pm.Status.ReplacementPodName)
	return true, nil
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

// preserveOperatorOwnedDurableStatus keeps the operator-owned DURABLE status fields immune to whole-status
// blob overwrites: the ADR-0398 StoragePreStageDispatch single-dispatch marker and the ADR-0393/0408
// SourcePodSpecSnapshot. Both fields are advanced ONLY via field-scoped, optimistic-lock patches (marker:
// ADR-0398 :1069/:1199/:1236; snapshot: ADR-0408 patchSourcePodSpecSnapshot/clearSourcePodSpecSnapshot),
// so a whole-status overwrite that installs a possibly-stale in-memory Status (which may predate the write)
// must NEVER regress either of them. Regressing the marker to nil would let the next reconcile re-claim and
// re-dispatch, defeating the exactly-once guarantee; regressing the snapshot to nil (or resurrecting a
// consumed one) is the ADR-0408 lost update that livelocks PreCopyMemory. server is the freshly-Get'd object
// holding the authoritative values; install is the Status about to be written.
// (§RESIDUAL: the general whole-status overwrite is a controller-wide latent hazard tracked as a separate
// follow-up; here we make these two operator-owned durable fields immune to it.)
func preserveOperatorOwnedDurableStatus(server *pmv1.PodMigration, install *pmv1.PodMigrationStatus) {
	install.StoragePreStageDispatch = server.Status.StoragePreStageDispatch
	install.SourcePodSpecSnapshot = server.Status.SourcePodSpecSnapshot
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
		server := fresh.DeepCopy()
		fresh.Status = *want
		preserveOperatorOwnedDurableStatus(server, &fresh.Status) // ADR-0398/0408: never blob-overwrite marker or snapshot
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
	if err := r.Patch(ctx, pod, patch); err != nil {
		// ADR-0359 condition: this gate removal is now the SOLE
		// load-bearing transition from "held out of the scheduling queue" to "schedulable"
		// for every migration — distinguish a failed patch from a routine reconcile error.
		logf.FromContext(ctx).Error(err, "removeSchedulingGate: failed to patch away scheduling gate",
			"migration", pm.Name, "pod", pod.Name, "gate", gate)
		return err
	}
	logf.FromContext(ctx).Info("removeSchedulingGate: scheduling gate removed, replacement pod now schedulable",
		"migration", pm.Name, "pod", pod.Name, "gate", gate)
	return nil
}

// schedulingGateAwaitingCheckpoint is the podmotion.io/awaiting-checkpoint PodSchedulingGate
// name injected by the mutating admission webhook (ADR-0046) and removed here once the
// checkpoint has been transferred to the destination node.
const schedulingGateAwaitingCheckpoint = "podmotion.io/awaiting-checkpoint"

// ensureReplacementPodBound (ADR-0360) is the single idempotent, re-entrant primitive that owns
// gate-removal AND its verification as one operation. It replaces the old pairing of
// removeSchedulingGate (whose nil return was, for three of its four paths, compatible with
// "we never looked at the real pod at all") plus a one-shot latch at the call site that treated
// that nil as proof.
//
// Behavior (ADR-0360 Decision §1):
//  1. Resolve the replacement pod via resolveReplacementPodByLabel — never pm.Status.ReplacementPodName
//     directly. Heal the status mirror inline if the label resolves a pod the mirror missed, the
//     same pattern already proven at reconcileTCPVerifying/reconcileRestoring.
//  2. If no pod resolves, return (nil, false, nil) — a legitimate not-yet-created state, distinct
//     from every other case below. Not an error.
//  3. If the live pod's Spec.SchedulingGates still contains the awaiting-checkpoint gate, patch it
//     off (same client.MergeFrom mechanics as the old removeSchedulingGate).
//  4. Regardless of whether step 3 patched anything THIS call, re-Get the pod fresh (not the
//     in-memory patched copy) and derive `bound` ONLY from that freshly observed object's
//     SchedulingGates. Never from "the patch call returned no error."
//  5. No internal one-shot latch — safe, and intended, to be called every reconcile of
//     reconcileTransferring; the caller no longer guards the call behind
//     conditionSchedulingGateRemoved.
func (r *PodMigrationReconciler) ensureReplacementPodBound(
	ctx context.Context, pm *pmv1.PodMigration,
) (pod *corev1.Pod, bound bool, err error) {
	log := logf.FromContext(ctx)

	resolved, resolveErr := r.resolveReplacementPodByLabel(ctx, pm)
	if resolveErr != nil {
		return nil, false, resolveErr
	}
	if resolved == nil {
		// Legitimate not-yet-created state — never treated as gate-removal success.
		return nil, false, nil
	}

	// Heal the status mirror so later phases that still read pm.Status.ReplacementPodName
	// resolve, mirroring reconcileTCPVerifying/reconcileRestoring's existing healing logic.
	if pm.Status.ReplacementPodName == "" {
		pm.Status.ReplacementPodName = resolved.Name
		if err := r.statusUpdate(ctx, pm); err != nil {
			log.Error(err, "ensureReplacementPodBound: failed to heal Status.ReplacementPodName — continuing",
				"migration", pm.Name, "replacementPod", resolved.Name)
		}
	}

	hasGate := false
	for _, g := range resolved.Spec.SchedulingGates {
		if g.Name == schedulingGateAwaitingCheckpoint {
			hasGate = true
			break
		}
	}
	if hasGate {
		patch := client.MergeFrom(resolved.DeepCopy())
		filtered := resolved.Spec.SchedulingGates[:0]
		for _, g := range resolved.Spec.SchedulingGates {
			if g.Name != schedulingGateAwaitingCheckpoint {
				filtered = append(filtered, g)
			}
		}
		resolved.Spec.SchedulingGates = filtered
		if err := r.Patch(ctx, resolved, patch); err != nil {
			log.Error(err, "ensureReplacementPodBound: failed to patch away scheduling gate",
				"migration", pm.Name, "pod", resolved.Name, "gate", schedulingGateAwaitingCheckpoint)
			return resolved, false, err
		}
		log.Info("ensureReplacementPodBound: patch-removed scheduling gate; verifying via fresh re-read",
			"migration", pm.Name, "pod", resolved.Name, "gate", schedulingGateAwaitingCheckpoint)
	}

	// The core fix: proof of "gate gone" is a fresh read of the real object, never the patch
	// call's return value (which today, and for three of its four early-return paths, means
	// nothing was ever verified against the live pod).
	fresh := &corev1.Pod{}
	getErr := r.Get(ctx, types.NamespacedName{Namespace: resolved.Namespace, Name: resolved.Name}, fresh)
	if getErr != nil {
		if apierrors.IsNotFound(getErr) {
			// The pod vanished between resolve and re-Get. Not proof of success — the caller
			// requeues and resolveReplacementPodByLabel is tried again next reconcile.
			return nil, false, nil
		}
		return resolved, false, getErr
	}

	for _, g := range fresh.Spec.SchedulingGates {
		if g.Name == schedulingGateAwaitingCheckpoint {
			// Gate still present on the freshly re-read object — not bound, whether or not a
			// patch was attempted this call.
			return fresh, false, nil
		}
	}
	return fresh, true, nil
}

// maxSameNodeRecoveryDeletes bounds the real, apiserver-legal recovery loop for a replacement pod
// the (migration-unaware) default scheduler bound onto the SOURCE node on the degraded
// scheduler.enabled=false substrate. A bound pod's spec.nodeName is IMMUTABLE — the apiserver
// rejects any in-place rebind — so the ONLY corrective action that actually reschedules is to
// DELETE the replacement pod and let the scheduler place a fresh one. Each attempt is one such
// delete+recreate. After this many deletes have all still landed the pod on the source node, the
// migration fails closed to RollingBack (source pod never deleted — ADR-0012; the replacement pod
// is torn down by the rollback path) rather than looping forever. 3 mirrors this file's other
// bounded retry budgets (cni0/IP-reclaim cleanup) and gives the default scheduler's
// BalancedAllocation/topology-spread scoring several independent chances — with the source pod still
// consuming the source node's resources each time — without unbounded pod churn.
const maxSameNodeRecoveryDeletes = 3

// replacementPlacementAction is what a caller of resolveAndValidateReplacementPlacement must do with
// the freshly-computed decision.
type replacementPlacementAction int

const (
	// replacementPlacementProceed: placement is valid (a present, Ready node distinct from the
	// source). The caller continues its phase; decision.DestNode is the validated destination and
	// Status.DestinationNodeName has been refreshed to it as an observability cache.
	replacementPlacementProceed replacementPlacementAction = iota
	// replacementPlacementRequeue: nothing is wrong that time won't fix (pod not yet bound), OR a
	// corrective delete/recreate was just issued. The caller requeues after decision.RequeueAfter.
	replacementPlacementRequeue
	// replacementPlacementTerminal: the replacement pod could not be placed off the source node
	// within the bound (or a still-gated pod is pinned to the source node with no legal reschedule).
	// The caller must fail the migration closed (rollback); decision.TerminalReason explains why.
	replacementPlacementTerminal
)

// replacementPlacementDecision is the single authoritative answer resolveAndValidateReplacementPlacement
// returns.
type replacementPlacementDecision struct {
	// Pod is the live replacement pod, or nil if none resolves yet.
	Pod *corev1.Pod
	// PodBound reports whether DestNode was taken from the live pod's own spec.nodeName (true) or
	// fell back to the declared destination for a still-gated/unbound pod (false).
	PodBound bool
	// DestNode is the validated destination node the caller should proceed with — the replacement
	// pod's ACTUAL binding when it is bound, else the declared destination (Status/spec) for a pod
	// still held by its scheduling gate. "" == not determinable yet.
	DestNode string
	// Valid is true only when Action == replacementPlacementProceed.
	Valid          bool
	Action         replacementPlacementAction
	RequeueAfter   time.Duration
	TerminalReason string
}

// destinationDistinctFromSource is the SINGLE definition of the load-bearing half of placement
// validity: a candidate destination node must be non-empty and different from the source node. A
// same-node destination is a degenerate non-migration (source and destination agents are the same
// process; the checkpoint would be "transferred" to the node it already lives on and nothing would
// move) and must never be persisted into Status.DestinationNodeName by ANY producer. sourceNode==""
// means the source node is not yet known — we cannot prove sameness, so we allow the candidate; the
// authoritative live-pod gate (resolveAndValidateReplacementPlacement in correct mode) re-checks
// against the real source before any transfer proceeds.
func destinationDistinctFromSource(candidate, sourceNode string) bool {
	return candidate != "" && candidate != sourceNode
}

// cacheDestinationNodeFromSpec seeds Status.DestinationNodeName — an observability CACHE, never the
// authority for placement validity — from a declared candidate node, but ONLY when the cache is
// still empty and the candidate is distinct from the source node. It mutates pm in memory and
// returns whether it assigned; the caller persists as part of its existing status write. Every
// pre-pod spec→status producer funnels through this one choke point so none can latch a same-node
// destination (the same-node wedge case: a second/third producer bypassing the same-node guard). The
// authoritative decision for an already-bound pod is resolveAndValidateReplacementPlacement, which
// re-reads the live pod and never trusts this cache.
func cacheDestinationNodeFromSpec(pm *pmv1.PodMigration, candidate, sourceNode string) bool {
	if pm.Status.DestinationNodeName != "" {
		return false
	}
	if !destinationDistinctFromSource(candidate, sourceNode) {
		return false
	}
	pm.Status.DestinationNodeName = candidate
	return true
}

// resolveEarlyDestinationNode implements ADR-0365 Decision §1: for an unpinned migration whose
// Status.DestinationNodeName is still empty, invoke the scheduler-plugin's MigrationAwareFilter/
// MigrationAwareScore decision logic — extracted into the framework-agnostic internal/placement
// package (ADR-0365 packaging resolution) so it is importable here without pulling any
// scheduler-framework dependency into the operator binary — directly against the live node list,
// the same way the real scheduler's node-iteration loop would, without submitting anything
// through Kubernetes (ADR-0365).
//
// Candidate nodes are evaluated with an unlabeled probe pod (no podmotion.io/migration-name
// label) so Filter/Score exercise their standard NMC-readiness/scoring path rather than the
// migration-label fast path — there is no replacement pod yet at this point in the pipeline.
//
// The winner (highest Score among nodes that pass Filter, ties broken lexicographically by node
// name for reproducibility) is written to Status.DestinationNodeName through
// cacheDestinationNodeFromSpec — the same assign-once, same-node-guarded choke point every other
// spec→status producer in this file uses (the same-node wedge choke point), so this cannot become a second,
// racing producer.
//
// Returns ("", non-nil error) when every candidate node was rejected (e.g. no capacity anywhere)
// — fail closed, never guess a destination. Callers must not advance the migration on error.
func (r *PodMigrationReconciler) resolveEarlyDestinationNode(ctx context.Context, pm *pmv1.PodMigration) (string, error) {
	log := logf.FromContext(ctx)

	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes); err != nil {
		return "", fmt.Errorf("ADR-0365 resolveEarlyDestinationNode: listing candidate nodes: %w", err)
	}

	var sourceNodeLabels map[string]string
	if pm.Status.SourceNodeName != "" {
		srcNode := &corev1.Node{}
		if err := r.Get(ctx, types.NamespacedName{Name: pm.Status.SourceNodeName}, srcNode); err != nil {
			log.Info("resolveEarlyDestinationNode: could not read source node for locality scoring — continuing without locality context",
				"migration", pm.Name, "sourceNode", pm.Status.SourceNodeName, "err", err)
		} else {
			sourceNodeLabels = srcNode.Labels
		}
	}

	filterPlugin := placement.NewMigrationAwareFilter(r.Client, r.Scheme)
	scorePlugin := placement.NewMigrationAwareScore(r.Client, placement.DefaultWeights)
	// No MigrationCheckpoint/RSS exists yet at Validating time — 0 is the already-defined,
	// non-penalizing degenerate scoreMemoryHeadroom uses (mirrors the scheduler adapter's own
	// PreScore behavior for a not-yet-checkpointed migration).
	scorePlugin.SetSourceContext(sourceNodeLabels, 0)

	// Unlabeled probe pod: exercises Filter/Score's standard NMC-readiness path, never the
	// migration-label fast path (podmotion.io/migration-name is intentionally absent — no
	// replacement pod exists yet).
	probePod := &corev1.Pod{}

	type candidate struct {
		name         string
		score        int64
		controlPlane bool
	}
	var winners []candidate
	var rejected []string
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if node.Name == pm.Status.SourceNodeName {
			continue
		}
		result := filterPlugin.Filter(ctx, probePod, node)
		if !result.Allowed {
			rejected = append(rejected, fmt.Sprintf("%s: %s", node.Name, result.Reason))
			continue
		}
		score, scoreErr := scorePlugin.Score(ctx, probePod, node)
		if scoreErr != nil {
			rejected = append(rejected, fmt.Sprintf("%s: score error: %v", node.Name, scoreErr))
			continue
		}
		winners = append(winners, candidate{name: node.Name, score: score, controlPlane: placement.IsControlPlaneNode(node)})
	}

	if len(winners) == 0 {
		return "", fmt.Errorf("no eligible destination node found among %d candidate node(s): %s",
			len(nodes.Items), strings.Join(rejected, "; "))
	}

	// Ordering, most-preferred first:
	//   1. Worker nodes rank strictly above control-plane nodes. The unpinned early
	//      decision (ADR-0365) must not send migration workloads to the control plane
	//      when any worker is eligible — the scoring dimensions (locality/thermal/load/
	//      headroom) don't distinguish role, and the lexicographic tie-break below would
	//      otherwise systematically favor a control-plane node named e.g. "pm-cp1" over a
	//      worker "pm-w2". A control-plane node is still selectable, but only as a last
	//      resort when no worker qualifies (mirrors createReplacementPod's force-toleration
	//      of the control-plane taint, which exists precisely to support that fallback and
	//      the operator-pinned Spec.TargetNodeName case).
	//   2. Higher Score wins.
	//   3. Lexicographic node name — deterministic tie-break (ADR-0365 packaging resolution).
	sort.Slice(winners, func(i, j int) bool {
		if winners[i].controlPlane != winners[j].controlPlane {
			return !winners[i].controlPlane // non-control-plane sorts first
		}
		if winners[i].score != winners[j].score {
			return winners[i].score > winners[j].score
		}
		return winners[i].name < winners[j].name
	})

	winnerNode := winners[0].name
	cacheDestinationNodeFromSpec(pm, winnerNode, pm.Status.SourceNodeName)
	log.Info("resolveEarlyDestinationNode: resolved early destination (ADR-0365)",
		"migration", pm.Name, "node", winnerNode, "score", winners[0].score,
		"controlPlaneFallback", winners[0].controlPlane,
		"candidates", len(nodes.Items), "rejected", len(rejected))
	return winnerNode, nil
}

// destinationNodeStale reports whether nodeName has become an invalid migration destination
// since it was chosen — NotReady-per-NMC, over its MaxConcurrentMigrationsDestination capacity,
// missing entirely, or newly labeled migration.podmotion.io/draining=true (ADR-0365 Condition 1 /
// placement.LabelDraining). reservedByUs indicates whether THIS migration's own capacity
// reservation (reserveDestinationCapacity, reconcilePreMigrating) is already counted in the NMC's
// ActiveDestinationMigrations — when it is, the migration's own slot must not be double-counted
// as "over capacity", so only a strict excess (active > max) is stale; when no reservation was
// ever made for this migration, active >= max means there is no room left for it.
func (r *PodMigrationReconciler) destinationNodeStale(ctx context.Context, nodeName string, reservedByUs bool) (bool, string) {
	node := &corev1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
		return true, fmt.Sprintf("node %s unreadable: %v", nodeName, err)
	}
	if node.Labels[placement.LabelDraining] == "true" {
		return true, fmt.Sprintf("node %s is now labeled %s=true", nodeName, placement.LabelDraining)
	}
	nmc, err := r.getNMC(ctx, nodeName)
	if err != nil {
		return true, fmt.Sprintf("NodeMigrationCapacity for %s unreadable: %v", nodeName, err)
	}
	if !nmc.Status.Ready {
		return true, fmt.Sprintf("node %s NodeMigrationCapacity.status.ready=false", nodeName)
	}
	active := nmc.Status.ActiveDestinationMigrations
	max := nmc.Spec.MaxConcurrentMigrationsDestination
	if reservedByUs {
		if active > max {
			return true, fmt.Sprintf("node %s destination capacity over-committed (%d/%d)", nodeName, active, max)
		}
	} else if active >= max {
		return true, fmt.Sprintf("node %s has no destination capacity (%d/%d)", nodeName, active, max)
	}
	return false, ""
}

// revalidateDestinationBeforeReplacementPod implements ADR-0365 Condition 1 (Arch-A, load-bearing):
// the early destination decision (resolveEarlyDestinationNode, run once in reconcileValidating) is
// otherwise trusted, unverified, all the way through PreCopyMemory's storage pre-stage and into
// actual replacement-pod creation in the freeze/transfer phases — a real time gap during which the
// chosen node could go NotReady-per-NMC, exceed MaxConcurrentMigrationsDestination, or get newly
// drain-labeled. This performs a bounded re-validation at the point closest to actual
// replacement-pod creation (reconcileCheckpointing, immediately before ensureReplacementPodCreated
// commits to the node) and fails closed on staleness — it never force-binds to a now-invalid node.
//
//   - Unpinned migration: release the stale decision (and any capacity reservation held for it),
//     clear Status.DestinationNodeName, and re-run resolveEarlyDestinationNode against fresh live
//     state. A fresh valid node is written the same way the first decision was; requeues so the
//     caller re-enters with the new (or still-missing, on failure) destination rather than
//     creating the replacement pod against stale data in this same call.
//   - Pinned migration (Spec.TargetNodeName / Spec.DestinationNode set): the controller must not
//     silently pick a different node than the operator pinned. Fail the phase and roll back, per
//     the existing invariant-#8/ADR-0012 pattern already used elsewhere in this controller (source
//     pod is never deleted before TrafficVerified=True; RollingBack tears down only the
//     replacement side).
//
// Returns proceed=true when the caller should continue with pod creation unchanged (destination
// still valid, or nothing to validate — no destination resolved at all, which is a separate,
// pre-existing empty-guard concern this function is not responsible for).
func (r *PodMigrationReconciler) revalidateDestinationBeforeReplacementPod(ctx context.Context, pm *pmv1.PodMigration) (res ctrl.Result, proceed bool, err error) {
	log := logf.FromContext(ctx)

	destNode := pm.Status.DestinationNodeName
	if destNode == "" {
		destNode = pm.Spec.TargetNodeName
	}
	if destNode == "" {
		destNode = pm.Spec.DestinationNode
	}
	if destNode == "" || destNode == pm.Status.SourceNodeName {
		// Nothing resolved yet, or a degenerate same-node value cacheDestinationNodeFromSpec
		// would already have refused — not this gate's concern.
		return ctrl.Result{}, true, nil
	}

	reservedByUs := meta.IsStatusConditionTrue(pm.Status.Conditions, conditionCapacityReserved)
	stale, reason := r.destinationNodeStale(ctx, destNode, reservedByUs)
	if !stale {
		return ctrl.Result{}, true, nil
	}

	log.Error(nil, "ADR-0365 Condition 1: destination node went stale between early decision and replacement-pod creation — failing closed",
		"migration", pm.Name, "node", destNode, "reason", reason)

	unpinned := pm.Spec.TargetNodeName == "" && pm.Spec.DestinationNode == ""
	if unpinned {
		r.releaseDestinationCapacity(ctx, pm)
		pm.Status.DestinationNodeName = ""
		meta.RemoveStatusCondition(&pm.Status.Conditions, conditionCapacityReserved)

		newNode, resolveErr := r.resolveEarlyDestinationNode(ctx, pm)
		if resolveErr != nil || newNode == "" {
			setCondition(pm, conditionDestinationResolvable, metav1.ConditionFalse,
				"StaleDestinationNoReplacement",
				fmt.Sprintf("destination node %s became invalid (%s) and no alternate destination could be resolved: %v",
					destNode, reason, resolveErr))
			if statusErr := r.statusUpdate(ctx, pm); statusErr != nil {
				return ctrl.Result{}, false, statusErr
			}
			return ctrl.Result{RequeueAfter: 10 * time.Second}, false, nil
		}

		setCondition(pm, conditionDestinationResolvable, metav1.ConditionTrue, "RedecidedAfterStaleness",
			fmt.Sprintf("original destination %s went stale (%s) before replacement-pod creation; re-resolved to %s",
				destNode, reason, newNode))
		if statusErr := r.statusUpdate(ctx, pm); statusErr != nil {
			return ctrl.Result{}, false, statusErr
		}
		if r.Recorder != nil {
			r.Recorder.Eventf(pm, corev1.EventTypeWarning, "DestinationRedecided",
				"destination %s went stale (%s); re-resolved to %s", destNode, reason, newNode)
		}
		return ctrl.Result{RequeueAfter: 3 * time.Second}, false, nil
	}

	// Pinned migration: cannot silently pick another node on the operator's behalf. Fail closed
	// via the existing invariant-#8/ADR-0012 rollback pattern rather than force-binding.
	rbRes, rbErr := r.initiateRollback(ctx, pm,
		fmt.Sprintf("pinned destination node %s became invalid before replacement-pod creation (ADR-0365 Condition 1): %s",
			destNode, reason))
	return rbRes, false, rbErr
}

// readSameNodeRecoveryAttempts returns the current same-node recovery (delete-and-reschedule)
// attempt count stamped on pm by sameNodeRecoveryAttemptsAnnotation, or 0 if absent/unparseable,
// mirroring readCni0CleanupVerifyAttempts / readIPReclaimVerifyAttempts.
func readSameNodeRecoveryAttempts(pm *pmv1.PodMigration) int {
	if pm.Annotations == nil {
		return 0
	}
	v, ok := pm.Annotations[sameNodeRecoveryAttemptsAnnotation]
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// nodeIsPresentAndReady reports whether the named Node exists and has NodeReady=True. When the Node
// object cannot be read (transient get error / RBAC), it returns present=false so the caller does
// NOT treat an unreadable Node as a hard placement failure — the load-bearing safety property is
// "distinct from source" (established separately), and blocking on a transient Node-get blip would
// trade a corrected placement for a needless hold.
func (r *PodMigrationReconciler) nodeIsPresentAndReady(ctx context.Context, nodeName string) (present bool, ready bool) {
	if nodeName == "" {
		return false, false
	}
	node := &corev1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
		return false, false
	}
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return true, c.Status == corev1.ConditionTrue
		}
	}
	// Node exists but reports no Ready condition yet (just registered) — present, not-yet-ready.
	return true, false
}

// replacementPodGated reports whether the replacement pod still carries the awaiting-checkpoint
// scheduling gate. A gated pod is held OUT of the scheduling queue entirely (real substrate: the
// webhook injects the gate and the podmotion-scheduler binds it only after the gate is lifted at the
// end of reconcileTransferring), so it will NOT self-bind to a distinct node on its own. That
// distinguishes "a source-pinned destination that a reschedule can never fix" (gated → terminal)
// from "an ungated pod that has simply not been bound yet" (wait).
func replacementPodGated(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for _, g := range pod.Spec.SchedulingGates {
		if g.Name == schedulingGateAwaitingCheckpoint {
			return true
		}
	}
	return false
}

// resolveAndValidateReplacementPlacement is THE single source of truth for the question
// "is the current replacement-pod placement valid, and if not, what corrective action fires?"
// Both historical producers of Status.DestinationNodeName — the top-level Reconcile normalize block
// and the reconcileTransferring backfill branch — now route through it, so exactly one place in the
// codebase decides valid-vs-needs-correcting, and a future producer cannot reintroduce the same-node
// latch bug class.
//
// On EVERY call it re-reads the LIVE replacement pod via resolveReplacementPodByLabel and, when that
// pod is actually bound, computes validity FRESHLY from its spec.nodeName — it NEVER trusts a
// persisted/latched Status.DestinationNodeName as the source of truth for placement (that field is
// only an observability cache of the last known-good node). A bound pod's real node is authoritative;
// only when the pod is still held by its scheduling gate (real substrate, unbound during the
// transfer) does it fall back to the declared destination (Status → spec) so that flow is preserved.
// Validity == bound to a node that is present, Ready, and != sourceNode.
//
// correctInvalid selects the two call modes:
//   - false (normalize/seed path, top of every reconcile, all phases): validate/cache only. With no
//     live pod it seeds Status.DestinationNodeName from the declared spec target via
//     cacheDestinationNodeFromSpec (refusing a same-node target). It NEVER deletes a pod and never
//     returns a terminal action.
//   - true (reconcileTransferring): additionally performs REAL, bounded recovery. A pod bound to the
//     source node is DELETED (grace 0 — replacement pods carry no finalizer, so the apiserver removes
//     it promptly; a delete is always legal, unlike an apiserver-rejected spec.nodeName mutation) so
//     the scheduler gets a fresh placement attempt, and a fresh pod is recreated on the following
//     pass once the old one is gone. This is BOUNDED by maxSameNodeRecoveryDeletes, after which the
//     migration is failed closed to rollback rather than looping forever.
//
// ADR-0012: the pod deleted here is ALWAYS the REPLACEMENT pod (label
// replacementPodMigrationNameLabel == pm.Name, ownerRef == the PodMigration CR). The SOURCE pod is
// never touched by this primitive and is never deleted before TrafficVerified=True — deleting the
// replacement pod for reschedule is unrelated to source-pod teardown.
func (r *PodMigrationReconciler) resolveAndValidateReplacementPlacement(
	ctx context.Context, pm *pmv1.PodMigration, sourceNode string, correctInvalid bool,
) (replacementPlacementDecision, error) {
	log := logf.FromContext(ctx)

	replPod, err := r.resolveReplacementPodByLabel(ctx, pm)
	if err != nil {
		return replacementPlacementDecision{Action: replacementPlacementRequeue, RequeueAfter: 3 * time.Second}, err
	}

	// Recovery recreate: we DELETED a same-node replacement pod on an earlier pass and it is now
	// gone. Recreate a fresh one (deterministic name, idempotent) so the scheduler makes its next
	// placement attempt. The source pod still exists (ADR-0012), so we can clone from it. Only in
	// correct mode; the seed path never recreates.
	if replPod == nil && correctInvalid && readSameNodeRecoveryAttempts(pm) > 0 {
		sourcePod, getErr := r.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
		if getErr != nil {
			log.Error(getErr, "resolveAndValidateReplacementPlacement: source pod unreadable during same-node recovery recreate — requeuing",
				"migration", pm.Name)
			return replacementPlacementDecision{Action: replacementPlacementRequeue, RequeueAfter: 3 * time.Second}, nil
		}
		if createErr := r.createReplacementPod(ctx, pm, sourcePod); createErr != nil {
			log.Error(createErr, "resolveAndValidateReplacementPlacement: recreate after same-node delete failed — requeuing",
				"migration", pm.Name)
			return replacementPlacementDecision{Action: replacementPlacementRequeue, RequeueAfter: 3 * time.Second}, nil
		}
		log.Info("resolveAndValidateReplacementPlacement: recreated replacement pod after same-node delete; awaiting fresh scheduler placement",
			"migration", pm.Name, "recoveryAttempt", readSameNodeRecoveryAttempts(pm))
		return replacementPlacementDecision{Action: replacementPlacementRequeue, RequeueAfter: 5 * time.Second}, nil
	}

	// Our prior corrective delete is not yet reaped. Wait; do NOT re-evaluate placement against a
	// terminating pod, and do not burn the recovery budget on it.
	if replPod != nil && !replPod.DeletionTimestamp.IsZero() {
		return replacementPlacementDecision{Pod: replPod, Action: replacementPlacementRequeue, RequeueAfter: 3 * time.Second}, nil
	}

	// Determine the effective destination and whether it came from the pod's ACTUAL binding.
	podBound := replPod != nil && replPod.Spec.NodeName != ""
	var effectiveNode string
	if podBound {
		// Authority: the pod's real binding (degraded substrate — pod is ungated and bound early).
		effectiveNode = replPod.Spec.NodeName
	} else {
		// Pod still gated (real substrate) or not yet created: the declared destination is the only
		// signal for where it is headed. Never trusted for VALIDITY of a bound pod — only used here
		// because there is no binding to read yet.
		effectiveNode = pm.Status.DestinationNodeName
		if effectiveNode == "" {
			effectiveNode = pm.Spec.TargetNodeName
		}
		if effectiveNode == "" {
			effectiveNode = pm.Spec.DestinationNode
		}
	}

	// SEED MODE (top-of-reconcile, all phases): behave like the historical normalize producer — cache
	// the declared spec target into the Status.DestinationNodeName observability cache ONLY when it is
	// still empty AND the target is valid (distinct from source). It writes at most once (only when it
	// actually seeds a new value), sets NO validity condition, deletes nothing, and never fails the
	// migration — so it does not perturb the finalizer-add / phase-handler writes that follow in the
	// same reconcile. Refusing to seed a same-node target is the finding-#2 fix: an empty cache cannot
	// latch the wedge. The authoritative valid-vs-needs-correcting decision (and all recovery) is the
	// correct-mode call in reconcileTransferring.
	if !correctInvalid {
		if !podBound {
			candidate := pm.Spec.TargetNodeName
			if candidate == "" {
				candidate = pm.Spec.DestinationNode
			}
			if cacheDestinationNodeFromSpec(pm, candidate, sourceNode) {
				if serr := r.statusUpdate(ctx, pm); serr != nil {
					return replacementPlacementDecision{Action: replacementPlacementRequeue, RequeueAfter: 2 * time.Second}, serr
				}
				effectiveNode = pm.Status.DestinationNodeName
			}
		}
		return replacementPlacementDecision{Pod: replPod, PodBound: podBound, DestNode: effectiveNode, Action: replacementPlacementProceed}, nil
	}

	// ---- Correct mode below (reconcileTransferring): validate the live placement and, if it is the
	// degenerate same-node case, perform bounded real recovery. ----
	if effectiveNode == "" {
		// Nothing known yet — wait for the scheduler to bind the pod (degraded) or a producer to set
		// the destination (real). Not an error.
		return replacementPlacementDecision{Pod: replPod, DestNode: "", Action: replacementPlacementRequeue, RequeueAfter: 3 * time.Second}, nil
	}

	if effectiveNode == sourceNode {
		return r.correctSameNodePlacement(ctx, pm, replPod, sourceNode, correctInvalid, podBound)
	}

	// ---- effectiveNode is distinct from the source node. ----
	// For a bound pod, additionally confirm the node is present + Ready (a NotReady destination is a
	// transient hold, not a same-node corrective case — a delete would not help). Fail-open when the
	// Node object is unreadable: != source is the load-bearing invariant, already satisfied here.
	if podBound {
		if present, ready := r.nodeIsPresentAndReady(ctx, effectiveNode); present && !ready {
			setCondition(pm, conditionDestinationPlacementValid, metav1.ConditionFalse, "DestinationNodeNotReady",
				fmt.Sprintf("replacement pod bound to node %q which is present but not Ready — holding until it recovers", effectiveNode))
			if serr := r.statusUpdate(ctx, pm); serr != nil {
				return replacementPlacementDecision{Pod: replPod, PodBound: podBound, DestNode: effectiveNode}, serr
			}
			return replacementPlacementDecision{Pod: replPod, PodBound: podBound, DestNode: effectiveNode, Action: replacementPlacementRequeue, RequeueAfter: 5 * time.Second}, nil
		}
	}

	// ---- Valid placement. Refresh the Status.DestinationNodeName cache, clear any veto, and clear
	// the recovery attempt counter. ----
	if attempts := readSameNodeRecoveryAttempts(pm); attempts != 0 {
		delete(pm.Annotations, sameNodeRecoveryAttemptsAnnotation)
		if uerr := r.Update(ctx, pm); uerr != nil {
			return replacementPlacementDecision{Pod: replPod, PodBound: podBound, DestNode: effectiveNode, Valid: true}, uerr
		}
	}
	statusDirty := false
	if pm.Status.DestinationNodeName != effectiveNode {
		pm.Status.DestinationNodeName = effectiveNode
		statusDirty = true
	}
	if !meta.IsStatusConditionTrue(pm.Status.Conditions, conditionDestinationPlacementValid) {
		setCondition(pm, conditionDestinationPlacementValid, metav1.ConditionTrue, "DistinctNodePlacement",
			fmt.Sprintf("destination node %q is distinct from source node %q", effectiveNode, sourceNode))
		statusDirty = true
	}
	if statusDirty {
		if serr := r.statusUpdate(ctx, pm); serr != nil {
			return replacementPlacementDecision{Pod: replPod, PodBound: podBound, DestNode: effectiveNode, Valid: true}, serr
		}
	}
	return replacementPlacementDecision{Pod: replPod, PodBound: podBound, DestNode: effectiveNode, Valid: true, Action: replacementPlacementProceed}, nil
}

// correctSameNodePlacement is the corrective half of resolveAndValidateReplacementPlacement, reached
// only when the effective destination equals the source node. It is the ONLY place that DELETES a
// replacement pod for placement recovery.
//
//   - Detect-only (correctInvalid=false, the seed caller): record the veto and ask the caller to
//     requeue. Never deletes; the authoritative gate in reconcileTransferring performs recovery.
//   - Correct + pod bound to the source node (correctInvalid=true, podBound=true): perform the
//     bounded, apiserver-legal recovery — DELETE the replacement pod so a fresh one can be scheduled
//     elsewhere, bumping the attempt counter; once maxSameNodeRecoveryDeletes deletes have all still
//     landed on the source node, return terminal so the caller fails closed to rollback.
//   - Correct + pod NOT bound but still gated to a source-pinned destination (podBound=false, gated):
//     no reschedule can fix a statically source-pinned destination on a gated pod — return terminal.
//   - Correct + pod not bound and ungated: the ungated pod may still bind to a distinct node — wait.
func (r *PodMigrationReconciler) correctSameNodePlacement(
	ctx context.Context, pm *pmv1.PodMigration, replPod *corev1.Pod, sourceNode string, correctInvalid, podBound bool,
) (replacementPlacementDecision, error) {
	log := logf.FromContext(ctx)

	podName := ""
	if replPod != nil {
		podName = replPod.Name
	}
	// The SameNodePlacement veto is set per-branch, always AFTER any metadata r.Update below: on the
	// status-subresource client an Update rewrites the in-memory status from the store, so setting the
	// condition before it would silently discard the veto.
	sameNodeMsg := fmt.Sprintf("replacement pod %q would be placed on the source node %q (no migration-aware scheduler on this substrate) — a same-node transfer moves nothing", podName, sourceNode)

	if !correctInvalid {
		// Detect-only: never delete; the top-level seed caller only records the veto.
		setCondition(pm, conditionDestinationPlacementValid, metav1.ConditionFalse, "SameNodePlacement", sameNodeMsg)
		if serr := r.statusUpdate(ctx, pm); serr != nil {
			return replacementPlacementDecision{Pod: replPod, DestNode: sourceNode}, serr
		}
		return replacementPlacementDecision{Pod: replPod, PodBound: podBound, DestNode: sourceNode, Valid: false, Action: replacementPlacementRequeue, RequeueAfter: 5 * time.Second}, nil
	}

	// ---- Correct mode. ----
	if !podBound {
		if replacementPodGated(replPod) {
			// A gated pod is held out of the scheduling queue and will not self-bind to a distinct
			// node; a source-pinned destination it cannot escape is unrecoverable by rescheduling.
			reason := fmt.Sprintf("declared destination equals the source node %q for a scheduling-gated replacement pod — no apiserver-legal reschedule can correct a statically source-pinned destination; failing closed to rollback (source never deleted — ADR-0012)", sourceNode)
			setCondition(pm, conditionDestinationPlacementValid, metav1.ConditionFalse, "SameNodePlacementUnrecoverable", reason)
			if serr := r.statusUpdate(ctx, pm); serr != nil {
				return replacementPlacementDecision{Pod: replPod, DestNode: sourceNode}, serr
			}
			log.Error(nil, "resolveAndValidateReplacementPlacement: gated replacement pod pinned to the source node — rolling back",
				"migration", pm.Name, "sourceNode", sourceNode)
			return replacementPlacementDecision{Pod: replPod, DestNode: sourceNode, Valid: false, Action: replacementPlacementTerminal, TerminalReason: reason}, nil
		}
		// Ungated and not yet bound — the default scheduler may still place it on a distinct node.
		// Wait for the binding to be revealed rather than acting on a declared value.
		setCondition(pm, conditionDestinationPlacementValid, metav1.ConditionFalse, "SameNodePlacement", sameNodeMsg)
		if serr := r.statusUpdate(ctx, pm); serr != nil {
			return replacementPlacementDecision{Pod: replPod, DestNode: sourceNode}, serr
		}
		return replacementPlacementDecision{Pod: replPod, DestNode: sourceNode, Valid: false, Action: replacementPlacementRequeue, RequeueAfter: 3 * time.Second}, nil
	}

	// Pod is actually bound to the source node: real, bounded delete-and-reschedule recovery.
	attempts := readSameNodeRecoveryAttempts(pm)
	if attempts >= maxSameNodeRecoveryDeletes {
		reason := fmt.Sprintf("replacement pod could not be scheduled off the source node %q after %d delete-and-reschedule attempts — failing closed to rollback rather than performing a degenerate same-node migration (source pod never deleted — ADR-0012)",
			sourceNode, maxSameNodeRecoveryDeletes)
		setCondition(pm, conditionDestinationPlacementValid, metav1.ConditionFalse, "SameNodePlacementUnrecoverable", reason)
		if serr := r.statusUpdate(ctx, pm); serr != nil {
			return replacementPlacementDecision{Pod: replPod, DestNode: sourceNode}, serr
		}
		log.Error(nil, "resolveAndValidateReplacementPlacement: same-node placement unrecoverable after bounded retries — rolling back",
			"migration", pm.Name, "sourceNode", sourceNode, "attempts", attempts, "maxAttempts", maxSameNodeRecoveryDeletes)
		return replacementPlacementDecision{Pod: replPod, PodBound: true, DestNode: sourceNode, Valid: false, Action: replacementPlacementTerminal, TerminalReason: reason}, nil
	}

	// Under budget: bump the attempt counter (metadata, r.Update) FIRST so the delete is always
	// accounted for; the veto condition is then set and persisted (status) AFTER it, because an
	// r.Update on the status-subresource client rewrites the in-memory status from the store and would
	// otherwise discard a veto set before it.
	if pm.Annotations == nil {
		pm.Annotations = make(map[string]string)
	}
	pm.Annotations[sameNodeRecoveryAttemptsAnnotation] = strconv.Itoa(attempts + 1)
	if uerr := r.Update(ctx, pm); uerr != nil {
		return replacementPlacementDecision{Pod: replPod, DestNode: sourceNode}, uerr
	}
	setCondition(pm, conditionDestinationPlacementValid, metav1.ConditionFalse, "SameNodePlacement", sameNodeMsg)
	if serr := r.statusUpdate(ctx, pm); serr != nil {
		return replacementPlacementDecision{Pod: replPod, DestNode: sourceNode}, serr
	}
	// Delete the REPLACEMENT pod (never the source — ADR-0012). Grace 0: replacement pods carry no
	// finalizer, so the apiserver removes it promptly and the next pass recreates a fresh one.
	if derr := r.Delete(ctx, replPod, client.GracePeriodSeconds(0)); derr != nil && !apierrors.IsNotFound(derr) {
		log.Error(derr, "resolveAndValidateReplacementPlacement: failed to delete same-node replacement pod — will retry",
			"migration", pm.Name, "pod", replPod.Name)
		return replacementPlacementDecision{Pod: replPod, DestNode: sourceNode, Action: replacementPlacementRequeue, RequeueAfter: 3 * time.Second}, nil
	}
	log.Info("resolveAndValidateReplacementPlacement: deleted same-node replacement pod for reschedule (real recovery, apiserver-legal delete)",
		"migration", pm.Name, "pod", replPod.Name, "sourceNode", sourceNode, "attempt", attempts+1, "maxAttempts", maxSameNodeRecoveryDeletes)
	return replacementPlacementDecision{Pod: replPod, PodBound: true, DestNode: sourceNode, Valid: false, Action: replacementPlacementRequeue, RequeueAfter: 5 * time.Second}, nil
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

// verifyRestoredSecurityContext is intended to assert the restored process's capabilities
// (CapEff/CapPrm/CapInh/CapBnd), seccomp mode, and AppArmor label match what was captured on
// the source at checkpoint time.
//
// fail-closed phase-gate (item 2): the prior stub was `return nil` unconditionally — a hard no-op that let
// conditionSecurityContextVerified go True on NOTHING, not even a degraded check. No code
// anywhere in this codebase captures the source process's Cap*/seccomp/AppArmor state at
// checkpoint time, and no RPC surface exists to read the restored process's real /proc state on
// the destination — the two capture points a real comparison needs (a source-side CRIU
// creds-<pid>.img decode + a destination-side /proc/<pid>/status + /proc/<pid>/attr/current
// read, both immediately available via primitives already proven elsewhere in this codebase —
// see docs/adr remediation design, item 2) do not exist yet. Wiring those is a materially larger
// change (new fields on the Checkpoint/Restore RPC surface and PodMigration.Status, touching
// both agents) than the other six items in this remediation and is intentionally NOT bundled
// into this fix, per the explicit scope note in the accompanying design doc.
//
// Per that design's own interim-compliant fallback: until the two capture RPCs are wired, this
// function returns a visible, typed "cannot verify" error — blocking the phase (the caller
// already fails the migration on any non-nil error, ADR-0012-safe: the source pod is never
// deleted before this phase, so failing closed here cannot orphan the source) — rather than the
// previous silent `nil` that fabricated a pass on nothing at all. Flagged for a dedicated
// follow-up ADR to land the real capture RPCs; do not silently re-introduce `return nil` as a
// substitute for actually implementing them.
func (r *PodMigrationReconciler) verifyRestoredSecurityContext(_ context.Context, _ *pmv1.PodMigration) error {
	return errSecurityContextVerificationNotImplemented
}

// errSecurityContextVerificationNotImplemented is the sentinel verifyRestoredSecurityContext
// returns until the source-side creds capture and destination-side /proc read (fail-closed phase-gate item 2)
// are wired. errors.Is-able so tests and any future caller can distinguish "not yet implemented"
// from a genuine attestation mismatch.
var errSecurityContextVerificationNotImplemented = errors.New(
	"verifyRestoredSecurityContext: not yet implemented — no source-side capability/seccomp/AppArmor " +
		"capture and no destination-side /proc read exist yet, so a real comparison cannot be made " +
		"(fail-closed phase-gate: failing closed rather than fabricating a pass; see remediation design item 2)")

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
// deleteReplacementPod tears down EVERY replacement pod created for this migration on the
// rollback / hard-failure path. Deleting the pod is the durable, kube-honored de-enrollment
// from the Service: once the pod acquires a deletionTimestamp the endpoint-slice controller
// drops it, so a resumed source (r.Rollbacker.Rollback, reconcileRollingBack) never
// round-robins with a live, unsynchronized replacement — the split-brain observed in
// live-proof-cycle2 §6 (replacement pod redis-src-m-24b3bf9b left Running AND in the redis-src
// Service Endpoints, driving sequence-regression WRITE_ERRORs minutes after RolledBack=True).
//
// It resolves the pods by the source-of-truth podmotion.io/migration-name LABEL stamped at
// createReplacementPod time (replacementPodMigrationNameLabel) — NOT by the pm.Status.
// ReplacementPodName mirror. That mirror is losable to the documented status-subresource
// clobber race (see the resolveReplacementPodByLabel switch in reconcileTCPVerifying, ~L1180);
// when it read empty here the prior name-only implementation early-returned and never deleted
// the replacement pod, leaving it live and enrolled indefinitely. Keying the teardown on the
// label the pod actually carries makes it a source-of-truth primitive rather than an
// inference from a losable mirror (source-of-truth primitive). All label matches are
// reaped, so a stale prior-attempt replacement pod cannot linger as a second split-brain
// endpoint either. Best-effort throughout: a resolution/list error is logged and MUST NOT
// block the ADR-0012-critical source rollback that follows this call.
//
// ADR-0350 D1: returns the reaped pods' UIDs plus a per-UID deleteConfirmed flag, captured at
// the point of deletion from the full pod objects this function already resolves and holds
// (toDelete). This is the ONLY change to this function — the resolution/reaping/best-effort
// logic above stays byte-for-byte. The caller (ensureReplacementEndpointsRemoved) consumes this
// return value directly and MUST NOT re-List/re-resolve the reaped pods after this call
// returns: replacement pods carry no finalizer, so a post-delete re-resolution races their
// disappearance and can return empty — reintroducing the losable-mirror inference this ADR
// retires (invariant #10).
func (r *PodMigrationReconciler) deleteReplacementPod(ctx context.Context, pm *pmv1.PodMigration) []reapedReplacementPod {
	log := logf.FromContext(ctx)

	// Source-of-truth resolution: every pod carrying this migration's label.
	toDelete := make(map[string]*corev1.Pod)
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList,
		client.InNamespace(pm.Spec.PodNamespace),
		client.MatchingLabels{replacementPodMigrationNameLabel: pm.Name},
	); err != nil {
		log.Error(err, "deleteReplacementPod: label list failed — falling back to recorded name",
			"migration", pm.Name)
	} else {
		for i := range podList.Items {
			p := &podList.Items[i]
			toDelete[p.Name] = p
		}
	}

	// Belt-and-suspenders for the inverse race (recorded name present, label lookup missed it):
	// resolve pm.Status.ReplacementPodName directly if it is not already collected.
	if pm.Status.ReplacementPodName != "" {
		if _, have := toDelete[pm.Status.ReplacementPodName]; !have {
			p := &corev1.Pod{}
			err := r.Get(ctx, types.NamespacedName{
				Namespace: pm.Spec.PodNamespace,
				Name:      pm.Status.ReplacementPodName,
			}, p)
			switch {
			case err == nil:
				toDelete[p.Name] = p
			case apierrors.IsNotFound(err):
				// already gone
			default:
				log.Error(err, "deleteReplacementPod: get by recorded name failed",
					"migration", pm.Name, "pod", pm.Status.ReplacementPodName)
			}
		}
	}

	if len(toDelete) == 0 {
		return nil // nothing was ever created for this migration, or it is already reaped
	}

	reaped := make([]reapedReplacementPod, 0, len(toDelete))
	for name, pod := range toDelete {
		confirmed := true
		if deleteErr := r.Delete(ctx, pod); deleteErr != nil && !apierrors.IsNotFound(deleteErr) {
			confirmed = false
			log.Error(deleteErr, "deleteReplacementPod: delete failed — manual cleanup may be required",
				"migration", pm.Name, "pod", name)
		} else {
			log.Info("deleted replacement pod on rollback/failure", "migration", pm.Name, "pod", name)
		}
		reaped = append(reaped, reapedReplacementPod{uid: pod.UID, deleteConfirmed: confirmed})
	}
	return reaped
}

// reapedReplacementPod is deleteReplacementPod's per-pod outcome, handed to
// ensureReplacementEndpointsRemoved as the source-of-truth UID set (ADR-0350 D1 — never
// re-resolved after the delete; replacement pods carry no finalizer, so a post-delete List
// races their disappearance).
type reapedReplacementPod struct {
	uid             types.UID
	deleteConfirmed bool // true iff r.Delete returned nil or NotFound
}

// ensureReplacementEndpointsRemoved is the ADR-0350 D1.2/D1.3/D3 happens-before primitive: it
// removes every reaped replacement pod's endpoint from all EndpointSlices in
// pm.Spec.PodNamespace via a bounded, operator-performed compare-and-set (never inferring kube's
// async EndpointSlice controller has converged — the retired brittle chain), then confirms
// absence. reaped is deleteReplacementPod's return value; the UIDs are never re-resolved here
// (D1's UID-handoff — a post-delete List/resolveReplacementPodByLabel call would race the pods'
// finalizer-less disappearance).
//
// Returns ok=true only when absence is confirmed durable (including the trivial case of no
// reaped pods). Returns ok=false, mode="undeletable" if any reaped pod's delete was not
// confirmed (deleteConfirmed=false — a stuck finalizer/rejecting webhook; the actionable case),
// else mode="contended" (transient EndpointSlice CAS contention exhausted the retry budget). The
// caller (reconcileRollingBack) is responsible for the D6 signal (condition/metric/event) and
// for withholding RolledBack=True on ok=false — this function never falls through to any
// inferred/async mechanism itself (invariant #10).
func (r *PodMigrationReconciler) ensureReplacementEndpointsRemoved(ctx context.Context, pm *pmv1.PodMigration, reaped []reapedReplacementPod) (ok bool, mode string, err error) {
	if len(reaped) == 0 {
		return true, "", nil
	}

	uids := make(map[types.UID]bool, len(reaped))
	anyUnconfirmed := false
	for _, rp := range reaped {
		uids[rp.uid] = true
		if !rp.deleteConfirmed {
			anyUnconfirmed = true
		}
	}

	// Removal is attempted for ALL reaped UIDs regardless of deleteConfirmed (D1: the flag does
	// not gate whether removal is attempted) — a confirmed pod's endpoint should still be
	// cleaned up even in a mixed reap batch.
	esMgr := traffic.NewEndpointSliceManager(r.Client)
	if _, remErr := esMgr.RemoveByTargetRefUIDs(ctx, pm.Spec.PodNamespace, uids); remErr != nil {
		if anyUnconfirmed {
			return false, "undeletable", remErr
		}
		return false, "contended", remErr
	}

	still, checkErr := esMgr.HasAnyTargetRefUID(ctx, pm.Spec.PodNamespace, uids)
	if checkErr != nil {
		if anyUnconfirmed {
			return false, "undeletable", checkErr
		}
		return false, "contended", checkErr
	}
	if still {
		// Removal reported success but a fresh read still finds a match — treat as exhaustion
		// under the same mode split (should be rare; RemoveByTargetRefUIDs already re-confirms
		// per-slice inside its own CAS loop, but D1.3 is the independent write-then-verify read).
		if anyUnconfirmed {
			return false, "undeletable", nil
		}
		return false, "contended", nil
	}

	// S-UNDELETABLE (arch_b): a reaped pod whose delete was not confirmed is still Running and
	// selector-matched, so kube's own EndpointSlice controller will re-materialize its endpoint
	// on its very next sync (S-REORDER) — an unwinnable CAS loop this reconcile's momentary
	// absence read cannot certify as durable. Do NOT trust a transient confirm here: treat any
	// unconfirmed delete as a decisive fail-closed exhaustion, not an inferred/hoped-for
	// convergence (invariant #10 — this is the primitive's own known-fact read, not a poll).
	if anyUnconfirmed {
		return false, "undeletable", nil
	}
	return true, "", nil
}

// dirtyPagesFreezeBudgetMB is the absolute dirty-page threshold (in MB) below which the
// freeze-go gate considers the latest pre-copy round converged enough to proceed to the final
// freeze. This reuses, verbatim, the exact threshold value already established as the freeze-go
// primitive at internal/agent/server/server.go's PreDumpRound handler
// (`ThresholdReached: result.DirtyPagesMB < 64`) rather than inventing a second, parallel
// threshold primitive for the same decision.
const dirtyPagesFreezeBudgetMB = 64

// preCopyDirtyConverged reports whether the LATEST pre-copy round's real, validated dirty-page
// measurement is below the freeze budget.
//
// This replaces the former ratio-based preCopyDirtyConvergence, which computed a "convergence"
// value as `1.0 - (finalMB / (finalMB * 2^rounds))` — algebraically a function of round count
// ALONE (it reduces to `1 - 2^(-rounds)`); real memory state never entered the computation, even
// on the nominal "success" path. Combined with three unconditional-pass branches (PreCopyStats
// == nil, finalMB <= 0, initialMB <= 0 — each returning 1.0), the old gate could advance phase
// on zero real information under multiple conditions.
//
// Fail-closed contract (exact semantics):
//   - DirtyStatsValid distinguishes "measured zero" (a real, legitimately idle round — passes)
//     from "could not measure" (a CRIU stats-decode failure, or a CRD field pruned/unset by a
//     manifest-regen gap — Go zero-value is false). Only DirtyStatsValid == false forces
//     block/requeue; a genuinely idle round is a real converged state, not a fake one.
//   - There is NO path in this function that returns true without PreCopyStats present, at
//     least one round completed, AND a validated real measurement for that round. The three old
//     unconditional-pass branches are deleted outright, not narrowed.
//   - InitialDirtyPagesMB is observability-only (round-0 baseline telemetry) and never appears
//     in this decision — there is no initialMB term left for a synthetic/zero baseline to
//     manufacture a pass through.
func preCopyDirtyConverged(pm *pmv1.PodMigration) bool {
	stats := pm.Status.PreCopyStats
	if stats == nil {
		return false
	}
	if stats.RoundsCompleted == 0 {
		return false
	}
	if !stats.DirtyStatsValid {
		return false
	}
	return stats.FinalDirtyPagesMB < dirtyPagesFreezeBudgetMB
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

// preCopyTCPGatePassed evaluates the freeze-go gate (M24):
//
//	dirty_convergence               — latest round's REAL, validated DirtyPagesMB < freeze budget (absolute, not a ratio)
//	seq_advance_rate < bandwidth    — send rate fits the transfer pipe (approximated via dirty convergence)
//	retransmit_queue_headroom < 0.5 — retransmit backlog is small
//
// All predicates must be true for the gate to pass.
// Returns true immediately when:
//   - TCPPreservationMode=None (no TCP state, gate irrelevant)
//   - MigrationModeCold (no pre-copy loop ran, gate irrelevant)
//   - MemorySynced=True with Reason=ForceFreeze (ADR-0011 PreCopyMaxRounds-exhausted
//     escape valve) AND PreCopyStats confirms a real measurement backs it
//     (DirtyStatsValid=true, RoundsCompleted > 0) — see the exemption block below.
//     the Reason string alone is NOT trusted as proof a measurement
//     exists, because the write path (RunPreCopyLoop) can set Reason=ForceFreeze via
//     patchMemorySynced even when the preceding updatePreCopyStats call failed and its
//     error was only logged (never propagated) — leaving PreCopyStats nil/stale while
//     Reason=ForceFreeze is persisted. The gate now reads the authoritative
//     PreCopyStats fields directly instead of trusting the Reason label alone.
//
// Blocks (requeues) when:
//   - PreCopyStats is nil (pre-copy loop not yet populated — defer to requeue)
//   - a real measurement exists but shows poor convergence (DirtyStatsValid=true,
//     FinalDirtyPagesMB >= budget)
//   - NO real measurement exists at all — PreCopyStats nil/zero-round, or explicitly
//     DirtyStatsValid=false (this used to fake-pass, see below)
func preCopyTCPGatePassed(pm *pmv1.PodMigration) bool {
	// MemorySynced=True is the authoritative convergence signal, but WHY it is True
	// matters — RunPreCopyLoop (internal/agent/replication/replication.go) sets it
	// True from three distinct call sites with three distinct Reasons, and only one
	// of them represents a real, validated measurement the strict dirty-gate recheck
	// below can safely skip:
	//
	//   - Reason=Converged        — a real round measured FinalDirtyPagesMB below the
	//     configured threshold. PreCopyStats is always populated with
	//     DirtyStatsValid=true here; falls through to the stats check below (which
	//     will pass, since the loop's own threshold and this gate's budget agree).
	//   - Reason=ForceFreeze      — ADR-0011's PreCopyMaxRounds-exhausted escape valve:
	//     rounds were genuinely run and PreCopyStats IS populated with
	//     DirtyStatsValid=true, but FinalDirtyPagesMB may still be at/above budget for
	//     a sustained-high-dirty-rate workload. This is an intentional, explicit
	//     bounded-downtime decision the project already allows (not a measurement
	//     failure) — this is exempted from the strict recheck below so a busy
	//     write-heavy pod under TCPPreservationMode=Strict/BestEffort does not
	//     livelock in PreCopyMemory until the ADR-0012 completion-timeout backstop.
	//   - Reason=MeasurementFailed — a PreDumpRound RPC error (transient network
	//     blip, agent-unreachable, timeout, or a decodeCRIUStats failure surfaced as a
	//     gRPC error). NO real measurement backs this state; PreCopyStats is written
	//     explicitly with DirtyStatsValid=false (never left nil) precisely so this
	//     function has a real signal to fail closed on. This reason must NOT be
	//     exempted — it falls through to the stats check below, where
	//     DirtyStatsValid=false (via preCopyDirtyConverged) blocks it. This is the
	//     exact gap this guards against: a genuine RPC/decode failure
	//     must never silently pass the TCP freeze-go gate.
	if cond := meta.FindStatusCondition(pm.Status.Conditions, conditionMemorySynced); cond != nil &&
		cond.Status == metav1.ConditionTrue && cond.Reason == pmv1.ReasonMemorySyncedForceFreeze &&
		pm.Status.PreCopyStats != nil &&
		pm.Status.PreCopyStats.DirtyStatsValid &&
		pm.Status.PreCopyStats.RoundsCompleted > 0 {
		return true
	}
	if pm.Status.PreCopyStats == nil {
		// Pre-copy loop has not reported stats yet; wait for at least one round.
		return false
	}
	if pm.Status.PreCopyStats.RoundsCompleted == 0 {
		return false
	}

	const maxRetransmitHeadroom = 0.5

	if !preCopyDirtyConverged(pm) {
		return false
	}

	retransmitHeadroom := preCopyRetransmitHeadroom(pm)
	if retransmitHeadroom >= maxRetransmitHeadroom {
		return false
	}

	return true
}
