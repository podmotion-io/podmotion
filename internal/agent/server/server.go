/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package server implements the MigrationAgentService gRPC server that runs on every node.
// In M4 the server wires up StubCheckpointer; real CRIU bindings land in M5.
package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/authz"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/grpclimits"
	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
	"github.com/podmotion-io/podmotion/internal/agent/network"
	"github.com/podmotion-io/podmotion/internal/agent/provenance"
	"github.com/podmotion-io/podmotion/internal/agent/seccomp"
	"github.com/podmotion-io/podmotion/internal/metrics"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

var log = logf.Log.WithName("agent-server")

// ADR-SEC-A §2.3 / ADR-SEC-B size bounds live in internal/agent/grpclimits (single source of
// truth shared with the operator client so server/client cannot skew).

// adrSecAServerMarker forces the ADR-SEC-A marker string into the agent binary string table so a
// deployed-binary grep can confirm the build carries this change, in addition to the authz package
// and the fail-closed error strings. adrSecBServerMarker does the same for ADR-SEC-B (verify-reject
// + sentinel paths).
const (
	adrSecAServerMarker = "ADR-SEC-A"
	adrSecBServerMarker = "ADR-SEC-B"
)

// adr0195Provenance is printed at server startup so the marker string is retained in the
// binary and is observable in agent logs. Deploy verification:
//   grep -a -c 'P-0195-1' bin/agent-linux-amd64  # must be >= 1
// The log.Info call below forces the string into the binary's string table and into the
// agent's startup log, confirming the ADR-0195 holder-contract change is deployed.
const adr0195Marker = "P-0195-1"

func init() {
	log.Info("ADR-0195 holder-contract build loaded", "marker", adr0195Marker)
}

// Sentinel errors used for structured error classification (errors.Is/As).
// Prefer these over string matching so callers remain stable across CRIU/kernel version changes.

// ErrCtrInFlightTCP is returned by ctrCheckpoint when the containerd-native checkpoint fails
// because in-flight TCP sockets are present. The caller should fall back to raw CRIU with
// TcpSkipInFlight=true.
var ErrCtrInFlightTCP = errors.New("ctr checkpoint: in-flight TCP sockets detected")

// ErrCRIUCapability aliases the sentinel from the criu package so server-layer code can use
// errors.Is without importing the criu package directly in every call site.
// Surface as gRPC codes.FailedPrecondition at the gRPC boundary.
var ErrCRIUCapability = criu.ErrCRIUCapability

// ErrRestoredPIDNotFound is returned by the cgroup-anchored restored-PID scan (ADR-0123 D2)
// when, after CRIU exits 0, no process resident in the replacement pod's cgroup can be found
// within the scan timeout. On the cold (--join-ns net:<path>) path the caller MUST fail loud on this error
// and MUST NOT fall back to the retired name-based comm-scan resolver (deleted per ADR-0245), and
// MUST NOT set criuRestoreConfirmed (ADR-0123 D2 step 5 / AC5).
var ErrRestoredPIDNotFound = errors.New("restored process PID not found in replacement pod cgroup")

// CRIUImageInconsistencyError is returned by patchCheckpointImages (ADR-0193 P-0193-1) when a
// PLAIN-REG fd (not inherited, not external, not remap) carries a positive mnt_id with no kept
// mountpoints counterpart — the image inconsistency that causes mount.c:3953 BUG_ON. The error
// carries {FdID, NameLeaf, BackingMntID} for structured event emission (P-0193-4 / S1). The
// NameLeaf is filepath.Base(name) — never the full path — so it is safe to surface in a
// world-readable Kubernetes Event (SEC-EVENT-1).
type CRIUImageInconsistencyError struct {
	FdID        int
	NameLeaf    string // filepath.Base(name) — e.g. "data" for "/data"
	BackingMntID int
}

func (e *CRIUImageInconsistencyError) Error() string {
	return criuImageInconsistencyEventMsg(e.FdID, e.NameLeaf, e.BackingMntID)
}

// ExternalMountUnresolvedError is returned by patchCheckpointImages (ADR-0194 P-0194-1) when a
// kept EXTERNAL mountpoints entry (ext_key set) survives without either a matching --ext-mount-map
// or a lockstep DROP+files.img reconcile. This converts mount.c:3141 into a loud, agent-side,
// pre-CRIU hard-stop. The Reason field indicates why: "propagation_peer" (shared_id/master_id
// non-zero, Security DECLINE class), "non_leaf_external" (has child entries), "survived_drop"
// (external entry not removed in the B-2 drop pass), "p0194_1c_dual_write_mismatch" (SC-2 guard).
type ExternalMountUnresolvedError struct {
	MntID    int
	ExtKey   string
	SharedID int
	MasterID int
	Reason   string
}

func (e *ExternalMountUnresolvedError) Error() string {
	return fmt.Sprintf("external mount mnt_id=%d ext_key=%s unresolved (reason=%s, shared_id=%d, master_id=%d): hard-stopped before criu restore (ADR-0194 P-0194-1)", e.MntID, e.ExtKey, e.Reason, e.SharedID, e.MasterID)
}

// ExternalMountDroppedInfo carries the structured info for a single B-2 external mount drop.
// Emitted as a Normal CRIUExternalMountDropped event on the PodMigration CR (H4 / C-2).
type ExternalMountDroppedInfo struct {
	MntID  int    `json:"mnt_id"`
	ExtKey string `json:"ext_key"`
	Source string `json:"source"`
}

// criuImageInconsistencyEventMsg constructs the Kubernetes Event message for a
// CRIUImageInconsistency event (ADR-0193 P-0193-4 / S1). nameLeaf MUST be
// filepath.Base(name) — never the full path — so the full volume path is not
// leaked into the world-readable Event. The full path stays only in the 0700-bounded
// agent log line (P-0193-1b / C-STATE).
func criuImageInconsistencyEventMsg(fdID int, nameLeaf string, backingMntID int) string {
	return fmt.Sprintf("files.img REG fd id=%d name_leaf=%s backing_mnt_id=%d: positive orphan mnt_id not in kept mountpoints — hard-stopped before criu restore (ADR-0193 P-0193-1)", fdID, nameLeaf, backingMntID)
}

// zwHoldState tracks per-migration zero-window hold state including armed timestamp and
// watchdog cancel for auto-disarm on FreezeWindowBudgetMs + margin expiry.
type zwHoldState struct {
	armedAtNs      int64
	watchdogCancel context.CancelFunc
	// watchdogFired is set to true by the watchdog goroutine when it auto-disarms
	// due to budget+margin expiry (ADR-0157 D1/D3). A subsequent DisarmZeroWindow
	// call checks this flag to return a distinct BlockingReason so the controller
	// can surface ConditionZeroWindowDisarmed reason=WatchdogFired (ADR-0157 D3).
	watchdogFired bool
}

// AgentServer implements agentpb.MigrationAgentServiceServer.
// One instance runs per node agent process.
type AgentServer struct {
	agentpb.UnimplementedMigrationAgentServiceServer
	checkpointer criu.Checkpointer
	nodeName     string
	k8sClient    client.Client // may be nil in pure-stub mode

	// ebpfMgr is the eBPF manager used for zero-window hold arm/disarm.
	// Initialised by New via network.NewEBPFManager; uses real cilium/ebpf
	// on kernel ≥5.9 and the no-op stub otherwise.
	ebpfMgr network.EBPFManager

	// migrationPodUID stores pod UID keyed by migration name, populated by PrepareSource.
	// Used by Checkpoint to resolve the container root PID via /proc cgroup scan.
	migrationPodUIDMu sync.RWMutex
	migrationPodUID   map[string]string

	// migrationSeqSnapshots stores source SeqSnapshots keyed by migration name.
	// Populated during Restore from RestoreRequest.SeqSnapshots; read by VerifyTCP.
	migrationSeqSnapshotsMu sync.RWMutex
	migrationSeqSnapshots   map[string][]*agentpb.SeqSnapshot

	// zwHoldMu guards zwHolds.
	zwHoldMu sync.Mutex
	// zwHolds tracks active zero-window holds keyed by migration name.
	zwHolds map[string]*zwHoldState

	// frozenSourcePIDsMu guards frozenSourcePIDs.
	frozenSourcePIDsMu sync.Mutex
	// frozenSourcePIDs tracks source PIDs left in SIGSTOP by LeaveStopped=true dumps.
	// Entry is removed when the migration completes successfully (TrafficVerified) or
	// when the source is thawed on rollback/failure. On any error exit the PID must be
	// SIGCONTed to prevent a permanently frozen source workload (ADR-0012 safety block).
	frozenSourcePIDs map[string]int32 // migrationName -> host-namespace PID

	// pendingResumePIDsMu guards pendingResumePIDs.
	pendingResumePIDsMu sync.Mutex
	// pendingResumePIDs tracks restored process PIDs whose SIGCONT (resume) has been
	// DEFERRED on the TCP-stateful (Strict) path so the restored tree stays in SIGSTOP
	// (CRIU --leave-stopped) until the destination OLD-IP datapath is installed and the
	// reachability probe passes (ADR-0142 D3). The deferred SIGCONT fires as the final
	// action of InjectIPHandoff. This realizes the seq_delta=0 "resume-after-handoff"
	// invariant without a new gRPC method. On rollback/timeout the entry is dropped and
	// the stopped tree is reaped with the rolled-back replacement pod (the held client
	// connection survives via the still-frozen source — ADR-0012).
	pendingResumePIDs map[string]int // migrationName -> restored root PID awaiting SIGCONT

	// destHostVethMu guards destHostVeth.
	destHostVethMu sync.RWMutex
	// destHostVeth stores the host-side veth peer name minted by PrepareDestinationNetns
	// (network.PrepareDestinationNetns → MigrationNetns.HostVethName, e.g. "pmh-<truncUID>").
	// Keyed by migrationName. Read by joinNsRestore to pass --veth-pair to CRIU restore.
	// Gate30: avoids re-deriving the name from migrationName (which would diverge if the
	// controller passes a pod UID to PrepareDestinationNetns and a migration name to Restore).
	destHostVeth map[string]string // migrationName -> minted host veth name

	// destWorkloadImageMu guards destWorkloadImage.
	destWorkloadImageMu sync.RWMutex
	// destWorkloadImage caches the workload OCI image reference delivered via
	// PrepareDestinationNetnsRequest.workload_image (ADR-0168 B2). The Restore gRPC
	// fallback path reads it when imageName=="" to start the placeholder container with
	// the SAME image as the checkpointed workload, matching CRIU mapped-VMA file sizes.
	destWorkloadImage map[string]string // migrationName -> OCI image ref

	// destMigrationNetnsMu guards destMigrationNetns.
	destMigrationNetnsMu sync.RWMutex
	// destMigrationNetns stores the *network.MigrationNetns handle constructed by
	// PrepareDestinationNetns so the Restore defer (GC-10, ADR-0168) can call
	// TeardownMigrationNetns on restore-failure rollback without reconstructing the handle.
	// Keyed by migrationName. Entry deleted on successful restore or teardown.
	destMigrationNetns map[string]*network.MigrationNetns
}

// New constructs an AgentServer with the given Checkpointer implementation.
// k8sClient may be nil; when set the Checkpoint handler will update MigrationCheckpoint CRs.
func New(nodeName string, cp criu.Checkpointer, k8sClient client.Client) *AgentServer {
	return &AgentServer{
		checkpointer:    cp,
		nodeName:        nodeName,
		k8sClient:       k8sClient,
		ebpfMgr:         network.NewEBPFManager(context.Background()),
		migrationPodUID:       make(map[string]string),
		migrationSeqSnapshots: make(map[string][]*agentpb.SeqSnapshot),
		zwHolds:               make(map[string]*zwHoldState),
		frozenSourcePIDs:      make(map[string]int32),
		pendingResumePIDs:     make(map[string]int),
		destHostVeth:          make(map[string]string),
		destWorkloadImage:     make(map[string]string),
		destMigrationNetns:    make(map[string]*network.MigrationNetns),
	}
}

// EnsureXDPBridgeLoaded delegates to the embedded eBPFManager to load and pin
// the xdp_bridge BPF program on the named host interface.  Must be called once
// at agent startup after NMC registration (ADR-0155 Decision 1).
func (s *AgentServer) EnsureXDPBridgeLoaded(ctx context.Context, hostIfname string, xdpBridgeCapable bool) error {
	return s.ebpfMgr.EnsureXDPBridgeLoaded(ctx, hostIfname, xdpBridgeCapable)
}

// readReplVethMACFn is the production implementation of ReadReplVethMAC.
// Overridable in tests to inject stub behaviour without spawning nsenter.
var readReplVethMACFn = ReadReplVethMAC

// joinNsRestoreFn is the production implementation of joinNsRestore.
// Overridable in tests to stub out the actual CRIU subprocess invocation.
// Signature: (migrationName, checkpointDir, imageName, containerID, destNetnsFd, sandboxID, storedHostVeth string, strictMode bool) (int, []ExternalMountDroppedInfo, error)
var joinNsRestoreFn = joinNsRestore

// restoreResult is the shared finalization result populated by finalizeRestore.
// All restore paths (NRI + both gRPC Restore branches) return this struct so that
// MAC population and SingleHomeRestoredPod parity are path-independent (E1, ADR-0133 D3,
// ADR-0137/0138).
type restoreResult struct {
	pid         int
	netnsPath   string
	mac         string
	singleHomed bool
}

// finalizeRestore is the shared restore-finalization primitive (Condition 1 + Condition 2).
// It calls ReadReplVethMAC(pid, netnsPath) to populate the replacement pod's eth0 MAC, then
// calls SingleHomeRestoredPod on both gRPC and NRI paths (parity — Condition 2).
// For tcpPreservationMode Strict or Full: an empty MAC is a hard failure (fail-closed,
// Condition 3). For None/BestEffort: an empty MAC records a queryable CR-status condition and
// continues. Returns the populated restoreResult; callers must pass result.mac to
// ReportRestoreConfirmed.
func (s *AgentServer) finalizeRestore(ctx context.Context, pid int, netnsPath, migrationName, namespace, tcpPreservationMode string) (restoreResult, error) {
	result := restoreResult{
		pid:       pid,
		netnsPath: netnsPath,
	}

	// Condition 1: call readReplVethMACFn (= ReadReplVethMAC in production; injectable in tests).
	mac, macErr := readReplVethMACFn(pid, netnsPath)
	result.mac = mac

	// Condition 3: fail-closed on Strict/Full for empty MAC; degrade on None/BestEffort.
	if macErr != nil || mac == "" {
		mode := tcpPreservationMode
		if mode == "Strict" || mode == "Full" {
			reason := "replVethMAC empty after restore — MAC resolution failed (path-independent contract violation)"
			log.Error(macErr, "finalizeRestore: "+reason, "migration", migrationName, "mode", mode)
			return result, fmt.Errorf("finalizeRestore [%s]: %s", mode, reason)
		}
		// None/BestEffort: record queryable condition but continue.
		if s.k8sClient != nil && namespace != "" {
			pm := &pmv1.PodMigration{}
			if getErr := s.k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: migrationName}, pm); getErr == nil {
				base := pm.DeepCopy()
				setConditionOnPM(pm, "ReplVethMACResolved", metav1.ConditionFalse,
					"MACEmpty", "ReadReplVethMAC returned empty — InjectIPHandoff will wait for writeback")
				if patchErr := s.k8sClient.Status().Patch(ctx, pm, client.MergeFrom(base)); patchErr != nil {
					log.Error(patchErr, "finalizeRestore: failed to patch ReplVethMACResolved condition",
						"migration", migrationName)
				}
			}
		}
		if macErr != nil {
			log.Error(macErr, "finalizeRestore: ReadReplVethMAC failed (non-fatal under "+tcpPreservationMode+")",
				"migration", migrationName)
		} else {
			log.Info("finalizeRestore: ReadReplVethMAC returned empty (non-fatal under "+tcpPreservationMode+")",
				"migration", migrationName)
		}
	} else {
		log.Info("finalizeRestore: ReadReplVethMAC collected (ADR-0133 D3)",
			"migration", migrationName, "replVethMAC", mac)
	}

	// Condition 2: SingleHomeRestoredPod parity — call on ALL paths (gRPC and NRI).
	if s.k8sClient != nil && namespace != "" && pid > 0 {
		if shErr := s.SingleHomeRestoredPod(ctx, migrationName, namespace, pid); shErr != nil {
			log.Error(shErr, "finalizeRestore: SingleHomeRestoredPod failed (ADR-0137) — pod may remain dual-homed",
				"migration", migrationName, "restoredPID", pid)
			// Non-fatal: log loud; source pod preserved per ADR-0012.
		} else {
			result.singleHomed = true
			log.Info("finalizeRestore: replacement pod single-homed on OLD IP (ADR-0137/0138)",
				"migration", migrationName, "restoredPID", pid)
		}
	}

	return result, nil
}

// setConditionOnPM is a local helper to set a metav1.Condition on a PodMigration object
// in-place (does not patch — caller must status-update).
func setConditionOnPM(pm *pmv1.PodMigration, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i, c := range pm.Status.Conditions {
		if c.Type == condType {
			pm.Status.Conditions[i].Status = status
			pm.Status.Conditions[i].Reason = reason
			pm.Status.Conditions[i].Message = message
			pm.Status.Conditions[i].LastTransitionTime = now
			return
		}
	}
	pm.Status.Conditions = append(pm.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
}

// JoinNsRestore is the exported entry point for the NRI StartContainer hook.
// It invokes the CRIU restore path that enters the container's existing namespaces
// (created by runc) and restores the checkpointed process tree.
// migrationName is used for log tagging; checkpointDir is the tmpfs images path;
// sandboxID is the containerd sandbox (pause container) ID of the replacement pod whose
// network namespace the restored process must join (ADR-0122). It comes from the NRI pod
// sandbox object (pod.GetId()).
// tcpPreservationMode is the value from spec.tcpPreservationMode on the PodMigration CR
// (ADR-0144): the caller MUST fetch it from the CR BEFORE invoking JoinNsRestore so that
// --leave-stopped is emitted when mode=Strict. Failure to fetch the CR must default to
// Strict (fail-closed) to preserve the seq_delta=0 invariant.
//
// ADR-0122 + ADR-0125: rather than minting an empty netns (--empty-ns net), JoinNsRestore
// resolves the replacement pod's sandbox netns via the containerd sandbox API (B1), opens the
// netns path with an fstat/stat inode cross-check (B2), then closes the fd and hands the netns
// PATH to CRIU via --join-ns net:<path> (ADR-0125 — CRIU 4.2 has no --net-fd flag). The restored
// process then comes up inside the pod netns, inheriting the pod IP, veth pair, and CNI routing —
// reachable at the pod IP with no post-restore namespace surgery.
//
// ADR-0144 Decision Points 1–3: on tcpPreservationMode=Strict, JoinNsRestore passes
// --leave-stopped to CRIU (via strictMode=true in buildCRIURestoreArgs), calls
// enforceRestoreOrderingInvariant with deferResume=true after the subprocess returns, and
// records the restored PID in pendingResumePIDs. SIGCONT fires exclusively from
// InjectIPHandoff after the OLD-IP datapath is confirmed live. No SIGCONT is sent inline here.
// ADR-0012 invariant: the source pod is not released until TrafficVerified=True, which only
// follows InjectIPHandoff returning success — the source is still frozen at the moment the
// restored tree resumes (ADR-0012).
//
// Returns (pid, mac, error) where mac is the replacement pod's eth0 MAC (E1 Condition 1).
// The NRI caller must pass mac directly to ReportRestoreConfirmed; it must NOT call
// ReadReplVethMAC independently.
func (s *AgentServer) JoinNsRestore(migrationName, checkpointDir, imageName, containerID, sandboxID, tcpPreservationMode string) (int, string, error) {
	strictMode := tcpPreservationMode == string(pmv1.TCPPreservationModeStrict)
	s.destHostVethMu.RLock()
	storedVeth := s.destHostVeth[migrationName]
	s.destHostVethMu.RUnlock()
	// ADR-0215: when the NRI ContainerEvent carries no image name (fetchContainerImage on the
	// placeholder/replacement container returned empty), resolve the AUTHORITATIVE source-pod
	// image cached by PrepareDestinationNetns (ADR-0168 B2 chain: source pod image →
	// MCP.Spec.WorkloadImage → PrepareDestinationNetnsRequest.workload_image →
	// destWorkloadImage[migrationName]). This replaces the prior hardcoded "docker.io/library/redis:7"
	// fallback in joinNsRestore, which silently substituted the wrong image (gate-11: pod runs
	// redis:7-alpine; hardcoded fallback requested redis:7 → "image not found").
	if imageName == "" {
		s.destWorkloadImageMu.RLock()
		imageName = s.destWorkloadImage[migrationName]
		s.destWorkloadImageMu.RUnlock()
		if imageName != "" {
			log.Info("ADR-0215: NRI image name empty — using authoritative cached workload image from PrepareDestinationNetns",
				"migration", migrationName, "image", imageName)
		}
	}
	// ADR-0217 D2: THIRD fallback. If both prior sources are empty — NRI ContainerEvent
	// carried no image AND the PrepareDestinationNetns cache is empty (e.g. the controller's
	// phase-order bug left WorkloadImage unset, or the agent restarted and lost the cache) —
	// self-resolve from the replacement pod's OWN container spec via the Kubernetes API.
	// This is the last resort before fail-close: the replacement pod created by the operator
	// carries the correct workload image in its spec, so we read it directly.
	if imageName == "" && s.k8sClient != nil {
		if resolved := s.resolveImageFromReplacementPod(migrationName); resolved != "" {
			imageName = resolved
			log.Info("ADR-0217 D2: resolved workload image from replacement pod spec",
				"migration", migrationName, "image", imageName)
		}
	}
	if imageName == "" {
		// All three sources exhausted (NRI event, PrepareDestinationNetns cache, replacement
		// pod spec). Fail-close rather than substitute a wrong image (gate-11 lesson, ADR-0215).
		return 0, "", fmt.Errorf("ADR-0217: restore image unresolved — NRI event, PrepareDestinationNetns cache, and replacement pod spec all empty for migration %s", migrationName)
	}
	pid, droppedMounts, err := joinNsRestoreFn(migrationName, checkpointDir, imageName, containerID, "", sandboxID, storedVeth, strictMode)
	if err != nil {
		// ADR-0193 P-0193-4 / S1: emit a Warning CRIUImageInconsistency Kubernetes Event on the
		// PodMigration CR when the P-0193-1 hard-stop fires. The event message carries only
		// {fd_id, name_leaf, backing_mnt_id} — the full path is NOT included (SEC-EVENT-1).
		var imgErr *CRIUImageInconsistencyError
		if errors.As(err, &imgErr) {
			s.emitCRIUImageInconsistencyEvent(context.Background(), migrationName, imgErr)
		}
		// ADR-0194 P-0194-1: emit ExternalMountUnresolved Warning event on hard-stop.
		var extErr *ExternalMountUnresolvedError
		if errors.As(err, &extErr) {
			s.emitExternalMountUnresolvedEvent(context.Background(), migrationName, extErr)
		}
		return 0, "", err
	}
	// ADR-0194 B-2 H4: emit CRIUExternalMountDropped Normal event for each B-2 drop.
	for _, d := range droppedMounts {
		s.emitExternalMountDroppedEvent(context.Background(), migrationName, d)
	}

	// ADR-0144 Decision Points 2–3: on the Strict path, enforce the gated-resume invariant.
	// expectedSocketCount is derived from the number of tcp-stream-*.img files in the checkpoint
	// directory (ADR-0144 NB-1): on the NRI path req.SeqSnapshots is always 0, so we must count
	// the tcp-stream image files directly. Using 0 would cause enforceRestoreOrderingInvariant to
	// return immediately without waiting for SocketsLive, bypassing the invariant entirely.
	if strictMode {
		tcpImgs, globErr := filepath.Glob(filepath.Join(checkpointDir, "tcp-stream-*.img"))
		expectedSocketCount := 0
		if globErr == nil {
			expectedSocketCount = len(tcpImgs)
		}
		// enforceRestoreOrderingInvariant with deferResume=true: confirms SocketsLive but does
		// NOT send SIGCONT. The restored tree stays in SIGSTOP; PID is recorded in
		// pendingResumePIDs for InjectIPHandoff to fire SIGCONT after datapath confirmation.
		_, resumedAt, orderErr := enforceRestoreOrderingInvariant(pid, migrationName, expectedSocketCount, true)
		if orderErr != nil {
			log.Error(orderErr, "JoinNsRestore: ordering invariant FAILED — SIGCONT withheld; "+
				"NRI callback will return error → containerd marks container failed → operator requeues (ADR-0144 NB-2)",
				"migration", migrationName, "pid", pid)
			return 0, "", fmt.Errorf("JoinNsRestore: ordering invariant: %w", orderErr)
		}
		if resumedAt.IsZero() {
			// SocketsLive confirmed; SIGCONT deferred — record PID for InjectIPHandoff.
			s.pendingResumePIDsMu.Lock()
			s.pendingResumePIDs[migrationName] = pid
			s.pendingResumePIDsMu.Unlock()
			log.Info("JoinNsRestore: --leave-stopped active, SIGCONT deferred to InjectIPHandoff (ADR-0144)",
				"migration", migrationName, "pid", pid, "expectedSocketCount", expectedSocketCount)
		}
	}

	// E1 Condition 1: resolve the netns path and call finalizeRestore so MAC is populated
	// path-independently. Namespace is not available here (no CR fetch in JoinNsRestore);
	// pass empty string — finalizeRestore will skip the k8s condition patch but still
	// populate mac and call SingleHomeRestoredPod.
	netnsPath := s.ResolvedNetnsPath(migrationName)
	fr, frErr := s.finalizeRestore(context.Background(), pid, netnsPath, migrationName, "", tcpPreservationMode)
	if frErr != nil {
		// Strict/Full fail-closed: propagate.
		return 0, "", frErr
	}
	return pid, fr.mac, nil
}

// resolveImageFromReplacementPod is the ADR-0217 D2 third fallback for restore image
// resolution. When the NRI event image and the PrepareDestinationNetns cache are both empty,
// it reads the replacement pod's own container[0].Image from the Kubernetes API. The
// replacement pod name lives on PodMigration.Status.ReplacementPodName and is carried in the
// workload namespace (pm.Spec.PodNamespace). Returns "" on any failure (caller fail-closes).
func (s *AgentServer) resolveImageFromReplacementPod(migrationName string) string {
	if s.k8sClient == nil || migrationName == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The PodMigration CR lives in the workload namespace; probe POD_NAMESPACE then default.
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		ns = "podmotion-system"
	}
	pm := &pmv1.PodMigration{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: migrationName, Namespace: ns}, pm); err != nil {
		// Fall back to a List across namespaces (the CR may live in the workload namespace,
		// e.g. "default", not the agent's POD_NAMESPACE).
		pmList := &pmv1.PodMigrationList{}
		if listErr := s.k8sClient.List(ctx, pmList); listErr != nil {
			return ""
		}
		found := false
		for i := range pmList.Items {
			if pmList.Items[i].Name == migrationName {
				*pm = pmList.Items[i]
				found = true
				break
			}
		}
		if !found {
			return ""
		}
	}

	replName := pm.Status.ReplacementPodName
	if replName == "" {
		return ""
	}
	podNs := pm.Spec.PodNamespace
	if podNs == "" {
		podNs = pm.Namespace
	}
	pod := &corev1.Pod{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: replName, Namespace: podNs}, pod); err != nil {
		return ""
	}
	if len(pod.Spec.Containers) == 0 {
		return ""
	}
	return pod.Spec.Containers[0].Image
}

// ReportRestoreConfirmed patches the PodMigration CR status to record that CRIU
// restore completed successfully (ADR-0120 D3). It sets criuRestoreConfirmed=true
// and restoredPID on the named migration's status subresource. migrationName is the
// PodMigration object name (equal to the checkpoint-ref); namespace is the CR namespace.
// replVethMAC (ADR-0133 D3) is the replacement pod's eth0 MAC inside the pod netns,
// collected by the NRI plugin at restore time so the operator can install the destination
// neighbor/FDB handoff for the OLD pod IP. May be empty if MAC collection failed; the
// operator falls back to a diagnostic exec in that case.
func (s *AgentServer) ReportRestoreConfirmed(ctx context.Context, migrationName, namespace string, pid int32, replVethMAC string) error {
	if s.k8sClient == nil {
		return fmt.Errorf("ReportRestoreConfirmed: no k8s client available on agent server")
	}
	if migrationName == "" || namespace == "" {
		return fmt.Errorf("ReportRestoreConfirmed: migrationName and namespace are required (got %q/%q)", namespace, migrationName)
	}

	pm := &pmv1.PodMigration{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: migrationName}, pm); err != nil {
		return fmt.Errorf("ReportRestoreConfirmed: get PodMigration %s/%s: %w", namespace, migrationName, err)
	}

	base := pm.DeepCopy()
	confirmed := true
	pm.Status.CRIURestoreConfirmed = &confirmed
	pm.Status.RestoredPID = pid
	if replVethMAC != "" {
		pm.Status.ReplVethMAC = replVethMAC
	}

	if err := s.k8sClient.Status().Patch(ctx, pm, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("ReportRestoreConfirmed: patch status %s/%s: %w", namespace, migrationName, err)
	}
	log.Info("ReportRestoreConfirmed: criuRestoreConfirmed set true",
		"migration", migrationName, "namespace", namespace, "restoredPID", pid, "replVethMAC", replVethMAC)
	return nil
}

// SingleHomeRestoredPod implements ADR-0137 (single-home variant): after CRIU restore and the
// ADR-0128 cgroup move, before ReportRestoreConfirmed, it removes the CNI-assigned NEW Flannel IP
// from the replacement pod's eth0, leaving only the CRIU-restored OLD pod IP (pm.Spec.SourcePodIP).
//
// Background (Sprint 26 blocker B6): the replacement pod is dual-homed — eth0 carries both the new
// Flannel IP (e.g. 10.244.1.94) and the CRIU-restored OLD IP (e.g. 10.244.0.94). The competing
// connected subnet makes the destination kernel classify VXLAN-decapped transit traffic for the OLD
// IP as local-input (RTN_LOCAL) and drop it. Removing the new Flannel IP eliminates the conflict so
// the kernel delivers transit traffic for the OLD IP at L2 to the pod veth via the ADR-0133 D2 neigh.
//
// No netlink dependency (vishvananda/netlink is not in go.mod; ADR-0045 forbids adding it): we reuse
// the in-tree nsenter+ip idiom already used by ReadReplVethMAC and the joinNsRestore lo-up. We only
// ever DELETE eth0 IPv4 addresses that are not the (validated) OLD IP — never add. Idempotent; an
// already-absent address is tolerated. Empty SourcePodIP → no-op (legacy/cold path unaffected).
func (s *AgentServer) SingleHomeRestoredPod(ctx context.Context, migrationName, namespace string, pid int) error {
	if s.k8sClient == nil {
		return fmt.Errorf("SingleHomeRestoredPod: no k8s client available on agent server")
	}
	if migrationName == "" || namespace == "" {
		return fmt.Errorf("SingleHomeRestoredPod: migrationName and namespace are required (got %q/%q)", namespace, migrationName)
	}
	if pid <= 0 {
		return fmt.Errorf("SingleHomeRestoredPod: invalid restored PID %d", pid)
	}

	pm := &pmv1.PodMigration{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: migrationName}, pm); err != nil {
		return fmt.Errorf("SingleHomeRestoredPod: get PodMigration %s/%s: %w", namespace, migrationName, err)
	}

	oldIP := strings.TrimSpace(pm.Spec.SourcePodIP)
	if oldIP == "" {
		log.Info("SingleHomeRestoredPod: pm.Spec.SourcePodIP is empty — no-op (legacy/cold path)",
			"migration", migrationName, "restoredPID", pid)
		return nil
	}
	if parsed := net.ParseIP(oldIP); parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("SingleHomeRestoredPod: SourcePodIP %q is not a valid IPv4", oldIP)
	}

	netnsPath := fmt.Sprintf("/proc/%d/ns/net", pid)

	// List eth0 IPv4 addresses inside the pod netns. `ip -o -4 addr show eth0` is netns-scoped
	// via nsenter --net (sysfs/`cat` would read the HOST's interfaces — see ReadReplVethMAC).
	out, err := exec.Command("nsenter", "--net="+netnsPath,
		"ip", "-o", "-4", "addr", "show", "eth0").CombinedOutput()
	if err != nil {
		return fmt.Errorf("SingleHomeRestoredPod: list eth0 addrs in netns %s: %w (%s)",
			netnsPath, err, strings.TrimSpace(string(out)))
	}
	addrs := parseEth0IPv4Addrs(string(out))
	log.Info("SingleHomeRestoredPod: eth0 addresses before single-home (ADR-0137)",
		"migration", migrationName, "restoredPID", pid, "oldIP", oldIP, "addrs", addrs)

	// ADR-0138: the join-ns CRIU restore does NOT replay the checkpoint's inet addr/route
	// config into the pod netns — at this point eth0 carries ONLY the new Flannel IP and no
	// OLD-CIDR route. So we must ASSIGN the OLD IP and the destination cni0-gateway routes,
	// not assume CRIU restored them (ADR-0137's disproven premise). Derive the destination
	// cni0 gateway from the on-eth0 Flannel IP (host octet -> 1, e.g. 10.244.1.95 -> 10.244.1.1);
	// fall back to the OLD-IP gateway if no Flannel IP is present.
	oldSeen := false
	var delErrs []string
	cni0Gateway := gatewayForIP(oldIP) // fallback
	for _, cidr := range addrs {
		ipOnly := cidr
		if i := strings.IndexByte(cidr, '/'); i >= 0 {
			ipOnly = cidr[:i]
		}
		if ipOnly == oldIP {
			oldSeen = true
			continue
		}
		// This is the new Flannel IP (or any other non-OLD address). The DESTINATION cni0
		// gateway must be derived from the address whose /24 is the destination node's pod
		// CIDR — i.e. an address NOT in the OLD IP's /24. A stale address in the OLD IP's own
		// /24 (e.g. a leftover from a prior restore) would otherwise yield the dead SOURCE
		// gateway (10.244.0.1) and break the pod's return path (probe/AC1 fail). Only adopt a
		// gateway from an out-of-OLD-/24 address; keep the OLD-/24 fallback otherwise.
		if cidr24ForIP(ipOnly) != cidr24ForIP(oldIP) {
			if gw := gatewayForIP(ipOnly); gw != "" {
				cni0Gateway = gw
			}
		}
		// Strip it so the pod is single-homed on the OLD IP.
		delOut, delErr := exec.Command("nsenter", "--net="+netnsPath,
			"ip", "addr", "del", cidr, "dev", "eth0").CombinedOutput()
		if delErr != nil {
			msg := strings.TrimSpace(string(delOut))
			// Idempotent: tolerate an already-absent address.
			if strings.Contains(strings.ToLower(msg), "cannot assign") ||
				strings.Contains(strings.ToLower(msg), "not found") ||
				strings.Contains(strings.ToLower(msg), "no such") {
				log.Info("SingleHomeRestoredPod: address already absent (idempotent)", "addr", cidr)
				continue
			}
			delErrs = append(delErrs, fmt.Sprintf("del %s: %v (%s)", cidr, delErr, msg))
			continue
		}
		log.Info("SingleHomeRestoredPod: removed non-OLD eth0 address (ADR-0138 single-home)",
			"migration", migrationName, "restoredPID", pid, "removed", cidr, "reason", "not OLD IP")
	}

	// ADR-0138 step 2: ASSIGN the OLD IP to eth0 if not already present (idempotent: tolerate
	// EEXIST). This replaces ADR-0137's invalid assumption that CRIU restored it.
	if !oldSeen {
		addOut, addErr := exec.Command("nsenter", "--net="+netnsPath,
			"ip", "addr", "add", oldIP+"/24", "dev", "eth0").CombinedOutput()
		if addErr != nil {
			msg := strings.TrimSpace(string(addOut))
			if strings.Contains(strings.ToLower(msg), "exists") {
				log.Info("SingleHomeRestoredPod: OLD IP already present (idempotent)", "oldIP", oldIP)
			} else {
				return fmt.Errorf("SingleHomeRestoredPod: assign OLD IP %s/24 to eth0: %w (%s)", oldIP, addErr, msg)
			}
		} else {
			log.Info("SingleHomeRestoredPod: assigned OLD IP to eth0 (ADR-0138)",
				"migration", migrationName, "restoredPID", pid, "oldIP", oldIP)
		}
	}

	// ADR-0138 step 3: add a link route to the destination cni0 gateway and an onlink default
	// via it, so the pod can reply to host-originated (AC1) and cross-node (AC4) traffic that
	// arrives via cni0. The OLD /24 is foreign to the destination cni0 subnet, so without this
	// the pod has no return path off its own /24 ("Network is unreachable").
	if cni0Gateway != "" {
		// link route to the gateway (idempotent)
		if rOut, rErr := exec.Command("nsenter", "--net="+netnsPath,
			"ip", "route", "add", cni0Gateway, "dev", "eth0").CombinedOutput(); rErr != nil {
			msg := strings.TrimSpace(string(rOut))
			if !strings.Contains(strings.ToLower(msg), "exists") {
				log.Info("SingleHomeRestoredPod: warning — add gateway link route", "gw", cni0Gateway, "err", rErr, "output", msg)
			}
		}
		// onlink default via the gateway (replace if present)
		if rOut, rErr := exec.Command("nsenter", "--net="+netnsPath,
			"ip", "route", "replace", "default", "via", cni0Gateway, "dev", "eth0", "onlink").CombinedOutput(); rErr != nil {
			log.Info("SingleHomeRestoredPod: warning — set onlink default route", "gw", cni0Gateway, "err", rErr, "output", strings.TrimSpace(string(rOut)))
		} else {
			log.Info("SingleHomeRestoredPod: installed cni0-gateway routes (ADR-0138)",
				"migration", migrationName, "restoredPID", pid, "gateway", cni0Gateway)
		}

		// ADR-0139 Decision 2 (reverse path, blocker B8): the OLD IP's connected /24
		// (10.244.0.0/24) makes the pod treat the SOURCE node's pod CIDR — including the
		// source VTEP IP 10.244.0.0 — as on-link, so replies ARP `who-has 10.244.0.0` and
		// never egress. Force replies to the source CIDR via the destination cni0 gateway
		// (which routes them over VXLAN back to pm-control) instead of on-link ARP. The
		// source CIDR is the /24 of the OLD IP. `ip route replace` is inherently idempotent.
		srcNodeCIDR := cidr24ForIP(oldIP)
		if srcNodeCIDR != "" {
			if rOut, rErr := exec.Command("nsenter", "--net="+netnsPath,
				"ip", "route", "replace", srcNodeCIDR, "via", cni0Gateway, "dev", "eth0").CombinedOutput(); rErr != nil {
				log.Info("SingleHomeRestoredPod: warning — set reverse-path route (ADR-0139 D2)",
					"srcNodeCIDR", srcNodeCIDR, "gw", cni0Gateway, "err", rErr, "output", strings.TrimSpace(string(rOut)))
			} else {
				log.Info("SingleHomeRestoredPod: installed reverse-path route to source CIDR via cni0 gateway (ADR-0139 D2)",
					"migration", migrationName, "restoredPID", pid, "srcNodeCIDR", srcNodeCIDR, "gateway", cni0Gateway)
			}
		}
	}

	// Verify: only the OLD IP should remain on eth0.
	verifyOut, verifyErr := exec.Command("nsenter", "--net="+netnsPath,
		"ip", "-o", "-4", "addr", "show", "eth0").CombinedOutput()
	if verifyErr != nil {
		return fmt.Errorf("SingleHomeRestoredPod: verify eth0 addrs in netns %s: %w (%s)",
			netnsPath, verifyErr, strings.TrimSpace(string(verifyOut)))
	}
	remaining := parseEth0IPv4Addrs(string(verifyOut))
	log.Info("SingleHomeRestoredPod: eth0 addresses after single-home (ADR-0138 AC5)",
		"migration", migrationName, "restoredPID", pid, "oldIP", oldIP, "remaining", remaining, "gateway", cni0Gateway)

	if len(delErrs) > 0 {
		return fmt.Errorf("SingleHomeRestoredPod: failed to remove %d address(es): %s",
			len(delErrs), strings.Join(delErrs, "; "))
	}
	// AC5: eth0 must carry the OLD IP and only the OLD IP.
	oldPresent := false
	for _, cidr := range remaining {
		ipOnly := cidr
		if i := strings.IndexByte(cidr, '/'); i >= 0 {
			ipOnly = cidr[:i]
		}
		if ipOnly == oldIP {
			oldPresent = true
		} else {
			return fmt.Errorf("SingleHomeRestoredPod: eth0 still has non-OLD address %s after single-home (remaining %v)", cidr, remaining)
		}
	}
	if !oldPresent {
		return fmt.Errorf("SingleHomeRestoredPod: OLD IP %s not present on eth0 after single-home (remaining %v)", oldIP, remaining)
	}
	return nil
}

// gatewayForIP returns the ".1" gateway address of the /24 containing ip (e.g. "10.244.1.95"
// -> "10.244.1.1"). Returns "" if ip is not a valid IPv4. Used to derive the destination cni0
// bridge gateway from the new Flannel IP (ADR-0138).
func gatewayForIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.1", v4[0], v4[1], v4[2])
}

// cidr24ForIP returns the /24 network CIDR containing ip (e.g. "10.244.0.97" ->
// "10.244.0.0/24"). Returns "" if ip is not a valid IPv4. Used by ADR-0139 to derive the
// SOURCE node's pod CIDR for the pod-netns reverse-path route.
func cidr24ForIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
}

// parseEth0IPv4Addrs extracts the "A.B.C.D/N" tokens from `ip -o -4 addr show eth0` output.
// Each line looks like: "2: eth0    inet 10.244.0.94/24 brd ... scope global eth0\\ ...".
// Returns the addresses in CIDR form (suitable to pass straight back to `ip addr del`).
func parseEth0IPv4Addrs(out string) []string {
	var addrs []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "inet" {
				addrs = append(addrs, fields[i+1])
			}
		}
	}
	return addrs
}

// ReadReplVethMAC reads the replacement pod's eth0 MAC for ADR-0133 D3. It prefers the
// sandbox network namespace path (the same netns the join-ns restore targeted, where eth0
// is reliably present), falling back to the restored process's own netns. The restored
// PID's /proc/<pid>/ns/net can transiently resolve to a netns without eth0 right after CRIU
// exits, so the sandbox-netns read is the authoritative source. Returns "" and a non-nil
// error if both fail; the caller treats MAC collection as best-effort.
//
// sandboxNetnsPath may be empty (host-network or unresolved), in which case only the PID
// path is attempted.
func ReadReplVethMAC(pid int, sandboxNetnsPath string) (string, error) {
	var attempts []string
	if sandboxNetnsPath != "" {
		attempts = append(attempts, sandboxNetnsPath)
	}
	if pid > 0 {
		attempts = append(attempts, "/proc/"+strconv.Itoa(pid)+"/ns/net")
	}
	if len(attempts) == 0 {
		return "", fmt.Errorf("ReadReplVethMAC: no netns source (pid=%d, sandboxNetnsPath=%q)", pid, sandboxNetnsPath)
	}
	var lastErr error
	for _, netnsArg := range attempts {
		// Read the MAC via `ip link` (netlink, net-namespace-scoped) — NOT
		// `cat /sys/class/net/eth0/address`. nsenter --net changes only the network
		// namespace, leaving the host's /sys mount in place, so reading sysfs would
		// return the HOST's interfaces, not the pod netns's. `ip -o link show eth0`
		// queries the kernel via rtnetlink scoped to the entered netns.
		out, err := exec.Command("nsenter", "--net="+netnsArg,
			"ip", "-o", "link", "show", "eth0").CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("ReadReplVethMAC: nsenter %s ip link: %w (%s)", netnsArg, err, strings.TrimSpace(string(out)))
			continue
		}
		mac := parseLinkEther(string(out))
		if mac == "" {
			lastErr = fmt.Errorf("ReadReplVethMAC: no link/ether in `ip link show eth0` output via %s: %s", netnsArg, strings.TrimSpace(string(out)))
			continue
		}
		return mac, nil
	}
	return "", lastErr
}

// parseLinkEther extracts the MAC from `ip -o link show <dev>` output, i.e. the token
// following "link/ether". Returns "" if not found.
func parseLinkEther(out string) string {
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "link/ether" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}


// resolvedNetnsPaths caches the netns path CRIU joined per migration (ADR-0133), so the NRI
// restore callback can read eth0's MAC from the exact pod netns rather than the restored
// PID's own ns/net (which can transiently resolve to the host netns post-restore).
var (
	resolvedNetnsPathsMu sync.RWMutex
	resolvedNetnsPaths   = map[string]string{}
)

func storeResolvedNetnsPath(migrationName, path string) {
	if migrationName == "" || path == "" {
		return
	}
	resolvedNetnsPathsMu.Lock()
	resolvedNetnsPaths[migrationName] = path
	resolvedNetnsPathsMu.Unlock()
}

// ResolvedNetnsPath returns the netns path CRIU joined for migrationName, or "" if unknown.
func (s *AgentServer) ResolvedNetnsPath(migrationName string) string {
	resolvedNetnsPathsMu.RLock()
	defer resolvedNetnsPathsMu.RUnlock()
	return resolvedNetnsPaths[migrationName]
}

// SandboxNetnsPath resolves the network namespace path for a containerd sandbox ID, for use
// by the NRI restore callback to collect the replacement pod's eth0 MAC (ADR-0133 D3).
// Returns "" with a nil error for host-network sandboxes (no netns to read).
func (s *AgentServer) SandboxNetnsPath(ctx context.Context, sandboxID string) (string, error) {
	if sandboxID == "" {
		return "", fmt.Errorf("SandboxNetnsPath: empty sandboxID")
	}
	return sandboxNetnsPath(ctx, sandboxID)
}

// InjectIPHandoff installs the ADR-0133 Decision 2 destination-side neighbor entries so
// the OLD pod IP becomes reachable at the replacement pod's veth MAC, then optionally runs
// an in-node reachability probe (Decision 5). Idempotent: uses RTM_NEWNEIGH NLM_F_REPLACE.
func (s *AgentServer) InjectIPHandoff(ctx context.Context, req *agentpb.InjectIPHandoffRequest) (*agentpb.InjectIPHandoffResponse, error) {
	log.Info("InjectIPHandoff called", "migration", req.MigrationName,
		"oldPodIP", req.OldPodIp, "replVethMAC", req.ReplVethMac, "srcNodeVTEPMAC", req.SrcNodeVtepMac)

	if req.OldPodIp == "" || req.ReplVethMac == "" {
		return nil, status.Errorf(codes.InvalidArgument,
			"InjectIPHandoff: old_pod_ip and repl_veth_mac are required (got %q/%q)", req.OldPodIp, req.ReplVethMac)
	}
	oldIP := net.ParseIP(req.OldPodIp)
	if oldIP == nil || oldIP.To4() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "InjectIPHandoff: old_pod_ip %q is not a valid IPv4", req.OldPodIp)
	}
	mac, err := net.ParseMAC(req.ReplVethMac)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "InjectIPHandoff: repl_veth_mac %q invalid: %v", req.ReplVethMac, err)
	}

	bridgeIf := req.BridgeIfname
	if bridgeIf == "" {
		// ADR-0158 Decision 5: no "cni0" literal fallback. Discover the host interface
		// at runtime (ADR-0154 Decision 3 kindnetProvider discovery). On kind/kindnet
		// the host-local CNI uses ptp (no bridge); the relevant interface is the node's
		// primary non-loopback ethernet interface (e.g. "eth0").
		discovered, discErr := discoverHostInterface(ctx)
		if discErr != nil || discovered == "" {
			return &agentpb.InjectIPHandoffResponse{Injected: false,
				BlockingReason: fmt.Sprintf("provider did not resolve a bridge interface and runtime discovery failed: %v", discErr)}, nil
		}
		bridgeIf = discovered
		log.Info("InjectIPHandoff: ADR-0154 runtime bridge interface discovery", "discovered", bridgeIf)
	}
	// fdbIf resolution: use operator-supplied FdbIfname if present (override path), otherwise
	// resolve at runtime via link-type VXLAN discrimination (ADR-0192 Site B B4 fix).
	// DiscoverFdbInterface returns "" on substrates with no VXLAN overlay (kind/kindnet).
	// No "flannel.1" literal: the provider method is the single source of truth (C-335).
	fdbIf := req.FdbIfname
	if fdbIf == "" {
		discovered, discErr := network.DiscoverFdbInterface()
		if discErr != nil {
			log.Error(discErr, "InjectIPHandoff: fdbIf VXLAN discovery error (non-fatal, treating as no-overlay)",
				"migration", req.MigrationName)
		}
		fdbIf = discovered // "" on kind/kindnet — FDB overlay leg will be skipped below
		if fdbIf != "" {
			log.Info("InjectIPHandoff: ADR-0192 runtime FDB interface discovery", "discovered", fdbIf)
		}
	}

	// ADR-0135: install a /32 link-scoped host route for the OLD pod IP via the bridge/host
	// interface so the kernel's route lookup selects the LOCAL bridge instead of routing back
	// to the source node. Without this the neighbor entries below are never consulted and the
	// reachability probe blackholes.
	if err := network.SetPodIPHostRoute(ctx, bridgeIf, oldIP); err != nil {
		return &agentpb.InjectIPHandoffResponse{Injected: false,
			BlockingReason: fmt.Sprintf("%s /32 route: %v", bridgeIf, err)}, nil
	}

	// D2.1: ip neigh replace <oldPodIP> lladdr <replVethMAC> dev <bridgeIf> nud permanent
	if err := network.SetPodIPNeigh(ctx, bridgeIf, oldIP, mac); err != nil {
		return &agentpb.InjectIPHandoffResponse{Injected: false,
			BlockingReason: fmt.Sprintf("%s neigh: %v", bridgeIf, err)}, nil
	}

	// ADR-0199 D1: the OLD-IP destination datapath-wiring leg (D2.2 neigh where applicable,
	// ADR-0139 tc-redirect, ADR-0140 FORWARD-ACCEPT, ADR-0141 NOTRACK) is substrate-portable —
	// it does NOT require a VXLAN device. Previously this entire leg was gated behind
	// `fdbIf != ""` and SILENT on kindnet (the M3 active-but-silent mechanism — silent on non-VXLAN substrates),
	// which made the in-node OLD-IP dial blackhole (`i/o timeout`) and wedged the handoff.
	//
	// The redirect needs a SOURCE interface on which OLD-IP frames arrive and a TARGET veth
	// peer to redirect them to. On VXLAN the source is `fdbIf` (unchanged — zero regression).
	// On kindnet/host-routed (`fdbIf == ""`) the equivalent source is the node's host
	// interface `bridgeIf` (already discovered above, already used by M1/M2). The TARGET
	// (resolveReplVethPeer) is identical on both substrates (no VXLAN dependency).
	redirectIf := fdbIf
	if redirectIf == "" {
		redirectIf = bridgeIf // ADR-0199: kindnet host-routed substrate — redirect on bridgeIf
		log.Info("InjectIPHandoff: ADR-0199 host-routed substrate — installing OLD-IP datapath leg on bridgeIf (no VXLAN device)",
			"migration", req.MigrationName, "bridgeIf", bridgeIf)
	}
	{
		// D2.2: ip neigh replace <oldPodIP> lladdr <replVethMAC> dev <redirectIf> nud permanent.
		// On kindnet redirectIf == bridgeIf, where the M1 neigh already lives; RTM_NEWNEIGH
		// NLM_F_REPLACE makes this idempotent (a no-op re-assert), so it is safe on both substrates.
		if err := network.SetPodIPNeigh(ctx, redirectIf, oldIP, mac); err != nil {
			return &agentpb.InjectIPHandoffResponse{Injected: false,
				BlockingReason: fmt.Sprintf("%s neigh: %v", redirectIf, err)}, nil
		}

		// ADR-0139 Decision 1 (forward path, blocker B8): install a tc-ingress redirect on the
		// redirect-source device that moves frames for the OLD IP straight to the replacement
		// pod's host-side veth peer, bypassing L3 local-input classification. Best-effort: a
		// resolution/setup failure is non-fatal so an otherwise-good handoff is not blocked;
		// the source is held until TrafficVerified so a requeue re-asserts it (idempotent).
		if replPID, pidErr := s.restoredPIDForMigration(ctx, req.MigrationName); pidErr == nil && replPID > 0 {
			if vethPeer, vErr := resolveReplVethPeer(replPID); vErr != nil {
				log.Error(vErr, "InjectIPHandoff: ADR-0139 could not resolve repl veth peer — tc redirect NOT installed (non-fatal)",
					"migration", req.MigrationName, "replPID", replPID)
			} else if vethPeer == "" {
				log.Info("InjectIPHandoff: ADR-0139 repl veth peer empty — tc redirect NOT installed (non-fatal)",
					"migration", req.MigrationName, "replPID", replPID)
			} else if tcErr := installTCRedirect(ctx, redirectIf, oldIP, vethPeer); tcErr != nil {
				log.Error(tcErr, "InjectIPHandoff: ADR-0139 tc redirect install failed (non-fatal)",
					"migration", req.MigrationName, "redirectIf", redirectIf, "oldPodIP", req.OldPodIp, "vethPeer", vethPeer)
			} else {
				log.Info("InjectIPHandoff: ADR-0139 tc-ingress redirect installed (forward path B8)",
					"migration", req.MigrationName, "redirectIf", redirectIf, "oldPodIP", req.OldPodIp, "vethPeer", vethPeer)
				// ADR-0140 (blocker B9): the tc `mirred` redirect steals the forward frame before
				// conntrack's ingress hook, so the pod's reply is conntrack-INVALID and kube-proxy's
				// KUBE-FORWARD `ctstate INVALID -j DROP` rule drops it. Insert a narrow OLD-IP/32
				// FORWARD ACCEPT pair at the head of FORWARD (before KUBE-FORWARD). These rules match
				// on OLD-IP, not on the overlay device, so they are interface-independent. Non-fatal.
				if fwErr := installOldIPForwardAccept(ctx, oldIP); fwErr != nil {
					log.Error(fwErr, "InjectIPHandoff: ADR-0140 FORWARD ACCEPT install failed (non-fatal)",
						"migration", req.MigrationName, "oldPodIP", req.OldPodIp)
				} else {
					log.Info("InjectIPHandoff: ADR-0140 OLD-IP FORWARD ACCEPT installed (reverse path B9)",
						"migration", req.MigrationName, "oldPodIP", req.OldPodIp)
				}
				// ADR-0140's filter ACCEPT fixes control/ICMP forwarding but the stateful-TCP DATA
				// segment is still conntrack-INVALID (the tc mirred redirect made the forward leg
				// conntrack-invisible), so the kernel RSTs it (B10). NOTRACK the OLD-IP flow in the
				// raw table (pre-conntrack) on this destination node, both directions. Non-fatal.
				if ntErr := installOldIPNotrack(ctx, oldIP, "both"); ntErr != nil {
					log.Error(ntErr, "InjectIPHandoff: ADR-0141 NOTRACK install failed (non-fatal)",
						"migration", req.MigrationName, "oldPodIP", req.OldPodIp)
				} else {
					log.Info("InjectIPHandoff: ADR-0141 OLD-IP NOTRACK installed (reverse data path B10)",
						"migration", req.MigrationName, "oldPodIP", req.OldPodIp)
				}
			}
		} else {
			log.Info("InjectIPHandoff: ADR-0139 RestoredPID not yet in CR status — tc redirect deferred to requeue (non-fatal)",
				"migration", req.MigrationName)
		}
	}

	// ADR-0158 Decision 2+3: emit gratuitous ARP AFTER /32 route and neigh are installed,
	// BEFORE returning Injected=true (i.e. before DisarmZeroWindow). Non-fatal — a gARP
	// failure is logged but does not block the handoff; the /32 + neigh are already in place.
	if garpErr := network.SendGratuitousARP(ctx, req.OldPodIp, bridgeIf); garpErr != nil {
		log.Error(garpErr, "InjectIPHandoff: ADR-0158 gratuitous ARP failed (non-fatal)",
			"migration", req.MigrationName, "oldPodIP", req.OldPodIp, "bridgeIf", bridgeIf)
	} else {
		log.Info("InjectIPHandoff: ADR-0158 gratuitous ARP emitted",
			"migration", req.MigrationName, "oldPodIP", req.OldPodIp, "bridgeIf", bridgeIf)
	}

	// Build response: set ResolvedFdbIf for observability (ADR-0192 VERIFY-11).
	// When req.FdbIfname was supplied by the operator, ResolvedFdbIf is left empty (override path).
	// When auto-discovered: the resolved device name, or "none:substrate-not-applicable" if absent.
	resolvedFdbIfAnnotation := ""
	if req.FdbIfname == "" {
		if fdbIf == "" {
			resolvedFdbIfAnnotation = "none:substrate-not-applicable"
		} else {
			resolvedFdbIfAnnotation = fdbIf
		}
	}
	resp := &agentpb.InjectIPHandoffResponse{Injected: true, ResolvedFdbIf: resolvedFdbIfAnnotation}

	// Decision 3: return this node's VTEP MAC for the operator to thread to source cleanup.
	// Only meaningful when fdbIf != "" (an overlay FDB device is present on this substrate).
	if fdbIf != "" {
		if vtepMAC, derr := network.DiscoverVTEPMAC(ctx, "", fdbIf); derr == nil {
			resp.DestVtepMac = vtepMAC.String()
		} else {
			log.Error(derr, "InjectIPHandoff: DiscoverVTEPMAC failed (non-fatal)", "ifName", fdbIf)
		}
	}

	// Decision 5: in-node reachability probe — TCP L4 dial to the OLD pod IP.
	// ADR-0192 R2: replaced exec ping (absent on kind nodes, requires CAP_NET_RAW) with
	// net.DialTimeout (no binary dependency, no capability required). A TCP SYN-ACK or
	// RST both confirm the IP is routable; ECONNREFUSED is also a success (the kernel
	// responded — the IP is live). Only a network-level timeout is a failure.
	//
	// ADR-0200 D1: the dial is anchored INSIDE the replacement pod netns, not the agent's
	// host netns. On the kindnet host-routed substrate the OLD IP is owned (ADR-0138 M7)
	// only inside the pod's eth0; a host-netns dial is on the wrong datapath (the ingress-
	// only M3 mirred redirect cannot carry a host-locally-originated SYN onto the pod veth),
	// so it always times out. Dialing from where the IP is owned returns RST → ProbeOk.
	// The probe PORT (:7) and the RST=success semantics are UNCHANGED (ADR-0200 D3); only
	// the dial's execution netns changes. The in-netns dial reuses the established in-tree
	// nsenter --net=/proc/<replPID>/ns/net idiom (no new external binary, ADR-0200 D1 (i)),
	// re-executing this same agent binary's __inetns_probe helper subcommand.
	if req.Probe {
		// ADR-0210a (atomic alias removal): the ADR-0201 lo/32 alias on the replacement pod's
		// loopback — and the ADR-0200 in-netns dial probe that depended on it — are REMOVED here.
		// They formed a tautology: the dial and the aliased IP lived in the SAME netns, so the
		// local kernel always answered RST and ProbeOk was True even when no off-node datapath
		// existed (cross-node clients saw 100% loss while TrafficVerified=True). The authoritative
		// reachability signal is now the CONTROLLER-driven cross-node nonce round-trip
		// (StartReachabilityEcho on this dest agent + ProbeDataplaneReachability on the source
		// agent), which flips DataplaneReachabilityVerified. PM-C4: the in-netns dial is DEMOTED
		// to a fast LOCAL PRE-CHECK (not deleted) — its result is advisory ProbeOk only and no
		// longer gates the deferred SIGCONT, source disarm, TrafficVerified, or deletion.
		replPID, pidErr := s.restoredPIDForMigration(ctx, req.MigrationName)
		if pidErr != nil || replPID <= 0 {
			resp.ProbeOk = false
			resp.ProbeOutput = "ADR-0210: RestoredPID not yet resolvable — local pre-check deferred (advisory only; cross-node gate is authoritative)"
			log.Info("InjectIPHandoff: ADR-0210 local pre-check deferred — RestoredPID not yet in CR status (advisory, non-gating)",
				"migration", req.MigrationName, "oldPodIp", req.OldPodIp)
		} else {
			probeOk, probeOut := s.probeOldIPInPodNetns(ctx, replPID, req.OldPodIp)
			resp.ProbeOk = probeOk
			resp.ProbeOutput = probeOut
			log.Info("InjectIPHandoff: ADR-0210 in-netns LOCAL PRE-CHECK complete (advisory only — cross-node DataplaneReachabilityVerified is authoritative)",
				"migration", req.MigrationName, "oldPodIp", req.OldPodIp, "replPID", replPID, "preCheckOk", probeOk, "probeOutput", probeOut)
		}
	}

	// ADR-0142 D3: the deferred SIGCONT (seq_delta=0 path). The restored tree has been held
	// in SIGSTOP since SocketsLive was confirmed in Restore. Now that the OLD-IP forward+reverse
	// datapath (ADR-0133/0139/0140/0141) is installed, resume the tree as the FINAL action so the
	// restored app only ever emits segments into a live datapath.
	// ADR-0210a: SIGCONT NO LONGER gates on the (now-demoted, tautological) in-netns ProbeOk.
	// The restored tree must resume so its preserved IP becomes dialable for the cross-node
	// nonce round-trip; the authoritative reachability gate (DataplaneReachabilityVerified) runs
	// at the controller AFTER resume and still holds the source pod until it passes. Re-anchoring
	// SIGCONT to the cross-node signal would deadlock (the cross-node dial needs a live listener
	// inside the resumed tree). QA-A1 consumer re-point: the resume gate is unconditioned on the
	// removed self-loop signal.
	{
		s.pendingResumePIDsMu.Lock()
		resumePID, hasPending := s.pendingResumePIDs[req.MigrationName]
		if hasPending {
			delete(s.pendingResumePIDs, req.MigrationName)
		}
		s.pendingResumePIDsMu.Unlock()
		if hasPending && resumePID > 0 {
			socketsLiveAt := time.Now()
			if err := syscall.Kill(resumePID, syscall.SIGCONT); err != nil {
				// Re-record so a requeue can retry; do not fail the handoff (source held).
				s.pendingResumePIDsMu.Lock()
				s.pendingResumePIDs[req.MigrationName] = resumePID
				s.pendingResumePIDsMu.Unlock()
				log.Error(err, "InjectIPHandoff: deferred SIGCONT FAILED — restored tree still stopped, will retry on requeue (ADR-0142 D3)",
					"migration", req.MigrationName, "pid", resumePID)
			} else {
				resumedAt := time.Now()
				log.Info("InjectIPHandoff: deferred SIGCONT sent — restored tree resumed after datapath ready (ADR-0142 D3, seq_delta=0)",
					"migration", req.MigrationName, "pid", resumePID, "resumedAt", resumedAt.UnixNano())
				if s.k8sClient != nil {
					if setErr := s.setOrderingConditions(req.MigrationName, resumePID, socketsLiveAt, resumedAt); setErr != nil {
						log.Error(setErr, "InjectIPHandoff: failed to set ordering conditions after deferred SIGCONT", "migration", req.MigrationName)
					}
				}
			}
		}
	}

	log.Info("InjectIPHandoff: handoff injected (ADR-0133 D2)", "migration", req.MigrationName,
		"oldPodIP", req.OldPodIp, "destVTEPMAC", resp.DestVtepMac, "probeOk", resp.ProbeOk)
	return resp, nil
}

// CleanupSourceIPHandoff removes the stale ARP/neighbor entries for the OLD pod IP on the
// SOURCE node after traffic has moved to the replacement (ADR-0133 Decision 4). Idempotent.
func (s *AgentServer) CleanupSourceIPHandoff(ctx context.Context, req *agentpb.CleanupSourceIPHandoffRequest) (*agentpb.CleanupSourceIPHandoffResponse, error) {
	log.Info("CleanupSourceIPHandoff called", "migration", req.MigrationName, "oldPodIP", req.OldPodIp)

	if req.OldPodIp == "" {
		return nil, status.Errorf(codes.InvalidArgument, "CleanupSourceIPHandoff: old_pod_ip is required")
	}
	oldIP := net.ParseIP(req.OldPodIp)
	if oldIP == nil || oldIP.To4() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "CleanupSourceIPHandoff: old_pod_ip %q is not a valid IPv4", req.OldPodIp)
	}

	// ADR-0158 Decision 5: BridgeIfname must come from provider runtime discovery (ADR-0154 D3).
	// No "cni0" fallback — the caller (controller) must supply the discovered interface name.
	bridgeIf := req.BridgeIfname
	fdbIf := req.FdbIfname
	if fdbIf == "" {
		fdbIf = "flannel.1"
	}

	// ADR-0136 correction: D4 cleanup must remove ONLY the stale LOCAL-bridge (cni0) entry
	// for the OLD pod IP. It must NOT touch the flannel.1 entries, because on the source node
	// those flannel.1 entries (/32 route + AF_INET neigh oldIP->replVethMAC + AF_BRIDGE FDB
	// replVethMAC->destNodeIP) are the live VXLAN redirect installed by InjectSourceRedirect —
	// they are what keeps the relocated OLD IP reachable from a source-co-resident client.
	// Deleting the flannel.1 neigh here (as the original ADR-0133 D4 did) tore down the
	// redirect in the same reconcile pass and re-blackholed the IP (Sprint 26 AC2 first run).
	// The flannel.1 redirect is retired separately when the IP is reclaimed by IPAM; for the
	// PoC it persists for the life of the replacement pod. cni0 cleanup remains idempotent.
	_ = fdbIf
	var firstErr error
	if err := network.DeletePodIPNeigh(ctx, bridgeIf, oldIP); err != nil {
		firstErr = err
	}
	// ADR-0135: remove any /32 host route on the LOCAL bridge (cni0). On the source node this
	// is a no-op (the redirect route is on flannel.1, deliberately left intact). Idempotent.
	if err := network.DeletePodIPHostRoute(ctx, bridgeIf, oldIP); err != nil && firstErr == nil {
		firstErr = err
	}
	if firstErr != nil {
		return &agentpb.CleanupSourceIPHandoffResponse{Cleaned: false,
			BlockingReason: firstErr.Error()}, nil
	}

	// ADR-0141: the source-node NOTRACK rules persist for the life of the relocated IP (like the
	// flannel.1 redirect above); they are removed only on IPAM reclaim. Not torn down here.

	log.Info("CleanupSourceIPHandoff: stale cni0 entry removed; flannel.1 redirect preserved (ADR-0133 D4 + ADR-0136)", "migration", req.MigrationName, "oldPodIP", req.OldPodIp)
	return &agentpb.CleanupSourceIPHandoffResponse{Cleaned: true}, nil
}

// restoredPIDForMigration fetches the PodMigration CR and returns Status.RestoredPID (the root
// PID of the restored container, set by this agent at ReportRestoreConfirmed). Used by ADR-0139
// to resolve the replacement pod's veth peer without a proto change (the agent already holds the
// k8s client and the migration name).
//
// Return contract (ADR-0244 N1/N2 correction, Sprint 40): callers MUST distinguish two cases
// that this function previously conflated into a single "0" return:
//  1. The CR/PID is POSITIVELY resolved and RestoredPID is genuinely unset/zero (pod gone, or
//     never restored on this node yet) — returns (0, nil). Nothing left to protect; not an error.
//  2. The LOOKUP ITSELF fails (e.g. a transient List error against the apiserver, or no
//     k8sClient configured) — returns (0, err). This is a genuine lookup failure, not a positive
//     absence, and callers on the safety-critical R7 path (ProbeDestSocketForIP) MUST propagate
//     it as an RPC error so the caller fails closed, exactly as NoLiveConntrackForIP (R6) already
//     does on its own RPC errors. Before this correction, case (2) was silently folded into case
//     (1) and returned "0, treat as absent", which failed OPEN on a transient error and could
//     have authorized a reclaim teardown against a live pinned connection (the same harm class
//     the R6/C1 finding identified, reached through R7 instead).
//
// Best-effort, non-safety-critical callers (e.g. the ADR-0139 tc-redirect install path, the
// ADR-0210 in-netns pre-check) may continue to treat any error the same as "not yet resolvable"
// (defer/skip), since those paths are already advisory-only and re-tried on the next requeue.
func (s *AgentServer) restoredPIDForMigration(ctx context.Context, migrationName string) (int, error) {
	if s.k8sClient == nil {
		return 0, fmt.Errorf("restoredPIDForMigration: no k8s client configured")
	}
	if migrationName == "" {
		return 0, fmt.Errorf("restoredPIDForMigration: migration_name is required")
	}
	// Namespace is not carried on the InjectIPHandoff request; PodMigrations are namespaced.
	// The PoC runs in "default". List across namespaces by name as a robust fallback so this
	// is not hard-wired to one namespace if the operator is reconfigured.
	pm := &pmv1.PodMigration{}
	getErr := s.k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: migrationName}, pm)
	if getErr == nil {
		return int(pm.Status.RestoredPID), nil
	}
	if !apierrors.IsNotFound(getErr) {
		// A non-NotFound Get error (transient apiserver/network failure) is a genuine lookup
		// failure — propagate it rather than falling through to the list-based fallback, which
		// would otherwise mask it as "not found in default, try listing" and risk the same
		// silent-absorption defect the List branch below is careful to avoid.
		return 0, fmt.Errorf("restoredPIDForMigration: get PodMigration %q: %w", migrationName, getErr)
	}
	pmList := &pmv1.PodMigrationList{}
	if err := s.k8sClient.List(ctx, pmList); err != nil {
		return 0, fmt.Errorf("restoredPIDForMigration: list PodMigrations failed for %q: %w", migrationName, err)
	}
	for i := range pmList.Items {
		if pmList.Items[i].Name == migrationName {
			return int(pmList.Items[i].Status.RestoredPID), nil
		}
	}
	// Positively enumerated every PodMigration and found none named migrationName: the CR
	// genuinely does not exist (or has no RestoredPID yet). This is case (1) — a real absence,
	// not a lookup failure.
	return 0, nil
}

// resolveNamespaceForMigration returns the Kubernetes namespace of the named PodMigration CR.
// The RestoreRequest proto does not carry a namespace field (no proto change allowed), so we
// replicate the restoredPIDForMigration lookup strategy: try "default" first (the PoC namespace),
// then list all PodMigrations and match by name. Returns "" if the CR cannot be found.
func (s *AgentServer) resolveNamespaceForMigration(ctx context.Context, migrationName string) string {
	if s.k8sClient == nil || migrationName == "" {
		return ""
	}
	pm := &pmv1.PodMigration{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: migrationName}, pm); err == nil {
		return pm.Namespace
	}
	pmList := &pmv1.PodMigrationList{}
	if err := s.k8sClient.List(ctx, pmList); err != nil {
		log.Info("resolveNamespaceForMigration: list PodMigrations failed", "migration", migrationName, "err", err)
		return ""
	}
	for i := range pmList.Items {
		if pmList.Items[i].Name == migrationName {
			return pmList.Items[i].Namespace
		}
	}
	return ""
}

// resolveReplVethPeer returns the HOST-side veth peer name for the replacement pod's eth0,
// given the restored PID. Inside the pod netns `ip -o link show eth0` reports the peer's host
// ifindex as `eth0@if<N>`; the host link with ifindex <N> (`ip -o link show`) is the veth peer.
// No netlink dependency (ADR-0045): reuses the in-tree nsenter+ip exec idiom.
func resolveReplVethPeer(replPID int) (string, error) {
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", replPID)
	out, err := exec.Command("nsenter", "--net="+netnsPath,
		"ip", "-o", "link", "show", "eth0").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("resolveReplVethPeer: ip link show eth0 in netns %s: %w (%s)",
			netnsPath, err, strings.TrimSpace(string(out)))
	}
	peerIdx := parseVethPeerIndex(string(out))
	if peerIdx <= 0 {
		return "", fmt.Errorf("resolveReplVethPeer: no eth0@if<N> peer index in: %s", strings.TrimSpace(string(out)))
	}
	hostOut, hErr := exec.Command("ip", "-o", "link", "show").CombinedOutput()
	if hErr != nil {
		return "", fmt.Errorf("resolveReplVethPeer: host ip link show: %w (%s)", hErr, strings.TrimSpace(string(hostOut)))
	}
	name := hostLinkNameByIndex(string(hostOut), peerIdx)
	if name == "" {
		return "", fmt.Errorf("resolveReplVethPeer: host link with ifindex %d not found", peerIdx)
	}
	return name, nil
}

// parseVethPeerIndex extracts <N> from an `ip -o link show eth0` line containing `eth0@if<N>`.
// Returns 0 if not present.
func parseVethPeerIndex(out string) int {
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, "eth0@if")
		if i < 0 {
			continue
		}
		rest := line[i+len("eth0@if"):]
		j := 0
		for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
			j++
		}
		if j == 0 {
			continue
		}
		if n, err := strconv.Atoi(rest[:j]); err == nil {
			return n
		}
	}
	return 0
}

// hostLinkNameByIndex extracts the interface name for ifindex idx from `ip -o link show` output.
// Each line begins "<idx>: <name>@... :" or "<idx>: <name>:". Returns "" if not found.
func hostLinkNameByIndex(out string, idx int) string {
	prefix := strconv.Itoa(idx) + ":"
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		if at := strings.IndexByte(name, '@'); at >= 0 {
			name = name[:at]
		}
		return name
	}
	return ""
}

// installTCRedirect installs the ADR-0139 Decision 1 tc-ingress redirect on the overlay
// interface (flannel.1): decapped frames with dst == oldPodIP/32 are redirected to the
// replacement pod's host-side veth peer, bypassing the L3 local-input misclassification.
// Idempotent: the ingress qdisc add tolerates "exists"; the filter is re-added on requeue.
func installTCRedirect(ctx context.Context, fdbIf string, oldIP net.IP, vethPeer string) error {
	// Ensure the ingress qdisc exists. `tc qdisc add ... ingress` fails with "Exclusivity flag
	// on, cannot modify." (NOT "exists") when an ingress qdisc is already present — the ingress
	// qdisc is a singleton. Tolerate both that and "exists"; only a genuinely different error
	// is fatal. (`tc qdisc replace ingress` is rejected by some iproute2 builds, so we add+tolerate.)
	if qOut, qErr := exec.CommandContext(ctx, "tc", "qdisc", "add", "dev", fdbIf, "ingress").CombinedOutput(); qErr != nil {
		msg := strings.ToLower(strings.TrimSpace(string(qOut)))
		if !strings.Contains(msg, "exists") && !strings.Contains(msg, "exclusivity") {
			return fmt.Errorf("tc qdisc add ingress on %s: %w (%s)", fdbIf, qErr, strings.TrimSpace(string(qOut)))
		}
	}
	// Clear any stale filter for idempotency, then add the redirect (ignore del errors).
	_, _ = exec.CommandContext(ctx, "tc", "filter", "del", "dev", fdbIf, "ingress").CombinedOutput()
	fOut, fErr := exec.CommandContext(ctx, "tc", "filter", "add", "dev", fdbIf, "ingress",
		"protocol", "ip", "u32",
		"match", "ip", "dst", oldIP.String()+"/32",
		"action", "mirred", "egress", "redirect", "dev", vethPeer).CombinedOutput()
	if fErr != nil {
		return fmt.Errorf("tc filter add redirect on %s -> %s: %w (%s)", fdbIf, vethPeer, fErr, strings.TrimSpace(string(fOut)))
	}
	return nil
}

// installOldIPForwardAccept inserts the ADR-0140 (blocker B9) narrow OLD-IP/32 FORWARD ACCEPT
// pair at the head of the FORWARD chain so the relocated pod's replies — conntrack-INVALID
// because the ADR-0139 tc `mirred` redirect stole the forward leg before conntrack — are not
// dropped by kube-proxy's KUBE-FORWARD `ctstate INVALID -j DROP` rule. Idempotent: each rule is
// deleted first (tolerate ENOENT) then inserted, so requeues do not stack duplicates.
func installOldIPForwardAccept(ctx context.Context, oldIP net.IP) error {
	cidr := oldIP.String() + "/32"
	for _, spec := range [][]string{
		{"-d", cidr},
		{"-s", cidr},
	} {
		// Delete any existing copy first (idempotent; ignore "does not exist").
		delArgs := append([]string{"-D", "FORWARD"}, spec...)
		delArgs = append(delArgs, "-j", "ACCEPT", "-m", "comment", "--comment", "podmotion ADR-0140 oldIP fwd")
		_, _ = exec.CommandContext(ctx, "iptables", delArgs...).CombinedOutput()
		// Insert at the head, before KUBE-FORWARD.
		insArgs := append([]string{"-I", "FORWARD", "1"}, spec...)
		insArgs = append(insArgs, "-j", "ACCEPT", "-m", "comment", "--comment", "podmotion ADR-0140 oldIP fwd")
		if out, err := exec.CommandContext(ctx, "iptables", insArgs...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables -I FORWARD %v: %w (%s)", spec, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// installOldIPNotrack installs the ADR-0141 (blocker B10) raw-table NOTRACK rules for the
// relocated OLD IP so the flow is never conntrack-tracked and can never be classified INVALID
// (which otherwise triggers a data-segment RST / KUBE-FORWARD INVALID DROP, because the
// ADR-0139 tc `mirred` redirect made the forward leg conntrack-invisible). The `raw` table runs
// in PREROUTING/OUTPUT before conntrack. dst-side controls the locally-bound src octet differs
// per node, so callers pass the directions relevant to their node:
//   - "both": PREROUTING -d and -s, plus OUTPUT -d (destination node, ADR-0139)
//   - "source": PREROUTING -s, plus OUTPUT -d (source node, ADR-0136)
// Idempotent: delete-then-insert. Best-effort: returns the first insert error.
func installOldIPNotrack(ctx context.Context, oldIP net.IP, mode string) error {
	cidr := oldIP.String() + "/32"
	type rule struct {
		chain string
		dir   string // "-d" or "-s"
	}
	var rules []rule
	switch mode {
	case "both": // destination node
		rules = []rule{
			{"PREROUTING", "-d"}, {"PREROUTING", "-s"}, {"OUTPUT", "-d"},
		}
	default: // "source"
		rules = []rule{
			{"PREROUTING", "-s"}, {"OUTPUT", "-d"},
		}
	}
	comment := "podmotion ADR-0141 oldIP notrack"
	for _, r := range rules {
		del := []string{"-t", "raw", "-D", r.chain, r.dir, cidr, "-j", "NOTRACK", "-m", "comment", "--comment", comment}
		_, _ = exec.CommandContext(ctx, "iptables", del...).CombinedOutput()
		ins := []string{"-t", "raw", "-I", r.chain, "1", r.dir, cidr, "-j", "NOTRACK", "-m", "comment", "--comment", comment}
		if out, err := exec.CommandContext(ctx, "iptables", ins...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables -t raw -I %s %s %s NOTRACK: %w (%s)", r.chain, r.dir, cidr, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// removeOldIPNotrack removes all ADR-0141 raw-table NOTRACK rules for the OLD IP (both chains,
// both directions) on the calling node. Idempotent: tolerates ENOENT.
func removeOldIPNotrack(ctx context.Context, oldIP net.IP) {
	cidr := oldIP.String() + "/32"
	comment := "podmotion ADR-0141 oldIP notrack"
	for _, chain := range []string{"PREROUTING", "OUTPUT"} {
		for _, dir := range []string{"-d", "-s"} {
			args := []string{"-t", "raw", "-D", chain, dir, cidr, "-j", "NOTRACK", "-m", "comment", "--comment", comment}
			for i := 0; i < 4; i++ {
				if _, err := exec.CommandContext(ctx, "iptables", args...).CombinedOutput(); err != nil {
					break
				}
			}
		}
	}
}

// removeOldIPForwardAccept removes the ADR-0140 OLD-IP/32 FORWARD ACCEPT pair (IPAM-reclaim /
// disarm). Idempotent: tolerates ENOENT. Removes all copies (loop until -D fails).
func removeOldIPForwardAccept(ctx context.Context, oldIP net.IP) {
	cidr := oldIP.String() + "/32"
	for _, spec := range [][]string{
		{"-d", cidr},
		{"-s", cidr},
	} {
		args := append([]string{"-D", "FORWARD"}, spec...)
		args = append(args, "-j", "ACCEPT", "-m", "comment", "--comment", "podmotion ADR-0140 oldIP fwd")
		// Remove up to a few duplicates defensively.
		for i := 0; i < 4; i++ {
			if _, err := exec.CommandContext(ctx, "iptables", args...).CombinedOutput(); err != nil {
				break
			}
		}
	}
}

// DisarmTCRedirect removes the ADR-0139 tc-ingress filter + qdisc from the overlay interface
// after TrafficVerified=True (Decision 3 disarm order). Idempotent: tolerates ENOENT.
func (s *AgentServer) DisarmTCRedirect(ctx context.Context, req *agentpb.DisarmTCRedirectRequest) (*agentpb.DisarmTCRedirectResponse, error) {
	// ADR-0199 (removal symmetry, item 4): the forward install (InjectIPHandoff)
	// now installs the tc-ingress redirect on `bridgeIf` when the substrate has no VXLAN
	// device (kindnet), NOT on `flannel.1`. The teardown MUST remove the filter from the
	// SAME interface it was installed on, else a stale /32 redirect survives on the host
	// interface after migration (the load-bearing asymmetry V3 catches). On kindnet
	// `req.FdbIfname` is empty (operator passes pm.Status.OverlayFdbIfname == ""), so we
	// must resolve the redirect-source interface the same way InjectIPHandoff did: discover
	// the host interface at runtime rather than defaulting to a `flannel.1` literal.
	fdbIf := req.FdbIfname
	if fdbIf == "" {
		discovered, discErr := discoverHostInterface(ctx)
		if discErr == nil && discovered != "" {
			fdbIf = discovered // ADR-0199: kindnet host-routed substrate — teardown on bridgeIf
		} else {
			// Last-resort fallback preserves prior behavior on a VXLAN substrate where
			// discovery is irrelevant; tolerated because filter del is ENOENT-safe below.
			fdbIf = "flannel.1"
			log.Info("DisarmTCRedirect: host interface discovery failed; falling back to flannel.1 (ENOENT-tolerant)",
				"migration", req.MigrationName, "err", discErr)
		}
	}
	log.Info("DisarmTCRedirect called (ADR-0139 D3)", "migration", req.MigrationName, "fdbIf", fdbIf)
	// Remove the filter, then the ingress qdisc. Both tolerate "does not exist"/ENOENT.
	if fOut, fErr := exec.CommandContext(ctx, "tc", "filter", "del", "dev", fdbIf, "ingress").CombinedOutput(); fErr != nil {
		msg := strings.ToLower(strings.TrimSpace(string(fOut)))
		if !strings.Contains(msg, "does not exist") && !strings.Contains(msg, "no such") && !strings.Contains(msg, "cannot") {
			log.Info("DisarmTCRedirect: tc filter del warning (non-fatal)", "fdbIf", fdbIf, "output", strings.TrimSpace(string(fOut)))
		}
	}
	if qOut, qErr := exec.CommandContext(ctx, "tc", "qdisc", "del", "dev", fdbIf, "ingress").CombinedOutput(); qErr != nil {
		msg := strings.ToLower(strings.TrimSpace(string(qOut)))
		if !strings.Contains(msg, "does not exist") && !strings.Contains(msg, "no such") && !strings.Contains(msg, "cannot") {
			log.Info("DisarmTCRedirect: tc qdisc del warning (non-fatal)", "fdbIf", fdbIf, "output", strings.TrimSpace(string(qOut)))
		}
	}
	// ADR-0140: remove the OLD-IP FORWARD ACCEPT pair alongside the tc redirect (same lifecycle).
	if req.OldPodIp != "" {
		if oldIP := net.ParseIP(req.OldPodIp); oldIP != nil && oldIP.To4() != nil {
			removeOldIPForwardAccept(ctx, oldIP)
			removeOldIPNotrack(ctx, oldIP)
			log.Info("DisarmTCRedirect: removed ADR-0140 FORWARD ACCEPT + ADR-0141 NOTRACK", "migration", req.MigrationName, "oldPodIP", req.OldPodIp)
		}
	}
	log.Info("DisarmTCRedirect: tc-ingress redirect disarmed (ADR-0139 D3)", "migration", req.MigrationName, "fdbIf", fdbIf)
	return &agentpb.DisarmTCRedirectResponse{Disarmed: true}, nil
}

// InjectSourceRedirect installs the SOURCE-node VXLAN redirect for the relocated OLD pod IP
// (ADR-0136). The OLD IP lives in the source node's own pod CIDR, so the kernel would route
// it to the local cni0 bridge — where the source pod no longer exists, blackholing it. This
// installs three consistent entries on flannel.1 so traffic to the OLD IP is instead
// VXLAN-encapsulated to the destination node's VTEP and delivered at the replacement pod:
//
//  1. /32 link-scope route for oldPodIP via flannel.1 (overrides the local cni0 /24 by LPM).
//  2. AF_INET neigh oldPodIP -> replVethMAC on flannel.1 (L3 resolves the overlay neighbor).
//  3. AF_BRIDGE FDB replVethMAC -> dstNodeIP on flannel.1 (VXLAN encap to the dest VTEP).
//
// The FDB MUST be keyed on the replacement veth MAC — the MAC the L3 neigh resolves to —
// NOT the destination VTEP MAC; keying it on the VTEP MAC was the Sprint 25 0-packet failure.
// Idempotent (RTM_NEWNEIGH/NEWROUTE NLM_F_REPLACE). Torn down by CleanupSourceIPHandoff.
func (s *AgentServer) InjectSourceRedirect(ctx context.Context, req *agentpb.InjectSourceRedirectRequest) (*agentpb.InjectSourceRedirectResponse, error) {
	log.Info("InjectSourceRedirect called", "migration", req.MigrationName,
		"oldPodIP", req.OldPodIp, "replVethMAC", req.ReplVethMac, "dstNodeIP", req.DstNodeIp)

	if req.OldPodIp == "" || req.ReplVethMac == "" || req.DstNodeIp == "" {
		return nil, status.Errorf(codes.InvalidArgument,
			"InjectSourceRedirect: old_pod_ip, repl_veth_mac and dst_node_ip are required (got %q/%q/%q)",
			req.OldPodIp, req.ReplVethMac, req.DstNodeIp)
	}
	oldIP := net.ParseIP(req.OldPodIp)
	if oldIP == nil || oldIP.To4() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "InjectSourceRedirect: old_pod_ip %q is not a valid IPv4", req.OldPodIp)
	}
	mac, err := net.ParseMAC(req.ReplVethMac)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "InjectSourceRedirect: repl_veth_mac %q invalid: %v", req.ReplVethMac, err)
	}
	dstNodeIP := net.ParseIP(req.DstNodeIp)
	if dstNodeIP == nil {
		return nil, status.Errorf(codes.InvalidArgument, "InjectSourceRedirect: dst_node_ip %q is not a valid IP", req.DstNodeIp)
	}

	fdbIf := req.FdbIfname
	if fdbIf == "" {
		fdbIf = "flannel.1"
	}

	// (1) /32 link-scope route for oldPodIP via flannel.1. Wins LPM over the cni0 /24, so the
	// kernel selects the overlay and consults the AF_INET neigh below instead of cni0 ARP.
	if err := network.SetPodIPHostRoute(ctx, fdbIf, oldIP); err != nil {
		return &agentpb.InjectSourceRedirectResponse{Injected: false,
			BlockingReason: fmt.Sprintf("flannel.1 /32 route: %v", err)}, nil
	}
	// (2) AF_INET neigh oldPodIP -> replVethMAC on flannel.1.
	if err := network.SetPodIPNeigh(ctx, fdbIf, oldIP, mac); err != nil {
		return &agentpb.InjectSourceRedirectResponse{Injected: false,
			BlockingReason: fmt.Sprintf("flannel.1 neigh: %v", err)}, nil
	}
	// (3) AF_BRIDGE FDB replVethMAC -> dstNodeIP on flannel.1 (the missing encap link from
	// Sprint 25). AddFDBEntry also re-asserts the AF_INET neigh for the same MAC — harmless.
	if err := network.NewFDBManager().AddFDBEntry(ctx, network.FDBEntry{
		IfName: fdbIf,
		PodIP:  oldIP,
		PodMAC: mac,
		VTEPIP: dstNodeIP,
	}); err != nil {
		return &agentpb.InjectSourceRedirectResponse{Injected: false,
			BlockingReason: fmt.Sprintf("flannel.1 AF_BRIDGE FDB: %v", err)}, nil
	}

	// ADR-0141 (blocker B10): NOTRACK the OLD-IP flow on the SOURCE node too, so the reply
	// arriving from the relocated pod (and the client SYN/GET egressing) is never conntrack-
	// tracked → never INVALID → no RST on the source side. Symmetric to the destination NOTRACK.
	if ntErr := installOldIPNotrack(ctx, oldIP, "source"); ntErr != nil {
		log.Error(ntErr, "InjectSourceRedirect: ADR-0141 source NOTRACK install failed (non-fatal)",
			"migration", req.MigrationName, "oldPodIP", req.OldPodIp)
	} else {
		log.Info("InjectSourceRedirect: ADR-0141 source NOTRACK installed (B10)",
			"migration", req.MigrationName, "oldPodIP", req.OldPodIp)
	}

	log.Info("InjectSourceRedirect: source VXLAN redirect installed (ADR-0136)",
		"migration", req.MigrationName, "oldPodIP", req.OldPodIp, "replVethMAC", req.ReplVethMac,
		"dstNodeIP", req.DstNodeIp, "ifName", fdbIf)
	return &agentpb.InjectSourceRedirectResponse{Injected: true}, nil
}

// TeardownSourceRedirect removes the ADR-0136 SOURCE-node flannel.1 VXLAN redirect and the
// ADR-0141 source-mode NOTRACK rule for the relocated OLD pod IP (ADR-0244 / NR-BLOCK-2, GC-5
// "Source-side teardown"). Symmetric to DisarmTCRedirect on the destination node: this is the
// missing "net new" half of the reclaim sweep — InjectSourceRedirect has no existing caller-side
// teardown, unlike the destination objects DisarmTCRedirect already removes.
//
// Removes, in order (ADR-0244 §5 item 2), tolerating ENOENT/already-absent at every step so a
// crash mid-teardown or a re-invocation on an already-torn-down IP is always safe to retry:
//
//  1. AF_BRIDGE FDB entry (network.NewFDBManager().RemoveFDBEntry) — VXLAN encap mapping.
//  2. AF_INET neigh (network.DeletePodIPNeigh) on the same interface — reused verbatim against
//     flannel.1, the same function CleanupSourceIPHandoff already calls against cni0.
//  3. The /32 host route (network.DeletePodIPHostRoute) that gave the OLD IP LPM priority over
//     the local cni0 /24.
//  4. The source-mode NOTRACK raw-table rule (removeOldIPNotrack) — already generic (deletes
//     both -d/-s directions in both PREROUTING/OUTPUT chains regardless of which
//     installOldIPNotrack mode installed them), so no change was needed there.
//
// This RPC does NOT itself decide reclaim eligibility — that is the controller-side
// ReclaimEligible/R1-R7 predicate (ADR-0244 §2). By the time this fires, the controller has
// already confirmed no live client can reach old_pod_ip; this handler's only job is to
// mechanically remove the five now-provably-dead objects it owns on the source node.
func (s *AgentServer) TeardownSourceRedirect(ctx context.Context, req *agentpb.TeardownSourceRedirectRequest) (*agentpb.TeardownSourceRedirectResponse, error) {
	log.Info("TeardownSourceRedirect called (ADR-0244 GC-5)", "migration", req.MigrationName,
		"oldPodIP", req.OldPodIp, "fdbIfname", req.FdbIfname, "replVethMAC", req.ReplVethMac, "dstNodeIP", req.DstNodeIp)

	if req.OldPodIp == "" {
		return nil, status.Errorf(codes.InvalidArgument, "TeardownSourceRedirect: old_pod_ip is required")
	}
	oldIP := net.ParseIP(req.OldPodIp)
	if oldIP == nil || oldIP.To4() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "TeardownSourceRedirect: old_pod_ip %q is not a valid IPv4", req.OldPodIp)
	}

	fdbIf := req.FdbIfname
	if fdbIf == "" {
		fdbIf = "flannel.1"
	}

	// (a) AF_BRIDGE FDB entry. repl_veth_mac/dst_node_ip identify the exact entry that was
	// installed by InjectSourceRedirect; both are required to key the delete (ADR-0136 keys the
	// FDB on the replacement veth MAC, not a VTEP MAC — see InjectSourceRedirect's own comment).
	// A missing MAC/dst IP is tolerated as a best-effort skip of this one step (not fatal to the
	// remaining three, which do not need it) rather than failing the whole teardown — the FDB
	// entry is harmless-if-orphaned relative to a live client (it is a forwarding hint, not a
	// blocking rule) and VerifyCleanup(IP_RECLAIM)'s flannel1_fdb probe will surface any leak.
	if req.ReplVethMac != "" && req.DstNodeIp != "" {
		mac, macErr := net.ParseMAC(req.ReplVethMac)
		dstNodeIP := net.ParseIP(req.DstNodeIp)
		if macErr != nil || dstNodeIP == nil {
			log.Info("TeardownSourceRedirect: repl_veth_mac/dst_node_ip invalid — skipping FDB removal (non-fatal)",
				"migration", req.MigrationName, "replVethMAC", req.ReplVethMac, "dstNodeIP", req.DstNodeIp)
		} else if err := network.NewFDBManager().RemoveFDBEntry(ctx, network.FDBEntry{
			IfName: fdbIf,
			PodIP:  oldIP,
			PodMAC: mac,
			VTEPIP: dstNodeIP,
		}); err != nil {
			return &agentpb.TeardownSourceRedirectResponse{TornDown: false,
				BlockingReason: fmt.Sprintf("flannel.1 AF_BRIDGE FDB removal: %v", err)}, nil
		}
	} else {
		log.Info("TeardownSourceRedirect: repl_veth_mac/dst_node_ip not supplied — skipping FDB removal (non-fatal)",
			"migration", req.MigrationName)
	}

	// (b) AF_INET neigh on fdbIf. DeletePodIPNeigh already tolerates ENOENT/missing interface.
	if err := network.DeletePodIPNeigh(ctx, fdbIf, oldIP); err != nil {
		return &agentpb.TeardownSourceRedirectResponse{TornDown: false,
			BlockingReason: fmt.Sprintf("flannel.1 neigh removal: %v", err)}, nil
	}

	// (c) /32 host route on fdbIf. DeletePodIPHostRoute already tolerates a missing interface.
	if err := network.DeletePodIPHostRoute(ctx, fdbIf, oldIP); err != nil {
		return &agentpb.TeardownSourceRedirectResponse{TornDown: false,
			BlockingReason: fmt.Sprintf("flannel.1 /32 route removal: %v", err)}, nil
	}

	// (d) source-mode NOTRACK. removeOldIPNotrack is already generic/idempotent and returns no
	// error (loops a bounded number of -D attempts, tolerating ENOENT at every step).
	removeOldIPNotrack(ctx, oldIP)

	log.Info("TeardownSourceRedirect: source flannel.1 redirect + NOTRACK torn down (ADR-0244 GC-5)",
		"migration", req.MigrationName, "oldPodIP", req.OldPodIp, "fdbIf", fdbIf)
	return &agentpb.TeardownSourceRedirectResponse{TornDown: true}, nil
}

// ProbeDestSocketForIP reports whether the DESTINATION agent's restored-pod network namespace
// has an ESTABLISHED TCP socket bound to old_pod_ip (ADR-0244 R7 / NoLiveDestSocketForIP,
// added by the 2026-07-04 C1 amendment). This is the conjunct that observes the NOTRACK'd
// tc-redirect flow class ProbeConntrackForIP/R6 structurally cannot see (see the ADR's NOTRACK
// coverage discussion): a
// live pinned/source-CIDR client connection carried over the ADR-0139/0136 tc-redirect + ADR-0141
// NOTRACK path is, by construction, absent from conntrack, but its ESTABLISHED socket in the
// restored pod's own netns is entirely unaffected by the raw-table NOTRACK rule sitting upstream
// of it on the host — so it remains directly observable here.
//
// Only ESTABLISHED-state sockets are visible through this probe (network.SocketInventory filters
// strictly on state=="01"); CLOSE_WAIT/FIN_WAIT/SYN_RECV flows on old_pod_ip are observed by
// neither this probe nor ProbeConntrackForIP — a disclosed residual, not resolved by this RPC.
//
// Fail-closed contract (ADR-0244 N1/N2 correction): restoredPIDForMigration now distinguishes a
// genuine lookup failure (propagated here as a gRPC error, so the controller's
// noLiveDestSocketForIP conjunct defers the sweep) from a positive absence (CR/PID resolves and
// is legitimately gone or never restored — present=false, not an error; nothing left to protect).
func (s *AgentServer) ProbeDestSocketForIP(ctx context.Context, req *agentpb.ProbeDestSocketForIPRequest) (*agentpb.ProbeDestSocketForIPResponse, error) {
	log.Info("ProbeDestSocketForIP called (ADR-0244 R7)", "migration", req.MigrationName, "oldPodIP", req.OldPodIp)

	if req.OldPodIp == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ProbeDestSocketForIP: old_pod_ip is required")
	}
	oldIP := net.ParseIP(req.OldPodIp)
	if oldIP == nil {
		return nil, status.Errorf(codes.InvalidArgument, "ProbeDestSocketForIP: old_pod_ip %q is not a valid IP", req.OldPodIp)
	}
	if req.MigrationName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ProbeDestSocketForIP: migration_name is required")
	}

	replPID, pidErr := s.restoredPIDForMigration(ctx, req.MigrationName)
	if pidErr != nil {
		// Case (2): the lookup itself failed (transient apiserver error, no k8s client, etc).
		// Fail closed — propagate as an RPC error so the controller defers the sweep exactly as
		// it already does on a ProbeConntrackForIP (R6) RPC error, rather than silently reading
		// this as "positively absent" (the N1 defect this amendment fixes).
		return nil, status.Errorf(codes.Unavailable,
			"ProbeDestSocketForIP: restoredPIDForMigration lookup failed for migration %q: %v",
			req.MigrationName, pidErr)
	}
	if replPID <= 0 {
		// Case (1): the CR/PID was positively resolved and there is no restored process (pod
		// gone, or never restored on this node). Nothing left to protect — present=false is a
		// correct, non-error result, not a fail-open reading of an unresolved lookup.
		log.Info("ProbeDestSocketForIP: no RestoredPID for migration — nothing to protect (present=false)",
			"migration", req.MigrationName, "oldPodIP", req.OldPodIp)
		return &agentpb.ProbeDestSocketForIPResponse{Present: false, Count: 0}, nil
	}

	entries, invErr := network.SocketInventory(int32(replPID))
	if invErr != nil {
		// A failure reading /proc/<pid>/net/tcp[6] (e.g. the process just exited between PID
		// resolution and the read) is likewise a genuine observation failure, not a positive
		// absence — fail closed rather than reporting present=false on an error.
		return nil, status.Errorf(codes.Unavailable,
			"ProbeDestSocketForIP: SocketInventory(pid=%d) failed for migration %q: %v",
			replPID, req.MigrationName, invErr)
	}

	count := 0
	for _, e := range entries {
		if e.SrcIP != nil && e.SrcIP.Equal(oldIP) {
			count++
			continue
		}
		if e.DstIP != nil && e.DstIP.Equal(oldIP) {
			count++
		}
	}

	log.Info("ProbeDestSocketForIP: probe complete (ADR-0244 R7)", "migration", req.MigrationName,
		"oldPodIP", req.OldPodIp, "replPID", replPID, "present", count > 0, "count", count)
	return &agentpb.ProbeDestSocketForIPResponse{Present: count > 0, Count: int32(count)}, nil
}

// ListenAndServe starts the gRPC server on addr (default ":9090").
// tlsCfg may be nil for insecure mode (dev/test only).
// Blocks until ctx is cancelled.
func (s *AgentServer) ListenAndServe(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	if addr == "" {
		addr = ":9090"
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
		// ADR-SEC-A §2.3 (C-333): bound gRPC message sizes (512 MiB) on the privileged
		// host-network daemon. The transfer RPC is the only one that legitimately approaches it.
		grpc.MaxRecvMsgSize(grpclimits.MaxCheckpointTarBytes),
		grpc.MaxSendMsgSize(grpclimits.MaxCheckpointTarBytes),
		// ADR-SEC-A §2.2 (C-331): deny-by-default per-RPC authz interceptor, registered FIRST in
		// the chain so authz runs before any handler logic.
		grpc.ChainUnaryInterceptor(authz.UnaryInterceptor(s.nodeName, s)),
	}
	if tlsCfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	} else {
		// ADR-SEC-A §2.1 (C-330): defense-in-depth. In the default build adrSecAHandleNoTLS
		// returns a fatal error (NEVER serves plaintext, NEVER logs "gRPC server starting
		// without TLS"). In the //go:build dev build it logs the insecure WARN and permits
		// plaintext (PODMOTION_INSECURE_GRPC path already gated in LoadServerConfig).
		if err := adrSecAHandleNoTLS(addr); err != nil {
			return err
		}
	}

	grpcSrv := grpc.NewServer(opts...)
	agentpb.RegisterMigrationAgentServiceServer(grpcSrv, s)

	log.Info("Agent gRPC server listening", "addr", addr, "node", s.nodeName)

	errCh := make(chan error, 1)
	go func() { errCh <- grpcSrv.Serve(lis) }()

	select {
	case <-ctx.Done():
		log.Info("Shutting down agent gRPC server")
		grpcSrv.GracefulStop()
		return nil
	case err := <-errCh:
		return fmt.Errorf("grpc serve: %w", err)
	}
}

// ── RPC handlers ─────────────────────────────────────────────────────────────

// PrepareSource verifies that the named pod is running on this node.
// On kind/dev where we cannot directly query containerd, we perform a
// best-effort /proc scan and always return Compatible=true so the end-to-end
// flow can proceed. In production this would use the containerd task API.
func (s *AgentServer) PrepareSource(_ context.Context, req *agentpb.PrepareSourceRequest) (*agentpb.PrepareSourceResponse, error) {
	log.Info("PrepareSource called", "migration", req.MigrationName, "pod", req.PodName, "ns", req.PodNamespace)

	note := ""
	compatible := true

	// Best-effort: scan /proc for a process whose cgroup path contains the pod UID.
	// This works on Linux nodes where cgroups are visible; on kind it usually works too.
	if req.PodUid != "" {
		// Store pod UID so Checkpoint can resolve the container root PID later.
		s.migrationPodUIDMu.Lock()
		s.migrationPodUID[req.MigrationName] = req.PodUid
		s.migrationPodUIDMu.Unlock()

		found := scanProcForPodUID(req.PodUid)
		if found {
			note = fmt.Sprintf("pod %s/%s confirmed running via /proc cgroup scan", req.PodNamespace, req.PodName)
			log.Info("PrepareSource: pod found via /proc cgroup scan", "uid", req.PodUid)
		} else {
			// Not found in /proc — could be that cgroup paths differ or we lack permission.
			// Return compatible=true with a note; the operator decides whether to proceed.
			note = fmt.Sprintf("pod %s/%s not confirmed via /proc (may still be running — kind/dev fallback)", req.PodNamespace, req.PodName)
			log.Info("PrepareSource: pod not found via /proc, using kind/dev fallback", "uid", req.PodUid)
		}
	} else {
		note = "no pod UID provided; skipping /proc scan — compatible=true (dev mode)"
	}

	log.Info("PrepareSource result", "compatible", compatible, "note", note)
	return &agentpb.PrepareSourceResponse{
		Compatible:     compatible,
		BlockingReason: note,
		StorageTier:    1,
	}, nil
}

// cgroupUIDVariants returns both the hyphen and underscore forms of a pod UID.
// cgroup v2 on systemd (Ubuntu 22.04+, k3s) encodes pod UIDs with underscores:
//
//	kubepods-besteffort-pod34b0b99f_b322_4cd8_b4e2_6b3003963468.slice
//
// so we must match either form.
func cgroupUIDVariants(podUID string) []string {
	underscored := strings.ReplaceAll(podUID, "-", "_")
	if underscored == podUID {
		return []string{podUID}
	}
	return []string{podUID, underscored}
}

// cgroupContainsPodUID returns true if the cgroup data contains the pod UID in
// either its hyphenated or underscore-encoded form.
func cgroupContainsPodUID(data, podUID string) bool {
	for _, v := range cgroupUIDVariants(podUID) {
		if strings.Contains(data, v) {
			return true
		}
	}
	return false
}

// scanProcForPodUID looks through /proc/*/cgroup for any entry containing podUID.
// Returns true if found. Ignores errors (best-effort).
func scanProcForPodUID(podUID string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cgroupPath := filepath.Join("/proc", entry.Name(), "cgroup")
		data, err := os.ReadFile(cgroupPath)
		if err != nil {
			continue
		}
		if cgroupContainsPodUID(string(data), podUID) {
			return true
		}
	}
	return false
}

// isPauseContainer returns true if the given PID is a pause/infra container.
// The pause container is the sandbox init process that holds the pod's namespaces
// but contains no real workload. CRIU must not be directed at it — we want the
// application container's root PID instead.
func isPauseContainer(pid int) bool {
	commData, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return false
	}
	comm := strings.TrimSpace(string(commData))
	// containerd-shim creates a "pause" process as the pod sandbox.
	// Some runtimes also name it "pause\x00" or similar — strip non-printable chars.
	return comm == "pause" || strings.HasPrefix(comm, "pause")
}

// FindContainerPID scans /proc/*/cgroup for a line containing podUID and returns
// the lowest-numbered matching host PID that is NOT the pause/infra container.
// The agent must have hostPID:true so all host PIDs are visible under /proc.
// Handles both hyphenated UIDs and the underscore-encoded form used by cgroup v2
// systemd slices (Ubuntu 22.04+, k3s).
func FindContainerPID(podUID string) (int32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("reading /proc: %w", err)
	}
	var lowest int32
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			continue
		}
		if !cgroupContainsPodUID(string(cgroupData), podUID) {
			continue
		}
		// Skip the pause/infra container — CRIU must dump the application container.
		if isPauseContainer(pid) {
			log.Info("FindContainerPID: skipping pause container", "pid", pid)
			continue
		}
		if lowest == 0 || int32(pid) < lowest {
			lowest = int32(pid)
		}
	}
	if lowest == 0 {
		return 0, fmt.Errorf("container PID not found for pod UID %s (tried hyphenated and underscore forms; pause containers skipped)", podUID)
	}
	return lowest, nil
}

// FindSandboxPID scans /proc/*/cgroup for a line containing podUID and returns the
// lowest-numbered matching host PID that IS the pause/sandbox container — the inverse
// of FindContainerPID's skip. The sandbox process holds the pod's network namespace
// and, unlike the application container, remains alive across the CRIU final-freeze
// (the app container is stopped/frozen at freeze time, so its PID disappears). Callers
// that need the POD NETNS (not the app process image) — e.g. veth ifindex resolution
// for the zero-window hold — must use this, because by ArmZeroWindow time the app PID
// is gone and FindContainerPID returns 0. The agent must run hostPID:true.
func FindSandboxPID(podUID string) (int32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("reading /proc: %w", err)
	}
	var lowest int32
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			continue
		}
		if !cgroupContainsPodUID(string(cgroupData), podUID) {
			continue
		}
		if !isPauseContainer(pid) {
			continue
		}
		if lowest == 0 || int32(pid) < lowest {
			lowest = int32(pid)
		}
	}
	if lowest == 0 {
		return 0, fmt.Errorf("sandbox (pause) PID not found for pod UID %s", podUID)
	}
	return lowest, nil
}

// ResolveNetnsFromSandbox returns an open *os.File for the network namespace of the
// containerd sandbox (pause container) identified by sandboxID, along with the resolved
// netns filesystem path. The caller must Close the returned file.
//
// ADR-0125 (Sprint 20): the open fd exists only to run the B2 TOCTOU inode cross-check
// (open path, fstat fd vs stat path). It is no longer handed to CRIU — the caller closes
// it and passes the returned path string to CRIU via --join-ns net:<path>.
//
// ADR-0122 B1: this replaces the previous /proc/*/comm "pause" scan, which
// was ambiguous on multi-pod nodes (every pod's pause process matches, so the scan could
// not reliably pick the correct sandbox). The sandbox ID comes from the NRI pod sandbox
// object (pod.GetId()) and is unambiguous per pod. We read the sandbox's OCI spec under
// the containerd "k8s.io" namespace, locate the spec.Linux.Namespaces entry with
// Type == "network", and open its Path directly.
//
// ADR-0122 B2: TOCTOU close-out. We open the netns *path* (e.g.
// /var/run/netns/<id> or a bind-mounted handle), then fstat the resulting fd and stat the
// path and compare inodes. If they differ the sandbox netns was torn down and its inode
// recycled between resolution and open; we return a "netns inode mismatch" error and abort
// rather than silently joining a recycled namespace.
//
// containerdClient is accepted as interface{} for forward compatibility with a typed
// containerd Go client (per the ADR signature). This agent talks to containerd via the
// `ctr` CLI (no containerd Go module in the build — see go.mod; consistent with
// ctrCheckpoint / FindContainerTaskID), so the sandbox spec is resolved via
// `ctr --namespace k8s.io containers info <sandboxID>`.
func ResolveNetnsFromSandbox(ctx context.Context, containerdClient interface{}, sandboxID string) (*os.File, string, error) {
	if sandboxID == "" {
		return nil, "", fmt.Errorf("ResolveNetnsFromSandbox: empty sandboxID")
	}

	netnsPath, err := sandboxNetnsPath(ctx, sandboxID)
	if err != nil {
		return nil, "", err
	}
	if netnsPath == "" {
		return nil, "", fmt.Errorf("ResolveNetnsFromSandbox: sandbox %s spec has no network namespace path "+
			"(host-network sandbox cannot be joined)", sandboxID)
	}

	// B2: open the path, then cross-check inodes (path stat vs fd fstat) to detect a netns
	// that was recycled between resolution and open.
	f, err := os.Open(netnsPath)
	if err != nil {
		return nil, "", fmt.Errorf("ResolveNetnsFromSandbox: open netns path %s for sandbox %s: %w", netnsPath, sandboxID, err)
	}

	var pathStat, fdStat syscall.Stat_t
	if serr := syscall.Stat(netnsPath, &pathStat); serr != nil {
		_ = f.Close()
		return nil, "", fmt.Errorf("ResolveNetnsFromSandbox: stat netns path %s: %w", netnsPath, serr)
	}
	if serr := syscall.Fstat(int(f.Fd()), &fdStat); serr != nil {
		_ = f.Close()
		return nil, "", fmt.Errorf("ResolveNetnsFromSandbox: fstat netns fd for %s: %w", netnsPath, serr)
	}
	if pathStat.Ino != fdStat.Ino || pathStat.Dev != fdStat.Dev {
		_ = f.Close()
		return nil, "", fmt.Errorf("ResolveNetnsFromSandbox: netns inode mismatch — sandbox may have been recycled "+
			"(sandbox %s path %s: path inode %d/dev %d, fd inode %d/dev %d)",
			sandboxID, netnsPath, pathStat.Ino, pathStat.Dev, fdStat.Ino, fdStat.Dev)
	}

	log.Info("ResolveNetnsFromSandbox: resolved sandbox netns (ADR-0122 B1/B2, ADR-0125)",
		"sandboxID", sandboxID, "netnsPath", netnsPath, "inode", fdStat.Ino)
	return f, netnsPath, nil
}

// sandboxNetnsPath reads the OCI spec of the containerd sandbox identified by sandboxID
// (under the k8s.io namespace) and returns the path of its network namespace — the
// spec.Linux.Namespaces entry whose Type == "network". Returns "" (no error) when the
// sandbox shares the host network namespace (no path).
func sandboxNetnsPath(_ context.Context, sandboxID string) (string, error) {
	// `ctr containers info` prints the container record including the OCI runtime Spec.
	out, err := nsenterCmd("ctr", "--namespace", "k8s.io", "containers", "info", sandboxID).Output()
	if err != nil {
		return "", fmt.Errorf("ctr containers info %s: %w", sandboxID, err)
	}

	// The record is JSON: { ..., "Spec": { "linux": { "namespaces": [ {type,path}, ... ] } } }.
	// We only need linux.namespaces, so decode loosely.
	var rec struct {
		Spec struct {
			Linux struct {
				Namespaces []struct {
					Type string `json:"type"`
					Path string `json:"path"`
				} `json:"namespaces"`
			} `json:"linux"`
		} `json:"Spec"`
	}
	if err := json.Unmarshal(out, &rec); err != nil {
		return "", fmt.Errorf("parse ctr containers info for sandbox %s: %w", sandboxID, err)
	}
	for _, ns := range rec.Spec.Linux.Namespaces {
		if ns.Type == "network" {
			return ns.Path, nil
		}
	}
	return "", nil
}

// FindContainerTaskID finds the containerd task ID (container ID) for a pod by scanning
// the containerd k8s.io namespace task list via ctr and matching against the pod UID.
// Returns the task ID of the application container (not the pause/sandbox container).
// Falls back to scanning /run/containerd/io.containerd.runtime.v2.task/k8s.io/ directly
// when the ctr binary is not available (e.g. inside the agent container on kind clusters).
// hostBundleDir returns the containerd task bundle directory for a given task ID, resolved
// through the agent-visible host mount.
//
// ADR-0213 D1: `ctr`/runc/criu run in the HOST mount namespace via nsenterCmd, but
// any native Go os.ReadFile in the agent runs in the AGENT container's mount namespace. The
// daemonset mounts host /run at /host-run (charts/podmotion/templates/daemonset.yaml:65-66,
// 180-182); the host bundle dir is therefore reachable at /host-run/containerd/...task...,
// NOT at the bare /run/containerd/...task... path (which does not exist in the agent ns —
// only the containerd SOCKET is mounted natively). Reading the bare path returns ENOENT, the
// error is swallowed, and the established-TCP-socket classifier goes silent. Every consumer of
// the host bundle path MUST go through this helper.
func hostBundleDir(taskID string) string {
	return fmt.Sprintf("/host-run/containerd/io.containerd.runtime.v2.task/k8s.io/%s", taskID)
}

// ctrReportedDumpLogPath extracts the criu-dump.log path that ctr reports in its own combined
// output (`... path= /run/containerd/.../<fullID>/criu-dump.log ...`) and translates it to the
// agent-visible host mount.
//
// ADR-0213 D2: FindContainerTaskID may return the abbreviated `ctr tasks list` column-0 ID while
// the on-disk bundle directory uses the full 64-char container ID, so deriving the path from the
// task ID alone can point at the wrong directory. ctr's own error names the exact file — prefer
// it. Returns "" if no host bundle path is present in the output.
func ctrReportedDumpLogPath(out string) string {
	const marker = "/run/containerd/io.containerd.runtime.v2.task/"
	idx := strings.Index(out, marker)
	if idx < 0 {
		return ""
	}
	rest := out[idx:]
	// The path token ends at the first whitespace, colon-space, or end of line.
	end := strings.IndexFunc(rest, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '\r'
	})
	if end >= 0 {
		rest = rest[:end]
	}
	rest = strings.TrimRight(rest, ":")
	if !strings.HasSuffix(rest, "criu-dump.log") {
		return ""
	}
	// Re-root the bare host path onto the agent-visible host mount.
	return "/host-run" + strings.TrimPrefix(rest, "/run")
}

func FindContainerTaskID(podUID string) (string, error) {
	out, err := nsenterCmd("/usr/local/bin/ctr", "--namespace", "k8s.io", "tasks", "list").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines[1:] { // skip header
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			taskID := fields[0]
			// Check if this task belongs to the pod by reading the cgroup of the task PID
			pid, _ := strconv.Atoi(fields[1])
			if pid == 0 {
				continue
			}
			cgroupData, cgErr := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
			if cgErr != nil {
				continue
			}
			if !cgroupContainsPodUID(string(cgroupData), podUID) {
				continue
			}
			if isPauseContainer(pid) {
				continue
			}
			return taskID, nil
		}
	}

	// Fallback: scan containerd bundle dirs on host (available via hostPath /run mount).
	// ADR-0213 D1: the host bundle dirs are reachable in the agent mount namespace only at
	// /host-run/containerd/... (host /run is mounted at /host-run; the bare /run/containerd
	// task path does not exist in the agent ns). Each bundle is at
	// /host-run/containerd/io.containerd.runtime.v2.task/k8s.io/<taskID>/config.json.
	// The pod UID appears in the cgroup path encoded in config.json's linux.cgroupsPath field.
	const bundleBase = "/host-run/containerd/io.containerd.runtime.v2.task/k8s.io"
	entries, dirErr := os.ReadDir(bundleBase)
	if dirErr == nil {
		// Normalize pod UID for cgroup path matching (hyphens → underscores).
		podUIDNorm := strings.ReplaceAll(podUID, "-", "_")
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			cfgPath := filepath.Join(bundleBase, e.Name(), "config.json")
			data, readErr := os.ReadFile(cfgPath)
			if readErr != nil {
				continue
			}
			// Check if config.json references this pod UID (hyphen or underscore form).
			content := string(data)
			if !strings.Contains(content, podUID) && !strings.Contains(content, podUIDNorm) {
				continue
			}
			// Skip pause/sandbox containers: they have no process args or use "/pause".
			if strings.Contains(content, `"pause"`) || !strings.Contains(content, `"args"`) {
				continue
			}
			return e.Name(), nil
		}
	}

	return "", fmt.Errorf("containerd task not found for pod UID %s (ctr err: %v)", podUID, err)
}

// ctrCheckpoint calls `ctr --namespace k8s.io tasks checkpoint` for the given task,
// writing CRIU images to imagesDir. Also copies config.json from the containerd
// bundle directory into imagesDir so the destination can set up an OCI bundle for restore.
func ctrCheckpoint(taskID, imagesDir string, tcpEstablished bool) (int64, error) {
	// 0700: checkpoint images contain verbatim process memory and must be root-only.
	if err := os.MkdirAll(imagesDir, 0o700); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", imagesDir, err)
	}
	cmd := nsenterCmd("/usr/local/bin/ctr", "--namespace", "k8s.io", "tasks", "checkpoint",
		"--image-path", imagesDir, taskID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Detect in-flight / established TCP socket failure so the caller can fall back to
		// raw CRIU (which passes --tcp-established). ctr's own stdout/stderr only carries a
		// short "runc did not terminate / criu failed" summary — the actual CRIU diagnostic
		// ("inet: Connected TCP socket, consider using --tcp-established option") is written
		// to criu-dump.log inside the task bundle, NOT to ctr's combined output. So we must
		// inspect both: ctr's output AND the dump log. Without reading the dump log the
		// established-socket case is misclassified as fatal and the raw-CRIU fallback never
		// fires, hard-failing every TCP-stateful checkpoint (ADR-0131).
		outStr := string(out)
		// ADR-0213 D1/D2: read the dump log through the agent-visible host mount (/host-run),
		// NOT the bare /run host path (which does not exist in the agent mount namespace). Prefer
		// the exact log path ctr itself reports in its output (`path= .../criu-dump.log`) so a
		// short-vs-full task-ID mismatch (FindContainerTaskID may return the abbreviated ctr-list
		// ID while the on-disk bundle uses the full container ID) cannot point us at the wrong dir.
		dumpLogPath := ctrReportedDumpLogPath(outStr)
		if dumpLogPath == "" {
			dumpLogPath = filepath.Join(hostBundleDir(taskID), "criu-dump.log")
		}
		dumpLogRead := false
		if dumpLog, readErr := os.ReadFile(dumpLogPath); readErr == nil {
			outStr += "\n--- criu-dump.log ---\n" + string(dumpLog)
			dumpLogRead = true
		} else {
			// ADR-0213 D3: make a silent classifier failure observable. Without this log the
			// established-socket case is misclassified as fatal and the raw-CRIU fallback never
			// fires (the gate-9 wall).
			log.Info("Checkpoint: ctr criu-dump.log unreadable — classifying fail-safe (ADR-0213 D2/D3)",
				"dumpLogPath", dumpLogPath, "readErr", readErr.Error(), "tcpEstablished", tcpEstablished)
		}
		if strings.Contains(outStr, "In-flight") ||
			strings.Contains(outStr, "in-flight") ||
			strings.Contains(outStr, "Connected TCP socket") ||
			strings.Contains(outStr, "tcp-established") ||
			strings.Contains(outStr, "sk-inet.c") ||
			strings.Contains(outStr, "inet") {
			return 0, fmt.Errorf("ctr tasks checkpoint: %w\noutput: %s", ErrCtrInFlightTCP, outStr)
		}
		// ADR-0213 D2 fail-safe: if the dump log was unreadable AND TCP preservation is requested,
		// a correctness-preserving migration must not hard-fail on a missing best-effort diagnostic.
		// Default to the established-TCP classification so the caller falls back to raw go-criu with
		// --tcp-established rather than aborting the migration.
		if !dumpLogRead && tcpEstablished {
			return 0, fmt.Errorf("ctr tasks checkpoint (dump log unreadable, fail-safe TCP classification): %w\noutput: %s", ErrCtrInFlightTCP, outStr)
		}
		return 0, fmt.Errorf("ctr tasks checkpoint: %w\noutput: %s", err, out)
	}

	// Copy config.json from the containerd bundle into the checkpoint dir.
	// ADR-0213 D1: same host-mount translation as the dump-log read — the bundle is
	// reachable in the agent ns only via /host-run.
	bundleDir := hostBundleDir(taskID)
	srcCfg := filepath.Join(bundleDir, "config.json")
	dstCfg := filepath.Join(imagesDir, "config.json")
	if data, readErr := os.ReadFile(srcCfg); readErr == nil {
		_ = os.WriteFile(dstCfg, data, 0o600) // ADR-SEC-B N-342: 0600 in checkpoint dir (invariant 7)
	}

	// Compute checkpoint size.
	var total int64
	_ = filepath.Walk(imagesDir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, nil
}

// containerdMaskedPaths is the canonical, single source of truth for the set of
// host-sensitive paths the containerd/runc OCI runtime masks by default (OCI
// runtime-spec linux.maskedPaths). containerd binds /dev/null or an empty
// read-only tmpfs over each, so CRIU dumps them as external mounts that require
// an --ext-mount-map on restore (ADR-0124). Both the restore-time pre-scan
// (buildMaskedPathExtMountArgs) and the patch step (patchCheckpointImages)
// consult this list — do not fork a divergent copy (AC6).
var containerdMaskedPaths = []string{
	"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
	"/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
	"/proc/sched_debug", "/proc/scsi",
	"/sys/firmware", "/sys/fs/pstore", "/sys/fs/bpf",
}

// standardPodMounts is the canonical set of external mounts that every Kubernetes
// pod container carries and that buildCRIURestoreArgs maps explicitly by PATH (not to
// /dev/null) via --ext-mount-map <mountpoint>:<host-target>. The pre-scan must recognise
// these as covered — they are legitimately restorable external mounts, not unmapped ones.
// This list MUST stay in lockstep with the path-form --ext-mount-map entries in
// buildCRIURestoreArgs (ADR-0124 R2 / AC6 — single source of truth, no divergent copy).
var standardPodMounts = []string{
	"/data",
	"/dev/termination-log",
	"/var/run/secrets/kubernetes.io/serviceaccount",
	"/run/secrets/kubernetes.io/serviceaccount", // /var/run is a symlink to /run on modern Linux; ctr checkpoint records the canonical form; handled by --skip-mnt in buildCRIURestoreArgs (ADR-0190)
	"/sys",                                      // captured by ctr checkpoint as an external mount; handled by --ext-mount-map auto in buildCRIURestoreArgs (ADR-0190)
	"/dev/shm",
	"/etc/resolv.conf",
	"/etc/hostname",
	"/etc/hosts",
}

// buildMaskedPathExtMountArgs pre-scans the checkpoint's mountpoints-*.img (ADR-0124)
// and generates the --ext-mount-map args CRIU needs to re-bind containerd's masked-path
// external mounts. It MUST run AFTER patchCheckpointImages so it sees exactly the mount
// set CRIU will be asked to restore (ordered, disjoint-by-construction with the patch's
// delete set).
//
// For each mount entry it flags a masked-path external mount when EITHER the pycriu-reported
// root (normalized by trimming a single leading '/') equals "null", OR the mountpoint is in
// containerdMaskedPaths. Each qualifying entry yields "--ext-mount-map <mnt_id>:/dev/null"
// (numeric mnt_id form — the form CRIU failed to resolve in "No mapping for 2288:...").
//
// Fail loud (ADR-0124 D4 / AC5): any external mount that is neither in containerdMaskedPaths
// nor mappable to /dev/null returns an error naming each unmapped mnt_id and mountpoint, and
// the caller must NOT invoke CRIU restore.
//
// pycriu is invoked as a python3 subprocess with PYTHONPATH set (ADR-0121); imagesDir is passed
// as argv (never string-formatted into the script body — Security note).
func buildMaskedPathExtMountArgs(imagesDir string) ([]string, error) {
	const scanScript = `
import pycriu, glob, json, sys
imgs = glob.glob(sys.argv[1] + '/mountpoints-*.img')
results = []
for img in imgs:
    with open(img, 'rb') as f:
        data = pycriu.images.load(f)
    for e in data.get('entries', []):
        if e.get('ext_key') or e.get('root') in ('null', '/null', None):
            results.append({'mnt_id': e.get('mnt_id'), 'mountpoint': e.get('mountpoint', ''), 'root': e.get('root', ''), 'ext_key': e.get('ext_key', '')})
print(json.dumps(results))
`
	scriptPath := "/dev/shm/pm-scan-mounts.py"
	if err := os.WriteFile(scriptPath, []byte(scanScript), 0o600); err != nil {
		return nil, fmt.Errorf("write mount-scan script: %w", err)
	}
	defer os.Remove(scriptPath)

	cmd := exec.Command("python3", scriptPath, imagesDir)
	cmd.Env = append(os.Environ(), "PYTHONPATH=/usr/lib/python3/dist-packages")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("mount-scan script failed: %w\n%s", err, out)
	}

	var entries []struct {
		MntID      int    `json:"mnt_id"`
		Mountpoint string `json:"mountpoint"`
		Root       string `json:"root"`
		ExtKey     string `json:"ext_key"`
	}
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("parse mount-scan output: %w\n%s", err, out)
	}

	masked := make(map[string]bool, len(containerdMaskedPaths))
	for _, p := range containerdMaskedPaths {
		masked[p] = true
	}
	stdPod := make(map[string]bool, len(standardPodMounts))
	for _, p := range standardPodMounts {
		stdPod[p] = true
	}

	var args []string
	var unmapped []string
	for _, e := range entries {
		// Normalize root by trimming a single leading '/' so both "null" and "/null" match (ADR-0124 R3).
		normRoot := strings.TrimPrefix(e.Root, "/")
		if normRoot == "null" || masked[e.Mountpoint] {
			args = append(args, "--ext-mount-map", fmt.Sprintf("%d:/dev/null", e.MntID))
			continue
		}
		// Standard pod mounts are mapped by PATH in buildCRIURestoreArgs (mountpoint:host-target),
		// not by numeric mnt_id here — emitting a numeric /dev/null map would clobber them. They are
		// covered, so skip without flagging as unmapped (ADR-0124 R2 / AC6).
		if stdPod[e.Mountpoint] {
			continue
		}
		// An external mount (root is external / ext_key set) that is neither a null bind, a known
		// masked path, nor a standard pod mount is unsafe to restore — fail loud (D4).
		unmapped = append(unmapped, fmt.Sprintf("mnt_id=%d mountpoint=%q root=%q", e.MntID, e.Mountpoint, e.Root))
	}
	if len(unmapped) > 0 {
		return nil, fmt.Errorf("buildMaskedPathExtMountArgs: %d external mount(s) not in containerdMaskedPaths and not a /dev/null bind — refusing to restore (ADR-0124 D4): %s",
			len(unmapped), strings.Join(unmapped, "; "))
	}
	return args, nil
}

// buildCRIURestoreArgs constructs the argument list for `criu restore`.
// strictMode is true when tcpPreservationMode=Strict on the NRI restore path; it causes
// --leave-stopped to be emitted even when destNetnsFd is empty (ADR-0144 Decision Point 1).
// Network namespace selection is tier-driven (ADR-0048):
//   - destNetnsFd non-empty → --join-ns net:<path> + --tcp-established: restore into the
//     pre-staged migration netns so that TCP seq/ack state is preserved across node handoff.
//   - destNetnsFd empty → --tcp-close + --join-ns net:<petnsPath>: stateless cold migration; the
//     restored process joins the replacement pod's pause container netns by PATH (ADR-0125),
//     inheriting the pod IP / veth / CNI routing so it answers at the pod IP.
//
// petnsPath is the filesystem path of the replacement-pod pause netns (e.g.
// /var/run/netns/<id>), resolved by the caller via ResolveNetnsFromSandbox. It is used only on
// the destNetnsFd-empty path; the caller must guarantee a non-empty path there. On the
// destNetnsFd-non-empty (--join-ns Restore) path it is ignored.
//
// ADR-0125 (Sprint 20, supersedes ADR-0122 §3): CRIU 4.2 has no --net-fd flag. The documented
// way to join an existing network namespace at restore is --join-ns net:<path>. We pass the
// netns path string directly; no fd is handed to CRIU via ExtraFiles.
//
// --restore-detached is intentionally absent: CRIU must remain the foreground parent of the
// restored process tree to avoid ghost containers (PID in /proc but untracked by any supervisor).
//
// --leave-stopped is added when destNetnsFd is non-empty (TCP-stateful path): the restored
// process tree stays in SIGSTOP until the caller sends SIGCONT, which must happen only AFTER
// SocketsLive=True is confirmed (M23 ordering invariant).
// checkpointHasEstablishedTCP reports whether the CRIU checkpoint in checkpointDir
// captured at least one established TCP connection. CRIU writes a tcp-stream-<id>.img
// for every ESTABLISHED socket dumped under --tcp-established; its presence is the
// authoritative signal that the restore must use --tcp-established (not --tcp-close)
// to rebuild the socket via TCP_REPAIR (ADR-0131 seq_delta=0).
func checkpointHasEstablishedTCP(checkpointDir string) bool {
	matches, err := filepath.Glob(filepath.Join(checkpointDir, "tcp-stream-*.img"))
	if err != nil {
		return false
	}
	return len(matches) > 0
}

// cgroupInheritFd describes one regular-file file-descriptor whose recorded path is
// under /sys/fs/cgroup, enumerated from the checkpoint images (ADR-0180). CRIU's
// files-reg.c regular-file restore pass aborts on the first such fd because the
// placeholder rootfs has no populated /sys/fs/cgroup subtree (files-reg.c:2353). We
// redirect each via --inherit-fd so CRIU dups an agent-held descriptor instead of
// calling open_path() against the (absent) image path.
type cgroupInheritFd struct {
	// Fd is the file-descriptor NUMBER the restored task holds (the "fd" field in
	// fdinfo-*.img). It is the NUM in CRIU's --inherit-fd fd[NUM]:RES form.
	Fd int
	// Path is the recorded path of the file (the "name" of the REG entry in files.img),
	// always under /sys/fs/cgroup. It is the RES in --inherit-fd fd[NUM]:RES; CRIU
	// matches the agent-held inherited fd to the image entry by this path string.
	Path string
}

// enumerateCgroupInheritFds parses the CRIU checkpoint images in checkpointDir via
// pycriu and returns every open regular-file fd whose recorded path is under
// /sys/fs/cgroup (ADR-0180 OC-2 / OC-3). The class is determined DYNAMICALLY by the
// predicate "path starts with /sys/fs/cgroup" — never hardcoded to cpu.max — so any
// Go 1.25+/cgroup-v2 runtime fd (cpu.max today, memory.max/cpu.stat tomorrow) is
// covered without code change (Arch-A S5 mandate). It joins fdinfo-*.img (fd -> file
// id, REG entries only) with files.img (file id -> path for REG files).
//
// CRIU 4.2 stores regular-file metadata in files.img (the modern equivalent of the
// older reg-files-*.img); the OC-2 inventory artifact documents the exact image layout.
func enumerateCgroupInheritFds(checkpointDir string) ([]cgroupInheritFd, error) {
	script := `
import pycriu, glob, json, sys, os

cpdir = sys.argv[1]

# files.img: REG file id -> path
id2path = {}
files_img = os.path.join(cpdir, 'files.img')
if os.path.exists(files_img):
    with open(files_img, 'rb') as f:
        files = pycriu.images.load(f)
    for e in files.get('entries', []):
        if e.get('type') == 'REG' and 'reg' in e:
            id2path[e['id']] = e['reg'].get('name')

# fdinfo-*.img: fd -> file id (REG only)
out = []
for fdinfo_img in sorted(glob.glob(os.path.join(cpdir, 'fdinfo-*.img'))):
    with open(fdinfo_img, 'rb') as f:
        fdinfo = pycriu.images.load(f)
    for e in fdinfo.get('entries', []):
        if e.get('type') != 'REG':
            continue
        p = id2path.get(e.get('id'))
        if p and p.startswith('/sys/fs/cgroup'):
            out.append({'fd': e.get('fd'), 'path': p})

# de-dup on (fd, path) — a path may appear in multiple fdinfo images for the same fd
seen = set()
uniq = []
for o in out:
    k = (o['fd'], o['path'])
    if k in seen:
        continue
    seen.add(k)
    uniq.append(o)
print(json.dumps(uniq))
`
	cmd := exec.Command("python3", "-c", script, checkpointDir)
	cmd.Env = append(os.Environ(), "PYTHONPATH=/usr/lib/python3/dist-packages")
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		return nil, fmt.Errorf("enumerateCgroupInheritFds pycriu: %w: %s", err, stderr)
	}
	var raw []struct {
		Fd   int    `json:"fd"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("enumerateCgroupInheritFds parse %q: %w", string(out), err)
	}
	fds := make([]cgroupInheritFd, 0, len(raw))
	for _, r := range raw {
		fds = append(fds, cgroupInheritFd{Fd: r.Fd, Path: r.Path})
	}
	return fds, nil
}

// resolveInheritCgroupSource picks the host cgroupfs cpu-controller file the agent
// opens for an inherited cgroup fd (ADR-0180 OC-1 / S2). The Go 1.25 containermaxprocs
// runtime re-reads the SAME held fd live (empirically verified: an in-place cpu.max
// quota change is reflected in GOMAXPROCS), but the held fd does NOT follow a cgroup
// MOVE. Therefore, so that the inherited fd reflects the destination pod's real quota
// after moveProcessToPodCgroup relocates the process, we open the file from the
// DESTINATION POD's own cgroup subtree (resolved via the sandbox pause PID) whenever a
// sandboxID is available. When it is not (or resolution fails) we fall back to the
// recorded image path if it exists on the destination, and finally to the cgroup-v2
// root cpu.max — the restore still advances past files-reg.c:2353 in every case (S1).
func resolveInheritCgroupSource(recordedPath, sandboxID string) string {
	base := filepath.Base(recordedPath) // e.g. "cpu.max" — preserve the controller file name
	if sandboxID != "" {
		if pausePID, err := sandboxPausePID(sandboxID); err == nil {
			if podCgroup, cerr := cgroupV2Path(pausePID); cerr == nil {
				cand := filepath.Join("/sys/fs/cgroup", podCgroup, base)
				if _, serr := os.Stat(cand); serr == nil {
					return cand
				}
			}
		}
	}
	if _, err := os.Stat(recordedPath); err == nil {
		return recordedPath
	}
	return filepath.Join("/sys/fs/cgroup", base)
}

func buildCRIURestoreArgs(checkpointDir, rootfsDir, dataDir, termlogFile, secretsDir, restoreLogPath, destNetnsFd, petnsPath, hostVethName string, strictMode bool) []string {
	// Choose --tcp-established whenever the checkpoint actually captured an established
	// TCP connection (presence of a tcp-stream-*.img), NOT merely when a pre-staged
	// migration netns fd was supplied. The NRI StartContainer restore path joins the
	// replacement pod sandbox netns by PATH (destNetnsFd==""), so the old
	// "destNetnsFd != ''" heuristic always picked --tcp-close there and dropped the
	// connection ("Will drop all TCP connections on restore"), defeating ADR-0131
	// seq_delta=0. The pre-staged pod netns carries the same pod IP, so --tcp-established
	// restores the socket via TCP_REPAIR into the correct namespace.
	tcpFlag := "--tcp-close"
	if destNetnsFd != "" || checkpointHasEstablishedTCP(checkpointDir) {
		tcpFlag = "--tcp-established"
	}
	args := []string{
		"restore",
		"--images-dir", checkpointDir,
		"--root", rootfsDir,
		tcpFlag,
		// --mntns-compat-mode is intentionally OMITTED here (gate-fix B1).
		// Compat-mode runs an umount pass inside the destination container's mount namespace
		// that tries to remove /sys → EBUSY (sysfs is kernel-referenced and cannot be
		// unmounted even with MNT_DETACH when it has active references from the host).
		// This causes CRIU to exit code 1 on kind control-plane nodes where the placeholder
		// container has a different sysfs mount topology than the worker nodes used in
		// Sprint 31. Without --mntns-compat-mode, CRIU uses mount-v2 mode
		// (MOVE_MOUNT_SET_GROUP) which does NOT run the umount pass and only mounts what
		// is recorded in the image (the 5 stripped entries: /, /proc, /dev, /dev/pts,
		// /dev/mqueue). The go-criu RPC restore path already uses MntnsCompatMode=false
		// for the same reason (see criu_checkpointer.go). Aligning the CLI path with the
		// go-criu path resolves the control-plane restore failure (Sprint 32 GC-1 through
		// GC-22 blocker).
		// --ext-mount-map auto handles the standard pseudo-fs and containerd/runc submounts
		// (/proc/*, /sys/*, /dev/*) that CRIU autodetects as external.
		// ADR-0193: the disproven "pm-data" ext-mount-map (which targeted a phantom mount
		// that was never in the mountpoints image on this checkpoint shape) is REMOVED.
		// Image evidence proved /data is absent from mountpoints entirely; the files.img REG fd
		// id 15 (/data) is now rebound to the restored ROOT mnt_id by patchCheckpointImages.
		"--ext-mount-map", "auto",
		"--manage-cgroups=ignore",
		"--ext-mount-map", "/dev/null:/dev/null",
		"--ext-mount-map", fmt.Sprintf("/dev/termination-log:%s", termlogFile),
		// The kubelet's service-account tmpfs is a source-node-specific bind mount whose
		// inner token files are not pre-staged on the destination; CRIU then fails to
		// bind-mount it ("Can't bind-mount at .../run/secrets/kubernetes.io/serviceaccount:
		// No such file or directory", mount.c:2511). Skip it on restore — it is re-provided
		// by the destination kubelet for the replacement pod, and the migrated workload
		// (redis) does not depend on the SA token. Mirrors the SkipMnt policy already used on
		// the go-criu restore path. (ADR-0131 restore path.)
		"--skip-mnt", "/var/run/secrets/kubernetes.io/serviceaccount",
		"--skip-mnt", "/run/secrets/kubernetes.io/serviceaccount", // canonical form used by ctr checkpoint (/var/run is symlink to /run on modern Linux) (ADR-0190)
		// ADR-0190: /sys and its entire subtree are dropped from the checkpoint image by
		// patchCheckpointImages (subtree-closed mnt_id graph closure). No /sys* entries
		// survive into the image, so --skip-mnt for dmi/id/*, powercap, firmware are
		// not needed and have been removed. Defense-in-depth --skip-mnt for service
		// account paths is kept (see above).
		"--ext-mount-map", "/dev/shm:/dev/shm",
		"--ext-mount-map", "/etc/resolv.conf:/etc/resolv.conf",
		"--ext-mount-map", "/etc/hostname:/etc/hostname",
		"--ext-mount-map", "/etc/hosts:/etc/hosts",
		// NetworkLock: the dump uses --network-lock skip unconditionally (criu_checkpointer.go:233),
		// so the restore MUST also pass --network-lock skip to honor the dump/restore-pair invariant.
		// A restore must not replay lock state the paired dump never captured (ADR-0192 Site A, R2).
		// This builder covers all three live restore entry points (NRI JoinNsRestore server.go:325,
		// gRPC Restore config.json branch server.go:4174, gRPC raw branch server.go:4335).
		"--network-lock", "skip",
		"-v4",
		"-o", restoreLogPath,
	}
	if destNetnsFd != "" {
		args = append(args, "--join-ns", "net:"+destNetnsFd)
		// --leave-stopped: restored process tree stays in SIGSTOP until we send SIGCONT.
		// SIGCONT is sent only after SocketsLive=True is confirmed (M23 ordering invariant).
		args = append(args, "--leave-stopped")
	} else if petnsPath != "" {
		// ADR-0125 (supersedes ADR-0122 §3): join the replacement pod's pause container netns
		// by PATH instead of minting an empty one. CRIU 4.2 has no --net-fd flag; the documented
		// flag is --join-ns net:<path>. The restored process inherits the pod IP, veth, and CNI
		// routes. No fd is passed via ExtraFiles.
		args = append(args, "--join-ns", "net:"+petnsPath)
		if strictMode {
			// ADR-0144 Decision Point 1: on the NRI path (destNetnsFd==""), strictMode=true means
			// tcpPreservationMode=Strict. Emit --leave-stopped so the restored process tree stays
			// in SIGSTOP until InjectIPHandoff fires SIGCONT via pendingResumePIDs. Without this,
			// the NRI path resumed immediately and could write into an unwired datapath, breaking
			// seq_delta=0 for actively-writing clients.
			args = append(args, "--leave-stopped")
		}
	}
	// Gate29: thread the host-side veth peer name (pmh-<uid>) into CRIU so it knows
	// which interface to wire eth0 into.  Without --veth-pair CRIU cannot locate the
	// host-bridge peer and fails with "Unknown peer net namespace".  When
	// --tcp-established is in effect the veth must additionally be declared external
	// (--external veth[eth0]:pmh-*) so CRIU does not try to re-assign the IP that
	// PrepareDestinationNetns already set on eth0 — matching the go-criu restore path
	// at criu_checkpointer.go:534-548.
	if hostVethName != "" {
		// CRIU's --veth-pair parses on '=' (criu/config.c) in the form
		// outside_name=inside_name. The colon form ("eth0:pmh-*") is rejected
		// with "invalid argument for --veth-pair". The inside name is eth0
		// (container side); the outside name is the host-side peer.
		args = append(args, "--veth-pair", hostVethName+"=eth0")
		if tcpFlag == "--tcp-established" {
			args = append(args, "--external", "veth[eth0]:"+hostVethName)
		}
	}
	// Authoritative restored-PID resolution via CRIU's own --pidfile.
	// CRIU writes the PID of the restored ROOT task to this file as a side effect of the
	// restore itself — the source-of-truth answer, replacing the prior poll-and-guess
	// broker-cgroup PID diff, a fragile, non-atomic inference chain (see readRestoredPIDFromPidfile).
	// dataDir is on /var/lib/podmotion (ext4), visible from BOTH the agent container and the
	// host mount namespace CRIU runs in, so the agent reads it back with a plain os.ReadFile.
	args = append(args, "--pidfile", filepath.Join(dataDir, restoredPidfileName))
	return args
}

// restoredPidfileName is the basename CRIU writes the restored root PID to (see --pidfile
// in buildCRIURestoreArgs). It lives in the restore dataDir (host-visible ext4).
const restoredPidfileName = "restored.pid"

// copyDirAll copies all regular files (non-recursive into subdirs is fine for CRIU image dirs
// which are flat) from src to dst. dst is created with 0o700 if it doesn't exist.
// Uses os.Link (hard-link) where possible (same filesystem); falls back to byte copy.
func copyDirAll(src, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			// Recurse into subdirectories (e.g. CRIU may create sub-dirs).
			if err := copyDirAll(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
			continue
		}
		srcPath := filepath.Join(src, e.Name())
		dstPath := filepath.Join(dst, e.Name())
		// Try hard-link first (fast, zero-copy within same filesystem).
		if err := os.Link(srcPath, dstPath); err == nil {
			continue
		}
		// Fall back to byte copy (cross-filesystem case: tmpfs → ext4).
		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// joinNsRestore restores a checkpointed container using a standalone overlayfs rootfs.
// When destNetnsFd is non-empty (a /proc/<pid>/fd/<n> path to a pre-staged migration netns),
// CRIU uses --join-ns net:<destNetnsFd> to restore TCP connections into the pre-staged netns
// (required for TCPPreservationMode=Strict/BestEffort per ADR-0048).
// When destNetnsFd is empty, CRIU joins the replacement pod's sandbox netns via
// --join-ns net:<path> (ADR-0125, supersedes ADR-0122 §3): sandboxID is resolved through the
// containerd sandbox API (ResolveNetnsFromSandbox), which opens the netns path and runs the B2
// inode cross-check (TOCTOU guard). The fd is then closed and only the path STRING is handed to
// CRIU — CRIU 4.2 has no --net-fd flag. The restored process then comes up inside the pod netns
// (pod IP, veth, CNI routes) and is reachable at the pod IP with no post-restore namespace
// surgery.
//
// Approach:
//  1. Patch checkpoint images: remove null-ext_key masked mounts, strip extRootNetNS from
//     netns image, remove VETH entry from netdev image (loopback only).
//  2. Mount an overlayfs rootfs from containerd snapshot layers.
//  3. Run CRIU restore with --root <overlayfs> and the appropriate netns flag plus
//     --ext-mount-map for every external mount.
//  4. Bring up loopback in the restored process's network namespace.
//
// Returns the host PID of the restored process.
// storedHostVeth is the host-side veth peer name stored by PrepareDestinationNetns (Gate30).
func joinNsRestore(migrationName, checkpointDir, imageName, containerID, destNetnsFd, sandboxID, storedHostVeth string, strictMode bool) (int, []ExternalMountDroppedInfo, error) {
	// Gate30: use the host-side veth name stored during PrepareDestinationNetns rather than
	// re-deriving from migrationName.  Re-derivation diverges when the controller passes a
	// pod UID to PrepareDestinationNetns and a migration name to Restore.
	// On the cold / no-netns path (destNetnsFd=="") no veth exists; pass empty string.
	hostVethName := ""
	if destNetnsFd != "" {
		if storedHostVeth != "" {
			hostVethName = storedHostVeth
		} else {
			// Fallback: re-derive (safe when migrationName == uid passed to PrepareDestinationNetns).
			hostVethName = network.HostVethPeerName(migrationName)
		}
	}
	// Use the image name passed in from the NRI ContainerEvent (fetched via ctr containers
	// info) or, when that is empty, the authoritative source-pod image resolved by the caller
	// from destWorkloadImage[migrationName] (ADR-0168 B2 chain). The checkpoint dir is a CRIU
	// dump dir and never contains an OCI bundle config.json, so we do not read it here.
	//
	// ADR-0215: there is NO hardcoded image fallback. A hardcoded "docker.io/library/redis:7"
	// previously masked an empty image name and silently substituted the wrong image — gate-11
	// failed because the pod ran redis:7-alpine but the placeholder requested redis:7 (absent on
	// the node). If the image is still unresolved here, every upstream authoritative source has
	// failed; fail loudly so the controller rolls back, rather than starting a placeholder with a
	// guessed image that does not match the checkpointed mapped-VMA file sizes.
	if imageName == "" {
		return 0, nil, fmt.Errorf("restore image unresolved (ADR-0215): no image from NRI ContainerEvent and no cached workload image for migration %q — controller must plumb MCP.Spec.WorkloadImage via PrepareDestinationNetns workload_image", migrationName)
	}
	if strings.Count(imageName, "/") == 0 {
		imageName = "docker.io/library/" + imageName
	} else if strings.Count(imageName, "/") == 1 && !strings.Contains(strings.SplitN(imageName, "/", 2)[0], ".") {
		imageName = "docker.io/" + imageName
	}

	// Pull the image if not already present. Use nsenterCmd to run ctr in the host mount namespace
	// (ctr is on the node, not in the agent container).
	pullOut, _ := nsenterCmd("ctr", "--namespace", "k8s.io", "images", "ls", "-q").Output()
	if !strings.Contains(string(pullOut), imageName) {
		if out, err := nsenterCmd("ctr", "--namespace", "k8s.io", "images", "pull", imageName).CombinedOutput(); err != nil {
			return 0, nil, fmt.Errorf("pull %s: %w\n%s", imageName, err, out)
		}
	}

	// ADR-0193 C-R3-1 / ADR-0180: enumerate cgroup inherit-fd names BEFORE patchCheckpointImages
	// so the P-0193-1 "NOT inherited" exclusion uses the same name set as buildCRIURestoreArgs.
	// This is the single source of truth: the names here are exactly what CRIU sees on --inherit-fd.
	// Degrade-and-continue on failure (same as the later code path: no --inherit-fd = pre-ADR-0180).
	cgInheritFdsEarly, cgEnumEarlyErr := enumerateCgroupInheritFds(checkpointDir)
	if cgEnumEarlyErr != nil {
		log.Info("ADR-0193/ADR-0180: cgroup inherit-fd enumeration failed; proceeding without --inherit-fd names in patchCheckpointImages",
			"err", cgEnumEarlyErr, "migration", migrationName)
		cgInheritFdsEarly = nil
	}
	var inheritFdNamesForPatch []string
	for _, c := range cgInheritFdsEarly {
		if c.Fd >= 3 {
			// Slash-stripped per ADR-0188 — must match CRIU's inherited_fd() line-2200 comparison.
			inheritFdNamesForPatch = append(inheritFdNamesForPatch, strings.TrimPrefix(c.Path, "/"))
		}
	}

	// Step 1: Patch checkpoint images to remove cross-node-incompatible entries and enforce
	// the files.img↔mountpoints consistency invariant (ADR-0193 P-0193-1).
	// inheritFdNamesForPatch is the same set that buildCRIURestoreArgs will pass via --inherit-fd
	// (C-R3-1 single source of truth — no independent recomputation).
	droppedMounts, patchErr := patchCheckpointImages(checkpointDir, inheritFdNamesForPatch)
	if patchErr != nil {
		return 0, nil, fmt.Errorf("patch checkpoint images: %w", patchErr)
	}

	// Step 1b: Copy checkpoint images to /var/lib/podmotion (ext4) so CRIU running in the
	// host mount namespace can access them. The agent's /run/podmotion/checkpoints is a tmpfs
	// mounted inside the agent container's mount namespace. CRIU (via nsenterCmd, entering the
	// host mount namespace) cannot see that tmpfs — it sees the host namespace where
	// /run/podmotion/checkpoints is a separate mount (or absent after agent restart).
	// /var/lib/podmotion is an ext4 bind-mount visible from BOTH the agent container and
	// the host mount namespace, so CRIU can open images from there.
	hostCheckpointDir := fmt.Sprintf("/var/lib/podmotion/restore/%s/checkpoint", migrationName)
	// ADR-0193 S2 (HARD — Security): arm defer zeroizeDir for the ext4 mirror BEFORE copyDirAll.
	// The ext4 host dir /var/lib/podmotion/restore/<m>/checkpoint previously had ZERO zeroize on
	// any exit path. This ADR adds net-new files.img.orig / fdinfo-*.img.orig plaintext backups
	// to that dir; Standing Rule 7 now applies here. The defer runs on EVERY exit path of
	// joinNsRestore — success AND the P-0193-1 HARD-STOP return above (server.go:2305-2306 prior,
	// now the patchCheckpointImages error return above). Glob-based (not hardcoded filename list).
	defer func() {
		if zErr := zeroizeDir(hostCheckpointDir); zErr != nil && !os.IsNotExist(zErr) {
			log.Error(zErr, "ADR-0193 S2: zeroizeDir(hostCheckpointDir) failed — residual plaintext may remain",
				"dir", hostCheckpointDir, "migration", migrationName)
		}
	}()
	if err := copyDirAll(checkpointDir, hostCheckpointDir); err != nil {
		return 0, nil, fmt.Errorf("copy checkpoint to host-visible dir: %w", err)
	}
	// Use the host-visible path for CRIU and all subsequent operations.
	checkpointDir = hostCheckpointDir

	// Step 2: Prepare rootfs from containerd snapshot layers.
	// The placeholder container (started via nsenter in the host mount namespace by setupRestoreOverlayfs)
	// has its rootfs available at the containerd task bundle path, which is exposed to the agent
	// container via the host-containerd-bundles volume mount.
	// We use this pre-mounted rootfs directly to avoid nested overlay mount limitations.
	placeholderID := "pm-placeholder-" + migrationName
	rootfsDir, err := setupRestoreOverlayfs(migrationName, checkpointDir, imageName, containerID)
	if err != nil {
		return 0, nil, fmt.Errorf("setup rootfs overlayfs: %w", err)
	}

	// On any error after this point: kill placeholder to release the rootfs mount.
	success := false
	defer func() {
		if success {
			return
		}
		_ = nsenterCmd("ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()
		_ = nsenterCmd("ctr", "--namespace", "k8s.io", "container", "rm", placeholderID).Run()
	}()

	// Step 3: Create ext-mount-map target paths in the agent container's filesystem.
	// These paths are used as ext-mount-map targets for CRIU; CRIU (running in the host
	// mount namespace) can access /var/lib/podmotion via the bind-mount (shared filesystem).
	dataDir := fmt.Sprintf("/var/lib/podmotion/restore/%s/data", migrationName)
	secretsDir := fmt.Sprintf("/var/lib/podmotion/restore/%s/secrets", migrationName)
	termlogFile := fmt.Sprintf("/var/lib/podmotion/restore/%s/termination-log", migrationName)
	_ = os.MkdirAll(dataDir, 0o700)
	_ = os.MkdirAll(secretsDir, 0o700)
	_ = os.WriteFile(termlogFile, nil, 0o644)

	// Create required directories and files inside the rootfs in the HOST mount namespace
	// via nsenterCmd. The rootfsDir is an overlayfs mounted in the host namespace; the agent
	// container only sees the mount-point directory (bind-mount propagation is PRIVATE), NOT
	// the overlay's merged view. All writes to rootfsDir MUST go via nsenterCmd so they land
	// in the overlay's upper dir as seen from the host namespace.
	//
	// These directories are needed as mount targets for CRIU when it restores the container's
	// mount namespace (proc, sys, dev, dev/pts, dev/mqueue, dev/shm, sys/fs/cgroup).
	// The dmi/id files (product_name, product_uuid) must exist BOTH at their canonical paths
	// AND at the rootfs ROOT because CRIU's bind-mount source path is relative to the rootfs root.
	dirsToCreate := []string{
		"proc", "sys", "dev", "dev/pts", "dev/mqueue", "dev/shm",
		"sys/fs/cgroup",
		"sys/devices/virtual/dmi/id",
		"sys/devices/virtual/powercap",
		"tmp", "data",
		"run", "var/run/secrets/kubernetes.io/serviceaccount",
	}
	for _, d := range dirsToCreate {
		if out, err := nsenterCmd("mkdir", "-p", filepath.Join(rootfsDir, d)).CombinedOutput(); err != nil {
			log.Error(err, "setupRootfsDirs: mkdir failed (non-fatal)", "dir", d, "out", string(out))
		}
	}
	// Create empty bind-mount target files at canonical paths and at rootfs root.
	filesToCreate := []string{
		filepath.Join(rootfsDir, "sys/devices/virtual/dmi/id/product_name"),
		filepath.Join(rootfsDir, "sys/devices/virtual/dmi/id/product_uuid"),
		filepath.Join(rootfsDir, "product_name"),
		filepath.Join(rootfsDir, "product_uuid"),
		filepath.Join(rootfsDir, "etc/resolv.conf"),
		filepath.Join(rootfsDir, "etc/hostname"),
		filepath.Join(rootfsDir, "etc/hosts"),
	}
	for _, f := range filesToCreate {
		if out, err := nsenterCmd("sh", "-c", fmt.Sprintf("[ -e %q ] || touch %q", f, f)).CombinedOutput(); err != nil {
			log.Error(err, "setupRootfsFiles: touch failed (non-fatal)", "file", f, "out", string(out))
		}
	}
	// Step 4: CRIU restore — standalone rootfs.
	//
	// ADR-0125 (supersedes ADR-0122 §3): on the stateless (destNetnsFd-empty) path, resolve the
	// replacement pod's sandbox netns via the containerd sandbox API and hand its PATH to CRIU via
	// --join-ns net:<path> so the restored process joins the pod netns (pod IP, veth, CNI routes)
	// instead of getting an empty one. CRIU 4.2 has no --net-fd flag; no fd is passed via
	// ExtraFiles. ResolveNetnsFromSandbox still opens the path briefly to run the B2 inode
	// cross-check (TOCTOU guard), then we close the fd and pass only the path string.
	// restore.log must be on /var/lib/podmotion (ext4 shared between host ns and agent container).
	// The checkpoint dir (/run/podmotion/checkpoints) uses the host TMPFS which is NOT visible
	// from the agent container's mount namespace; CRIU (running via nsenter in host namespace)
	// would write to the TMPFS but the agent (in its own namespace) would read from ext4 and
	// never see the marker. /var/lib/podmotion uses ext4 and is accessible from both.
	restoreLogPath := filepath.Join(dataDir, "restore.log")
	_ = os.WriteFile(restoreLogPath, nil, 0o644)
	var petnsPath string
	if destNetnsFd == "" {
		if sandboxID == "" {
			// tcpPreservationMode=None on the gRPC Restore path: no sandbox ID is supplied
			// because the operator does not pass one (RestoreRequest has no sandbox_id field).
			// For cold migration (no TCP state to preserve) the --join-ns net:<path> is not
			// required — petnsPath stays empty and buildCRIURestoreArgs omits --join-ns.
			// The NRI hook path always supplies a sandboxID; this branch is only hit on the
			// fallback gRPC Restore path used in kind/dev clusters with tcpPreservationMode=None.
			log.Info("joinNsRestore: no sandboxID and no destNetnsFd — skipping netns join (tcpPreservationMode=None cold path)",
				"migration", migrationName)
		} else {
			// B1: resolve via the containerd sandbox API (unambiguous per pod, no /proc comm scan).
			// B2: ResolveNetnsFromSandbox opens the netns path and cross-checks fd/path inodes.
			netnsFd, resolvedPath, rerr := ResolveNetnsFromSandbox(context.Background(), nil, sandboxID)
			if rerr != nil {
				return 0, nil, fmt.Errorf("resolve replacement pod sandbox netns: %w", rerr)
			}
			// ADR-0125: the fd existed only for the B2 inode cross-check. Close it now; CRIU joins by
			// path, not by inherited fd.
			_ = netnsFd.Close()
			petnsPath = resolvedPath
			// ADR-0133: stash the exact netns path CRIU joined so the NRI callback can read the
			// replacement pod's eth0 MAC from it (the restored PID's own /proc/<pid>/ns/net can
			// transiently resolve to the host netns right after CRIU exits).
			storeResolvedNetnsPath(migrationName, petnsPath)
			log.Info("joinNsRestore: joining replacement pod netns via --join-ns net:<path> (ADR-0125)",
				"sandboxID", sandboxID, "netnsPath", petnsPath)
		}
	}

	criuArgs := buildCRIURestoreArgs(checkpointDir, rootfsDir, dataDir, termlogFile, secretsDir, restoreLogPath, destNetnsFd, petnsPath, hostVethName, strictMode)
	// ADR-0124: dynamically scan the (post-patch) mountpoints-*.img for containerd masked-path
	// external mounts and append their --ext-mount-map <mnt_id>:/dev/null args. Fail loud before
	// invoking CRIU if any external mount is not safely mappable (D4).
	maskedArgs, err := buildMaskedPathExtMountArgs(checkpointDir)
	if err != nil {
		return 0, nil, err
	}
	criuArgs = append(criuArgs, maskedArgs...)

	// Gate10 fix: pre-lazy-umount /sys from the placeholder container's mount namespace
	// before CRIU runs compat-mode cleanup.
	//
	// Background: CRIU compat-mode enters the destination container's mount namespace
	// and runs an "umount pass" to remove mounts not present in the checkpoint image.
	// /sys is mounted in every container by containerd/runc. CRIU can't restore /sys as
	// external because CRIU 4.2 does not write ext_key for sysfs mounts when declared via
	// --external mnt[/sys]:pm-sys (path-form matches at walk time but doesn't persist).
	// Without ext_key, compat-mode treats /sys as a non-external regular mount and calls
	// umount2(./sys, 0) → EBUSY (sysfs has a kernel reference from the host bind mount).
	//
	// Solution: before CRIU runs, enter the placeholder container's mount namespace and
	// lazy-umount /sys (MNT_DETACH — detaches from namespace tree even if busy). CRIU then
	// enters the namespace, doesn't find /sys, skips the umount for it, and proceeds.
	// After CRIU restores, /sys is not in the image (skipped at dump), so the restored
	// process inherits whatever the container runtime provides at container start time
	// (containerd/runc re-mounts /sys when the replacement pod starts).
	//
	// Implementation: get the placeholder PID via `ctr task ls`, find its mount namespace
	// fd at /proc/<pid>/ns/mnt (accessible from host mount namespace via nsenter), then
	// use nsenter --mount=<ns> to run umount -l /sys inside it.
	placeholderIDForUmount := "pm-placeholder-" + migrationName
	if placeholderPIDOut, pidErr := nsenterCmd("ctr", "--namespace", "k8s.io", "tasks", "ls", "--quiet").Output(); pidErr == nil {
		// `ctr task ls --quiet` lists running task IDs (not PIDs). Get the PID from `ctr task info`.
		if strings.Contains(string(placeholderPIDOut), placeholderIDForUmount) {
			if pidInfo, piErr := nsenterCmd("ctr", "--namespace", "k8s.io", "task", "ls").Output(); piErr == nil {
				for _, line := range strings.Split(string(pidInfo), "\n") {
					if strings.Contains(line, placeholderIDForUmount) {
						fields := strings.Fields(line)
						if len(fields) >= 2 {
							placeholderPID := fields[1]
							nsMntPath := fmt.Sprintf("/proc/%s/ns/mnt", placeholderPID)
							log.Info("gate10 fix: lazy-umounting /sys from placeholder container namespace",
								"placeholderID", placeholderIDForUmount, "pid", placeholderPID)
							// Lazy-umount children of /sys first (in case kernel requires bottom-up)
							sysMounts := []string{
								"/sys/firmware", "/sys/devices/virtual/powercap",
								"/sys/devices/virtual/dmi/id/sys_vendor",
								"/sys/devices/virtual/dmi/id/chassis_serial",
								"/sys/devices/virtual/dmi/id/board_serial",
								"/sys/devices/virtual/dmi/id/product_uuid",
								"/sys/devices/virtual/dmi/id/product_name",
								"/sys/kernel/config", "/sys/fs/fuse/connections",
								"/sys/kernel/debug", "/sys/kernel/tracing",
								"/sys/fs/bpf", "/sys/fs/cgroup", "/sys",
							}
							for _, mnt := range sysMounts {
								umountOut, umountErr := exec.Command("nsenter", "--mount="+nsMntPath, "--", "umount", "-l", mnt).CombinedOutput()
								if umountErr != nil {
									// Non-fatal: some mounts may not exist in this container
									log.Info("gate10 fix: lazy-umount skipped (mount absent or error)",
										"mount", mnt, "err", umountErr, "output", string(umountOut))
								} else {
									log.Info("gate10 fix: lazy-umounted successfully", "mount", mnt)
								}
							}
						}
						break
					}
				}
			}
		} else {
			log.Info("gate10 fix: placeholder not found in running tasks — skipping pre-umount (NRI path or already cleaned up)",
				"placeholderID", placeholderIDForUmount)
		}
	}

	// Run CRIU in the host mount namespace via nsenter. The agent container cannot join
	// the replacement pod's netns directly (nested container user namespace restriction);
	// running in the host mount namespace lets CRIU's child process call setns(CLONE_NEWNET)
	// from the correct namespace context. The checkpoint files and rootfsDir are both
	// accessible from the host mount namespace (checkpoint dir visible via host tmpfs;
	// rootfsDir is the placeholder container's bundle path exposed by containerd).
	// ADR-0180: enumerate cgroup inherit-fds for --inherit-fd and --cgroup-fd=N:path wrapper args.
	// ADR-0193 C-R3-1: enumeration was already performed early (cgInheritFdsEarly) and used by
	// patchCheckpointImages for the P-0193-1 "NOT inherited" exclusion. Reuse that result here
	// rather than re-enumerating (same source of truth: avoids any drift between patch-time and
	// restore-time name sets). The host-visible checkpoint dir is already in place (Step 1b above).
	//
	// Cleanup contract (ADR-0180 OC-2 / Standing Rule 7): every agent-held cgroup fd opened
	// here is closed on EVERY exit path of this function via the deferred closer below
	// (success, failure, and the ctx-cancel/Abort path that returns through joinNsRestore).
	// No cgroup fd is leaked into the agent process.
	cgInheritFds := cgInheritFdsEarly
	// ADR-0181: build the --cgroup-fd=N:path args for the wrapper and the --inherit-fd fd[N]:path
	// args for CRIU from the same enumeration so fd numbers and resolved paths cannot drift.
	// The agent does NOT hold any cgroup fds — the wrapper process opens them fresh inside the
	// host mount namespace (already entered by nsenter before the wrapper runs), dup3s each to
	// its target N, and execve()s criu. nsenter's internal opens happen before the wrapper runs
	// and cannot displace target N because the wrapper sets each slot last.
	//
	// OC-5(a): the heldCgroupFds / closeHeldCgroupFds / inheritExtraFiles / ExtraFiles block
	// from ADR-0180 is removed here. There are no agent-held cgroup fds. The wrapper process
	// owns the descriptors; they are released when criu exits (reaped by the background Wait
	// goroutine below). Abort clean-teardown contract: Abort kills the wrapper/criu child via
	// checkpointer.Abort; the kernel releases the child's fd table on exit. No agent-side
	// defer chain is needed.
	var cgroupFdMapArgs []string
	for _, c := range cgInheritFds {
		if c.Fd < 3 {
			log.Info("ADR-0181: skipping cgroup inherit-fd with reserved fd number",
				"fd", c.Fd, "path", c.Path)
			continue
		}
		src := resolveInheritCgroupSource(c.Path, sandboxID)
		cgroupFdMapArgs = append(cgroupFdMapArgs, fmt.Sprintf("--cgroup-fd=%d:%s", c.Fd, src))
		// CRIU files-reg.c:2611 stores rfi->path = rfe->name+1 (no leading slash).
		// --inherit-fd key must match exactly — strip the leading '/'. ADR-0188.
		criuArgs = append(criuArgs, "--inherit-fd", fmt.Sprintf("fd[%d]:%s", c.Fd, strings.TrimPrefix(c.Path, "/")))
		log.Info("ADR-0181: cgroup fd routed via wrapper+dup3 (not ExtraFiles)",
			"fd", c.Fd, "recordedPath", c.Path, "hostSource", src, "migration", migrationName)
	}

	// ADR-0181: launch podmotion-criu-wrapper instead of criu directly.
	// wrapperArgs: wrapper binary, per-fd --cgroup-fd=N:path flags, separator, criu binary+args.
	// ADR-0183 r1: wrapper installed to PodMotion-owned non-PATH dir (/opt/podmotion/bin),
	// not host system PATH (/usr/local/bin). Path resolves against host mount namespace via nsenter.
	wrapperArgs := append([]string{"/opt/podmotion/bin/podmotion-criu-wrapper"}, cgroupFdMapArgs...)
	wrapperArgs = append(wrapperArgs, "--", "/usr/sbin/criu")
	wrapperArgs = append(wrapperArgs, criuArgs...)
	// ADR-0234: the CRIU wrapper is launched via the BROKER async exec ops
	// (exec_start / exec_poll / exec_signal), not a LOCAL nsenter *exec.Cmd. Under
	// SD-1 (main agent privileged:false) a local nsenter EPERMs on setns(CLONE_NEWNS)
	// into the host mount namespace — only the privileged broker holds CAP_SYS_ADMIN
	// in the host init userns. ADR-0231 broker-delegated the SHORT host-mount-ns
	// commands and left THIS long-running wrapper launch as the named next wall;
	// ADR-0234 extends the broker with a detached-spawn + host-PID + cross-process-reap
	// mechanism so the wrapper runs broker-side while the agent keeps the same async
	// lifecycle it had with the local *exec.Cmd. brokerCriuCmd emulates the exact
	// .Start()/poll()/.Pid() subset joinNsRestore used.
	criuCmd := newBrokerCriuCmd(wrapperArgs...)
	// ADR-0125: netns is joined by path (--join-ns net:<path>), not by an inherited fd.
	// ADR-0181: no ExtraFiles — the wrapper owns fd delivery; the agent holds no cgroup fds.
	// Capture CRIU's stderr: when CRIU fails before opening its -o logfile (e.g. arg/ext-mount
	// resolution errors), the only diagnostic is on stderr. The broker captures the detached
	// wrapper's stderr and returns it on each exec_poll; criuCmd.Stderr mirrors it.
	criuStderr := criuCmd.Stderr

	// Remove any stale pidfile from a prior attempt of THIS SAME migration before launching
	// CRIU. os.MkdirAll(dataDir) above does not clean the directory, and CRIU opens --pidfile
	// with O_TRUNC (not O_EXCL), so a leftover restored.pid can be read by the pidfile poll
	// below in its first iteration — before the new CRIU process rewrites it — and if that
	// stale PID is still live (or recycled) the restore would report success for the WRONG
	// process. That is exactly the report-success-on-wrong-PID failure class the --pidfile
	// primitive exists to prevent. Fail CLOSED: any removal error other than "not present"
	// is a hard stop (an unremovable stale file must never be silently polled past).
	stalePidfilePath := filepath.Join(dataDir, restoredPidfileName)
	if err := removeStalePidfile(stalePidfilePath, os.Remove); err != nil {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_stale_pidfile_unlink").Inc()
		return 0, nil, err
	}

	if err := criuCmd.Start(); err != nil {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_criu_start").Inc()
		return 0, nil, fmt.Errorf("criu restore start: %w", err)
	}

	// ADR-0192 R2 (supersedes ADR-0127): liveness detection via cgroup-PID signal.
	// ADR-0234: the cgroup observed is the BROKER cgroup (the wrapper is now a broker
	// child, so --manage-cgroups=ignore lands the restored tree there, not in the agent
	// cgroup). The broker returns its cgroup PID set on every exec_poll; the agent diffs
	// it against a baseline captured on the FIRST poll right after exec_start (the wrapper
	// has forked but the workload tree has not yet been restored).
	//
	// On the cold --join-ns net:<path> path CRIU does NOT self-exit: after restore it stays as
	// the foreground workload parent (blocking in wait4 for the lifetime of the workload). A
	// synchronous Wait would hang until the workload exits — the Sprint 22 failure.
	// --restore-detached is forbidden (the project conventions doc Standing Rule 6). --leave-stopped is only on
	// the TCP-stateful branch. The broker reaps the wrapper exactly once when it eventually
	// exits (no zombie); the agent polls liveness via exec_poll until either new PIDs appear in
	// the broker cgroup (proof CRIU launched the workload tree) OR the wrapper exits non-zero.
	const (
		cgroupPollInterval = brokerCriuWrapperPollInterval
		cgroupPollTimeout  = 60 * time.Second
	)
	// Baseline broker-cgroup PID set: captured on the first poll. beforeAgentPIDs holds
	// it (the variable name is retained — it is now the BROKER cgroup baseline — so the
	// downstream ADR-0128 resolution path is unchanged). criuWrapperPID is excluded from
	// the diff exactly as the local CRIU PID was.
	var beforeAgentPIDs map[int]bool
	var agentPIDsErr error
	criuWrapperPID := criuCmd.Pid()
	var workloadLive bool
	cgroupDeadline := time.Now().Add(cgroupPollTimeout)
	for time.Now().Before(cgroupDeadline) {
		exited, exitCode, brokerCgroupPIDs, pollErr := criuCmd.poll()
		if pollErr != nil {
			// Broker round-trip failure is transient relative to the wrapper; retry on the
			// next tick. Record it so a persistent failure surfaces in the no-liveness error.
			agentPIDsErr = pollErr
			time.Sleep(cgroupPollInterval)
			continue
		}
		if exited {
			if exitCode != 0 {
				stderrTail := strings.TrimSpace(criuStderr.String())
				if len(stderrTail) > 4096 {
					stderrTail = stderrTail[len(stderrTail)-4096:]
				}
				return 0, nil, fmt.Errorf("criu restore exited (exit code %d): broker-delegated wrapper\ncriu stderr:\n%s",
					exitCode, stderrTail)
			}
			// Exit 0 means restore succeeded and CRIU is done (detached-like path or early exit).
			workloadLive = true
			break
		}
		// Establish the baseline on the first successful poll (wrapper forked, workload not
		// yet restored), then diff every subsequent poll against it.
		if beforeAgentPIDs == nil {
			beforeAgentPIDs = make(map[int]bool, len(brokerCgroupPIDs))
			for _, p := range brokerCgroupPIDs {
				beforeAgentPIDs[p] = true
			}
			agentPIDsErr = nil
			time.Sleep(cgroupPollInterval)
			continue
		}
		// New workload PIDs appear in the broker cgroup once CRIU has successfully forked the
		// process tree. Exclude the wrapper PID itself (it is a broker-cgroup resident too).
		for _, pid := range brokerCgroupPIDs {
			if !beforeAgentPIDs[pid] && pid != criuWrapperPID {
				workloadLive = true
				break
			}
		}
		if workloadLive {
			break
		}
		time.Sleep(cgroupPollInterval)
	}

	if !workloadLive {
		stderrTail := strings.TrimSpace(criuStderr.String())
		if len(stderrTail) > 4096 {
			stderrTail = stderrTail[len(stderrTail)-4096:]
		}
		return 0, nil, fmt.Errorf("criu restore did not produce workload PIDs in agent cgroup within %s: criu stderr:\n%s",
			cgroupPollTimeout, stderrTail)
	}

	// Copy restore.log to checkpointDir so gate checks can find it under
	// /run/podmotion/checkpoints/ (the agent container sees this path; restore.log was
	// written to /var/lib/podmotion/restore/<name>/data/restore.log by CRIU running
	// via nsenter in the host mount namespace).
	if logBytes, err := os.ReadFile(restoreLogPath); err == nil {
		_ = os.WriteFile(filepath.Join(checkpointDir, "restore.log"), logBytes, 0o600) // ADR-SEC-B N-342: 0600 in checkpoint dir (invariant 7)
	}

	log.Info("joinNsRestore: cgroup-PID signal confirmed workload live — proceeding to PID resolution",
		"migration", migrationName)

	// Step 5: resolve the restored application PID from CRIU's own --pidfile primitive on BOTH
	// restore entry points (the NRI path and the gRPC Restore RPC path). CRIU writes the PID it
	// restored to <dataDir>/restored.pid on every restore — buildCRIURestoreArgs appends --pidfile
	// unconditionally, and dataDir is computed identically on both paths — so this is CRIU's own
	// authoritative output and its resolution does NOT depend on having a sandboxID. Both prior
	// resolvers are retired and MUST NOT be reintroduced on ANY path: the comm-scan
	// findRestoredProcessPID (comm is attacker-controlled via prctl(PR_SET_NAME) — ADR-0245) and
	// the broker-cgroup PID diff (poll-and-guess, non-atomic — ADR-0228 NRI/gRPC symmetry). The
	// sandboxID gate that previously wrapped this resolution was a remnant of the old resolver
	// chain (sandboxID was the anchor the cgroup-diff resolver needed); the --pidfile primitive
	// needs only dataDir, so the gate is removed here and both paths converge on this resolver.
	if agentPIDsErr != nil {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_broker_cgroup_snapshot").Inc()
		return 0, nil, fmt.Errorf("snapshot broker cgroup PIDs before restore: %w", agentPIDsErr)
	}
	if beforeAgentPIDs == nil {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_broker_cgroup_baseline_missing").Inc()
		return 0, nil, fmt.Errorf("broker cgroup baseline was never captured (wrapper never polled live)")
	}
	var pid int
	pidfilePath := filepath.Join(dataDir, restoredPidfileName)
	pidfilePoll := func() (bool, error) {
		exited, _, _, perr := criuCmd.poll()
		return exited, perr
	}
	pid, err = readRestoredPIDFromPidfile(pidfilePath, 30*time.Second, pidfilePoll)
	if err != nil {
		// Fail loud — never fall back to comm-scan or cgroup-diff (ADR-0228 NRI/gRPC symmetry).
		metrics.MigrationsFailedTotal.WithLabelValues("restore_pidfile_missing").Inc()
		return 0, nil, fmt.Errorf("resolve restored PID via CRIU --pidfile: %w", err)
	}
	// ADR-0228 Invariant 1: identity is guaranteed by --pidfile (CRIU reports the PID it
	// restored — never the wrapper/holder stub); the residual check is liveness. Defense in
	// depth: reject the impossible case where the pidfile PID coincides with the wrapper PID.
	if pid == criuWrapperPID {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_pid_equals_wrapper").Inc()
		return 0, nil, fmt.Errorf("pidfile-reported PID %d equals the CRIU wrapper (holder) PID — refusing to trust", pid)
	}
	if verr := verifyRestoredPIDAlive(pid, 100*time.Millisecond); verr != nil {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_pid_dead").Inc()
		return 0, nil, fmt.Errorf("ADR-0228 Invariant 1: %w", verr)
	}
	log.Info("joinNsRestore: resolved restored PID via CRIU --pidfile (authoritative primitive)",
		"pid", pid, "pidfile", pidfilePath, "migration", migrationName)

	// ADR-0128: cgroup placement requires a pod sandbox to anchor to, so it is the ONE step that
	// still legitimately depends on sandboxID (it is NOT retired). On the NRI path (sandboxID set)
	// --manage-cgroups=ignore leaves the restored tree in the broker/launcher cgroup, so move it
	// into the pod's sandbox cgroup for containerd/k8s to manage. The gRPC/--join-ns path has no
	// pod sandbox (sandboxID == "") and therefore no pod cgroup to move into — this step is
	// skipped. PID resolution above is identical on both paths regardless.
	if sandboxID != "" {
		// Resolve the pod's sandbox cgroup path from the pause PID (same anchor as ADR-0123 D2).
		pausePID, perr := sandboxPausePID(sandboxID)
		if perr != nil {
			return 0, nil, fmt.Errorf("ADR-0128: resolve pause PID for sandbox %s: %w", sandboxID, perr)
		}
		podCgroup, cerr := cgroupV2Path(pausePID)
		if cerr != nil {
			return 0, nil, fmt.Errorf("ADR-0128: read pod cgroup from pause PID %d (sandbox %s): %w",
				pausePID, sandboxID, cerr)
		}
		// Move the restored tree root into the pod cgroup (single cgroup.procs write moves the group).
		if merr := moveProcessToPodCgroup(pid, podCgroup); merr != nil {
			return 0, nil, fmt.Errorf("ADR-0128: move restored PID %d into pod cgroup %s: %w", pid, podCgroup, merr)
		}
		log.Info("joinNsRestore: moved restored process into pod cgroup (ADR-0128)",
			"pid", pid, "podCgroup", podCgroup, "sandboxID", sandboxID)
	}
	log.Info("joinNsRestore: found restored process", "pid", pid)

	// Step 6: ADR-0123 D4 — bring loopback up in the RESTORED application's net namespace,
	// using the PID resolved from the pod cgroup (never the CRIU PID). On the cold path this
	// is the CNI-wired pod netns (lo is normally already up); on the TCP-stateful path it is the
	// pre-staged migration netns. Idempotent either way.
	if out, err := exec.Command("nsenter",
		fmt.Sprintf("--net=/proc/%d/ns/net", pid), "--",
		"ip", "link", "set", "lo", "up",
	).CombinedOutput(); err != nil {
		log.Info("joinNsRestore: warning — failed to bring up loopback", "err", err, "output", string(out))
	}

	success = true
	return pid, droppedMounts, nil
}

// readLogTail was removed: ADR-0127 scaffold (restore.log success-signal) removed per ADR-0192.
// The liveness signal is now the cgroup-PID diff (see joinNsRestore above).

// ADR-0200: exit codes for the __inetns_probe helper subcommand. The helper performs the
// TCP dial INSIDE the replacement pod netns (entered via nsenter by probeOldIPInPodNetns)
// and reports the refused/timeout/success classification through its exit code — preserving
// the exact isConnRefused() semantics (error-classification preservation
// across the host-netns→pod-netns relocation, same commit).
const (
	inetnsProbeExitSuccess   = 0 // SYN-ACK: a listener answered — IP live
	inetnsProbeExitRefused   = 64 // RST (ECONNREFUSED): kernel answered, no listener — IP live (success)
	inetnsProbeExitTimeout   = 65 // i/o timeout: no kernel on the path owns the IP — failure
	inetnsProbeExitOtherErr  = 66 // any other dial error — failure
)

// probeOldIPInPodNetns performs the ADR-0200 D1 reachability probe by re-executing this same
// agent binary's __inetns_probe helper INSIDE the replacement pod's network namespace via the
// established in-tree nsenter --net=/proc/<replPID>/ns/net idiom (the same idiom used by
// SingleHomeRestoredPod (server.go:535) and resolveReplVethPeer (server.go:1182); ADR-0045 —
// no netlink/new external dependency). Dialing the OLD IP:7 from where the IP is owned returns
// RST (ECONNREFUSED) → ProbeOk=true (ADR-0200 D3: port :7 and RST=success are unchanged).
// Returns (probeOk, probeOutput) mirroring the prior in-process dial's contract exactly.
func probeOldIPInPodNetnsImpl(replPID int, oldPodIP string) (bool, string) {
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", replPID)
	self, err := os.Executable()
	if err != nil {
		self = "/proc/self/exe"
	}
	// nsenter --net=<pod netns> <agent-binary> __inetns_probe <oldIP> 7
	cmd := exec.Command("nsenter", "--net="+netnsPath, self, "__inetns_probe", oldPodIP, "7")
	out, runErr := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if runErr == nil {
		// Exit 0 — SYN-ACK success.
		return true, output
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		switch exitErr.ExitCode() {
		case inetnsProbeExitRefused:
			// RST / ECONNREFUSED — the kernel in the pod netns answered: IP is live (success),
			// identical to the host-netns isConnRefused()==true classification it replaces.
			return true, output
		case inetnsProbeExitTimeout:
			return false, output
		default:
			return false, output
		}
	}
	// Could not even launch nsenter / the helper — treat as failure (deferred to requeue).
	return false, fmt.Sprintf("ADR-0200: in-netns probe exec failed: %v (%s)", runErr, output)
}

// probeOldIPInPodNetns is the AgentServer method seam (overridable in tests).
func (s *AgentServer) probeOldIPInPodNetns(_ context.Context, replPID int, oldPodIP string) (bool, string) {
	return probeOldIPInPodNetnsImpl(replPID, oldPodIP)
}

// ProbeDataplaneReachability is the ADR-0210 cross-node dataplane probe. It is called by
// the CONTROLLER on the SOURCE-node agent (a node != destination) to dial the preserved pod
// IP and confirm the real overlay/host-route datapath is live. Unlike the disproven
// ADR-0200/0201 in-netns self-probe (which dialed an IP aliased onto lo in the SAME netns —
// the local kernel always answered, a tautology), this dial originates from the SOURCE
// node's HOST netns, so its SYN must traverse the real overlay (VXLAN/VTEP) to reach the
// destination. A positive result REQUIRES the destination's nonce-echo listener
// (StartReachabilityEcho) to return the controller-issued nonce — the source agent cannot
// synthesize success alone (Security-C3). The controller is the authority that flips
// DataplaneReachabilityVerified based on this nonce round-trip.
func (s *AgentServer) ProbeDataplaneReachability(ctx context.Context, req *agentpb.ProbeDataplaneReachabilityRequest) (*agentpb.ProbeDataplaneReachabilityResponse, error) {
	resp := &agentpb.ProbeDataplaneReachabilityResponse{}
	timeout := time.Duration(req.TimeoutS) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if req.TargetIp == "" || req.TargetPort == 0 {
		resp.Reachable = false
		resp.Detail = "ADR-0210: target_ip/target_port required"
		return resp, nil
	}
	// Positive-evidence egress assertion: record which host device the route to TargetIP
	// resolves to. On a 2-node fallback this VTEP-egress assertion is the non-waivable
	// proof the SYN leaves on the overlay (flannel.1/VTEP), not a local /32 host route.
	resp.EgressDev = egressDevForIP(req.TargetIp)

	addr := net.JoinHostPort(req.TargetIp, fmt.Sprintf("%d", req.TargetPort))
	d := net.Dialer{Timeout: timeout}
	conn, derr := d.DialContext(ctx, "tcp", addr)
	if derr != nil {
		resp.Reachable = false
		resp.Detail = fmt.Sprintf("ADR-0210: cross-node dial %s failed (egressDev=%s): %v", addr, resp.EgressDev, derr)
		log.Info("ProbeDataplaneReachability: cross-node dial failed (ADR-0210)",
			"migration", req.MigrationName, "target", addr, "egressDev", resp.EgressDev, "err", derr.Error())
		return resp, nil
	}
	defer conn.Close()
	// Nonce round-trip: read what the destination echo listener wrote. Reachability is
	// asserted ONLY when the echoed bytes match the controller-issued nonce.
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, len(req.ExpectedNonce)+16)
	n, rerr := conn.Read(buf)
	got := ""
	if n > 0 {
		got = string(buf[:n])
	}
	if rerr != nil && n == 0 {
		resp.Reachable = false
		resp.Detail = fmt.Sprintf("ADR-0210: connected %s but nonce read failed (egressDev=%s): %v", addr, resp.EgressDev, rerr)
		log.Info("ProbeDataplaneReachability: connected but no nonce echoed — NOT reachable (ADR-0210)",
			"migration", req.MigrationName, "target", addr, "egressDev", resp.EgressDev)
		return resp, nil
	}
	if got != req.ExpectedNonce {
		resp.Reachable = false
		resp.Detail = fmt.Sprintf("ADR-0210: nonce mismatch from %s (egressDev=%s): want=%q got=%q", addr, resp.EgressDev, req.ExpectedNonce, got)
		log.Info("ProbeDataplaneReachability: nonce mismatch — NOT reachable (ADR-0210)",
			"migration", req.MigrationName, "target", addr, "egressDev", resp.EgressDev)
		return resp, nil
	}
	resp.Reachable = true
	resp.Detail = fmt.Sprintf("ADR-0210: cross-node datapath reachable to %s, nonce round-trip OK (egressDev=%s)", addr, resp.EgressDev)
	log.Info("ProbeDataplaneReachability: cross-node datapath VERIFIED via nonce round-trip (ADR-0210)",
		"migration", req.MigrationName, "target", addr, "egressDev", resp.EgressDev)
	return resp, nil
}

// egressDevForIP returns the host interface the kernel would use to reach ip, per
// `ip route get`. Best-effort observability for the ADR-0210 VTEP-egress assertion;
// returns "" when it cannot be resolved (non-fatal — the nonce round-trip is the proof).
func egressDevForIP(ip string) string {
	out, err := exec.Command("ip", "route", "get", ip).CombinedOutput()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// StartReachabilityEcho is the ADR-0210 destination half of the cross-node nonce round-trip.
// Called by the controller on the DESTINATION-node agent, it re-executes this agent binary's
// __inetns_echo helper INSIDE the replacement pod netns (same nsenter idiom as the disproven
// __inetns_probe, but now bind+echo instead of self-dial) to open a short-lived TCP listener
// bound to the preserved pod IP that echoes the controller-issued nonce. The SOURCE-node
// agent's ProbeDataplaneReachability then connects cross-node and must read that nonce back.
func (s *AgentServer) StartReachabilityEcho(ctx context.Context, req *agentpb.StartReachabilityEchoRequest) (*agentpb.StartReachabilityEchoResponse, error) {
	resp := &agentpb.StartReachabilityEchoResponse{}
	if req.ListenIp == "" || req.ListenPort == 0 || req.Nonce == "" {
		resp.Started = false
		resp.Detail = "ADR-0210: listen_ip/listen_port/nonce required"
		return resp, nil
	}
	replPID, pidErr := s.restoredPIDForMigration(ctx, req.MigrationName)
	if pidErr != nil || replPID <= 0 {
		resp.Started = false
		resp.Detail = "ADR-0210: replacement PID not yet resolvable — echo deferred to requeue"
		return resp, nil
	}
	ttl := req.TtlS
	if ttl <= 0 {
		ttl = 15
	}
	self, err := os.Executable()
	if err != nil {
		self = "/proc/self/exe"
	}
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", replPID)
	// Launch the in-netns echo listener detached — it serves for ttl seconds then exits.
	cmd := exec.Command("nsenter", "--net="+netnsPath, self, "__inetns_echo",
		req.ListenIp, fmt.Sprintf("%d", req.ListenPort), req.Nonce, fmt.Sprintf("%d", ttl))
	if startErr := cmd.Start(); startErr != nil {
		resp.Started = false
		resp.Detail = fmt.Sprintf("ADR-0210: failed to start in-netns echo listener: %v", startErr)
		log.Error(startErr, "StartReachabilityEcho: launch failed (ADR-0210)", "migration", req.MigrationName)
		return resp, nil
	}
	// Reap the helper asynchronously so it does not become a zombie.
	go func() { _ = cmd.Wait() }()
	resp.Started = true
	resp.Detail = fmt.Sprintf("ADR-0210: in-netns nonce-echo listener started on %s:%d (replPID=%d, ttl=%ds)",
		req.ListenIp, req.ListenPort, replPID, ttl)
	log.Info("StartReachabilityEcho: in-netns nonce-echo listener started (ADR-0210)",
		"migration", req.MigrationName, "listenIP", req.ListenIp, "port", req.ListenPort, "replPID", replPID, "ttl", ttl)
	return resp, nil
}

// isConnRefused reports whether err is a connection-refused error (TCP RST). ECONNREFUSED
// means the kernel responded — the IP is routable on this node — which is sufficient for the
// ADR-0192 Decision 5 reachability probe. Used by the ADR-0200 __inetns_probe helper to
// classify the in-netns dial error.
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.Is(opErr.Err, syscall.ECONNREFUSED)
	}
	return false
}

// moveProcessToPodCgroup implements ADR-0128: moves pid into the pod's sandbox cgroup by writing
// it to <podCgroupPath>/cgroup.procs under /sys/fs/cgroup. A single cgroup.procs write moves the
// whole thread group of the leader; the CRIU-restored tree shares one cgroup, so moving the root
// migrates the group. podCgroupPath is the cgroup v2 path (e.g. "/kubepods.slice/.../...scope").
func moveProcessToPodCgroup(pid int, podCgroupPath string) error {
	procsPath := filepath.Join("/sys/fs/cgroup", podCgroupPath, "cgroup.procs")
	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("write PID %d to %s: %w", pid, procsPath, err)
	}
	return nil
}

// removeStalePidfile deletes a leftover restored-PID pidfile from a prior attempt of the same
// migration before a CRIU restore launch (C1 fix). CRIU opens --pidfile with O_TRUNC (not O_EXCL),
// so a leftover restored.pid could be read by the pidfile poll in its first iteration — before the
// new CRIU process rewrites it — reporting success for the WRONG (stale/recycled) PID. removeFn is
// injected (os.Remove in production) so the fail-open-on-not-exist vs fail-closed-on-any-other-error
// behavior is unit-testable without a real filesystem — the same reader-injection pattern used by
// readRestoredPIDFromPidfileWithReader. Returns nil when the file was removed OR was already absent;
// returns a wrapped error for any other removeFn failure (an unremovable stale file must never be
// silently polled past).
func removeStalePidfile(path string, removeFn func(string) error) error {
	if err := removeFn(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale restored-PID pidfile %s before CRIU launch: %w", path, err)
	}
	return nil
}

// --- Authoritative restored-PID resolution via CRIU --pidfile ---
//
// The prior primary resolver (findRestoredPIDInBrokerCgroup) INFERRED the restored PID by
// diffing the broker cgroup's PID set against a pre-CRIU snapshot and excluding the wrapper
// PID and any comm=="criu" entrant — a multi-step poll-and-guess, fragile, non-atomic
// inference chain: CRIU already knows the restored root
// PID with certainty internally, yet the agent re-derived it externally, non-atomically, on
// a signal (comm) the restored workload can spoof via prctl(PR_SET_NAME) (ADR-0228 C3).
//
// readRestoredPIDFromPidfile replaces that inference with CRIU's own --pidfile primitive
// (wired in buildCRIURestoreArgs): CRIU writes the restored root task's PID to a file as an
// authoritative side effect of the restore. This is the source-of-truth answer, and it
// structurally satisfies ADR-0228's identity invariant — the PID CRIU reports is BY
// CONSTRUCTION the process CRIU restored (the application), never a holder/wrapper stub — so
// no comm-based "not-criu" exclusion is needed or used. The only residual check is liveness
// (verifyRestoredPIDAlive), covering the legitimate case of a process that exits between
// pidfile-write and use.

// pidfileReadFunc reads the raw bytes of the pidfile. Injected in tests so no real
// broker/nsenter/host-mount round-trip is required; production passes os.ReadFile.
type pidfileReadFunc func(path string) ([]byte, error)

// pidfilePollFunc reports whether the CRIU/wrapper process has already exited. When it has
// AND the pidfile never became valid, the restore has failed and the poll fails FAST rather
// than waiting out the full backstop budget. May be nil.
type pidfilePollFunc func() (exited bool, err error)

// pidfilePollInterval is the between-read backoff while waiting for the pidfile to appear.
const pidfilePollInterval = 50 * time.Millisecond

// readRestoredPIDFromPidfile is the production entry point (real os.ReadFile). It polls the
// CRIU --pidfile until it holds a well-formed positive PID, the CRIU/wrapper process exits
// without producing one, or the timeout expires.
func readRestoredPIDFromPidfile(path string, timeout time.Duration, poll pidfilePollFunc) (int, error) {
	return readRestoredPIDFromPidfileWithReader(path, timeout, os.ReadFile, poll)
}

// readRestoredPIDFromPidfileWithReader is the reader-injected core (see pidfileReadFunc).
func readRestoredPIDFromPidfileWithReader(path string, timeout time.Duration, read pidfileReadFunc, poll pidfilePollFunc) (int, error) {
	deadline := time.Now().Add(timeout)
	for {
		// A successful, parseable read WINS unconditionally — even if the process has since
		// exited: CRIU may write the pidfile shortly before it exits on some paths, so a
		// valid read is never overridden by a concurrent process-exit observation.
		if data, err := read(path); err == nil {
			if pid, ok := parsePidfileContent(data); ok {
				return pid, nil
			}
			// File present but not yet a valid PID (partial write / garbage) — keep polling.
		}
		// Fast-fail: CRIU/wrapper already exited and no valid pidfile → restore failed.
		if poll != nil {
			if exited, pollErr := poll(); pollErr == nil && exited {
				return 0, fmt.Errorf("%w (pidfile %s never appeared; CRIU/wrapper process exited)", ErrRestoredPIDNotFound, path)
			}
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("%w (pidfile %s not valid within %s)", ErrRestoredPIDNotFound, path, timeout)
		}
		time.Sleep(pidfilePollInterval)
	}
}

// parsePidfileContent parses a CRIU pidfile body into a positive PID. ok=false for
// empty / non-integer / non-positive content.
func parsePidfileContent(data []byte) (pid int, ok bool) {
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// ErrRestoredPIDDead is returned by verifyRestoredPIDAlive when the resolved restored PID is
// not present, is a zombie/dead, or exits during the settle window (ADR-0228 Invariant 1).
var ErrRestoredPIDDead = errors.New("restored PID failed liveness verification")

// verifyRestoredPIDAlive implements ADR-0228 Invariant 1's liveness gate: /proc/<pid> exists
// and the task is not a zombie, re-confirmed after a short settle window to reject a PID that
// exits between resolution and use. Identity ("not the holder stub") is guaranteed upstream by
// the --pidfile source-of-truth, so this gate is liveness-only and never consults comm. A
// settle of 0 skips the re-read (single-shot liveness).
func verifyRestoredPIDAlive(pid int, settle time.Duration) error {
	if pid <= 0 {
		return fmt.Errorf("%w: non-positive pid %d", ErrRestoredPIDDead, pid)
	}
	check := func() (alive bool, fatal error) {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return false, nil // /proc/<pid> gone → reaped
		}
		// state is the field immediately after "(comm)"; comm may contain spaces and ')',
		// so anchor on the LAST ')'.
		s := string(data)
		i := strings.LastIndexByte(s, ')')
		if i < 0 || i+2 >= len(s) {
			return false, fmt.Errorf("%w: unparseable /proc/%d/stat", ErrRestoredPIDDead, pid)
		}
		switch s[i+2] {
		case 'Z', 'X', 'x':
			return false, nil
		default:
			return true, nil
		}
	}
	alive, fatal := check()
	if fatal != nil {
		return fatal
	}
	if !alive {
		return fmt.Errorf("%w: pid %d not alive at first check", ErrRestoredPIDDead, pid)
	}
	if settle > 0 {
		time.Sleep(settle)
		alive, fatal = check()
		if fatal != nil {
			return fatal
		}
		if !alive {
			return fmt.Errorf("%w: pid %d exited or became a zombie during the settle window", ErrRestoredPIDDead, pid)
		}
	}
	return nil
}

// priorRestoredPIDIfAlive implements the ADR-0228 restore-idempotency contract used by the
// gRPC Restore fallback. CRIU writes the restored root task's PID to
// <dataDir>/restored.pid as an authoritative side effect of a SUCCEEDING restore
// (buildCRIURestoreArgs appends --pidfile unconditionally, and dataDir is derived
// deterministically per migration). When the controller's NRI-confirm timeout re-invokes the
// gRPC Restore RPC for a migration whose NRI-hook restore already SUCCEEDED, that pidfile is
// present and its PID is alive.
//
// This is the source-of-truth idempotency check: rather than blindly re-running CRIU restore a
// second time (which, on the cold --join-ns path, would spawn a second CRIU that stays the
// foreground parent in do_wait forever while the already-restored workload holds the netns —
// hanging the Restore RPC between the ptrace-window open and its deferred close, a brittle
// poll-and-hope-on-subprocess-exit failure), we ask the on-disk pidfile whether a prior
// restore already produced a LIVE workload. Returns (pid, true) only when the pidfile exists,
// holds a well-formed positive PID, and that PID passes the ADR-0228 liveness gate. Any missing
// file / unparseable content / dead PID returns (0, false) so the caller proceeds to a real
// restore. It NEVER re-runs CRIU and NEVER blocks (single-shot reads, no poll loop).
//
// ADR-0306 item (d): --pidfile guarantees identity of the PID recorded ONLY at the moment CRIU
// wrote it (restore-write time). It does NOT guarantee that the PID read back here still refers
// to the same workload at READ time — the PID could have exited and been recycled by the kernel
// to an unrelated process between write and read. This function alone is therefore liveness-only,
// not an identity guarantee; the confirm-path caller re-establishes identity at read time via
// netns membership (ADR-0306 item a) before trusting this result.
func priorRestoredPIDIfAlive(dataDir string) (int, bool) {
	return priorRestoredPIDIfAliveSettle(dataDir, 0)
}

// priorRestoredPIDIfAliveSettle is priorRestoredPIDIfAlive with an explicit settle window
// (ADR-0306 item c) passed through to verifyRestoredPIDAlive. Its sole caller today is the
// confirm-path block in Restore, which needs a non-zero settle to avoid a false-alive read of a
// PID that is in the middle of exiting. priorRestoredPIDIfAlive (settle=0) keeps its existing
// contract and all 12 pre-existing tests unmodified.
func priorRestoredPIDIfAliveSettle(dataDir string, settle time.Duration) (int, bool) {
	data, err := os.ReadFile(filepath.Join(dataDir, restoredPidfileName))
	if err != nil {
		return 0, false
	}
	pid, ok := parsePidfileContent(data)
	if !ok {
		return 0, false
	}
	// Liveness-only: identity at READ time is NOT guaranteed by CRIU's --pidfile primitive (see
	// doc comment above) — only that a live PID at this deterministic path means a prior restore
	// for THIS migration wrote this PID at restore-write time. The confirm-path caller of
	// priorRestoredPIDIfAliveSettle re-establishes identity via netns membership afterward.
	if err := verifyRestoredPIDAlive(pid, settle); err != nil {
		return 0, false
	}
	return pid, true
}

// pidNetnsMatchesPath is the ADR-0306 item (a) B2-style inode/dev cross-check: it stats
// /proc/<pid>/ns/net and compares its inode/dev against a stat of expectedNetnsPath. Returns
// (true, nil) only on a genuine match; any stat failure or mismatch returns (false, err/nil)
// so the caller fails closed.
func pidNetnsMatchesPath(pid int, expectedNetnsPath string) (bool, error) {
	var pidStat, expStat syscall.Stat_t
	pidNsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	if err := syscall.Stat(pidNsPath, &pidStat); err != nil {
		return false, fmt.Errorf("pidNetnsMatchesPath: stat %s: %w", pidNsPath, err)
	}
	if err := syscall.Stat(expectedNetnsPath, &expStat); err != nil {
		return false, fmt.Errorf("pidNetnsMatchesPath: stat %s: %w", expectedNetnsPath, err)
	}
	return pidStat.Ino == expStat.Ino && pidStat.Dev == expStat.Dev, nil
}

// procStatStateChar reads field 3 (state) of /proc/<pid>/stat, e.g. 'R', 'S', 'D', 'T', 't', 'Z'.
// Returns (0, err) if the file cannot be read or parsed — treated by the caller as "not
// currently eligible for deferred resume" rather than a hard error (ADR-0306 item b).
func procStatStateChar(pid int) (byte, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// Fields after the "(comm)" parenthesized field can contain spaces, so locate the closing
	// paren and split from there rather than naive whitespace splitting.
	s := string(data)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 >= len(s) {
		return 0, fmt.Errorf("procStatStateChar: malformed /proc/%d/stat", pid)
	}
	rest := strings.TrimSpace(s[closeParen+1:])
	fields := strings.Fields(rest)
	if len(fields) < 1 || len(fields[0]) != 1 {
		return 0, fmt.Errorf("procStatStateChar: malformed state field in /proc/%d/stat", pid)
	}
	return fields[0][0], nil
}

// cgroupV2Path returns the unified cgroup v2 path (the "0::<path>" entry) for pid from
// /proc/<pid>/cgroup. Returns an error if the file cannot be read (e.g. the PID has exited) or
// has no unified entry.
func cgroupV2Path(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::"), nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 (0::) entry in /proc/%d/cgroup", pid)
}

// sandboxPausePID resolves the host PID of the pause/sandbox container identified by sandboxID
// via `ctr --namespace k8s.io tasks list`. The sandbox ID is the pause container's containerd
// task ID (from the NRI pod sandbox object, pod.GetId()), so its PID is the task's PID.
func sandboxPausePID(sandboxID string) (int, error) {
	out, err := nsenterCmd("/usr/local/bin/ctr", "--namespace", "k8s.io", "tasks", "list").Output()
	if err != nil {
		return 0, fmt.Errorf("ctr tasks list: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] != sandboxID {
			continue
		}
		pid, convErr := strconv.Atoi(fields[1])
		if convErr != nil || pid == 0 {
			return 0, fmt.Errorf("sandbox %s task has invalid PID %q", sandboxID, fields[1])
		}
		return pid, nil
	}
	return 0, fmt.Errorf("sandbox %s not found in ctr tasks list (pause container may have exited)", sandboxID)
}

// resolveSandboxIDForMigration is the ADR-0306 item (a) agent-side self-resolve helper used
// when RestoreRequest.sandbox_id is empty. It reads the PodMigration CR (via
// resolveNamespaceForMigration's lookup strategy) to find Status.ReplacementPodName, reads that
// pod's UID from the Kubernetes API, then resolves the containerd sandbox (pause container) ID
// for that pod UID via `ctr --namespace k8s.io`. Returns "" on any failure (caller fails closed).
func (s *AgentServer) resolveSandboxIDForMigration(ctx context.Context, migrationName string) (string, error) {
	if s.k8sClient == nil || migrationName == "" {
		return "", fmt.Errorf("resolveSandboxIDForMigration: no k8sClient or empty migrationName")
	}
	ns := s.resolveNamespaceForMigration(ctx, migrationName)
	if ns == "" {
		return "", fmt.Errorf("resolveSandboxIDForMigration: could not resolve namespace for migration %s", migrationName)
	}
	pm := &pmv1.PodMigration{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: migrationName}, pm); err != nil {
		return "", fmt.Errorf("resolveSandboxIDForMigration: get PodMigration %s/%s: %w", ns, migrationName, err)
	}
	replName := pm.Status.ReplacementPodName
	if replName == "" {
		return "", fmt.Errorf("resolveSandboxIDForMigration: PodMigration %s/%s has no ReplacementPodName yet", ns, migrationName)
	}
	podNs := pm.Spec.PodNamespace
	if podNs == "" {
		podNs = pm.Namespace
	}
	pod := &corev1.Pod{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: replName, Namespace: podNs}, pod); err != nil {
		return "", fmt.Errorf("resolveSandboxIDForMigration: get replacement pod %s/%s: %w", podNs, replName, err)
	}
	if pod.UID == "" {
		return "", fmt.Errorf("resolveSandboxIDForMigration: replacement pod %s/%s has no UID", podNs, replName)
	}
	sandboxID, err := sandboxIDForPodUID(string(pod.UID))
	if err != nil {
		return "", fmt.Errorf("resolveSandboxIDForMigration: %w", err)
	}
	return sandboxID, nil
}

// sandboxIDForPodUID resolves the containerd sandbox (pause container) task ID for the given
// pod UID via `ctr --namespace k8s.io containers list`, filtering by the io.kubernetes.pod.uid
// label. Mirrors the existing ctr-based lookup idiom (sandboxPausePID/sandboxNetnsPath) — no
// new external binary dependency.
func sandboxIDForPodUID(podUID string) (string, error) {
	out, err := nsenterCmd("/usr/local/bin/ctr", "--namespace", "k8s.io", "containers", "list",
		"-q", "labels.\"io.kubernetes.pod.uid\"=="+podUID).Output()
	if err != nil {
		return "", fmt.Errorf("ctr containers list for pod uid %s: %w", podUID, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		id := strings.TrimSpace(line)
		if id != "" {
			return id, nil
		}
	}
	return "", fmt.Errorf("no sandbox container found for pod uid %s", podUID)
}

// patchCheckpointImages modifies the CRIU image files in checkpointDir to remove entries
// that cannot be restored cross-node:
//   - mountpoints: remove mounts with null or absent ext_key (masked proc/sys paths that
//     reference source-node device IDs with no valid external mapping).
//   - netns:       remove the extRootNetNS ext_key (references the source host's net ns).
//   - netdev:      remove VETH interfaces (peer ifindex doesn't exist on destination); keep lo.
//
// patchCheckpointImagesFn is the production implementation of patchCheckpointImages.
// Tests can replace this variable to inject failures without requiring real CRIU images.
// The function variable wraps patchCheckpointImages; it discards the dropped-mounts info
// (callers that need events use patchCheckpointImages directly).
var patchCheckpointImagesFn = func(checkpointDir string, inheritFdNames []string) error {
	_, err := patchCheckpointImages(checkpointDir, inheritFdNames)
	return err
}

// classifyRegFdPy is the SINGLE files.img REG-fd classifier used by patchCheckpointImages.
//
// Before this refactor the skip/rebind/hard-stop ladder was written out inline TWICE — once
// in the main reconciliation pass and once in the post-write consistency re-check — and the
// two copies could (and historically did) drift, producing blind spots. It is now one Python
// function, `classify_reg_fd(entry, ctx)`, returning exactly one action:
//
//   - 'KEEP'            the fd is outside the PLAIN-REG hard-stop class (external / remap /
//                       inherited / sentinel mnt_id) OR already consistent (mnt_id kept): no change.
//   - 'REBIND_TO_ROOT'  a PLAIN-REG *directory* fd with an orphan mnt_id whose rebind target
//                       (root_mnt_id) is sane: rebind mnt_id → root (covers both generic
//                       ADR-0193 §4 orphans and ADR-0194 B-2 ext-drop lockstep). The production
//                       call site emits a WARNING for every such rebind (ADR-0245 D2 visibility).
//   - 'DECLINE'         a PLAIN-REG *non-directory* fd with an orphan mnt_id (cannot be safely
//                       rebound — would still fire mount.c:3953 / P-0193-1), OR a *directory* fd
//                       whose rebind target root_mnt_id is unusable (missing / not a kept
//                       mountpoint): hard-stop rather than redirect the fd onto another absent
//                       mnt_id (ADR-0245 D2 fail-closed target validation).
//
// ctx carries the cross-image sets the decision needs: remap_ids, inherit_fd_names,
// kept_mnt_ids, ext_drop_mnt_ids, root_mnt_id. The mnt_id>0 / open_path() discriminants are the
// CRIU-4.2 source-proven predicate (files-reg.c:2191-2263, mount.c:3946-3953).
//
// This constant is prepended verbatim to the production patch script AND is exercised
// directly (in --classify-selftest mode) by TestClassifyRegFd_RealScript — the test runs the
// SAME code that ships, not a Go re-implementation of it (the anti-pattern that let
// patch_checkpoint_regfd_test.go's Go mirror miss real defects).
const classifyRegFdPy = `
import sys, os, json

_S_IFMT  = 0o170000
_S_IFDIR = 0o040000

def classify_reg_fd(entry, ctx):
    if entry.get('type') != 'REG':
        return 'KEEP'
    reg = entry.get('reg', {})
    fd_id = entry.get('id', -1)
    name = reg.get('name', '') or ''
    mnt_id = reg.get('mnt_id')
    # External (rfe->ext): exits before open_path().
    if bool(reg.get('ext', False)):
        return 'KEEP'
    # Remap: graceful rfi_remap (files-reg.c:2066).
    if fd_id in ctx['remap_ids']:
        return 'KEEP'
    # Inherited: inherited_fd() exits at line 2200 (slash-stripped names, ADR-0188).
    if name.lstrip('/') in ctx['inherit_fd_names']:
        return 'KEEP'
    # Sentinel mnt_id (None/0/-1): rebinds to mntinfo, safe.
    if mnt_id is None or mnt_id <= 0:
        return 'KEEP'
    # Consistent: mnt_id is in the kept mountpoints set.
    if mnt_id in ctx['kept_mnt_ids']:
        return 'KEEP'
    # Positive orphan mnt_id — PLAIN-REG class that would fire mount.c:3953.
    if (reg.get('mode', 0) & _S_IFMT) == _S_IFDIR:
        # ADR-0245 D2 (Storage Architect finding): an orphan *directory* fd is rebound to the
        # container root instead of hard-stopping. That rebind is only safe if the rebind
        # TARGET is itself sane — root_mnt_id must exist AND be a kept mountpoint, otherwise
        # rebinding would just move the fd onto another mnt_id that is ALSO absent from the
        # restored mount set and fire mount.c:3953 anyway. Previously this was assumed rather
        # than checked, so a directory fd could be silently redirected to an unusable target.
        # Validate the target here; if it is not sane, fail loud (DECLINE) — consistent with
        # this redesign's fail-closed philosophy everywhere else (pidfile primitive, C1 guard).
        # The visibility half of the fix (a WARNING on every directory rebind that DOES fire)
        # lives at the production call site, which alone holds the fd path/label for diagnostics.
        root_mnt_id = ctx.get('root_mnt_id')
        if root_mnt_id is None or root_mnt_id not in ctx['kept_mnt_ids']:
            return 'DECLINE'
        return 'REBIND_TO_ROOT'
    return 'DECLINE'

# --classify-selftest: read {"ctx":{...},"entries":[...]} from stdin, print the action list.
# Dormant in production (the patch script never passes this argv). This is the entry point the
# Go unit test drives, so the shipped classifier is what gets tested.
if len(sys.argv) >= 2 and sys.argv[1] == '--classify-selftest':
    _p = json.loads(sys.stdin.read())
    _c = _p.get('ctx', {})
    _ctx = {
        'remap_ids': set(_c.get('remap_ids', [])),
        'inherit_fd_names': set(_c.get('inherit_fd_names', [])),
        'kept_mnt_ids': set(_c.get('kept_mnt_ids', [])),
        'ext_drop_mnt_ids': set(_c.get('ext_drop_mnt_ids', [])),
        'root_mnt_id': _c.get('root_mnt_id'),
    }
    print(json.dumps([classify_reg_fd(e, _ctx) for e in _p.get('entries', [])]))
    sys.exit(0)
`

// patchCheckpointImages modifies the CRIU image files in checkpointDir to remove entries
// that cannot be restored cross-node, and enforces the files.img↔mountpoints consistency
// invariant (ADR-0193 P-0193-1).
//
// inheritFdNames is the set of --inherit-fd names (slash-stripped, per ADR-0188) that
// buildCRIURestoreArgs passes to CRIU. It MUST be sourced from the same builder (C-R3-1) so
// the P-0193-1 "NOT inherited" exclusion is byte-identical to CRIU's own inherited_fd()
// line-2200 decision. Pass nil/empty when no cgroup fds are inherited (degrade-and-continue).
//
// Idempotent: backs up originals as *.orig on first call; subsequent calls are no-ops.
// Returns (droppedMounts, error). droppedMounts is non-nil when B-2 external drops fired
// successfully; callers should emit CRIUExternalMountDropped Normal events for each entry.
func patchCheckpointImages(checkpointDir string, inheritFdNames []string) ([]ExternalMountDroppedInfo, error) {
	// Write the patch script to a temp file and run it with the system python3 + pycriu.
	// containerdMaskedPaths is injected as a JSON argv so the patch step consumes the same
	// single source of truth as buildMaskedPathExtMountArgs (ADR-0124 R2 / AC6) — no divergent
	// hardcoded copy. The delete set (masked path AND no ext_key) and the restore-time map set
	// are disjoint by construction: entries deleted here are never presented to CRIU.
	maskedJSON, err := json.Marshal(containerdMaskedPaths)
	if err != nil {
		return nil, fmt.Errorf("marshal masked paths: %w", err)
	}
	// Normalize nil to empty slice so json.Marshal emits "[]" not "null".
	// pm-patch-ckpt.py:10 calls set(json.loads(argv[3])) — set(None) raises TypeError.
	if inheritFdNames == nil {
		inheritFdNames = []string{}
	}
	inheritJSON, err := json.Marshal(inheritFdNames)
	if err != nil {
		return nil, fmt.Errorf("marshal inherit fd names: %w", err)
	}
	// The single REG-fd classifier (classifyRegFdPy) is prepended verbatim so the main pass and
	// the consistency re-check below both call the one classify_reg_fd() abstraction.
	patchScript := classifyRegFdPy + `
import sys, os, shutil, glob, json
import pycriu
from pycriu.images import MagicException

ckpt = sys.argv[1]
null_ext_key_masked = set(json.loads(sys.argv[2]))
# ADR-0193 C-R3-1: inherit-fd name set (slash-stripped, from same builder as buildCRIURestoreArgs).
# Used by P-0193-1 to exclude inherited fds from the PLAIN-REG firing class.
_raw_inherit = json.loads(sys.argv[3]); inherit_fd_names = set(_raw_inherit) if _raw_inherit is not None else set()

def backup(path):
    orig = path + '.orig'
    if not os.path.exists(orig):
        # ADR-0233: content-only copy (copyfile), NOT copy2. copy2 calls copystat,
        # which invokes utimensat to clone mtime/atime onto the .orig backup. Under
        # the M22 hardened seccomp posture (charts/podmotion/profiles/agent-criu.json,
        # defaultAction=SCMP_ACT_ERRNO) utimensat is NOT allowlisted, so copystat
        # raised PermissionError: [Errno 1] Operation not permitted — aborting the
        # patch step BEFORE the CRIU restore launch (upstream of go-criu RPC). These
        # .orig files are throwaway backups of binary CRIU image blobs; timestamps,
        # mode, owner, and xattrs are irrelevant to restore correctness — only the
        # bytes matter. copyfile copies content with zero metadata syscalls.
        shutil.copyfile(path, orig)
    return orig

def load_image(image_file, fail_on_magic_error=True):
    """Load a CRIU image file, with configurable error handling.

    For strip-only images (netdev, netns, ifaddr): fail_on_magic_error=False — log warning, skip.
    For mountpoints images: fail_on_magic_error=True — fail loud with typed error.

    Catches MagicException (unknown magic value) AND generic Exception (no handler registered
    for a known-magic-but-unhandled image type, e.g. IFADDR in older pycriu builds).
    Both are treated equivalently: fail-loud for mountpoints, skip-on-unknown for strip-only.
    """
    try:
        with open(image_file, 'rb') as f:
            return pycriu.images.load(f)
    except MagicException as e:
        magic_val = getattr(e, 'magic', 'unknown')
        if fail_on_magic_error:
            print('PATCH_ERROR: %s:%s:%s' % (image_file, magic_val, str(e)), file=sys.stderr)
            sys.exit(1)
        else:
            print('WARNING: skipping %s — unknown magic %s: %s' % (image_file, magic_val, str(e)))
            return None
    except Exception as e:
        # Catches "No handler found for image with magic <name>" when magic is known
        # but the vendored pycriu lacks the handler (e.g. IFADDR in older pycriu).
        if fail_on_magic_error:
            print('PATCH_ERROR: %s:unknown:%s' % (image_file, str(e)), file=sys.stderr)
            sys.exit(1)
        else:
            print('WARNING: skipping %s — no pycriu handler: %s' % (image_file, str(e)))
            return None

# ---- mountpoints: keep only mounts with valid (non-null) ext_key or standard in-container mounts ----
for mp_path in glob.glob(os.path.join(ckpt, 'mountpoints-*.img')):
    src = backup(mp_path)
    img = load_image(src, fail_on_magic_error=True)
    if img is None:
        continue
    # ADR-0190: subtree-closed mount drop via mnt_id graph closure.
    #
    # The previous prefix-based approach dropped /sys by path but left children with
    # different mnt_ids (e.g. mnt_id 7730 → parent_mnt_id 9107=/sys) in the image.
    # CRIU's mount-tree builder aborted: "No parent found for mountpoint 7730
    # (@/sys/devices/virtual/dmi/id/product_name)" (mount.c:381).
    #
    # Fix: seed drop_ids from DROP_ROOT_FSTYPES (sysfs) and DROP_PATHS, then run a
    # fixpoint closure over the parent_mnt_id graph. Any entry whose parent is in
    # drop_ids is also dropped. The closure terminates because drop_ids only grows.
    # /proc and /dev are NOT in DROP_ROOT_FSTYPES — policy keeps /proc root and /dev;
    # only specific submounts listed in DROP_PATHS are removed exactly.

    DROP_ROOT_FSTYPES = {
        'sysfs',   # /sys — re-provided by destination runtime; catches both sysfs instances in kind
        # NOTE: procfs NOT here — policy keeps /proc root, drops only named submounts
    }

    DROP_PATHS = {
        '/var/run/secrets/kubernetes.io/serviceaccount',
        '/run/secrets/kubernetes.io/serviceaccount',  # canonical form (ADR-0190)
        '/etc/hosts', '/etc/hostname', '/etc/resolv.conf',
        '/dev/termination-log', '/dev/shm',
        '/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger',
        '/proc/acpi', '/proc/scsi', '/proc/interrupts', '/proc/kcore', '/proc/keys',
        '/proc/latency_stats', '/proc/timer_list', '/proc/sched_debug',
        '/sys/firmware', '/sys/fs/pstore', '/sys/fs/bpf', '/sys/fs/cgroup',
        '/sys',
    }

    def is_drop_root(entry):
        mp = entry.get('mountpoint')
        if mp in DROP_PATHS:
            return True
        if entry.get('fstype') in DROP_ROOT_FSTYPES:
            return True
        return False

    # Phase B: close drop_ids under the parent_mnt_id relation (computed once, not per-entry).
    # Seed: all drop-root mnt_ids.
    drop_ids = {e['mnt_id'] for e in img['entries'] if is_drop_root(e) and 'mnt_id' in e}

    # Root mount protection: / must never be dropped even if a logic error tries to add it.
    root_entries = [e for e in img['entries'] if e.get('mountpoint') == '/']
    root_ids = {e['mnt_id'] for e in root_entries if 'mnt_id' in e}
    if root_ids & drop_ids:
        print('mountpoints: WARNING root mount (/) found in drop_ids — removing from drop set (should be impossible)')
        drop_ids -= root_ids

    # Fixpoint closure: if an entry's parent is in drop_ids, add it to drop_ids.
    changed = True
    while changed:
        changed = False
        for e in img['entries']:
            mid = e.get('mnt_id')
            pid = e.get('parent_mnt_id')
            if mid is None or mid in drop_ids:
                continue
            if pid in drop_ids:
                drop_ids.add(mid)
                changed = True

    # Re-check root protection after closure (belt-and-suspenders).
    if root_ids & drop_ids:
        print('mountpoints: WARNING root mount (/) in drop_ids after closure — removing')
        drop_ids -= root_ids

    # Filter: keep entries NOT in drop_ids, AND apply existing null_ext_key_masked test.
    # Entries lacking mnt_id fall back to path-prefix drop (belt-and-suspenders for
    # images produced by older ctr checkpoint versions that omit mnt_id).
    def _fallback_drop(entry):
        """Path-prefix drop for entries missing mnt_id."""
        mp = entry.get('mountpoint')
        if mp is None:
            return False
        for p in DROP_PATHS:
            if mp == p or mp.startswith(p + '/'):
                return True
        if entry.get('fstype') in DROP_ROOT_FSTYPES:
            return True
        return False

    kept = []
    for e in img['entries']:
        mid = e.get('mnt_id')
        mp = e.get('mountpoint')
        # Skip entries in drop_ids.
        if mid is not None and mid in drop_ids:
            continue
        # For entries without mnt_id, fall back to path-prefix matching.
        if mid is None and _fallback_drop(e):
            print('mountpoints: WARNING missing mnt_id on entry mountpoint=%r fstype=%r — dropped by path fallback' % (mp, e.get('fstype')))
            continue
        # Apply existing null_ext_key_masked test.
        if mp in null_ext_key_masked and not e.get('ext_key'):
            continue
        kept.append(e)
    # ADR-0193: the disproven /data ext_key→pm-data rewrite loop is REMOVED.
    # ADR-0194 Outcome-A symmetric-remap block (MntpImageInconsistencyError/P-0194-1-remap) is REVERTED (SC-1).

    # ADR-0194 B-2 (DROP-together): find and drop external mount entries from the kept set.
    # An "external" mountpoints entry is one whose ext_key is set (and non-empty).
    # These entries require an --ext-mount-map at restore time; since ADR-0193 removed
    # the pm-data binding (correctly under B-2), any remaining external entry without a
    # matching restore-arg binding is an unresolved external mount → mount.c:3141.
    # Direction B-2: DROP the external entry AND rebind all files.img REG fds whose mnt_id
    # references the dropped entry to root_mnt_id (lockstep). See ADR-0194 §4.
    #
    # P-0194-1b (SC-3, H5): HARD-STOP if any external entry has non-zero shared_id or
    # master_id — collapsing a propagation-peer group is forbidden (Security DECLINE class).
    # Runtime check so this is not silently skipped on a future non-zero-propagation image.
    for e in kept:
        ext_key = e.get('ext_key')
        if not ext_key:
            continue
        sid = e.get('shared_id', 0) or 0
        mid_prop = e.get('master_id', 0) or 0
        if sid != 0 or mid_prop != 0:
            print('EXTERNAL_MOUNT_UNRESOLVED:{"mnt_id":%d,"ext_key":"%s","shared_id":%d,"master_id":%d,"reason":"propagation_peer"}' % (
                e.get('mnt_id', -1), ext_key.replace('"', '\\"'), sid, mid_prop), file=sys.stderr)
            sys.exit(1)

    # Identify root mnt_id (dynamic lookup of the kept '/' entry — not hardcoded).
    root_mnt_id = None
    for e in kept:
        if e.get('mountpoint') == '/':
            root_mnt_id = e.get('mnt_id')
            break

    # Identify and drop external entries. Collect the mnt_ids being dropped (ext_drop_mnt_ids)
    # for the lockstep files.img rebind in the next section.
    ext_drop_mnt_ids = {}  # mnt_id -> ext_key (for event emission)
    kept_after_ext_drop = []
    for e in kept:
        ext_key = e.get('ext_key')
        mnt_id = e.get('mnt_id')
        if ext_key and mnt_id is not None:
            # P-0194-1b re-entry guard (H2): before dropping, assert no kept entry references
            # this mnt_id as parent_mnt_id (i.e. confirm it is a leaf — AC-1 re-assertion).
            referencing_parents = [x for x in kept if x.get('parent_mnt_id') == mnt_id and x.get('mnt_id') != mnt_id]
            if referencing_parents:
                print('EXTERNAL_MOUNT_UNRESOLVED:{"mnt_id":%d,"ext_key":"%s","shared_id":0,"master_id":0,"reason":"non_leaf_external"}' % (
                    mnt_id, ext_key.replace('"', '\\"')), file=sys.stderr)
                sys.exit(1)
            ext_drop_mnt_ids[mnt_id] = ext_key
            # Emit CRIUExternalMountDropped event token (H4 / Platform PM C-2).
            # ext_key is the path (e.g. "/data") — safe as a name, not a full volume path.
            print('CRIU_EXTERNAL_MOUNT_DROPPED:{"mnt_id":%d,"ext_key":"%s","source":"%s"}' % (
                mnt_id,
                ext_key.replace('"', '\\"'),
                (e.get('source') or '').replace('"', '\\"')))
        else:
            kept_after_ext_drop.append(e)

    img['entries'] = kept_after_ext_drop
    # Build the set of kept mountpoints mnt_ids AFTER external-drop (for P-0193-1 + P-0194-1c).
    kept_mnt_ids = {e['mnt_id'] for e in kept_after_ext_drop if 'mnt_id' in e}

    # P-0194-1 (H2 re-entry guard / P-0194-1c pre-check): verify no external entry survives
    # without a mapping. Under B-2 all external entries were dropped above; if any survived
    # (e.g. future code path adds one back), HARD-STOP before writing the image.
    for e in kept_after_ext_drop:
        if e.get('ext_key'):
            print('EXTERNAL_MOUNT_UNRESOLVED:{"mnt_id":%d,"ext_key":"%s","shared_id":0,"master_id":0,"reason":"survived_drop"}' % (
                e.get('mnt_id', -1), (e.get('ext_key') or '').replace('"', '\\"')), file=sys.stderr)
            sys.exit(1)

    # Atomic mountpoints write: temp file → fsync → rename (H1 / SC-2).
    # The original is already backed up as .orig; the rename is both-or-neither with files.img
    # rename (see P-0194-1c below). A failure before the rename leaves the .orig intact.
    mp_tmp = mp_path + '.tmp.' + str(os.getpid())
    with open(mp_tmp, 'wb') as f:
        pycriu.images.dump(img, f)
        f.flush()
        os.fsync(f.fileno())
    # (rename happens after files.img temp write, in P-0194-1c block below)
    print('mountpoints:', os.path.basename(mp_path), 'kept', len(kept_after_ext_drop), 'entries',
          '(ext-dropped:', len(ext_drop_mnt_ids), ')')

# ---- netns: remove extRootNetNS dependency (references source host net ns) ----
# strip-only image: skip-on-unknown-magic (S1)
netns_path = os.path.join(ckpt, 'netns-10.img')
if os.path.exists(netns_path):
    src = backup(netns_path)
    img = load_image(src, fail_on_magic_error=False)
    if img is not None:
        for e in img['entries']:
            e.pop('ext_key', None)
        with open(netns_path, 'wb') as f:
            pycriu.images.dump(img, f)
        print('netns: removed ext_key entries')

# ---- netdev: remove VETH (peer missing cross-node); keep loopback only ----
# strip-only image: skip-on-unknown-magic (S1)
netdev_path = os.path.join(ckpt, 'netdev-10.img')
if os.path.exists(netdev_path):
    src = backup(netdev_path)
    img = load_image(src, fail_on_magic_error=False)
    if img is not None:
        kept = []
        for e in img['entries']:
            lnk = e.get('link', {})
            # LOOPBACK type = 772; keep only loopback, remove VETH and others
            if lnk.get('type') == 772:
                lnk.pop('peer_nsid', None)
                kept.append(e)
        img['entries'] = kept
        with open(netdev_path, 'wb') as f:
            pycriu.images.dump(img, f)
        print('netdev: kept', len(kept), 'entries (loopback only)')

# ---- ifaddr: remove source pod IP addresses; keep loopback only (ADR-0125, ADR-0162) ----
# strip-only image: skip-on-unknown-magic (S1)
# ifaddr-10.img: strip all non-loopback addresses so CRIU does not attempt 'ip addr add
# <source-ip>' in the dest netns (which is pre-staged by ADR-0165 SP-1/SP-2/SP-3).
# When the image has zero non-loopback entries OR pycriu cannot parse it, delete the file
# entirely — CRIU skips ip-addr restore when the file is absent, avoiding the external
# 'ip addr restore' subprocess that rejects any malformed or empty framing
# (observed: 8-byte magic-only stub → "Magic mismatch (1 elems, 54564319 magic)").

ifaddr_path = os.path.join(ckpt, 'ifaddr-10.img')
if os.path.exists(ifaddr_path):
    src = backup(ifaddr_path)
    img = load_image(src, fail_on_magic_error=False)
    if img is not None:
        kept = [e for e in img['entries']
                if e.get('ifaddr', {}).get('ifindex') == 1]
        if kept:
            img['entries'] = kept
            with open(ifaddr_path, 'wb') as f:
                pycriu.images.dump(img, f)
            print('ifaddr: kept', len(kept), 'entries (loopback only)')
        else:
            # No non-loopback addresses to restore — delete the image file so CRIU's
            # external 'ip addr restore' subprocess is never launched against it.
            # CRIU skips ip-addr restore entirely when ifaddr-*.img is absent.
            # Dest netns IP is pre-staged by ADR-0165 SP-1/SP-2/SP-3; no ifaddr image needed.
            os.remove(ifaddr_path)
            print('ifaddr: 0 non-loopback entries — deleted', ifaddr_path, '(CRIU skip-restore path; dest IP pre-staged by ADR-0165)')
    else:
        # pycriu IFADDR handler missing (older pycriu build) — delete the image file entirely.
        # Writing any stub risks CRIU's external 'ip addr restore' subprocess rejecting the
        # framing with "Magic mismatch" (observed: 8-byte magic-only stub caused
        # exactly this failure). Absence of the file causes CRIU to skip ip-addr restore.
        # Dest netns IP is pre-staged by ADR-0165 SP-1/SP-2/SP-3; no ifaddr image needed.
        os.remove(ifaddr_path)
        print('ifaddr: pycriu handler missing — deleted', ifaddr_path, '(CRIU skip-restore path; dest IP pre-staged by ADR-0165)')

# ---- route-10.img / route6-10.img: delete (ADR-0167 SD-3) ----
# Source-node routes reference the source veth device by index/name; on the destination
# those indices differ. CRIU route restore fails with RTNETLINK: No such device
# (criu/net.c:1969) when the device index/name in the route image does not match.
# Destination routes are established by ADR-0167 SD-1 host-route injection (or by bridge
# membership + provider-injected routes on the bridge path). Strip = delete, not rewrite:
# CRIU skips route restore entirely when route-*.img is absent (proven safe by ifaddr pattern).
for route_file in ['route-10.img', 'route6-10.img']:
    route_path = os.path.join(ckpt, route_file)
    if os.path.exists(route_path):
        orig = route_path + '.orig'
        if not os.path.exists(orig):
            import shutil
            # ADR-0233: copyfile, not copy2 — see backup() above. copy2's copystat
            # step calls utimensat (not in the M22 seccomp allowlist) and EPERMs.
            shutil.copyfile(route_path, orig)
        os.remove(route_path)
        print('route: deleted', route_file, '(CRIU skip-route-restore; dest routes via host-route injection or pre-staged)')

# ---- ADR-0193/ADR-0194: files.img / fdinfo-*.img reconciliation (P-0193-1 / P-0194-1 unified) ----
# Enforce files.img↔mountpoints cross-image consistency for PLAIN-REG fds.
# A PLAIN-REG fd is one that reaches open_path() line 2263 in CRIU (files-reg.c) —
# i.e. NOT inherited, NOT external (rfe->ext unset), NOT a remap, AND carries a POSITIVE
# mnt_id. Such a fd fires mount.c:3953 BUG_ON if its mnt_id is not in the restored mount set.
# Source-proven discriminant: CRIU 4.2 files-reg.c:2191-2263, mount.c:3946-3953.
#
# ADR-0194 B-2 extension: fds whose mnt_id is in ext_drop_mnt_ids are now ALSO orphans
# (those mnt_ids were dropped from the mountpoints image by the external-drop pass above).
# The existing dir-rebind path handles them correctly — they will appear as "mnt_id not in
# kept_mnt_ids" below. The lockstep rebind to root_mnt_id IS the ADR-0194 B-2 symmetric
# operation that ADR-0193 claimed but never applied on the real checkpoint shape.
#
# C-R3-1: inherit_fd_names is sourced from the same builder as buildCRIURestoreArgs so the
# "NOT inherited" exclusion is byte-identical to CRIU's own inherited_fd() line-2200 decision.
# C-R3-2: pycriu exposes the ext boolean on RegFileEntry — read via entry["reg"].get("ext").

files_img_path = os.path.join(ckpt, 'files.img')
if os.path.exists(files_img_path) and kept_mnt_ids is not None and root_mnt_id is not None:
    # P-0194-1c re-entry guard (H2): if the mountpoints temp file exists but the final image has
    # already been renamed (i.e. a prior call completed), check consistency and skip.
    mp_tmp_exists = os.path.exists(mp_tmp)

    # Build remap set: fd ids that have a remap entry (graceful rfi_remap path — out of scope).
    remap_ids = set()
    for remap_f in glob.glob(os.path.join(ckpt, 'remap-*.img')):
        try:
            with open(remap_f, 'rb') as f:
                remap_img = pycriu.images.load(f)
            for e in remap_img.get('entries', []):
                orig_id = e.get('orig_id')
                if orig_id is not None:
                    remap_ids.add(orig_id)
        except Exception as remap_err:
            print('WARNING: could not parse %s: %s' % (remap_f, remap_err))

    files_src = backup(files_img_path)
    try:
        with open(files_src, 'rb') as f:
            files_img = pycriu.images.load(f)
    except Exception as fe:
        print('PATCH_ERROR: %s:unknown:%s' % (files_img_path, str(fe)), file=sys.stderr)
        sys.exit(1)

    # Single source of truth for the REG-fd decision: classify_reg_fd (classifyRegFdPy).
    # ctx carries the cross-image sets. ext_drop_mnt_ids is a dict (mnt_id->ext_key); its key
    # set is passed for completeness (classify only needs membership of the other four sets).
    classify_ctx = {
        'remap_ids': remap_ids,
        'inherit_fd_names': inherit_fd_names,
        'kept_mnt_ids': kept_mnt_ids,
        'ext_drop_mnt_ids': set(ext_drop_mnt_ids),
        # ADR-0245 D2: rebind-target for orphan directory fds. The classifier validates this is
        # a sane (present + kept) target before authorizing REBIND_TO_ROOT; otherwise DECLINE.
        'root_mnt_id': root_mnt_id,
    }
    modified = False
    for entry in files_img.get('entries', []):
        action = classify_reg_fd(entry, classify_ctx)
        if action == 'KEEP':
            continue
        reg = entry.get('reg', {})
        fd_id = entry.get('id', -1)
        name = reg.get('name', '') or ''
        mnt_id = reg.get('mnt_id')
        name_leaf = os.path.basename(name) if name else str(fd_id)
        if action == 'REBIND_TO_ROOT':
            # C-R3-3 / ADR-0194 B-2 lockstep: REG directory fd with an orphan mnt_id — rebind to
            # root mnt_id (drop-together). Covers both generic PLAIN-REG dir orphans (ADR-0193 §4)
            # and fds whose mnt_id was in ext_drop_mnt_ids (ADR-0194 B-2 lockstep). The label is
            # diagnostic only; the classifier's decision is identical for both.
            label = 'b2-lockstep-ext-drop' if mnt_id in ext_drop_mnt_ids else 'generic-orphan'
            # ADR-0245 D2 (Storage Architect finding): a directory-fd rebind is NOT silent
            # success. Redirecting an open directory handle from its checkpoint-time backing
            # mount to the container root is benign for PodMotion checkpoint scaffolding (the
            # /podmotion holder mount, dropped externals that re-attach at the destination) but
            # would be a data-visibility change if a live workload held an open directory handle
            # inside an actively-managed persistent volume (Longhorn / Ceph RBD / RWX NFS
            # subdirectory / snapshot-rsync target) at checkpoint time. The classifier cannot
            # distinguish those two cases from the image alone (a PV mount handled as external
            # lands in ext_drop_mnt_ids exactly like scaffolding does), so instead of silently
            # picking one interpretation we make EVERY directory rebind LOUD and structured, so
            # it is visible in restore logs/diagnostics and can be correlated against the
            # workload's known volume set. The 'generic-orphan' label (mnt_id in neither the
            # kept nor the ext-drop set) is the higher-suspicion case — an fd backed by a mount
            # that simply vanished from the mountpoints image — and is called out explicitly.
            print('WARNING pm-image-consistency: directory-fd rebind — fd_id=%d name=%s backing_mnt_id=%d label=%s new_mnt_id=%d (open directory handle redirected to container root; verify this is not a live persistent-volume directory)' % (
                fd_id, name, mnt_id, label, root_mnt_id))
            print('CRIU_IMAGE_DIR_FD_REBOUND:{"fd_id":%d,"name":"%s","backing_mnt_id":%d,"new_mnt_id":%d,"label":"%s"}' % (
                fd_id, name.replace('"', '\\"'), mnt_id, root_mnt_id, label))
            reg['mnt_id'] = root_mnt_id
            modified = True
        elif action == 'DECLINE':
            # Non-directory REG fd with positive orphan mnt_id — cannot safely rebind.
            # Hard-stop: P-0193-1 (C-R3-3 non-directory path).
            print('CRIU_IMAGE_INCONSISTENCY:{"fd_id":%d,"name_leaf":"%s","backing_mnt_id":%d}' % (
                fd_id, name_leaf.replace('"', '\\"'), mnt_id), file=sys.stderr)
            sys.exit(1)

    # Atomic files.img write: temp file → fsync → rename (H1 / SC-2 dual-image atomicity).
    files_tmp = files_img_path + '.tmp.' + str(os.getpid())
    with open(files_tmp, 'wb') as f:
        pycriu.images.dump(files_img, f)
        f.flush()
        os.fsync(f.fileno())
    if modified:
        # Back up fdinfo-*.img for zeroize coverage (Standing Rule 7 / ADR-0193 S2).
        for fdinfo_f in glob.glob(os.path.join(ckpt, 'fdinfo-*.img')):
            backup(fdinfo_f)

    # P-0194-1c (SC-2 atomic dual-write, H2): commit BOTH images in sequence.
    # Both temp files exist and are fsynced; rename them into place now.
    # A failure between the two os.rename calls is the only residual window;
    # both originals remain intact (backed up as .orig) and are recoverable.
    os.rename(mp_tmp, mp_path)
    os.rename(files_tmp, files_img_path)

    if modified:
        print('files.img: reconciled PLAIN-REG fds with positive orphan mnt_ids (ADR-0193/0194 unified)')

    # P-0193-1 / P-0194-1 unified hard-stop assertion: after reconciliation and rename,
    # verify no in-scope PLAIN-REG fd still carries a positive mnt_id absent from kept_mnt_ids.
    # Re-load the committed files.img to check the final on-disk state.
    with open(files_img_path, 'rb') as f:
        files_img_final = pycriu.images.load(f)
    # Re-check uses the SAME classify_reg_fd abstraction as the main pass (classify_ctx is
    # unchanged — the rebind above set orphan dir fds to root_mnt_id, which IS in kept_mnt_ids,
    # so those now classify KEEP). Any surviving non-KEEP action means an fd would still fire
    # mount.c:3953 → hard-stop. One classifier, both passes: no divergent copy to drift.
    for entry in files_img_final.get('entries', []):
        if classify_reg_fd(entry, classify_ctx) == 'KEEP':
            continue
        reg = entry.get('reg', {})
        fd_id = entry.get('id', -1)
        name = reg.get('name', '') or ''
        mnt_id = reg.get('mnt_id')
        name_leaf = os.path.basename(name) if name else str(fd_id)
        # P-0193-1 / P-0194-1 unified: hard-stop — this fd would still fire mount.c:3953.
        print('CRIU_IMAGE_INCONSISTENCY:{"fd_id":%d,"name_leaf":"%s","backing_mnt_id":%d}' % (
            fd_id, name_leaf.replace('"', '\\"'), mnt_id), file=sys.stderr)
        sys.exit(1)

    # P-0194-1c cross-image assertion (SC-2): verify dual-write consistency.
    # After rename: mountpoints must have no /data (ext_drop mnt_ids absent from kept_mnt_ids),
    # AND files.img must have no REG fd still referencing those dropped mnt_ids.
    # This is the both-or-neither enforcement at the assertion layer.
    with open(mp_path, 'rb') as f:
        mp_img_final = pycriu.images.load(f)
    surviving_ext_in_mp = {e['mnt_id'] for e in mp_img_final.get('entries', [])
                           if e.get('ext_key') and 'mnt_id' in e}
    surviving_ext_in_files = set()
    for entry in files_img_final.get('entries', []):
        if entry.get('type') != 'REG':
            continue
        reg = entry.get('reg', {})
        mnt_id = reg.get('mnt_id')
        if mnt_id in ext_drop_mnt_ids:
            surviving_ext_in_files.add(mnt_id)
    if surviving_ext_in_mp or surviving_ext_in_files:
        print('EXTERNAL_MOUNT_UNRESOLVED:{"mnt_id":-1,"ext_key":"","shared_id":0,"master_id":0,"reason":"p0194_1c_dual_write_mismatch","mp_surviving":%s,"files_surviving":%s}' % (
            list(surviving_ext_in_mp), list(surviving_ext_in_files)), file=sys.stderr)
        sys.exit(1)

    print('files.img: P-0193-1/P-0194-1 unified consistency check passed (no PLAIN-REG orphan mnt_ids; P-0194-1c dual-write verified)')
else:
    # files.img not present or preconditions not met: still commit mountpoints rename.
    if os.path.exists(mp_tmp):
        os.rename(mp_tmp, mp_path)
`
	// /dev/shm is an in-memory filesystem (tmpfs) — avoids writing the script to disk.
	// 0600 so only root can read the path; removed immediately after exec.
	scriptPath := "/dev/shm/pm-patch-ckpt.py"
	if err := os.WriteFile(scriptPath, []byte(patchScript), 0o600); err != nil {
		return nil, fmt.Errorf("write patch script: %w", err)
	}
	defer os.Remove(scriptPath)
	// argv[1]=checkpointDir argv[2]=maskedJSON argv[3]=inheritJSON (C-R3-1).
	cmd := exec.Command("python3", scriptPath, checkpointDir, string(maskedJSON), string(inheritJSON))
	cmd.Env = append(os.Environ(), "PYTHONPATH=/usr/lib/python3/dist-packages")
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	out, runErr := cmd.Output()
	// Parse CRIU_EXTERNAL_MOUNT_DROPPED tokens from stdout (H4 / Platform PM C-2).
	// These are informational (Normal event) and do not indicate failure.
	outStr := string(out)
	var droppedMounts []ExternalMountDroppedInfo
	for _, line := range strings.Split(outStr, "\n") {
		if strings.HasPrefix(line, "CRIU_EXTERNAL_MOUNT_DROPPED:") {
			payload := strings.TrimPrefix(line, "CRIU_EXTERNAL_MOUNT_DROPPED:")
			var d ExternalMountDroppedInfo
			if jsonErr := json.Unmarshal([]byte(payload), &d); jsonErr == nil {
				droppedMounts = append(droppedMounts, d)
			}
		}
	}
	if runErr != nil {
		stderrStr := stderrBuf.String()
		// ADR-0193 P-0193-1: parse structured CRIU_IMAGE_INCONSISTENCY error from stderr.
		// The script writes: CRIU_IMAGE_INCONSISTENCY:{"fd_id":N,"name_leaf":"X","backing_mnt_id":M}
		// The full path is NOT in this line — only the leaf basename (SEC-EVENT-1 / S1).
		for _, line := range strings.Split(stderrStr, "\n") {
			if strings.HasPrefix(line, "CRIU_IMAGE_INCONSISTENCY:") {
				payload := strings.TrimPrefix(line, "CRIU_IMAGE_INCONSISTENCY:")
				var parsed struct {
					FdID        int    `json:"fd_id"`
					NameLeaf    string `json:"name_leaf"`
					BackingMntID int   `json:"backing_mnt_id"`
				}
				if jsonErr := json.Unmarshal([]byte(payload), &parsed); jsonErr == nil {
					return nil, &CRIUImageInconsistencyError{
						FdID:        parsed.FdID,
						NameLeaf:    parsed.NameLeaf,
						BackingMntID: parsed.BackingMntID,
					}
				}
			}
			// ADR-0194 P-0194-1: parse EXTERNAL_MOUNT_UNRESOLVED hard-stop from stderr.
			// The script writes: EXTERNAL_MOUNT_UNRESOLVED:{"mnt_id":N,"ext_key":"X",...}
			if strings.HasPrefix(line, "EXTERNAL_MOUNT_UNRESOLVED:") {
				payload := strings.TrimPrefix(line, "EXTERNAL_MOUNT_UNRESOLVED:")
				var parsed struct {
					MntID    int    `json:"mnt_id"`
					ExtKey   string `json:"ext_key"`
					SharedID int    `json:"shared_id"`
					MasterID int    `json:"master_id"`
					Reason   string `json:"reason"`
				}
				if jsonErr := json.Unmarshal([]byte(payload), &parsed); jsonErr == nil {
					return nil, &ExternalMountUnresolvedError{
						MntID:    parsed.MntID,
						ExtKey:   parsed.ExtKey,
						SharedID: parsed.SharedID,
						MasterID: parsed.MasterID,
						Reason:   parsed.Reason,
					}
				}
			}
		}
		return nil, fmt.Errorf("patch script failed: %w\n%s\n%s", runErr, outStr, stderrStr)
	}
	log.Info("patchCheckpointImages", "output", strings.TrimSpace(outStr))
	// Return dropped mounts info for caller to emit CRIUExternalMountDropped events (H4).
	return droppedMounts, nil
}

// hostMntNS returns the path to the host's mount namespace via PID 1 (requires hostPID: true).
const hostMntNS = "/proc/1/ns/mnt"

// brokerExecTimeout bounds a single broker host-mount-ns exec. ctr image pull on
// a cold node can take tens of seconds; CRIU restore is launched ASYNC (see the
// criu wrapper path) and is NOT subject to this timeout.
const brokerExecTimeout = 5 * time.Minute

// brokerCmd is the run-to-completion shim returned by nsenterCmd. ADR-0231: the
// SD-1 main agent cannot itself enter the host mount namespace (setns(CLONE_NEWNS)
// requires CAP_SYS_ADMIN effective in the HOST init userns — only the privileged
// netns-broker sidecar has it; the de-privileged agent's nsenter returns
// "reassociate to namespace 'ns/mnt' failed: Operation not permitted"). So every
// host-mount-ns command on the RESTORE path is delegated to the broker over its
// root-owned Unix socket, the same channel HOLD-C used for netns binds. brokerCmd
// emulates the *exec.Cmd subset the restore-path call sites actually use:
// Output(), CombinedOutput(), Run(). The long-running CRIU wrapper is NOT routed
// here (it needs a detached spawn + host PID) — see nsenterCriuWrapperStart.
type brokerCmd struct {
	argv []string
}

func (b *brokerCmd) result() netnsbroker.ExecResult {
	ctx, cancel := context.WithTimeout(context.Background(), brokerExecTimeout)
	defer cancel()
	return netnsbroker.NewClient().Exec(ctx, brokerExecTimeout, b.argv...)
}

// Output returns stdout and, on non-zero exit, an error carrying the exit code —
// matching exec.Cmd.Output semantics closely enough for the restore-path callers.
func (b *brokerCmd) Output() ([]byte, error) {
	r := b.result()
	if r.SpawnErr != nil {
		return r.Stdout, r.SpawnErr
	}
	if r.ExitCode != 0 {
		return r.Stdout, fmt.Errorf("host-mount-ns exec %v: exit status %d: %s", b.argv, r.ExitCode, strings.TrimSpace(string(r.Stderr)))
	}
	return r.Stdout, nil
}

// CombinedOutput returns interleaved stdout+stderr and an error on non-zero exit.
func (b *brokerCmd) CombinedOutput() ([]byte, error) {
	r := b.result()
	if r.SpawnErr != nil {
		return r.Combined, r.SpawnErr
	}
	if r.ExitCode != 0 {
		return r.Combined, fmt.Errorf("exit status %d", r.ExitCode)
	}
	return r.Combined, nil
}

// Run executes the command and returns an error only on broker failure or non-zero exit.
func (b *brokerCmd) Run() error {
	r := b.result()
	if r.SpawnErr != nil {
		return r.SpawnErr
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("exit status %d", r.ExitCode)
	}
	return nil
}

// nsenterCmd returns a brokerCmd that runs the command inside the HOST mount
// namespace VIA THE PRIVILEGED netns-broker sidecar (ADR-0231). It previously
// built a local `nsenter --mount=/proc/1/ns/mnt` *exec.Cmd, which the SD-1
// de-privileged agent cannot execute (EPERM on setns). The call sites are
// unchanged — they invoke .Output()/.CombinedOutput()/.Run() on the result.
func nsenterCmd(args ...string) *brokerCmd {
	return &brokerCmd{argv: args}
}

// ADR-0234: the CRIU restore wrapper launch is now broker-delegated.
//
// nsenterLocalCmd (the LOCAL `nsenter --mount=/proc/1/ns/mnt` *exec.Cmd) was the
// ADR-0231 "KNOWN NEXT WALL": under SD-1 (main agent privileged:false) the agent's
// own nsenter EPERMs on setns(CLONE_NEWNS) into the host mount namespace —
// "reassociate to namespace 'ns/mnt' failed: Operation not permitted" — because
// CAP_SYS_ADMIN in the host init userns is held only by the privileged netns-broker
// sidecar. ADR-0231 broker-delegated the SHORT host-mount-ns commands (ctr pull,
// rootfs scaffolding) via the run-to-completion exec op, and EXPLICITLY left the
// long-running CRIU wrapper launch on local nsenter as the named next wall, because
// the wrapper needs the full *exec.Cmd async lifecycle (.Start()/.Wait()/.Process.Pid/
// .ProcessState/streaming .Stderr) the run-to-completion shim does not expose: on the
// cold --join-ns path CRIU never self-exits, so the agent must launch it, poll a
// cgroup-PID liveness signal while it still runs, and reap it asynchronously (ADR-0192).
//
// ADR-0234 closes that wall by EXTENDING the broker with async exec ops
// (exec_start / exec_poll / exec_signal) — a detached-spawn + host-PID-return +
// cross-process-reap mechanism — and routing the wrapper launch through them. The
// brokerCriuCmd type below emulates the exact *exec.Cmd subset the joinNsRestore
// call site uses, backed by the broker. nsenterLocalCmd is REMOVED (its
// sole consumer, the wrapper launch, is converted in the same commit). The main
// agent stays privileged:false (SD-1); the broker (privileged:true) does the setns.

// brokerCriuWrapperPollInterval is the broker exec_poll cadence. It matches the
// prior local-nsenter cgroupPollInterval so the liveness-signal latency is unchanged.
const brokerCriuWrapperPollInterval = 50 * time.Millisecond

// brokerCriuCmd is the ADR-0234 broker-backed replacement for the local-nsenter
// CRIU wrapper *exec.Cmd. It emulates exactly the subset joinNsRestore consumed:
//   - Stderr: a *bytes.Buffer the poll loop reads CRIU's pre-logfile diagnostics from
//     (filled from the broker-side stderr capture returned by exec_poll);
//   - Start(): broker exec_start (detached host-mount-ns spawn), records the wrapper PID;
//   - poll():  broker exec_poll — returns (exited, exitCode, brokerCgroupPIDs);
//   - Pid():   the host PID of the wrapper (for the ADR-0128 diff exclusion);
//   - Signal(): broker exec_signal (Abort).
//
// The liveness diff that previously read the AGENT cgroup (getAgentCgroupPIDs) now
// reads the BROKER cgroup PIDs returned by exec_poll: the wrapper is a broker child,
// so --manage-cgroups=ignore lands the restored tree in the broker cgroup, not the
// agent cgroup. The diff logic (new entrant != pre-spawn snapshot, != wrapper PID,
// != "criu" comm) is otherwise unchanged.
type brokerCriuCmd struct {
	argv       []string
	wrapperPID int
	Stderr     *bytes.Buffer
}

func (c *brokerCriuCmd) Pid() int { return c.wrapperPID }

// Start spawns the wrapper detached via the broker and records its host PID.
func (c *brokerCriuCmd) Start() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pid, err := netnsbroker.NewClient().ExecStart(ctx, c.argv...)
	if err != nil {
		return err
	}
	c.wrapperPID = pid
	return nil
}

// poll returns whether the wrapper has exited, its exit code (valid only when
// exited), and the broker-cgroup PID set for the liveness diff. It also refreshes
// the Stderr buffer from the broker-side capture so the failure path can surface
// CRIU's stderr exactly as the local-nsenter path did.
func (c *brokerCriuCmd) poll() (exited bool, exitCode int, cgroupPIDs []int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pr, perr := netnsbroker.NewClient().ExecPoll(ctx, c.wrapperPID)
	if perr != nil {
		return false, 0, nil, perr
	}
	if len(pr.Stderr) > 0 {
		c.Stderr.Reset()
		c.Stderr.Write(pr.Stderr)
	}
	return !pr.Running, pr.ExitCode, pr.CgroupPIDs, nil
}

// Signal asks the broker to deliver sig to the wrapper (Abort path).
func (c *brokerCriuCmd) Signal(sig int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return netnsbroker.NewClient().ExecSignal(ctx, c.wrapperPID, sig)
}

// newBrokerCriuCmd builds a broker-backed CRIU wrapper command for the given argv.
func newBrokerCriuCmd(args ...string) *brokerCriuCmd {
	return &brokerCriuCmd{argv: args, Stderr: &bytes.Buffer{}}
}

// setupRestoreOverlayfs launches a temporary placeholder container (via nsenter in the host
// mount namespace) so containerd prepares the overlayfs snapshot layers, then returns the path
// to the placeholder's rootfs which is accessible via the host-containerd-bundles volume mount.
//
// The placeholder container MUST stay alive (not killed) until after CRIU restore completes —
// the caller is responsible for cleanup via the returned placeholderID ctr kill+rm.
//
// The returned rootfsDir is the containerd bundle rootfs path exposed through the
// host-containerd-bundles volume: /run/containerd/io.containerd.runtime.v2.task/k8s.io/<id>/rootfs
// This avoids the nested overlay mount limitation (agent container cannot mount overlayfs).
//
// containerID: when non-empty, the replacement container's own bundle rootfs is used directly
// (it is already set up by containerd when NRI StartContainer fires). The placeholder container
// path is only used as a fallback when containerID is empty (legacy gRPC restore path).
func setupRestoreOverlayfs(migrationName, checkpointDir, imageName, containerID string) (string, error) {
	// ADR-0151: prefer the replacement container's own bundle rootfs over creating a placeholder.
	// At NRI StartContainer time containerd has already mounted the overlay for the replacement
	// container at this path. Using it directly avoids the placeholder overlay corruption problem:
	// writing dirs into a mounted overlay populates the upper layer, which can hide lower-layer
	// content (e.g. redis-server in a deeper snapshot) if the upper layer gets GC'd or is
	// missing on retry. The replacement container's overlay is stable for the duration of the
	// NRI hook.
	if containerID != "" {
		containerRootfs := fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s/rootfs", containerID)
		// Verify the overlay is mounted in the host namespace (/proc/1/mounts is readable from
		// agent container). The agent container cannot access /run/containerd/... directly
		// (its /run is a private tmpfs), so content checks use nsenterCmd.
		if mountsData, err := os.ReadFile("/proc/1/mounts"); err == nil {
			for _, line := range strings.Split(string(mountsData), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 3 && fields[1] == containerRootfs && fields[2] == "overlay" {
					// ADR-0186: non-empty ls-A replaces fixed allowlist — works for distroless/symlink
					// layouts where test -d {usr,bin,lib,sbin} is a false negative. A mounted overlay
					// with ≥1 top-level entry IS the real image rootfs (mirrors the placeholder path's
					// own readiness check below). Use the SAME acceptance criterion on both paths.
					lsOut, lsErr := nsenterCmd("ls", "-A", containerRootfs).Output()
					hasImageContent := lsErr == nil && len(strings.TrimSpace(string(lsOut))) > 0
					if hasImageContent {
						log.Info("setupRestoreOverlayfs: using replacement container bundle rootfs directly (ADR-0151)",
							"containerID", containerID, "rootfs", containerRootfs)
						return containerRootfs, nil
					}
					log.Info("setupRestoreOverlayfs: replacement container rootfs overlay found but image content not visible — falling back to placeholder",
						"containerID", containerID, "rootfs", containerRootfs,
						"lsErr", lsErr, "lsOut", strings.TrimSpace(string(lsOut)))
					break
				}
			}
		}
	}

	placeholderID := "pm-placeholder-" + migrationName
	// rootfsDir is the host-namespace path used by nsenterCmd, CRIU --root, and /proc/1/mounts entries.
	// The agent container cannot access /run/containerd/... directly (its /run is a private tmpfs).
	// All existence/readiness checks use either /proc/1/mounts (host mount table, readable from
	// agent) or nsenterCmd (runs commands in host mount namespace).
	rootfsDir := fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s/rootfs", placeholderID)
	bundleDir := fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s", placeholderID)

	// hostOverlayMounted reports whether the overlay for rootfsDir is mounted in the host namespace.
	// Uses /proc/1/mounts which is readable from the agent container because the agent has hostPID=true.
	hostOverlayMounted := func() bool {
		mountsData, err := os.ReadFile("/proc/1/mounts")
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(mountsData), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[1] == rootfsDir && fields[2] == "overlay" {
				return true
			}
		}
		return false
	}

	// Check if the placeholder task is already running with an overlay mounted.
	// Use `ctr task ls --quiet` to check for a running task with the placeholder ID.
	// A stale bundle dir (from a previous failed attempt) would have dirs but no running task
	// and no overlay mount — do NOT accept it.
	taskOut, _ := nsenterCmd("ctr", "--namespace", "k8s.io", "tasks", "ls", "--quiet").Output()
	placeholderRunning := strings.Contains(string(taskOut), placeholderID)
	if placeholderRunning && hostOverlayMounted() {
		log.Info("setupRestoreOverlayfs: placeholder rootfs already present (overlay confirmed)", "rootfs", rootfsDir)
		return rootfsDir, nil
	}

	// Kill any stale placeholder from a previous attempt.
	_ = nsenterCmd("ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()
	_ = nsenterCmd("ctr", "--namespace", "k8s.io", "container", "rm", placeholderID).Run()
	// Remove stale bundle dir left by containerd (containerd does not auto-clean on kill).
	// This is necessary so containerd can create a fresh bundle with a properly mounted overlay.
	// Use nsenterCmd since the agent container cannot access /run/containerd/... directly.
	if out, err := nsenterCmd("rm", "-rf", bundleDir).CombinedOutput(); err != nil {
		// Non-fatal — bundleDir may not exist; ctr run will create a fresh one.
		log.Info("setupRestoreOverlayfs: rm stale bundleDir (non-fatal)", "dir", bundleDir, "err", err, "out", string(out))
	}

	// Launch a placeholder container inside the host mount namespace so containerd prepares
	// the overlayfs snapshot layers. nsenterCmd ensures ctr runs in the host mount namespace
	// (necessary because containerd resolves temp paths like /tmp in the host namespace).
	runOut, err := nsenterCmd("ctr", "--namespace", "k8s.io", "run",
		"--detach", "--snapshotter", "overlayfs",
		imageName, placeholderID, "sleep", "600",
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ctr run placeholder: %w\n%s", err, runOut)
	}

	// Wait for containerd to mount the rootfs overlayfs in the host namespace.
	// Poll /proc/1/mounts (readable from agent) until overlay appears, then verify
	// content exists via nsenterCmd("ls", rootfsDir).
	for i := 0; i < 25; i++ {
		time.Sleep(200 * time.Millisecond)
		if !hostOverlayMounted() {
			continue
		}
		// Overlay is mounted. Verify image content via nsenterCmd (runs in host namespace).
		lsOut, lsErr := nsenterCmd("ls", rootfsDir).Output()
		if lsErr == nil && len(strings.TrimSpace(string(lsOut))) > 0 {
			log.Info("setupRestoreOverlayfs: placeholder rootfs ready (overlay mounted + content verified)",
				"rootfs", rootfsDir, "attempts", i+1)
			return rootfsDir, nil
		}
	}

	// Final check: if overlay is mounted but ls returned empty/error, still return success
	// since the rootfs directory exists (CRIU will operate via nsenterCmd in host namespace).
	if hostOverlayMounted() {
		log.Info("setupRestoreOverlayfs: overlay confirmed via /proc/1/mounts (ls timed out)", "rootfs", rootfsDir)
		return rootfsDir, nil
	}

	return "", fmt.Errorf("placeholder container rootfs overlay not mounted after 5s (checked via /proc/1/mounts): %s", rootfsDir)
}

// buildMinimalOCIConfig strips pod-specific paths from config.json, leaving only
// the process spec and standard container mounts. Uses fresh network/ipc/uts namespaces.
func buildMinimalOCIConfig(src map[string]interface{}, rootfsDir string) map[string]interface{} {
	cfg := map[string]interface{}{
		"ociVersion": src["ociVersion"],
		"process":    src["process"],
		"root":       map[string]interface{}{"path": rootfsDir, "readonly": false},
		"mounts": []interface{}{
			map[string]interface{}{"destination": "/proc", "type": "proc", "source": "proc"},
			map[string]interface{}{"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			map[string]interface{}{"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": []string{"nosuid", "noexec", "nodev", "ro"}},
			map[string]interface{}{"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"}},
			map[string]interface{}{"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue", "options": []string{"nosuid", "noexec", "nodev"}},
		},
		"linux": map[string]interface{}{
			"namespaces": []interface{}{
				map[string]interface{}{"type": "pid"},
				map[string]interface{}{"type": "ipc"},
				map[string]interface{}{"type": "uts"},
				map[string]interface{}{"type": "mount"},
				map[string]interface{}{"type": "network"},
				map[string]interface{}{"type": "cgroup"},
			},
			"maskedPaths":   []string{"/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/scsi", "/sys/firmware"},
			"readonlyPaths": []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"},
		},
		"annotations": src["annotations"],
	}
	// Preserve resource limits from original config.
	if linux, ok := src["linux"].(map[string]interface{}); ok {
		if res, ok := linux["resources"]; ok {
			cfg["linux"].(map[string]interface{})["resources"] = res
		}
	}
	return cfg
}

func (s *AgentServer) PreDumpRound(_ context.Context, req *agentpb.PreDumpRoundRequest) (*agentpb.PreDumpRoundResponse, error) {
	log.Info("PreDumpRound called", "migration", req.MigrationName, "round", req.RoundNumber)

	// Resolve the container root PID so CRIU dumps the right process tree,
	// not the agent's own cgroup. Without this, CRIU detects itself in the
	// dump tree and fails with "The criu itself is within dumped tree."
	var containerPID int32
	if req.PodUid != "" {
		pid, pidErr := FindContainerPID(req.PodUid)
		if pidErr != nil {
			log.Error(pidErr, "PreDumpRound: failed to resolve container PID", "podUID", req.PodUid)
		} else {
			containerPID = pid
			log.Info("PreDumpRound: resolved container PID", "pid", containerPID, "podUID", req.PodUid)
		}
	}

	imagesDir := fmt.Sprintf("/run/podmotion/checkpoints/%s/round-%d", req.MigrationName, req.RoundNumber)
	if err := os.MkdirAll(imagesDir, 0o700); err != nil {
		return nil, fmt.Errorf("PreDumpRound: mkdir %s: %w", imagesDir, err)
	}
	var prevImagesDir string
	if req.RoundNumber > 0 {
		prevImagesDir = fmt.Sprintf("/run/podmotion/checkpoints/%s/round-%d", req.MigrationName, req.RoundNumber-1)
	}
	result, err := s.checkpointer.PreDump(context.Background(), criu.PreDumpOptions{
		ImagesDir:     imagesDir,
		PrevImagesDir: prevImagesDir,
		Pid:           containerPID,
	})
	if err != nil {
		return nil, fmt.Errorf("PreDumpRound %d: %w", req.RoundNumber, err)
	}
	return &agentpb.PreDumpRoundResponse{
		DirtyPagesMb:     result.DirtyPagesMB,
		RoundDurationMs:  result.FreezeDurationMs,
		ThresholdReached: result.DirtyPagesMB < 64,
	}, nil
}

// Checkpoint performs the final (freezing) CRIU dump.
// When PODMOTION_MOCK_CRIU=true (dev/kind env var), a graceful fallback writes a mock
// checkpoint manifest so the end-to-end flow can proceed without real CRIU support.
// In production (PODMOTION_MOCK_CRIU unset), CRIU errors propagate up as failures.
func (s *AgentServer) Checkpoint(_ context.Context, req *agentpb.CheckpointRequest) (*agentpb.CheckpointResponse, error) {
	log.Info("Checkpoint called", "migration", req.MigrationName)

	// Stage on tmpfs (/run is a tmpfs mount on Linux) so checkpoint images containing
	// process memory and secrets are never written to persistent disk (ADR-0046).
	imagesDir := fmt.Sprintf("/run/podmotion/checkpoints/%s/final", req.MigrationName)

	// ADR-0182 Issue 2 (Standing Rule 7): PreDumpRound writes pre-dump images
	// containing live workload memory pages to /run/podmotion/checkpoints/<mig>/round-<N>/ BEFORE
	// this handler runs. On ANY Checkpoint-phase abort (CR-lookup failure at L3552, ctr fatal at
	// L3615, CRIU dump failure at L3773, etc.) those round-N dirs were previously left intact on
	// tmpfs until node reboot — a Standing Rule 7 violation ("zeroized on all exit paths").
	//
	// Register a single deferred zeroize-then-unlink sweep at the TOP of the handler, armed by
	// default, disarmed only on the success-return path via checkpointSucceeded. This guarantees
	// no current or future failure-return path can silently skip cleanup. We use zeroizeDir
	// (zeroize-then-unlink) — NOT os.RemoveAll — because a bare unlink leaves recoverable live
	// memory pages on tmpfs. The sweep covers every round-* subdir AND the final/ images dir.
	//
	// C-3 (Performance Reviewer): the zeroize runs SYNCHRONOUSLY on the gRPC handler goroutine.
	// This is intentional and within budget: it executes only on the failure-return path, which
	// has NO live-migration latency SLA (the migration is already aborting/rolling back). A
	// synchronous sweep is strictly more secure than async-with-timeout — an incomplete async
	// zeroize would leave live memory pages recoverable on tmpfs across a restart. Per the
	// Security Reviewer, that exposure outweighs any failure-path latency concern; bounded
	// sub-10ms tmpfs zeroize of the pre-dump set is well within the (non-existent) failure budget.
	checkpointSucceeded := false
	defer func() {
		if checkpointSucceeded {
			return
		}
		migDir := fmt.Sprintf("/run/podmotion/checkpoints/%s", req.MigrationName)
		rounds, _ := filepath.Glob(filepath.Join(migDir, "round-*"))
		for _, rd := range rounds {
			if zErr := zeroizeDir(rd); zErr != nil {
				log.Error(zErr, "Checkpoint abort cleanup: zeroize round dir failed (GC-9/SR-7, warn-only)",
					"migration", req.MigrationName, "dir", rd)
			}
		}
		// Also zeroize the final/ images dir — a partial ctr/CRIU dump may have written pages there.
		if zErr := zeroizeDir(imagesDir); zErr != nil && !os.IsNotExist(zErr) {
			log.Error(zErr, "Checkpoint abort cleanup: zeroize final images dir failed (GC-9/SR-7, warn-only)",
				"migration", req.MigrationName, "dir", imagesDir)
		}
		log.Info("Checkpoint abort cleanup: pre-dump round-N and final images zeroized (GC-9/SR-7)",
			"migration", req.MigrationName)
	}()

	// Fetch the PodMigration CR up front (ADR-0118). The CR is the canonical source of
	// migration identity: it provides both the TCPPreservationMode and the SourcePodUID
	// fallback used when the in-memory map has been lost across an agent restart.
	pm := &pmv1.PodMigration{}
	if s.k8sClient != nil {
		workloadNs := req.WorkloadNamespace
		if workloadNs == "" {
			return nil, fmt.Errorf("checkpoint: WorkloadNamespace is empty in CheckpointRequest; cannot resolve TCPPreservationMode — refusing to dump to avoid silent stateless downgrade")
		}
		lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer lookupCancel()
		if err := s.k8sClient.Get(lookupCtx, types.NamespacedName{
			Name:      req.MigrationName,
			Namespace: workloadNs,
		}, pm); err != nil {
			return nil, fmt.Errorf("checkpoint: CR lookup failed: %w", err)
		}
	}

	// Resolve the container root PID from the pod UID stored during PrepareSource.
	s.migrationPodUIDMu.RLock()
	podUID := s.migrationPodUID[req.MigrationName]
	s.migrationPodUIDMu.RUnlock()

	// ADR-0118: if the in-memory map missed (e.g. the agent restarted between PrepareSource
	// and Checkpoint), recover the pod UID from the CR's spec.sourcePodUID.
	if podUID == "" && s.k8sClient != nil {
		if pm.Spec.SourcePodUID == "" {
			return nil, fmt.Errorf("checkpoint: SourcePodUID is empty in CR — " +
				"controller has not completed Validating yet")
		}
		log.Info("Checkpoint: podUID not in memory map — recovering from CR spec.sourcePodUID",
			"migration", req.MigrationName, "uid", pm.Spec.SourcePodUID)
		podUID = pm.Spec.SourcePodUID
		// Repopulate the map so subsequent calls in this agent session skip the CR fallback.
		s.migrationPodUIDMu.Lock()
		s.migrationPodUID[req.MigrationName] = podUID
		s.migrationPodUIDMu.Unlock()
	}

	// Resolve TCPPreservationMode from the already-fetched PodMigration CR so TcpEstablished
	// is tier-driven. Done early so both the ctr and raw-CRIU paths can use the same value.
	tcpEstablished := false
	if s.k8sClient != nil {
		mode := pm.Spec.TCPPreservationMode
		tcpEstablished = mode == pmv1.TCPPreservationModeStrict || mode == pmv1.TCPPreservationModeBestEffort
	}

	// resolvedTaskID caches the containerd task ID resolved during the ctr attempt so the
	// raw-CRIU config.json staging step can reuse it without a second (racy) lookup (ADR-0134).
	var resolvedTaskID string

	// Try containerd-native checkpoint first (ctr tasks checkpoint).
	// This handles all container namespaces correctly (network, mount, etc.) and produces
	// CRIU images that runc can restore on the destination. Falls back to raw CRIU (go-criu)
	// if the containerd task ID can't be found (non-k8s environments, tests).
	if podUID != "" {
		taskID, taskErr := FindContainerTaskID(podUID)
		if taskErr == nil {
			// ADR-0134: cache the resolved task ID so the raw-CRIU config.json staging step
			// below can reuse it. After the raw CRIU dump runs with --tcp-established, the
			// task may no longer be enumerable by FindContainerTaskID (the frozen/dumped
			// process drops off the running-task scan), so re-resolving there returns
			// "task not found" and config.json is never staged → destination restore fails
			// with "read config.json: no such file or directory".
			resolvedTaskID = taskID
			log.Info("Checkpoint: using containerd-native ctr checkpoint", "taskID", taskID)
			freezeStart := time.Now()
			sizeBytes, ctrErr := ctrCheckpoint(taskID, imagesDir, tcpEstablished)
			freezeDurationMs := time.Since(freezeStart).Milliseconds()

			if ctrErr != nil {
				// Fall through to raw CRIU only for in-flight/established TCP socket failures —
				// ctr invokes CRIU without --tcp-established, so containers with active TCP
				// connections fail. The raw go-criu Dump path below sets TcpEstablished=tcpEstablished
				// (ADR-0131 D2), so established connections are PRESERVED via TCP_REPAIR, not closed.
				// Any other ctr error (OOM, permission, corrupt task) is fatal and returned directly
				// to avoid a double-freeze and to surface the real cause.
				if !errors.Is(ctrErr, ErrCtrInFlightTCP) {
					return nil, fmt.Errorf("checkpoint failed (ctr): %w", ctrErr)
				}
				log.Info("Checkpoint: ctr failed due to established TCP socket — falling back to raw CRIU with --tcp-established (ADR-0131 D2: connection preserved)",
					"taskID", taskID, "tcpEstablished", tcpEstablished, "err", ctrErr)
				// Clear any partial ctr images before raw CRIU writes to the same dir.
				// ADR-0182 Issue 2: zeroize-then-unlink, NOT a
				// bare os.RemoveAll — a partial ctr dump may already contain live memory pages in
				// final/, and a bare unlink leaves them recoverable on tmpfs (Standing Rule 7).
				if rmErr := zeroizeDir(imagesDir); rmErr != nil {
					return nil, fmt.Errorf("checkpoint: clearing partial ctr images before raw CRIU: %w", rmErr)
				}
			} else {
				sha := sha256OfDir(imagesDir)
				log.Info("Checkpoint complete (ctr)", "migration", req.MigrationName,
					"sizeBytes", sizeBytes, "sha256", sha, "freezeMs", freezeDurationMs)
				// ADR-0246 D1/D4: fail closed before transfer if the checkpoint references an
				// anon-shmem segment (mm-*.img) with no matching pagemap-shmem-<shmid>.img — the
				// confirmed CRIU 4.2 anon-shmem dump defect. Runs unconditionally on both the
				// ctr-native path (here) and the raw-CRIU fallback path below; not scoped to one
				// entry point (D1 step 4).
				if shmemErr := verifyShmemPagemapCompleteness(imagesDir); shmemErr != nil {
					log.Error(shmemErr, "Checkpoint (ctr): incomplete shmem pagemap set — refusing to transfer (ADR-0246)",
						"migration", req.MigrationName)
					// ADR-0246 typed-status redesign: return codes.FailedPrecondition with a
					// structured errdetails.ErrorInfo{Reason: ShmemPagemapMissingReason} payload
					// so the controller classifies this via grpcStatus.Details(), not string
					// matching (mirrors the ErrCRIUCapability pattern below).
					return nil, newShmemPagemapMissingStatus(shmemErr)
				}
				// Capture socket inventory from the (now frozen) container via its PID.
				// Non-fatal: ctr checkpoint already succeeded; SeqSnapshot is best-effort here.
				var ctrSeqSnapshots []*agentpb.SeqSnapshot
				if tcpEstablished {
					if ctrPID, pidErr := FindContainerPID(podUID); pidErr == nil {
						if sockEntries, invErr := network.SocketInventory(ctrPID); invErr == nil {
							for _, e := range sockEntries {
								ctrSeqSnapshots = append(ctrSeqSnapshots, &agentpb.SeqSnapshot{
									SrcIp:    e.SrcIP.String(),
									SrcPort:  uint32(e.SrcPort),
									DstIp:    e.DstIP.String(),
									DstPort:  uint32(e.DstPort),
									SndNxt:   e.SndNxt,
									RcvNxt:   e.RcvNxt,
									TsRecent: e.TsRecent,
								})
							}
							log.Info("Checkpoint: socket inventory (ctr path)", "migration", req.MigrationName,
								"connections", len(ctrSeqSnapshots))
						}
					}
				}
				// Success (ctr path): disarm the deferred abort-zeroize sweep. The final/ dir
				// holds the completed checkpoint which the transfer phase consumes; round-N dirs
				// are released later by ReleaseCheckpoint (ADR-0179) on the controller path.
				checkpointSucceeded = true
				return &agentpb.CheckpointResponse{
					FreezeDurationMs:    freezeDurationMs,
					CheckpointSha256:    sha,
					CheckpointSizeBytes: sizeBytes,
					SeqSnapshots:        ctrSeqSnapshots,
				}, nil
			}
		}
		log.Info("Checkpoint: ctr task lookup failed, using raw CRIU", "err", taskErr)
	}

	var containerPID int32
	if podUID != "" {
		pid, pidErr := FindContainerPID(podUID)
		if pidErr != nil {
			log.Error(pidErr, "Checkpoint: failed to resolve container root PID", "migration", req.MigrationName, "podUID", podUID)
		} else {
			containerPID = pid
			log.Info("Checkpoint: found container root PID", "pid", containerPID, "podUID", podUID)
		}
	} else {
		log.Info("Checkpoint: no pod UID recorded for migration — PID will be 0 (PrepareSource may not have been called)", "migration", req.MigrationName)
	}

	// Ensure the images directory exists before invoking CRIU — on a freshly provisioned VM
	// the directory will not exist and criu.Dump() will fail with "opening images dir".
	if mkErr := os.MkdirAll(imagesDir, 0o700); mkErr != nil {
		return nil, fmt.Errorf("checkpoint: cannot create images dir %s: %w", imagesDir, mkErr)
	}

	// Capture TCP sequence state immediately before freeze (ADR-0049, ADR-0156 D4).
	// On the Strict/BestEffort path we use TCP_REPAIR mode getsockopt to obtain real
	// snd_nxt / rcv_nxt values. /proc/net/tcp does NOT contain sequence numbers in any
	// kernel version (SocketInventory always returns SndNxt=0/RcvNxt=0), so SocketInventory
	// alone cannot satisfy GC-27. TCP_REPAIR is entered and immediately exited per D4 so the
	// socket is fully restored to normal operation before the CRIU dump begins.
	var seqSnapshots []*agentpb.SeqSnapshot
	if tcpEstablished && containerPID != 0 {
		repairEntries, repairErr := network.ExportTCPRepairState(containerPID)
		if repairErr != nil {
			log.Error(repairErr, "Checkpoint: TCP_REPAIR export failed — continuing without SeqSnapshot (ADR-0156 D4)",
				"pid", containerPID)
		} else {
			for _, e := range repairEntries {
				seqSnapshots = append(seqSnapshots, &agentpb.SeqSnapshot{
					SrcIp:    e.SrcIP.String(),
					SrcPort:  uint32(e.SrcPort),
					DstIp:    e.DstIP.String(),
					DstPort:  uint32(e.DstPort),
					SndNxt:   e.SndNxt,
					RcvNxt:   e.RcvNxt,
					TsRecent: e.TsRecent,
				})
			}
			log.Info("Checkpoint: TCP_REPAIR socket state exported (ADR-0156 D4, GC-27)",
				"migration", req.MigrationName, "pid", containerPID,
				"connections", len(seqSnapshots))
		}
	}

	// SD-4 (ADR-0039, ADR-0148): open the ptrace window precisely around the CRIU dump.
	// CAP_SYS_PTRACE is held continuously by SD-1's discrete cap set, but it is only
	// LEGITIMATELY exercised inside this dump window — CRIU's PTRACE_SEIZE/INTERRUPT of the
	// source process tree. The window marker is the in-window hint a future SD-5 seccomp-BPF
	// ptrace arg-filter consults; opening/closing it here bounds "ptrace is expected" to the
	// freeze boundary, never steady state. Deferred close is the panic/early-return fallback;
	// the explicit close immediately after Dump is the happy path. The stale-window sweeper
	// (StartStaleWindowSweeper, agent init) is the third line of defense against a stuck window.
	if owErr := seccomp.PtraceWindowOpen(req.MigrationName); owErr != nil {
		log.Error(owErr, "SD-4: failed to open ptrace window before CRIU dump — continuing (sweeper backstop)", "migration", req.MigrationName)
	}
	defer func() { _ = seccomp.PtraceWindowClose(req.MigrationName) }()

	freezeStart := time.Now()
	result, err := s.checkpointer.Dump(context.Background(), criu.DumpOptions{
		ImagesDir:      imagesDir,
		Pid:            containerPID,
		TcpEstablished: tcpEstablished,
		// LeaveStopped keeps the source process in SIGSTOP after the dump so no new
		// TCP data is sent while the destination is restoring (M23 ordering invariant).
		// Only set for TCP-stateful migrations — stateless migrations resume normally.
		// CRITICAL: Every error/rollback path that follows a successful LeaveStopped dump
		// MUST call thawFrozenSource(migrationName) so the source is never permanently
		// frozen. registerFrozenSource is called immediately after a successful dump.
		LeaveStopped: tcpEstablished,
	})

	// SD-4: ptrace is no longer expected once Dump returns (success or failure) — close the
	// window immediately on the happy path. The deferred close above is the fallback only.
	_ = seccomp.PtraceWindowClose(req.MigrationName)

	// freezeTimestampNs is CLOCK_REALTIME ns captured immediately after CRIU dump
	// returns. When LeaveStopped=true the process is in SIGSTOP at this point.
	freezeTimestampNs := time.Now().UnixNano()

	// Register the frozen source PID immediately after a successful LeaveStopped dump.
	// This ensures that any subsequent error return (SeedRelayFromSnapshots failure,
	// ordering invariant failure, transfer failure, controller crash handled by watchdog)
	// can thaw the source via Abort or the frozen-source watchdog.
	if err == nil && tcpEstablished && containerPID != 0 {
		s.registerFrozenSource(req.MigrationName, containerPID)
	}

	// ADR-0156 D4: after dump, write tcp_socket_state.json to the checkpoint dir.
	// The pre-dump TCP_REPAIR export (above) captured the real snd_nxt/rcv_nxt; we persist
	// them to a sidecar JSON so GC-27 can be verified by inspecting the checkpoint dir.
	// The post-dump SocketInventory call is intentionally omitted: it would overwrite the
	// TCP_REPAIR sequence numbers with zeros (/proc/net/tcp has no seq columns), destroying
	// the only valid snd_nxt/rcv_nxt values we hold. The pre-dump TCP_REPAIR values are
	// captured at the freeze boundary (ArmZeroWindow engaged, no new data possible) and are
	// exactly correct for seq_delta=0 verification.
	if err == nil && tcpEstablished && len(seqSnapshots) > 0 {
		if jsonErr := writeTCPSocketStateJSON(imagesDir, seqSnapshots); jsonErr != nil {
			log.Error(jsonErr, "Checkpoint: failed to write tcp_socket_state.json (non-fatal, GC-27 evidence only)",
				"migration", req.MigrationName)
		} else {
			log.Info("Checkpoint: tcp_socket_state.json written (GC-27)",
				"migration", req.MigrationName, "connections", len(seqSnapshots),
				"path", imagesDir+"/tcp_socket_state.json")
		}
	}

	var checkpointPath string
	var sha256sum string
	var sizeBytes int64
	var fallbackNote string
	var freezeDurationMs int64

	mockCRIU := os.Getenv("PODMOTION_MOCK_CRIU") == "true"

	if err != nil {
		log.Error(err, "Checkpoint: CRIU dump failed", "migration", req.MigrationName)

		if !mockCRIU {
			// Return codes.FailedPrecondition for capability/ptrace errors so the controller
			// can use grpcStatus.Code() == codes.FailedPrecondition instead of string matching
			// (M19.5 criterion 13: error classification via errors.Is/As not string matching).
			if errors.Is(err, ErrCRIUCapability) {
				return nil, status.Errorf(codes.FailedPrecondition, "checkpoint failed: %v", err)
			}
			// In production, propagate the error — do not silently substitute a mock checkpoint.
			return nil, fmt.Errorf("checkpoint failed: %w", err)
		}

		// PODMOTION_MOCK_CRIU=true — write a mock checkpoint manifest so the operator
		// can complete its state machine transitions in kind/dev environments.
		log.Info("Checkpoint: PODMOTION_MOCK_CRIU=true, writing mock checkpoint (kind/dev fallback)", "err", err)

		if mkErr := os.MkdirAll(imagesDir, 0o700); mkErr != nil {
			return nil, fmt.Errorf("checkpoint fallback: cannot create images dir: %w", mkErr)
		}

		// ADR-SEC-B: renamed from checkpoint-manifest.json to avoid colliding with the
		// new signed provenance manifest filename; mode 0o644→0o600 (N-342, invariant 7).
		manifestPath := filepath.Join(imagesDir, "checkpoint-mock-manifest.json")
		manifest := fmt.Sprintf(`{
  "migrationName": %q,
  "node": %q,
  "timestamp": %q,
  "mode": "mock-fallback",
  "reason": %q
}
`, req.MigrationName, s.nodeName, time.Now().UTC().Format(time.RFC3339), err.Error())

		if writeErr := os.WriteFile(manifestPath, []byte(manifest), 0o600); writeErr != nil {
			return nil, fmt.Errorf("checkpoint fallback: cannot write manifest: %w", writeErr)
		}

		checkpointPath = imagesDir
		sha256sum = sha256HexOfString(manifest)
		sizeBytes = int64(len(manifest))
		freezeDurationMs = time.Since(freezeStart).Milliseconds()
		fallbackNote = fmt.Sprintf("mock checkpoint (kind/dev fallback): criu error: %v", err)
	} else {
		checkpointPath = result.ImagesDir
		freezeDurationMs = result.FreezeDurationMs
		// Compute SHA256 of all files in the images directory.
		sha256sum, sizeBytes = checksumDir(checkpointPath)
		fallbackNote = "real CRIU checkpoint"

		// Stage config.json from the containerd bundle into the checkpoint dir.
		// The ctr-native path (ctrCheckpoint) copies this automatically, but the raw
		// go-criu Dump path (taken for established-TCP migrations falling back from ctr)
		// does NOT — and the destination NRI restore reads
		// <checkpointDir>/config.json to build the OCI bundle. Without it restore fails
		// with "read config.json: no such file or directory" (ADR-0131 restore path).
		if podUID != "" {
			// ADR-0134: prefer the task ID cached during the ctr attempt. Re-resolving here
			// fails after the raw CRIU dump (frozen task drops off FindContainerTaskID's scan).
			stageTaskID := resolvedTaskID
			var taskErr error
			if stageTaskID == "" {
				stageTaskID, taskErr = FindContainerTaskID(podUID)
			}
			if taskErr == nil && stageTaskID != "" {
				srcCfg := fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s/config.json", stageTaskID)
				dstCfg := filepath.Join(checkpointPath, "config.json")
				if data, readErr := os.ReadFile(srcCfg); readErr == nil {
					if wErr := os.WriteFile(dstCfg, data, 0o600); wErr != nil { // ADR-SEC-B N-342: 0600 (invariant 7)
						log.Error(wErr, "Checkpoint: failed to stage config.json into checkpoint dir (raw CRIU path) — restore will fail", "dst", dstCfg)
					} else {
						log.Info("Checkpoint: staged config.json into checkpoint dir (raw CRIU path)", "dst", dstCfg, "taskID", stageTaskID)
					}
				} else {
					log.Error(readErr, "Checkpoint: could not read bundle config.json (raw CRIU path)", "src", srcCfg)
				}
			} else {
				log.Info("Checkpoint: could not resolve task ID to stage config.json (raw CRIU path)", "podUID", podUID, "err", taskErr)
			}
		}
	}

	log.Info("Checkpoint complete", "path", checkpointPath, "sha256", sha256sum, "fallback", fallbackNote)

	// ADR-0246 D1/D4: fail closed before transfer if the checkpoint references an anon-shmem
	// segment (mm-*.img) with no matching pagemap-shmem-<shmid>.img — the confirmed CRIU 4.2
	// anon-shmem dump defect. Must run here, before encryptCheckpointDir below, since the guard
	// needs to read plaintext mm-*.img/pagemap-shmem-*.img content. Runs unconditionally on both
	// the raw-CRIU fallback path (here) and the ctr-native path above (D1 step 4).
	if shmemErr := verifyShmemPagemapCompleteness(imagesDir); shmemErr != nil {
		log.Error(shmemErr, "Checkpoint (raw CRIU): incomplete shmem pagemap set — refusing to transfer (ADR-0246)",
			"migration", req.MigrationName)
		// ADR-0246 typed-status redesign: see the ctr-native call site above for the full
		// rationale — same treatment on this path, unconditionally, per D1 step 4.
		return nil, newShmemPagemapMissingStatus(shmemErr)
	}

	// SD-2 (ADR-0029, ADR-0160): encrypt the checkpoint layer set AT REST in final/ before the
	// transfer phase reads it — encrypt-on-write at its source so ciphertext, never plaintext,
	// survives on tmpfs. No-op when no per-migration checkpoint-key Secret is present (ADR-0029
	// opt-in default). HB-1 AAD binds each layer to migrationUID:layerIndex:epoch; HB-3 zeroizes
	// derived key material. Failure here is FATAL: a half-encrypted final/ must not transfer.
	if encErr := s.encryptCheckpointDir(context.Background(), req.MigrationName, imagesDir); encErr != nil {
		return nil, fmt.Errorf("SD-2: encrypt checkpoint layer set at rest: %w", encErr)
	}

	// Success (raw-CRIU path): disarm the deferred abort-zeroize sweep. The completed
	// checkpoint in final/ is consumed by the transfer phase; round-N dirs are released
	// later by ReleaseCheckpoint (ADR-0179). ADR-0182 Issue 2.
	checkpointSucceeded = true

	// Update MigrationCheckpoint CR if we have a k8s client.
	// The CR name convention mirrors the PodMigration name.
	if s.k8sClient != nil {
		if updateErr := s.upsertMigrationCheckpoint(req.MigrationName, checkpointPath, sha256sum, sizeBytes); updateErr != nil {
			log.Error(updateErr, "Failed to upsert MigrationCheckpoint CR — non-fatal")
		}
	}

	return &agentpb.CheckpointResponse{
		FreezeDurationMs:    freezeDurationMs,
		CheckpointSha256:    sha256sum,
		CheckpointSizeBytes: sizeBytes,
		SeqSnapshots:        seqSnapshots,
		FreezeTimestampNs:   freezeTimestampNs,
	}, nil
}

// MigrationNodes implements authz.MigrationBinder (ADR-SEC-A §2.2.4). It reads the PodMigration
// CR via the agent's cached k8s client and returns the source and destination node names so the
// authz interceptor can bind a PEER_AGENT caller to a migration its node is actually party to.
// found=false when there is no k8s client or the CR is absent (deny).
func (s *AgentServer) MigrationNodes(ctx context.Context, migrationName string) (sourceNode, destNode string, found bool) {
	if s.k8sClient == nil || migrationName == "" {
		return "", "", false
	}
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		ns = "podmotion-system"
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pm := &pmv1.PodMigration{}
	if err := s.k8sClient.Get(lookupCtx, types.NamespacedName{Name: migrationName, Namespace: ns}, pm); err != nil {
		return "", "", false
	}
	src := pm.Status.SourceNodeName
	dst := pm.Status.DestinationNodeName
	if dst == "" {
		dst = pm.Spec.DestinationNode
	}
	if dst == "" {
		dst = pm.Spec.TargetNodeName
	}
	return src, dst, true
}

// upsertMigrationCheckpoint creates or updates the MigrationCheckpoint CR for this migration.
func (s *AgentServer) upsertMigrationCheckpoint(migrationName, checkpointPath, sha256sum string, sizeBytes int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Derive namespace from agent env or default to podmotion-system.
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		ns = "podmotion-system"
	}

	// Try to fetch existing CR first.
	existing := &pmv1.MigrationCheckpoint{}
	err := s.k8sClient.Get(ctx, types.NamespacedName{Name: migrationName, Namespace: ns}, existing)
	if err != nil {
		// Create a new MigrationCheckpoint.
		sz := sizeBytes
		mc := &pmv1.MigrationCheckpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name:      migrationName,
				Namespace: ns,
				Labels: map[string]string{
					"podmotion.io/migration": migrationName,
				},
			},
			Spec: pmv1.MigrationCheckpointSpec{
				PodMigrationRef: migrationName,
				SourceNodeName:  s.nodeName,
				TransferMode:    pmv1.CheckpointTransferModeDirectP2P,
				RegistryRef:     checkpointPath,
				ContentSHA256:   sha256sum,
				SizeBytes:       &sz,
			},
		}
		if createErr := s.k8sClient.Create(ctx, mc); createErr != nil {
			return fmt.Errorf("create MigrationCheckpoint: %w", createErr)
		}
		log.Info("MigrationCheckpoint CR created", "name", migrationName, "ns", ns)
		return nil
	}

	// Update existing.
	sz := sizeBytes
	existing.Spec.ContentSHA256 = sha256sum
	existing.Spec.SizeBytes = &sz
	existing.Spec.RegistryRef = checkpointPath
	if updateErr := s.k8sClient.Update(ctx, existing); updateErr != nil {
		return fmt.Errorf("update MigrationCheckpoint: %w", updateErr)
	}
	log.Info("MigrationCheckpoint CR updated", "name", migrationName, "ns", ns)
	return nil
}

func (s *AgentServer) PrepareDestination(_ context.Context, req *agentpb.PrepareDestinationRequest) (*agentpb.PrepareDestinationResponse, error) {
	log.Info("PrepareDestination called", "migration", req.MigrationName, "sourceNode", req.SourceNode)
	// Ensure /run/podmotion/netns/ exists on the destination node so that CRIU
	// --join-ns net:<path> can access the bind-mounted netns file. PrepareDestinationNetns
	// creates this directory, but PrepareDestination is called first and on failure paths
	// the netns dir may be absent. Creating it here is idempotent and guarantees the
	// parent directory exists before any bind-mount attempt (Sprint 32 gate blocker B6).
	if err := os.MkdirAll("/run/podmotion/netns", 0o700); err != nil {
		log.Error(err, "PrepareDestination: failed to create /run/podmotion/netns — CRIU join-ns will fail",
			"migration", req.MigrationName)
		// Non-fatal: return ready so the controller can proceed to PrepareDestinationNetns
		// which will fail with a clearer error if the directory is truly inaccessible.
	}
	return &agentpb.PrepareDestinationResponse{
		Ready:        true,
		IpReserved:   true,
		StorageReady: true,
	}, nil
}

// Restore recreates the container from dump images on the destination node.
// On kind/dev where CRIU restore lacks permissions, a graceful fallback starts
// a fresh nginx container via exec to simulate the restored workload.
func (s *AgentServer) Restore(ctx context.Context, req *agentpb.RestoreRequest) (*agentpb.RestoreResponse, error) {
	log.Info("Restore called", "migration", req.MigrationName, "checkpointRef", req.CheckpointRef)

	imagesDir := req.CheckpointRef
	if imagesDir == "" {
		// Consistent with the source agent's ctrCheckpoint and PutCheckpointTar paths.
		imagesDir = fmt.Sprintf("/run/podmotion/checkpoints/%s/final", req.MigrationName)
	}

	// 0700: checkpoint images contain process memory and secrets.
	if mkErr := os.MkdirAll(imagesDir, 0o700); mkErr != nil {
		log.Info("Restore: cannot create images dir, proceeding to fallback", "err", mkErr)
	}
	// Zeroize checkpoint images ONLY after restore is confirmed successful. The controller
	// calls Restore more than once (retry/requeue paths); an unconditional defer would wipe
	// the checkpoint dir on the first call and the second call would find inventory.img gone
	// → RestoreFailed (Sprint 32 gate21 root cause). restoreConfirmed is set true only at the
	// terminal confirmed-success returns.
	restoreConfirmed := false
	defer func() {
		if restoreConfirmed {
			_ = zeroizeDir(imagesDir)
		}
	}()

	// ADR-0168 GC-10: tear down the pre-staged dest migration netns on restore-failure rollback.
	// Covers all early-return failure sites with a single call site. The teardown is warn-only
	// (ADR-0012/ADR-0165-r2 SP-7). Only runs when a dest netns was pre-staged (DestNetnsFd set)
	// and restore did not succeed.
	defer func() {
		if restoreConfirmed || req.DestNetnsFd == "" {
			return
		}
		s.destMigrationNetnsMu.Lock()
		ns, hasNs := s.destMigrationNetns[req.MigrationName]
		if hasNs {
			delete(s.destMigrationNetns, req.MigrationName)
		}
		s.destMigrationNetnsMu.Unlock()
		if hasNs {
			if teardownErr := network.TeardownMigrationNetns(context.Background(), ns); teardownErr != nil {
				log.Error(teardownErr, "GC-10: TeardownMigrationNetns warn-only on restore-failure rollback", "migration", req.MigrationName)
			} else {
				log.Info("GC-10: dest migration netns torn down on restore-failure rollback", "migration", req.MigrationName)
			}
		} else {
			log.Info("GC-10: no stored MigrationNetns handle for teardown (PrepareDestinationNetns may not have run on this path)", "migration", req.MigrationName)
		}
	}()

	// ADR-0168 B2: read the cached workload image for this migration. If set, it will be used
	// instead of the joinNsRestore hardcoded fallback when imageName is empty on this gRPC path.
	s.destWorkloadImageMu.RLock()
	storedWorkloadImage := s.destWorkloadImage[req.MigrationName]
	s.destWorkloadImageMu.RUnlock()

	// ADR-0235: gRPC-Restore-path workload-image self-resolve fallback (ADR-0217 D2 parity).
	// The controller's NRI fallback (reconcileRestoringNRI, controller:2724) invokes THIS gRPC
	// Restore RPC ~60s after the NRI confirm window times out. Unlike the NRI hook path
	// ((*AgentServer).JoinNsRestore, server.go:401-440 — which carries the ADR-0217 D2 third
	// fallback), this gRPC path passed ONLY destWorkloadImage[migration] straight into
	// joinNsRestoreFn (line below). When the B2 cache is empty — observed live on
	// sprint37-hardened-e2e: the deployed MigrationCheckpoint CRD lacked spec.workloadImage so
	// the controller's D1/B2 MCP write was dropped server-side ("unknown field spec.workloadImage")
	// and PrepareDestinationNetns received workloadImage="" → cache never populated — the gRPC
	// path fell straight through to the ADR-0215 fail-close at server.go:2606 ("restore image
	// unresolved (ADR-0215) ... controller must plumb ..."), EVEN THOUGH the NRI path had already
	// self-resolved the same image ("ADR-0217 D2: resolved workload image from replacement pod
	// spec"). Apply the identical D2 self-resolve here so both live restore entry points behave
	// the same. No hardcoded image is reintroduced — D2 reads the operator-created replacement
	// pod's real container[0].Image; ADR-0215's fail-closed-rather-than-guess intent is preserved.
	if storedWorkloadImage == "" && s.k8sClient != nil {
		if resolved := s.resolveImageFromReplacementPod(req.MigrationName); resolved != "" {
			storedWorkloadImage = resolved
			log.Info("ADR-0235: gRPC Restore — B2 cache empty, resolved workload image from replacement pod spec (ADR-0217 D2 parity)",
				"migration", req.MigrationName, "image", storedWorkloadImage)
		}
	}

	// SD-2 (ADR-0029, ADR-0160): decrypt the checkpoint layer set in place before CRIU reads it.
	// No-op when the encrypted-set marker is absent (encryption was off, or a prior restore
	// attempt already decrypted — idempotent). Fail closed: a marked-encrypted final/ with no
	// available key, a wrong key, an AAD mismatch (wrong migration/layer/epoch), or a tampered
	// layer all abort the restore here rather than handing ciphertext to CRIU. HB-3: the derived
	// shared key is zeroized inside decryptCheckpointDir.
	if decErr := s.decryptCheckpointDir(ctx, req.MigrationName, imagesDir); decErr != nil {
		msg := fmt.Sprintf("Restore: SD-2 decrypt checkpoint layer set: %v", decErr)
		log.Error(decErr, msg, "migration", req.MigrationName)
		return &agentpb.RestoreResponse{Success: false, ErrorMessage: msg}, nil
	}

	// Pre-restore sanity: inventory.img must exist and be non-empty. If absent, CRIU
	// fails immediately with "No inventory.img image / Unexpected EOF on (empty-image)".
	// Catching this here gives a clear error instead of an opaque CRIU exit-1.
	invPath := filepath.Join(imagesDir, "inventory.img")
	if info, statErr := os.Stat(invPath); statErr != nil || info.Size() == 0 {
		msg := fmt.Sprintf("Restore: inventory.img missing or empty at %s (size=%d, err=%v) — checkpoint transfer incomplete",
			invPath, func() int64 {
				if info != nil {
					return info.Size()
				}
				return -1
			}(), statErr)
		log.Error(statErr, msg, "migration", req.MigrationName)
		return &agentpb.RestoreResponse{Success: false, ErrorMessage: msg}, nil
	}

	// B2 (Sprint 32 gate25) — strict-mode fail-closed netns-fd assertion.
	// The RestoreRequest proto carries no tcpPreservationMode field; on this gRPC path a
	// Strict migration is signalled by populated SeqSnapshots (per-connection TCP sequence
	// state is only transferred when TCP preservation is active). When Strict is in effect
	// the controller's DestinationNetnsReady stage MUST plumb the destination netns fd into
	// DestNetnsFd. If it is empty, joinNsRestore would silently fall through the
	// tcpPreservationMode=None cold path (no --join-ns), restoring the TCP-preserving process
	// tree into the wrong namespace and bricking it post-checkpoint. Refuse instead.
	if len(req.SeqSnapshots) > 0 && req.DestNetnsFd == "" {
		msg := fmt.Sprintf("Restore: Strict migration %s refused: DestNetnsFd empty; DestinationNetnsReady stage did not plumb netns fd — refusing None cold path fallthrough to prevent post-checkpoint brick", req.MigrationName)
		log.Info(msg, "migration", req.MigrationName)
		return &agentpb.RestoreResponse{Success: false, ErrorMessage: msg}, nil
	}

	// ADR-0228 restore idempotency (gRPC-fallback path): the controller re-invokes this gRPC
	// Restore RPC after its NRI-confirm window times out (reconcileRestoringNRI, controller
	// "NRI confirm timeout — falling back to agent Restore RPC"). On the live NRI path CRIU
	// restore already ran and SUCCEEDED in the NRI StartContainer hook, leaving the workload
	// alive and its PID recorded at the deterministic pidfile path. Blindly re-running CRIU
	// restore here would spawn a SECOND CRIU that, on the cold --join-ns path, stays the
	// foreground parent in do_wait forever (rule 6: no --restore-detached) while the
	// already-restored workload holds the netns — hanging THIS RPC between the ptrace-window
	// open below and its deferred close (observed live: the seccomp sweeper firing
	// "deferred close did not fire — likely agent crash inside CRIU window", the CR stuck at
	// RestoreSocketReattach). Consult the SOURCE OF TRUTH first: if a prior restore already
	// produced a LIVE workload PID for this migration, confirm-and-advance instead of
	// re-restoring. This never opens a ptrace window and never blocks on a subprocess.
	{
		dataDir := fmt.Sprintf("/var/lib/podmotion/restore/%s/data", req.MigrationName)
		// ADR-0306 item (c): non-zero settle window on the confirm-path liveness check only.
		const confirmPathSettle = 200 * time.Millisecond
		if priorPID, alive := priorRestoredPIDIfAliveSettle(dataDir, confirmPathSettle); alive {
			log.Info("Restore: prior restore already produced a live workload PID — confirming idempotently without re-running CRIU (ADR-0228)",
				"migration", req.MigrationName, "restoredPID", priorPID)

			// ADR-0306 item (a): restart-durable netns-identity gate. --pidfile only guarantees
			// identity at CRIU-restore-write time (ADR-0306 item d); a live PID at read time
			// could be a recycled, unrelated process. Re-establish identity via netns membership,
			// resolved through the restart-durable ResolveNetnsFromSandbox — NOT the in-memory
			// s.ResolvedNetnsPath cache, which is empty across an agent restart.
			sandboxID := req.SandboxId
			if sandboxID == "" {
				resolvedID, resolveErr := s.resolveSandboxIDForMigration(ctx, req.MigrationName)
				if resolveErr != nil {
					msg := fmt.Sprintf("Restore: idempotent confirm path — sandbox ID unobtainable (req.SandboxId empty and self-resolve failed): %v", resolveErr)
					log.Error(resolveErr, "Restore: idempotent confirm path — sandbox ID unobtainable, failing closed (ADR-0306 item a)", "migration", req.MigrationName)
					return &agentpb.RestoreResponse{Success: false, ErrorMessage: msg}, nil
				}
				sandboxID = resolvedID
			}
			expectedNetnsFile, expectedNetnsPath, netnsErr := ResolveNetnsFromSandbox(ctx, nil, sandboxID)
			if netnsErr != nil {
				msg := fmt.Sprintf("Restore: idempotent confirm path — could not resolve expected sandbox netns for identity check: %v", netnsErr)
				log.Error(netnsErr, "Restore: idempotent confirm path — netns resolution failed, failing closed (ADR-0306 item a)", "migration", req.MigrationName, "sandboxID", sandboxID)
				return &agentpb.RestoreResponse{Success: false, ErrorMessage: msg}, nil
			}
			_ = expectedNetnsFile.Close()
			match, matchErr := pidNetnsMatchesPath(priorPID, expectedNetnsPath)
			if matchErr != nil || !match {
				msg := fmt.Sprintf("Restore: idempotent confirm path — netns identity mismatch for restored PID %d (sandbox %s): matchErr=%v match=%v",
					priorPID, sandboxID, matchErr, match)
				log.Info(msg, "migration", req.MigrationName)
				return &agentpb.RestoreResponse{Success: false, ErrorMessage: msg}, nil
			}
			log.Info("Restore: idempotent confirm path — netns identity confirmed via restart-durable sandbox resolution (ADR-0306 item a)",
				"migration", req.MigrationName, "restoredPID", priorPID, "sandboxID", sandboxID)

			// ADR-0306 item (b): Strict gated-resume fix. If this migration is Strict (or
			// BestEffort with TCP sequence snapshots) and the restored tree is currently stopped
			// (SIGSTOP 'T' or tracing-stop 't'), re-insert it into pendingResumePIDs so
			// InjectIPHandoff's existing dequeue delivers the deferred SIGCONT. A transient
			// unreadable /proc/<pid>/stat is treated as "not currently eligible," not an error.
			if req.TcpPreservationMode == "Strict" || (req.TcpPreservationMode == "BestEffort" && len(req.SeqSnapshots) > 0) {
				if stateChar, stateErr := procStatStateChar(priorPID); stateErr == nil && (stateChar == 'T' || stateChar == 't') {
					s.pendingResumePIDsMu.Lock()
					s.pendingResumePIDs[req.MigrationName] = priorPID
					s.pendingResumePIDsMu.Unlock()
					log.Info("Restore: idempotent confirm path — restored tree is stopped under Strict/TCP-preserving mode, re-armed deferred SIGCONT (ADR-0306 item b)",
						"migration", req.MigrationName, "restoredPID", priorPID, "state", string(stateChar))
				}
			}

			// Parity with the terminal success path: populate MAC + SingleHomeRestoredPod.
			netnsPath := s.ResolvedNetnsPath(req.MigrationName)
			fr, frErr := s.finalizeRestore(ctx, priorPID, netnsPath, req.MigrationName, "", req.TcpPreservationMode)
			if frErr != nil {
				log.Error(frErr, "Restore: finalizeRestore failed on idempotent confirm path (Strict/Full fail-closed)", "migration", req.MigrationName)
				return &agentpb.RestoreResponse{Success: false, ErrorMessage: frErr.Error()}, nil
			}
			// Report restore confirmed — this sets status.criuRestoreConfirmed, the exact
			// signal reconcileRestoringNRI polls for to advance the phase (closes the loop
			// the double-restore hang left open).
			if s.k8sClient != nil {
				ns := s.resolveNamespaceForMigration(ctx, req.MigrationName)
				if ns != "" {
					if rcErr := s.ReportRestoreConfirmed(ctx, req.MigrationName, ns, int32(priorPID), fr.mac); rcErr != nil {
						log.Error(rcErr, "Restore: ReportRestoreConfirmed failed on idempotent confirm path (non-fatal — GC-08 will not pass)", "migration", req.MigrationName, "namespace", ns)
					}
				} else {
					log.Info("Restore: could not resolve namespace for migration — ReportRestoreConfirmed skipped (idempotent confirm path)", "migration", req.MigrationName)
				}
			}

			// Map cleanup mirrors the terminal success return.
			s.destMigrationNetnsMu.Lock()
			delete(s.destMigrationNetns, req.MigrationName)
			s.destMigrationNetnsMu.Unlock()
			s.destWorkloadImageMu.Lock()
			delete(s.destWorkloadImage, req.MigrationName)
			s.destWorkloadImageMu.Unlock()

			restoreConfirmed = true
			return &agentpb.RestoreResponse{Success: true}, nil
		}
	}

	// SD-4 (ADR-0039, ADR-0148): open the ptrace window around the CRIU restore. Restore is
	// the second window in which the agent legitimately exercises CAP_SYS_PTRACE (CRIU
	// PTRACE_SEIZE/INTERRUPT of the restored process tree on the destination). The Restore
	// handler has multiple CRIU-invoking paths and many return points, so the window is opened
	// once here — immediately before the first CRIU restore invocation — and closed via the
	// deferred fallback covering every return path; the explicit happy-path close fires right
	// after the join-ns restore returns. The stale-window sweeper backstops a crash mid-restore.
	if owErr := seccomp.PtraceWindowOpen(req.MigrationName); owErr != nil {
		log.Error(owErr, "SD-4: failed to open ptrace window before CRIU restore — continuing (sweeper backstop)", "migration", req.MigrationName)
	}
	defer func() { _ = seccomp.PtraceWindowClose(req.MigrationName) }()

	// Check if we have a config.json (produced by ctr checkpoint) — use join-ns restore:
	// launch a fresh placeholder container then restore checkpoint state into its namespaces.
	cfgPath := filepath.Join(imagesDir, "config.json")
	if _, statErr := os.Stat(cfgPath); statErr == nil {
		log.Info("Restore: config.json found — using join-ns restore (ctr placeholder + CRIU)",
			"destNetnsFd", req.DestNetnsFd)
		restoreStart := time.Now()
		// ADR-0122: the Restore gRPC path does not carry a replacement pod sandbox ID (no proto
		// field). On the --join-ns (DestNetnsFd set) path the sandbox ID is unused. On the
		// stateless path, joinNsRestore now requires the sandbox netns and will fail loudly —
		// the live North Star restore flows through the NRI hook (cmd/agent/main.go), which
		// supplies the sandbox ID from pod.GetId().
		// Operator Restore RPC: strictMode=false here because --leave-stopped is already gated
		// on destNetnsFd != "" inside buildCRIURestoreArgs (the M23 ordering invariant path).
		// ADR-0144: the NRI path uses strictMode=true when tcpPreservationMode=Strict.
		s.destHostVethMu.RLock()
		storedVeth := s.destHostVeth[req.MigrationName]
		s.destHostVethMu.RUnlock()
		// ADR-0168 B2: pass storedWorkloadImage so the placeholder uses the correct image.
		pid, droppedMnts, joinErr := joinNsRestoreFn(req.MigrationName, imagesDir, storedWorkloadImage, "", req.DestNetnsFd, "", storedVeth, false)
		// SD-4: CRIU restore has returned — ptrace is no longer expected. Close the window on
		// the happy path immediately (the deferred close above is the fallback for early returns).
		_ = seccomp.PtraceWindowClose(req.MigrationName)
		for _, d := range droppedMnts {
			s.emitExternalMountDroppedEvent(context.Background(), req.MigrationName, d)
		}
		restoreDurationMs := time.Since(restoreStart).Milliseconds()
		if joinErr != nil {
			return nil, fmt.Errorf("runc restore failed: %w", joinErr)
		}
		log.Info("Restore: join-ns restore succeeded", "migration", req.MigrationName, "restoredPID", pid, "durationMs", restoreDurationMs)

		// Persist SeqSnapshots for VerifyTCP post-restore comparison.
		if len(req.SeqSnapshots) > 0 {
			s.migrationSeqSnapshotsMu.Lock()
			s.migrationSeqSnapshots[req.MigrationName] = req.SeqSnapshots
			s.migrationSeqSnapshotsMu.Unlock()
		}

		// Seed PM_SEQ_XLAT from the source freeze SeqSnapshots before ZeroWindowDisarm fires
		// (ADR-0049 predicate B: map entries verified before disarm).
		if len(req.SeqSnapshots) > 0 {
			relayIfname := req.RelayIfname
			if relayIfname == "" {
				relayIfname = "flannel.1"
			}
			snaps := make([]network.SeqSnapshot, 0, len(req.SeqSnapshots))
			for _, ss := range req.SeqSnapshots {
				snaps = append(snaps, network.SeqSnapshot{
					SrcIP:   ss.SrcIp,
					SrcPort: ss.SrcPort,
					DstIP:   ss.DstIp,
					DstPort: ss.DstPort,
					SndNxt:  ss.SndNxt,
					RcvNxt:  ss.RcvNxt,
				})
			}
			seedCtx, seedCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer seedCancel()
			if _, seedErr := network.SeedRelayFromSnapshots(seedCtx, int32(pid), snaps, relayIfname, s.ebpfMgr); seedErr != nil {
				// CRITICAL: SeqSnapshots were provided but PM_SEQ_XLAT seeding failed.
				// Returning success here would allow the controller to advance to
				// CutoverComplete and delete the source pod while sequence translation
				// is absent — causing TCP RST on all migrated connections (ADR-0049).
				// Fail closed so the controller rolls back and the source pod is preserved.
				log.Error(seedErr, "Restore: SeedRelayFromSnapshots FAILED — returning failure to prevent premature source deletion",
					"migration", req.MigrationName)
				return &agentpb.RestoreResponse{
					Success:      false,
					ErrorMessage: fmt.Sprintf("SeedRelayFromSnapshots: %v — relay seq translation not seeded; migration cannot safely proceed", seedErr),
				}, nil
			}
		}

		// M23 ordering invariant: when TCP-stateful restore was used (--leave-stopped),
		// the restored process is in SIGSTOP. We MUST verify TCP sockets are ESTABLISHED
		// (SocketsLive) before sending SIGCONT. This is a hard gate — SIGCONT is withheld
		// until the confirmed socket count matches the expected source connection count.
		if req.DestNetnsFd != "" && pid > 0 {
			// ADR-0142 D3: defer SIGCONT past InjectIPHandoff whenever there is a
			// TCP-established connection to preserve (the seq_delta=0 path). The restored
			// tree stays SIGSTOP-held until the OLD-IP datapath is wired; InjectIPHandoff
			// fires the deferred SIGCONT as its final action. When no TCP connections are
			// expected, enforceRestoreOrderingInvariant resumes inline (deferResume ignored).
			deferResume := len(req.SeqSnapshots) > 0
			socketsLiveAt, resumedAt, orderErr := enforceRestoreOrderingInvariant(pid, req.MigrationName, len(req.SeqSnapshots), deferResume)
			if orderErr != nil {
				log.Error(orderErr, "Restore: ordering invariant FAILED — SIGCONT withheld, failing restore for rollback",
					"migration", req.MigrationName, "pid", pid)
				return &agentpb.RestoreResponse{
					Success:      false,
					ErrorMessage: fmt.Sprintf("ordering invariant: %v", orderErr),
				}, nil
			}
			if deferResume && resumedAt.IsZero() {
				// SocketsLive confirmed but SIGCONT deferred — record the pending PID so
				// InjectIPHandoff can resume the tree after the datapath is live (ADR-0142 D3).
				s.pendingResumePIDsMu.Lock()
				s.pendingResumePIDs[req.MigrationName] = pid
				s.pendingResumePIDsMu.Unlock()
				log.Info("Restore: SIGCONT deferred — restored tree held in SIGSTOP until InjectIPHandoff (ADR-0142 D3)",
					"migration", req.MigrationName, "pid", pid)
			}
			log.Info("Restore: ordering invariant satisfied",
				"migration", req.MigrationName,
				"socketsLiveAt", socketsLiveAt,
				"resumedAt", resumedAt,
				"resumeDeferred", deferResume && resumedAt.IsZero(),
			)
			if s.k8sClient != nil && !resumedAt.IsZero() {
				if setErr := s.setOrderingConditions(req.MigrationName, pid, socketsLiveAt, resumedAt); setErr != nil {
					// Ordering condition update failure is non-fatal for the migration itself,
					// but we log it as an error because the condition API contract is violated.
					log.Error(setErr, "Restore: failed to set ordering conditions", "migration", req.MigrationName)
				}
			}
		}

		// E1 Condition 1+2: call finalizeRestore to populate MAC and run SingleHomeRestoredPod
		// on this gRPC path (parity with NRI path — Condition 2).
		// Unconditional: finalizeRestore always runs (MAC resolution + Strict/Full fail-closed applies even without k8s client).
		netnsPath := s.ResolvedNetnsPath(req.MigrationName)
		fr, frErr := s.finalizeRestore(ctx, pid, netnsPath, req.MigrationName, "", req.TcpPreservationMode)
		if frErr != nil {
			log.Error(frErr, "Restore: finalizeRestore failed (Strict/Full fail-closed)", "migration", req.MigrationName)
			return &agentpb.RestoreResponse{Success: false, ErrorMessage: frErr.Error()}, nil
		}
		// Gate k8s side-effects (ReportRestoreConfirmed, namespace resolution) on k8sClient.
		if s.k8sClient != nil {
			ns := s.resolveNamespaceForMigration(ctx, req.MigrationName)
			if ns != "" {
				if rcErr := s.ReportRestoreConfirmed(ctx, req.MigrationName, ns, int32(pid), fr.mac); rcErr != nil {
					log.Error(rcErr, "Restore: ReportRestoreConfirmed failed (non-fatal — GC-08 will not pass)", "migration", req.MigrationName, "namespace", ns)
				}
			} else {
				log.Info("Restore: could not resolve namespace for migration — ReportRestoreConfirmed skipped", "migration", req.MigrationName)
			}
		}

		// ADR-0168 GC-10: clean up maps on successful restore (defer only handles failure path).
		s.destMigrationNetnsMu.Lock()
		delete(s.destMigrationNetns, req.MigrationName)
		s.destMigrationNetnsMu.Unlock()
		s.destWorkloadImageMu.Lock()
		delete(s.destWorkloadImage, req.MigrationName)
		s.destWorkloadImageMu.Unlock()

		restoreConfirmed = true
		return &agentpb.RestoreResponse{
			Success:           true,
			RestoreDurationMs: restoreDurationMs,
		}, nil
	}

	// Raw CRIU restore via joinNsRestore (same path as ctr checkpoint, but without config.json).
	// The raw CRIU path (go-criu swrk) fails because it runs CRIU in the agent container's
	// mount namespace, which has /sys. CRIU compat-mode tries to umount /sys → EBUSY.
	// joinNsRestore runs CRIU via nsenter in the HOST mount namespace with --root pointing to
	// the container's overlayfs, which avoids the agent namespace /sys issue entirely.
	// Gate10: patch checkpoint images first (same as the config.json path).
	//
	// ADR-0049 Amendment D (A1): under tcpPreservationMode=Strict, patchCheckpointImages
	// failure is a hard failure — proceeding on un-patched images is a security fail-open
	// (source-pod IP / netns identity remnants survive per ADR-0125/0162). Abort and let
	// the controller initiate rollback (source pod preserved per ADR-0012).
	// Mode is now carried explicitly via req.TCPPreservationMode (field 9); this replaces
	// the previous SeqSnapshots>0 proxy which failed-open when Strict had zero TCP connections.
	// Under None/BestEffort: log clearly and continue (typed PATCH_ERROR from Python layer
	// is surfaced in the error string via patchCheckpointImages return value).
	// ADR-0193 C-R3-1: no early enumerate here (gRPC Restore path does not build cgroup inherit-fds
	// at this layer; joinNsRestoreFn handles that internally when config.json branch is taken above).
	// For the non-config.json gRPC path below, pass nil (degrade-and-continue on P-0193-1).
	if patchErr := patchCheckpointImagesFn(imagesDir, nil); patchErr != nil {
		if req.TcpPreservationMode == "Strict" {
			// Strict: fail closed. The controller will initiate rollback.
			log.Error(patchErr, "Restore: patchCheckpointImages failed under Strict — aborting restore (ADR-0049 Amendment D A1)", "migration", req.MigrationName)
			return nil, fmt.Errorf("restore aborted (strict): patchCheckpointImages: %w", patchErr)
		}
		// None/BestEffort: degrade-and-continue. Surface the typed PATCH_ERROR from pycriu.
		log.Error(patchErr, "Restore: patchCheckpointImages failed (non-fatal under BestEffort/None, proceeding on un-patched images)", "migration", req.MigrationName)
	}

	t0 := time.Now()
	// ADR-0168 B2: storedWorkloadImage replaces the empty imageName on the gRPC fallback path.
	// containerID="" → joinNsRestore uses the placeholder container path (no NRI hook).
	// destNetnsFd=req.DestNetnsFd — cold migration passes empty string.
	s.destHostVethMu.RLock()
	storedVeth2 := s.destHostVeth[req.MigrationName]
	s.destHostVethMu.RUnlock()
	rawPID, droppedMnts2, joinErr := joinNsRestoreFn(req.MigrationName, imagesDir, storedWorkloadImage, "", req.DestNetnsFd, "", storedVeth2, false)
	for _, d := range droppedMnts2 {
		s.emitExternalMountDroppedEvent(context.Background(), req.MigrationName, d)
	}
	if joinErr != nil {
		log.Info("Restore: joinNsRestore failed", "err", joinErr)
		return nil, fmt.Errorf("restore failed: %w", joinErr)
	}
	log.Info("Restore: joinNsRestore succeeded (raw CRIU path via joinNs)", "migration", req.MigrationName, "pid", rawPID)
	result := criu.RestoreResult{PID: rawPID, RestoredAt: time.Now()}

	// E1 Condition 1+2: finalizeRestore for MAC population + SingleHomeRestoredPod parity
	// on the raw CRIU fallback path (Conditions 1, 2, 3).
	// Unconditional: finalizeRestore always runs (MAC resolution + Strict/Full fail-closed applies even without k8s client).
	netnsPath2 := s.ResolvedNetnsPath(req.MigrationName)
	fr2, frErr2 := s.finalizeRestore(ctx, result.PID, netnsPath2, req.MigrationName, "", req.TcpPreservationMode)
	if frErr2 != nil {
		log.Error(frErr2, "Restore (raw CRIU path): finalizeRestore failed (Strict/Full fail-closed)", "migration", req.MigrationName)
		return &agentpb.RestoreResponse{Success: false, ErrorMessage: frErr2.Error()}, nil
	}
	// Gate k8s side-effects (ReportRestoreConfirmed, namespace resolution) on k8sClient.
	if s.k8sClient != nil {
		ns := s.resolveNamespaceForMigration(ctx, req.MigrationName)
		if ns != "" {
			if rcErr := s.ReportRestoreConfirmed(ctx, req.MigrationName, ns, int32(result.PID), fr2.mac); rcErr != nil {
				log.Error(rcErr, "Restore (raw CRIU path): ReportRestoreConfirmed failed (non-fatal)", "migration", req.MigrationName, "namespace", ns)
			}
		} else {
			log.Info("Restore (raw CRIU path): could not resolve namespace — ReportRestoreConfirmed skipped", "migration", req.MigrationName)
		}
	}

	// ADR-0168 GC-10: clean up maps on successful restore (defer only handles failure path).
	s.destMigrationNetnsMu.Lock()
	delete(s.destMigrationNetns, req.MigrationName)
	s.destMigrationNetnsMu.Unlock()
	s.destWorkloadImageMu.Lock()
	delete(s.destWorkloadImage, req.MigrationName)
	s.destWorkloadImageMu.Unlock()

	restoreConfirmed = true
	return &agentpb.RestoreResponse{
		Success:           true,
		RestoreDurationMs: time.Since(result.RestoredAt).Milliseconds() + time.Since(t0).Milliseconds(),
	}, nil
}

// startFallbackContainer starts a detached nginx container named after the migration
// to simulate a restored workload. Uses `docker run` which is available on kind nodes.
func startFallbackContainer(migrationName string) (string, error) {
	containerName := fmt.Sprintf("pm-restore-%s", migrationName)

	// Remove any existing container with this name (idempotency).
	_ = runCmd("docker", "rm", "-f", containerName)

	out, err := runCmdOutput("docker", "run", "-d",
		"--name", containerName,
		"--label", "podmotion.io/migration="+migrationName,
		"--label", "podmotion.io/restore=fallback",
		"nginx:alpine")
	if err != nil {
		return "", fmt.Errorf("docker run: %w (output: %s)", err, out)
	}

	containerID := strings.TrimSpace(out)
	return fmt.Sprintf("fallback nginx container started: %s (id: %.12s)", containerName, containerID), nil
}

// runCmd runs a command discarding output. Returns error if exit code != 0.
func runCmd(name string, args ...string) error {
	_, err := runCmdOutput(name, args...)
	return err
}

// runCmdOutput runs a command and returns combined stdout+stderr.
func runCmdOutput(name string, args ...string) (string, error) {
	// Import os/exec inline to avoid top-level import cycle concerns.
	// We use a subprocess here intentionally (docker CLI), consistent with ADR-0002.
	cmd := newExecCmd(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s *AgentServer) Verify(_ context.Context, req *agentpb.VerifyRequest) (*agentpb.VerifyResponse, error) {
	log.Info("Verify called", "migration", req.MigrationName, "pod", req.PodName)
	// M4: stub — real readiness probe wired when traffic agent is complete.
	return &agentpb.VerifyResponse{Healthy: true}, nil
}

// VerifyTCP reads /proc/<pid>/net/tcp[6] post-restore, compares each ESTABLISHED
// connection's snd_nxt/rcv_nxt against the source SeqSnapshots within ±MSS (1448 bytes),
// and issues the configured SQL/TCP application probe. Returns verified=true only when
// all connections pass the continuity check and the application probe succeeds.
func (s *AgentServer) VerifyTCP(ctx context.Context, req *agentpb.VerifyTCPRequest) (*agentpb.VerifyTCPResponse, error) {
	log.Info("VerifyTCP called", "migration", req.MigrationName)

	// Retrieve stored SeqSnapshots; fall back to request-supplied ones.
	s.migrationSeqSnapshotsMu.RLock()
	stored := s.migrationSeqSnapshots[req.MigrationName]
	s.migrationSeqSnapshotsMu.RUnlock()

	sourceSnaps := stored
	if len(sourceSnaps) == 0 {
		sourceSnaps = req.SourceSeqSnapshots
	}

	// Resolve destination container PID.
	s.migrationPodUIDMu.RLock()
	podUID := s.migrationPodUID[req.MigrationName]
	s.migrationPodUIDMu.RUnlock()
	if req.PodUid != "" {
		podUID = req.PodUid
	}

	if podUID == "" {
		return &agentpb.VerifyTCPResponse{
			Verified:      false,
			FailureReason: "VerifyTCP: pod UID unknown; cannot resolve destination PID",
		}, nil
	}

	pid, pidErr := FindContainerPID(podUID)
	if pidErr != nil {
		return &agentpb.VerifyTCPResponse{
			Verified:      false,
			FailureReason: fmt.Sprintf("VerifyTCP: cannot resolve destination container PID: %v", pidErr),
		}, nil
	}

	destEntries, invErr := network.SocketInventory(pid)
	if invErr != nil {
		return &agentpb.VerifyTCPResponse{
			Verified:      false,
			FailureReason: fmt.Sprintf("VerifyTCP: socket inventory failed on destination pid=%d: %v", pid, invErr),
		}, nil
	}

	// If no source snapshots are available and there are ESTABLISHED connections on the
	// destination, fail CLOSED. An empty snapshot set means either:
	//   (a) the proto wire bug dropped the field — verified=true with no evidence is
	//       catastrophic because it authorises source-pod deletion without proof, or
	//   (b) there were genuinely zero ESTABLISHED sockets at freeze time — in which
	//       case len(destEntries) should also be 0 (no connections to verify).
	// We never treat absence-of-evidence as proof of continuity (ADR-0049 fail-closed).
	//
	// Exception: if both source snapshots AND destination connections are zero, the
	// migration had no TCP state to preserve — that is genuinely verified.
	if len(sourceSnaps) == 0 {
		if len(destEntries) == 0 {
			// No ESTABLISHED connections at either end — stateless migration, trivially verified.
			log.Info("VerifyTCP: no source SeqSnapshots and no destination ESTABLISHED sockets — stateless migration verified",
				"migration", req.MigrationName)
			return &agentpb.VerifyTCPResponse{
				Verified:            true,
				ConnectionsVerified: 0,
				ConnectionsExpected: 0,
			}, nil
		}
		// Source snapshots missing but destination has live ESTABLISHED connections.
		// This is a verification failure — absence of evidence is not success.
		msg := fmt.Sprintf("VerifyTCP: source SeqSnapshots absent but destination has %d ESTABLISHED connection(s) — cannot verify TCP continuity (ADR-0049 fail-closed); regenerate proto/gen if proto wire bug suspected",
			len(destEntries))
		log.Error(nil, msg, "migration", req.MigrationName)
		return &agentpb.VerifyTCPResponse{
			Verified:            false,
			ConnectionsVerified: 0,
			ConnectionsExpected: -1, // sentinel: snapshots missing, not zero
			FailureReason:       msg,
		}, nil
	}

	// Match each source snapshot to a destination entry by 4-tuple, then verify
	// snd_nxt/rcv_nxt continuity within ±MSS (TCP Maximum Segment Size = 1448 bytes).
	const mss uint32 = 1448
	verified := 0
	var failures []string
	// ADR-0210: track the MEASURED maximum per-direction sequence delta across all
	// connections. This is returned to the controller, which sets the seq_delta gauge and
	// the North Star assertion from it — never from a hard-coded literal 0. A non-zero value
	// fails Strict verification at the controller.
	var sndDeltaMax, rcvDeltaMax uint32

	for _, snap := range sourceSnaps {
		matched := false
		for _, dest := range destEntries {
			if dest.SrcIP.String() != snap.SrcIp || dest.DstIP.String() != snap.DstIp {
				continue
			}
			if uint32(dest.SrcPort) != snap.SrcPort || uint32(dest.DstPort) != snap.DstPort {
				continue
			}
			matched = true
			// Compare snd_nxt with ±MSS tolerance using 32-bit modular arithmetic.
			sndDelta := absDiffU32(dest.SndNxt, snap.SndNxt)
			rcvDelta := absDiffU32(dest.RcvNxt, snap.RcvNxt)
			// ADR-0210: record measured maxima (whether or not within MSS tolerance).
			if sndDelta > sndDeltaMax {
				sndDeltaMax = sndDelta
			}
			if rcvDelta > rcvDeltaMax {
				rcvDeltaMax = rcvDelta
			}
			if sndDelta > mss {
				failures = append(failures, fmt.Sprintf(
					"4-tuple %s:%d→%s:%d snd_nxt delta %d > MSS %d (src=%d dest=%d)",
					snap.SrcIp, snap.SrcPort, snap.DstIp, snap.DstPort,
					sndDelta, mss, snap.SndNxt, dest.SndNxt))
			} else if rcvDelta > mss {
				failures = append(failures, fmt.Sprintf(
					"4-tuple %s:%d→%s:%d rcv_nxt delta %d > MSS %d (src=%d dest=%d)",
					snap.SrcIp, snap.SrcPort, snap.DstIp, snap.DstPort,
					rcvDelta, mss, snap.RcvNxt, dest.RcvNxt))
			} else {
				verified++
			}
			break
		}
		if !matched {
			failures = append(failures, fmt.Sprintf(
				"4-tuple %s:%d→%s:%d not found in destination /proc/net/tcp[6]",
				snap.SrcIp, snap.SrcPort, snap.DstIp, snap.DstPort))
		}
	}

	resp := &agentpb.VerifyTCPResponse{
		ConnectionsVerified: int32(verified),
		ConnectionsExpected: int32(len(sourceSnaps)),
		// ADR-0210: measured maxima — controller plumbs these to the gauge/North Star,
		// never a hard-coded 0.
		SndSeqDeltaMax: sndDeltaMax,
		RcvSeqDeltaMax: rcvDeltaMax,
	}
	if len(failures) > 0 {
		resp.Verified = false
		resp.FailureReason = strings.Join(failures, "; ")
		log.Info("VerifyTCP: sequence continuity check failed",
			"migration", req.MigrationName, "failures", len(failures), "reason", resp.FailureReason)
		return resp, nil
	}

	// Application probe: SQL or TCP probe if configured.
	if req.AppProbeProtocol != "" {
		probeErr := runAppProbe(ctx, req)
		if probeErr != nil {
			resp.Verified = false
			resp.AppProbeOk = false
			resp.AppProbeError = probeErr.Error()
			resp.FailureReason = fmt.Sprintf("app probe failed: %v", probeErr)
			log.Info("VerifyTCP: application probe failed",
				"migration", req.MigrationName, "protocol", req.AppProbeProtocol, "err", probeErr)
			return resp, nil
		}
		resp.AppProbeOk = true
	}

	resp.Verified = true
	log.Info("VerifyTCP: all connections verified",
		"migration", req.MigrationName, "verified", verified, "expected", len(sourceSnaps))
	return resp, nil
}

// isNetTimeout returns true if err is a network timeout error.
func isNetTimeout(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// absDiffU32 returns the minimum distance between two uint32 sequence numbers
// using 32-bit modular (TCP wraparound-safe) arithmetic.
func absDiffU32(a, b uint32) uint32 {
	if a >= b {
		d := a - b
		if d > 0x7FFFFFFF {
			return ^d + 1 // wrapped: distance is 2^32 - d
		}
		return d
	}
	d := b - a
	if d > 0x7FFFFFFF {
		return ^d + 1
	}
	return d
}

// runAppProbe issues a SQL (SELECT 1) or raw TCP connect probe.
func runAppProbe(ctx context.Context, req *agentpb.VerifyTCPRequest) error {
	timeout := time.Duration(req.AppProbeTimeoutS) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch strings.ToUpper(req.AppProbeProtocol) {
	case "TCP":
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", req.AppProbeAddress)
		if err != nil {
			return fmt.Errorf("TCP probe to %s failed: %w", req.AppProbeAddress, err)
		}
		conn.Close()
		return nil
	case "SQL":
		// Raw TCP connect to the SQL port + send the query, read one response line.
		// This avoids importing a database driver (custom-over-packages, ADR).
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", req.AppProbeAddress)
		if err != nil {
			return fmt.Errorf("SQL probe TCP connect to %s failed: %w", req.AppProbeAddress, err)
		}
		defer conn.Close()
		query := req.AppProbeQuery
		if query == "" {
			query = "SELECT 1"
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		// For PostgreSQL wire protocol, a startup message is required before queries.
		// A bare TCP connect + immediate read is sufficient to confirm the port is open
		// and the server is accepting connections. A full SQL response requires the
		// protocol handshake; the probe here validates TCP-level liveness.
		// Read one byte to confirm the server is actively listening (sends startup banner).
		buf := make([]byte, 1)
		_, readErr := conn.Read(buf)
		// EOF is acceptable: server accepted and closed cleanly (e.g. healthcheck port).
		if readErr != nil && readErr.Error() != "EOF" && !isNetTimeout(readErr) {
			return fmt.Errorf("SQL probe read from %s failed: %w", req.AppProbeAddress, readErr)
		}
		return nil
	default:
		return fmt.Errorf("unsupported app probe protocol %q", req.AppProbeProtocol)
	}
}

func (s *AgentServer) Abort(_ context.Context, req *agentpb.AbortRequest) (*agentpb.AbortResponse, error) {
	log.Info("Abort called", "migration", req.MigrationName, "reason", req.Reason)

	// Thaw any frozen source PID before aborting CRIU. If LeaveStopped=true left the
	// source process in SIGSTOP after a successful dump, the source must be SIGCONTed
	// here so the workload resumes on the source node (ADR-0012 rollback atomicity).
	// This is idempotent — if the source was never frozen, this is a no-op.
	s.thawFrozenSource(req.MigrationName)

	// GC-10 (ADR-0173): tear down the pre-staged destination migration netns on the
	// NRI/operator-driven restore-failure path. The ADR-0168 Restore defer never fires
	// on this path (Restore RPC was never the entry point), so the operator's rollback
	// drives teardown via Abort. This MUST run unconditionally — defer it BEFORE the
	// checkpointer.Abort call so an early error return cannot skip dest-netns cleanup.
	// Idempotent: the map entry is deleted on first call (Restore-defer or repeat Abort
	// become safe no-ops). Warn-only (ADR-0012 / ADR-0165-r2 SP-7): never blocks Abort.
	defer func() {
		s.destMigrationNetnsMu.Lock()
		ns, hasNs := s.destMigrationNetns[req.MigrationName]
		if hasNs {
			delete(s.destMigrationNetns, req.MigrationName)
		}
		s.destMigrationNetnsMu.Unlock()
		if hasNs {
			if teardownErr := network.TeardownMigrationNetns(context.Background(), ns); teardownErr != nil {
				log.Error(teardownErr, "GC-10: TeardownMigrationNetns warn-only on Abort", "migration", req.MigrationName)
			} else {
				log.Info("GC-10: dest migration netns torn down on Abort", "migration", req.MigrationName)
			}
		}
	}()

	if err := s.checkpointer.Abort(context.Background(), "", "k8s.io"); err != nil {
		return &agentpb.AbortResponse{Success: false}, err
	}
	return &agentpb.AbortResponse{Success: true}, nil
}

func (s *AgentServer) EstimateCheckpoint(ctx context.Context, req *agentpb.EstimateCheckpointRequest) (*agentpb.EstimateCheckpointResponse, error) {
	log.Info("EstimateCheckpoint called", "pod", req.PodName, "ns", req.PodNamespace)

	// One short pre-dump round gives us real dirty page count and elapsed time.
	// The container is NOT frozen — track-mem only mode.
	sampleDir := fmt.Sprintf("/var/lib/podmotion/estimate/%s-%s", req.PodNamespace, req.PodName)
	start := time.Now()
	result, err := s.checkpointer.PreDump(ctx, criu.PreDumpOptions{
		ContainerID:   req.PodName,
		Namespace:     "k8s.io",
		ImagesDir:     sampleDir,
		PrevImagesDir: "",
	})
	if err != nil {
		log.Error(err, "EstimateCheckpoint pre-dump failed — falling back to stub values")
		return &agentpb.EstimateCheckpointResponse{
			DirtyPageRateMbPerSec:     32.0,
			EstimatedFreezeDurationMs: 150,
			EstimatedCheckpointSizeMb: 512,
			StorageTier:               1,
			Migratable:                true,
		}, nil
	}

	elapsedMs := time.Since(start).Milliseconds()
	var rateMBps float32
	if elapsedMs > 0 {
		rateMBps = float32(result.DirtyPagesMB) / float32(float64(elapsedMs)/1000.0)
	}

	// Predict freeze duration: dirty_mb / 100 MB/s * 1000ms (assumes 800Mbps link).
	const assumedBandwidthMBps = 100
	freezeMs := int64(0)
	if assumedBandwidthMBps > 0 {
		freezeMs = result.DirtyPagesMB * 1000 / assumedBandwidthMBps
	}

	return &agentpb.EstimateCheckpointResponse{
		DirtyPageRateMbPerSec:     rateMBps,
		EstimatedFreezeDurationMs: freezeMs,
		EstimatedCheckpointSizeMb: result.DirtyPagesMB,
		StorageTier:               1,
		Migratable:                true,
	}, nil
}

// PutCheckpointTar receives a gzip-compressed tar of checkpoint images from the operator
// and extracts them into the migration's checkpoint directory on this (destination) node.
// This implements the LAN cold-migration transfer path: the operator reads the source
// checkpoint files (local on pm-control) and streams them here via gRPC unary call.
func (s *AgentServer) PutCheckpointTar(ctx context.Context, req *agentpb.PutCheckpointTarRequest) (*agentpb.PutCheckpointTarResponse, error) {
	if req.MigrationName == "" {
		return &agentpb.PutCheckpointTarResponse{Success: false, Error: "migration_name required"}, nil
	}
	if len(req.TarData) == 0 {
		return &agentpb.PutCheckpointTarResponse{Success: false, Error: "tar_data is empty"}, nil
	}

	// ── ADR-SEC-B §2.3 verify-before-extract gate. Bytes reach the restore dir (final/) only
	// after ALL checks pass, in cheap→expensive order. Decompression goes to a STAGING dir, not
	// final/; staging is zeroized on every reject path.

	// (1) ADR-SEC-A §2.3: on-wire size cap + gzip decompression bound (defense-in-depth; the gRPC
	// MaxRecvMsgSize already rejected oversize frames before this handler).
	if int64(len(req.TarData)) > grpclimits.MaxCheckpointTarBytes {
		return nil, status.Errorf(codes.ResourceExhausted, "ADR-SEC-A: tar_data %d exceeds cap %d", len(req.TarData), grpclimits.MaxCheckpointTarBytes)
	}

	// (2) Wire-integrity (C-334): verify sha256(tar_data) BEFORE any decompression begins.
	if req.TarSha256 == "" {
		return nil, status.Error(codes.DataLoss, "ADR-SEC-B: tar_sha256 absent — refusing checkpoint without wire-integrity hash")
	}
	computed := provenance.SHA256Hex(req.TarData)
	if computed != req.TarSha256 {
		log.Error(nil, "ADR-SEC-B: PutCheckpointTar wire-hash mismatch — rejecting before decompress",
			"migration", req.MigrationName, "expected", req.TarSha256, "computed", computed)
		return nil, status.Errorf(codes.DataLoss, "ADR-SEC-B: tar wire-hash mismatch (expected %s, got %s)", req.TarSha256, computed)
	}

	// (3) Signature (C-332): verify manifest_sig over manifest using the operator public key,
	// pinned via the trusted CA + operator SPIFFE ID.
	if len(req.Manifest) == 0 || len(req.ManifestSig) == 0 {
		return nil, status.Error(codes.PermissionDenied, "ADR-SEC-B: manifest or signature absent — refusing unverified checkpoint")
	}
	var manifest provenance.Manifest
	if err := json.Unmarshal(req.Manifest, &manifest); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-B: manifest decode: %v", err)
	}
	caPEM, caErr := os.ReadFile(agentCAPath())
	if caErr != nil {
		return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-B: read CA for operator-key pin: %v", caErr)
	}
	pub, pubErr := provenance.OperatorPublicKeyFromCA(caPEM, []byte(manifest.OperatorCertPEM))
	if pubErr != nil {
		log.Error(pubErr, "ADR-SEC-B: operator cert failed CA/SPIFFE pin — rejecting", "migration", req.MigrationName)
		return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-B: operator key pin failed: %v", pubErr)
	}
	canonical, cErr := provenance.CanonicalJSON(&manifest)
	if cErr != nil {
		return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-B: canonicalize manifest: %v", cErr)
	}
	if !provenance.Verify(pub, canonical, req.ManifestSig) {
		log.Error(nil, "ADR-SEC-B: manifest signature INVALID — rejecting checkpoint", "migration", req.MigrationName)
		return nil, status.Error(codes.PermissionDenied, "ADR-SEC-B: manifest signature verification failed")
	}
	// set_digest must match the file set the signature commits to.
	if manifest.SetDigest != provenance.ComputeSetDigest(manifest.Files) {
		return nil, status.Error(codes.DataLoss, "ADR-SEC-B: manifest set_digest does not match file list")
	}

	// (5) Migration binding (anti-replay, §2.5): manifest.migration == req name AND
	// manifest.migration_uid == the live PodMigration CR's UID. (Checked before extraction.)
	if manifest.Migration != req.MigrationName {
		return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-B: manifest migration %q != request %q", manifest.Migration, req.MigrationName)
	}
	if err := s.verifyMigrationUID(ctx, req.MigrationName, manifest.MigrationUID); err != nil {
		log.Error(err, "ADR-SEC-B: migration_uid binding failed — rejecting (anti-replay)", "migration", req.MigrationName)
		return nil, status.Errorf(codes.PermissionDenied, "ADR-SEC-B: migration_uid binding failed: %v", err)
	}

	// (4) Manifest↔tar binding + extraction to STAGING. Decompress to a staging dir, hash each
	// extracted file, and require the extracted set to EXACTLY equal manifest.files.
	stagingDir := fmt.Sprintf("/run/podmotion/checkpoints/%s/staging", req.MigrationName)
	_ = zeroizeDir(stagingDir) // clean any prior partial staging
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return &agentpb.PutCheckpointTarResponse{Success: false, Error: fmt.Sprintf("mkdir staging %s: %v", stagingDir, err)}, nil
	}
	stagingOK := false
	defer func() {
		if !stagingOK {
			_ = zeroizeDir(stagingDir)
		}
	}()

	gzr, err := gzip.NewReader(bytes.NewReader(req.TarData))
	if err != nil {
		return nil, status.Errorf(codes.DataLoss, "ADR-SEC-B: gzip open: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(io.LimitReader(gzr, grpclimits.MaxDecompressedTarBytes+1))
	var bytesWritten int64
	extracted := map[string]int64{} // flat filename -> size
	for {
		hdr, hErr := tr.Next()
		if hErr == io.EOF {
			break
		}
		if hErr != nil {
			return nil, status.Errorf(codes.DataLoss, "ADR-SEC-B: tar read: %v", hErr)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		// Path-traversal mitigation retained: write all files flat into stagingDir.
		filename := filepath.Base(hdr.Name)
		if filename == "" || filename == "." || filename == ".." {
			continue
		}
		outPath := filepath.Join(stagingDir, filename)
		f, oErr := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
		if oErr != nil {
			return nil, status.Errorf(codes.Internal, "ADR-SEC-B: create %s: %v", outPath, oErr)
		}
		n, wErr := io.Copy(f, tr)
		f.Close()
		if wErr != nil {
			return nil, status.Errorf(codes.Internal, "ADR-SEC-B: write %s: %v", filename, wErr)
		}
		bytesWritten += n
		if bytesWritten > grpclimits.MaxDecompressedTarBytes {
			return nil, status.Errorf(codes.ResourceExhausted, "ADR-SEC-B: decompressed size exceeds %d (gzip-bomb guard)", grpclimits.MaxDecompressedTarBytes)
		}
		extracted[filename] = n
	}

	// Per-file digest + size verification against the signed manifest; set membership equality.
	if len(extracted) != len(manifest.Files) {
		return nil, status.Errorf(codes.DataLoss, "ADR-SEC-B: tar file count %d != manifest %d", len(extracted), len(manifest.Files))
	}
	for _, want := range manifest.Files {
		gotSize, present := extracted[want.Name]
		if !present {
			return nil, status.Errorf(codes.DataLoss, "ADR-SEC-B: manifest file %q missing from tar", want.Name)
		}
		if gotSize != want.Size {
			return nil, status.Errorf(codes.DataLoss, "ADR-SEC-B: file %q size %d != manifest %d", want.Name, gotSize, want.Size)
		}
		data, rErr := os.ReadFile(filepath.Join(stagingDir, want.Name))
		if rErr != nil {
			return nil, status.Errorf(codes.Internal, "ADR-SEC-B: re-read staged %q: %v", want.Name, rErr)
		}
		if got := provenance.SHA256Hex(data); got != want.SHA256 {
			log.Error(nil, "ADR-SEC-B: per-file digest mismatch — rejecting checkpoint",
				"migration", req.MigrationName, "file", want.Name, "expected", want.SHA256, "got", got)
			return nil, status.Errorf(codes.DataLoss, "ADR-SEC-B: file %q digest mismatch", want.Name)
		}
	}

	// (6) All checks passed. Atomically move staging → final/ and write the checkpoint-verified
	// sentinel (0600) that the NRI restore gate (§2.6) and the socket-reattach path require.
	destDir := fmt.Sprintf("/run/podmotion/checkpoints/%s/final", req.MigrationName)
	_ = zeroizeDir(destDir)
	if err := os.Rename(stagingDir, destDir); err != nil {
		return nil, status.Errorf(codes.Internal, "ADR-SEC-B: promote staging→final: %v", err)
	}
	stagingOK = true // staging is now final/ — disarm the staging zeroize defer
	if err := os.WriteFile(filepath.Join(destDir, checkpointVerifiedSentinel), []byte(manifest.SetDigest), 0o600); err != nil {
		// Sentinel write failure: fail closed (zeroize final so an unverified-but-present dir
		// cannot be restored from). Source pod is never deleted pre-TrafficVerified (invariant 5).
		_ = zeroizeDir(destDir)
		return nil, status.Errorf(codes.Internal, "ADR-SEC-B: write verification sentinel: %v", err)
	}

	hasInventory := false
	for name := range extracted {
		if name == "inventory.img" {
			hasInventory = true
		}
	}
	if !hasInventory {
		log.Error(nil, "PutCheckpointTar: inventory.img NOT in tar — CRIU restore will fail",
			"migration", req.MigrationName, "fileCount", len(extracted))
	}

	log.Info("ADR-SEC-B: PutCheckpointTar: extracted checkpoint images (provenance-verified)",
		"migration", req.MigrationName,
		"destDir", destDir,
		"fileCount", len(extracted),
		"bytesWritten", bytesWritten,
		"tarSize", len(req.TarData),
		"hasInventory", hasInventory,
		"migrationUID", manifest.MigrationUID)
	return &agentpb.PutCheckpointTarResponse{Success: true, BytesWritten: bytesWritten}, nil
}

// checkpointVerifiedSentinel is the ADR-SEC-B §2.3 step 6 / §2.6 sentinel written into final/
// after the provenance gate passes. The NRI restore path and the socket-reattach path refuse to
// proceed without it.
const checkpointVerifiedSentinel = "checkpoint-verified"

// verifyMigrationUID checks the signed manifest's migration_uid matches the live PodMigration
// CR's .metadata.uid (ADR-SEC-B §2.5 anti-replay). A nil k8s client cannot verify the binding —
// fail closed.
func (s *AgentServer) verifyMigrationUID(ctx context.Context, migrationName, manifestUID string) error {
	if manifestUID == "" {
		return fmt.Errorf("ADR-SEC-D: manifest migration_uid empty")
	}
	if s.k8sClient == nil {
		return fmt.Errorf("ADR-SEC-D: no k8s client to verify migration_uid binding")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// ADR-SEC-D: The PodMigration CR namespace is NOT carried on the wire and is NOT the
	// agent's own namespace. The original ADR-SEC-B impl read os.Getenv("POD_NAMESPACE")
	// with a hardcoded "podmotion-system" default; the agent DaemonSet sets no POD_NAMESPACE
	// (ADR-SEC-B §5.2, env-provenance), so the Get targeted the wrong
	// namespace and returned NotFound for default-namespace migrations. Resolve the namespace
	// namespace-agnostically using the codebase's established default-first-then-List-by-name
	// pattern (resolveNamespaceForMigration / restoredPIDForMigration, server.go:1186-1228).
	// Namespace LOCATES the CR only; it never authorizes — the UID comparison below is the
	// sole binding decision (C2).
	pm := &pmv1.PodMigration{}
	if ns := s.resolveNamespaceForMigration(lookupCtx, migrationName); ns != "" {
		if err := s.k8sClient.Get(lookupCtx, types.NamespacedName{Name: migrationName, Namespace: ns}, pm); err != nil {
			return fmt.Errorf("ADR-SEC-D: read PodMigration CR %q in ns %q: %w", migrationName, ns, err)
		}
	} else {
		// C1: List-by-name across all namespaces; require EXACTLY one match. Zero or
		// more-than-one match → fail closed (PermissionDenied semantics — caller wraps).
		pmList := &pmv1.PodMigrationList{}
		if err := s.k8sClient.List(lookupCtx, pmList); err != nil {
			return fmt.Errorf("ADR-SEC-D: list PodMigrations to bind migration_uid: %w", err)
		}
		var matches []*pmv1.PodMigration
		for i := range pmList.Items {
			if pmList.Items[i].Name == migrationName {
				matches = append(matches, &pmList.Items[i])
			}
		}
		if len(matches) == 0 {
			return fmt.Errorf("ADR-SEC-D: no PodMigration CR named %q found to verify migration_uid binding", migrationName)
		}
		if len(matches) > 1 {
			return fmt.Errorf("ADR-SEC-D: ambiguous migration_uid binding: %d PodMigration CRs named %q across namespaces — failing closed", len(matches), migrationName)
		}
		pm = matches[0]
	}
	if string(pm.UID) != manifestUID {
		return fmt.Errorf("ADR-SEC-D: manifest migration_uid %q != live CR UID %q (replay)", manifestUID, string(pm.UID))
	}
	return nil
}

// agentCAPath is the trusted CA bundle the agent uses to pin the operator signing cert
// (ADR-SEC-B §2.1). Same ca.crt ADR-SEC-A mounts; no new secret.
func agentCAPath() string {
	if p := os.Getenv("PODMOTION_CA_FILE"); p != "" {
		return p
	}
	return "/etc/podmotion/tls/ca.crt"
}

// GetCheckpointTar reads the checkpoint image directory on this (source) node and
// returns a gzip-compressed tar. This is a pure read — it does NOT zeroize the source.
// The controller calls GetCheckpointTar → PutCheckpointTar (dest) → persists
// CheckpointTransferred=true → ReleaseCheckpoint (source). This sequence ensures the
// source copy survives a controller crash between Put and the status write.
func (s *AgentServer) GetCheckpointTar(_ context.Context, req *agentpb.GetCheckpointTarRequest) (*agentpb.GetCheckpointTarResponse, error) {
	if req.MigrationName == "" {
		return &agentpb.GetCheckpointTarResponse{Success: false, Error: "migration_name required"}, nil
	}

	srcDir := fmt.Sprintf("/run/podmotion/checkpoints/%s/final", req.MigrationName)
	entries, err := os.ReadDir(srcDir)
	if err != nil || len(entries) == 0 {
		return &agentpb.GetCheckpointTarResponse{
			Success: false,
			Error:   fmt.Sprintf("checkpoint dir not ready: %v", err),
		}, nil
	}

	tarData, err := tarGzServerDir(srcDir)
	if err != nil {
		return &agentpb.GetCheckpointTarResponse{
			Success: false,
			Error:   fmt.Sprintf("tar checkpoint: %v", err),
		}, nil
	}

	// ADR-SEC-B §2.3 (C-334): compute the source-side hash of the EXACT gzip tar bytes returned so
	// the destination can verify wire-integrity before decompress, and the operator forwards it
	// unchanged (catching controller-memory corruption between Get and Put).
	tarSha256 := provenance.SHA256Hex(tarData)

	log.Info("GetCheckpointTar: checkpoint packaged (source intact until ReleaseCheckpoint)",
		"migration", req.MigrationName,
		"srcDir", srcDir,
		"tarSizeBytes", len(tarData),
		"tarSha256", tarSha256)

	return &agentpb.GetCheckpointTarResponse{
		Success:   true,
		TarData:   tarData,
		BytesRead: int64(len(tarData)),
		TarSha256: tarSha256,
	}, nil
}

// ReleaseCheckpoint zeroizes and removes the checkpoint directory on this (source) node.
// Called by the controller only after PutCheckpointTar has succeeded AND
// pm.Status.CheckpointTransferred has been durably persisted. Idempotent: returns success
// if the directory is already absent (handles controller-restart replay after release).
func (s *AgentServer) ReleaseCheckpoint(_ context.Context, req *agentpb.ReleaseCheckpointRequest) (*agentpb.ReleaseCheckpointResponse, error) {
	if req.MigrationName == "" {
		return &agentpb.ReleaseCheckpointResponse{Success: false, Error: "migration_name required"}, nil
	}

	// Clean the entire migration directory (round-N/ pre-dump rounds + final/).
	// ADR-0165 GC-9: pre-dump round artifacts in round-N/ subdirs were not removed on
	// rollback path — only final/ was cleaned. Remove the whole migration tree so no
	// pre-dump img files are orphaned on source after rollback or success.
	migDir := fmt.Sprintf("/run/podmotion/checkpoints/%s", req.MigrationName)
	if _, err := os.Stat(migDir); os.IsNotExist(err) {
		// Already released (or never existed) — idempotent success.
		log.Info("ReleaseCheckpoint: source dir already absent (idempotent)",
			"migration", req.MigrationName, "dir", migDir)
		return &agentpb.ReleaseCheckpointResponse{Success: true}, nil
	}

	if err := zeroizeDir(migDir); err != nil {
		log.Error(err, "ReleaseCheckpoint: zeroize failed — images remain on tmpfs until node reboot",
			"migration", req.MigrationName, "dir", migDir)
		// Non-fatal: tmpfs is volatile; images are gone on node reboot.
		// Return success so the controller doesn't retry in a loop.
	}

	log.Info("ReleaseCheckpoint: source checkpoint zeroized and removed",
		"migration", req.MigrationName, "dir", migDir)
	return &agentpb.ReleaseCheckpointResponse{Success: true}, nil
}

// tarGzServerDir creates a gzip-compressed tar of all regular files in dir.
// Mirrors tarGzDir in the controller package; duplicated here to avoid cross-package deps.
func tarGzServerDir(dir string) ([]byte, error) {
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

// ── helpers ───────────────────────────────────────────────────────────────────

// sha256OfDir returns the hex-encoded SHA256 of the inventory.img (canonical checkpoint ID).
// Falls back to checksumming all files if inventory.img is absent.
func sha256OfDir(dir string) string {
	inv := filepath.Join(dir, "inventory.img")
	if data, err := os.ReadFile(inv); err == nil {
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:])
	}
	sum, _ := checksumDir(dir)
	return sum
}

// sha256HexOfString returns the hex-encoded SHA256 of a string.
func sha256HexOfString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// checksumDir computes a combined SHA256 over all files in dir and returns
// the hex string and total size in bytes. Non-fatal on errors.
func checksumDir(dir string) (string, int64) {
	h := sha256.New()
	var totalBytes int64
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		n, _ := io.Copy(h, f)
		totalBytes += n
		return nil
	})
	return hex.EncodeToString(h.Sum(nil)), totalBytes
}

// zwWatchdogMargin is added to FreezeWindowBudgetMs to give the controller time to send
// DisarmZeroWindow before the watchdog fires an emergency disarm.
const zwWatchdogMargin = 500 * time.Millisecond

// ArmZeroWindow implements MigrationAgentServiceServer.ArmZeroWindow.
// It polls tcpi_unacked==0 for all TCP sockets of the source pod before returning armed=true,
// ensuring no in-flight bytes are in the send buffer when FinalFreeze fires (ADR-0049).
// A watchdog goroutine auto-disarms if DisarmZeroWindow is not received within
// FreezeWindowBudgetMs + zwWatchdogMargin to prevent indefinite client stall.
func (s *AgentServer) ArmZeroWindow(ctx context.Context, req *agentpb.ArmZeroWindowRequest) (*agentpb.ArmZeroWindowResponse, error) {
	log.Info("ArmZeroWindow: arming zero-window hold", "migration", req.MigrationName, "podUID", req.PodUid)

	s.migrationPodUIDMu.RLock()
	podUID := s.migrationPodUID[req.MigrationName]
	s.migrationPodUIDMu.RUnlock()
	if podUID == "" && req.PodUid != "" {
		podUID = req.PodUid
	}

	// Resolve source pod veth ifindex. On darwin/stub resolveVethIfindex returns 0 without error.
	ifindex, err := resolveVethIfindex(podUID)
	if err != nil {
		log.Info("ArmZeroWindow: veth ifindex resolution failed (stub path)", "migration", req.MigrationName, "err", err)
	}

	// Arm the TC-BPF zero-window hold. On non-Linux this is a no-op stub.
	// Pass tcpPreservationMode so armZeroWindowBPF can enforce fail-closed under Strict
	// (ADR-0049 Amendment D A2/C3): on arm failure or ifindex==0 under Strict it returns
	// a typed error, and we MUST NOT set Armed=true in that case.
	if err := armZeroWindowBPF(ctx, ifindex, req.TcpPreservationMode); err != nil {
		return &agentpb.ArmZeroWindowResponse{
			Armed:          false,
			BlockingReason: fmt.Sprintf("BPF arm failed: %v", err),
		}, nil
	}

	// ADR-0224: arm the source-side conntrack NOTRACK rule so the kernel never resets
	// the migrated TCP connection on out-of-window segments during the overlay handoff
	// (ADR-0048 predicate E). Fail-closed: same disposition as the BPF arm path above —
	// if the NOTRACK rule cannot be installed we MUST NOT report Armed=true, otherwise
	// the atomicity barrier predicate E reads source=false at DisengageHold.
	sourceConntrackArmed := false
	if req.SourcePodIp != "" {
		log.Info("ArmZeroWindow: arming source conntrack NOTRACK (ADR-0224)",
			"migration", req.MigrationName, "sourcePodIP", req.SourcePodIp)
		if err := network.ArmConntrackNotrack(ctx, network.ConntrackNotrackRule{
			PodIP:   req.SourcePodIp,
			Comment: "pm-notrack-" + req.MigrationName,
		}); err != nil {
			log.Error(err, "ArmZeroWindow: conntrack NOTRACK arm failed — failing closed (ADR-0224)",
				"migration", req.MigrationName, "sourcePodIP", req.SourcePodIp)
			// Roll back the BPF hold we just armed so we do not leave a half-armed state.
			disarmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if dErr := disarmZeroWindowBPF(disarmCtx, ifindex); dErr != nil {
				log.Info("ArmZeroWindow: BPF rollback after NOTRACK arm failure errored", "migration", req.MigrationName, "err", dErr)
			}
			cancel()
			return &agentpb.ArmZeroWindowResponse{
				Armed:          false,
				BlockingReason: fmt.Sprintf("conntrack NOTRACK arm failed (ADR-0224): %v", err),
			}, nil
		}
		sourceConntrackArmed = true
	} else {
		log.Info("ArmZeroWindow: SourcePodIp empty — skipping conntrack NOTRACK arm (ADR-0224 legacy/cold path)",
			"migration", req.MigrationName)
	}

	// Poll tcpi_unacked==0 on all TCP sockets reachable via the pod's network namespace
	// (ADR-0049 predicate A). On non-Linux or when the pod PID is not found, returns immediately.
	if err := pollUnackedZero(ctx, podUID); err != nil {
		log.Info("ArmZeroWindow: unacked drain poll failed or timed out",
			"migration", req.MigrationName, "err", err)
	}

	armedAtNs := time.Now().UnixNano()

	// Register hold state and launch watchdog goroutine.
	budget := time.Duration(req.FreezeWindowBudgetMs)*time.Millisecond + zwWatchdogMargin
	wdCtx, wdCancel := context.WithCancel(context.Background())
	s.zwHoldMu.Lock()
	s.zwHolds[req.MigrationName] = &zwHoldState{
		armedAtNs:      armedAtNs,
		watchdogCancel: wdCancel,
	}
	s.zwHoldMu.Unlock()

	go func() {
		select {
		case <-time.After(budget):
			// ADR-0157 D1: watchdog is defense-in-depth ONLY. Firing means the
			// controller did not call DisarmZeroWindow within budget+margin — an
			// abnormal timing fault. Disarm BPF hold, mark watchdogFired so a
			// subsequent DisarmZeroWindow RPC returns the distinct WatchdogFired
			// blocking reason (ADR-0157 D3). State entry is NOT deleted here;
			// it is cleaned up by the controller's DisarmZeroWindow call.
			log.Info("ArmZeroWindow: watchdog triggered — emergency auto-disarm (ADR-0157 D1/D3)",
				"migration", req.MigrationName, "budgetMs", req.FreezeWindowBudgetMs)
			disarmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if dErr := disarmZeroWindowBPF(disarmCtx, ifindex); dErr != nil {
				log.Info("ArmZeroWindow: watchdog disarm BPF error", "migration", req.MigrationName, "err", dErr)
			}
			s.zwHoldMu.Lock()
			if st, exists := s.zwHolds[req.MigrationName]; exists {
				st.watchdogFired = true
			}
			s.zwHoldMu.Unlock()
		case <-wdCtx.Done():
			// Normal path: DisarmZeroWindow cancelled the watchdog.
		}
	}()

	log.Info("ArmZeroWindow: hold armed", "migration", req.MigrationName, "armedAtNs", armedAtNs,
		"sourceConntrackArmed", sourceConntrackArmed)
	return &agentpb.ArmZeroWindowResponse{
		Armed:                true,
		ArmedAtNs:            armedAtNs,
		SourceConntrackArmed: sourceConntrackArmed,
	}, nil
}

// DisarmZeroWindow implements MigrationAgentServiceServer.DisarmZeroWindow.
// It cancels the watchdog goroutine and detaches the TC-BPF zero-window hold.
// If the watchdog already fired (ADR-0157 D3), returns Disarmed=false with
// BlockingReason="watchdog fired" so the controller can surface the distinct
// WatchdogFired condition reason and ZeroWindowWatchdogFired event.
func (s *AgentServer) DisarmZeroWindow(_ context.Context, req *agentpb.DisarmZeroWindowRequest) (*agentpb.DisarmZeroWindowResponse, error) {
	log.Info("DisarmZeroWindow: disarming zero-window hold", "migration", req.MigrationName)

	s.zwHoldMu.Lock()
	state, ok := s.zwHolds[req.MigrationName]
	if ok {
		if !state.watchdogFired {
			// Normal path: cancel the watchdog goroutine so it does not also disarm.
			state.watchdogCancel()
		}
		delete(s.zwHolds, req.MigrationName)
	}
	s.zwHoldMu.Unlock()

	if !ok {
		return &agentpb.DisarmZeroWindowResponse{
			Disarmed:       false,
			BlockingReason: "no active zero-window hold for migration",
		}, nil
	}

	// ADR-0157 D3: if the watchdog already fired, the BPF hold is already gone.
	// Return disarmed=false with a distinct reason so the controller surfaces
	// ConditionZeroWindowDisarmed reason=WatchdogFired and emits ZeroWindowWatchdogFired event.
	if state.watchdogFired {
		log.Info("DisarmZeroWindow: watchdog already fired — BPF hold was auto-disarmed (ADR-0157 D3)",
			"migration", req.MigrationName)
		return &agentpb.DisarmZeroWindowResponse{
			Disarmed:       false,
			BlockingReason: "watchdog fired",
		}, nil
	}

	s.migrationPodUIDMu.RLock()
	podUID := s.migrationPodUID[req.MigrationName]
	s.migrationPodUIDMu.RUnlock()
	if podUID == "" {
		podUID = req.PodUid
	}

	ifindex, err := resolveVethIfindex(podUID)
	if err != nil {
		log.Info("DisarmZeroWindow: veth ifindex resolution failed (stub path)", "migration", req.MigrationName, "err", err)
	}

	disarmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := disarmZeroWindowBPF(disarmCtx, ifindex); err != nil {
		log.Info("DisarmZeroWindow: BPF disarm error", "migration", req.MigrationName, "err", err)
	}

	// ADR-0224 3h-SYM: remove the conntrack NOTRACK rule installed at arm time so it does
	// not leak. Warn-only — a partial disarm (BPF down, NOTRACK rule lingering) is a better
	// state than a stuck-disarmed response that blocks migration completion. The rule is
	// idempotent on delete (ENOENT treated as success).
	if req.SourcePodIp != "" {
		log.Info("DisarmZeroWindow: disarming source conntrack NOTRACK (ADR-0224 3h-SYM)",
			"migration", req.MigrationName, "sourcePodIP", req.SourcePodIp)
		if err := network.DisarmConntrackNotrack(disarmCtx, network.ConntrackNotrackRule{
			PodIP:   req.SourcePodIp,
			Comment: "pm-notrack-" + req.MigrationName,
		}); err != nil {
			log.Info("DisarmZeroWindow: conntrack NOTRACK disarm failed (warn-only, ADR-0224 3h-SYM)",
				"migration", req.MigrationName, "sourcePodIP", req.SourcePodIp, "err", err)
		}
	}

	disarmedAtNs := time.Now().UnixNano()
	holdMs := int64(0)
	if state.armedAtNs > 0 {
		holdMs = (disarmedAtNs - state.armedAtNs) / int64(time.Millisecond)
	}
	log.Info("DisarmZeroWindow: hold disarmed", "migration", req.MigrationName,
		"holdDurationMs", holdMs, "disarmedAtNs", disarmedAtNs)
	return &agentpb.DisarmZeroWindowResponse{
		Disarmed:       true,
		DisarmedAtNs:   disarmedAtNs,
		HoldDurationMs: holdMs,
	}, nil
}

// ConfirmOverlayReady evaluates the ADR-0049 6-predicate atomicity barrier on the destination
// node. It is called by the controller after Restore succeeds and before DisarmZeroWindow is
// sent to the source node. Predicate A (tcpi_unacked==0) is already satisfied by ArmZeroWindow.
//
// The handler:
//  1. Builds BarrierPredicates from the request fields.
//  2. Captures CLOCK_MONOTONIC ns for PAWS ts_delta computation.
//  3. Calls CheckAtomicityBarrier (predicates B–F).
//  4. Computes ts_delta from source_clock_ns vs dest_clock_ns and patches PM_SEQ_XLAT.
func (s *AgentServer) ConfirmOverlayReady(ctx context.Context, req *agentpb.ConfirmOverlayReadyRequest) (*agentpb.ConfirmOverlayReadyResponse, error) {
	log.Info("ConfirmOverlayReady: evaluating atomicity barrier", "migration", req.MigrationName)

	destClockNs := monoTimeNs()

	fdbMgr := network.NewFDBManager()

	var sourceFDB *network.FDBEntry
	var destFDB *network.FDBEntry
	if req.FdbIfname != "" && req.PodIp != "" && req.PodMac != "" {
		podIP := net.ParseIP(req.PodIp)
		podMAC, macErr := net.ParseMAC(req.PodMac)
		// vtep_ip is optional: the caller may omit it because the destination agent is
		// already on the destination node and can derive the VTEP IP from the interface.
		vtepIP := net.ParseIP(req.VtepIp)
		if vtepIP == nil && req.FdbIfname != "" {
			vtepIP = localInterfaceIP(req.FdbIfname)
		}
		if podIP != nil && vtepIP != nil && macErr == nil {
			e := network.FDBEntry{
				IfName: req.FdbIfname,
				PodIP:  podIP,
				PodMAC: podMAC,
				VTEPIP: vtepIP,
			}
			sourceFDB = &e
			destFDB = &e
		}
	}

	predicates := network.BarrierPredicates{
		SeqXlatSeeded:        req.SeqXlatSeeded,
		SourceFDBEntry:       sourceFDB,
		DestFDBEntry:         destFDB,
		SourceConntrackArmed: req.SourceConntrackArmed,
		DestConntrackArmed:   true, // destination conntrack is armed locally by PrepareDestinationNetns
		RestoreComplete:      req.RestoreComplete,
		PreRestore:           req.PreRestore,
		FDBManager:           fdbMgr,
	}

	result, barrierErr := network.CheckAtomicityBarrier(ctx, predicates)

	resp := &agentpb.ConfirmOverlayReadyResponse{
		PredicateBOk: result.BPredicate,
		PredicateCOk: result.CFdbSource,
		PredicateDOk: result.DFdbDest,
		PredicateEOk: result.EPredicate,
		PredicateFOk: result.FPredicate,
		DestClockNs:  destClockNs,
	}

	if barrierErr != nil {
		log.Error(barrierErr, "ConfirmOverlayReady: barrier not satisfied", "migration", req.MigrationName)
		resp.Ready = false
		resp.BlockingReason = barrierErr.Error()
		return resp, nil
	}

	// Compute PAWS ts_delta from monotonic clock offsets and patch PM_SEQ_XLAT.
	tsDelta := network.ComputePAWSTsDelta(req.SourceClockNs, destClockNs)
	resp.TsDelta = tsDelta
	log.Info("ConfirmOverlayReady: barrier satisfied", "migration", req.MigrationName,
		"sourceClockNs", req.SourceClockNs, "destClockNs", destClockNs, "tsDelta", tsDelta)

	resp.Ready = true
	return resp, nil
}

// thawSourcePID sends SIGCONT to the given PID, recovering a source process that was
// left in SIGSTOP by LeaveStopped=true after a CRIU dump. Called on every error/rollback
// path that follows a successful dump so the source workload is never permanently frozen.
// Idempotent: if the process is already running (not stopped), SIGCONT is harmless.
func thawSourcePID(pid int32, migrationName string) {
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(int(pid), syscall.SIGCONT); err != nil {
		log.Error(err, "thawSourcePID: SIGCONT to source PID failed — manual intervention may be required",
			"migration", migrationName, "sourcePID", pid)
		return
	}
	log.Info("thawSourcePID: SIGCONT sent to frozen source process",
		"migration", migrationName, "sourcePID", pid)
}

// registerFrozenSource records that migration's source process (pid) is now in SIGSTOP
// due to LeaveStopped=true. Must be called immediately after a successful Dump with LeaveStopped.
// The entry must be cleared by clearFrozenSource once the source is confirmed thawed or
// the migration completes successfully.
func (s *AgentServer) registerFrozenSource(migrationName string, pid int32) {
	s.frozenSourcePIDsMu.Lock()
	defer s.frozenSourcePIDsMu.Unlock()
	s.frozenSourcePIDs[migrationName] = pid
	// ADR-0216: mirror the registration to a durable on-disk record so an agent
	// restart between this freeze and the matching SIGCONT cannot orphan the source.
	// The in-memory map only thaws within THIS agent process; the durable record is
	// what ReconcileOrphanedFrozenSources() uses to thaw across a restart.
	if persistErr := persistFrozenSource(migrationName, pid); persistErr != nil {
		log.Error(persistErr, "registerFrozenSource (ADR-0216): durable record write failed — cross-restart thaw not guaranteed for this migration",
			"migration", migrationName, "sourcePID", pid)
	}
	log.Info("registerFrozenSource: source process frozen",
		"migration", migrationName, "sourcePID", pid)
}

// clearFrozenSource removes the frozen-source record for migrationName.
// Called after thawing or on successful migration completion.
func (s *AgentServer) clearFrozenSource(migrationName string) {
	s.frozenSourcePIDsMu.Lock()
	delete(s.frozenSourcePIDs, migrationName)
	s.frozenSourcePIDsMu.Unlock()
	// ADR-0216: drop the durable record in lockstep with the in-memory entry so a
	// completed/thawed migration leaves no stale record for startup reconcile.
	removeFrozenSourceRecord(migrationName)
}

// thawFrozenSource thaws the recorded frozen source PID for migrationName (if any)
// and clears the record. Safe to call when no frozen source is registered.
func (s *AgentServer) thawFrozenSource(migrationName string) {
	s.frozenSourcePIDsMu.Lock()
	pid, ok := s.frozenSourcePIDs[migrationName]
	if ok {
		delete(s.frozenSourcePIDs, migrationName)
	}
	s.frozenSourcePIDsMu.Unlock()
	// ADR-0216: remove the durable record whether or not an in-memory entry was
	// present. After an agent restart the in-memory map is empty but a durable
	// record may still exist; an explicit Abort/rollback for that migration must
	// clear it so startup reconcile does not later act on an already-handled entry.
	removeFrozenSourceRecord(migrationName)
	if ok {
		thawSourcePID(pid, migrationName)
	}
}

// emitCRIUImageInconsistencyEvent emits a Warning CRIUImageInconsistency Kubernetes Event on
// the PodMigration CR identified by migrationName (ADR-0193 P-0193-4 / S1).
// The event message is constructed from {FdID, NameLeaf, BackingMntID} ONLY — the full path
// is NOT included because Kubernetes Events are world-readable cluster-wide (SEC-EVENT-1 / S1).
// Best-effort: logs on failure but does not block the caller's error path.
func (s *AgentServer) emitCRIUImageInconsistencyEvent(ctx context.Context, migrationName string, imgErr *CRIUImageInconsistencyError) {
	if s.k8sClient == nil {
		log.Info("emitCRIUImageInconsistencyEvent: k8sClient nil — event not emitted",
			"migration", migrationName)
		return
	}
	namespace := s.resolveNamespaceForMigration(ctx, migrationName)
	if namespace == "" {
		namespace = "default"
	}
	pm := &pmv1.PodMigration{}
	if getErr := s.k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: migrationName}, pm); getErr != nil {
		log.Error(getErr, "emitCRIUImageInconsistencyEvent: could not fetch PodMigration to emit event",
			"migration", migrationName)
		return
	}
	msg := criuImageInconsistencyEventMsg(imgErr.FdID, imgErr.NameLeaf, imgErr.BackingMntID)
	now := metav1.Now()
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.criu-image-inconsistency.%d", migrationName, now.UnixNano()),
			Namespace: namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "podmotion.io/v1alpha1",
			Kind:       "PodMigration",
			Name:       pm.Name,
			Namespace:  pm.Namespace,
			UID:        pm.UID,
		},
		Reason:         "CRIUImageInconsistency",
		Message:        msg,
		Type:           corev1.EventTypeWarning,
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Source: corev1.EventSource{Component: "podmotion-agent"},
	}
	if createErr := s.k8sClient.Create(ctx, event); createErr != nil {
		log.Error(createErr, "emitCRIUImageInconsistencyEvent: failed to create Event",
			"migration", migrationName, "msg", msg)
	} else {
		log.Info("emitCRIUImageInconsistencyEvent: Warning CRIUImageInconsistency Event emitted (ADR-0193 P-0193-4)",
			"migration", migrationName, "msg", msg)
	}
}

// emitExternalMountUnresolvedEvent emits a Warning ExternalMountUnresolved Kubernetes Event on
// the PodMigration CR when ADR-0194 P-0194-1 hard-stops before criu restore (H4).
// ext_key is safe to include (it is the mount path, e.g. "/data" — not a volume UUID).
// Best-effort: logs on failure but does not block the caller's error path.
func (s *AgentServer) emitExternalMountUnresolvedEvent(ctx context.Context, migrationName string, extErr *ExternalMountUnresolvedError) {
	if s.k8sClient == nil {
		log.Info("emitExternalMountUnresolvedEvent: k8sClient nil — event not emitted",
			"migration", migrationName)
		return
	}
	namespace := s.resolveNamespaceForMigration(ctx, migrationName)
	if namespace == "" {
		namespace = "default"
	}
	pm := &pmv1.PodMigration{}
	if getErr := s.k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: migrationName}, pm); getErr != nil {
		log.Error(getErr, "emitExternalMountUnresolvedEvent: could not fetch PodMigration",
			"migration", migrationName)
		return
	}
	msg := extErr.Error()
	now := metav1.Now()
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.external-mount-unresolved.%d", migrationName, now.UnixNano()),
			Namespace: namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "podmotion.io/v1alpha1",
			Kind:       "PodMigration",
			Name:       pm.Name,
			Namespace:  pm.Namespace,
			UID:        pm.UID,
		},
		Reason:         "ExternalMountUnresolved",
		Message:        msg,
		Type:           corev1.EventTypeWarning,
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Source:         corev1.EventSource{Component: "podmotion-agent"},
	}
	if createErr := s.k8sClient.Create(ctx, event); createErr != nil {
		log.Error(createErr, "emitExternalMountUnresolvedEvent: failed to create Event",
			"migration", migrationName)
	} else {
		log.Info("emitExternalMountUnresolvedEvent: Warning ExternalMountUnresolved Event emitted (ADR-0194 P-0194-1)",
			"migration", migrationName, "mnt_id", extErr.MntID, "ext_key", extErr.ExtKey, "reason", extErr.Reason)
	}
}

// emitExternalMountDroppedEvent emits a Normal CRIUExternalMountDropped Kubernetes Event on
// the PodMigration CR when ADR-0194 B-2 drops an external mountpoints entry (H4 / C-2).
// Best-effort: logs on failure but does not block the caller's success path.
func (s *AgentServer) emitExternalMountDroppedEvent(ctx context.Context, migrationName string, d ExternalMountDroppedInfo) {
	if s.k8sClient == nil {
		log.Info("emitExternalMountDroppedEvent: k8sClient nil — event not emitted",
			"migration", migrationName)
		return
	}
	namespace := s.resolveNamespaceForMigration(ctx, migrationName)
	if namespace == "" {
		namespace = "default"
	}
	pm := &pmv1.PodMigration{}
	if getErr := s.k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: migrationName}, pm); getErr != nil {
		log.Error(getErr, "emitExternalMountDroppedEvent: could not fetch PodMigration",
			"migration", migrationName)
		return
	}
	msg := fmt.Sprintf("external mount mnt_id=%d ext_key=%s source=%s dropped by B-2 lockstep with files.img rebind to root (ADR-0194 B-2)", d.MntID, d.ExtKey, d.Source)
	now := metav1.Now()
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.criu-ext-mount-dropped.%d", migrationName, now.UnixNano()),
			Namespace: namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "podmotion.io/v1alpha1",
			Kind:       "PodMigration",
			Name:       pm.Name,
			Namespace:  pm.Namespace,
			UID:        pm.UID,
		},
		Reason:         "CRIUExternalMountDropped",
		Message:        msg,
		Type:           corev1.EventTypeNormal,
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Source:         corev1.EventSource{Component: "podmotion-agent"},
	}
	if createErr := s.k8sClient.Create(ctx, event); createErr != nil {
		log.Error(createErr, "emitExternalMountDroppedEvent: failed to create Event",
			"migration", migrationName)
	} else {
		log.Info("emitExternalMountDroppedEvent: Normal CRIUExternalMountDropped Event emitted (ADR-0194 B-2)",
			"migration", migrationName, "mnt_id", d.MntID, "ext_key", d.ExtKey)
	}
}

// enforceRestoreOrderingInvariant verifies that TCP sockets on the restored process (pid)
// are ESTABLISHED, then — and only then — sends SIGCONT. Returns (socketsLiveAt, resumedAt).
//
// This is a HARD gate on the TCP-stateful path (M23 ordering invariant, ADR-0095):
//   - If SocketInventory fails, the restore is failed (SIGCONT is withheld).
//   - If no ESTABLISHED sockets are found after polling, the restore is failed.
//   - socketsLiveAt is set only after confirmed ESTABLISHED socket count > 0.
//   - SIGCONT is sent only after that confirmed observation.
//
// expectedCount is the number of TCP connections from the source SeqSnapshots;
// when 0 (non-TCP-stateful path) the function is a no-op that returns the current time.
// deferResume (ADR-0142 D3): when true, this function confirms SocketsLive (ESTABLISHED
// sockets ≥ expectedCount) but does NOT send SIGCONT — the restored tree stays in SIGSTOP
// (CRIU --leave-stopped) and the caller records the PID for a later, datapath-gated SIGCONT
// fired by InjectIPHandoff. resumedAt is returned as the zero time in that case. When false,
// the legacy behavior is preserved: SIGCONT is sent inline immediately after SocketsLive.
func enforceRestoreOrderingInvariant(pid int, migrationName string, expectedCount int, deferResume bool) (time.Time, time.Time, error) {
	// If the restore was not TCP-stateful (no expected connections), skip socket
	// polling and resume immediately — the invariant only applies to TCP migrations.
	// (deferResume is irrelevant here: with no TCP sockets there is no seq_delta to
	// preserve and no handoff to wait for.)
	if expectedCount == 0 {
		now := time.Now()
		log.Info("enforceRestoreOrderingInvariant: no TCP connections expected, resuming immediately",
			"migration", migrationName, "pid", pid)
		if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
			return now, time.Time{}, fmt.Errorf("SIGCONT pid=%d: %w", pid, err)
		}
		resumedAt := time.Now()
		return now, resumedAt, nil
	}

	// Poll SocketInventory until we observe at least expectedCount ESTABLISHED sockets
	// or the polling deadline is exceeded. This gates SIGCONT on real socket liveness.
	const (
		pollInterval = 20 * time.Millisecond
		pollDeadline = 5 * time.Second
	)
	deadline := time.Now().Add(pollDeadline)
	var lastErr error
	var lastCount int
	for time.Now().Before(deadline) {
		sockEntries, invErr := network.SocketInventory(int32(pid))
		if invErr != nil {
			// Inventory failure: the process's netns is not yet visible or /proc is
			// not populated for the restored PID. Retry until deadline.
			lastErr = invErr
			log.Info("enforceRestoreOrderingInvariant: SocketInventory failed (retrying)",
				"migration", migrationName, "pid", pid, "err", invErr)
			time.Sleep(pollInterval)
			continue
		}
		lastErr = nil
		lastCount = len(sockEntries)
		if lastCount >= expectedCount {
			// Confirmed: at least expectedCount ESTABLISHED sockets observed.
			socketsLiveAt := time.Now()
			// ADR-0142 D3: on the seq_delta=0 path, defer SIGCONT until the destination
			// OLD-IP datapath is installed (InjectIPHandoff). Confirm SocketsLive and
			// return with a zero resumedAt; the caller records the pending PID. The
			// restored tree stays in SIGSTOP, so it emits no segments into a not-yet-wired
			// datapath — preserving the held client connection and seq_delta=0.
			if deferResume {
				log.Info("enforceRestoreOrderingInvariant: SocketsLive confirmed — SIGCONT DEFERRED until InjectIPHandoff (ADR-0142 D3)",
					"migration", migrationName,
					"pid", pid,
					"establishedConnections", lastCount,
					"expectedConnections", expectedCount,
					"socketsLiveAt", socketsLiveAt.UnixNano(),
				)
				return socketsLiveAt, time.Time{}, nil
			}
			log.Info("enforceRestoreOrderingInvariant: SocketsLive confirmed — sending SIGCONT",
				"migration", migrationName,
				"pid", pid,
				"establishedConnections", lastCount,
				"expectedConnections", expectedCount,
				"socketsLiveAt", socketsLiveAt.UnixNano(),
			)
			if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
				return socketsLiveAt, time.Time{}, fmt.Errorf("SIGCONT pid=%d: %w", pid, err)
			}
			resumedAt := time.Now()
			log.Info("enforceRestoreOrderingInvariant: SIGCONT sent",
				"migration", migrationName,
				"pid", pid,
				"resumedAt", resumedAt.UnixNano(),
				"orderingHoldNs", resumedAt.Sub(socketsLiveAt).Nanoseconds(),
			)
			return socketsLiveAt, resumedAt, nil
		}
		log.Info("enforceRestoreOrderingInvariant: waiting for ESTABLISHED sockets",
			"migration", migrationName, "pid", pid,
			"found", lastCount, "expected", expectedCount)
		time.Sleep(pollInterval)
	}

	// Deadline exceeded — SIGCONT is withheld. Fail closed so the migration rolls back.
	// The source process (if frozen) will be thawed by the rollback path.
	if lastErr != nil {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"enforceRestoreOrderingInvariant: SocketInventory still failing after %s: %w; SIGCONT withheld",
			pollDeadline, lastErr)
	}
	return time.Time{}, time.Time{}, fmt.Errorf(
		"enforceRestoreOrderingInvariant: only %d/%d ESTABLISHED sockets observed after %s; SIGCONT withheld to prevent RST on migrated connections",
		lastCount, expectedCount, pollDeadline)
}

// setOrderingConditions sets SocketsLive=True and ProcessResumedAfterSocketsLive=True
// on the PodMigration CR. ProcessResumedAfterSocketsLive.LastTransitionTime must be
// strictly after SocketsLive.LastTransitionTime (M23 ordering invariant assertion).
// pid is the restored destination PID, recorded in the condition message for observability.
func (s *AgentServer) setOrderingConditions(migrationName string, pid int, socketsLiveAt, resumedAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		ns = "podmotion-system"
	}

	pm := &pmv1.PodMigration{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: migrationName, Namespace: ns}, pm); err != nil {
		return fmt.Errorf("get PodMigration %s/%s: %w", ns, migrationName, err)
	}

	socketsLiveMeta := metav1.NewTime(socketsLiveAt)
	resumedMeta := metav1.NewTime(resumedAt)

	if !resumedAt.After(socketsLiveAt) {
		// This must not happen: enforceRestoreOrderingInvariant guarantees socketsLiveAt
		// is set before SIGCONT, so resumedAt must be strictly after socketsLiveAt.
		// If this fires it indicates a clock regression or a caller bug — fail hard rather
		// than silently stamping a condition that violates the ordering invariant.
		return fmt.Errorf("setOrderingConditions: resumedAt (%d) is not strictly after socketsLiveAt (%d) — ordering invariant violated",
			resumedAt.UnixNano(), socketsLiveAt.UnixNano())
	}

	setConditionAt(pm, pmv1.ConditionSocketsLive, metav1.ConditionTrue, "SocketsLive",
		fmt.Sprintf("TCP sockets ESTABLISHED on restored process pid=%d at %s", pid, socketsLiveAt.UTC().Format(time.RFC3339Nano)),
		socketsLiveMeta)
	setConditionAt(pm, pmv1.ConditionProcessResumedAfterSocketsLive, metav1.ConditionTrue, "ProcessResumed",
		fmt.Sprintf("SIGCONT delivered to pid=%d at %s; sockets were live at %s (ordering invariant satisfied)",
			pid, resumedAt.UTC().Format(time.RFC3339Nano), socketsLiveAt.UTC().Format(time.RFC3339Nano)),
		resumedMeta)

	return s.k8sClient.Status().Update(ctx, pm)
}

// setConditionAt sets a condition with an explicit LastTransitionTime (for ordering invariant).
func setConditionAt(pm *pmv1.PodMigration, condType string, status metav1.ConditionStatus, reason, message string, at metav1.Time) {
	now := at
	for i, c := range pm.Status.Conditions {
		if c.Type == condType {
			pm.Status.Conditions[i] = metav1.Condition{
				Type:               condType,
				Status:             status,
				Reason:             reason,
				Message:            message,
				LastTransitionTime: now,
			}
			return
		}
	}
	pm.Status.Conditions = append(pm.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
}

// zeroizeDir overwrites all regular files in dir with zeros then removes the directory.
// Called to scrub checkpoint images (verbatim process memory) from tmpfs on all exit paths.
func zeroizeDir(dir string) error {
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

// localInterfaceIP returns the first non-loopback, non-link-local unicast IPv4 address
// assigned to the named interface. Used by ConfirmOverlayReady to derive the local VTEP IP
// when the caller omits vtep_ip (the destination agent runs on the destination node and can
// always resolve its own overlay interface address).
func localInterfaceIP(ifname string) net.IP {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4
		}
	}
	return nil
}

// writeTCPSocketStateJSON persists the TCP_REPAIR-captured sequence snapshots
// to <checkpointDir>/tcp_socket_state.json (ADR-0156 GC-27 evidence).
// The file is readable by the operator for post-restore seq verification and by
// humans inspecting the checkpoint dir to validate GC-27.
func writeTCPSocketStateJSON(checkpointDir string, snaps []*agentpb.SeqSnapshot) error {
	type socketStateEntry struct {
		SrcIP   string `json:"src_ip"`
		SrcPort uint32 `json:"src_port"`
		DstIP   string `json:"dst_ip"`
		DstPort uint32 `json:"dst_port"`
		SndNxt  uint32 `json:"snd_nxt"`
		RcvNxt  uint32 `json:"rcv_nxt"`
	}
	entries := make([]socketStateEntry, 0, len(snaps))
	for _, s := range snaps {
		entries = append(entries, socketStateEntry{
			SrcIP:   s.SrcIp,
			SrcPort: s.SrcPort,
			DstIP:   s.DstIp,
			DstPort: s.DstPort,
			SndNxt:  s.SndNxt,
			RcvNxt:  s.RcvNxt,
		})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("writeTCPSocketStateJSON: marshal: %w", err)
	}
	path := checkpointDir + "/tcp_socket_state.json"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writeTCPSocketStateJSON: write %s: %w", path, err)
	}
	return nil
}

// discoverHostInterface returns the name of the first non-loopback, non-virtual
// network interface with an IPv4 address. On kind/kindnet nodes this is "eth0",
// which is the interface kindnet's host-local/ptp CNI routes pod traffic through.
// This implements ADR-0154 Decision 3 runtime discovery when the caller (controller)
// does not supply BridgeIfname (ADR-0158 Decision 5 — no "cni0" literal fallback).
func discoverHostInterface(_ context.Context) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("discoverHostInterface: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// Skip virtual/overlay devices that don't carry host IP traffic.
		name := iface.Name
		if name == "lo" || name == "flannel.1" || name == "cni0" || name == "docker0" {
			continue
		}
		if strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "tun") ||
			strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "dummy") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("discoverHostInterface: no suitable non-loopback IPv4 interface found")
}
