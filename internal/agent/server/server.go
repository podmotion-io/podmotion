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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
//
//	grep -a -c 'P-0195-1' bin/agent-linux-amd64  # must be >= 1
//
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

// ErrCtrMaskedMount is returned by ctrCheckpoint when the containerd-native checkpoint fails
// in CRIU's mountpoint-dump pass on a container-runtime masked/injected mount that runc's CRIU
// invocation cannot resolve to a proper root — e.g. the masked-path bind over /proc/interrupts:
//
//	Error (criu/mount.c:753): mnt: 625:./proc/interrupts doesn't have a proper root mount
//	Dumping FAILED.
//
// ctr tasks checkpoint drives runc's own CRIU argv and carries NONE of the agent's --skip-mnt /
// --external declarations, so these masked mounts abort the dump before the network pass. The
// caller should fall back to the raw go-criu Dump path, which DOES carry the dump-side skipMnts
// (criu_checkpointer.go) that skip this exact masked set — mirroring the ErrCtrInFlightTCP
// fall-through. This is a mount-class failure, not a TCP one, so it needs its own sentinel: the
// non-TCP branch would otherwise return it as fatal at the Checkpoint RPC and never reach the
// raw-CRIU path (the postgres live failure observed 2026-07-10).
var ErrCtrMaskedMount = errors.New("ctr checkpoint: masked mount has no proper root (fall back to raw CRIU)")

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
//
// ADR-0193 P-0193-1 grounding: BackingFstype and BackingMountpoint are the DECODED backing-mount
// fstype/mountpoint for BackingMntID, added so the orphan cause is diagnosable in one run (a
// tmpfs/shm segment that should have rebound vs a genuine persistent data mount that correctly
// DECLINEd). BackingFstype (a filesystem-type enum name, not a path) is safe in the world-readable
// Event; BackingMountpoint is a full path and stays OUT of the Event — it is logged only to the
// 0700-bounded agent log (SEC-EVENT-1 / P-0193-1b).
type CRIUImageInconsistencyError struct {
	FdID              int
	NameLeaf          string // filepath.Base(name) — e.g. "data" for "/data"
	BackingMntID      int
	BackingFstype     string // decoded fstype enum name of BackingMntID, or "None"; safe for Event
	BackingMountpoint string // full mountpoint path of BackingMntID; log-only, NEVER in the Event
}

func (e *CRIUImageInconsistencyError) Error() string {
	return criuImageInconsistencyEventMsg(e.FdID, e.NameLeaf, e.BackingMntID, e.BackingFstype)
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
func criuImageInconsistencyEventMsg(fdID int, nameLeaf string, backingMntID int, backingFstype string) string {
	// ADR-0193 P-0193-1 grounding: include the decoded backing_fstype (a filesystem-type
	// enum name — NOT a path, so SEC-EVENT-1-safe). It disambiguates a tmpfs/shm orphan
	// (should have rebound) from a genuine persistent data mount (correctly declined). The
	// full mountpoint path is deliberately omitted here (log-only). Empty fstype ("") means
	// the decode was unavailable (older marker / mount absent from mnt_fstypes).
	if backingFstype == "" {
		return fmt.Sprintf("files.img REG fd id=%d name_leaf=%s backing_mnt_id=%d: positive orphan mnt_id not in kept mountpoints — hard-stopped before criu restore (ADR-0193 P-0193-1)", fdID, nameLeaf, backingMntID)
	}
	return fmt.Sprintf("files.img REG fd id=%d name_leaf=%s backing_mnt_id=%d backing_fstype=%s: positive orphan mnt_id not in kept mountpoints — hard-stopped before criu restore (ADR-0193 P-0193-1)", fdID, nameLeaf, backingMntID, backingFstype)
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

	// podCIDRAllowlist is the ADR-0325 cached SSRF dial-allowlist, parsed once from
	// Node.Spec.PodCIDRs and refreshed on the NMC re-registration cadence. nil-safe: an
	// unpopulated/empty allowlist makes dialAllowed fail CLOSED (refuse), never open.
	podCIDRAllowlistMu sync.RWMutex
	podCIDRAllowlist   []*net.IPNet

	// ebpfMgr is the eBPF manager used for zero-window hold arm/disarm.
	// Initialised by New via network.NewEBPFManager; uses real cilium/ebpf
	// on kernel ≥5.9 and the no-op stub otherwise.
	ebpfMgr network.EBPFManager

	// livenessSustainPasses / livenessSustainInterval configure the ADR-0325 SUSTAINED
	// workload-liveness primitive (sprint46B9). runAppProbe requires this many CONSECUTIVE
	// application-probe passes, each separated by this interval, before it reports the
	// workload live — closing the "answered the handshake for one instant" gap that let a
	// crash-looping backend flip WorkloadLivenessVerified=True. Zero values fall back to
	// defaultLivenessSustainPasses / defaultLivenessSustainInterval (see resolveSustain).
	livenessSustainPasses   int
	livenessSustainInterval time.Duration

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
	s := &AgentServer{
		checkpointer:          cp,
		nodeName:              nodeName,
		k8sClient:             k8sClient,
		ebpfMgr:               network.NewEBPFManager(context.Background()),
		migrationPodUID:       make(map[string]string),
		migrationSeqSnapshots: make(map[string][]*agentpb.SeqSnapshot),
		zwHolds:               make(map[string]*zwHoldState),
		frozenSourcePIDs:      make(map[string]int32),
		pendingResumePIDs:     make(map[string]int),
		destHostVeth:          make(map[string]string),
		destWorkloadImage:     make(map[string]string),
		destMigrationNetns:    make(map[string]*network.MigrationNetns),
	}
	return s
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
// Signature: (ctx context.Context, migrationName, checkpointDir, imageName, containerID, destNetnsFd, sandboxID, storedHostVeth string, strictMode bool, reattachMountPaths []reattachMount, containerCgroupsPath, podCgroupParent, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error)
// ADR-0351 D1.2: containerCgroupsPath/podCgroupParent are two of the trailing params — the
// NRI-carried cgroup-anchor fields, threaded through as plain data from THREE call sites (the
// exported AgentServer.JoinNsRestore NRI wrapper, which has real values; both gRPC Restore
// branches, which pass "" — no NRI event on that path, see the anchor call site's comment for why
// that is a documented skip, not a silent gap).
// ADR-0355 D3: preservedSourceIP is the trailing param — pm.Spec.SourcePodIP, read by the caller
// (which holds s.k8sClient) and threaded down so the pre-CRIU bind-prep gate can make it locally
// bindable before soccr's bind() (see prepPreservedSourceAddrForRestore, D1/D3).
var joinNsRestoreFn = joinNsRestore

// ADR-0355 D1/D3 preserved-source-IP bind-prep primitives.
//
// errInvalidPreservedSourceIP is the sentinel returned (wrapped) when a NON-EMPTY preservedSourceIP
// is not a valid IPv4 at the D3 insertion point — the DR-15 fail-closed condition, kept
// errors.Is-testable (D5 test 1). The load-bearing assertion is the metric increment + the
// return-before-CRIU, not the error text.
var errInvalidPreservedSourceIP = errors.New("preserved source IP is not valid IPv4")

// brokerNetnsExecFn is the seam over netnsbroker.NewClient().NetnsExec used by
// addPreservedSourceAddr (D1) AND SingleHomeRestoredPod (D4) for all their netns-scoped `ip` ops.
// Overridden in the helper-shape test (D5 test 2) to capture (srcPID, netnsPath, argv) and assert
// the broker delegation — no in-process unix.Setns — and in the D4 scope-awareness test (D5 test 5b)
// to simulate the eth0 address list and capture the oldIP/24 scope-global add.
var brokerNetnsExecFn = func(ctx context.Context, srcPID int, netnsPath string, argv ...string) netnsbroker.ExecResult {
	return netnsbroker.NewClient().NetnsExec(ctx, srcPID, netnsPath, argv...)
}

// netnsBrokerClientFn is the seam over netnsbroker.NewClient() used by brokerCmd.result()
// (D2), brokerCriuCmd.Start()/poll()/Signal() (D2b), resolveReplVethPeer, ReadReplVethMAC, and
// joinNsRestore's loopback-up netns_exec (D2c) — every ADR-0354 broker-exec caller-deadline-
// binding shim on this file. Mirrors the existing readReplVethMACFn/joinNsRestoreFn/
// brokerNetnsExecFn indirection pattern. Production default is netnsbroker.NewClient (dials
// the real root-owned socket); ADR-0354 D6 regression tests override it to point at a fake,
// test-owned broker listener so brokerCmd/brokerCriuCmd/resolveReplVethPeer can be exercised
// against a controllable transport without requiring root or a live broker sidecar.
var netnsBrokerClientFn = netnsbroker.NewClient

// addPreservedSourceAddrFn is the seam over addPreservedSourceAddr used by the joinNsRestore
// bind-prep gate. Overridden in the joinNsRestore-level gating test (D5 test 1) to count calls and
// capture args. Same idiom as joinNsRestoreFn/readReplVethMACFn/resolveNetnsFromSandboxFn.
var addPreservedSourceAddrFn = addPreservedSourceAddr

// singleHomeRestoredPodFn is the seam over (*AgentServer).SingleHomeRestoredPod so finalizeRestore's
// D4 liveness + fail-closed behavior is unit-testable through the real finalizeRestore entry
// (D5 test 5 — a direct SingleHomeRestoredPod call is explicitly NOT accepted as the liveness proof,
// ADR-0355 DR-7). Production value delegates straight to the method.
var singleHomeRestoredPodFn = func(s *AgentServer, ctx context.Context, migrationName, namespace string, pid int) error {
	return s.SingleHomeRestoredPod(ctx, migrationName, namespace, pid)
}

// procNetnsPID parses "/proc/<N>/ns/net" → (N, true); anything else → (0, false). Used by
// addPreservedSourceAddr to map joinNsRestore's petnsPath onto the broker's two-form target
// contract: the broker's validateNetnsPath REJECTS /proc paths by design (SR-4 containment), so a
// raw /proc/<pid>/ns/net target (the ADR-0325 inode-mapping fallback) MUST go through srcPID, while
// the usual /var/run/netns/cni-<id> bind path goes through netnsPath.
func procNetnsPID(netnsTarget string) (int, bool) {
	const prefix = "/proc/"
	const suffix = "/ns/net"
	if !strings.HasPrefix(netnsTarget, prefix) || !strings.HasSuffix(netnsTarget, suffix) {
		return 0, false
	}
	mid := netnsTarget[len(prefix) : len(netnsTarget)-len(suffix)]
	if mid == "" || strings.Contains(mid, "/") {
		return 0, false
	}
	pid, err := strconv.Atoi(mid)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// addPreservedSourceAddr makes ip locally bindable — an IPv4 /32, scope host — on ifname inside the
// RESTORE-TARGET netns, so CRIU's soccr bind() of the checkpointed TCP_ESTABLISHED socket finds
// inet_addr_type()==RTN_LOCAL for the preserved source IP (fixes soccr.c:499 EADDRNOTAVAIL).
//
// SPONSOR DIRECTIVE (2026-07-15, ADR-0355 D1): the netns entry + address programming are DELEGATED
// to the unconfined netns broker (ADR-0348 fail-closed) — NEVER an in-process unix.Setns / raw
// netlink RTM_NEWADDR on the main agent. This is byte-for-byte the delegation SingleHomeRestoredPod
// already uses for its sibling `ip addr add`/`ip addr del` on this same restore path. `scope host`
// (never selected as an outbound/ARP source) and the /32 prefixlen (a DIFFERENT kernel ifa key from
// any CNI-assigned <ip>/24 scope-global primary, so it never displaces it) give the required
// properties. Idempotent via `ip addr replace` (RTM_NEWADDR|NLM_F_REPLACE|NLM_F_CREATE at the
// iproute2 level): re-issuing the SAME /32 scope-host add returns success, not EEXIST; a pin-honored
// <ip>/24 scope-global primary is a different ifa key and is NOT touched.
//
// netnsTarget is joinNsRestore's petnsPath — the SAME value CRIU joins via --join-ns net:<path>.
// ip is already-validated IPv4 (the caller rejects non-IPv4 before this — D3); a defensive
// To4()==nil check here still errors rather than mis-forming the command. Fail-closed on
// r.SpawnErr != nil (broker-unreachable/rejected) or r.ExitCode != 0.
func addPreservedSourceAddr(ctx context.Context, netnsTarget, ifname string, ip net.IP) error {
	if ip.To4() == nil {
		return fmt.Errorf("addPreservedSourceAddr: %v is not IPv4", ip)
	}
	var srcPID int
	var netnsPath string
	if pid, ok := procNetnsPID(netnsTarget); ok {
		srcPID = pid // /proc/<pid>/ns/net → broker srcPID form
	} else {
		netnsPath = netnsTarget // /var/run/netns/cni-<id> (or /run/netns/<name>) → broker netnsPath form
	}
	// argv[0]=="ip" is the ONLY thing the broker's netnsExecAllowlist checks; the subcommand is
	// unrestricted, exactly as SingleHomeRestoredPod's `ip addr add`/`del` rely on.
	r := brokerNetnsExecFn(ctx, srcPID, netnsPath,
		"ip", "-4", "addr", "replace", ip.String()+"/32", "scope", "host", "dev", ifname)
	if r.SpawnErr != nil {
		return fmt.Errorf("addPreservedSourceAddr: netns broker exec (ip addr replace %s/32 scope host dev %s): %w", ip, ifname, r.SpawnErr)
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("addPreservedSourceAddr: ip addr replace %s/32 scope host dev %s: exit %d (%s)",
			ip, ifname, r.ExitCode, strings.TrimSpace(string(r.Combined)))
	}
	return nil
}

// prepPreservedSourceAddrForRestore is the ADR-0355 D3 pre-CRIU bind-prep gate, extracted from
// joinNsRestore's sandboxID branch so the gating decision is unit-testable without the joinNsRestore
// monolith's real patchCheckpointImages/overlay/CRIU I/O (D5 test 1). It runs ONLY when there is a
// non-empty preservedSourceIP AND the checkpoint captured an established TCP connection
// (checkpointHasEstablishedTCP) — so it never fires for cold (None) or connectionless migrations.
//
// FAIL-CLOSED on BOTH new branches, each incrementing the SAME distinct
// restore_preserved_source_addr_bind_prep reason (matching the sibling joinNsRestore failure
// branches) and returning an error the caller propagates BEFORE buildCRIURestoreArgs/CRIU:
//   - DR-15: a non-empty but unparseable / non-IPv4 preservedSourceIP (no silent fall-through to
//     soccr.c:499), mirroring SingleHomeRestoredPod's own parsed==nil||To4()==nil convention.
//   - a broker addPreservedSourceAddr failure.
//
// A nil return means "no prep needed" (gate not met) or "prep succeeded". The caller is confined to
// the petnsPath != "" (sandboxID != "") branch, so netnsPath here is always the joined netns and
// ifname is the authoritative recorded value (recordAuthoritativeRestoreNetns), never a fresh
// "eth0" literal (DR-4).
func prepPreservedSourceAddrForRestore(ctx context.Context, migrationName, checkpointDir, netnsPath, ifname, preservedSourceIP string) error {
	if preservedSourceIP == "" || !checkpointHasEstablishedTCP(checkpointDir) {
		return nil
	}
	ip := net.ParseIP(preservedSourceIP)
	if ip == nil || ip.To4() == nil {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_preserved_source_addr_bind_prep").Inc()
		log.Error(fmt.Errorf("unparseable preservedSourceIP"), "joinNsRestore: preserved source IP is not a valid IPv4 — cannot make bindable before CRIU restore; failing closed (ADR-0355 D3/DR-15)",
			"migration", migrationName, "preservedSourceIP", preservedSourceIP)
		return fmt.Errorf("preserved source IP %q is not a valid IPv4 — cannot make bindable before CRIU restore (ADR-0355 D3, fail-closed): %w", preservedSourceIP, errInvalidPreservedSourceIP)
	}
	if aerr := addPreservedSourceAddrFn(ctx, netnsPath, ifname, ip); aerr != nil {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_preserved_source_addr_bind_prep").Inc()
		return fmt.Errorf("make preserved source IP %s bindable in pod-sandbox netns before CRIU restore (broker-delegated, ADR-0355 D1): %w", preservedSourceIP, aerr)
	}
	log.Info("joinNsRestore: preserved source IP made bindable in pod-sandbox netns before CRIU restore (ADR-0355 D1, broker-delegated)",
		"migration", migrationName, "ifname", ifname, "preservedSourceIP", preservedSourceIP, "netnsPath", netnsPath)
	return nil
}

// resolvePreservedSourceIP reads pm.Spec.SourcePodIP (the authoritative preserved source IP — the
// SAME field SingleHomeRestoredPod single-homes on, so D1's pre-CRIU /32 and the post-CRIU /24
// backfill cannot diverge; ADR-0355 D2 same-value invariant) for the named migration. It is NOT a
// cache map: a fresh API-server read that cannot go stale on migration-name reuse. Returns "" when
// the CR is unavailable/unreadable or the field is empty — the bind-prep gate treats "" as "no
// preserved-IP prep needed."
func (s *AgentServer) resolvePreservedSourceIP(ctx context.Context, namespace, migrationName string) string {
	if s.k8sClient == nil || namespace == "" || migrationName == "" {
		return ""
	}
	pm := &pmv1.PodMigration{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: migrationName}, pm); err != nil {
		log.Info("resolvePreservedSourceIP: get PodMigration failed — no preserved-IP bind-prep (ADR-0355 D2)",
			"migration", migrationName, "namespace", namespace, "err", err)
		return ""
	}
	return strings.TrimSpace(pm.Spec.SourcePodIP)
}

// resolvePreservedSourceIPForMigration is the gRPC-path variant of resolvePreservedSourceIP that
// resolves the namespace itself (the RestoreRequest proto carries no namespace field) via the same
// resolveNamespaceForMigration the gRPC path already trusts post-finalize. Returns "" on any miss.
func (s *AgentServer) resolvePreservedSourceIPForMigration(ctx context.Context, migrationName string) string {
	if s.k8sClient == nil {
		return ""
	}
	return s.resolvePreservedSourceIP(ctx, s.resolveNamespaceForMigration(ctx, migrationName), migrationName)
}

// ADR-0353: restoreClaim is the single-owner in-flight restore claim record. owner is "NRI" or
// "gRPC" — the two actors that can drive a CRIU restore into the destination pod/netns.
type restoreClaim struct {
	owner     string
	startedAt time.Time
}

// ADR-0353: restoreClaimsMu guards restoreClaims.
var restoreClaimsMu sync.Mutex

// ADR-0353 R1: restoreClaims is the authoritative in-process ownership registry, keyed by bare
// migrationName (not "<namespace>/<name>" as the ADR text literally says: namespace is not
// available at the claim point on the gRPC path without a new, currently-nonexistent hard-fail
// precondition, and every sibling per-migration map on AgentServer — migrationPodUID,
// migrationSeqSnapshots, pendingResumePIDs, destHostVeth, destWorkloadImage, destMigrationNetns —
// already keys by bare migrationName). Package-level, not an AgentServer field,
// because joinNsRestore is a deliberately receiver-less free function (D4/G5, see the
// joinNsRestoreFn var above for the same constraint). Sound
// because there is exactly one AgentServer per process (ADR-0353 D1, cmd/agent/main.go:409) so
// "package-level" and "per-agent-instance" coincide.
var restoreClaims = make(map[string]*restoreClaim)

// ADR-0353 R3/R5: ErrRestoreInFlight is returned when a second actor finds the single-owner
// in-flight restore claim already held by another owner for this migration. It is
// TRANSIENT-RETRY: the in-flight restore may still confirm. Callers MUST NOT treat this as a
// terminal failure and MUST NOT zeroize the checkpoint tmpfs images dir on this return.
var ErrRestoreInFlight = errors.New("restore already in flight for this migration under another owner")

// claimRestore atomically acquires the ADR-0353 single-owner in-flight restore claim for
// migrationName (R3, test-and-set under restoreClaimsMu). Returns true if acquired (no existing
// claim existed); false if a claim is already held by a DIFFERENT owner (existing claim is left
// untouched — the caller MUST NOT proceed to drive CRIU). Re-entrant calls are treated as a fresh
// acquire failure too — this ADR does not define re-entrant claims; no call site needs them, each
// of the three call sites acquires exactly once per restore attempt.
func claimRestore(migrationName, owner string) bool {
	restoreClaimsMu.Lock()
	defer restoreClaimsMu.Unlock()
	if _, held := restoreClaims[migrationName]; held {
		return false
	}
	restoreClaims[migrationName] = &restoreClaim{owner: owner, startedAt: time.Now()}
	return true
}

// releaseRestore releases the ADR-0353 claim for migrationName (R4/R6). Idempotent — safe to call
// even when no claim is held, so a defer can call this unconditionally on every return path
// without checking whether the acquire actually succeeded upstream.
func releaseRestore(migrationName string) {
	restoreClaimsMu.Lock()
	defer restoreClaimsMu.Unlock()
	delete(restoreClaims, migrationName)
}

// isRestoreClaimed is the ADR-0353 R2 entry-assertion read: reports whether a claim is currently
// held for migrationName. Read-only — never acquires or mutates. Used exclusively by the
// joinNsRestoreFn entry assertion (joinNsRestore, below) to fail loud if a future call site
// bypasses claimRestore.
func isRestoreClaimed(migrationName string) bool {
	restoreClaimsMu.Lock()
	defer restoreClaimsMu.Unlock()
	_, held := restoreClaims[migrationName]
	return held
}

// resolveNetnsFromSandboxFn is the production implementation of ResolveNetnsFromSandbox.
// Overridable in tests (R1 CI pin, ADR-0349 test (d)) to avoid a real containerd/ctr dependency.
var resolveNetnsFromSandboxFn = ResolveNetnsFromSandbox

// restoreResult is the shared finalization result populated by finalizeRestore.
// All restore paths (NRI + both gRPC Restore branches) return this struct so that
// MAC population and SingleHomeRestoredPod parity are path-independent (E1, ADR-0133 D3,
// ADR-0137/0138).
type restoreResult struct {
	pid       int
	netnsPath string
	mac       string
	// singleHomed is true when SingleHomeRestoredPod completed the ADR-0137/0138 single-home backfill
	// on eth0 (stripped non-OLD addresses, assigned oldIP/24 scope-global + the destination
	// gateway/default/reverse-path routes) — the routable form the deferred SIGCONT resumes onto.
	singleHomed bool
}

// finalizeRestore is the shared restore-finalization primitive (Condition 1 + Condition 2).
// It calls ReadReplVethMAC(pid, netnsPath) to populate the replacement pod's eth0 MAC, then
// calls SingleHomeRestoredPod on both gRPC and NRI paths (parity — Condition 2).
// For tcpPreservationMode Strict or Full: an empty MAC is a hard failure (fail-closed,
// Condition 3). For None/BestEffort: an empty MAC records a queryable CR-status condition and
// continues. Returns the populated restoreResult; callers must pass result.mac to
// ReportRestoreConfirmed.
func (s *AgentServer) finalizeRestore(ctx context.Context, pid int, netnsPath, ifname, migrationName, namespace, tcpPreservationMode, checkpointDir string) (restoreResult, error) {
	result := restoreResult{
		pid:       pid,
		netnsPath: netnsPath,
	}

	// Condition 1: resolve the replacement pod's dataplane MAC.
	//
	// SECURITY WRITE-BACK (ADR-0349 — Security Reviewer, sprint46B2 validation cycle 1). The MAC is
	// an AUTHORITATIVE at-restore-time CAPTURE taken from the restored process's OWN netns
	// (captureRestoredVethMAC, invoked by joinNsRestore the instant CRIU brings the process up) and
	// WRITTEN BACK into the per-migration record. finalizeRestore SERVES that VALUE — it does NOT
	// re-enter a recorded netns PATH after the fact. The live-proof
	// (docs/sprints/sprint46B2/live-proof-cycle1.md) falsified the record-a-pointer / re-read-the-path
	// design: the controller re-invoked Restore ~25 times over ~75s, each re-reading `eth0` against
	// the recorded /var/run/netns/cni-<id> handle via the broker's path-mode nsenter and getting
	// empty — even though the restored pod was reachable at its pod IP — the exact poll-and-hope
	// brittle chain invariant #10 forbids. The SrcPID entry the capture uses (/proc/<pid>/ns/net, the
	// same one the restore lo-up uses successfully) is the reliable one and the true source of truth
	// for where CRIU actually placed the process.
	//
	// ifname is the interface to read — "pmdst0" for a PrepareDestinationNetns migration netns,
	// "eth0" for the pod-sandbox netns (see finalizeNetnsPath / the recorded handle).
	//
	// Security invariants preserved:
	//   R2 — the capture and the residual read below both enter the restored process's OWN netns by
	//        SrcPID; ReadReplVethMAC constructs the /proc/<pid>/ns/net entry through the BROKER (the
	//        agent never spawns nsenter directly), so the historical agent-side AppArmor /proc denial
	//        cannot recur — proven live (the lo-up on this same entry succeeds; zero nsenter denials,
	//        criterion 3). No recorded bind PATH is ever re-read for the MAC.
	//   R4 — net.ParseMAC validates at the producer (in the capture and here); a malformed value
	//        fails closed under Strict at READ time, not as a late InjectIPHandoff requeue.
	//   R3/D3 — an empty capture drives the EXISTING Strict fail-closed branch below; the value is
	//        never sourced from Status.ReplVethMAC. The broker containment gate is untouched.
	mac := s.resolvedNetnsMAC(migrationName)
	var macErr error
	if mac == "" {
		// No at-restore capture was latched for this migration: the idempotent-confirm re-entry
		// where joinNsRestore did not run in THIS RPC, a direct unit call, or a host-network / None
		// cold restore with no eth0. Read the restored process's OWN netns directly (SrcPID —
		// /proc/<pid>/ns/net through the broker; NEVER a recorded bind PATH, NEVER a guessed ifname,
		// NEVER Status.ReplVethMAC), then apply the same producer-side validation + write-back.
		readIfname := ifname
		if readIfname == "" {
			readIfname = "eth0"
		}
		mac, macErr = readReplVethMACFn(ctx, pid, "", readIfname)
		if macErr == nil && mac != "" {
			if _, perr := net.ParseMAC(mac); perr != nil {
				macErr = fmt.Errorf("replVethMAC unparseable %q: %w", mac, perr)
				mac = ""
			} else if netnsPath != "" {
				// Latch the authoritative capture so re-invocations serve the VALUE (R5 idempotent
				// write-back; no-op when no gate-readable handle was recorded).
				storeResolvedNetnsMAC(migrationName, mac)
			}
		}
	}
	result.mac = mac

	// Condition 3: fail-closed on Strict/Full for empty MAC; degrade on None/BestEffort.
	if macErr != nil || mac == "" {
		mode := tcpPreservationMode
		if mode == "Strict" || mode == "Full" {
			reason := "replVethMAC empty after restore — MAC resolution failed (path-independent contract violation)"
			if netnsPath == "" {
				// R3 (ADR-0349): distinct, greppable cause. finalizeNetnsPath found no
				// gate-readable Tier-1 record — this is NOT a transient read failure against a
				// known-good netns, it is "no source of truth was ever recorded." Status/event
				// consumers must be able to tell the two apart (D8).
				reason = fmt.Sprintf("no authoritative restored netns recorded for migration %s", migrationName)
			}
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
	//
	// ADR-0355 D4: make the ADR-0138 routable /24 backfill ACTUALLY RUN on every live restore. All
	// four production callers historically passed namespace="" (the guard left the backfill DEAD), so
	// resolve the authoritative namespace here (resolveNamespaceForMigration — migrationName-keyed,
	// API-server authoritative, the SAME resolver the gRPC path already trusts post-finalize) when the
	// caller supplied none. SingleHomeRestoredPod then strips non-OLD eth0 addresses and assigns
	// oldIP/24 scope-global + the destination gateway/default/reverse-path routes (the ADR-0137/0138
	// contract), composing with D1's pre-CRIU /32 scope-host so eth0 ends restore in a routable form.
	//
	// establishedTCP is the SINGLE source-of-truth "did D1 add a /32" signal — the exact gate D1/D3
	// use (checkpointHasEstablishedTCP), NOT the tcpPreservationMode string (there is no "Full" mode,
	// and a connectionless Strict restore has no held socket to strand while a BestEffort
	// established-TCP restore DOES). On an established-TCP restore a backfill FAILURE (or an unresolved
	// namespace that prevents the backfill) is fail-closed (DR-14): D1's non-routable /32 is present
	// and, without the /24 backfill, the deferred SIGCONT would resume the ESTABLISHED socket onto a
	// non-routable /32 (the H3' silent stranding) — so we fail the restore instead.
	establishedTCP := checkpointHasEstablishedTCP(checkpointDir)
	shNamespace := namespace
	if shNamespace == "" && s.k8sClient != nil {
		shNamespace = s.resolveNamespaceForMigration(ctx, migrationName)
	}
	if s.k8sClient != nil && shNamespace != "" && pid > 0 {
		if shErr := singleHomeRestoredPodFn(s, ctx, migrationName, shNamespace, pid); shErr != nil {
			if establishedTCP {
				// FAIL CLOSED (DR-14): D1's non-routable /32 is present and the routable /24 backfill
				// FAILED — resuming the ESTABLISHED socket onto the /32 is the H3' silent stranding,
				// strictly worse than the crash D1 fixes. Return an error so the restore FAILS: no
				// deferred SIGCONT ever fires (InjectIPHandoff is a separate later RPC, reached only on
				// restore success), the frozen tree is torn down by rollback, and the source pod is
				// preserved (ADR-0012, invariant #1). Mirrors the MAC fail-closed already in this function.
				log.Error(shErr, "finalizeRestore: SingleHomeRestoredPod backfill failed on established-TCP restore — replacement would strand on non-routable /32; failing closed (ADR-0355 D4/DR-14, ADR-0012 inv #1 — source preserved)",
					"migration", migrationName, "restoredPID", pid)
				return result, fmt.Errorf("finalizeRestore: SingleHomeRestoredPod backfill failed on established-TCP restore (ADR-0355 D4, DR-14 fail-closed): %w", shErr)
			}
			// Connectionless / non-established-TCP: no D1 /32 was added, so there is nothing to strand
			// on — keep the pre-existing tolerable behavior (log loud, non-fatal; pod may remain
			// dual-homed on its CNI IP). Source pod preserved per ADR-0012 either way.
			log.Error(shErr, "finalizeRestore: SingleHomeRestoredPod failed (ADR-0137) — pod may remain dual-homed (non-established-TCP, non-fatal)",
				"migration", migrationName, "restoredPID", pid)
		} else {
			result.singleHomed = true
			log.Info("finalizeRestore: replacement pod single-homed on OLD IP (ADR-0137/0138)",
				"migration", migrationName, "restoredPID", pid)
		}
	} else if s.k8sClient != nil && shNamespace == "" && establishedTCP {
		// Namespace UNRESOLVED on an established-TCP restore: the /24 backfill cannot run and D1's /32
		// is present → the same strand. Also fail-closed (DR-14), not a silent/loud skip — a skip here
		// is indistinguishable from H3' at SIGCONT time.
		err := fmt.Errorf("finalizeRestore: namespace unresolved for established-TCP restore — OLD-IP /24 backfill cannot run, replacement would strand on non-routable /32 (ADR-0355 D4/DR-14/H3', ADR-0012 inv #1 — source preserved)")
		log.Error(err, "finalizeRestore: failing closed on unresolved namespace", "migration", migrationName)
		return result, err
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
// namespace is the PodMigration CR's namespace (ADR-0353 R4/D6): JoinNsRestore now calls
// ReportRestoreConfirmed itself on the terminal success path, so it needs namespace to do so —
// the caller must resolve it the same way it always did before passing it here. The NRI caller
// must pass mac directly to ReportRestoreConfirmed; it must NOT call ReadReplVethMAC independently.
// containerCgroupsPath/podCgroupParent are the ADR-0351 D1 NRI-carried cgroup-anchor fields —
// read directly off the event by the caller (cmd/agent/main.go), threaded here as plain
// parameters (no query, no poll, no side-map) and passed through to joinNsRestore.
// restoreInvariantBudget is the constitutional invariant-#8 live-migration cap (120s) — the
// single, authoritative overall restore/migration deadline already cited throughout this
// codebase (this file's replacementSandboxWaitBudget comment: "the 120s live-migration hard
// bound (constitutional invariant #8)"; internal/controller/podmigration_controller.go's
// invariant-#8 completion-budget gate; the "120s cap" reviewed at sprint46B7). It is named here
// (not re-derived as a bare literal) so the NRI restore path — which has no caller-supplied ctx
// to thread (ADR-0354 DR-2) — bounds itself against the SAME cap the rest of the system already
// enforces, rather than an arbitrary or re-guessed number.
const restoreInvariantBudget = 120 * time.Second

func (s *AgentServer) JoinNsRestore(migrationName, namespace, checkpointDir, imageName, containerID, sandboxID, containerCgroupsPath, podCgroupParent, tcpPreservationMode string) (int, string, error) {
	// ADR-0353 R2/R3: acquire the single-owner in-flight restore claim before driving CRIU. A
	// second actor (the gRPC Restore fallback) racing this same migration MUST NOT proceed —
	// decline with the TRANSIENT-RETRY ErrRestoreInFlight and leave this owner as sole authority.
	if !claimRestore(migrationName, "NRI") {
		log.Info("JoinNsRestore: restore already in flight for this migration under another owner — declining (ADR-0353 R3)",
			"migration", migrationName)
		return 0, "", ErrRestoreInFlight
	}
	// ADR-0353 R4: release on every terminal exit — success and every failure/error return —
	// via defer so no early return leaks the claim. ReportRestoreConfirmed is folded into this
	// function below (D6) so the release below never fires before the terminal confirm.
	//
	// ADR-0354 D3/DR-3: this existing defer-based release already composes correctly with the new
	// rollbackExecBudget bound — no additional machinery is needed. releaseRestore only runs AFTER
	// this synchronous function (and everything it calls, including joinNsRestoreFn and any
	// brokerCriuCmd.Signal() kill on the fail-closed leg) returns. Every blocking call inside that
	// path is now itself bounded: forward broker/CRIU execs by min(remaining(ctx), their ceiling)
	// (D2/D2b), and the abort-leg Signal() kill by rollbackExecBudget via
	// context.WithTimeout(context.WithoutCancel(ctx), rollbackExecBudget) regardless of whether the
	// forward ctx is already Done (D2b). So the longest this claim can be held past the forward
	// ctx's expiry is bounded by rollbackExecBudget (plus whatever bounded forward work was still
	// in flight) — the claim can never be held open for a wedged broker exec running out a stale
	// 5-minute/30s Background() budget the way it could before this ADR.
	defer releaseRestore(migrationName)

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
		// AUTHORITATIVE source first: MCP.Spec.WorkloadImage (ADR-0217 D1) is set in Validating and
		// is race-free (independent of Status.ReplacementPodName / a live replacement pod). Prefer
		// it over the replacement-pod resolver, which was observed racing on the agent-Restore-RPC
		// fallback path. Fall back to the pod resolver only if the MCP is unreadable/empty.
		if resolved := s.resolveImageFromMCP(migrationName); resolved != "" {
			imageName = resolved
			log.Info("ADR-0217 D1: resolved workload image from MCP.Spec.WorkloadImage (authoritative)",
				"migration", migrationName, "image", imageName)
		} else if resolved := s.resolveImageFromReplacementPod(migrationName); resolved != "" {
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
	// Resolve shared/re-attach PVC mount paths (Tier0 RWX) so patchCheckpointImages preserves them
	// and CRIU re-attaches them on restore instead of P-0193-1 hard-stopping their open file fds.
	// The replacement pod is a paused placeholder created ~5s before restore; its RWX volume may not
	// be published in the destination kubelet's mount table at the instant this NRI restore fires, so
	// bounded-wait on the kubelet-published mount rather than emitting a broken 1:1 map. Budget is
	// 85s — kept just under the 90s outer NRI restoreCtx so the wait yields to the outer deadline.
	// (JoinNsRestore takes no ctx param; the budget is derived here to keep the diff minimal.)
	reCtx, reCancel := context.WithTimeout(context.Background(), 85*time.Second)
	reattachMounts, reErr := s.resolveReattachMountsWaiting(reCtx, migrationName)
	reCancel()
	if reErr != nil {
		return 0, "", reErr
	}
	// ADR-0351 D3.1/D1.2: the pause-PID bounded-wait ceiling (sandboxPausePIDWaitSubCap) this
	// block used to derive is retired along with sandboxPausePIDWaiting itself — the cgroup-anchor
	// primitive is a zero-query, zero-poll, zero-retry read of event data already in hand, so no
	// ctx budget is needed for it.
	// ADR-0354 DR-2: joinNsRestoreFn still takes a ctx parameter (other call sites thread the
	// real gRPC/restore ctx they were given). The NRI ContainerEvent path that reaches
	// JoinNsRestore genuinely has no caller ctx to thread — NRI is a synchronous hook callback,
	// not a ctx-bearing RPC, so there is no upstream deadline/cancellation to propagate (unlike
	// the gRPC Restore handler's primary and raw-CRIU-fallback drives, which DO have one). Rather
	// than rooting on a bare context.Background() with no ceiling of its own (the same defect
	// class this ADR retires elsewhere), construct a BOUNDED ctx here from the authoritative
	// restore/migration deadline (restoreInvariantBudget, constitutional invariant #8 — the same
	// 120s live-migration cap already cited at server.go's replacementSandboxWaitBudget and
	// throughout internal/controller/podmigration_controller.go's invariant-#8 completion-budget
	// gate) so every broker exec (D2/D2b/D2c) this call drives is still deadline-bound, just off
	// a locally-constructed ceiling instead of an inherited one. This CANNOT widen any existing
	// bound (there was none here before) and is strictly tighter than the prior unbounded
	// Background() root.
	joinNsRestoreCtx, joinNsRestoreCancel := context.WithTimeout(context.Background(), restoreInvariantBudget)
	defer joinNsRestoreCancel()
	// ADR-0355 D2/D3: read the authoritative preserved source IP (pm.Spec.SourcePodIP — the same
	// field SingleHomeRestoredPod single-homes on) and thread it into joinNsRestore so the pre-CRIU
	// bind-prep can make it locally bindable before soccr's bind() on an established-TCP restore.
	// Empty (no CR / empty field) → the bind-prep gate is a no-op.
	preservedSourceIP := s.resolvePreservedSourceIP(joinNsRestoreCtx, namespace, migrationName)
	pid, droppedMounts, err := joinNsRestoreFn(joinNsRestoreCtx, migrationName, checkpointDir, imageName, containerID, "", sandboxID, storedVeth, strictMode, reattachMounts, containerCgroupsPath, podCgroupParent, preservedSourceIP)
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
		_, resumedAt, orderErr := enforceRestoreOrderingInvariant(joinNsRestoreCtx, pid, migrationName, expectedSocketCount, true)
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
	// path-independently.
	// ADR-0355 D4: namespace IS available here — it is a JoinNsRestore parameter, populated by the
	// NRI caller (cmd/agent/main.go) — so pass it (not the prior ""), which makes the ADR-0138 /24
	// backfill in SingleHomeRestoredPod live on the NRI path; in the common case namespace is
	// non-empty and the resolveNamespaceForMigration fallback inside finalizeRestore never fires.
	// checkpointDir is threaded so finalizeRestore can read the checkpointHasEstablishedTCP
	// fail-closed gate (DR-14). The prior "Namespace is not available here" comment was false.
	// ADR-0308 follow-up: use finalizeNetnsPath so that if ResolvedNetnsPath was not recorded
	// (parity with the gRPC fallback path), MAC resolution falls back to the PrepareDestinationNetns
	// bind mount rather than the ptrace'd /proc/<pid>/ns/net path AppArmor denies.
	netnsPath, macIfname := s.finalizeNetnsPath(migrationName)
	fr, frErr := s.finalizeRestore(joinNsRestoreCtx, pid, netnsPath, macIfname, migrationName, namespace, tcpPreservationMode, checkpointDir)
	if frErr != nil {
		// Strict/Full fail-closed: propagate.
		return 0, "", frErr
	}

	// ADR-0353 R4/D6: ReportRestoreConfirmed is consolidated here (moved from
	// cmd/agent/main.go, outside the server package) so the deferred releaseRestore above fires
	// AFTER the terminal confirm, not before — the release must never straddle the server<->main
	// package boundary. A second actor entering the not-yet-alive window at ANY point up to and
	// including this confirm now observes the claim.
	//
	// Gated identically to the gRPC path's ReportRestoreConfirmed call sites — non-fatal on
	// failure: a nil k8sClient or unresolved namespace no longer fails the NRI restore outright,
	// matching the gRPC path's existing parity and relying on the gRPC Restore idempotent-confirm
	// branch as the retry-safe reconciler if the CR patch is missed here.
	if s.k8sClient != nil && namespace != "" {
		reportCtx, reportCancel := context.WithTimeout(context.Background(), 30*time.Second)
		rcErr := s.ReportRestoreConfirmed(reportCtx, migrationName, namespace, int32(pid), fr.mac)
		reportCancel()
		if rcErr != nil {
			log.Error(rcErr, "JoinNsRestore: ReportRestoreConfirmed failed (non-fatal — gRPC Restore idempotent-confirm branch will reconcile)",
				"migration", migrationName, "namespace", namespace)
		}
	} else {
		log.Info("JoinNsRestore: k8sClient nil or namespace unresolved — ReportRestoreConfirmed skipped",
			"migration", migrationName, "namespace", namespace)
	}
	return pid, fr.mac, nil
}

// resolveImageFromReplacementPod is the ADR-0217 D2 third fallback for restore image
// resolution. When the NRI event image and the PrepareDestinationNetns cache are both empty,
// it reads the replacement pod's own container[0].Image from the Kubernetes API. The
// replacement pod name lives on PodMigration.Status.ReplacementPodName and is carried in the
// workload namespace (pm.Spec.PodNamespace). Returns "" on any failure (caller fail-closes).
// lookupPodMigration resolves the PodMigration CR for migrationName. The CR lives in the
// workload namespace; probe POD_NAMESPACE then podmotion-system, and finally fall back to a
// cross-namespace List (the CR may live in the workload namespace, e.g. "default", not the
// agent's POD_NAMESPACE). Returns the CR (and its resolved namespace) or false on any failure.
func (s *AgentServer) lookupPodMigration(ctx context.Context, migrationName string) (*pmv1.PodMigration, bool) {
	if s.k8sClient == nil || migrationName == "" {
		return nil, false
	}
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		ns = "podmotion-system"
	}
	pm := &pmv1.PodMigration{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: migrationName, Namespace: ns}, pm); err != nil {
		pmList := &pmv1.PodMigrationList{}
		if listErr := s.k8sClient.List(ctx, pmList); listErr != nil {
			return nil, false
		}
		for i := range pmList.Items {
			if pmList.Items[i].Name == migrationName {
				*pm = pmList.Items[i]
				return pm, true
			}
		}
		return nil, false
	}
	return pm, true
}

// resolveImageFromMCP is the AUTHORITATIVE, race-free restore-image source. It reads
// MigrationCheckpoint.Spec.WorkloadImage — set by the controller's ADR-0217 D1 producer in the
// Validating phase (podmigration_controller.go), long before restore, and equal to the source
// pod's container[0].Image. The MCP is named {pm.Name, pm.Namespace} (same key as the
// PodMigration CR). Unlike resolveImageFromReplacementPod, this does NOT depend on
// Status.ReplacementPodName being populated or on the replacement pod being alive/not mid-teardown
// at resolve time — the observed race on the agent-Restore-RPC fallback path (~60s after the NRI
// confirm window times out) where the replacement pod resolver returned empty. Returns "" on any
// failure (caller falls through to the pod resolver, then fail-closes).
func (s *AgentServer) resolveImageFromMCP(migrationName string) string {
	if s.k8sClient == nil || migrationName == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The MCP shares the PodMigration CR's name+namespace. Resolve the namespace via the same
	// lookup the pod resolver uses so we tolerate the CR living in a non-agent namespace.
	pm, ok := s.lookupPodMigration(ctx, migrationName)
	if !ok {
		return ""
	}
	mcp := &pmv1.MigrationCheckpoint{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, mcp); err != nil {
		return ""
	}
	return mcp.Spec.WorkloadImage
}

func (s *AgentServer) resolveImageFromReplacementPod(migrationName string) string {
	if s.k8sClient == nil || migrationName == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pm, ok := s.lookupPodMigration(ctx, migrationName)
	if !ok {
		return ""
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

// reattachMount is one shared/re-attach (Tier0) volume mount preserved across a migration.
// ContainerPath is the in-container mountPath (== the mountpoints-image MOUNTPOINT the patch
// classifier keys the re-attach preservation on — NOT the CRIU ext_key, which is the constant
// literal "CRIU:AUTOGENERATED" for every auto-detected external and thus useless for matching).
// HostTarget is the path — visible in the
// destination HOST mount namespace where CRIU runs via nsenter — that CRIU binds the mount FROM
// on restore (the kubelet-mounted volume dir of the replacement pod). ContainerPath alone drives
// the patch's KEEP decision; the (ContainerPath, HostTarget) pair drives the restore-side
// --ext-mount-map so CRIU re-attaches the SAME live data the destination pod already mounted.
type reattachMount struct {
	ContainerPath string
	HostTarget    string
}

// reattachContainerPaths projects the in-container paths from a []reattachMount (the set the patch
// classifier needs). Order-preserving.
func reattachContainerPaths(ms []reattachMount) []string {
	if len(ms) == 0 {
		return nil
	}
	paths := make([]string, 0, len(ms))
	for _, m := range ms {
		paths = append(paths, m.ContainerPath)
	}
	return paths
}

// reattachHostTargets projects a []reattachMount into a {ContainerPath: HostTarget} map — the
// argv[5] the patch script uses to rewrite each preserved re-attach mount's recorded root/source
// (the SOURCE-node kubelet volume path baked in at dump) to the DESTINATION kubelet volume dir.
// CRIU restores an auto-detected external (ext_key="CRIU:AUTOGENERATED") by binding from mi->source
// directly and bypasses --ext-mount-map (criu/mount.c get_mp_root, 4.2), so rewriting the recorded
// source in the image is the only way to point a cross-node re-attach at the destination volume.
// Entries with an empty HostTarget are omitted (no rewrite; buildCRIURestoreArgs fail-closes on
// them). Returns nil for an empty input so json.Marshal emits an empty object downstream.
func reattachHostTargets(ms []reattachMount) map[string]string {
	if len(ms) == 0 {
		return nil
	}
	m := make(map[string]string, len(ms))
	for _, rm := range ms {
		if rm.ContainerPath != "" && rm.HostTarget != "" {
			m[rm.ContainerPath] = rm.HostTarget
		}
	}
	return m
}

// replacementPodLabelKey is the label the controller stamps on the replacement pod at creation
// time (podmigration_controller.go). It equals the PodMigration name. It is the authoritative,
// race-free way to find the replacement pod on the destination node — unlike
// pm.Status.ReplacementPodName, which is a Status field that is frequently read back empty at
// restore time (the replacement pod is created ~5s before restore runs and the status write races
// the agent's cached read). This mirrors the image-resolution hardening (resolveImageFromMCP):
// prefer a source of truth that does not depend on a Status field being populated at the exact
// instant the agent reads it (reads the authoritative value instead of inferring it).
const replacementPodLabelKey = "podmotion.io/migration-name"

// resolveReplacementPod finds the replacement pod for a migration by the authoritative
// migration-name label instead of the flaky pm.Status.ReplacementPodName status field. It lists
// pods in podNs carrying replacementPodLabelKey==migrationName and returns the single match.
// Returns nil if none/ambiguous — callers decide whether that is fatal. This is the label-selector
// primitive the Sprint-44 diagnosis prescribes: the controller stamps the label at replacement-pod
// creation, so it is present long before restore and does not race the status write.
func (s *AgentServer) resolveReplacementPod(ctx context.Context, migrationName, podNs string) *corev1.Pod {
	if s.k8sClient == nil || migrationName == "" || podNs == "" {
		return nil
	}
	podList := &corev1.PodList{}
	if err := s.k8sClient.List(ctx, podList,
		client.InNamespace(podNs),
		client.MatchingLabels{replacementPodLabelKey: migrationName}); err != nil {
		return nil
	}
	var match *corev1.Pod
	for i := range podList.Items {
		p := &podList.Items[i]
		// Skip pods already terminating (a prior failed attempt's replacement mid-teardown).
		if p.DeletionTimestamp != nil {
			continue
		}
		if match != nil {
			// Ambiguous: more than one live replacement pod for this migration. Do not guess.
			return nil
		}
		match = p
	}
	return match
}

// ReattachVolumeNotYetPublishedError is a RETRYABLE sentinel returned by resolveReattachMounts when
// the replacement pod is resolved (its UID is known via the migration-name label) but the kubelet
// has NOT yet published the re-attach (Tier0 RWX) PV's mount into the host mount table — i.e. the
// destination kubelet's NodePublish for that volume has not completed at the instant restore fires.
// This is DISTINCT from the terminal ExternalMountUnresolvedError: callers separate "not yet"
// (bounded wait on the real kubelet-driven mount-table edge) from "never" (fail closed). The
// replacement pod is a paused placeholder created ~5s before restore; its RWX volume mount is not
// guaranteed established on the destination node at the instant restore is dispatched, so a present
// mountpoint is a legitimate bounded WAIT rather than an immediate hard stop.
type ReattachVolumeNotYetPublishedError struct {
	ContainerPath string
	PVName        string
	ReplUID       string
}

func (e *ReattachVolumeNotYetPublishedError) Error() string {
	return fmt.Sprintf("reattach volume not yet published: kubelet mountpoint for pv=%s (pod uid=%s) backing container path %s is not present in the host mount table yet", e.PVName, e.ReplUID, e.ContainerPath)
}

// resolveReattachMounts returns the shared/re-attach (Tier0 RWX) PVC mounts of the migrating pod,
// each as an (in-container path, destination host-target path) pair. These are legitimate,
// restorable EXTERNAL mounts: the checkpoint records a PVC-backed volume as an external mountpoints
// entry whose MOUNTPOINT is the in-container mountPath (its ext_key is the constant literal
// "CRIU:AUTOGENERATED" — CRIU's auto-external marker — NOT the path), and the workload holds open
// file handles on it (e.g. PostgreSQL WAL/relation files under /var/lib/postgresql/data). Such a
// mount must be PRESERVED across the checkpoint-image patch (kept in kept_mnt_ids so its files.img
// REG fds classify consistent, NOT dropped-and-orphaned into the P-0193-1 hard-stop) and re-attached
// on restore via --ext-mount-map <containerPath>:<hostTarget>. The patch keys the preservation on
// the mountpoint == ContainerPath (patch_checkpoint_script.go); the restore-side --ext-mount-map
// keys on the same mountpoint. This is the "RWX re-attach" storage tier — no data bytes move; the
// same volume is visible on both nodes.
//
// The in-container path comes from the pod spec (not a hardcoded workload path): every
// container volumeMount whose named volume resolves to a PVC. The HOST TARGET is the kubelet volume
// directory the destination kubelet already mounted for the replacement pod
// (/var/lib/kubelet/pods/<replUID>/volumes/kubernetes.io~*/<pvName>) — CRIU runs in the host mount
// namespace and cannot see the in-container path (it exists only inside the replacement pod's mount
// ns), so mapping <containerPath>:<containerPath> fails with "open_tree ... No such file or
// directory"; the host kubelet dir is the real bind source. Returns nil on any failure — the caller
// then patches with no re-attach set (prior fail-closed behavior).
// resolveReattachMounts single-shot-resolves the re-attach mounts. It returns:
//   - (nil, nil)   — no re-attach mounts apply (no client, lookup fail, no PVCs, spec pod get fail).
//   - (mounts, nil) — every re-attach mount's host target resolved.
//   - (nil, *ReattachVolumeNotYetPublishedError) — the replacement pod is resolved (UID known via
//     label) but at least one PVC-backed mount's kubelet volume is not yet published in the host
//     mount table. This is the RETRYABLE "not yet" case — the caller re-probes under its ctx budget.
//
// When the replacement pod is NOT resolved at all (no label match and Status.ReplacementPodName
// empty), the "never/label-missing" branch stays terminal: a HostTarget=="" mount is appended so
// buildCRIURestoreArgs' guard (server.go ~3266) fails closed with "replacement pod not found by
// label".
func (s *AgentServer) resolveReattachMounts(ctx context.Context, migrationName string) ([]reattachMount, error) {
	return s.resolveReattachMountsImpl(ctx, migrationName, false)
}

// pvcIsTier0RWX reports whether a PVC classifies as Tier0 (ReadWriteMany re-attach) storage — the
// ONLY tier eligible for the checkpoint-image re-attach mount-path rewrite. It mirrors the Tier0
// determination in internal/agent/storage.classifier: a ReadWriteMany access mode maps to Tier0
// regardless of provisioner. Every other access mode (ReadWriteOnce / ReadOnlyMany /
// ReadWriteOncePod) resolves to a higher tier — Longhorn dual-engine, Ceph RBD live, or
// snapshot+rsync — each of which owns its replication/consistency handoff and must NOT be re-attached
// by rewriting the recorded mount source to the destination kubelet volume dir.
func pvcIsTier0RWX(pvc *corev1.PersistentVolumeClaim) bool {
	if pvc == nil {
		return false
	}
	for _, am := range pvc.Spec.AccessModes {
		if am == corev1.ReadWriteMany {
			return true
		}
	}
	return false
}

// resolveReattachMountsImpl is the shared body behind resolveReattachMounts (terminalOnBudget=false,
// returns the retryable sentinel for a not-yet-published volume) and reattachMountsUnresolvedForTerminal
// (terminalOnBudget=true, promotes the not-yet mount to a HostTarget=="" entry so the terminal
// buildCRIURestoreArgs guard fails closed once the wait budget is spent).
//
// ADR-0354 D2c: the host-target resolution below (resolveKubeletVolumeHostPath -> kubeletVolumeGlobFn
// -> nsenterCmd) is a broker exec that funnels Client.do, so its ctx must derive from the caller's
// real migration/restore ctx, never a fresh context.Background(). callerCtx is bounded here to the
// existing 5s per-call ceiling via context.WithTimeout(callerCtx, 5*time.Second), which can only
// TIGHTEN the effective budget (never widen it) — same clamp discipline as brokerExecBudget (D2).
func (s *AgentServer) resolveReattachMountsImpl(callerCtx context.Context, migrationName string, terminalOnBudget bool) ([]reattachMount, error) {
	if s.k8sClient == nil || migrationName == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(callerCtx, 5*time.Second)
	defer cancel()

	pm, ok := s.lookupPodMigration(ctx, migrationName)
	if !ok {
		return nil, nil
	}
	podNs := pm.Spec.PodNamespace
	if podNs == "" {
		podNs = pm.Namespace
	}

	// The REPLACEMENT pod is authoritative for the host target — it is the pod whose kubelet
	// mount we bind from on the destination. Its volume set is identical to the source's by
	// construction (same spec). Resolve it by the migration-name LABEL (the source of truth the
	// controller stamps at replacement-pod creation) rather than pm.Status.ReplacementPodName,
	// which is frequently read back empty at restore time — the defect that produced the broken
	// 1:1 container-path ext-mount-map (reads the authoritative value instead of inferring it). Fall back to the
	// status field only if the label lookup finds nothing, then to the source pod for the
	// in-container path set (host-target resolution then no-ops and buildCRIURestoreArgs
	// fail-closes on the unresolved host target).
	replPod := s.resolveReplacementPod(ctx, migrationName, podNs)
	if replPod == nil {
		replName := pm.Status.ReplacementPodName
		if replName != "" {
			p := &corev1.Pod{}
			if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: replName, Namespace: podNs}, p); err == nil {
				replPod = p
			}
		}
	}
	specPod := replPod
	if specPod == nil {
		p := &corev1.Pod{}
		if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: pm.Spec.PodName, Namespace: podNs}, p); err != nil {
			return nil, nil
		}
		specPod = p
	}

	// Map each PVC-backed volume name → its in-container mountPath(s).
	pvcVolToClaim := make(map[string]string)
	for _, v := range specPod.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			pvcVolToClaim[v.Name] = v.PersistentVolumeClaim.ClaimName
		}
	}
	if len(pvcVolToClaim) == 0 {
		return nil, nil
	}

	// Resolve each claim → PV name (the leaf dir under the kubelet volumes dir) once, and record
	// whether the claim classifies as Tier0 (ReadWriteMany re-attach) storage. Only Tier0 PVCs are
	// re-attach-eligible: the checkpoint-image mount-path rewrite (patchCheckpointImages) points a
	// preserved external mount at the destination kubelet volume dir, which is correct ONLY when the
	// same volume is concurrently visible on both nodes (RWX, zero data movement). A non-RWX PVC
	// (Longhorn dual-engine, Ceph RBD live, snapshot-rsync — typically ReadWriteOnce) has its own
	// replication/consistency handoff; treating it as a re-attach mount would silently bind the
	// destination volume dir over CRIU's recorded source and bypass that handoff entirely. The Tier0
	// test mirrors internal/agent/storage.classifier (a ReadWriteMany access mode maps to Tier0
	// regardless of provisioner).
	claimToPV := make(map[string]string)
	claimIsTier0 := make(map[string]bool)
	for _, claim := range pvcVolToClaim {
		if _, done := claimToPV[claim]; done {
			continue
		}
		pvc := &corev1.PersistentVolumeClaim{}
		if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: claim, Namespace: podNs}, pvc); err == nil {
			claimToPV[claim] = pvc.Spec.VolumeName
			claimIsTier0[claim] = pvcIsTier0RWX(pvc)
		}
	}

	replUID := ""
	if replPod != nil {
		replUID = string(replPod.UID)
	}

	seen := make(map[string]bool)
	var mounts []reattachMount
	// Track the first PVC mount whose host target could not be resolved while the replacement pod
	// WAS resolved (replUID known) — that is the retryable "not yet published" case. We defer the
	// decision until after the collect loops so the whole mount set is walked deterministically.
	var notYetCP, notYetPV string
	collect := func(mnts []corev1.VolumeMount) {
		for _, m := range mnts {
			claim, isPVC := pvcVolToClaim[m.Name]
			if !isPVC {
				continue
			}
			// Tier gate (fail-closed against mis-classification): a PVC-backed mount is re-attach
			// eligible ONLY if it classifies as Tier0 (ReadWriteMany re-attach). Excluding a non-Tier0
			// PVC here keeps it out of reattach_mount_paths, so patch_checkpoint_script leaves its
			// recorded mount source alone (the pre-existing non-Tier0 handling) rather than rewriting
			// it as a cross-node re-attach mount.
			if !claimIsTier0[claim] {
				continue
			}
			cp := filepath.Clean(m.MountPath)
			if cp == "" || cp == "." || seen[cp] {
				continue
			}
			seen[cp] = true
			host := resolveKubeletVolumeHostPath(ctx, replUID, claimToPV[claim])
			if host == "" && replUID != "" && !terminalOnBudget {
				// Replacement pod resolved but its kubelet volume is not yet published in the host
				// mount table: capture it as the retryable "not yet" case rather than appending a
				// HostTarget=="" mount (which would fail closed immediately).
				if notYetCP == "" {
					notYetCP = cp
					notYetPV = claimToPV[claim]
				}
				continue
			}
			mounts = append(mounts, reattachMount{ContainerPath: cp, HostTarget: host})
		}
	}
	for i := range specPod.Spec.InitContainers {
		collect(specPod.Spec.InitContainers[i].VolumeMounts)
	}
	for i := range specPod.Spec.Containers {
		collect(specPod.Spec.Containers[i].VolumeMounts)
	}
	if notYetCP != "" {
		// At least one re-attach volume is not yet published (replacement pod resolved). Signal the
		// retryable sentinel so the caller re-probes the mount table under its bounded ctx budget.
		return nil, &ReattachVolumeNotYetPublishedError{ContainerPath: notYetCP, PVName: notYetPV, ReplUID: replUID}
	}
	return mounts, nil
}

// reattachMountsUnresolvedForTerminal rebuilds the re-attach mount list exactly like
// resolveReattachMounts but, once the wait budget is spent, appends any not-yet-published mount with
// HostTarget=="" so buildCRIURestoreArgs' terminal guard fires with its actionable
// "reattach host target unresolved" error (never the broken 1:1 map). Used only by
// resolveReattachMountsWaiting on ctx expiry — the "never" branch.
//
// ADR-0354 D3 pattern: this fires PRECISELY because the caller's forward ctx has already expired
// (resolveReattachMountsWaiting's ctx.Done() branch), so resolveReattachMountsImpl's nsenterCmd-backed
// host-target read must NOT be bound to that already-Done ctx (which would abort every broker exec
// instantly and always resolve to HostTarget==""). Same primitive as the D3 rollback leg and the D2b
// Signal() abort leg: sever cancellation from the expired forward deadline via context.WithoutCancel,
// then re-bound with a small budget (the existing 5s ceiling resolveReattachMountsImpl already
// applies) so a wedged broker exec on this terminal leg still cannot hang indefinitely.
func (s *AgentServer) reattachMountsUnresolvedForTerminal(ctx context.Context, migrationName string) []reattachMount {
	mounts, _ := s.resolveReattachMountsImpl(context.WithoutCancel(ctx), migrationName, true)
	return mounts
}

// resolveReattachMountsWaiting re-probes the kubelet mount table under ctx until every RWX re-attach
// volume is published, or ctx expires. "Not yet" is a bounded wait on the real kubelet-driven state
// transition (mountpoint absent → re-probe); expiry fails closed via the caller's existing terminal
// guard (buildCRIURestoreArgs refuses the broken 1:1 map when HostTarget=="").
func (s *AgentServer) resolveReattachMountsWaiting(ctx context.Context, migrationName string) ([]reattachMount, error) {
	for {
		m, err := s.resolveReattachMounts(ctx, migrationName)
		var notYet *ReattachVolumeNotYetPublishedError
		if !errors.As(err, &notYet) {
			return m, err // resolved, no-mounts, or a real error
		}
		select {
		case <-ctx.Done():
			// Budget spent: convert to the terminal path. Rebuild the mount list with the not-yet
			// mount promoted to a HostTarget=="" entry so buildCRIURestoreArgs' existing guard
			// fails closed (never the 1:1 map) with an actionable message.
			return s.reattachMountsUnresolvedForTerminal(ctx, migrationName), nil
		case <-time.After(1 * time.Second):
		}
	}
}

// parseKubeletMountFromMountinfo resolves the destination-host bind source for a re-attach PV by
// reading the kubelet-published mount out of a /proc/self/mountinfo dump, rather than globbing the
// pod dir. The mount table is written by the kubelet exactly when NodePublish completes and is the
// same bind source CRIU passes to open_tree, so a present mountpoint is the atomic non-flapping
// truth (both presence AND exact shape) — a mkdir'd-but-unmounted dir reads as NOT ready. CSI
// publishes a <pvName>/mount leaf; in-tree NFS a <pvName> dir; one table resolves both.
//
// Per proc(5) each mountinfo line is `mountID parentID major:minor root MOUNTPOINT ...`, so the
// mountpoint is field index 4 (0-based). A mountpoint matches this PV iff it begins with
// /var/lib/kubelet/pods/<replUID>/volumes/, the first path segment after that prefix matches
// kubernetes.io~* (any provisioner subdir — nfs, csi, …; discovered not hardcoded), and the
// remainder is EITHER exactly <pvName> (in-tree NFS shape) OR <pvName>/mount (CSI shape). When both
// the bare dir and the /mount leaf are present (CSI), the /mount leaf wins — that is the bind the
// workload holds open. Returns "" when nothing matches.
//
// Pure/deterministic (no broker) so the parsing is unit-testable without a host-ns round trip.
func parseKubeletMountFromMountinfo(mountinfo []byte, replUID, pvName string) string {
	if replUID == "" || pvName == "" {
		return ""
	}
	basePrefix := "/var/lib/kubelet/pods/" + replUID + "/volumes/"
	var bareDir, mountLeaf string
	for _, line := range strings.Split(string(mountinfo), "\n") {
		fields := strings.Split(line, " ")
		if len(fields) < 5 {
			continue
		}
		mountpoint := fields[4]
		if !strings.HasPrefix(mountpoint, basePrefix) {
			continue
		}
		rest := strings.TrimPrefix(mountpoint, basePrefix)
		segs := strings.Split(rest, "/")
		// segs[0] is the provisioner subdir (kubernetes.io~nfs, ~csi, …); the remainder is the PV.
		if len(segs) < 2 {
			continue
		}
		if !strings.HasPrefix(segs[0], "kubernetes.io~") {
			continue
		}
		remainder := strings.Join(segs[1:], "/")
		switch remainder {
		case pvName:
			bareDir = mountpoint
		case pvName + "/mount":
			mountLeaf = mountpoint
		}
	}
	// Prefer the CSI /mount leaf over the bare PV dir when both are published.
	if mountLeaf != "" {
		return mountLeaf
	}
	return bareDir
}

// kubeletVolumeGlobFn resolves the on-host kubelet volume directory for (replUID, pvName) by reading
// the HOST kernel mount table (/proc/self/mountinfo in the host mount namespace via the broker) and
// matching the kubelet-published mountpoint for this PV. This replaces the prior `ls -d <glob>`
// inference (which reads true for a half-created/wrong-shaped dir and false during the publish
// window): the mount table is written by the kubelet exactly when — and only when — NodePublish
// completes, and is the same bind source CRIU passes to open_tree, so a present mountpoint is the
// atomic non-flapping truth for both presence and exact shape (read the fact from its writer,
// not a proxy). The provisioner subdir (kubernetes.io~nfs, ~csi, …) is discovered, not hardcoded.
// Overridable in tests. Returns "" when nothing resolves (the volume is not yet published, or the
// pod/PV is wrong); a not-yet-published read is a legitimate bounded WAIT for the caller.
var kubeletVolumeGlobFn = func(ctx context.Context, replUID, pvName string) string {
	if replUID == "" || pvName == "" {
		return ""
	}
	// Read the host mount table in the host mount namespace (broker-delegated nsenter) — the agent's
	// own mount ns does not carry /var/lib/kubelet, and the de-privileged agent EPERMs on a local
	// setns, so it MUST go through the broker.
	out, err := nsenterCmd(ctx, "/bin/sh", "-c", "cat /proc/self/mountinfo 2>/dev/null").Output()
	if err != nil {
		return ""
	}
	return parseKubeletMountFromMountinfo(out, replUID, pvName)
}

// resolveKubeletVolumeHostPath returns the destination-host path CRIU binds the re-attach volume
// FROM (the replacement pod's kubelet-mounted volume dir), or "" if it cannot be resolved.
func resolveKubeletVolumeHostPath(ctx context.Context, replUID, pvName string) string {
	return kubeletVolumeGlobFn(ctx, replUID, pvName)
}

// pvcBackedMountPaths extracts, from a pod spec, the set of container volumeMount mountPaths whose
// named volume is a PersistentVolumeClaim. Pure/deterministic (no client) so it is unit-testable
// without a live pod. Paths are cleaned and de-duplicated; ordering is stable (first-seen,
// init-containers before app containers). This is the in-container-path half of
// resolveReattachMounts (the half the patch classifier keys on).
func pvcBackedMountPaths(pod *corev1.Pod) []string {
	pvcVolNames := make(map[string]bool)
	for _, v := range pod.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			pvcVolNames[v.Name] = true
		}
	}
	if len(pvcVolNames) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var paths []string
	collect := func(mounts []corev1.VolumeMount) {
		for _, m := range mounts {
			if !pvcVolNames[m.Name] {
				continue
			}
			p := filepath.Clean(m.MountPath)
			if p == "" || p == "." || seen[p] {
				continue
			}
			seen[p] = true
			paths = append(paths, p)
		}
	}
	for i := range pod.Spec.InitContainers {
		collect(pod.Spec.InitContainers[i].VolumeMounts)
	}
	for i := range pod.Spec.Containers {
		collect(pod.Spec.Containers[i].VolumeMounts)
	}
	return paths
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

// SingleHomeRestoredPod single-homes the CRIU-restored replacement pod onto the preserved OLD source
// IP (pm.Spec.SourcePodIP), programming eth0 into the ADR-0138 routable form the deferred SIGCONT
// resumes onto. ADR-0355 D4 makes this backfill ACTUALLY RUN on every live restore (its four
// finalizeRestore callers formerly passed namespace="", leaving it dead) and composes it with D1's
// pre-CRIU /32 scope-host add. It:
//
//  1. lists eth0's IPv4 addresses (broker-delegated `ip -o -4 addr show`, ADR-0348);
//  2. STRIPS every non-OLD address (single-home), deriving the destination gateway from a stripped
//     address whose /24 differs from the OLD IP's /24;
//  3. ASSIGNS oldIP/24 scope-global if not already present as a scope-GLOBAL address — ADR-0355 D4
//     part 3 makes `oldSeen` scope-aware so D1's oldIP/32 scope-host artifact does NOT suppress the
//     /24 add (an oldIP/32 scope host is never stripped, but only a scope-GLOBAL oldIP counts as
//     already-single-homed);
//  4. installs the destination gateway link route + onlink default + the ADR-0139 D2 reverse-path
//     route to the source CIDR;
//  5. verifies eth0 carries the OLD IP and only the OLD IP (both the D1 /32 scope-host and the /24
//     scope-global are the OLD IP, so both pass).
//
// Empty SourcePodIP → no-op (legacy/cold path unaffected). A failure here is fail-closed on an
// established-TCP restore at the finalizeRestore call site (DR-14): without the routable /24, the
// SIGCONT would resume the ESTABLISHED socket onto D1's non-routable /32 (the H3' strand).
//
// SUBSTRATE NOTE (ADR-0355 Consequences / DR-5, ADR-0330): the gateway derivation and cni0-oriented
// routes here are from the Flannel flat-overlay lineage. Their interaction with Cilium's own
// CiliumEndpoint/ipcache accounting for the stripped CNI-assigned primary is explicitly UNRECONCILED
// by ADR-0355 and DEFERRED to its DR-5 live proof + ADR-0330 (a real Cilium ipcache substrate) — not
// re-decided in this function. See ADR-0355 §Consequences and the sprint46B9 DR-5 live proof.
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

	// List eth0's IPv4 addresses inside the pod netns. `ip -o -4 addr show eth0` is netns-scoped via
	// nsenter --net (sysfs/`cat` would read the HOST's interfaces — see ReadReplVethMAC). ADR-0348:
	// routed through the netns broker (fail-closed) via the brokerNetnsExecFn seam.
	r1 := brokerNetnsExecFn(ctx, pid, "", "ip", "-o", "-4", "addr", "show", "eth0")
	if r1.SpawnErr != nil {
		return fmt.Errorf("SingleHomeRestoredPod: netns exec failed: list eth0 addrs in netns %s: %w",
			netnsPath, r1.SpawnErr)
	}
	if r1.ExitCode != 0 {
		return fmt.Errorf("SingleHomeRestoredPod: list eth0 addrs in netns %s: exit %d (%s)",
			netnsPath, r1.ExitCode, strings.TrimSpace(string(r1.Combined)))
	}
	addrs := parseEth0IPv4Addrs(string(r1.Combined))
	log.Info("SingleHomeRestoredPod: eth0 addresses before single-home (ADR-0137/0138)",
		"migration", migrationName, "restoredPID", pid, "oldIP", oldIP, "addrs", addrs)

	// ADR-0352 Strict DUAL-HOME (sprint46B9 regression fix): the preserved-IP pin need NOT be
	// honored — under Cilium cluster-pool IPAM the restored pod is legitimately assigned a FRESH
	// dest-local CNI IP that is NOT oldIP, and that fresh IP appears on eth0 as a non-OLD
	// scope-GLOBAL address. THAT address is the pod's real, Cilium-programmed, cluster-routable
	// identity: the k8s Status.PodIP the controller builds the WorkloadLivenessVerified probe
	// target from (podmigration_controller.go destPodIP := destPod.Status.PodIP), the address the
	// Service endpoint routes to, and the address dialAllowedForMigrationProbe admits
	// (migrationRestoredWorkloadIP — one source of truth, invariant #10). Single-homing onto oldIP
	// STRIPS that primary and makes the pod unreachable at the very IP everything probes and routes
	// to — the exact sprint46B9 failure ("Redis probe TCP connect to <freshCNIIP>:6379 failed:
	// connect: no route to host", sustained 240s, rollback), while TCPSequenceContinuityVerified
	// stayed True (the held socket restore itself was never the problem).
	//
	// So when a non-OLD scope-global primary is present we DUAL-HOME, not single-home: KEEP the CNI
	// primary as the routable identity AND keep oldIP present (D1's /32 scope-host, which soccr bound
	// the held ESTABLISHED socket to). The held socket egresses via the intact CNI default route with
	// src=oldIP; held-connection continuity is proven by TCPSequenceContinuityVerified and client
	// reachability by the Service ClusterIP — neither needs the pod re-homed onto oldIP. We STRIP and
	// re-home (the ADR-0138 backfill below) ONLY when no foreign scope-global primary exists (the pin
	// WAS honored, i.e. oldIP is itself the CNI primary, or a legacy replay left oldIP as the sole
	// address). The signal is the pod's OWN eth0 address set — a local source of truth with no
	// dependency on Status.PodIP having propagated yet.
	dualHomePrimary := ""
	for _, a := range addrs {
		ipOnly := a.CIDR
		if i := strings.IndexByte(ipOnly, '/'); i >= 0 {
			ipOnly = ipOnly[:i]
		}
		if ipOnly != oldIP && a.Scope == "global" {
			dualHomePrimary = ipOnly
			break
		}
	}
	if dualHomePrimary != "" {
		// DUAL-HOME: keep the CNI primary AND oldIP; do not strip, do not re-home, do not rewrite the
		// (correct, CNI-provided) routes. Verify routability for the DR-14 fail-closed contract: a
		// scope-global primary must be present (it is — dualHomePrimary) and oldIP must be present on
		// eth0 (D1's /32 scope-host, or a scope-global oldIP). If oldIP is somehow absent the held
		// socket would strand — fail closed rather than resume onto a missing bind address.
		oldPresent := false
		for _, a := range addrs {
			ipOnly := a.CIDR
			if i := strings.IndexByte(ipOnly, '/'); i >= 0 {
				ipOnly = ipOnly[:i]
			}
			if ipOnly == oldIP {
				oldPresent = true
				break
			}
		}
		if !oldPresent {
			return fmt.Errorf("SingleHomeRestoredPod: dual-home — OLD IP %s absent from eth0 (D1 /32 bind missing); held socket would strand (addrs %v)", oldIP, addrs)
		}
		log.Info("SingleHomeRestoredPod: dual-homed restored pod — kept CNI primary + preserved OLD IP (ADR-0352 Strict, sprint46B9 fix; pin not honored, no single-home strip)",
			"migration", migrationName, "restoredPID", pid, "oldIP", oldIP, "cniPrimary", dualHomePrimary, "addrs", addrs)
		return nil
	}

	// ADR-0138: the join-ns CRIU restore does NOT replay the checkpoint's inet addr/route config
	// into the pod netns — at this point eth0 carries the new CNI IP (and, from ADR-0355 D1, the
	// preserved OLD IP as a /32 scope host). Single-home onto the OLD IP: STRIP every NON-OLD
	// address, deriving the destination gateway from the on-eth0 CNI IP (host octet -> 1); then
	// ASSIGN oldIP/24 scope-global and the destination gateway/default routes.
	//
	// ADR-0355 D4 part 3 (scope-aware oldSeen): a scope-host /32 for the OLD IP is the D1 CRIU-bind
	// artifact — NEVER strip it, and do NOT let it suppress the /24 scope-global add; only a
	// scope-GLOBAL OLD-IP address counts as "already single-homed".
	oldSeen := false
	var delErrs []string
	cni0Gateway := gatewayForIP(oldIP) // fallback
	for _, a := range addrs {
		cidr := a.CIDR
		ipOnly := cidr
		if i := strings.IndexByte(cidr, '/'); i >= 0 {
			ipOnly = cidr[:i]
		}
		if ipOnly == oldIP {
			// Never strip an OLD-IP address. Only a scope-GLOBAL OLD IP suppresses the /24 add
			// (ADR-0355 D4 part 3) — a scope-host /32 (the D1 artifact) must NOT.
			if a.Scope == "global" {
				oldSeen = true
			}
			continue
		}
		// This is the new CNI IP (or any other non-OLD address). Derive the DESTINATION gateway from
		// an address whose /24 is NOT the OLD IP's /24 (an OLD-/24 leftover would yield the dead
		// SOURCE gateway and break the pod's return path); keep the OLD-/24 fallback otherwise.
		if cidr24ForIP(ipOnly) != cidr24ForIP(oldIP) {
			if gw := gatewayForIP(ipOnly); gw != "" {
				cni0Gateway = gw
			}
		}
		// Strip it so the pod is single-homed on the OLD IP (ADR-0348 broker-delegated).
		delR := brokerNetnsExecFn(ctx, pid, "", "ip", "addr", "del", cidr, "dev", "eth0")
		var delOut []byte
		var delErr error
		if delR.SpawnErr != nil {
			delErr = fmt.Errorf("netns exec failed: %w", delR.SpawnErr)
		} else if delR.ExitCode != 0 {
			delOut = delR.Combined
			delErr = fmt.Errorf("exit %d", delR.ExitCode)
		} else {
			delOut = delR.Combined
		}
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

	// ADR-0138 step 2: ASSIGN oldIP/24 scope-global to eth0 if no scope-global OLD IP is already
	// present (idempotent: tolerate EEXIST). This replaces ADR-0137's invalid assumption that CRIU
	// restored it, and is NOT suppressed by D1's oldIP/32 scope-host artifact (scope-aware oldSeen).
	if !oldSeen {
		addR := brokerNetnsExecFn(ctx, pid, "", "ip", "addr", "add", oldIP+"/24", "dev", "eth0")
		var addOut []byte
		var addErr error
		if addR.SpawnErr != nil {
			addErr = fmt.Errorf("netns exec failed: %w", addR.SpawnErr)
		} else if addR.ExitCode != 0 {
			addOut = addR.Combined
			addErr = fmt.Errorf("exit %d", addR.ExitCode)
		} else {
			addOut = addR.Combined
		}
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

	// ADR-0138 step 3: add a link route to the destination gateway and an onlink default via it, so
	// the pod can reply to host-originated (AC1) and cross-node (AC4) traffic. ADR-0139 D2: a
	// reverse-path route to the source CIDR via the gateway so replies to the source node egress
	// instead of ARPing on-link. All broker-delegated (ADR-0348), all idempotent.
	if cni0Gateway != "" {
		if linkR := brokerNetnsExecFn(ctx, pid, "", "ip", "route", "add", cni0Gateway, "dev", "eth0"); linkR.SpawnErr != nil {
			log.Info("SingleHomeRestoredPod: warning — add gateway link route", "gw", cni0Gateway, "err", linkR.SpawnErr, "op", "netns_exec")
		} else if linkR.ExitCode != 0 {
			msg := strings.TrimSpace(string(linkR.Combined))
			if !strings.Contains(strings.ToLower(msg), "exists") {
				log.Info("SingleHomeRestoredPod: warning — add gateway link route", "gw", cni0Gateway, "err", fmt.Errorf("exit %d", linkR.ExitCode), "output", msg)
			}
		}
		if defR := brokerNetnsExecFn(ctx, pid, "", "ip", "route", "replace", "default", "via", cni0Gateway, "dev", "eth0", "onlink"); defR.SpawnErr != nil {
			log.Info("SingleHomeRestoredPod: warning — set onlink default route", "gw", cni0Gateway, "err", defR.SpawnErr, "op", "netns_exec")
		} else if defR.ExitCode != 0 {
			log.Info("SingleHomeRestoredPod: warning — set onlink default route", "gw", cni0Gateway, "err", fmt.Errorf("exit %d", defR.ExitCode), "output", strings.TrimSpace(string(defR.Combined)))
		} else {
			log.Info("SingleHomeRestoredPod: installed cni0-gateway routes (ADR-0138)",
				"migration", migrationName, "restoredPID", pid, "gateway", cni0Gateway)
		}
		srcNodeCIDR := cidr24ForIP(oldIP)
		if srcNodeCIDR != "" {
			if revR := brokerNetnsExecFn(ctx, pid, "", "ip", "route", "replace", srcNodeCIDR, "via", cni0Gateway, "dev", "eth0"); revR.SpawnErr != nil {
				log.Info("SingleHomeRestoredPod: warning — set reverse-path route (ADR-0139 D2)",
					"srcNodeCIDR", srcNodeCIDR, "gw", cni0Gateway, "err", revR.SpawnErr, "op", "netns_exec")
			} else if revR.ExitCode != 0 {
				log.Info("SingleHomeRestoredPod: warning — set reverse-path route (ADR-0139 D2)",
					"srcNodeCIDR", srcNodeCIDR, "gw", cni0Gateway, "err", fmt.Errorf("exit %d", revR.ExitCode), "output", strings.TrimSpace(string(revR.Combined)))
			} else {
				log.Info("SingleHomeRestoredPod: installed reverse-path route to source CIDR via cni0 gateway (ADR-0139 D2)",
					"migration", migrationName, "restoredPID", pid, "srcNodeCIDR", srcNodeCIDR, "gateway", cni0Gateway)
			}
		}
	}

	// Verify: only the OLD IP should remain on eth0. ADR-0348 broker-delegated.
	verifyR := brokerNetnsExecFn(ctx, pid, "", "ip", "-o", "-4", "addr", "show", "eth0")
	if verifyR.SpawnErr != nil {
		return fmt.Errorf("SingleHomeRestoredPod: netns exec failed: verify eth0 addrs in netns %s: %w",
			netnsPath, verifyR.SpawnErr)
	}
	if verifyR.ExitCode != 0 {
		return fmt.Errorf("SingleHomeRestoredPod: verify eth0 addrs in netns %s: exit %d (%s)",
			netnsPath, verifyR.ExitCode, strings.TrimSpace(string(verifyR.Combined)))
	}
	remaining := parseEth0IPv4Addrs(string(verifyR.Combined))
	log.Info("SingleHomeRestoredPod: eth0 addresses after single-home (ADR-0138 AC5)",
		"migration", migrationName, "restoredPID", pid, "oldIP", oldIP, "remaining", remaining, "gateway", cni0Gateway)

	if len(delErrs) > 0 {
		return fmt.Errorf("SingleHomeRestoredPod: failed to remove %d address(es): %s",
			len(delErrs), strings.Join(delErrs, "; "))
	}
	// AC5: eth0 must carry the OLD IP and only the OLD IP (both the D1 /32 scope-host and the /24
	// scope-global are the OLD IP, so both pass).
	oldPresent := false
	for _, a := range remaining {
		cidr := a.CIDR
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
// bridge gateway from the new CNI IP (ADR-0138). SUBSTRATE NOTE (ADR-0355/ADR-0330): the ".1"
// derivation is Flannel-oriented; its correctness on Cilium is deferred to the DR-5 live proof.
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

// eth0Addr is one IPv4 address parsed from `ip -o -4 addr show eth0`, retaining BOTH the CIDR AND
// the scope token ("global"/"host"/"link"). The scope is load-bearing for SingleHomeRestoredPod's
// reachability check (ADR-0355 follow-up): a scope-GLOBAL address is the CNI-assigned routable
// primary (== Status.PodIP, the reachability the liveness probe/Service require), whereas a
// scope-HOST /32 (the D1 CRIU-bind artifact for the preserved OLD IP) is deliberately NOT counted
// as a routable primary — a pod carrying only scope-host addresses would strand.
type eth0Addr struct {
	CIDR  string
	Scope string
}

// parseEth0IPv4Addrs extracts the (CIDR, scope) pairs from `ip -o -4 addr show eth0` output.
// Each -o (oneline) line looks like: "2: eth0    inet 10.244.0.94/24 brd ... scope global eth0 ...".
func parseEth0IPv4Addrs(out string) []eth0Addr {
	var addrs []eth0Addr
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		var cidr, scope string
		for i := 0; i < len(fields); i++ {
			if fields[i] == "inet" && i+1 < len(fields) {
				cidr = fields[i+1]
			}
			if fields[i] == "scope" && i+1 < len(fields) {
				scope = fields[i+1]
			}
		}
		if cidr != "" {
			addrs = append(addrs, eth0Addr{CIDR: cidr, Scope: scope})
		}
	}
	return addrs
}

// ReadReplVethMAC reads the replacement pod's replVeth MAC for ADR-0133 D3. It prefers the
// sandbox network namespace path (the same netns the join-ns restore targeted, where the
// veth is reliably present), falling back to the restored process's own netns. The restored
// PID's /proc/<pid>/ns/net can transiently resolve to a netns without the veth right after
// CRIU exits, so the sandbox-netns read is the authoritative source. Returns "" and a
// non-nil error if both fail; the caller treats MAC collection as best-effort.
//
// ifname is the interface to read INSIDE the entered netns. It is NOT always "eth0":
// the true pod-sandbox netns exposes the pod veth as "eth0", but the PrepareDestinationNetns
// migration-netns bind mount exposes only "lo" and the migration veth peer
// (network.MigrationVethPeer == "pmdst0"). Reading "eth0" inside the migration netns returns
// "device does not exist" → empty MAC → Strict fail-closed, which is exactly the
// path-independent contract violation the ADR-0308 bind-mount fix otherwise ran into. The
// caller (finalizeNetnsPath) knows which netns it resolved and passes the matching ifname.
//
// sandboxNetnsPath may be empty (host-network or unresolved), in which case only the PID
// path is attempted.
func ReadReplVethMAC(ctx context.Context, pid int, sandboxNetnsPath, ifname string) (string, error) {
	if ifname == "" {
		ifname = "eth0"
	}
	// ADR-0348: each attempt is either a stable sandbox bind-mount path (routed to the broker
	// as NetnsPath, validated broker-side by netnsPathRe) or a live PID (routed as SrcPID, the
	// broker derives /proc/<pid>/ns/net itself) — never both for the same attempt (D3).
	type attempt struct {
		label     string // for error messages only
		netnsPath string // non-empty => broker NetnsPath attempt
		pid       int    // >0 => broker SrcPID attempt
	}
	var attempts []attempt
	if sandboxNetnsPath != "" {
		attempts = append(attempts, attempt{label: sandboxNetnsPath, netnsPath: sandboxNetnsPath})
	}
	if pid > 0 {
		attempts = append(attempts, attempt{label: "/proc/" + strconv.Itoa(pid) + "/ns/net", pid: pid})
	}
	if len(attempts) == 0 {
		return "", fmt.Errorf("ReadReplVethMAC: no netns source (pid=%d, sandboxNetnsPath=%q)", pid, sandboxNetnsPath)
	}
	// ADR-0354 D2c (bonus finding): ctx is now a leading parameter, threaded from the caller
	// (finalizeRestore, which carries a real ctx — server.go:584 — and captureRestoredVethMAC,
	// threaded in turn from joinNsRestore's ctx). Every attempt below funnels Client.do via
	// NetnsExec, so this was a Background()-rooted broker exec of the same defect class D2c
	// retires elsewhere on the restore path.
	var lastErr error
	for _, a := range attempts {
		// Read the MAC via `ip link` (netlink, net-namespace-scoped) — NOT
		// `cat /sys/class/net/<ifname>/address`. nsenter --net changes only the network
		// namespace, leaving the host's /sys mount in place, so reading sysfs would
		// return the HOST's interfaces, not the pod netns's. `ip -o link show <ifname>`
		// queries the kernel via rtnetlink scoped to the entered netns.
		r := netnsBrokerClientFn().NetnsExec(ctx, a.pid, a.netnsPath, "ip", "-o", "link", "show", ifname)
		if r.SpawnErr != nil {
			lastErr = fmt.Errorf("ReadReplVethMAC: netns exec failed via %s ip link show %s: %w", a.label, ifname, r.SpawnErr)
			continue
		}
		if r.ExitCode != 0 {
			lastErr = fmt.Errorf("ReadReplVethMAC: nsenter %s ip link show %s: %w (%s)", a.label, ifname, fmt.Errorf("exit %d", r.ExitCode), strings.TrimSpace(string(r.Combined)))
			continue
		}
		mac := parseLinkEther(string(r.Combined))
		if mac == "" {
			lastErr = fmt.Errorf("ReadReplVethMAC: no link/ether in `ip link show %s` output via %s: %s", ifname, a.label, strings.TrimSpace(string(r.Combined)))
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

// resolvedNetns records, per migration, the exact netns path AND the interface name CRIU
// joined on restore (ADR-0133), so the restore callback can read the replacement pod's replVeth
// MAC from the exact netns+interface CRIU joined rather than the restored PID's own ns/net
// (which can transiently resolve to the host netns post-restore).
//
// The ifname is load-bearing and MUST be recorded here rather than inferred downstream. Two
// different restore targets are possible and they expose DIFFERENT interfaces:
//   - ADR-0325 pod-sandbox-netns join (--join-ns net:<pod-sandbox>): the CNI-wired pod netns,
//     whose dataplane interface is "eth0".
//   - agent-staged migration netns (--join-ns net:<destNetnsFd>): holds only "lo" and the
//     migration veth peer network.MigrationVethPeer ("pmdst0"), never "eth0".
//
// joinNsRestore is the only component that knows which of these it joined, so it is the source
// of truth for the interface name. Recording it here (instead of finalizeNetnsPath re-deriving
// "pmdst0" from the mere presence of a resolved path) is the fix for the live Strict
// fail-closed: ADR-0325 retargeted the join from the migration netns to the pod sandbox netns
// (eth0), but finalizeNetnsPath still hardcoded "pmdst0", so `ip link show pmdst0` inside the
// pod sandbox netns returned "device does not exist" → empty MAC → "replVethMAC empty after
// restore" (sprint46 live-proof cycle 2).
type resolvedNetns struct {
	path   string
	ifname string
	// mac is the authoritative replacement-pod dataplane MAC CAPTURED at restore time inside
	// (path, ifname) and WRITTEN BACK here, so finalizeRestore reads it as a source-of-truth
	// VALUE rather than re-reading the recorded path on every reconcile. Empty until the first
	// successful at-restore capture latches it (ADR-0349 security write-back — Security Reviewer,
	// sprint46B2 validation cycle 1; retires the invariant-#10 recorded-path re-read that the
	// live-proof falsified). Never sourced from Status.ReplVethMAC (ADR-0349 D3) — it is the
	// agent's own kernel read.
	mac string
}

var (
	resolvedNetnsPathsMu sync.RWMutex
	resolvedNetnsPaths   = map[string]resolvedNetns{}
)

// storeResolvedNetnsPath records the netns path AND the dataplane interface name CRIU joined for
// migrationName. ifname is the interface INSIDE that netns whose MAC the replVeth handoff reads:
// "eth0" for a pod sandbox netns (ADR-0325), network.MigrationVethPeer ("pmdst0") for the
// agent-staged migration netns. An empty ifname defaults to "eth0" (the pod-sandbox convention).
func storeResolvedNetnsPath(migrationName, path, ifname string) {
	if migrationName == "" || path == "" {
		return
	}
	if ifname == "" {
		ifname = "eth0"
	}
	resolvedNetnsPathsMu.Lock()
	resolvedNetnsPaths[migrationName] = resolvedNetns{path: path, ifname: ifname}
	resolvedNetnsPathsMu.Unlock()
}

// storeResolvedNetnsMAC writes back the authoritative dataplane MAC captured AT restore time for
// migrationName — the source-of-truth VALUE finalizeRestore serves on subsequent invocations
// instead of re-reading the recorded netns path (ADR-0349 security write-back — Security Reviewer,
// sprint46B2 validation cycle 1). It is deliberately a no-op when no (path, ifname) handle was
// recorded first: a MAC has no netns to belong to without its authoritative record, and
// fabricating a bare-MAC entry would let a value leak across migrations. Idempotent: repeated
// identical write-backs converge (R5). Callers MUST have already net.ParseMAC-validated the value
// (R4); this function does not re-validate.
func storeResolvedNetnsMAC(migrationName, mac string) {
	if migrationName == "" || mac == "" {
		return
	}
	resolvedNetnsPathsMu.Lock()
	defer resolvedNetnsPathsMu.Unlock()
	rec, ok := resolvedNetnsPaths[migrationName]
	if !ok || rec.path == "" {
		return
	}
	rec.mac = mac
	resolvedNetnsPaths[migrationName] = rec
}

// restoredVethMACCaptureBudget / -Interval bound how long captureRestoredVethMAC waits for the
// CNI-wired dataplane interface to become visible in the restored process's netns before giving up.
// vars (not consts) so tests can shrink them. Sized well under the 120s live-migration hard bound
// (invariant #8): in practice the veth is already present the instant CRIU brings the process up
// (the lo-up on the SAME netns entry succeeds first), so the loop returns on the first read; the
// budget only matters for the narrow CNI-programming window and for a genuine host-network absence.
var (
	restoredVethMACCaptureBudget   = 10 * time.Second
	restoredVethMACCaptureInterval = 500 * time.Millisecond
)

// captureRestoredVethMAC is the ADR-0349 authoritative AT-RESTORE-TIME MAC capture (Security
// Reviewer, sprint46B2 validation cycle 1). At the moment CRIU has brought the restored process up
// (joinNsRestore calls it right after the loopback-up, on the SAME netns entry), it reads the
// replacement pod's dataplane-interface MAC from the restored process's OWN network namespace and
// WRITES IT BACK into the per-migration record (storeResolvedNetnsMAC). finalizeRestore then serves
// that VALUE; it never re-enters a recorded netns PATH after the fact.
//
// Why the process's OWN netns (SrcPID) and NOT the recorded bind path: the recorded
// /var/run/netns/cni-<id> handle and the restored process's netns are the SAME namespace, but they
// differ in ACCESS METHOD. The broker's path-mode nsenter EvalSymlink-resolves the bind and, on the
// live substrate, returned empty `ip link show eth0` for ~75s across ~25 controller re-invocations
// even though the pod was reachable at its pod IP (docs/sprints/sprint46B2/live-proof-cycle1.md). The
// SrcPID entry (/proc/<pid>/ns/net, routed through the broker — the agent never spawns nsenter
// directly) is the reliable one: it is exactly what the lo-up uses successfully, with zero AppArmor
// nsenter denials (live-proof criterion 3). Reading the process's own namespace is also the true
// source of truth for "where did CRIU actually put this process," immune to a recorded path going
// stale or unresolvable. This retires the invariant-#10 record-a-pointer / re-read-the-path brittle
// chain the review panel rejected, in favor of one authoritative capture keyed on the process itself.
//
// storeResolvedNetnsMAC is a no-op unless a (path, ifname) handle was recorded first, so this only
// latches on a MAC-handoff restore (a pod dataplane netns was joined); host-network / None cold
// restores have no eth0 and latch nothing. The bounded wait (invariant #8) tolerates the narrow
// window where the CNI veth is not yet visible; every attempt reads the SAME source of truth (the
// process's own netns), never a fallback chain to a different access method.
func captureRestoredVethMAC(ctx context.Context, migrationName string, pid int, ifname string) {
	if migrationName == "" || pid <= 0 {
		return
	}
	if ifname == "" {
		// Default to the interface joinNsRestore recorded for this migration
		// (recordAuthoritativeRestoreNetns records "eth0" for the pod sandbox netns) so the capture
		// reads whatever CRIU actually joined, never a hardcoded guess; eth0 if nothing recorded.
		resolvedNetnsPathsMu.RLock()
		ifname = resolvedNetnsPaths[migrationName].ifname
		resolvedNetnsPathsMu.RUnlock()
		if ifname == "" {
			ifname = "eth0"
		}
	}
	deadline := time.Now().Add(restoredVethMACCaptureBudget)
	for {
		// SrcPID entry: netnsPath == "" so ReadReplVethMAC constructs ONLY the pid attempt
		// (/proc/<pid>/ns/net via the broker) — the restored process's own netns, never a bind path.
		mac, err := readReplVethMACFn(ctx, pid, "", ifname)
		if err == nil && mac != "" {
			if _, perr := net.ParseMAC(mac); perr == nil {
				storeResolvedNetnsMAC(migrationName, mac) // R4-validated; no-op if no handle recorded
				return
			}
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(restoredVethMACCaptureInterval)
	}
}

// recordAuthoritativeRestoreNetns implements ADR-0349 R1: the single point where a
// non-host-network restore records the (path, ifname) handle that finalizeNetnsPath's Tier 1
// reads back (storeResolvedNetnsPath). Extracted out of joinNsRestore so the record-or-not
// decision is unit-testable without a real CRIU/ctr/nsenter dependency (test (d)).
//
// sandboxID == "" is the legitimate no-record case (branch 1: no MAC-handoff requirement, see
// joinNsRestore's caller-side ADR-0325 gate) — returns ("", "", nil).
// sandboxID != "" resolves the pod sandbox netns and records it with ifname "eth0" (branch 2,
// the live Strict/BestEffort path, server.go:4023 pre-extraction). A resolution error is
// returned to the caller, which MUST fail the restore rather than substitute a guess.
func recordAuthoritativeRestoreNetns(ctx context.Context, migrationName, sandboxID string) (path, ifname string, err error) {
	if sandboxID == "" {
		return "", "", nil
	}
	netnsFd, resolvedPath, rerr := resolveNetnsFromSandboxFn(ctx, nil, sandboxID)
	if rerr != nil {
		return "", "", rerr
	}
	// ADR-0125: the fd existed only for the B2 inode cross-check inside ResolveNetnsFromSandbox.
	// Close it now; CRIU joins by path, not by inherited fd.
	_ = netnsFd.Close()
	storeResolvedNetnsPath(migrationName, resolvedPath, "eth0")
	return resolvedPath, "eth0", nil
}

// ResolvedNetnsPath returns the netns path CRIU joined for migrationName, or "" if unknown.
func (s *AgentServer) ResolvedNetnsPath(migrationName string) string {
	resolvedNetnsPathsMu.RLock()
	defer resolvedNetnsPathsMu.RUnlock()
	return resolvedNetnsPaths[migrationName].path
}

// resolvedNetnsIfname returns the dataplane interface name CRIU joined for migrationName (the
// interface whose MAC the replVeth handoff reads), or "" if unknown. Keyed on the value
// joinNsRestore recorded — never inferred from the netns kind.
func (s *AgentServer) resolvedNetnsIfname(migrationName string) string {
	resolvedNetnsPathsMu.RLock()
	defer resolvedNetnsPathsMu.RUnlock()
	return resolvedNetnsPaths[migrationName].ifname
}

// resolvedNetnsMAC returns the authoritative dataplane MAC captured AT restore time and written
// back for migrationName (ADR-0349 security write-back), or "" if nothing has been captured yet.
// finalizeRestore consumes this VALUE directly to avoid re-reading the recorded netns path on
// every reconcile (invariant #10). This is the agent's own kernel read, never Status.ReplVethMAC.
func (s *AgentServer) resolvedNetnsMAC(migrationName string) string {
	resolvedNetnsPathsMu.RLock()
	defer resolvedNetnsPathsMu.RUnlock()
	return resolvedNetnsPaths[migrationName].mac
}

// finalizeNetnsPath resolves the sandbox-netns path handed to ReadReplVethMAC (via
// finalizeRestore) for migrationName.
//
// ADR-0349 R2: Tier-1-only resolution. The three inference/guess fallback tiers that used to
// live here (an in-memory destMigrationNetns bind-mount guess, a reconstructed canonical
// on-disk bind path, and a PID-terminal that fed the AppArmor-denied /proc/<pid>/ns/net read)
// are retired as unreachable-by-construction: R1 guarantees every non-host-network MAC-handoff
// (Strict/BestEffort) restore already has a gate-readable Tier-1 record
// (recordAuthoritativeRestoreNetns / storeResolvedNetnsPath), so the fallback tiers existed only
// to paper over a record that is now pinned by CI (test (d)). Returning the ifname read back
// from the source of truth — never inferred from the presence of a path — remains load-bearing:
// post-ADR-0325 the default restore joins the pod SANDBOX netns (--join-ns net:<pod-sandbox>),
// whose dataplane interface is "eth0"; joinNsRestore records whichever it actually joined.
func (s *AgentServer) finalizeNetnsPath(migrationName string) (netnsPath, ifname string) {
	if p := s.ResolvedNetnsPath(migrationName); p != "" {
		// Source of truth: joinNsRestore recorded BOTH the path and the interface it actually
		// joined for this migration (recordAuthoritativeRestoreNetns / storeResolvedNetnsPath).
		// Read that ifname back — never infer it from the presence of a resolved path (ADR-0325
		// retargeted the join from the agent-staged migration netns to the pod sandbox netns;
		// hardcoding an ifname here was the sprint46 cycle-2 live regression).
		return p, s.resolvedNetnsIfname(migrationName)
	}
	// R3 (ADR-0349): no gate-readable netns was recorded for this migration. Return the empty
	// value that drives the EXISTING Strict fail-closed branch (finalizeRestore, server.go:344-
	// 350) — do NOT guess an ifname, do NOT reconstruct a canonical bind path, do NOT fall back
	// to Status.ReplVethMAC. finalizeRestore emits the distinct R3 fail-closed string when it
	// observes netnsPath == "" here.
	log.Info("finalizeNetnsPath: no authoritative restored netns recorded — no gate-readable Tier 1 record for this migration",
		"migration", migrationName)
	return "", "eth0"
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
			if vethPeer, vErr := resolveReplVethPeer(ctx, replPID); vErr != nil {
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
	// ADR-0142 D3: fire the deferred SIGCONT for the --leave-stopped restored tree. Retained here for
	// the BestEffort / legacy-8-phase paths that still route through InjectIPHandoff; under ADR-0352
	// the Strict completion path retired injectIPHandoff and resumes via the VerifyTCP liveness path
	// instead (see resumeDeferredRestoredProcess). Idempotent — whichever fires first wins.
	s.resumeDeferredRestoredProcess(ctx, req.MigrationName)

	log.Info("InjectIPHandoff: handoff injected (ADR-0133 D2)", "migration", req.MigrationName,
		"oldPodIP", req.OldPodIp, "destVTEPMAC", resp.DestVtepMac, "probeOk", resp.ProbeOk)
	return resp, nil
}

// resumeDeferredRestoredProcess fires the ADR-0142 D3 deferred SIGCONT for a Strict restore that
// JoinNsRestore left in SIGSTOP via --leave-stopped (recorded in pendingResumePIDs). It is
// idempotent — the pending entry is consumed on a successful resume, and re-recorded on a transient
// failure so a later call retries — and safe to call from every point in the Strict completion flow
// that requires the restored workload to actually be running.
//
// ADR-0352 (sprint46B9 regression fix): the Strict completion path RETIRED injectIPHandoff (the
// controller no longer issues the InjectIPHandoff RPC for Strict — the retired OLD-IP preservation
// inference), which used to be the SOLE trigger for this SIGCONT. Left unresumed, the restored redis
// stays frozen: it completes the TCP handshake at the kernel but the SIGSTOPped process never answers
// the wire-protocol probe (respPing → i/o timeout), so WorkloadLivenessVerified fails and the
// migration rolls back at the completion deadline (observed live: restored tree in state `T`, probe
// "read tcp ...->:6379: i/o timeout"). The resume is now driven from the VerifyTCP AppProbeOnly
// (liveness) path, which the Strict ServiceVerifying phase issues AFTER TCPVerifying established
// seq-continuity (from the frozen snapshots) and DisengageHold disarmed the zero-window hold — so the
// ADR-0142 "resume only into a live datapath" ordering is preserved, keyed on the ADR-0352
// Service-continuity datapath instead of the retired OLD-IP inference. BestEffort/None never record a
// pending PID (no --leave-stopped), so this is a no-op for them.
func (s *AgentServer) resumeDeferredRestoredProcess(ctx context.Context, migrationName string) {
	s.pendingResumePIDsMu.Lock()
	resumePID, hasPending := s.pendingResumePIDs[migrationName]
	if hasPending {
		delete(s.pendingResumePIDs, migrationName)
	}
	s.pendingResumePIDsMu.Unlock()
	if !hasPending || resumePID <= 0 {
		return
	}
	socketsLiveAt := time.Now()
	// ADR-0312: the restored tree runs under containerd's default AppArmor profile; the confined main
	// agent's own profile DENIES a cross-profile SIGCONT (apparmor DENIED operation="signal"
	// signal=cont). Delegate the resume to the unconfined netns-broker. The tree has been in SIGSTOP
	// continuously since JoinNsRestore recorded it, so its PID cannot have been reused; read field 22
	// (starttime) and pass it so the broker re-verifies identity before the kill (PID-reuse guard).
	resumeStartTime, stErr := readProcStartTime(int32(resumePID))
	if stErr != nil {
		s.pendingResumePIDsMu.Lock()
		s.pendingResumePIDs[migrationName] = resumePID
		s.pendingResumePIDsMu.Unlock()
		log.Error(stErr, "resumeDeferredRestoredProcess: could not read restored PID starttime — will retry on requeue (ADR-0312)",
			"migration", migrationName, "pid", resumePID)
		return
	}
	if err := netnsbroker.NewClient().SignalPID(ctx, resumePID, int(syscall.SIGCONT), resumeStartTime); err != nil {
		s.pendingResumePIDsMu.Lock()
		s.pendingResumePIDs[migrationName] = resumePID
		s.pendingResumePIDsMu.Unlock()
		log.Error(err, "resumeDeferredRestoredProcess: deferred SIGCONT FAILED via broker — restored tree still stopped, will retry on requeue (ADR-0142 D3 / ADR-0312)",
			"migration", migrationName, "pid", resumePID)
		return
	}
	resumedAt := time.Now()
	log.Info("resumeDeferredRestoredProcess: deferred SIGCONT sent — restored tree resumed (ADR-0142 D3, seq_delta=0; ADR-0352 Strict resume no longer gated on the retired injectIPHandoff)",
		"migration", migrationName, "pid", resumePID, "resumedAt", resumedAt.UnixNano())
	if s.k8sClient != nil {
		if setErr := s.setOrderingConditions(migrationName, resumePID, socketsLiveAt, resumedAt); setErr != nil {
			log.Error(setErr, "resumeDeferredRestoredProcess: failed to set ordering conditions after deferred SIGCONT", "migration", migrationName)
		}
	}
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
func resolveReplVethPeer(ctx context.Context, replPID int) (string, error) {
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", replPID)
	// ADR-0348: routed through the netns broker (fail-closed), SrcPID (replPID is always a live
	// PID here, not a stable bind-mount path — see the D3 discussion in ADR-0348 §3).
	// ADR-0354 D2c: ctx is threaded from the sole caller, InjectIPHandoff, which carries the
	// real request ctx — this is a FORWARD/best-effort op (idempotent, non-fatal on failure), so
	// the binding is symmetric (no context.WithoutCancel; contrast D2b's Signal()).
	r := netnsBrokerClientFn().NetnsExec(ctx, replPID, "", "ip", "-o", "link", "show", "eth0")
	if r.SpawnErr != nil {
		if ctx.Err() != nil {
			metrics.BrokerExecDeadlineAbortsTotal.WithLabelValues("netns_exec").Inc()
			log.Info("ADR-0354 D2c/D7: netns_exec (veth-peer resolve) aborted on caller-deadline enforcement",
				"replPID", replPID, "ctxErr", ctx.Err())
		}
		return "", fmt.Errorf("resolveReplVethPeer: netns exec failed: ip link show eth0 in netns %s: %w",
			netnsPath, r.SpawnErr)
	}
	if r.ExitCode != 0 {
		return "", fmt.Errorf("resolveReplVethPeer: ip link show eth0 in netns %s: %w (%s)",
			netnsPath, fmt.Errorf("exit %d", r.ExitCode), strings.TrimSpace(string(r.Combined)))
	}
	out := r.Combined
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
//
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
	// ADR-0325: netnsPath is a HOST-namespace path. On the Cilium/containerd substrate it is now
	// a stable bind mount /var/run/netns/cni-<id> (mapped by sandboxNetnsPath from the OCI
	// /proc/<pid>/ns/net form via inode identity). The agent daemonset mounts the host
	// /var/run/netns at /var/run/netns (HostToContainer), so this native os.Open/stat resolves
	// the SAME bind mount the agent can open — no /proc/<pid>/ns/net AppArmor denial — and it is
	// exactly the path CRIU joins via --join-ns net:<path> in the host mount namespace.
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
func sandboxNetnsPath(ctx context.Context, sandboxID string) (string, error) {
	// `ctr containers info` prints the container record including the OCI runtime Spec.
	out, err := nsenterCmd(ctx, "ctr", "--namespace", "k8s.io", "containers", "info", sandboxID).Output()
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
			// ADR-0325 UNIVERSAL POD-NETNS INTEGRATION: some CNIs (Cilium cluster-pool on
			// containerd 2.x) record the sandbox network namespace in the OCI spec as a
			// per-process path "/proc/<pause-pid>/ns/net" rather than a stable bind mount. The
			// agent (under its AppArmor profile, in its own mount namespace) cannot open another
			// process's /proc/<pid>/ns/net — and even if it could, that path is not a durable
			// join target for CRIU across the restore. Every CNI that plumbs a pod netns ALSO
			// bind-mounts it at /var/run/netns/cni-<id> (ip-netns convention). Resolve that
			// stable bind path by NETNS INODE IDENTITY (the source of truth), not by name: read
			// the proc path's netns inode in the HOST mount namespace (where /proc is reachable)
			// and match it against the /var/run/netns/cni-* bind mounts. The returned bind path
			// is openable from the agent (via the /host-run mount) AND is exactly what CRIU joins
			// via --join-ns net:<path> in the host mount namespace. Fall back to the raw proc
			// path only if no bind mount matches (preserves prior behavior for CNIs that already
			// hand back a bind path).
			if strings.HasPrefix(ns.Path, "/proc/") && strings.HasSuffix(ns.Path, "/ns/net") {
				if bind := resolveNetnsBindByProcPath(ctx, ns.Path); bind != "" {
					log.Info("sandboxNetnsPath: mapped /proc/<pid>/ns/net to stable /var/run/netns bind by inode (ADR-0325)",
						"sandboxID", sandboxID, "procPath", ns.Path, "bindPath", bind)
					return bind, nil
				}
				log.Info("sandboxNetnsPath: could not map proc netns path to a /var/run/netns bind — returning raw proc path (ADR-0325 fallback)",
					"sandboxID", sandboxID, "procPath", ns.Path)
			}
			return ns.Path, nil
		}
	}
	return "", nil
}

// resolveNetnsBindByProcPath maps a per-process network-namespace path of the form
// "/proc/<pid>/ns/net" to the stable bind-mount path "/var/run/netns/cni-<id>" that refers to
// the SAME network namespace, matched by netns inode identity (ADR-0325). Both the inode read
// of the proc path and the inode reads of the bind mounts run in the HOST mount namespace via
// nsenterCmd (the agent's own mount namespace cannot see the host /proc/<pid> or the CNI's
// /var/run/netns bind mounts). Returns "" when no bind mount matches (caller falls back to the
// raw proc path). This is not a poll-and-hope: the netns inode is an exact kernel identity.
func resolveNetnsBindByProcPath(ctx context.Context, procPath string) string {
	// Both the proc-path inode read and the /var/run/netns bind-mount scan run in ONE `sh -c`
	// (the netns-broker's exec allowlist permits "sh" but not a bare "stat"; the shell invokes
	// the node's real stat). The shell resolves the proc-path netns inode, then scans the
	// /var/run/netns/* bind mounts for the one with the matching inode and prints it. Empty
	// output → no match → caller falls back to the raw proc path.
	script := fmt.Sprintf(
		`want=$(stat -L -c %%i %q 2>/dev/null); [ -z "$want" ] && exit 0; `+
			`for f in /var/run/netns/*; do i=$(stat -L -c %%i "$f" 2>/dev/null); `+
			`if [ "$i" = "$want" ]; then printf '%%s\n' "$f"; break; fi; done`,
		procPath)
	matchOut, err := nsenterCmd(ctx, "sh", "-c", script).Output()
	if err != nil {
		log.Error(err, "resolveNetnsBindByProcPath: proc→bind inode scan failed", "procPath", procPath)
		return ""
	}
	return strings.TrimSpace(string(matchOut))
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

// resolveCtrDumpLogPath returns the agent-visible path to runc's criu-dump.log for a task,
// trying every place it can actually land, in order of authority. runc runs CRIU with its
// working directory set to the task's `work` dir — a symlink in the run bundle that points at
// /var/lib/containerd/io.containerd.runtime.v2.task/k8s.io/<fullID> — and writes criu-dump.log
// THERE, not in the run bundle. On containerd 2.2.1 the run bundle (/host-run/containerd/...)
// therefore never contains criu-dump.log, so the old single-path read ("unreadable, no such
// file") went silent and every non-TCP ctr checkpoint failure (e.g. postgres) hard-failed with
// only runc's opaque "exit status 1" summary and no CRIU diagnostic surfaced.
//
// Resolution order (source-of-truth first):
//  1. the exact path ctr printed in its own output, if any (ctrReportedDumpLogPath).
//  2. the `work` symlink target, re-rooted onto the agent-visible containerd-state mount
//     (/host-var-lib-containerd, added to the agent container's volumeMounts). This is where
//     runc actually writes the log.
//  3. the run bundle dir (legacy path) as a last resort.
//
// The first path that exists on disk wins; if none exists the run-bundle path is returned so
// the caller's "unreadable" log still names a concrete location.
func resolveCtrDumpLogPath(taskID, ctrOutput string) string {
	const dumpLogName = "criu-dump.log"

	// (1) ctr-reported path — most authoritative (immune to short-vs-full task-ID mismatch).
	if p := ctrReportedDumpLogPath(ctrOutput); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// (2) `work` symlink target → agent-visible containerd-state mount.
	// The symlink lives in the run bundle (readable via /host-run) but its target is an absolute
	// /var/lib/containerd/... path (readable via /host-var-lib-containerd).
	workLink := filepath.Join(hostBundleDir(taskID), "work")
	if target, err := os.Readlink(workLink); err == nil {
		if p := remapWorkTargetToDumpLog(target); p != "" {
			if _, statErr := os.Stat(p); statErr == nil {
				return p
			}
		}
	}

	// (3) run bundle dir (legacy) — return unconditionally as the named fallback location.
	return filepath.Join(hostBundleDir(taskID), dumpLogName)
}

// remapWorkTargetToDumpLog re-roots a runc task `work` symlink target (an absolute
// /var/lib/containerd/... host path) onto the agent-visible containerd-state mount
// (/host-var-lib-containerd) and appends criu-dump.log. Returns "" if the target is not under
// the containerd state prefix (nothing to remap). Pure string transform, split out so the
// re-rooting is unit-testable without a real /host-run mount.
func remapWorkTargetToDumpLog(workTarget string) string {
	const hostStatePrefix = "/var/lib/containerd"
	const agentStatePrefix = "/host-var-lib-containerd"
	if !strings.HasPrefix(workTarget, hostStatePrefix) {
		return ""
	}
	agentWork := agentStatePrefix + strings.TrimPrefix(workTarget, hostStatePrefix)
	return filepath.Join(agentWork, "criu-dump.log")
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

func FindContainerTaskID(ctx context.Context, podUID string) (string, error) {
	out, err := nsenterCmd(ctx, "/usr/local/bin/ctr", "--namespace", "k8s.io", "tasks", "list").Output()
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
func ctrCheckpoint(ctx context.Context, taskID, imagesDir string, tcpEstablished bool) (int64, error) {
	// 0700: checkpoint images contain verbatim process memory and must be root-only.
	if err := os.MkdirAll(imagesDir, 0o700); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", imagesDir, err)
	}
	cmd := nsenterCmd(ctx, "/usr/local/bin/ctr", "--namespace", "k8s.io", "tasks", "checkpoint",
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
		// ADR-0213 D1/D2 + postgres live fix: read the dump log through the agent-visible host
		// mounts. resolveCtrDumpLogPath tries, in order, (1) the exact path ctr printed, (2) the
		// task `work` symlink target where runc actually writes criu-dump.log
		// (/var/lib/containerd/... re-rooted onto /host-var-lib-containerd), and (3) the run
		// bundle dir. The old code read ONLY the run bundle (/host-run/containerd/.../<taskID>/),
		// which on containerd 2.2.1 never holds the log — runc writes it in the `work` dir — so
		// the classifier went blind and every non-TCP ctr failure (postgres) hard-failed with just
		// runc's opaque "exit status 1" and no CRIU diagnostic.
		dumpLogPath := resolveCtrDumpLogPath(taskID, outStr)
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
		return 0, classifyCtrCheckpointFailure(outStr, err, dumpLogRead, tcpEstablished)
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

// classifyCtrCheckpointFailure maps a failed `ctr tasks checkpoint` invocation to a typed error
// so the Checkpoint RPC can decide whether to fall through to the raw go-criu Dump path. outStr is
// ctr's combined output with the resolved criu-dump.log appended (or not, per dumpLogRead); rawErr
// is the exec error; tcpEstablished is the tier-driven TCP preservation flag. Extracted as a pure
// function so the classification — the exact logic the postgres masked-mount live failure exercised
// (2026-07-10) — is unit-testable without shelling out to ctr/runc. Precedence:
//  1. established/in-flight TCP → ErrCtrInFlightTCP (raw CRIU re-dumps with --tcp-established).
//  2. masked-mount dump abort (criu/mount.c "doesn't have a proper root mount") → ErrCtrMaskedMount
//     (raw CRIU re-dumps carrying the dump-side --skip-mnt list ctr/runc never applied).
//  3. dump log unreadable AND TCP requested → fail-safe to ErrCtrInFlightTCP (ADR-0213 D2).
//  4. otherwise fatal (wraps rawErr).
func classifyCtrCheckpointFailure(outStr string, rawErr error, dumpLogRead, tcpEstablished bool) error {
	if strings.Contains(outStr, "In-flight") ||
		strings.Contains(outStr, "in-flight") ||
		strings.Contains(outStr, "Connected TCP socket") ||
		strings.Contains(outStr, "tcp-established") ||
		strings.Contains(outStr, "sk-inet.c") ||
		strings.Contains(outStr, "inet") {
		return fmt.Errorf("ctr tasks checkpoint: %w\noutput: %s", ErrCtrInFlightTCP, outStr)
	}
	// Masked/injected-mount dump failure (e.g. /proc/interrupts). runc's CRIU invocation via
	// `ctr tasks checkpoint` does not carry our --skip-mnt list, so CRIU's mountpoint pass aborts
	// on a masked bind it cannot resolve to a proper root — BEFORE the network pass, so no TCP
	// diagnostic is emitted and the block above does not fire. Classify it so the Checkpoint RPC
	// falls through to the raw go-criu Dump path, which DOES skip this set (dump-side skipMnts in
	// criu_checkpointer.go). Match on the CRIU mount-pass diagnostic strings from the dump log,
	// not on runc's opaque "exit status 1".
	if strings.Contains(outStr, "doesn't have a proper root mount") ||
		strings.Contains(outStr, "mount.c") ||
		strings.Contains(outStr, "Can't dump a file system") {
		return fmt.Errorf("ctr tasks checkpoint: %w\noutput: %s", ErrCtrMaskedMount, outStr)
	}
	// ADR-0213 D2 fail-safe: if the dump log was unreadable AND TCP preservation is requested, a
	// correctness-preserving migration must not hard-fail on a missing best-effort diagnostic.
	// Default to the established-TCP classification so the caller falls back to raw go-criu with
	// --tcp-established rather than aborting the migration.
	if !dumpLogRead && tcpEstablished {
		return fmt.Errorf("ctr tasks checkpoint (dump log unreadable, fail-safe TCP classification): %w\noutput: %s", ErrCtrInFlightTCP, outStr)
	}
	return fmt.Errorf("ctr tasks checkpoint: %w\noutput: %s", rawErr, outStr)
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
	"/sys", // captured by ctr checkpoint as an external mount; handled by --ext-mount-map auto in buildCRIURestoreArgs (ADR-0190)
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
func buildMaskedPathExtMountArgs(imagesDir string, reattachMountPaths []string) ([]string, error) {
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
	reattach := make(map[string]bool, len(reattachMountPaths))
	for _, p := range reattachMountPaths {
		reattach[p] = true
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
		// Shared/re-attach PVC volumes (Tier0 RWX) are preserved in the image and re-attached by
		// rewriting the recorded mount source to the destination kubelet volume dir in
		// patchCheckpointImages (CRIU binds mi->source directly for the AUTOGENERATED external and
		// bypasses --ext-mount-map). The destination pod mounts the identical RWX volume. Covered, so
		// skip without a numeric /dev/null clobber or an unmapped fail-loud.
		if reattach[e.Mountpoint] {
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
// CONTAINER's own cgroup subtree whenever the NRI-carried containerCgroupsPath is
// available (ADR-0351 D3.2 — re-pointed off the retired sandboxPausePIDOnce+cgroupV2Path
// pause-PID chain onto the same D2 resolveCgroupAnchorTarget primitive the real anchor uses,
// so this best-effort GOMAXPROCS caller and the anchor never disagree on which cgroup is the
// destination's real scope). When it is not available (or resolution fails) we fall back to
// the recorded image path if it exists on the destination, and finally to the cgroup-v2 root
// cpu.max — the restore still advances past files-reg.c:2353 in every case (S1). Best-effort:
// this value is NOT load-bearing for restore correctness (only for GOMAXPROCS accuracy), so it
// keeps its existing non-fatal fallback chain — it just no longer resolves a pause PID to get
// there.
func resolveInheritCgroupSource(recordedPath, containerCgroupsPath, podCgroupParent string) string {
	base := filepath.Base(recordedPath) // e.g. "cpu.max" — preserve the controller file name
	if containerCgroupsPath != "" {
		if anchorTarget, err := resolveCgroupAnchorTarget(containerCgroupsPath, podCgroupParent); err == nil {
			cand := filepath.Join(cgroupFsRoot, anchorTarget, base)
			if _, serr := os.Stat(cand); serr == nil {
				return cand
			}
		}
	}
	if _, err := os.Stat(recordedPath); err == nil {
		return recordedPath
	}
	return filepath.Join(cgroupFsRoot, base)
}

// NON-REGRESSION (ADR-0346 D8): the ADR-0348 twelve-site re-point of the direct-agent
// `nsenter --net=` calls onto the netns broker does NOT reorder the external-mount reattach
// (the Tier0-RWX postgres re-attach, emitted here as --ext-mount-map entries) relative to CRIU
// restore. open_tree for those ext-mounts is performed by `criu restore` ITSELF, inside the child
// process this function's argv launches; every broker-delegated netns-exec on the restore path
// (joinNsRestore's lo-up at ~server.go:4245, ReadReplVethMAC, resolveReplVethPeer, and the
// ADR-0200/0210 probe/echo) runs only AFTER that CRIU child returns (buildCRIURestoreArgs ->
// exec CRIU -> reap -> post-restore netns-exec). The re-point changes WHO runs nsenter (broker vs
// confined agent), never WHEN open_tree runs relative to CRIU return — so the postgres reattach
// ordering the next milestone rides on is preserved.
func buildCRIURestoreArgs(checkpointDir, rootfsDir, dataDir, termlogFile, secretsDir, restoreLogPath, destNetnsFd, petnsPath, hostVethName string, strictMode bool, reattachMountPaths []reattachMount) ([]string, error) {
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
		// NOTE: no "--ext-mount-map /dev/shm:/dev/shm" here. The live restore.log proves
		// /dev/shm is NOT a mount in the checkpointed container — it is a plain subdirectory
		// inside the single /dev tmpfs, which the OCI runtime recreates empty on restore. A
		// /dev/shm ext-mount-map is therefore a dead no-op (there is no /dev/shm mount to map),
		// and PostgreSQL's dynamic shared memory is routed to SysV (dynamic_shared_memory_type=sysv)
		// so CRIU content-captures it in the image rather than as a dangling /dev/shm/* files-reg
		// reference that ENOENTs on restore (files-reg.c:2353). Removing the entry deletes a false
		// signal that /dev/shm is being handled here.
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
	// Shared/re-attach PVC volumes (Tier0 RWX): the source recorded each as an AUTODETECTED external
	// mount (ext_key == CRIU's constant "CRIU:AUTOGENERATED"), and patchCheckpointImages PRESERVED it
	// in the image AND rewrote its recorded root/source to the destination kubelet volume dir (the
	// replacement pod's already-mounted volume). That image rewrite is the ACTUAL re-attach mechanism:
	// CRIU restores an autodetected external by binding from mi->source directly (get_mp_root in
	// criu/mount.c 4.2), and it BYPASSES --ext-mount-map for AUTODETECTED_MOUNT entries — so a
	// restore-side "--ext-mount-map <containerPath>:<hostTarget>" (or any mnt_id/ext_key form) is INERT
	// and is deliberately NOT emitted here (emitting it caused the postgres None/PreCopy wall: it read
	// as "handled" while CRIU silently open_tree()'d the un-rewritten SOURCE-node path and ENOENT'd at
	// mount-v2.c:319). This loop stays as the FAIL-CLOSED precondition gate: an unresolved host target
	// means the patch could not rewrite the source, so we stop here with an actionable error BEFORE
	// CRIU is ever invoked — never restore a mount whose recorded source only exists on the source
	// node. (The rewrite itself needs the mnt_id from the post-patch image, which only the patch has;
	// this function sees only (containerPath, hostTarget) and validates their resolution.)
	for _, m := range reattachMountPaths {
		if m.ContainerPath == "" {
			continue
		}
		if m.HostTarget == "" {
			return nil, fmt.Errorf("reattach host target unresolved for %s: the destination kubelet volume dir for this re-attach (Tier0 RWX) mount could not be resolved (replacement pod not found by label %s, or its kubelet volume dir not yet mounted); refusing to restore a checkpoint whose recorded external source was not rewritten to a destination path (CRIU would open_tree the source-node path and abort with ENOENT)",
				m.ContainerPath, replacementPodLabelKey)
		}
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
	return args, nil
}

// restoredPidfileName is the basename CRIU writes the restored root PID to (see --pidfile
// in buildCRIURestoreArgs). It lives in the restore dataDir (host-visible ext4).
const restoredPidfileName = "restored.pid"

// restoreDevNode is one OCI-standard character device node the restore rootfs must carry so
// CRIU's reopen-by-PATH of a workload fd whose backing file is /dev/<name> (files-reg.c:2353)
// succeeds. See joinNsRestore's provisioning loop for the grounding (pm-w2 restore.log, sprint46).
type restoreDevNode struct {
	rel          string // path relative to the rootfs root, e.g. "dev/null" (no leading slash — CRIU openat is root-relative)
	major, minor int    // fixed Linux device numbers (Documentation/admin-guide/devices.txt)
	required     bool   // true => fail CLOSED if creation fails (a workload fd is backed by it)
}

// standardRestoreDevNodes is the workload-agnostic OCI default device-node set (runc
// defaultDevices) that a container overlay image lacks: an image ships an EMPTY /dev, and the
// runtime-managed /dev tmpfs is not part of the host-mount-ns bundle rootfs we restore into. Only
// /dev/null is `required`: CRIU aborts the ENTIRE restore before writing --pidfile when a workload
// fd (e.g. redis fd 0) reopens /dev/null by path and it is absent (decoded live on pm-w2, sprint46
// live-proof cycle 1). The rest are best-effort (log-and-continue).
var standardRestoreDevNodes = []restoreDevNode{
	{rel: "dev/null", major: 1, minor: 3, required: true},
	{rel: "dev/zero", major: 1, minor: 5},
	{rel: "dev/full", major: 1, minor: 7},
	{rel: "dev/random", major: 1, minor: 8},
	{rel: "dev/urandom", major: 1, minor: 9},
	{rel: "dev/tty", major: 5, minor: 0},
}

// devNodeMknodShellCmd returns the idempotent shell command (run via the privileged netns broker's
// allowlisted "sh") that creates one device node at <rootfsDir>/<node.rel>. `umask 0000` defeats
// the broker umask so `-m 666` yields exactly crw-rw-rw- (matching the host nodes); the `[ -e ]`
// guard makes it idempotent so an NRI bundle whose runtime already populated /dev is left
// untouched. Pure (string-only) so the provisioning contract is unit-testable without a broker /
// mknod round-trip — the coverage that was absent when the missing /dev/null aborted cycle 1.
func devNodeMknodShellCmd(rootfsDir string, node restoreDevNode) string {
	p := filepath.Join(rootfsDir, node.rel)
	return fmt.Sprintf("umask 0000; [ -e %q ] || mknod -m 666 %q c %d %d", p, p, node.major, node.minor)
}

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
// reattachMountPaths are the shared/re-attach PVC mounts (resolveReattachMounts): they are
// preserved as external mounts through patchCheckpointImages (keyed on ContainerPath) and
// re-attached on restore via --ext-mount-map <ContainerPath>:<HostTarget>. Empty for stateless.
// ctx is unused by the cgroup-anchor gate as of ADR-0351 D1.2 (the retired sandboxPausePIDWaiting
// was its only ctx-consuming caller in this function) — kept in the signature because all three
// live call sites already thread one and a future consumer may need it; Go permits an unused
// parameter without error.
func joinNsRestore(ctx context.Context, migrationName, checkpointDir, imageName, containerID, destNetnsFd, sandboxID, storedHostVeth string, strictMode bool, reattachMountPaths []reattachMount, containerCgroupsPath, podCgroupParent, preservedSourceIP string) (int, []ExternalMountDroppedInfo, error) {
	// ADR-0353 R2: joinNsRestoreFn is the sole CRIU-restore chokepoint — every live call site
	// (the NRI path via (*AgentServer).JoinNsRestore, and the gRPC Restore handler's primary and
	// raw-CRIU-fallback drives) MUST acquire the single-owner in-flight restore claim
	// (claimRestore) before reaching this function. This is the self-checking invariant that
	// catches any FUTURE call site that bypasses the primitive — fail loud instead of silently
	// allowing a second concurrent CRIU-restore drive into the same destination.
	if !isRestoreClaimed(migrationName) {
		panic(fmt.Sprintf("joinNsRestore: entered for migration %q with no restore claim held — ADR-0353 R2 invariant violated (a call site is bypassing claimRestore)", migrationName))
	}
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
	pullOut, _ := nsenterCmd(ctx, "ctr", "--namespace", "k8s.io", "images", "ls", "-q").Output()
	if !strings.Contains(string(pullOut), imageName) {
		if out, err := nsenterCmd(ctx, "ctr", "--namespace", "k8s.io", "images", "pull", imageName).CombinedOutput(); err != nil {
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
	droppedMounts, patchErr := patchCheckpointImages(checkpointDir, inheritFdNamesForPatch, reattachContainerPaths(reattachMountPaths), reattachHostTargets(reattachMountPaths))
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
	rootfsDir, err := setupRestoreOverlayfs(ctx, migrationName, checkpointDir, imageName, containerID)
	if err != nil {
		return 0, nil, fmt.Errorf("setup rootfs overlayfs: %w", err)
	}

	// On any error after this point: kill placeholder to release the rootfs mount.
	// ADR-0354 D3: this is a fail-closed teardown that must still fire (and complete) even if
	// the forward migration ctx is already Done/cancelled by the time this defer runs — binding
	// to the raw ctx risks leaking a ghost placeholder container (invariant #3). Derive a bounded,
	// cancel-detached ctx at the top of the defer, same primitive as brokerCriuCmd.Signal().
	success := false
	defer func() {
		if success {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackExecBudget)
		defer cancel()
		_ = nsenterCmd(rollbackCtx, "ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()
		_ = nsenterCmd(rollbackCtx, "ctr", "--namespace", "k8s.io", "container", "rm", placeholderID).Run()
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
		if out, err := nsenterCmd(ctx, "mkdir", "-p", filepath.Join(rootfsDir, d)).CombinedOutput(); err != nil {
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
		if out, err := nsenterCmd(ctx, "sh", "-c", fmt.Sprintf("[ -e %q ] || touch %q", f, f)).CombinedOutput(); err != nil {
			log.Error(err, "setupRootfsFiles: touch failed (non-fatal)", "file", f, "out", string(out))
		}
	}
	// Populate the restore rootfs /dev with the OCI-standard device nodes before CRIU restore.
	//
	// GROUNDING (decoded live on pm-w2, sprint46 live-proof cycle 1 — NOT inferred):
	// /var/lib/podmotion/restore/redis-live-strict/data/restore.log ended with
	//   1: Error (criu/files-reg.c:2353): Can't open file dev/null on restore: No such file or directory
	//   1: Error (criu/files.c:1221): Unable to open fd=0 id=0x5
	//   Error (criu/cr-restore.c:2324): Restoring FAILED.
	// CRIU dumped the workload's fd 0 as a REG-file open of path "/dev/null" (image fd table:
	// FD 0 -> id 0x5 type 1/REG). On restore CRIU reopens that backing file by PATH relative to
	// --root <rootfsDir> (openat(root, "dev/null")). A container's /dev is a runtime-managed tmpfs
	// the OCI runtime (runc defaultDevices) populates with these nodes at container-create time; it
	// is NOT part of the overlay image and is NOT mounted into the host-mount-ns view of the bundle
	// rootfs we restore into — so /dev is empty here, the reopen ENOENTs, and CRIU ABORTS the whole
	// restore at ~0.8s BEFORE it writes --pidfile. That abort surfaced only as the misleading
	// downstream "restored process PID not found ... pidfile never appeared" symptom (the real cause
	// is the restore.log tail the caller appends). This is the classic kind->KVM substrate exposure:
	// kind's node /dev differed; the standing KVM containerd bundle leaves /dev unpopulated.
	//
	// FIX (general primitive, workload-agnostic — covers every workload with a /dev-backed fd, not
	// just this redis fd 0): create the standard char device nodes so CRIU's reopen-by-path succeeds.
	// mknod requires CAP_MKNOD, which the SD-1 de-privileged agent (privileged:false) does not hold —
	// so it is DELEGATED to the privileged broker via the already-allowlisted "sh" host-mount-ns exec
	// (execAllowlist, ADR-0231/0346), the SAME mechanism the mkdir/touch scaffolding above uses; no
	// allowlist widening. `umask 0000` defeats the broker umask so -m 666 yields exactly 0666 (match
	// the host nodes: crw-rw-rw-). Idempotent ([ -e ] guard) so an NRI bundle whose runtime already
	// populated /dev is left untouched. Major/minor are the fixed Linux mem/tty device numbers
	// (Documentation/admin-guide/devices.txt), verified against pm-w2 /dev.
	// The node list + command builder are extracted to package scope (standardRestoreDevNodes /
	// devNodeMknodShellCmd) so the provisioning contract is unit-testable — see restore_devnode_test.go.
	for _, n := range standardRestoreDevNodes {
		p := filepath.Join(rootfsDir, n.rel)
		out, err := nsenterCmd(ctx, "sh", "-c", devNodeMknodShellCmd(rootfsDir, n)).CombinedOutput()
		if err == nil {
			continue
		}
		if n.required {
			// /dev/null is the load-bearing node: CRIU reopens fd 0/1/2's /dev/null backing by path
			// under --root and aborts the ENTIRE restore before writing --pidfile if it is absent (the
			// decoded pm-w2 failure). Fail CLOSED here with the real cause rather than letting the
			// restore proceed and re-surface as the downstream "restored PID not found" symptom.
			metrics.MigrationsFailedTotal.WithLabelValues("restore_devnull_create").Inc()
			return 0, nil, fmt.Errorf("create required restore-rootfs device node %s (CRIU aborts reopening a workload fd backed by it without it): %w\n%s", p, err, string(out))
		}
		log.Error(err, "setupRootfsDevNodes: mknod failed (non-fatal)", "path", p, "out", string(out))
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
	// ADR-0349: the destNetnsFd != "" else-block that used to live here is DELETED (dead code —
	// all three joinNsRestore call sites pass destNetnsFd="" literally, so the branch never
	// executed; its comment claiming it "executes for every Strict-mode migration" was false).
	// destNetnsFd stays a live parameter (used above for hostVethName and below for
	// buildCRIURestoreArgs) — only the dead record-and-join branch is removed (D10, scope item 5).
	var petnsPath string
	if destNetnsFd == "" {
		if sandboxID == "" {
			// tcpPreservationMode=None on the gRPC Restore path (or any path where
			// s.k8sClient == nil at the caller and no self-resolve was attempted — see
			// docs/sprints/sprint46B2/template-adr-1.md §0.2 for the precise gating): no
			// sandbox ID is supplied. For cold migration (no TCP state to preserve) the
			// --join-ns net:<path> is not required — petnsPath stays empty and
			// buildCRIURestoreArgs omits --join-ns. The NRI hook path always supplies a
			// sandboxID (cmd/agent/main.go -> event.SandboxID); a Strict/BestEffort gRPC
			// restore with a live k8sClient fails closed upstream (ADR-0325 gate,
			// server.go:6587-6591 / 6774-6778) before ever reaching this branch with a live pid.
			log.Info("joinNsRestore: no sandboxID and no destNetnsFd — skipping netns join",
				"migration", migrationName)
		} else {
			// ADR-0325 / ADR-0349 R1: resolve + record the pod sandbox netns as the single
			// authoritative source finalizeNetnsPath's Tier 1 reads back. Extracted to
			// recordAuthoritativeRestoreNetns so it is table-driven-testable (test (d)).
			// ADR-0355 D3: capture the authoritative ifname (previously discarded as `_`) — it is
			// the recorded dataplane interface name ("eth0" for the pod sandbox netns), the SAME
			// value captureRestoredVethMAC reads back — so the bind-prep uses one source of truth,
			// never a fresh "eth0" literal (DR-4).
			p, ifname, rerr := recordAuthoritativeRestoreNetns(ctx, migrationName, sandboxID)
			if rerr != nil {
				return 0, nil, fmt.Errorf("resolve replacement pod sandbox netns: %w", rerr)
			}
			petnsPath = p
			log.Info("joinNsRestore: joining replacement pod netns via --join-ns net:<path> (ADR-0125)",
				"sandboxID", sandboxID, "netnsPath", petnsPath)

			// ADR-0355 D1/D3: BEFORE buildCRIURestoreArgs/CRIU, make the preserved source IP locally
			// bindable (scope-host /32, broker-delegated) inside the netns CRIU will join, so soccr's
			// bind() of the checkpointed TCP_ESTABLISHED socket finds RTN_LOCAL and does not fail with
			// soccr.c:499 EADDRNOTAVAIL. Structurally confined to this petnsPath != "" branch (a netns
			// was actually joined). Self-gated on preservedSourceIP != "" && checkpointHasEstablishedTCP
			// and fail-closed (before CRIU) on a malformed IP (DR-15) or a broker-add failure. ctx is
			// joinNsRestore's own context parameter, in scope here.
			if perr := prepPreservedSourceAddrForRestore(ctx, migrationName, checkpointDir, petnsPath, ifname, preservedSourceIP); perr != nil {
				return 0, nil, perr
			}
		}
	}

	criuArgs, err := buildCRIURestoreArgs(checkpointDir, rootfsDir, dataDir, termlogFile, secretsDir, restoreLogPath, destNetnsFd, petnsPath, hostVethName, strictMode, reattachMountPaths)
	if err != nil {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_reattach_host_target_unresolved").Inc()
		return 0, nil, err
	}
	// ADR-0124: dynamically scan the (post-patch) mountpoints-*.img for containerd masked-path
	// external mounts and append their --ext-mount-map <mnt_id>:/dev/null args. Fail loud before
	// invoking CRIU if any external mount is not safely mappable (D4).
	maskedArgs, err := buildMaskedPathExtMountArgs(checkpointDir, reattachContainerPaths(reattachMountPaths))
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
	if placeholderPIDOut, pidErr := nsenterCmd(ctx, "ctr", "--namespace", "k8s.io", "tasks", "ls", "--quiet").Output(); pidErr == nil {
		// `ctr task ls --quiet` lists running task IDs (not PIDs). Get the PID from `ctr task info`.
		if strings.Contains(string(placeholderPIDOut), placeholderIDForUmount) {
			if pidInfo, piErr := nsenterCmd(ctx, "ctr", "--namespace", "k8s.io", "task", "ls").Output(); piErr == nil {
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
		src := resolveInheritCgroupSource(c.Path, containerCgroupsPath, podCgroupParent)
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
	criuCmd := newBrokerCriuCmd(ctx, wrapperArgs...)
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
	// ADR-0354 D2b(iii): the cgroup-liveness wait is bounded by min(now+cgroupPollTimeout,
	// ctx.Deadline()), not a fixed 60s clock divorced from the caller's migration deadline —
	// this is the actual invariant-#8 overshoot fix (the fixed 60s + fixed 30s poll clocks
	// were the concrete overshoot vector, not the per-RPC 30s bound in Start()/poll()). The
	// loop also exits promptly on ctx.Err() (cancellation), not just deadline expiry.
	cgroupDeadline := time.Now().Add(cgroupPollTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(cgroupDeadline) {
		cgroupDeadline = dl
	}
	for time.Now().Before(cgroupDeadline) && ctx.Err() == nil {
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
				logTail := restoreLogTail(restoreLogPath, 4096)
				return 0, nil, fmt.Errorf("criu restore exited (exit code %d): broker-delegated wrapper\ncriu restore.log tail:\n%s\ncriu stderr:\n%s",
					exitCode, logTail, stderrTail)
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
		if ctx.Err() != nil {
			// ADR-0354 D2b/D7: the loop exited on the CALLER's deadline/cancellation, not the
			// local 60s fixed clock — record this distinctly from a genuine broker/CRIU failure
			// so post-incident review can tell "the invariant-#8 guardrail fired as designed"
			// from "CRIU actually never produced a live workload."
			metrics.BrokerExecDeadlineAbortsTotal.WithLabelValues("broker_criu_poll_cgroup").Inc()
			log.Info("ADR-0354 D2b/D7: cgroup-liveness poll loop aborted on caller-deadline enforcement",
				"migration", migrationName, "ctxErr", ctx.Err())
		}
		stderrTail := strings.TrimSpace(criuStderr.String())
		if len(stderrTail) > 4096 {
			stderrTail = stderrTail[len(stderrTail)-4096:]
		}
		logTail := restoreLogTail(restoreLogPath, 4096)
		return 0, nil, fmt.Errorf("criu restore did not produce workload PIDs in agent cgroup within %s: criu restore.log tail:\n%s\ncriu stderr:\n%s",
			cgroupPollTimeout, logTail, stderrTail)
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
	// ADR-0354 D2b(iii): bound the pidfile-resolution wait by min(remaining(ctx), 30s) instead
	// of a bare 30s literal divorced from the caller's migration deadline, and exit on
	// ctx.Err() rather than running the fixed clock out. pidfileCtxAborted distinguishes a
	// caller-deadline/cancel exit (D7) from a genuine "CRIU never wrote a pidfile" failure.
	pidfileBudget := remainingOrCeiling(ctx, 30*time.Second)
	pidfileCtxAborted := false
	pidfilePoll := func() (bool, error) {
		if ctx.Err() != nil {
			pidfileCtxAborted = true
			return true, nil
		}
		exited, _, _, perr := criuCmd.poll()
		return exited, perr
	}
	pid, err = readRestoredPIDFromPidfile(pidfilePath, pidfileBudget, pidfilePoll)
	if err != nil {
		if pidfileCtxAborted || ctx.Err() != nil {
			metrics.BrokerExecDeadlineAbortsTotal.WithLabelValues("broker_criu_poll_pidfile").Inc()
			log.Info("ADR-0354 D2b/D7: pidfile-resolution wait aborted on caller-deadline enforcement",
				"migration", migrationName, "ctxErr", ctx.Err())
		}
		// Fail loud — never fall back to comm-scan or cgroup-diff (ADR-0228 NRI/gRPC symmetry).
		// Surface the CRIU restore.log tail: a missing pidfile is usually the DOWNSTREAM symptom
		// of a restore that aborted earlier (e.g. mount-v2 open_tree on an external mount), and the
		// real cause is only in restore.log — not in this wrapper message.
		metrics.MigrationsFailedTotal.WithLabelValues("restore_pidfile_missing").Inc()
		logTail := restoreLogTail(restoreLogPath, 4096)
		return 0, nil, fmt.Errorf("resolve restored PID via CRIU --pidfile: %w\ncriu restore.log tail:\n%s", err, logTail)
	}
	// ADR-0228 Invariant 1: identity is guaranteed by --pidfile (CRIU reports the PID it
	// restored — never the wrapper/holder stub); the residual check is liveness. Defense in
	// depth: reject the impossible case where the pidfile PID coincides with the wrapper PID.
	if pid == criuWrapperPID {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_pid_equals_wrapper").Inc()
		// ADR-0351 G5: a live restored process already exists at this point — reap it (and its
		// holder) on every post-PID-live terminal leg so a fail-closed abort never leaves a
		// destination ghost. holderPID is passed explicitly (never re-derived from /proc
		// ancestry) precisely so this degenerate pid==criuWrapperPID leg cannot walk past the
		// wrapper into the broker's own process tree — see reapRestoredProcessTree's doc comment.
		reapRestoredProcessTreeFn(pid, criuWrapperPID)
		return 0, nil, fmt.Errorf("pidfile-reported PID %d equals the CRIU wrapper (holder) PID — refusing to trust", pid)
	}
	if verr := verifyRestoredPIDAlive(pid, 100*time.Millisecond); verr != nil {
		metrics.MigrationsFailedTotal.WithLabelValues("restore_pid_dead").Inc()
		reapRestoredProcessTreeFn(pid, criuWrapperPID) // ADR-0351 G5
		return 0, nil, fmt.Errorf("ADR-0228 Invariant 1: %w", verr)
	}
	log.Info("joinNsRestore: resolved restored PID via CRIU --pidfile (authoritative primitive)",
		"pid", pid, "pidfile", pidfilePath, "migration", migrationName)

	// ADR-0128/ADR-0351 D2: cgroup placement requires a pod sandbox to anchor to, so it is the
	// ONE step that still legitimately depends on sandboxID (it is NOT retired). On the NRI path
	// (sandboxID set) --manage-cgroups=ignore leaves the restored tree in the broker/launcher
	// cgroup, so move it into the CONTAINER's OWN cgroup scope (ADR-0351 D2.1 — never the
	// pause/sandbox scope Defect 2 identified) for containerd/k8s to manage. The gRPC/--join-ns
	// path has no pod sandbox (sandboxID == "") and therefore no pod cgroup to move into — that
	// case is unchanged, still skipped.
	//
	// ADR-0351 D1.2/D2: containerCgroupsPath=="" with sandboxID!="" is a SEPARATE, DISTINCT case
	// from sandboxID=="" — verified against live source this pass (server.go
	// resolvePodNetnsSandboxWaiting/ADR-0325) that the gRPC restore path DOES resolve a real,
	// non-empty sandboxID via its own self-resolve mechanism, NOT only the NRI path as originally
	// assumed. That path has no NRI ContainerEvent and therefore no NRI-carried cgroup value.
	// Reintroducing a ctr/containerd query here to backfill it would be exactly the brittle-chain
	// pattern this ADR retires (invariant #10) — so this leg SKIPS the anchor (identical
	// "no pod cgroup to move into" effect as sandboxID=="") rather than either (a) reintroducing a
	// query, or (b) fail-closed-reaping every gRPC-path restore that resolves a sandbox, which
	// would be a severe regression relative to the pre-ADR-0351 pause-PID-derived anchor that
	// DID cover this path. Tracked, not silently claimed closed — same discipline as the BD-8
	// whole-tree-containment gap: the gRPC/raw-CRIU fallback path's cgroup anchoring is a KNOWN,
	// RECORDED gap (no longer covered, where it used to be, via the retired pause-PID mechanism)
	// pending a named follow-up ADR addressing per-container cgroup resolution on the non-NRI path.
	if sandboxID != "" && containerCgroupsPath == "" {
		logCgroupAnchorOutcome(migrationName, "skipped-no-nri-cgroup-path", nil)
		log.Info("joinNsRestore: sandboxID present but no NRI-carried containerCgroupsPath (raw-CRIU/gRPC restore path) — cgroup anchor SKIPPED, restored process stays in broker cgroup (ADR-0351 D2, tracked gap — see follow-up ADR)",
			"pid", pid, "sandboxID", sandboxID, "migration", migrationName)
	} else if sandboxID != "" {
		// ADR-0351 D2.1-D2.4: resolve + confine the NRI-carried container cgroup path — pure,
		// zero-query, zero-poll, zero-retry (D1.4/BD-2).
		anchorTarget, aerr := resolveCgroupAnchorTarget(containerCgroupsPath, podCgroupParent)
		if aerr != nil {
			reapRestoredProcessTreeFn(pid, criuWrapperPID) // ADR-0351 G5
			logCgroupAnchorOutcome(migrationName, "failed-closed-resolve", aerr)
			return 0, nil, fmt.Errorf("ADR-0351: resolve cgroup anchor for sandbox %s: %w", sandboxID, aerr)
		}
		if merr := moveProcessToPodCgroup(pid, anchorTarget); merr != nil {
			reapRestoredProcessTreeFn(pid, criuWrapperPID) // ADR-0351 G5
			logCgroupAnchorOutcome(migrationName, "failed-closed-write", merr)
			return 0, nil, fmt.Errorf("ADR-0351: move restored PID %d into cgroup %s: %w", pid, anchorTarget, merr)
		}
		logCgroupAnchorOutcome(migrationName, "anchored", nil)
		log.Info("joinNsRestore: moved restored process into container's OWN cgroup (ADR-0351 D2, corrects ADR-0128 Defect 2 wrong-scope)",
			"pid", pid, "containerScope", anchorTarget, "sandboxID", sandboxID)
	}
	log.Info("joinNsRestore: found restored process", "pid", pid)

	// Step 6: ADR-0123 D4 — bring loopback up in the RESTORED application's net namespace,
	// using the PID resolved from the pod cgroup (never the CRIU PID). On the cold path this
	// is the CNI-wired pod netns (lo is normally already up); on the TCP-stateful path it is the
	// pre-staged migration netns. Idempotent either way.
	// ADR-0348: routed through the netns broker (fail-closed), SrcPID. ADR-0354 D2c: joinNsRestore
	// DOES carry a real ctx — its first parameter — so this now threads it instead of rooting on
	// context.Background(). This is a FORWARD/idempotent op (bringing lo up is a no-op if already
	// up), so the binding is symmetric — no context.WithoutCancel (contrast D2b's Signal()).
	deadlineAborted := false
	r := netnsBrokerClientFn().NetnsExec(ctx, pid, "", "ip", "link", "set", "lo", "up")
	if r.SpawnErr != nil && ctx.Err() != nil {
		deadlineAborted = true
	}
	if deadlineAborted {
		metrics.BrokerExecDeadlineAbortsTotal.WithLabelValues("netns_exec").Inc()
		log.Info("ADR-0354 D2c/D7: netns_exec (loopback-up) aborted on caller-deadline enforcement",
			"migration", migrationName, "ctxErr", ctx.Err())
	}
	if r.SpawnErr != nil {
		log.Info("joinNsRestore: warning — failed to bring up loopback", "err", r.SpawnErr, "op", "netns_exec")
	} else if r.ExitCode != 0 {
		log.Info("joinNsRestore: warning — failed to bring up loopback", "err", fmt.Errorf("exit %d", r.ExitCode), "output", string(r.Combined))
	}

	// ADR-0349 (Security Reviewer, sprint46B2 validation cycle 1): capture the authoritative
	// replVethMAC NOW — the instant CRIU has brought the restored process up — from the process's OWN
	// netns (the SAME denial-free SrcPID broker entry the lo-up just used) and write it back for
	// finalizeRestore to serve as a VALUE. This replaces the post-hoc recorded-bind-path re-read that
	// returned empty for ~75s live (live-proof-cycle1) even though the pod was reachable at its pod
	// IP. Gated on petnsPath != "" — a pod dataplane netns was joined (the MAC-handoff case);
	// host-network / None cold restores join no eth0-bearing netns and latch nothing.
	if petnsPath != "" {
		captureRestoredVethMAC(ctx, migrationName, pid, "")
	}

	success = true
	return pid, droppedMounts, nil
}

// readLogTail was removed: ADR-0127 scaffold (restore.log success-signal) removed per ADR-0192.
// The liveness signal is now the cgroup-PID diff (see joinNsRestore above).

// restoreLogTail reads the tail of CRIU's restore.log (written by criu -o restoreLogPath, running
// via nsenter in the host mount ns) so the REAL restore failure — e.g. the mount-v2 open_tree
// error that aborts before the pidfile is written — is surfaced in the failure/RPC error instead
// of only the downstream "restored PID not found" wrapper symptom. Returns "" when the log is
// absent/unreadable (CRIU may have failed before opening it, in which case the caller still has the
// captured stderr). Bounded to the last maxBytes so a large log cannot balloon the error message.
func restoreLogTail(restoreLogPath string, maxBytes int) string {
	if restoreLogPath == "" {
		return ""
	}
	b, err := os.ReadFile(restoreLogPath)
	if err != nil || len(b) == 0 {
		return ""
	}
	if maxBytes > 0 && len(b) > maxBytes {
		b = b[len(b)-maxBytes:]
	}
	return strings.TrimSpace(string(b))
}

// ADR-0200: exit codes for the __inetns_probe helper subcommand. The helper performs the
// TCP dial INSIDE the replacement pod netns (entered via nsenter by probeOldIPInPodNetns)
// and reports the refused/timeout/success classification through its exit code — preserving
// the exact isConnRefused() semantics (error-classification preservation
// across the host-netns→pod-netns relocation, same commit).
const (
	inetnsProbeExitSuccess  = 0  // SYN-ACK: a listener answered — IP live
	inetnsProbeExitRefused  = 64 // RST (ECONNREFUSED): kernel answered, no listener — IP live (success)
	inetnsProbeExitTimeout  = 65 // i/o timeout: no kernel on the path owns the IP — failure
	inetnsProbeExitOtherErr = 66 // any other dial error — failure
)

// netnsSelfExecFn / netnsSelfExecStartFn are the broker-delegated SELF-PATH exec seams for the two
// in-netns primitives that re-execute this agent's own binary (ADR-0200 __inetns_probe /
// ADR-0210 __inetns_echo). They default to the real netns-broker client calls; they exist so a
// server-package test can capture the transmitted Argv and prove the ADR-0346 D3/D5 self-path
// sentinel (netnsbroker.NetnsExecSelfToken) is what these sites send — NEVER a live
// os.Executable()/"/proc/self/exe" path, which the broker's exact-match allowlist rejects
// (discharge req 11). Same package-var test-seam idiom already used by joinNsRestoreFn.
var netnsSelfExecFn = func(ctx context.Context, replPID int, netnsPath string, argv ...string) netnsbroker.ExecResult {
	return netnsbroker.NewClient().NetnsExec(ctx, replPID, netnsPath, argv...)
}
var netnsSelfExecStartFn = func(ctx context.Context, replPID int, netnsPath string, argv ...string) (int, error) {
	return netnsbroker.NewClient().NetnsExecStart(ctx, replPID, netnsPath, argv...)
}

// probeOldIPInPodNetns performs the ADR-0200 D1 reachability probe by re-executing this same
// agent binary's __inetns_probe helper INSIDE the replacement pod's network namespace via the
// established in-tree nsenter --net=/proc/<replPID>/ns/net idiom (the same idiom used by
// SingleHomeRestoredPod (server.go:535) and resolveReplVethPeer (server.go:1182); ADR-0045 —
// no netlink/new external dependency). Dialing the OLD IP:7 from where the IP is owned returns
// RST (ECONNREFUSED) → ProbeOk=true (ADR-0200 D3: port :7 and RST=success are unchanged).
// Returns (probeOk, probeOutput) mirroring the prior in-process dial's contract exactly.
// ADR-0348 (D2, D5a, D4): routed through the netns broker (fail-closed), SrcPID. This is the
// sync (non-detached) probe site — do NOT map it to NetnsExecStart (it is a synchronous,
// classification-bearing call, not a fire-and-forget listener). The broker's ExecResult.ExitCode
// MUST carry the __inetns_probe child's real exit code (nsenter-propagated, not broker-collapsed)
// for inetnsProbeExitRefused (64) to be observably distinguishable from inetnsProbeExitTimeout
// (65) here — see doNetnsExec in internal/agent/netnsbroker/broker.go.
func probeOldIPInPodNetnsImpl(ctx context.Context, replPID int, oldPodIP string) (bool, string) {
	// ADR-0346 D3/D5: transmit the fixed self-path sentinel as argv[0], NEVER os.Executable()/
	// "/proc/self/exe". The broker's exact-match netnsExecAllowlist keys on NetnsExecSelfToken and
	// substitutes its OWN pinned self path server-side; a live binary path is not in the allowlist,
	// so it is rejected ("not in broker allowlist"), r.SpawnErr fires, and the probe fails closed on
	// every call — the datapath-dead regression discharge req 11 guards against.
	// netns broker exec: <broker-self-binary> __inetns_probe <oldIP> 7, run inside the pod netns.
	r := netnsSelfExecFn(ctx, replPID, "", netnsbroker.NetnsExecSelfToken, "__inetns_probe", oldPodIP, "7")
	if r.SpawnErr != nil {
		// D4: broker unreachable -> fail closed, advisory-only probe returns false (matches
		// the prior local exec-launch-failure behavior).
		return false, fmt.Sprintf("ADR-0200: in-netns probe exec failed: %v", r.SpawnErr)
	}
	output := strings.TrimSpace(string(r.Combined))
	switch r.ExitCode {
	case inetnsProbeExitSuccess:
		// Exit 0 — SYN-ACK success.
		return true, output
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

// probeOldIPInPodNetns is the AgentServer method seam (overridable in tests).
func (s *AgentServer) probeOldIPInPodNetns(ctx context.Context, replPID int, oldPodIP string) (bool, string) {
	return probeOldIPInPodNetnsImpl(ctx, replPID, oldPodIP)
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
	// ADR-0348 (D2, D4): launch the in-netns echo listener detached, routed through the netns
	// broker's NetnsExecStart (SrcPID) — it serves for ttl seconds then exits. Reap is handled by
	// the broker's existing asyncExecReg/doExecPoll/doExecSignal machinery (ADR-0346 D1); do not
	// re-add a local `go func(){ cmd.Wait() }()`.
	// ADR-0346 D3/D5: transmit the fixed self-path sentinel as argv[0], NEVER os.Executable()/
	// "/proc/self/exe" — the broker exact-matches NetnsExecSelfToken and substitutes its own pinned
	// self path server-side; a live binary path is rejected, startErr fires, and the listener never
	// starts (Started=false) on every call, the dead-datapath regression discharge req 11 guards.
	_, startErr := netnsSelfExecStartFn(ctx, replPID, "", netnsbroker.NetnsExecSelfToken, "__inetns_echo",
		req.ListenIp, fmt.Sprintf("%d", req.ListenPort), req.Nonce, fmt.Sprintf("%d", ttl))
	if startErr != nil {
		// D4: broker-unreachable -> Started MUST be false. Never true when no listener actually
		// started -- a downstream bug could otherwise misread the absence as a real listener.
		resp.Started = false
		resp.Detail = fmt.Sprintf("ADR-0210: netns exec failed: %v", startErr)
		log.Error(startErr, "StartReachabilityEcho: launch failed (ADR-0210)", "migration", req.MigrationName,
			"op", "netns_exec_start")
		return resp, nil
	}
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

// cgroupFsRoot is the host cgroup v2 mount point the agent writes cgroup.procs under. A package
// var (not a bare constant) so resolveCgroupAnchorTarget's confinement check and
// moveProcessToPodCgroup's write path cannot drift apart (ADR-0351 D2.4/BD-10) while still being
// overridable in tests to point at a fixture tree instead of a real host /sys/fs/cgroup.
var cgroupFsRoot = "/sys/fs/cgroup"

// isSliceToken reports whether containerCgroupsPath is a systemd cgroup-driver slice token
// ("<slice>.slice:<runtime-prefix>:<id>", 3 colon-separated fields) rather than a raw
// /sys/fs/cgroup-relative filesystem path. ADR-0351 D2.2, shape GROUNDED live (G0.2,
// docs/sprints/sprint46B7/g0-probe-adr0351-transcript.md): on this substrate
// container.GetLinux().GetCgroupsPath() always arrives in this form
// ("kubepods-burstable-pod<uid>.slice:cri-containerd:<containerID>"), never a raw path — but the
// check is written generically (colon-count + a leading path separator disqualifies) so a future
// cgroupfs-driver substrate that DOES deliver a raw path degrades to a no-op passthrough instead
// of misparsing.
func isSliceToken(containerCgroupsPath string) bool {
	if strings.HasPrefix(containerCgroupsPath, "/") {
		return false
	}
	return strings.Count(containerCgroupsPath, ":") == 2
}

// expandSliceToken expands a systemd cgroup-driver slice token
// ("<slice>.slice:<runtime-prefix>:<id>") to its real cgroup v2 filesystem leaf, relative to
// cgroupFsRoot — e.g. "kubepods-burstable-podX.slice:cri-containerd:abc" expands to
// "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podX.slice/cri-containerd-abc.scope".
// This is the standard systemd slice-unit nesting expansion (each hyphen-delimited segment of the
// slice name is its own nested ".slice" unit — the same algorithm runc's cgroups/systemd package
// uses), applied to the LIVE shape G0.2 captured (D2.2) — verified this pass to be byte-identical
// to the independently-carried PodCgroupParent field for the matching pod, which is the strongest
// available cross-check without a second live probe.
func expandSliceToken(containerCgroupsPath string) (string, error) {
	parts := strings.SplitN(containerCgroupsPath, ":", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("ADR-0351: malformed slice token %q: expected 3 colon-separated fields", containerCgroupsPath)
	}
	sliceName, runtimePrefix, id := parts[0], parts[1], parts[2]
	if runtimePrefix == "" || id == "" {
		return "", fmt.Errorf("ADR-0351: malformed slice token %q: empty runtime prefix or id", containerCgroupsPath)
	}
	slicePath, err := expandSystemdSlice(sliceName)
	if err != nil {
		return "", fmt.Errorf("ADR-0351: expand slice %q: %w", sliceName, err)
	}
	return slicePath + "/" + runtimePrefix + "-" + id + ".scope", nil
}

// expandSystemdSlice expands a systemd slice unit name (e.g.
// "kubepods-burstable-podX.slice") into its full nested cgroupfs path (e.g.
// "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podX.slice"). Pure string
// manipulation, no I/O.
func expandSystemdSlice(sliceName string) (string, error) {
	const suffix = ".slice"
	if !strings.HasSuffix(sliceName, suffix) {
		return "", fmt.Errorf("slice name %q does not end in %q", sliceName, suffix)
	}
	trimmed := strings.TrimSuffix(sliceName, suffix)
	if trimmed == "" {
		return "", fmt.Errorf("slice name %q has no content before %q", sliceName, suffix)
	}
	segments := strings.Split(trimmed, "-")
	var path, prefix strings.Builder
	for _, seg := range segments {
		if seg == "" {
			return "", fmt.Errorf("slice name %q has an empty '-'-delimited segment", sliceName)
		}
		if prefix.Len() > 0 {
			prefix.WriteByte('-')
		}
		prefix.WriteString(seg)
		path.WriteByte('/')
		path.WriteString(prefix.String())
		path.WriteString(suffix)
	}
	return path.String(), nil
}

// resolveCgroupAnchorTarget implements ADR-0351 D2: turns the NRI-carried containerCgroupsPath
// into the confined, write-safe cgroup v2 leaf path (relative to cgroupFsRoot, matching
// moveProcessToPodCgroup's existing contract), or a fail-closed error. Pure function apart from
// the filepath.EvalSymlinks confinement check (D2.4) — no exec, no query, no poll, no retry
// (D1.4/BD-2 — TestCgroupAnchor_NoQueryNoPoll polices this).
//
// containerCgroupsPath: the raw NRI-carried value — a systemd slice token on the G0.2-grounded
//
//	live shape (may be a raw /sys/fs/cgroup-relative path on some other substrate; isSliceToken
//	degrades to a passthrough in that case, per D2.2).
//
// podCgroupParent: the NRI-carried pod parent slice, used ONLY as a D2.3 validation bound — NEVER
//
//	a write target (writing into a non-leaf cgroup with children EBUSYs on cgroup v2).
func resolveCgroupAnchorTarget(containerCgroupsPath, podCgroupParent string) (string, error) {
	if containerCgroupsPath == "" {
		return "", fmt.Errorf("ADR-0351: empty ContainerCgroupsPath — fail closed (G0 precondition violated live)")
	}
	leaf := containerCgroupsPath
	if isSliceToken(leaf) {
		var err error
		leaf, err = expandSliceToken(leaf)
		if err != nil {
			return "", fmt.Errorf("ADR-0351: expand slice token %q: %w", containerCgroupsPath, err)
		}
	}

	// ADR-0351 D2.4/BD-10: real path-confinement via EvalSymlinks + prefix check — NOT lexical
	// filepath.Clean alone (which does not defeat ".." traversal composed with filepath.Join, and
	// never resolves symlinks). Reject anything that does not canonicalize under
	// cgroupFsRoot/kubepods.
	candidate := filepath.Join(cgroupFsRoot, leaf)
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("ADR-0351: resolve cgroup leaf %q: %w", candidate, err)
	}
	if !strings.HasPrefix(resolved, filepath.Join(cgroupFsRoot, "kubepods")) {
		return "", fmt.Errorf("ADR-0351: cgroup leaf %q resolves to %q, outside %s/kubepods* — refusing (path-confinement, BD-10)",
			containerCgroupsPath, resolved, cgroupFsRoot)
	}

	// ADR-0351 D2.3: never anchor at the parent slice itself (cgroup v2 no-internal-process rule
	// — writing a PID into a cgroup that has child cgroups returns EBUSY). Compare the resolved
	// leaf against the resolved parent when PodCgroupParent is populated.
	if podCgroupParent != "" {
		parentCandidate := filepath.Join(cgroupFsRoot, podCgroupParent)
		if parentResolved, perr := filepath.EvalSymlinks(parentCandidate); perr == nil && resolved == parentResolved {
			return "", fmt.Errorf("ADR-0351: cgroup anchor target %q equals the pod PARENT slice %q — refusing (cgroup v2 no-internal-process rule, D2.3)",
				resolved, parentResolved)
		}
	}

	// moveProcessToPodCgroup joins its argument onto cgroupFsRoot itself — return the leaf
	// RELATIVE to cgroupFsRoot so that contract is unchanged for its one call site.
	rel := strings.TrimPrefix(resolved, cgroupFsRoot)
	return rel, nil
}

// moveProcessToPodCgroup implements ADR-0128/ADR-0351 D2: moves pid into the container's own
// cgroup by writing it to <podCgroupPath>/cgroup.procs under /sys/fs/cgroup. A single
// cgroup.procs write moves the whole thread group of the leader; the CRIU-restored tree shares
// one cgroup, so moving the root migrates the group (whole-tree containment is scoped to that
// property — see ADR-0351 D2.6/BD-8 for the multi-process/descendant-TGID gap, not changed by
// this ADR). podCgroupPath is the cgroup v2 path (e.g. "/kubepods.slice/.../...scope").
func moveProcessToPodCgroup(pid int, podCgroupPath string) error {
	procsPath := filepath.Join("/sys/fs/cgroup", podCgroupPath, "cgroup.procs")
	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("write PID %d to %s: %w", pid, procsPath, err)
	}
	return nil
}

// reapRestoredProcessTreeFn is the production implementation of reapRestoredProcessTree.
// Overridable in tests (mirrors joinNsRestoreFn/sandboxIDForPodUIDFn) so the ADR-0351 G5
// no-ghost-on-fail-closed assertions can spy on the reap without a real host cgroupfs.
var reapRestoredProcessTreeFn = reapRestoredProcessTree

// reapRestoredProcessTree implements ADR-0351 G5: on every post-PID-live terminal leg inside
// joinNsRestore, the already-restored process tree MUST be reaped before returning the error, or
// a fail-closed abort leaves a destination ghost. Traced this pass: the pre-ADR-0351 error returns
// after the PID is live (server.go, was 4472/4476/4491/4495/4500) were bare `return 0, nil, err`
// that neither reap pid nor even surface it to the caller (the PID return position is 0), so no
// upstream Restore() unwind can reap it — the handle exists only as this function's own `pid`
// local, so the reap MUST be local and mandatory.
//
// ADR-0351 G5 REVISED (sprint46B7 round 2 — corrects a cross-migration reap / broker-suicide
// defect found in the round-1 landing). Round 1 resolved the tree to reap via cgroupV2Path(pid)
// and wrote "1" to that cgroup's cgroup.kill — but because --manage-cgroups=ignore parks the
// restored tree in the netns-broker's OWN cgroup (netnsbroker/broker.go:843-867 —
// brokerCgroupPIDs reads the BROKER's own "/proc/self/cgroup", not a per-migration scope), pid
// and holderPID are co-resident there with the broker daemon itself AND with every concurrent
// migration's restored/parked tree. Writing cgroup.kill to that shared cgroup SIGKILLs the broker
// daemon and every other concurrent restore on the node, not just this migration's ghost — a
// node-global blast radius on a leg that must be scoped to exactly one migration.
//
// The fix replaces the shared-cgroup-wide kill with a precise walk of the KERNEL's own process
// hierarchy — the authoritative primitive, not an inference: holderPID (the CRIU/wrapper process,
// passed explicitly by the caller — see joinNsRestore's criuWrapperPID, never re-derived from
// /proc ancestry, which would misresolve in the degenerate pid==criuWrapperPID leg) stays the
// restored root's OS parent after restore (server.go ~4477, "stays as the foreground workload
// parent"), so collectProcessTree(holderPID) — a direct read of /proc/<tgid>/task/<tgid>/children,
// the kernel's own child-enumeration file, populated because CONFIG_CHECKPOINT_RESTORE=y is this
// project's own mandatory kernel requirement (CLAUDE.md "Key kernel requirements") — enumerates
// holderPID, pid, and every descendant of pid in one pass, with NOTHING that belongs to the broker
// daemon or a sibling migration ever a member of that set (holderPID's only child in a restore is
// this migration's own restored root). Every enumerated PID is then SIGKILLed directly — no
// cgroup write, no shared state touched.
func reapRestoredProcessTree(pid int, holderPID int) {
	victims := collectProcessTree(holderPID)
	if !containsPID(victims, pid) {
		// Defensive: if the holder's own child enumeration somehow missed pid (e.g. it already
		// reparented), still make sure pid's own subtree is reaped explicitly — never rely on the
		// holder-rooted walk alone to cover the one PID this call exists to reap.
		victims = append(victims, collectProcessTree(pid)...)
	}
	killed := 0
	for _, v := range victims {
		if err := syscall.Kill(v, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			log.Error(err, "ADR-0351 G5: SIGKILL failed for restored-tree member — process may be left running", "pid", v, "root", pid, "holder", holderPID)
			continue
		}
		killed++
	}
	log.Info("ADR-0351 G5: reaped restored process tree on fail-closed terminal leg", "pid", pid, "holder", holderPID, "killed", killed, "total", len(victims))
}

// containsPID reports whether pid appears in pids.
func containsPID(pids []int, pid int) bool {
	for _, p := range pids {
		if p == pid {
			return true
		}
	}
	return false
}

// collectProcessTree enumerates root and every descendant TGID via the kernel's own
// /proc/<tgid>/task/<tgid>/children primitive — a direct read of the kernel's process hierarchy,
// not an inferred/polled scan of every PID on the host. This file is populated only under
// CONFIG_CHECKPOINT_RESTORE=y, which this project already mandates (CLAUDE.md "Key kernel
// requirements" — the same config gate CRIU itself needs), so the primitive is always available
// on a substrate this agent can run CRIU restores on at all. Enumeration completes fully BEFORE
// any kill is issued by the caller, so a PID exiting mid-walk cannot truncate the collected set.
// Best-effort past a read error on any one node (the process may have already exited) — the
// already-collected result is returned as-is rather than aborting the whole walk.
func collectProcessTree(root int) []int {
	seen := map[int]bool{}
	queue := []int{root}
	var all []int
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if seen[p] {
			continue
		}
		seen[p] = true
		all = append(all, p)
		childrenPath := fmt.Sprintf("/proc/%d/task/%d/children", p, p)
		data, err := os.ReadFile(childrenPath)
		if err != nil {
			continue
		}
		for _, tok := range strings.Fields(string(data)) {
			if cpid, cerr := strconv.Atoi(tok); cerr == nil {
				queue = append(queue, cpid)
			}
		}
	}
	return all
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

// cgroupV2Path (the ADR-0128-era pause-PID-derived cgroup lookup) is REMOVED as of ADR-0351 G5
// round 2 (sprint46B7): its sole remaining caller was the round-1 reapRestoredProcessTree, which
// wrote "1" to this resolved cgroup's cgroup.kill — but that cgroup is the netns-broker daemon's
// OWN shared cgroup under --manage-cgroups=ignore (netnsbroker/broker.go:843-867), so the write
// SIGKILLed the broker and every concurrent migration's restored tree on the node, not just this
// migration's ghost (cross-migration reap / broker-suicide). reapRestoredProcessTree now walks the
// kernel's own process hierarchy (collectProcessTree, below) instead of resolving or writing to
// any cgroup, so this lookup has no remaining purpose. See reapRestoredProcessTree's doc comment
// for the full defect history.

// logCgroupAnchorOutcome emits the ADR-0351 D3.1a RETARGETED G10 structured log + metric on the
// cgroup-anchor primitive's success and every terminal leg — REPLACES the deleted
// logSandboxPausePIDOutcome/"sandboxPausePIDWaiting outcome" producer (D3.3/BD-9: the deleted
// pause-PID apparatus's outcome log had NO surviving producer once that apparatus was retired).
// No "polls" field: the primitive is zero-query (D1.2), so the retired "polls>1 = race
// exercised" evidence is void — the pause-PID race it measured no longer exists. Consumed
// read-only by the D2.6 live proof (leg="nri-cgroup-anchor" identifies the NRI primary path
// executed, not the raw-CRIU fallback) and by ADR-0352's D6(f)/DR-15 (re-pointed, BD-9).
func logCgroupAnchorOutcome(migrationName, outcome string, err error) {
	log.Info("ADR-0351: cgroup-anchor outcome",
		"migration", migrationName, "leg", "nri-cgroup-anchor", "outcome", outcome)
	if err != nil {
		log.Error(err, "ADR-0351: cgroup-anchor outcome detail", "migration", migrationName)
	}
	metrics.CgroupAnchorOutcomeTotal.WithLabelValues(outcome).Inc()
}

// ReplacementSandboxNotYetCreatedError is a RETRYABLE sentinel — the pod-netns-join analogue of
// ReattachVolumeNotYetPublishedError. resolveSandboxIDForMigration returns it when the replacement
// pod is resolved (its UID is known via the authoritative podmotion.io/migration-name label) but the
// destination kubelet has NOT yet created its containerd sandbox (pause container): the pod-sandbox
// netns the ADR-0325 restore gate must join exists LATER, not never. The replacement pod is
// NodeName-pinned to the destination node (createReplacementPod), so its sandbox materializes
// asynchronously a few seconds after the scheduling gate is removed — a one-shot ctr lookup at
// restore-dispatch time legitimately races the kubelet (grounded: live-proof-cycle1, the pm-w2
// sandbox was present ~6s after the replacement pod appeared, still before the migration reached
// terminal Failed). resolvePodNetnsSandboxWaiting bounded-waits on this sentinel (the real
// kubelet-driven sandbox edge); every other resolution failure — no replacement pod at all, no UID,
// a hard ctr/containerd error — stays terminal and fails the gate closed, preserving "refuse to
// restore into a detached/non-pod namespace" (invariant preservation; a "not yet" vs "never" split,
// never a guess).
type ReplacementSandboxNotYetCreatedError struct {
	PodUID             string
	ReplacementPodName string
}

func (e *ReplacementSandboxNotYetCreatedError) Error() string {
	return fmt.Sprintf("replacement pod sandbox not yet created: no containerd sandbox for replacement pod %s (uid=%s) present on the destination node yet", e.ReplacementPodName, e.PodUID)
}

// replacementSandboxWaitBudget bounds how long the ADR-0325 restore gate waits for the replacement
// pod's real sandbox netns to appear before failing closed. It is a var (not const) so tests can
// shrink it to exercise the budget-spent fail-closed leg without a real wait. Sized well under the
// 120s live-migration hard bound (constitutional invariant #8): the sandbox appears in ~6s on the
// standing KVM substrate and this gate is reached only after checkpoint, so 60s leaves ample
// headroom while never approaching the migration cap. The incoming RPC ctx still caps it
// (context.WithTimeout takes the min), so a shorter operator deadline wins.
var replacementSandboxWaitBudget = 60 * time.Second

// replacementSandboxPollInterval is the re-probe cadence for the sandbox bounded-wait (var for tests),
// matching resolveReattachMountsWaiting's 1s kubelet-edge cadence.
var replacementSandboxPollInterval = 1 * time.Second

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
	podNs := pm.Spec.PodNamespace
	if podNs == "" {
		podNs = pm.Namespace
	}
	// Resolve the replacement pod by the migration-name LABEL (source of truth stamped by the
	// controller at creation) rather than pm.Status.ReplacementPodName, which frequently reads
	// back empty at restore time (reads the authoritative value instead of inferring it). Fall back to the status
	// field only if the label lookup finds nothing.
	pod := s.resolveReplacementPod(ctx, migrationName, podNs)
	if pod == nil {
		replName := pm.Status.ReplacementPodName
		if replName == "" {
			return "", fmt.Errorf("resolveSandboxIDForMigration: no replacement pod found for migration %s/%s by label %s and Status.ReplacementPodName is empty", ns, migrationName, replacementPodLabelKey)
		}
		p := &corev1.Pod{}
		if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: replName, Namespace: podNs}, p); err != nil {
			return "", fmt.Errorf("resolveSandboxIDForMigration: get replacement pod %s/%s: %w", podNs, replName, err)
		}
		pod = p
	}
	if pod.UID == "" {
		return "", fmt.Errorf("resolveSandboxIDForMigration: replacement pod %s/%s has no UID", podNs, pod.Name)
	}
	sandboxID, err := sandboxIDForPodUIDFn(ctx, string(pod.UID))
	if err != nil {
		// The replacement pod is resolved (its UID is known via the authoritative migration-name
		// label), but the ctr query found no containerd sandbox for it yet — the destination kubelet
		// has not created the pause container at this instant. That is the benign "not yet" race edge
		// (errNoSandboxForPodUID), NOT a detached/unresolvable namespace: surface the RETRYABLE
		// sentinel so resolvePodNetnsSandboxWaiting bounded-waits for the real sandbox netns rather
		// than failing the ADR-0325 gate closed on a race it wins within the migration budget. A hard
		// ctr error (containerd down, binary missing) is NOT errNoSandboxForPodUID and stays terminal.
		if errors.Is(err, errNoSandboxForPodUID) {
			return "", &ReplacementSandboxNotYetCreatedError{PodUID: string(pod.UID), ReplacementPodName: pod.Name}
		}
		return "", fmt.Errorf("resolveSandboxIDForMigration: %w", err)
	}
	return sandboxID, nil
}

// resolvePodNetnsSandboxOnce is the single-shot universal pod-netns-integration read (ADR-0325) for
// the gRPC Restore path. It decides which sandbox ID (if any) joinNsRestore should use to join the
// restored process into its pod's network namespace, and returns the CLASSIFIED error alongside
// (sandboxID, attempted) so resolvePodNetnsSandboxWaiting can distinguish a RETRYABLE
// "sandbox-not-created-yet" race (ReplacementSandboxNotYetCreatedError) from a terminal failure:
//
//   - destNetnsFd == "" (cold path — None, or BestEffort/Strict): resolve the replacement pod's real
//     sandbox (pause-container) netns via the restart-durable source-of-truth the idempotent-confirm
//     path uses (resolveSandboxIDForMigration → replacement-pod UID → containerd sandbox label). This
//     is what makes pod-netns join UNIVERSAL: the cold path used to skip the join and leave the
//     workload in a detached placeholder petns (unreachable at the pod IP). Returns "" on failure so
//     the caller fails closed rather than restoring into a detached namespace.
//
// Gated on s.k8sClient != nil, consistent with every other k8s-backed self-resolve/fail-closed gate
// on this path: without a running k8s client there is no source of truth to resolve the replacement
// pod's sandbox from, so self-resolve cannot even be attempted — that is a missing operator
// connection, not evidence of a detached namespace. In that case it returns ("", false, nil) and the
// caller falls back to its pre-ADR-0325 behavior (no pod-netns join attempted) rather than failing
// the restore closed. When s.k8sClient != nil, resolution failure IS evidence-bearing (the source of
// truth was consulted and came back empty/erroring) and the caller fails closed as designed.
func (s *AgentServer) resolvePodNetnsSandboxOnce(ctx context.Context, migrationName string) (sandboxID string, attempted bool, err error) {
	if s.k8sClient == nil {
		log.Info("resolvePodNetnsSandbox: no k8sClient — skipping pod-netns self-resolve (ADR-0325); restore proceeds without pod-netns join",
			"migration", migrationName)
		return "", false, nil
	}
	id, rerr := s.resolveSandboxIDForMigration(ctx, migrationName)
	if rerr != nil {
		log.Error(rerr, "resolvePodNetnsSandbox: pod-sandbox self-resolve failed (ADR-0325) — pod-netns join cannot proceed", "migration", migrationName)
		return "", true, rerr
	}
	log.Info("resolvePodNetnsSandbox: pod-netns join will use self-resolved replacement pod sandbox (ADR-0325)",
		"migration", migrationName, "sandboxID", id)
	return id, true, nil
}

// resolvePodNetnsSandboxWaiting is the bounded-wait form of the ADR-0325 pod-netns self-resolve used
// by the live restore gate. It mirrors resolveReattachMountsWaiting exactly — the sibling
// kubelet-edge wait already on this Restore path (server.go ~L952) — retrying the source-of-truth
// read (does the replacement pod's containerd sandbox exist on this node?) while AND ONLY WHILE the
// failure is the RETRYABLE ReplacementSandboxNotYetCreatedError, until the sandbox appears or the
// budget is spent.
//
// This is NOT a poll-and-guess fallback tier (invariant #10): it reads ONE authoritative value (the
// pod sandbox in containerd) at the correct time — after the destination kubelet's asynchronous
// sandbox-creation edge — exactly as resolveReattachMountsWaiting waits for the kubelet mount edge.
// Every non-retryable outcome (resolved; no k8sClient; no replacement pod at all; no UID; a hard
// ctr/containerd error) returns immediately with the unchanged (sandboxID, attempted) semantics, so
// the gate's fail-closed invariant — "refuse to restore into a detached/non-pod namespace" — is
// preserved: a genuinely-detached or unresolvable namespace never becomes a wait, and a sandbox that
// never materializes within the bound still fails closed.
func (s *AgentServer) resolvePodNetnsSandboxWaiting(ctx context.Context, migrationName string) (sandboxID string, attempted bool) {
	waitCtx, cancel := context.WithTimeout(ctx, replacementSandboxWaitBudget)
	defer cancel()
	for {
		id, att, err := s.resolvePodNetnsSandboxOnce(waitCtx, migrationName)
		var notYet *ReplacementSandboxNotYetCreatedError
		if !errors.As(err, &notYet) {
			return id, att // resolved, no-client, or a terminal error → caller's existing gate logic
		}
		select {
		case <-waitCtx.Done():
			// Budget spent: the replacement pod's sandbox never materialized within the bound. Fail
			// closed exactly as the one-shot gate did (attempted=true, empty id) — a sandbox that
			// never appears IS the detached/non-pod-namespace condition the ADR-0325 gate guards.
			log.Info("resolvePodNetnsSandboxWaiting: replacement pod sandbox did not appear within wait budget (ADR-0325) — failing closed",
				"migration", migrationName, "budget", replacementSandboxWaitBudget.String())
			return "", true
		case <-time.After(replacementSandboxPollInterval):
		}
	}
}

// errNoSandboxForPodUID is returned by sandboxIDForPodUID when the ctr query SUCCEEDS but no
// containerd sandbox exists for the pod UID yet — the destination kubelet has not created the
// replacement pod's pause container at this instant. It is deliberately distinct from a ctr command
// error (containerd down, binary missing): the empty-result case is the benign "not yet" race edge
// the ADR-0325 restore gate must bounded-wait on, NOT a detached/unresolvable namespace. Callers
// classify it via errors.Is to build the retryable ReplacementSandboxNotYetCreatedError sentinel.
var errNoSandboxForPodUID = errors.New("no sandbox container found for pod uid")

// sandboxIDForPodUIDFn is the production implementation of sandboxIDForPodUID. It is a package var
// so the ADR-0325 bounded-wait tests can inject a sandbox that appears only after N polls (modelling
// the real kubelet-driven sandbox-creation edge) without a live containerd.
var sandboxIDForPodUIDFn = sandboxIDForPodUID

// sandboxIDForPodUID resolves the containerd sandbox (pause container) task ID for the given
// pod UID via `ctr --namespace k8s.io containers list`, filtering by the io.kubernetes.pod.uid
// label. Mirrors the existing ctr-based lookup idiom (sandboxNetnsPath) — no
// new external binary dependency. Returns errNoSandboxForPodUID (wrapped) when the query succeeds
// but no sandbox exists yet, so callers can distinguish that retryable race from a hard ctr error.
func sandboxIDForPodUID(ctx context.Context, podUID string) (string, error) {
	out, err := nsenterCmd(ctx, "/usr/local/bin/ctr", "--namespace", "k8s.io", "containers", "list",
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
	return "", fmt.Errorf("%w %s", errNoSandboxForPodUID, podUID)
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
var patchCheckpointImagesFn = func(checkpointDir string, inheritFdNames []string, reattachMountPaths []string, reattachHostTargets map[string]string) error {
	_, err := patchCheckpointImages(checkpointDir, inheritFdNames, reattachMountPaths, reattachHostTargets)
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
//     inherited / sentinel mnt_id) OR already consistent (mnt_id kept): no change.
//   - 'REBIND_TO_ROOT'  a PLAIN-REG *directory* fd with an orphan mnt_id whose rebind target
//     (root_mnt_id) is sane: rebind mnt_id → root (covers both generic
//     ADR-0193 §4 orphans and ADR-0194 B-2 ext-drop lockstep). ALSO authorized
//     for a PLAIN-REG *non-directory* (REG-type) fd whose orphan mnt_id is a
//     dropped tmpfs/shm mount (ctx['tmpfs_drop_mnt_ids'], ADR-0311): tmpfs/shm
//     content does not survive a checkpoint anyway (it's memory-backed, not
//     durable), so rebinding the handle to root — rather than hard-stopping the
//     whole restore — is safe and matches the dir-fd precedent. The production
//     call site emits a WARNING for every such rebind (ADR-0245 D2 visibility)
//     and records entry_type ('DIR'|'REG') for diagnostics (ADR-0311).
//   - 'DECLINE'         a PLAIN-REG *non-directory* fd with an orphan mnt_id that is NOT a
//     dropped tmpfs/shm mount (cannot be safely rebound — would still fire
//     mount.c:3953 / P-0193-1), OR a *directory* fd whose rebind target
//     root_mnt_id is unusable (missing / not a kept mountpoint): hard-stop
//     rather than redirect the fd onto another absent mnt_id (ADR-0245 D2
//     fail-closed target validation).
//
// ctx carries the cross-image sets the decision needs: remap_ids, inherit_fd_names,
// kept_mnt_ids, ext_drop_mnt_ids, root_mnt_id, tmpfs_drop_mnt_ids (ADR-0311). The mnt_id>0 /
// open_path() discriminants are the CRIU-4.2 source-proven predicate (files-reg.c:2191-2263,
// mount.c:3946-3953).
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
    is_dir = (reg.get('mode', 0) & _S_IFMT) == _S_IFDIR
    if is_dir:
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
    # ADR-0311: a PLAIN-REG *non-directory* fd is still safely rebindable when its orphan
    # mnt_id is backed by a tmpfs/shm mount. tmpfs/shm backing storage is memory-only and
    # never survives a checkpoint regardless, so redirecting the handle to root (rather than
    # the previous dir-vs-nondir proxy that always DECLINEd non-directory orphans) fixes
    # /dev/shm-backed workloads (PostgreSQL POSIX-shmem segments) without weakening the Strict
    # guard for any other orphan class.
    #
    # ADR-0311 follow-up (live-path fix): the rebind decision is now keyed on the mount FSTYPE,
    # resolved from the mountpoints table the reconciliation pass already built, NOT solely on
    # the narrowly-seeded tmpfs_drop_mnt_ids set. The original set was seeded only from mounts
    # that were BOTH is_drop_root(e) AND fstype=='TMPFS'; a live PostgreSQL checkpoint carried a
    # /dev/shm PostgreSQL.* REG fd whose backing mnt_id (observed live: 943) resolved to a tmpfs
    # mount that was NOT in that seed set, so it fell through to DECLINE (the P-0193-1 hard-stop
    # seen live) even though it is exactly the safe tmpfs/shm rebind class. Keying on
    # ctx['mnt_fstypes'][mnt_id] ∈ TMPFS_FSTYPES (TMPFS/DEVTMPFS — the pycriu-decoded enum name
    # spellings, source-grounded in mnt.proto's fstype enum) catches every tmpfs/shm-backed
    # orphan regardless of how it was (or was not) classified in the drop pass. The pre-existing
    # tmpfs_drop_mnt_ids set is retained as a belt: an orphan whose mnt_id is a dropped tmpfs
    # mount that has already been REMOVED from mnt_fstypes (so fstype is no longer resolvable)
    # still rebinds. Guard is UNWEAKENED: an orphan whose mnt_id is absent from mnt_fstypes AND
    # tmpfs_drop_mnt_ids (a mount that simply vanished), or whose resolved fstype is non-tmpfs
    # (sysfs, overlayfs, a real persistent volume), still DECLINEs below.
    tmpfs_drop_mnt_ids = ctx.get('tmpfs_drop_mnt_ids') or set()
    mnt_fstypes = ctx.get('mnt_fstypes') or {}
    # JSON object keys are strings; the --classify-selftest path serializes mnt_fstypes as such.
    # Look up by int first (production, where keys are native ints), then by str (selftest).
    fstype_for_mnt = mnt_fstypes.get(mnt_id)
    if fstype_for_mnt is None:
        fstype_for_mnt = mnt_fstypes.get(str(mnt_id))
    # ADR-0311 live-path grounding (postgres /dev/shm P-0193-1, decoded 2026-07-10):
    # mnt_entry.fstype in CRIU's mnt.proto is a plain uint32 field carrying an enum-valued
    # code (fstype enum: DEVTMPFS=3, TMPFS=5), NOT a native protobuf enum field. pycriu's
    # pb2dict therefore decodes it as the raw INTEGER unless load() is called with pretty=True
    # (which the production patch path is NOT — patchCheckpointImages calls
    # pycriu.images.load(f) with no pretty flag). The prior ADR-0311 classifier compared the
    # decoded fstype ONLY against the enum-NAME strings ('TMPFS','DEVTMPFS'); on a real live
    # image fstype came back as int 5, so the "5 in TMPFS/DEVTMPFS" test was always False and the
    # postgres /dev/shm REG fd fell through to DECLINE -> P-0193-1 hard-stop -> restore fail.
    # The synthetic corpus that gated ADR-0311 used the string spelling, hiding the mismatch.
    # Fix: accept BOTH representations — the enum-name strings (pretty=True / selftest corpora)
    # AND the raw integer enum codes (production, pretty=False). Source of truth for the codes:
    # pycriu/images/mnt_pb2.py (TMPFS=5, DEVTMPFS=3). Guard is UNWEAKENED: only genuine
    # tmpfs/devtmpfs backings authorize the rebind; any other fstype (sysfs=2, overlayfs=17,
    # proc=1, a real persistent volume=0) still DECLINEs.
    TMPFS_FSTYPES = ('TMPFS', 'DEVTMPFS', 5, 3)
    if (fstype_for_mnt in TMPFS_FSTYPES) or (mnt_id in tmpfs_drop_mnt_ids):
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
        'tmpfs_drop_mnt_ids': set(_c.get('tmpfs_drop_mnt_ids', [])),
        # ADR-0311 follow-up: mnt_id -> fstype (enum-name string) for all mountpoints entries.
        # JSON object keys arrive as strings; classify_reg_fd tolerates int-or-str lookup.
        'mnt_fstypes': _c.get('mnt_fstypes', {}) or {},
    }
    def _entry_type(e):
        reg = e.get('reg', {}) or {}
        if (reg.get('mode', 0) & _S_IFMT) == _S_IFDIR:
            return 'DIR'
        return 'REG'
    print(json.dumps([
        {'action': classify_reg_fd(e, _ctx), 'entry_type': _entry_type(e)}
        for e in _p.get('entries', [])
    ]))
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
// reattachMountPaths is the set of in-container mount paths backed by a shared/re-attach PVC
// (Tier0 RWX). Such an external mountpoints entry is PRESERVED (not B-2 dropped) so its files.img
// REG fds classify consistent instead of orphaning into the P-0193-1 hard-stop; on restore CRIU
// re-attaches it via --ext-mount-map <path>:<path> to the identically-mounted destination volume.
// Sourced from the pod spec (resolveReattachMounts primitive), NOT a hardcoded workload
// path. Pass nil/empty for stateless workloads (prior behavior — every external entry is dropped).
//
// Idempotent: backs up originals as *.orig on first call; subsequent calls are no-ops.
// Returns (droppedMounts, error). droppedMounts is non-nil when B-2 external drops fired
// successfully; callers should emit CRIUExternalMountDropped Normal events for each entry.
func patchCheckpointImages(checkpointDir string, inheritFdNames []string, reattachMountPaths []string, reattachHostTargets map[string]string) ([]ExternalMountDroppedInfo, error) {
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
	// argv[4]: shared/re-attach PVC mount paths (preserved external mounts). Normalize nil→[].
	if reattachMountPaths == nil {
		reattachMountPaths = []string{}
	}
	reattachJSON, err := json.Marshal(reattachMountPaths)
	if err != nil {
		return nil, fmt.Errorf("marshal reattach mount paths: %w", err)
	}
	// argv[5]: shared/re-attach PVC host targets {containerPath: destination kubelet volume dir}. The
	// patch rewrites each preserved re-attach mount's recorded root/source (the SOURCE-node kubelet
	// path baked in at dump) to this destination path so CRIU auto-binds the destination volume on a
	// cross-node restore (CRIU binds mi->source directly for AUTODETECTED_MOUNT externals — it
	// bypasses --ext-mount-map, so the recorded source is the only lever). Normalize nil→{} so
	// json.Marshal emits "{}" not "null" (the script does dict.get on it).
	if reattachHostTargets == nil {
		reattachHostTargets = map[string]string{}
	}
	reattachHostTargetsJSON, err := json.Marshal(reattachHostTargets)
	if err != nil {
		return nil, fmt.Errorf("marshal reattach host targets: %w", err)
	}
	// The single REG-fd classifier (classifyRegFdPy) is prepended verbatim so the main pass and
	// the consistency re-check below both call the one classify_reg_fd() abstraction.
	// assemblePatchScript() is the SINGLE SOURCE OF TRUTH for the assembled patch script (H-19):
	// it returns classifyRegFdPy + patchCheckpointScriptBody. The corpus contract tests
	// (pycriu_corpus_test.go) run assemblePatchScript() directly — never a hand-copied reproduction —
	// so the exact script that ships is the one exercised. Any edit to the body lands in the tests
	// automatically; there is no divergent test copy to drift out of sync.
	patchScript := assemblePatchScript()
	// /dev/shm is an in-memory filesystem (tmpfs) — avoids writing the script to disk.
	// 0600 so only root can read the path; removed immediately after exec.
	scriptPath := "/dev/shm/pm-patch-ckpt.py"
	if err := os.WriteFile(scriptPath, []byte(patchScript), 0o600); err != nil {
		return nil, fmt.Errorf("write patch script: %w", err)
	}
	defer os.Remove(scriptPath)
	// argv[1]=checkpointDir argv[2]=maskedJSON argv[3]=inheritJSON (C-R3-1) argv[4]=reattachJSON
	// argv[5]=reattachHostTargetsJSON (destination kubelet dirs for the cross-node source rewrite).
	cmd := exec.Command("python3", scriptPath, checkpointDir, string(maskedJSON), string(inheritJSON), string(reattachJSON), string(reattachHostTargetsJSON))
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
					FdID         int    `json:"fd_id"`
					NameLeaf     string `json:"name_leaf"`
					BackingMntID int    `json:"backing_mnt_id"`
					// ADR-0193 P-0193-1 grounding: decoded backing-mount fstype/mountpoint.
					// Absent on older marker lines — the zero value ("") is handled downstream.
					BackingFstype     string `json:"backing_fstype"`
					BackingMountpoint string `json:"backing_mountpoint"`
				}
				if jsonErr := json.Unmarshal([]byte(payload), &parsed); jsonErr == nil {
					// ADR-0193 P-0193-1b / SEC-EVENT-1: the full mountpoint path is logged
					// ONLY here (0700-bounded agent log), never in the world-readable Event.
					log.Info("patchCheckpointImages: P-0193-1 hard-stop (orphan REG fd not in kept mountpoints)",
						"fd_id", parsed.FdID,
						"name_leaf", parsed.NameLeaf,
						"backing_mnt_id", parsed.BackingMntID,
						"backing_fstype", parsed.BackingFstype,
						"backing_mountpoint", parsed.BackingMountpoint,
					)
					return nil, &CRIUImageInconsistencyError{
						FdID:              parsed.FdID,
						NameLeaf:          parsed.NameLeaf,
						BackingMntID:      parsed.BackingMntID,
						BackingFstype:     parsed.BackingFstype,
						BackingMountpoint: parsed.BackingMountpoint,
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

// brokerCriuOpTimeout (ADR-0354 D2b) is the per-RPC upper clamp for a single
// brokerCriuCmd Start()/poll() round-trip (exec_start / exec_poll). It is the promoted,
// named form of the previous bare `30 * time.Second` literal — the value is unchanged,
// only its role changes: it is now a CEILING combined with the caller ctx via
// remainingOrCeiling (min(remaining(ctx), brokerCriuOpTimeout)), never a floor.
const brokerCriuOpTimeout = 30 * time.Second

// rollbackExecBudget (ADR-0354 D3/D2b) bounds every fail-closed rollback/abort broker exec —
// the CRIU-wrapper Signal() kill (D2b) and the rollback cleanup execs (D3) — once the forward
// migration ctx is already Done. It is deliberately SHORT relative to brokerExecTimeout/
// brokerCriuOpTimeout: rollback is entered precisely because the forward budget was exhausted,
// and ADR-0353's single-owner restore lock must not be held open by a wedged rollback exec.
// 10s is chosen as comfortably above the broker's normal exec_signal/exec round-trip (well
// under 1s on a healthy node, per the runtime-dependency audit) while staying an order of
// magnitude below brokerCriuOpTimeout (30s) and two orders below brokerExecTimeout (5m) — short
// enough that a rollback exec that blows this budget is unambiguously wedged, not just slow.
const rollbackExecBudget = 10 * time.Second

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
	ctx  context.Context
	argv []string
}

// remainingOrCeiling returns the smaller of ctx's remaining budget and ceiling. When ctx
// carries no deadline, the ceiling itself is returned (ADR-0354 D2/D2b: the ceiling is only
// ever an upper clamp for a caller with no deadline, never a floor that widens a shorter
// caller budget).
func remainingOrCeiling(ctx context.Context, ceiling time.Duration) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining < ceiling {
			if remaining < 0 {
				return 0
			}
			return remaining
		}
	}
	return ceiling
}

// brokerExecBudget returns the D2 clamp for a brokerCmd exec: min(remaining(ctx),
// brokerExecTimeout). This can only tighten, never widen, the effective ceiling.
func brokerExecBudget(ctx context.Context) time.Duration {
	return remainingOrCeiling(ctx, brokerExecTimeout)
}

func (b *brokerCmd) result() netnsbroker.ExecResult {
	callerCtx := b.ctx
	if callerCtx == nil {
		// Defensive fallback only — every call site is required (D1/D6.3) to construct
		// brokerCmd via nsenterCmd(ctx, ...), which always sets ctx. A nil here means a
		// future call site bypassed nsenterCmd; do not silently root in Background().
		callerCtx = context.Background()
	}
	budget := brokerExecBudget(callerCtx)
	ctx, cancel := context.WithTimeout(callerCtx, budget)
	defer cancel()
	result := netnsBrokerClientFn().Exec(ctx, budget, b.argv...)
	if ctx.Err() != nil && result.SpawnErr != nil {
		metrics.BrokerExecDeadlineAbortsTotal.WithLabelValues("broker_cmd").Inc()
		log.Info("ADR-0354 D2/D7: broker exec aborted on caller-deadline enforcement, not a broker failure",
			"argv", b.argv, "ctxErr", ctx.Err())
	}
	return result
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
func nsenterCmd(ctx context.Context, args ...string) *brokerCmd {
	return &brokerCmd{ctx: ctx, argv: args}
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
	// ctx is the caller's restore/migration ctx (ADR-0354 D2b), threaded from
	// joinNsRestore's ctx parameter at construction (newBrokerCriuCmd). Start()/poll()
	// derive their per-RPC budget from it; Signal() deliberately does NOT bind to it
	// directly (see Signal's comment) — the asymmetric abort leg.
	ctx        context.Context
	argv       []string
	wrapperPID int
	Stderr     *bytes.Buffer
}

func (c *brokerCriuCmd) Pid() int { return c.wrapperPID }

// brokerCriuOpBudget returns the D2b clamp for a single Start()/poll() RPC:
// min(remaining(ctx), brokerCriuOpTimeout). Tighten-only, same discipline as D2/D6.4.
func brokerCriuOpBudget(ctx context.Context) time.Duration {
	return remainingOrCeiling(ctx, brokerCriuOpTimeout)
}

// Start spawns the wrapper detached via the broker and records its host PID. Forward op —
// bound to the caller ctx (ADR-0354 D2b), never context.Background().
func (c *brokerCriuCmd) Start() error {
	budget := brokerCriuOpBudget(c.ctx)
	ctx, cancel := context.WithTimeout(c.ctx, budget)
	defer cancel()
	pid, err := netnsBrokerClientFn().ExecStart(ctx, c.argv...)
	if err != nil {
		return err
	}
	c.wrapperPID = pid
	return nil
}

// poll returns whether the wrapper has exited, its exit code (valid only when
// exited), and the broker-cgroup PID set for the liveness diff. It also refreshes
// the Stderr buffer from the broker-side capture so the failure path can surface
// CRIU's stderr exactly as the local-nsenter path did. Forward op — bound to the
// caller ctx (ADR-0354 D2b), never context.Background().
func (c *brokerCriuCmd) poll() (exited bool, exitCode int, cgroupPIDs []int, err error) {
	budget := brokerCriuOpBudget(c.ctx)
	ctx, cancel := context.WithTimeout(c.ctx, budget)
	defer cancel()
	pr, perr := netnsBrokerClientFn().ExecPoll(ctx, c.wrapperPID)
	if perr != nil {
		return false, 0, nil, perr
	}
	if len(pr.Stderr) > 0 {
		c.Stderr.Reset()
		c.Stderr.Write(pr.Stderr)
	}
	return !pr.Running, pr.ExitCode, pr.CgroupPIDs, nil
}

// Signal asks the broker to deliver sig to the wrapper (Abort/kill path). This is the
// deliberately-ASYMMETRIC leg (ADR-0354 D2b): it is invoked precisely when c.ctx is already
// Done() (operator Abort, or forward-deadline expiry), so binding it to c.ctx directly would
// make do() compute an already-past deadline and fail the exec_signal RPC WITHOUT delivering
// the kill — orphaning the CRIU wrapper AND the CRIU-restored process tree on the destination
// (a destination ghost, invariant #3). context.WithoutCancel(c.ctx) severs the Done-ness of the
// expired forward ctx while rollbackExecBudget still hard-bounds the kill, so it both (a) still
// fires when the forward ctx is Done and (b) cannot hold ADR-0353's restore lock open past
// rollbackExecBudget.
func (c *brokerCriuCmd) Signal(sig int) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.ctx), rollbackExecBudget)
	defer cancel()
	return netnsBrokerClientFn().ExecSignal(ctx, c.wrapperPID, sig)
}

// newBrokerCriuCmd builds a broker-backed CRIU wrapper command for the given argv, bound to
// the caller's restore/migration ctx (ADR-0354 D2b) — threaded from joinNsRestore's ctx
// parameter at the construction site.
func newBrokerCriuCmd(ctx context.Context, args ...string) *brokerCriuCmd {
	return &brokerCriuCmd{ctx: ctx, argv: args, Stderr: &bytes.Buffer{}}
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
func setupRestoreOverlayfs(ctx context.Context, migrationName, checkpointDir, imageName, containerID string) (string, error) {
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
					lsOut, lsErr := nsenterCmd(ctx, "ls", "-A", containerRootfs).Output()
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
	taskOut, _ := nsenterCmd(ctx, "ctr", "--namespace", "k8s.io", "tasks", "ls", "--quiet").Output()
	placeholderRunning := strings.Contains(string(taskOut), placeholderID)
	if placeholderRunning && hostOverlayMounted() {
		log.Info("setupRestoreOverlayfs: placeholder rootfs already present (overlay confirmed)", "rootfs", rootfsDir)
		return rootfsDir, nil
	}

	// Kill any stale placeholder from a previous attempt.
	// ADR-0354 D3: this is a fail-closed ghost-container teardown (the placeholder is an orphan
	// left by a prior cancelled/failed attempt) and must still fire even if the CURRENT forward
	// ctx is already Done/cancelled by the time it runs — binding to the raw ctx risks leaking
	// that ghost placeholder (invariant #3). Derive a bounded, cancel-detached ctx, same primitive
	// as brokerCriuCmd.Signal() and the joinNsRestore placeholder-teardown defer.
	rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackExecBudget)
	defer rollbackCancel()
	_ = nsenterCmd(rollbackCtx, "ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()
	_ = nsenterCmd(rollbackCtx, "ctr", "--namespace", "k8s.io", "container", "rm", placeholderID).Run()
	// Remove stale bundle dir left by containerd (containerd does not auto-clean on kill).
	// This is necessary so containerd can create a fresh bundle with a properly mounted overlay.
	// Use nsenterCmd since the agent container cannot access /run/containerd/... directly.
	if out, err := nsenterCmd(rollbackCtx, "rm", "-rf", bundleDir).CombinedOutput(); err != nil {
		// Non-fatal — bundleDir may not exist; ctr run will create a fresh one.
		log.Info("setupRestoreOverlayfs: rm stale bundleDir (non-fatal)", "dir", bundleDir, "err", err, "out", string(out))
	}

	// Launch a placeholder container inside the host mount namespace so containerd prepares
	// the overlayfs snapshot layers. nsenterCmd ensures ctr runs in the host mount namespace
	// (necessary because containerd resolves temp paths like /tmp in the host namespace).
	runOut, err := nsenterCmd(ctx, "ctr", "--namespace", "k8s.io", "run",
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
		lsOut, lsErr := nsenterCmd(ctx, "ls", rootfsDir).Output()
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
func (s *AgentServer) Checkpoint(ctx context.Context, req *agentpb.CheckpointRequest) (*agentpb.CheckpointResponse, error) {
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

	// Resolve the container root PID from the pod UID. The freshly-fetched CR's
	// spec.SourcePodUID (fetched live above, not merely on restart) is authoritative — the
	// in-memory map (written once by PrepareSource, never evicted mid-migration) is a fallback
	// ONLY for when no k8sClient is wired (test/stub paths). CheckpointRequest carries no PodUid
	// field of its own to prefer, unlike ArmZeroWindow/DisarmZeroWindow — the CR is the fresh
	// source of truth here (sprint46B9 pre-work diagnosis).
	s.migrationPodUIDMu.RLock()
	cachedPodUID := s.migrationPodUID[req.MigrationName]
	s.migrationPodUIDMu.RUnlock()
	podUID := cachedPodUID
	if s.k8sClient != nil {
		if pm.Spec.SourcePodUID == "" {
			return nil, fmt.Errorf("checkpoint: SourcePodUID is empty in CR — " +
				"controller has not completed Validating yet")
		}
		var stale bool
		podUID, stale = authoritativePodUID(cachedPodUID, pm.Spec.SourcePodUID)
		if stale {
			log.Info("Checkpoint: stale migrationPodUID cache detected — preferring fresh CR spec.SourcePodUID",
				"migration", req.MigrationName, "cachedUID", cachedPodUID, "freshUID", pm.Spec.SourcePodUID)
		}
		// Repopulate the map so subsequent calls in this agent session see the current value.
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
		taskID, taskErr := FindContainerTaskID(ctx, podUID)
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
			sizeBytes, ctrErr := ctrCheckpoint(ctx, taskID, imagesDir, tcpEstablished)
			freezeDurationMs := time.Since(freezeStart).Milliseconds()

			if ctrErr != nil {
				// Fall through to raw CRIU for two recoverable ctr-checkpoint failure classes:
				//  1. in-flight/established TCP sockets — ctr invokes CRIU without --tcp-established,
				//     so active TCP connections fail. The raw go-criu Dump path below sets
				//     TcpEstablished=tcpEstablished (ADR-0131 D2), preserving them via TCP_REPAIR.
				//  2. masked-mount dump failure (e.g. /proc/interrupts, criu/mount.c:753) — ctr's runc
				//     CRIU argv carries none of our --skip-mnt list, so a masked bind CRIU cannot
				//     resolve aborts the dump. The raw go-criu Dump path below carries the dump-side
				//     skipMnts (criu_checkpointer.go) that skip exactly this set, so it succeeds where
				//     ctr could not (postgres live failure 2026-07-10).
				// Any other ctr error (OOM, permission, corrupt task) is fatal and returned directly
				// to avoid a double-freeze and to surface the real cause.
				if !errors.Is(ctrErr, ErrCtrInFlightTCP) && !errors.Is(ctrErr, ErrCtrMaskedMount) {
					return nil, fmt.Errorf("checkpoint failed (ctr): %w", ctrErr)
				}
				if errors.Is(ctrErr, ErrCtrMaskedMount) {
					log.Info("Checkpoint: ctr failed on a masked mount CRIU could not resolve — falling back to raw CRIU which skips the masked set (dump-side skipMnts, criu_checkpointer.go)",
						"taskID", taskID, "err", ctrErr)
				} else {
					log.Info("Checkpoint: ctr failed due to established TCP socket — falling back to raw CRIU with --tcp-established (ADR-0131 D2: connection preserved)",
						"taskID", taskID, "tcpEstablished", tcpEstablished, "err", ctrErr)
				}
				// Clear any partial ctr images before raw CRIU writes to the same dir.
				// ADR-0182 Issue 2: zeroize-then-unlink, NOT a
				// bare os.RemoveAll — a partial ctr dump may already contain live memory pages in
				// final/, and a bare unlink leaves them recoverable on tmpfs (Standing Rule 7).
				if rmErr := zeroizeDir(imagesDir); rmErr != nil {
					return nil, fmt.Errorf("checkpoint: clearing partial ctr images before raw CRIU: %w", rmErr)
				}
			} else {
				// SHA over the plaintext layer set, computed BEFORE finalizeCheckpointDir
				// encrypts in place (parity with the raw-CRIU path, which likewise checksums
				// before encryptCheckpointDir).
				sha := sha256OfDir(imagesDir)
				log.Info("Checkpoint complete (ctr)", "migration", req.MigrationName,
					"sizeBytes", sizeBytes, "sha256", sha, "freezeMs", freezeDurationMs)
				// Capture socket inventory from the (now frozen) container via its PID.
				// Non-fatal: ctr checkpoint already succeeded; SeqSnapshot is best-effort here.
				// Reads live-PID socket state, not the checkpoint images, so it is order-
				// independent of the finalize/encrypt step below.
				var ctrSeqSnapshots []*agentpb.SeqSnapshot
				if tcpEstablished {
					if ctrPID, pidErr := FindContainerPID(podUID); pidErr == nil {
						if sockEntries, invErr := network.SocketInventory(ctrPID); invErr == nil {
							// Same migratable-connection scoping as the raw-CRIU path above:
							// exclude intra-pod loopback health-probe connections so they never
							// enter the source-of-truth "expected" set (see FilterMigratableTCP).
							migratable := network.FilterMigratableTCP(sockEntries)
							for _, e := range migratable {
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
								"connections", len(ctrSeqSnapshots),
								"loopbackExcluded", len(sockEntries)-len(migratable))
						}
					}
				}
				// A-01: shmem-completeness guard + at-rest encryption, run on the ctr-native
				// DEFAULT path identically to the raw-CRIU fallback below. Before this unification
				// the ctr branch returned here WITHOUT encrypting — shipping plaintext process
				// memory at rest (finding C-1). finalizeCheckpointDir enforces guard-before-encrypt
				// ordering and returns the typed shmem status / fatal encrypt error unchanged.
				if finErr := s.finalizeCheckpointDir(req.MigrationName, imagesDir); finErr != nil {
					return nil, finErr
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
			// Scope the freeze inventory to MIGRATABLE connections before it becomes the
			// source-of-truth "expected" set. Intra-pod loopback connections (both ends on
			// 127.0.0.0/8 / ::1) are the pod's own exec/TCP health-probe traffic (e.g. a
			// redis-cli readiness ping → 127.0.0.1:6379): they have no external peer, CRIU
			// restores both ends atomically, and their ephemeral client port is gone after
			// restore — so a loopback tuple captured at the freeze instant is structurally
			// unmatchable in VerifyTCP and rolls back an otherwise-successful Strict migration
			// (an intermittent race vs the probe cadence). They are categorically outside the
			// TCP sequence-continuity contract; excluding them HERE means every downstream
			// consumer inherits the correct scope: expectedCount (enforceRestoreOrderingInvariant),
			// PM_SEQ_XLAT seeding, VerifyTCP's ConnectionsExpected, and the seq_delta metrics.
			migratable := network.FilterMigratableTCP(repairEntries)
			for _, e := range migratable {
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
				"connections", len(seqSnapshots),
				"loopbackExcluded", len(repairEntries)-len(migratable))
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
		// LeaveStopped keeps the source process in SIGSTOP after the dump so it cannot
		// run (or be restarted) between the freeze and source teardown. This is required
		// for ALL modes, not just TCP-stateful:
		//
		//   - TCP-stateful (M23 ordering invariant): no new TCP data is sent while the
		//     destination is restoring.
		//   - Storage-sharing migrations (Tier0 RWX re-attach — e.g. postgres on an
		//     nfs-shared PVC): the source and destination pods mount the SAME live data
		//     directory. If the source is instead KILLED after the dump (CRIU's default
		//     disposition with neither --leave-running nor --leave-stopped), the source
		//     container's main process exits, kubelet's restartPolicy restarts the
		//     container, and a FRESH source workload boots and re-acquires the shared
		//     data directory (postgres: crash-recovery + a new postmaster.pid data-dir
		//     lock). That live source then collides with the CRIU-restored destination on
		//     the same on-disk state — two postmasters over one PGDATA — and the restored
		//     destination loses the data directory it was migrated onto and dies (observed:
		//     restored postgres briefly serves one query, then the reclaiming source wins
		//     and the destination shuts down; roundsCompleted looked fine but the DB was
		//     dead). Leaving the source SIGSTOPped means the container never exits, kubelet
		//     never restarts it, and nothing reclaims the shared directory until the source
		//     pod is torn down post-cutover.
		//
		// This STRENGTHENS source preservation (ADR-0012): a stopped source is fully
		// recoverable via the thaw machinery below, whereas a killed+kubelet-restarted
		// source is an uncontrolled second workload.
		// CRITICAL: Every error/rollback path that follows a successful LeaveStopped dump
		// MUST thaw the source (Rollbacker.Rollback source-resume / Abort → thawFrozenSource /
		// the ADR-0216 durable-record startup orphan reconcile) so the source is never
		// permanently frozen. registerFrozenSource is called immediately after the dump.
		LeaveStopped: true,
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
	// Register for ALL modes now that LeaveStopped is unconditional (above): the source
	// is left in SIGSTOP regardless of TCP preservation, so every mode needs the
	// frozen-source record that the rollback/Abort/startup-reconcile thaw paths key on.
	// Gating this on tcpEstablished (as before) would leave a None-mode source frozen with
	// NO thaw record — a source-preservation violation.
	if err == nil && containerPID != 0 {
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
				stageTaskID, taskErr = FindContainerTaskID(ctx, podUID)
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

	// A-01: shmem-completeness guard + at-rest encryption, run on the raw-CRIU fallback path
	// identically to the ctr-native DEFAULT path above (single finalizeCheckpointDir primitive).
	// Guard-before-encrypt ordering is enforced inside the helper: verifyShmemPagemapCompleteness
	// reads plaintext mm-*.img/pagemap-shmem-*.img BEFORE encryptCheckpointDir replaces the layers
	// with ciphertext. Failure is FATAL: a half-encrypted final/ must not transfer.
	if finErr := s.finalizeCheckpointDir(req.MigrationName, imagesDir); finErr != nil {
		return nil, finErr
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

	// ADR-0353 R2/R3/R5: acquire the single-owner in-flight restore claim BEFORE any
	// zeroize-eligible branch (the nearest one is the restoreConfirmed-gated defer registered
	// just below) and before any CRIU-restore drive. This also covers the idempotent-confirm
	// short-circuit further down (no CRIU drive there, but R6 treats "another actor's restore
	// attempt currently in flight for this same migration" as the exact concurrent-drive hazard
	// this lock exists for). Declining here preserves the checkpoint images (no zeroize has run
	// yet) and returns the TRANSIENT-RETRY codes.Aborted status.
	if !claimRestore(req.MigrationName, "gRPC") {
		log.Info("Restore: restore already in flight for this migration under another owner — declining (ADR-0353 R3/R5)",
			"migration", req.MigrationName)
		return nil, status.Error(codes.Aborted, ErrRestoreInFlight.Error())
	}
	// ADR-0354 D3/DR-3: same reasoning as JoinNsRestore's release (server.go ~821) — the
	// rollbackExecBudget-bounded brokerCriuCmd.Signal() kill (D2b) and the tighten-only
	// min(remaining(ctx), ceiling) forward broker execs (D2/D2b) mean this defer-based release
	// already cannot be held open by a wedged broker exec past its bound. No additional lock
	// machinery is added here.
	defer releaseRestore(req.MigrationName)

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
			if zErr := zeroizeDir(imagesDir); zErr != nil && !os.IsNotExist(zErr) {
				log.Error(zErr, "Restore success cleanup: zeroize checkpoint images failed — residual plaintext may remain (SR-7/M-8)",
					"migration", req.MigrationName, "dir", imagesDir)
			}
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
			// ADR-0354 round-5 sweep: network.TeardownMigrationNetns -> netnsbroker.Client.Teardown
			// funnels the same Client.do(ctx) as the other broker-exec surfaces (D5's predicate). This
			// is a fail-closed rollback leg (restore-failure cleanup on the Restore RPC path, which DOES
			// have a real caller ctx in scope at 7573), so it uses the D3 primitive — severed from the
			// forward ctx (which may already be Done, the reason this leg is running) and hard-bounded
			// by rollbackExecBudget — instead of an unbounded context.Background().
			teardownCtx, teardownCancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackExecBudget)
			teardownErr := network.TeardownMigrationNetns(teardownCtx, ns)
			teardownCancel()
			if teardownErr != nil {
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
		// AUTHORITATIVE source first: MCP.Spec.WorkloadImage (ADR-0217 D1) is set in Validating
		// and is race-free — it does not depend on Status.ReplacementPodName or a live replacement
		// pod. On the agent-Restore-RPC fallback path (~60s after the NRI confirm window times out)
		// the replacement pod resolver was observed returning empty (ReplacementPodName not yet
		// populated / pod mid-teardown). Read the MCP directly before the racy pod resolver.
		if resolved := s.resolveImageFromMCP(req.MigrationName); resolved != "" {
			storedWorkloadImage = resolved
			log.Info("ADR-0235: gRPC Restore — B2 cache empty, resolved workload image from MCP.Spec.WorkloadImage (authoritative, ADR-0217 D1)",
				"migration", req.MigrationName, "image", storedWorkloadImage)
		} else if resolved := s.resolveImageFromReplacementPod(req.MigrationName); resolved != "" {
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
	// D2-C1 (ADR-0049 Amendment D parity): the requirement to join the pre-staged destination
	// netns is a property of the DECLARED preservation MODE, not of whether any TCP connection
	// happened to be established at the freeze instant. The prior key on SeqSnapshots>0 was a
	// fail-open proxy: a legitimately-Strict but momentarily-idle workload transfers zero
	// SeqSnapshots, so this guard never fired and the restore silently fell through the
	// tcpPreservationMode=None cold path (no --join-ns), restoring the process tree into the
	// wrong namespace and bricking it post-checkpoint. Gate on mode==Strict instead — under
	// Strict an empty DestNetnsFd is never a valid cold-path value; it means the controller's
	// DestinationNetnsReady stage failed to plumb the netns fd, and we must refuse rather than
	// infer a cold path the caller never declared. (An explicitly cold migration carries
	// mode=None/BestEffort, for which the empty DestNetnsFd is the declared cold-path value.)
	if req.TcpPreservationMode == string(pmv1.TCPPreservationModeStrict) && req.DestNetnsFd == "" {
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
			netnsPath, macIfname := s.finalizeNetnsPath(req.MigrationName)
			fr, frErr := s.finalizeRestore(ctx, priorPID, netnsPath, macIfname, req.MigrationName, "", req.TcpPreservationMode, imagesDir)
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
			s.destHostVethMu.Lock()
			delete(s.destHostVeth, req.MigrationName)
			s.destHostVethMu.Unlock()

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
		// Bounded-wait on the kubelet-published re-attach mount (defense-in-depth for the gRPC
		// fallback path); the RPC handler ctx carries the deadline.
		reattachMounts, reErr := s.resolveReattachMountsWaiting(ctx, req.MigrationName)
		if reErr != nil {
			return nil, fmt.Errorf("resolve re-attach mounts: %w", reErr)
		}
		// UNIVERSAL POD-NETNS INTEGRATION (ADR-0325): joining the restored process into ITS
		// pod's REAL network namespace (the CNI-wired sandbox netns that owns the new pod IP) is a
		// property of the restore path, NOT of tcpPreservationMode. We resolve the replacement
		// pod's sandbox (pause-container) netns from the source-of-truth — the replacement pod UID
		// → containerd sandbox label → sandbox OCI network/path (resolveSandboxIDForMigration →
		// ResolveNetnsFromSandbox) — and hand THAT sandbox to joinNsRestore for None/BestEffort/
		// Strict alike, so CRIU restores via --join-ns net:<pod-sandbox-netns> and the workload
		// serves at its pod IP. We deliberately do NOT join the agent-staged migration netns
		// (req.DestNetnsFd = /run/podmotion/netns/pm-mig-*/bind): that synthetic netns exists only
		// for OLD-IP preservation (a separate substrate effort, explicitly out of scope here) and
		// carries the source pod's /32 old IP with no CNI routing — restoring into it left the
		// workload alive but unreachable at the new pod IP. This is not a poll-and-hope: the
		// sandbox ID derives deterministically from the pod UID. Fail-closed on resolution failure.
		joinSandboxID, sandboxAttempted := s.resolvePodNetnsSandboxWaiting(ctx, req.MigrationName)
		if joinSandboxID == "" && sandboxAttempted {
			msg := fmt.Sprintf("Restore: pod-netns integration failed for migration %s: could not resolve replacement pod sandbox netns (ADR-0325) — refusing to restore into a detached/non-pod namespace", req.MigrationName)
			log.Info(msg, "migration", req.MigrationName)
			return &agentpb.RestoreResponse{Success: false, ErrorMessage: msg}, nil
		}
		// ADR-0351 D3.1: pass the incoming gRPC Restore handler ctx — the operator-set restore-RPC
		// deadline D_restore is the real budget source on this path; no new derivation needed.
		// ADR-0351 D1.2/D2: this gRPC path has no NRI ContainerEvent, so there is no per-container
		// cgroup value to thread — passed empty. joinSandboxID CAN still be non-empty here
		// (ADR-0325 self-resolve), so the anchor gate's containerCgroupsPath=="" leg (documented at
		// the anchor call site, server.go) applies: the cgroup-anchor step is skipped rather than
		// fail-closed, a tracked gap (see the anchor call site's comment for the full rationale).
		// ADR-0355 D2/D3: resolve the authoritative preserved source IP (pm.Spec.SourcePodIP) and
		// thread it into joinNsRestore for the pre-CRIU bind-prep. "" (no CR / empty field) → no-op.
		preservedSourceIP := s.resolvePreservedSourceIPForMigration(ctx, req.MigrationName)
		pid, droppedMnts, joinErr := joinNsRestoreFn(ctx, req.MigrationName, imagesDir, storedWorkloadImage, "", "", joinSandboxID, storedVeth, false, reattachMounts, "", "", preservedSourceIP)
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
			socketsLiveAt, resumedAt, orderErr := enforceRestoreOrderingInvariant(ctx, pid, req.MigrationName, len(req.SeqSnapshots), deferResume)
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
		netnsPath, macIfname := s.finalizeNetnsPath(req.MigrationName)
		fr, frErr := s.finalizeRestore(ctx, pid, netnsPath, macIfname, req.MigrationName, "", req.TcpPreservationMode, imagesDir)
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
		s.destHostVethMu.Lock()
		delete(s.destHostVeth, req.MigrationName)
		s.destHostVethMu.Unlock()

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
	// Shared/re-attach PVC mounts (Tier0 RWX) are preserved + re-attached on both paths.
	// Bounded-wait on the kubelet-published mount (defense-in-depth for the gRPC fallback path).
	rawReattachMounts, rawReErr := s.resolveReattachMountsWaiting(ctx, req.MigrationName)
	if rawReErr != nil {
		return nil, fmt.Errorf("resolve re-attach mounts: %w", rawReErr)
	}
	if patchErr := patchCheckpointImagesFn(imagesDir, nil, reattachContainerPaths(rawReattachMounts), reattachHostTargets(rawReattachMounts)); patchErr != nil {
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
	// UNIVERSAL POD-NETNS INTEGRATION (ADR-0325): raw-CRIU gRPC path parity with the
	// config.json branch above — resolve the replacement pod's REAL sandbox netns and join it so
	// the restored process serves at its pod IP regardless of tcpPreservationMode. The synthetic
	// migration netns (req.DestNetnsFd) is deliberately NOT joined (old-IP preservation is out of
	// scope). See the config.json branch for the full rationale. Fail-closed on resolution failure.
	joinSandboxID2, sandboxAttempted2 := s.resolvePodNetnsSandboxWaiting(ctx, req.MigrationName)
	if joinSandboxID2 == "" && sandboxAttempted2 {
		msg := fmt.Sprintf("Restore: pod-netns integration failed for migration %s: could not resolve replacement pod sandbox netns (ADR-0325) — refusing to restore into a detached/non-pod namespace", req.MigrationName)
		log.Info(msg, "migration", req.MigrationName)
		return nil, fmt.Errorf("%s", msg)
	}
	// ADR-0351 D3.1: same rationale as the config.json branch above — pass the incoming gRPC
	// Restore handler ctx (D_restore).
	// ADR-0351 D1.2/D2: same rationale as the primary gRPC branch above — no NRI event on this
	// raw-CRIU fallback path, so no cgroup value to thread; the anchor gate skips (tracked gap).
	// ADR-0355 D2/D3: same pre-CRIU bind-prep threading as the config.json branch above.
	preservedSourceIP2 := s.resolvePreservedSourceIPForMigration(ctx, req.MigrationName)
	rawPID, droppedMnts2, joinErr := joinNsRestoreFn(ctx, req.MigrationName, imagesDir, storedWorkloadImage, "", "", joinSandboxID2, storedVeth2, false, rawReattachMounts, "", "", preservedSourceIP2)
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
	netnsPath2, macIfname2 := s.finalizeNetnsPath(req.MigrationName)
	fr2, frErr2 := s.finalizeRestore(ctx, result.PID, netnsPath2, macIfname2, req.MigrationName, "", req.TcpPreservationMode, imagesDir)
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
	s.destHostVethMu.Lock()
	delete(s.destHostVeth, req.MigrationName)
	s.destHostVethMu.Unlock()

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
	log.Info("VerifyTCP called", "migration", req.MigrationName, "appProbeOnly", req.AppProbeOnly)

	// ADR-0325: AppProbeOnly scopes this call to ONLY the application-layer probe.
	// Skip PID/socket-inventory resolution and seq-delta accounting entirely — this
	// path MUST NOT write TCPSequenceContinuityVerified, the measured-seq-delta
	// annotation, or the seq_delta gauge (those remain owned exclusively by the
	// full-verification path below). Used by reconcileServiceVerifying to populate
	// WorkloadLivenessVerified for ALL TCPPreservationMode values, including None,
	// which never reaches the full-verification path.
	if req.AppProbeOnly {
		resp := &agentpb.VerifyTCPResponse{}
		if req.AppProbeProtocol == "" {
			resp.Verified = true
			return resp, nil
		}
		// ADR-0352 Strict (sprint46B9 fix): resume the --leave-stopped restored tree BEFORE probing.
		// The Strict completion path retired injectIPHandoff, the former sole trigger for the ADR-0142
		// deferred SIGCONT, so without this the frozen process completes the TCP handshake at the
		// kernel but never answers the wire probe (i/o timeout → false liveness failure → rollback).
		// No-op for BestEffort/None (no pending PID) and idempotent across the sustained-probe requeues.
		s.resumeDeferredRestoredProcess(ctx, req.MigrationName)
		probeErr := s.runAppProbe(ctx, req)
		if probeErr != nil {
			resp.Verified = false
			resp.AppProbeOk = false
			resp.AppProbeError = probeErr.Error()
			resp.FailureReason = fmt.Sprintf("app probe failed: %v", probeErr)
			log.Info("VerifyTCP: application probe failed (AppProbeOnly)",
				"migration", req.MigrationName, "protocol", req.AppProbeProtocol, "err", probeErr)
			return resp, nil
		}
		resp.Verified = true
		resp.AppProbeOk = true
		return resp, nil
	}

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
	// Scope the destination observation to the SAME migratable-connection class as the
	// source "expected" set (sourceSnaps was captured loopback-free at freeze). Without
	// this, a fresh intra-pod loopback health probe that happens to be ESTABLISHED at
	// verify time would (a) be mistaken for a migrated connection in the match loop and
	// (b) — when the pod held no real connections (len(sourceSnaps)==0) — trip the
	// absence-of-evidence fail-closed guard below with a misleading message. Filtering
	// keeps expected/observed comparing like-with-like; it does NOT weaken the guard.
	destEntries = network.FilterMigratableTCP(destEntries)

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
		probeErr := s.runAppProbe(ctx, req)
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

// ciliumNodePodCIDRGVK is the cilium.io/v2 CiliumNode resource — cluster-scoped, named after
// the Kubernetes node. It is read as unstructured via the controller-runtime client because the
// typed clientset does not compile in cilium.io/v2 (see cmd/main.go: no scheme registered for it).
var ciliumNodePodCIDRGVK = schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNode"}

// nodePodCIDRAllowlist returns the cached []*net.IPNet of this node's pod IPs — the SSRF
// containment reference dialAllowed enforces (ADR-0325). It reads the AUTHORITATIVE allocator,
// CiliumNode.spec.ipam.podCIDRs (the Cilium cluster-pool IPAM per-node block), NOT
// Node.Spec.PodCIDRs. On a Cilium cluster-pool cluster the two DISAGREE: kube's node-ipam
// controller writes Node.Spec.PodCIDRs, but Cilium runs its own IPAM and hands pod IPs out of
// CiliumNode.spec.ipam.podCIDRs, so real pods do NOT live in Node.Spec.PodCIDRs. Verified live on
// the standing cluster (2026-07-14): pm-w2 Node.Spec.PodCIDRs=10.244.2.0/24 while pm-w2's pods are
// allocated from Cilium 10.244.1.0/24 (every node is permuted). Keying the allowlist on
// Node.Spec.PodCIDRs therefore refuses every legitimate local pod IP AND admits a /24 that holds
// none — an SSRF control reading a field the CNI ignores. This reads the source of truth the CNI
// actually allocates from (invariant #10 / SUBSTRATE-PRIMITIVE: read the allocator's write-back,
// do not key on a field it does not own).
//
// Fail-CLOSED, NO fallback: k8sClient==nil, an absent/unreadable CiliumNode, or an empty/
// unparsable podCIDRs list yields an EMPTY slice, which makes dialAllowed refuse every dial. It
// does NOT fall back to Node.Spec.PodCIDRs — that field is proven to diverge on this substrate, so
// a fallback would be a brittle chain re-admitting the wrong /24 (invariant #10). Never hardcode a
// CIDR literal.
func (s *AgentServer) nodePodCIDRAllowlist(ctx context.Context) []*net.IPNet {
	s.podCIDRAllowlistMu.RLock()
	cached := s.podCIDRAllowlist
	s.podCIDRAllowlistMu.RUnlock()
	if cached != nil {
		return cached
	}
	out := parseCIDRAllowlist(s.ciliumNodePodCIDRs(ctx))
	s.podCIDRAllowlistMu.Lock()
	s.podCIDRAllowlist = out
	s.podCIDRAllowlistMu.Unlock()
	return out
}

// ciliumNodePodCIDRs reads this node's Cilium cluster-pool IPAM per-node pod CIDRs from the
// cilium.io/v2 CiliumNode CR (spec.ipam.podCIDRs) via the controller-runtime client as
// unstructured. Returns nil on any failure so the caller falls CLOSED (empty allowlist). Reads
// the CR named for this node; requires get on ciliumnodes.cilium.io (podmotion-agent-role).
func (s *AgentServer) ciliumNodePodCIDRs(ctx context.Context) []string {
	if s.k8sClient == nil || s.nodeName == "" {
		return nil
	}
	cn := &unstructured.Unstructured{}
	cn.SetGroupVersionKind(ciliumNodePodCIDRGVK)
	if err := s.k8sClient.Get(ctx, client.ObjectKey{Name: s.nodeName}, cn); err != nil {
		return nil
	}
	cidrs, _, err := unstructured.NestedStringSlice(cn.Object, "spec", "ipam", "podCIDRs")
	if err != nil {
		return nil
	}
	return cidrs
}

// parseCIDRAllowlist parses CIDR strings into []*net.IPNet, skipping any that do not parse. Pure
// and side-effect-free so the SSRF allowlist admission logic is unit-testable against real cluster
// CIDR values without a live CiliumNode read.
func parseCIDRAllowlist(cidrs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range cidrs {
		if _, ipnet, perr := net.ParseCIDR(cidr); perr == nil {
			out = append(out, ipnet)
		}
	}
	return out
}

// dialAllowed refuses to dial any host outside this node's pod CIDR allowlist
// (ADR-0325 SSRF containment control — non-negotiable). Called at the top of runAppProbe
// for every protocol, before any dial.
func (s *AgentServer) dialAllowed(ctx context.Context, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("NonPodCIDRRefused: address %q host %q is not a valid IP", address, host)
	}
	allowlist := s.nodePodCIDRAllowlist(ctx)
	for _, ipnet := range allowlist {
		if ipnet.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("NonPodCIDRRefused: %s is outside the node pod-CIDR allowlist", ip)
}

// dialAllowedForMigrationTarget (ADR-0352 D1.2) is the SINGLE authoritative dial-authorization
// primitive for an application probe. It admits address iff EITHER (a) address's IP is within
// this node's pod-CIDR allowlist (the ADR-0325 SSRF containment — same-node/normal probes
// are unaffected), OR (b) address's IP EXACTLY equals one of the migration's own authoritative,
// independently-resolved out-of-pod-CIDR expected targets — the Service ClusterIP
// (expected_cluster_ip) and/or the PRESERVED pod IP (expected_pod_ip). Both classes are
// outside the DESTINATION node's own pod-CIDR by design (a Service ClusterIP lives in the
// Service CIDR; a preserved cross-node pod IP lives in the SOURCE node's pod-CIDR), so the
// unmodified pod-CIDR allowlist alone would ALWAYS reject them with NonPodCIDRRefused —
// silently masquerading the ClusterIP round-trip as "failed" and, structurally, making the
// Strict workload-liveness gate unreachable for every preserved-IP cross-node migration.
// Each expected IP is a value the CALLING migration's controller independently resolved from a
// DIFFERENT source of truth than address (the real Service object / spec.sourcePodIP vs. the
// live pod-status read used to build AppProbeAddress); requiring an EXACT match is a deliberate
// belt-and-suspenders check against a construction bug threading an unrelated address. This is
// NEVER a CIDR-range widening — only these exact IP(s) are permitted, per request. It replaces
// the prior per-path carve-outs with ONE source-of-truth-keyed authorization (invariant #10).
func (s *AgentServer) dialAllowedForMigrationTarget(ctx context.Context, address string, expectedIPs ...string) error {
	if err := s.dialAllowed(ctx, address); err == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip != nil {
		for _, exp := range expectedIPs {
			if exp == "" {
				continue
			}
			if expIP := net.ParseIP(exp); expIP != nil && ip.Equal(expIP) {
				return nil
			}
		}
	}
	return fmt.Errorf("NonPodCIDRRefused: address %q is outside the node pod-CIDR allowlist and matches none of this migration's authoritative expected target IPs (ClusterIP/preserved pod IP)", address)
}

// dialAllowedForServiceContinuity (ADR-0352 D1.2) is the Service-continuity ClusterIP entry
// point, retained as a named seam for its unit tests. It is a thin wrapper over the unified
// dialAllowedForMigrationTarget primitive: admit the pod-CIDR allowlist OR exactly
// expectedClusterIP. All authorization policy lives in the one primitive.
func (s *AgentServer) dialAllowedForServiceContinuity(ctx context.Context, address, expectedClusterIP string) error {
	return s.dialAllowedForMigrationTarget(ctx, address, expectedClusterIP)
}

// migrationRestoredWorkloadIP reads the AUTHORITATIVE IP the restored workload actually answers on
// for migrationName: the REPLACEMENT pod's own Status.PodIP, read directly from the k8s API — the
// SAME source of truth the controller uses to build the ADR-0325 WorkloadLivenessVerified probe
// target (reconcileServiceVerifying: destPodIP := destPod.Status.PodIP, podmigration_controller.go
// ~1491/1555). Keying the dial-authorization on THIS value makes the probe target and the dial-auth
// admit ONE identical fact by construction, read from ONE source of truth (invariant #10) — closing
// the sprint46B7 cycle-2 divergence where the controller probed destPod.Status.PodIP while the agent
// admitted a DIFFERENT field.
//
// It DELIBERATELY does NOT read Spec.SourcePodIP (the retired cycle-1 key). Spec.SourcePodIP is the
// migration's REQUESTED preserved IP. Under ADR-0352 the Strict completion path is the Service-
// continuity model (ServiceContinuityVerified + WorkloadLivenessVerified); the preserved-IP-on-
// endpoint gate (ConfirmEndpointOwnsPreservedIP, reached via injectIPHandoff) is RETIRED from Strict
// (podmigration_controller.go D3), so cluster-pool IPAM may legitimately assign the replacement pod
// a FRESH destination-local IP that is NOT Spec.SourcePodIP (the ipam.cilium.io/ip pin need not be
// honored for Strict to complete). The controller probes that fresh IP; admitting Spec.SourcePodIP
// instead refused the very address under probe (live-proof cycle-2: admitted 10.244.0.63, probe
// target 10.244.1.203 refused). When the pin IS honored the two are equal, so reading the
// replacement pod's Status.PodIP is correct in BOTH cases — it is strictly the authoritative "IP the
// restored workload answers on".
//
// Resolves the replacement pod by the race-free migration-name LABEL (resolveReplacementPod — the
// same primitive the restore path uses), falling back to Status.ReplacementPodName only if the label
// lookup finds nothing. Returns "" if the CR, the replacement pod, or its Status.PodIP cannot be
// resolved (the caller then falls closed on the plain pod-CIDR allowlist), so a construction bug or
// hostile caller threading an unrelated address cannot self-authorize.
func (s *AgentServer) migrationRestoredWorkloadIP(ctx context.Context, migrationName string) string {
	if s.k8sClient == nil || migrationName == "" {
		return ""
	}
	pm, ok := s.lookupPodMigration(ctx, migrationName)
	if !ok {
		return ""
	}
	podNs := pm.Spec.PodNamespace
	if podNs == "" {
		podNs = pm.Namespace
	}
	replPod := s.resolveReplacementPod(ctx, migrationName, podNs)
	if replPod == nil {
		// Label race: fall back to the Status field (same pattern as resolveReattachMountsImpl).
		if replName := pm.Status.ReplacementPodName; replName != "" {
			p := &corev1.Pod{}
			if err := s.k8sClient.Get(ctx, types.NamespacedName{Name: replName, Namespace: podNs}, p); err == nil {
				replPod = p
			}
		}
	}
	if replPod == nil {
		return ""
	}
	return replPod.Status.PodIP
}

// dialAllowedForMigrationProbe (sprint46B7 Validation cycle-1 fix) is the SINGLE authoritative
// dial-authorization entrypoint for every VerifyTCP application probe (ADR-0325 SSRF containment).
// It replaces the prior split in runAppProbe where a Service-continuity probe got the ADR-0352
// D1.2 ClusterIP carve-out but the sibling ADR-0325 WorkloadLivenessVerified probe fell through to
// plain dialAllowed — which admits ONLY the destination node's own pod-CIDR. That destination-CIDR
// allowlist is the WRONG reference for the replacement pod's liveness probe on a cross-node
// migration: the controller probes the replacement pod's actual Status.PodIP, which is NOT
// guaranteed to sit in this node's Node.Spec.PodCIDRs (under Cilium cluster-pool the real allocator
// is the CiliumNode block, which can diverge from Node.Spec.PodCIDRs), so the plain path fails
// CLOSED with NonPodCIDRRefused on the NORMAL case of the very feature under test — leaving Strict
// completion structurally unreachable (WorkloadLivenessVerified never goes True, so the
// livenessOK && ServiceContinuityVerified advance guard never fires).
//
// This primitive admits the target ONLY when it is an IP this migration AUTHORITATIVELY owns, each
// established from a source-of-truth read — never a CIDR-range widening, never AppProbeAddress on
// trust alone (a buggy/hostile caller threading an unrelated address still fails closed):
//
//	(a) the destination node's pod-CIDR allowlist (ordinary same-node / Mode=None new-IP case),
//	    unchanged ADR-0325 SSRF semantics;
//	(b) the IP the restored workload authoritatively answers on — the REPLACEMENT pod's own
//	    Status.PodIP, read by req.MigrationName from the SAME k8s source of truth the controller uses
//	    to build the probe target (migrationRestoredWorkloadIP). This is the sprint46B7 cycle-2 fix:
//	    it makes the dial-auth admit the exact IP the controller probes, closing the prior divergence
//	    where the agent instead admitted Spec.SourcePodIP (which cluster-pool IPAM may not have put
//	    on the pod); or
//	(c) the expected Service ClusterIP the controller independently resolved (ADR-0352 D1.2),
//	    delegated unchanged to dialAllowedForServiceContinuity so that landed carve-out and its
//	    unit contract remain the authority for the ClusterIP case.
func (s *AgentServer) dialAllowedForMigrationProbe(ctx context.Context, req *agentpb.VerifyTCPRequest) error {
	address := req.AppProbeAddress
	// (a) ordinary pod-CIDR allowlist — unchanged ADR-0325 SSRF semantics, fast path.
	if err := s.dialAllowed(ctx, address); err == nil {
		return nil
	}
	host, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("NonPodCIDRRefused: address %q host %q is not a valid IP", address, host)
	}
	// (b) the IP the restored workload authoritatively answers on = the REPLACEMENT pod's own
	// Status.PodIP, read from the SAME k8s source of truth the controller used to build the probe
	// target (destPod.Status.PodIP). This closes the sprint46B7 cycle-2 divergence: the controller
	// probes the replacement pod's actual (possibly fresh, dest-local) IP, so the dial-auth must
	// admit THAT exact IP — not Spec.SourcePodIP, which under ADR-0352 Strict need not be the IP the
	// pod ended up with (preserved-IP-on-endpoint gate retired; cluster-pool IPAM may hand a fresh
	// IP). Exact-match only, re-derived independently by the agent, so a hostile/buggy caller
	// threading an unrelated AppProbeAddress still fails closed (SSRF containment preserved).
	if restoredIP := s.migrationRestoredWorkloadIP(ctx, req.MigrationName); restoredIP != "" {
		if rip := net.ParseIP(restoredIP); rip != nil && rip.Equal(ip) {
			return nil
		}
	}
	// (c) expected Service ClusterIP (ADR-0352 D1.2) — delegate to the existing scoped guard so its
	// belt-and-suspenders check and unit contract remain the authority for the ClusterIP case.
	if req.ExpectedClusterIp != "" {
		return s.dialAllowedForServiceContinuity(ctx, address, req.ExpectedClusterIp)
	}
	return fmt.Errorf("NonPodCIDRRefused: %s is outside the node pod-CIDR allowlist and is neither this migration's preserved pod IP nor its expected Service ClusterIP", ip)
}

// runAppProbe (ADR-0325) issues a real wire-protocol application probe. This is now a
// METHOD on *AgentServer (previously a free function) so it can read this node's identity
// to derive the pod-CIDR SSRF allowlist. Both VerifyTCP call sites (the AppProbeOnly branch
// and the full-verification tail) route through it and inherit the CIDR guard and the real
// protocol bodies.
func (s *AgentServer) runAppProbe(ctx context.Context, req *agentpb.VerifyTCPRequest) error {
	// ADR-0325 / ADR-0352 D1.2 / sprint46B7 Validation cycle-2 fix: route EVERY app probe through
	// the single authoritative migration-aware dial-authorization primitive. It admits the
	// destination node's pod-CIDR (ordinary case), the IP the restored workload authoritatively
	// answers on — the replacement pod's own Status.PodIP, the SAME value the controller builds the
	// probe target from (the cross-node liveness case, where cluster-pool IPAM may assign a fresh
	// dest-local IP the plain destination-CIDR allowlist does not contain), and the expected Service
	// ClusterIP (Service-continuity round-trip). Replaces the prior split where the liveness branch
	// fell through to plain dialAllowed and refused the replacement pod's probe IP.
	//
	// The address is fixed for the whole sustained window, so authorize ONCE up front rather than
	// on every attempt.
	if err := s.dialAllowedForMigrationProbe(ctx, req); err != nil {
		return err
	}

	// ADR-0325 round-3 (sprint46B9): SUSTAINED verification. Instead of a single instantaneous
	// probe (which a crash-looping backend passes at the exact instant it happens to answer the
	// handshake), require N consecutive passes over a real interval. Each attempt re-dials and
	// re-probes the backend's CURRENT state via runAppProbeOnce; a flapping backend fails a later
	// attempt on connection-refused and never reports live. Both VerifyTCP call sites — the
	// AppProbeOnly branch (WorkloadLivenessVerified) and the full-verification tail (AppProbeOk,
	// which feeds TrafficVerified/ServiceContinuity) — inherit this hardening for free.
	passes, interval := s.resolveSustain()
	return sustainedProbe(ctx, passes, interval, func(attemptCtx context.Context) error {
		return s.runAppProbeOnce(attemptCtx, req)
	})
}

// resolveSustain returns the configured sustained-liveness parameters, falling back to the
// package defaults when the AgentServer fields are unset (the zero value, e.g. &AgentServer{}).
func (s *AgentServer) resolveSustain() (int, time.Duration) {
	passes := s.livenessSustainPasses
	if passes < 1 {
		passes = defaultLivenessSustainPasses
	}
	interval := s.livenessSustainInterval
	if interval <= 0 {
		interval = defaultLivenessSustainInterval
	}
	return passes, interval
}

// runAppProbeOnce issues exactly ONE wire-protocol application probe (a single dial + protocol
// exchange) with its own per-probe timeout. It is the single-shot body that sustainedProbe
// invokes repeatedly; the SSRF dial-authorization is performed once by the caller (runAppProbe),
// so this method never dials an unauthorized address (every attempt targets the same authorized
// req.AppProbeAddress).
func (s *AgentServer) runAppProbeOnce(ctx context.Context, req *agentpb.VerifyTCPRequest) error {
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
		// ADR-0325: app_probe_query (proto field 6) carries the SQL query for this
		// protocol (default "SELECT 1" when empty). Real Postgres v3 handshake+query —
		// see pgprobe.go. Never sends a password.
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", req.AppProbeAddress)
		if err != nil {
			return fmt.Errorf("SQL probe TCP connect to %s failed: %w", req.AppProbeAddress, err)
		}
		defer conn.Close()
		if err := pgProbe(dialCtx, conn, req.AppProbeQuery, timeout); err != nil {
			return fmt.Errorf("SQL probe to %s failed: %w", req.AppProbeAddress, err)
		}
		return nil
	case "REDIS":
		// app_probe_query is unused/ignored for Redis.
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", req.AppProbeAddress)
		if err != nil {
			return fmt.Errorf("Redis probe TCP connect to %s failed: %w", req.AppProbeAddress, err)
		}
		defer conn.Close()
		if err := respPing(conn, timeout); err != nil {
			return fmt.Errorf("Redis probe to %s failed: %w", req.AppProbeAddress, err)
		}
		return nil
	case "HTTP":
		// ADR-0325: app_probe_query (proto field 6) carries the HTTP path for this
		// protocol (default "/" when empty). Requires a genuine [200,300) response;
		// CheckRedirect=http.ErrUseLastResponse refuses to follow redirects (3xx=FAILURE).
		// No auth header attached.
		if err := httpGet2xx(dialCtx, req.AppProbeAddress, req.AppProbeQuery, timeout); err != nil {
			return fmt.Errorf("HTTP probe to %s failed: %w", req.AppProbeAddress, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported app probe protocol %q", req.AppProbeProtocol)
	}
}

func (s *AgentServer) Abort(_ context.Context, req *agentpb.AbortRequest) (*agentpb.AbortResponse, error) {
	log.Info("Abort called", "migration", req.MigrationName, "reason", req.Reason)

	// Evict this migration's source-side identity/state on the failure path — the mirror of
	// DisarmZeroWindow's success-path eviction. Without this, a migration name reused after an
	// abort (a retried CR, or a test harness) resolves stale state from the aborted attempt.
	// pendingResumePIDs is included here too: its only other eviction site is deep inside a
	// success-path branch (~server.go:2100), so an abort between Restore recording an entry and
	// that branch running would otherwise leak it.
	s.migrationPodUIDMu.Lock()
	delete(s.migrationPodUID, req.MigrationName)
	s.migrationPodUIDMu.Unlock()
	s.migrationSeqSnapshotsMu.Lock()
	delete(s.migrationSeqSnapshots, req.MigrationName)
	s.migrationSeqSnapshotsMu.Unlock()
	s.pendingResumePIDsMu.Lock()
	delete(s.pendingResumePIDs, req.MigrationName)
	s.pendingResumePIDsMu.Unlock()

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
	// clean any prior partial staging (may hold recoverable plaintext from an aborted put)
	if zErr := zeroizeDir(stagingDir); zErr != nil && !os.IsNotExist(zErr) {
		log.Error(zErr, "PutCheckpointTar: pre-clean of prior staging dir failed — residual plaintext may remain (SR-7/M-8)",
			"migration", req.MigrationName, "dir", stagingDir)
	}
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return &agentpb.PutCheckpointTarResponse{Success: false, Error: fmt.Sprintf("mkdir staging %s: %v", stagingDir, err)}, nil
	}
	stagingOK := false
	defer func() {
		if !stagingOK {
			if zErr := zeroizeDir(stagingDir); zErr != nil && !os.IsNotExist(zErr) {
				log.Error(zErr, "PutCheckpointTar abort cleanup: zeroize staging dir failed — residual plaintext may remain (SR-7/M-8)",
					"migration", req.MigrationName, "dir", stagingDir)
			}
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
	if zErr := zeroizeDir(destDir); zErr != nil && !os.IsNotExist(zErr) {
		log.Error(zErr, "PutCheckpointTar: pre-clean of stale final dir failed — residual plaintext may remain (SR-7/M-8)",
			"migration", req.MigrationName, "dir", destDir)
	}
	if err := os.Rename(stagingDir, destDir); err != nil {
		return nil, status.Errorf(codes.Internal, "ADR-SEC-B: promote staging→final: %v", err)
	}
	stagingOK = true // staging is now final/ — disarm the staging zeroize defer
	if err := os.WriteFile(filepath.Join(destDir, checkpointVerifiedSentinel), []byte(manifest.SetDigest), 0o600); err != nil {
		// Sentinel write failure: fail closed (zeroize final so an unverified-but-present dir
		// cannot be restored from). Source pod is never deleted pre-TrafficVerified (invariant 5).
		if zErr := zeroizeDir(destDir); zErr != nil && !os.IsNotExist(zErr) {
			log.Error(zErr, "PutCheckpointTar fail-closed: zeroize unverified final dir failed — unverified plaintext may remain (SR-7/M-8)",
				"migration", req.MigrationName, "dir", destDir)
		}
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

// authoritativePodUID resolves the pod UID for a per-migration RPC, given the agent's
// migrationPodUID cache and a freshly-resolved value from the caller (the controller's live pod
// read on ArmZeroWindow/DisarmZeroWindow, or the freshly-fetched CR's spec.SourcePodUID on
// Checkpoint). The fresh value always wins when non-empty: it reflects the CURRENT pod
// incarnation, whereas the cache — written once by PrepareSource and never evicted mid-migration
// — is a crash-recovery fallback only, and can be stale for a migration name reused across pod
// incarnations (sprint46B9 pre-work diagnosis: a retried CR, or this repo's own live-proof test
// harness, reusing one migration name across separate redis pods). Returns the UID to use and
// whether a stale, disagreeing cache value was found, so the caller can log a diagnostic instead
// of silently swapping.
func authoritativePodUID(cachedUID, freshUID string) (podUID string, stale bool) {
	if freshUID == "" {
		return cachedUID, false
	}
	return freshUID, cachedUID != "" && cachedUID != freshUID
}

// ArmZeroWindow implements MigrationAgentServiceServer.ArmZeroWindow.
// It polls tcpi_unacked==0 for all TCP sockets of the source pod before returning armed=true,
// ensuring no in-flight bytes are in the send buffer when FinalFreeze fires (ADR-0049).
// A watchdog goroutine auto-disarms if DisarmZeroWindow is not received within
// FreezeWindowBudgetMs + zwWatchdogMargin to prevent indefinite client stall.
func (s *AgentServer) ArmZeroWindow(ctx context.Context, req *agentpb.ArmZeroWindowRequest) (*agentpb.ArmZeroWindowResponse, error) {
	log.Info("ArmZeroWindow: arming zero-window hold", "migration", req.MigrationName, "podUID", req.PodUid)

	// The caller-supplied UID is authoritative: the controller resolves it fresh from the
	// live source pod on every reconcile (podmigration_controller.go ~756-760). The cached
	// migrationPodUID map (written once by PrepareSource, never evicted mid-migration) is a
	// crash-recovery fallback ONLY — it must never override a fresh value the caller supplies,
	// or a migration name reused across pod incarnations (a retried CR, or this repo's own
	// live-proof test harness) resolves a dead PID left over from a prior incarnation instead
	// of the live one (sprint46B9 pre-work diagnosis).
	s.migrationPodUIDMu.RLock()
	cachedPodUID := s.migrationPodUID[req.MigrationName]
	s.migrationPodUIDMu.RUnlock()
	podUID, stale := authoritativePodUID(cachedPodUID, req.PodUid)
	if stale {
		log.Info("ArmZeroWindow: stale migrationPodUID cache detected — preferring fresh caller-supplied UID",
			"migration", req.MigrationName, "cachedUID", cachedPodUID, "freshUID", req.PodUid)
	}

	// Resolve source pod veth ifindex. On darwin/stub resolveVethIfindex returns (0, nil).
	// On Linux it now returns a TYPED ERROR when the read mechanism itself failed (no host PID
	// sharing the pod netns, netns-broker spawn error, or a non-zero netns-exec) — distinct from
	// the authoritative (0, nil) "eth0 present but not a veth" non-veth-CNI signal.
	ifindex, rerr := resolveVethIfindex(podUID)
	if rerr != nil {
		// The veth ifindex read mechanism FAILED — this is NOT the terminal "non-veth CNI"
		// capability gap. On a veth CNI (Cilium lxc*, Flannel/kind) the peer demonstrably
		// exists; a resolution failure here is the "the read mechanism itself failed" race
		// class and must be reported truthfully, not mislabeled by armZeroWindowBPF(ifindex==0)
		// as "CNI unsupported (non-veth CNI path)". Under Strict we still fail CLOSED
		// (Armed=false — no false-green), but with an accurate, diagnosable BlockingReason that
		// names the real failing sub-path instead of libeling the CNI (ADR-0049 Amendment D).
		if req.TcpPreservationMode == "Strict" {
			log.Error(rerr, "ArmZeroWindow: veth ifindex resolution failed under Strict — failing closed (read-mechanism failure, NOT non-veth CNI)",
				"migration", req.MigrationName, "podUID", podUID)
			return &agentpb.ArmZeroWindowResponse{
				Armed:          false,
				BlockingReason: fmt.Sprintf("veth ifindex resolution failed (read mechanism — not a non-veth CNI): %v", rerr),
			}, nil
		}
		// None/BestEffort: degrade-and-continue (the hold is a protective optimisation, not
		// required for seq_delta=0 correctness). ifindex is 0 here; armZeroWindowBPF is a no-op
		// under these modes.
		log.Info("ArmZeroWindow: veth ifindex resolution failed — degrading (BestEffort/None; hold is optional)",
			"migration", req.MigrationName, "podUID", podUID, "err", rerr)
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

	// See ArmZeroWindow: the caller-supplied UID must win over the cache for the same reason.
	s.migrationPodUIDMu.RLock()
	cachedPodUID := s.migrationPodUID[req.MigrationName]
	s.migrationPodUIDMu.RUnlock()
	podUID, stale := authoritativePodUID(cachedPodUID, req.PodUid)
	if stale {
		log.Info("DisarmZeroWindow: stale migrationPodUID cache detected — preferring fresh caller-supplied UID",
			"migration", req.MigrationName, "cachedUID", cachedPodUID, "freshUID", req.PodUid)
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

	// DisarmZeroWindow is the last source-agent RPC that reads migrationPodUID /
	// migrationSeqSnapshots in a successful migration — evict here, not on the
	// destination-side Restore path (a different AgentServer process on a different node)
	// and not on ReleaseCheckpoint (which fires earlier in this same migration, before this
	// handler runs, and would delete the entry out from under this very read).
	s.migrationPodUIDMu.Lock()
	delete(s.migrationPodUID, req.MigrationName)
	s.migrationPodUIDMu.Unlock()
	s.migrationSeqSnapshotsMu.Lock()
	delete(s.migrationSeqSnapshots, req.MigrationName)
	s.migrationSeqSnapshotsMu.Unlock()

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

// brokerThawSourcePID delivers SIGCONT to a frozen SOURCE workload PID via the
// unconfined netns-broker (C-06 grounding decision: MUST_ROUTE_BROKER).
//
// The prior assumption was that a source workload runs under peer=podmotion-agent
// and is therefore signal-permitted by the confined agent's own AppArmor profile,
// so source-tree thaws used a direct syscall.Kill(pid, SIGCONT). That premise is
// UNVERIFIED against a live containerd-managed source workload on the KVM substrate
// (the C-06 mechanism-grounding precondition; the empirical peer-label capture is
// owed to the Sprint-44 live baseline). The broker route is correct-by-construction
// regardless of the label: the unconfined broker is not subject to AppArmor signal
// mediation, so it delivers SIGCONT whether the direct path would have been permitted
// or DENIED. If the direct path were in fact denied, a direct syscall.Kill would leave
// the source in SIGSTOP — an invariant-1 / ADR-0012 break (the source is the only
// surviving copy on the abort/rollback path); routing through the broker forecloses
// that hazard by construction. The broker is the single resume owner for BOTH the
// restored tree (brokerResumeRestoredPID) and the source tree, so the class of
// regression that produced the earlier MAC/SIGCONT drift cannot recur.
//
// The starttime (field 22 of /proc/<pid>/stat) is read now and passed to the broker,
// which re-verifies it before the kill (PID-reuse guard). On the thaw path the source
// is held in SIGSTOP (State T) by CRIU --leave-stopped, so it cannot have been reused
// between freeze and thaw. A read failure means the process is already gone (nothing
// to thaw); the broker refuses on a starttime mismatch. Idempotent: SIGCONT to an
// already-running process is harmless.
func brokerThawSourcePID(pid int32) error {
	startTime, err := readProcStartTime(pid)
	if err != nil {
		return fmt.Errorf("read source pid %d starttime for broker thaw: %w", pid, err)
	}
	return brokerSignalSourcePID(pid, startTime)
}

// brokerSignalSourcePID is the single broker call-site for a source-tree SIGCONT
// (C-06 MUST_ROUTE_BROKER). It takes an already-known starttime so callers that have
// a verified PID-reuse identity in hand (the durable frozen-source record on the
// startup-reconcile path) do not re-read /proc. The broker re-verifies the starttime
// server-side before signalling and rejects a zero starttime, so this fails closed on
// a lost identity rather than signalling a possibly-reused PID.
func brokerSignalSourcePID(pid int32, startTime uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return netnsbroker.NewClient().SignalPID(ctx, int(pid), int(syscall.SIGCONT), startTime)
}

// thawSourcePID resumes a source process that was left in SIGSTOP by LeaveStopped=true
// after a CRIU dump. Called on every error/rollback path that follows a successful dump
// so the source workload is never permanently frozen. Idempotent: if the process is
// already running (not stopped), SIGCONT is harmless.
//
// C-06 (MUST_ROUTE_BROKER): the resume is delegated to the unconfined netns-broker
// (brokerThawSourcePID) rather than the confined agent's own syscall.Kill, which is
// AppArmor-DENIED against a containerd-default-profile source workload. Leaving the
// source frozen would break invariant-1 / ADR-0012 (source must stay serving until
// TrafficVerified=True), so a failed thaw is loudly logged for manual intervention.
func thawSourcePID(pid int32, migrationName string) {
	if pid <= 0 {
		return
	}
	if err := brokerThawSourcePID(pid); err != nil {
		log.Error(err, "thawSourcePID: broker SIGCONT to source PID failed — source may remain frozen, manual intervention may be required (C-06)",
			"migration", migrationName, "sourcePID", pid)
		return
	}
	log.Info("thawSourcePID: SIGCONT delivered to frozen source process via netns-broker (C-06)",
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
	msg := criuImageInconsistencyEventMsg(imgErr.FdID, imgErr.NameLeaf, imgErr.BackingMntID, imgErr.BackingFstype)
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
		Source:         corev1.EventSource{Component: "podmotion-agent"},
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
// brokerResumeRestoredPID delivers SIGCONT to the CRIU-restored workload root via
// the unconfined netns-broker (ADR-0312). The restored tree runs under containerd's
// default AppArmor profile (a runtime-defined peer label, e.g. runc), so the
// confined main agent's own syscall.Kill(pid, SIGCONT) is DENIED by AppArmor signal
// mediation; the broker is unconfined and not mediated. The PID is at this point
// held in SIGSTOP by CRIU (--leave-stopped) so it cannot have been reused; field 22
// (starttime) is read now and passed so the broker re-verifies identity before the
// kill (PID-reuse guard). C-06 (MUST_ROUTE_BROKER): source-tree thaws
// (frozen_source_registry.go, thawSourcePID via brokerThawSourcePID) route through
// the broker too. The broker route is correct-by-construction whether or not the
// direct peer=podmotion-agent path would be permitted (that label is UNVERIFIED against
// a live source workload — capture owed to the Sprint-44 live baseline), so the broker
// is the single resume owner for both the restored tree and the source tree.
// ADR-0354 round-5 sweep: netnsbroker.Client.SignalPID funnels the same Client.do(ctx) as the
// other broker-exec surfaces (D5's predicate). Both live call sites (enforceRestoreOrderingInvariant,
// reached from joinNsRestore's NRI entry point AND the gRPC Restore handler) have a real caller ctx
// in scope, so it is threaded through here instead of rooting a fresh context.Background(). The 30s
// per-call ceiling is preserved via remainingOrCeiling's tighten-only clamp (D2 discipline).
func brokerResumeRestoredPID(ctx context.Context, pid int) error {
	startTime, err := readProcStartTime(int32(pid))
	if err != nil {
		return fmt.Errorf("read restored pid %d starttime for broker resume: %w", pid, err)
	}
	budget := remainingOrCeiling(ctx, 30*time.Second)
	sigCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return netnsbroker.NewClient().SignalPID(sigCtx, pid, int(syscall.SIGCONT), startTime)
}

func enforceRestoreOrderingInvariant(ctx context.Context, pid int, migrationName string, expectedCount int, deferResume bool) (time.Time, time.Time, error) {
	// If the restore was not TCP-stateful (no expected connections), skip socket
	// polling and resume immediately — the invariant only applies to TCP migrations.
	// (deferResume is irrelevant here: with no TCP sockets there is no seq_delta to
	// preserve and no handoff to wait for.)
	if expectedCount == 0 {
		now := time.Now()
		log.Info("enforceRestoreOrderingInvariant: no TCP connections expected, resuming immediately",
			"migration", migrationName, "pid", pid)
		// ADR-0312: the restored tree runs under containerd's default AppArmor profile;
		// the confined agent's own SIGCONT is DENIED. Delegate to the unconfined broker.
		if err := brokerResumeRestoredPID(ctx, pid); err != nil {
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
		// Count only MIGRATABLE sockets. expectedCount = len(SeqSnapshots) was captured
		// loopback-free at freeze, so the observed count must exclude intra-pod loopback
		// too: a fresh kubelet health probe on the restored pod is not one of the migrated
		// sockets this liveness gate waits for, and must not satisfy the count before the
		// real held socket is actually restored (which would release SIGCONT prematurely).
		lastCount = len(network.FilterMigratableTCP(sockEntries))
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
			// ADR-0312: delegate the cross-profile resume to the unconfined broker
			// (the confined agent's SIGCONT to the restored tree is AppArmor-DENIED).
			if err := brokerResumeRestoredPID(ctx, pid); err != nil {
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

// secureWipeChunkBytes is the fixed reusable zero-buffer size used to overwrite files in
// zeroizeDir. A single reusable buffer looped to file size replaces the prior per-file
// make([]byte, info.Size()) allocation, which allocated GB+ for pages-*.img images (M-8).
const secureWipeChunkBytes = 1 << 20 // 1 MiB

// zeroizeDir overwrites all regular files in dir with zeros then removes the directory.
// Called to scrub checkpoint images (verbatim process memory) from tmpfs on all exit paths
// (Standing Rule 7 / invariant 4). It is the single audited secure-wipe primitive.
//
// M-8 (B-04): a failed overwrite is now PROPAGATED, not swallowed. The prior implementation
// discarded both the per-file WriteAt error and the filepath.Walk error, then returned only
// os.RemoveAll's result — so a file that could not be zeroed (WriteAt failure) still yielded a
// nil error while os.RemoveAll unlinked it, leaving recoverable live memory pages on tmpfs and
// reporting success. Now: any WriteAt failure (or a non-skippable Walk/open error) makes
// zeroizeDir return non-nil so every abort/exit-path caller can treat the wipe as failed
// (fatal-and-logged) rather than silently trusting a "wiped" claim. The directory is still
// removed on the RemoveAll path afterward, but a wipe failure is surfaced first.
func zeroizeDir(dir string) error {
	zeros := make([]byte, secureWipeChunkBytes)
	wipeErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// A stat/open error during traversal: propagate os.IsNotExist so callers can
			// treat an already-absent dir as success, but surface any other error (e.g.
			// permission) so a file that cannot be reached is not silently skipped.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, openErr := os.OpenFile(path, os.O_WRONLY, 0)
		if openErr != nil {
			if os.IsNotExist(openErr) {
				return nil
			}
			return fmt.Errorf("secure-wipe: open %q: %w", path, openErr)
		}
		// Overwrite the whole file with zeros using a fixed reusable buffer looped to size,
		// so a GB+ image does not allocate a GB+ buffer (M-8) and every WriteAt error is caught.
		var off int64
		remaining := info.Size()
		var writeErr error
		for remaining > 0 {
			n := int64(len(zeros))
			if remaining < n {
				n = remaining
			}
			if _, wErr := f.WriteAt(zeros[:n], off); wErr != nil {
				writeErr = fmt.Errorf("secure-wipe: overwrite %q at offset %d: %w", path, off, wErr)
				break
			}
			off += n
			remaining -= n
		}
		if syncErr := f.Sync(); syncErr != nil && writeErr == nil {
			writeErr = fmt.Errorf("secure-wipe: sync %q: %w", path, syncErr)
		}
		if closeErr := f.Close(); closeErr != nil && writeErr == nil {
			writeErr = fmt.Errorf("secure-wipe: close %q: %w", path, closeErr)
		}
		return writeErr
	})
	rmErr := os.RemoveAll(dir)
	// Surface a wipe failure ahead of the removal result: a failed overwrite is the
	// security-relevant fact (memory may be recoverable), whereas RemoveAll failing is a
	// lesser "dir still present" condition. If the wipe succeeded, report RemoveAll's result.
	if wipeErr != nil {
		return wipeErr
	}
	return rmErr
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
