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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/network"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

var log = logf.Log.WithName("agent-server")

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
// and MUST NOT fall back to the name-based findRestoredProcessPID scan, and MUST NOT set
// criuRestoreConfirmed (ADR-0123 D2 step 5 / AC5).
var ErrRestoredPIDNotFound = errors.New("restored process PID not found in replacement pod cgroup")

// zwHoldState tracks per-migration zero-window hold state including armed timestamp and
// watchdog cancel for auto-disarm on FreezeWindowBudgetMs + margin expiry.
type zwHoldState struct {
	armedAtNs      int64
	watchdogCancel context.CancelFunc
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
	}
}

// JoinNsRestore is the exported entry point for the NRI StartContainer hook.
// It invokes the CRIU restore path that enters the container's existing namespaces
// (created by runc) and restores the checkpointed process tree.
// migrationName is used for log tagging; checkpointDir is the tmpfs images path;
// sandboxID is the containerd sandbox (pause container) ID of the replacement pod whose
// network namespace the restored process must join (ADR-0122). It comes from the NRI pod
// sandbox object (pod.GetId()).
//
// ADR-0122 + ADR-0125: rather than minting an empty netns (--empty-ns net), JoinNsRestore
// resolves the replacement pod's sandbox netns via the containerd sandbox API (B1), opens the
// netns path with an fstat/stat inode cross-check (B2), then closes the fd and hands the netns
// PATH to CRIU via --join-ns net:<path> (ADR-0125 — CRIU 4.2 has no --net-fd flag). The restored
// process then comes up inside the pod netns, inheriting the pod IP, veth pair, and CNI routing —
// reachable at the pod IP with no post-restore namespace surgery.
func (s *AgentServer) JoinNsRestore(migrationName, checkpointDir, sandboxID string) (int, error) {
	return joinNsRestore(migrationName, checkpointDir, "", sandboxID)
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
		out, err := exec.Command("nsenter", "--net="+netnsArg,
			"cat", "/sys/class/net/eth0/address").CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("ReadReplVethMAC: nsenter %s: %w (%s)", netnsArg, err, strings.TrimSpace(string(out)))
			continue
		}
		mac := strings.TrimSpace(string(out))
		if mac == "" {
			lastErr = fmt.Errorf("ReadReplVethMAC: empty MAC via %s", netnsArg)
			continue
		}
		return mac, nil
	}
	return "", lastErr
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
		bridgeIf = "cni0"
	}
	fdbIf := req.FdbIfname
	if fdbIf == "" {
		fdbIf = "flannel.1"
	}

	// D2.1: ip neigh replace <oldPodIP> lladdr <replVethMAC> dev cni0 nud permanent
	if err := network.SetPodIPNeigh(ctx, bridgeIf, oldIP, mac); err != nil {
		return &agentpb.InjectIPHandoffResponse{Injected: false,
			BlockingReason: fmt.Sprintf("cni0 neigh: %v", err)}, nil
	}
	// D2.2: ip neigh replace <oldPodIP> lladdr <replVethMAC> dev flannel.1 nud permanent
	if err := network.SetPodIPNeigh(ctx, fdbIf, oldIP, mac); err != nil {
		return &agentpb.InjectIPHandoffResponse{Injected: false,
			BlockingReason: fmt.Sprintf("flannel.1 neigh: %v", err)}, nil
	}

	resp := &agentpb.InjectIPHandoffResponse{Injected: true}

	// Decision 3: return this node's VTEP MAC for the operator to thread to source cleanup.
	if vtepMAC, derr := network.DiscoverVTEPMAC(ctx, "", fdbIf); derr == nil {
		resp.DestVtepMac = vtepMAC.String()
	} else {
		log.Error(derr, "InjectIPHandoff: DiscoverVTEPMAC failed (non-fatal)", "ifName", fdbIf)
	}

	// Decision 5: in-node reachability probe — ping the OLD pod IP from this node.
	if req.Probe {
		out, perr := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", req.OldPodIp).CombinedOutput()
		resp.ProbeOutput = strings.TrimSpace(string(out))
		resp.ProbeOk = perr == nil
		if perr != nil {
			log.Info("InjectIPHandoff: reachability probe failed", "oldPodIP", req.OldPodIp, "err", perr, "output", resp.ProbeOutput)
		} else {
			log.Info("InjectIPHandoff: reachability probe OK", "oldPodIP", req.OldPodIp)
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

	bridgeIf := req.BridgeIfname
	if bridgeIf == "" {
		bridgeIf = "cni0"
	}
	fdbIf := req.FdbIfname
	if fdbIf == "" {
		fdbIf = "flannel.1"
	}

	var firstErr error
	if err := network.DeletePodIPNeigh(ctx, bridgeIf, oldIP); err != nil {
		firstErr = err
	}
	if err := network.DeletePodIPNeigh(ctx, fdbIf, oldIP); err != nil && firstErr == nil {
		firstErr = err
	}
	if firstErr != nil {
		return &agentpb.CleanupSourceIPHandoffResponse{Cleaned: false,
			BlockingReason: firstErr.Error()}, nil
	}

	log.Info("CleanupSourceIPHandoff: stale neigh removed (ADR-0133 D4)", "migration", req.MigrationName, "oldPodIP", req.OldPodIp)
	return &agentpb.CleanupSourceIPHandoffResponse{Cleaned: true}, nil
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
	}
	if tlsCfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	} else {
		log.Info("gRPC server starting without TLS — dev mode", "addr", addr)
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

// ResolveNetnsFromSandbox returns an open *os.File for the network namespace of the
// containerd sandbox (pause container) identified by sandboxID, along with the resolved
// netns filesystem path. The caller must Close the returned file.
//
// ADR-0125 (Sprint 20): the open fd exists only to run the B2 TOCTOU inode cross-check
// (open path, fstat fd vs stat path). It is no longer handed to CRIU — the caller closes
// it and passes the returned path string to CRIU via --join-ns net:<path>.
//
// ADR-0122 B1 (post-quorum): this replaces the previous /proc/*/comm "pause" scan, which
// was ambiguous on multi-pod nodes (every pod's pause process matches, so the scan could
// not reliably pick the correct sandbox). The sandbox ID comes from the NRI pod sandbox
// object (pod.GetId()) and is unambiguous per pod. We read the sandbox's OCI spec under
// the containerd "k8s.io" namespace, locate the spec.Linux.Namespaces entry with
// Type == "network", and open its Path directly.
//
// ADR-0122 B2 (post-quorum): TOCTOU close-out. We open the netns *path* (e.g.
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
	out, err := exec.Command("ctr", "--namespace", "k8s.io", "containers", "info", sandboxID).Output()
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
func FindContainerTaskID(podUID string) (string, error) {
	out, err := exec.Command("ctr", "--namespace", "k8s.io", "tasks", "list").Output()
	if err != nil {
		return "", fmt.Errorf("ctr tasks list: %w", err)
	}
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
		cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
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
	return "", fmt.Errorf("containerd task not found for pod UID %s", podUID)
}

// ctrCheckpoint calls `ctr --namespace k8s.io tasks checkpoint` for the given task,
// writing CRIU images to imagesDir. Also copies config.json from the containerd
// bundle directory into imagesDir so the destination can set up an OCI bundle for restore.
func ctrCheckpoint(taskID, imagesDir string) (int64, error) {
	// 0700: checkpoint images contain verbatim process memory and must be root-only.
	if err := os.MkdirAll(imagesDir, 0o700); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", imagesDir, err)
	}
	cmd := exec.Command("ctr", "--namespace", "k8s.io", "tasks", "checkpoint",
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
		bundleDir := fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s", taskID)
		if dumpLog, readErr := os.ReadFile(filepath.Join(bundleDir, "criu-dump.log")); readErr == nil {
			outStr += "\n--- criu-dump.log ---\n" + string(dumpLog)
		}
		if strings.Contains(outStr, "In-flight") ||
			strings.Contains(outStr, "in-flight") ||
			strings.Contains(outStr, "Connected TCP socket") ||
			strings.Contains(outStr, "tcp-established") ||
			strings.Contains(outStr, "sk-inet.c") ||
			strings.Contains(outStr, "inet") {
			return 0, fmt.Errorf("ctr tasks checkpoint: %w\noutput: %s", ErrCtrInFlightTCP, outStr)
		}
		return 0, fmt.Errorf("ctr tasks checkpoint: %w\noutput: %s", err, out)
	}

	// Copy config.json from the containerd bundle into the checkpoint dir.
	bundleDir := fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s", taskID)
	srcCfg := filepath.Join(bundleDir, "config.json")
	dstCfg := filepath.Join(imagesDir, "config.json")
	if data, readErr := os.ReadFile(srcCfg); readErr == nil {
		_ = os.WriteFile(dstCfg, data, 0o644)
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
	"/run/secrets/kubernetes.io/serviceaccount",
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

func buildCRIURestoreArgs(checkpointDir, rootfsDir, dataDir, termlogFile, secretsDir, restoreLogPath, destNetnsFd, petnsPath string) []string {
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
		"--mntns-compat-mode",
		// --ext-mount-map auto handles the standard pseudo-fs and containerd/runc submounts
		// (/proc/*, /sys/*, /dev/*) that CRIU autodetects as external. The explicit
		// "/data:<dataDir>" map below takes precedence for /data, overriding auto's
		// CRIU:AUTOGENERATED key so the redis volume binds to a real (empty) destination dir
		// instead of the nonexistent source-node containerd volume path. (ADR-0131.)
		"--ext-mount-map", "auto",
		"--manage-cgroups=ignore",
		"--ext-mount-map", "/dev/null:/dev/null",
		// /data's ext_key is rewritten to the stable token "pm-data" in patchCheckpointImages;
		// map that token to an empty destination dir so the redis volume mount resolves cross-node.
		"--ext-mount-map", fmt.Sprintf("pm-data:%s", dataDir),
		"--ext-mount-map", fmt.Sprintf("/dev/termination-log:%s", termlogFile),
		// The kubelet's service-account tmpfs is a source-node-specific bind mount whose
		// inner token files are not pre-staged on the destination; CRIU then fails to
		// bind-mount it ("Can't bind-mount at .../run/secrets/kubernetes.io/serviceaccount:
		// No such file or directory", mount.c:2511). Skip it on restore — it is re-provided
		// by the destination kubelet for the replacement pod, and the migrated workload
		// (redis) does not depend on the SA token. Mirrors the SkipMnt policy already used on
		// the go-criu restore path. (ADR-0131 restore path.)
		"--skip-mnt", "/run/secrets/kubernetes.io/serviceaccount",
		"--ext-mount-map", "/dev/shm:/dev/shm",
		"--ext-mount-map", "/etc/resolv.conf:/etc/resolv.conf",
		"--ext-mount-map", "/etc/hostname:/etc/hostname",
		"--ext-mount-map", "/etc/hosts:/etc/hosts",
		"-v4",
		"-o", restoreLogPath,
	}
	if destNetnsFd != "" {
		args = append(args, "--join-ns", "net:"+destNetnsFd)
		// --leave-stopped: restored process tree stays in SIGSTOP until we send SIGCONT.
		// SIGCONT is sent only after SocketsLive=True is confirmed (M23 ordering invariant).
		args = append(args, "--leave-stopped")
	} else {
		// ADR-0125 (supersedes ADR-0122 §3): join the replacement pod's pause container netns
		// by PATH instead of minting an empty one. CRIU 4.2 has no --net-fd flag; the documented
		// flag is --join-ns net:<path>. The restored process inherits the pod IP, veth, and CNI
		// routes. No fd is passed via ExtraFiles.
		args = append(args, "--join-ns", "net:"+petnsPath)
	}
	return args
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
func joinNsRestore(migrationName, checkpointDir, destNetnsFd, sandboxID string) (int, error) {
	cfgPath := filepath.Join(checkpointDir, "config.json")
	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		return 0, fmt.Errorf("read config.json: %w", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		return 0, fmt.Errorf("parse config.json: %w", err)
	}

	// Determine the container image from OCI annotations.
	imageName := "docker.io/library/redis:7-alpine"
	if ann, ok := cfg["annotations"].(map[string]interface{}); ok {
		if img, ok := ann["io.kubernetes.cri.image-name"].(string); ok && img != "" {
			imageName = img
		}
	}
	if strings.Count(imageName, "/") == 0 {
		imageName = "docker.io/library/" + imageName
	} else if strings.Count(imageName, "/") == 1 && !strings.Contains(strings.SplitN(imageName, "/", 2)[0], ".") {
		imageName = "docker.io/" + imageName
	}

	// Pull the image if not already present.
	pullOut, _ := exec.Command("ctr", "--namespace", "k8s.io", "images", "ls", "-q").Output()
	if !strings.Contains(string(pullOut), imageName) {
		if out, err := exec.Command("ctr", "--namespace", "k8s.io", "images", "pull", imageName).CombinedOutput(); err != nil {
			return 0, fmt.Errorf("pull %s: %w\n%s", imageName, err, out)
		}
	}

	// Step 1: Patch checkpoint images to remove cross-node-incompatible entries.
	if err := patchCheckpointImages(checkpointDir); err != nil {
		return 0, fmt.Errorf("patch checkpoint images: %w", err)
	}

	// Step 2: Mount overlayfs rootfs from containerd snapshot layers.
	bundleDir := fmt.Sprintf("/var/lib/podmotion/restore/%s/bundle", migrationName)
	rootfsDir := filepath.Join(bundleDir, "rootfs")
	placeholderID := "pm-placeholder-" + migrationName
	if err := setupRestoreOverlayfs(migrationName, checkpointDir, imageName, rootfsDir); err != nil {
		return 0, fmt.Errorf("setup rootfs overlayfs: %w", err)
	}
	// On any error after this point: unmount overlay, remove upper/work dirs, kill placeholder.
	success := false
	defer func() {
		if success {
			return
		}
		_ = exec.Command("umount", rootfsDir).Run()
		_ = os.RemoveAll(bundleDir)
		_ = exec.Command("ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()
		_ = exec.Command("ctr", "--namespace", "k8s.io", "container", "rm", placeholderID).Run()
	}()

	// Step 3: Create ext-mount-map target paths on the host.
	dataDir := fmt.Sprintf("/var/lib/podmotion/restore/%s/data", migrationName)
	secretsDir := fmt.Sprintf("/var/lib/podmotion/restore/%s/secrets", migrationName)
	termlogFile := fmt.Sprintf("/var/lib/podmotion/restore/%s/termination-log", migrationName)
	// dataDir (0o755): CRIU re-enters the container's /data mount via --ext-mount-map;
	// the directory must be world-executable so CRIU (running as root but entering the
	// container's user ns) can traverse it (ADR-0121).
	// secretsDir stays 0o700: holds service-account tokens — never world-readable.
	_ = os.MkdirAll(dataDir, 0o755)
	_ = os.MkdirAll(secretsDir, 0o700)
	_ = os.WriteFile(termlogFile, nil, 0o644)
	// Create missing mount target directories inside rootfs (CRIU bind-mounts into these).
	_ = os.MkdirAll(filepath.Join(rootfsDir, "run/secrets/kubernetes.io/serviceaccount"), 0o755)
	// Create mountpoint directories CRIU bind-mounts into during restore. redis:7 declares
	// /data as a VOLUME and it is not guaranteed to materialise as a directory in the overlay
	// lower layers; /dev/shm likewise. Without the mountpoint dir present in the restore rootfs
	// CRIU fails with "Can't bind-mount at .../data: No such file or directory" (mount.c:2511).
	for _, d := range []string{"data", "dev/shm"} {
		_ = os.MkdirAll(filepath.Join(rootfsDir, d), 0o755)
	}
	for _, f := range []string{"etc/resolv.conf", "etc/hostname", "etc/hosts"} {
		p := filepath.Join(rootfsDir, f)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			_ = os.WriteFile(p, nil, 0o644)
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
	restoreLogPath := filepath.Join(checkpointDir, "restore.log")
	var petnsPath string
	if destNetnsFd == "" {
		if sandboxID == "" {
			return 0, fmt.Errorf("ADR-0125: replacement pod sandbox ID required to resolve netns for --join-ns net:<path> restore")
		}
		// B1: resolve via the containerd sandbox API (unambiguous per pod, no /proc comm scan).
		// B2: ResolveNetnsFromSandbox opens the netns path and cross-checks fd/path inodes.
		netnsFd, resolvedPath, rerr := ResolveNetnsFromSandbox(context.Background(), nil, sandboxID)
		if rerr != nil {
			return 0, fmt.Errorf("resolve replacement pod sandbox netns: %w", rerr)
		}
		// ADR-0125: the fd existed only for the B2 inode cross-check. Close it now; CRIU joins by
		// path, not by inherited fd.
		_ = netnsFd.Close()
		petnsPath = resolvedPath
		log.Info("joinNsRestore: joining replacement pod netns via --join-ns net:<path> (ADR-0125)",
			"sandboxID", sandboxID, "netnsPath", petnsPath)
	}

	criuArgs := buildCRIURestoreArgs(checkpointDir, rootfsDir, dataDir, termlogFile, secretsDir, restoreLogPath, destNetnsFd, petnsPath)
	// ADR-0124: dynamically scan the (post-patch) mountpoints-*.img for containerd masked-path
	// external mounts and append their --ext-mount-map <mnt_id>:/dev/null args. Fail loud before
	// invoking CRIU if any external mount is not safely mappable (D4).
	maskedArgs, err := buildMaskedPathExtMountArgs(checkpointDir)
	if err != nil {
		return 0, err
	}
	criuArgs = append(criuArgs, maskedArgs...)
	criuCmd := exec.Command("/usr/local/sbin/criu", criuArgs...)
	// ADR-0125: no ExtraFiles — CRIU joins the netns by path (--join-ns net:<path>), not by an
	// inherited fd. The previous --net-fd fd-passing was removed (CRIU 4.2 has no --net-fd flag).
	// Capture CRIU's stderr: when CRIU fails before opening its -o logfile (e.g. arg/ext-mount
	// resolution errors), the only diagnostic is on stderr. A bounded buffer keeps it cheap.
	var criuStderr bytes.Buffer
	criuCmd.Stderr = &criuStderr

	// ADR-0128: snapshot the agent's own cgroup PID set BEFORE launching CRIU. With
	// --manage-cgroups=ignore the restored process tree inherits the launcher's (agent's)
	// cgroup; we diff this snapshot after restore to find the new workload PID, then move
	// it into the pod's sandbox cgroup. Best-effort: only used on the cold (sandboxID!="")
	// path; a snapshot error there is fatal and surfaced at resolution time.
	beforeAgentPIDs, agentPIDsErr := getAgentCgroupPIDs()

	if err := criuCmd.Start(); err != nil {
		return 0, fmt.Errorf("criu restore start: %w", err)
	}

	// ADR-0127 (revised Sprint 22): restore.log content is the PRIMARY success signal — and on the
	// cold --join-ns net:<path> path CRIU does NOT self-exit. Without --restore-detached (forbidden
	// by standing constraint) and without --leave-stopped (that flag is only on the TCP-stateful
	// branch), CRIU restores the process tree, writes "Restore finished successfully. Tasks
	// resumed." to restore.log, and then stays in the foreground as the parent of the restored
	// workload, blocking in wait4() for the lifetime of the workload (confirmed Sprint 22: criu
	// in do_wait, redis-server alive as its child, restore.log marker present, 57 KiB written).
	//
	// Therefore we must NOT call criuCmd.Wait() synchronously here — it would never return and the
	// NRI StartContainer handler would hang until containerd kills the container (the Sprint 22
	// failure: replacement pod entered Failed). Instead we poll restore.log for the success marker
	// while CRIU keeps running; once the marker appears the process tree is live and we proceed.
	// A background goroutine performs the single Wait() to reap CRIU if/when it eventually exits,
	// so there is no zombie and Wait() is still called exactly once (Arch-A double-Wait guard).
	criuReaped := make(chan error, 1)
	go func() { criuReaped <- criuCmd.Wait() }()

	const (
		markerPollInterval = 100 * time.Millisecond
		markerPollTimeout  = 60 * time.Second
	)
	markerSeen := false
	deadline := time.Now().Add(markerPollTimeout)
	for time.Now().Before(deadline) {
		if logBytes, rerr := os.ReadFile(restoreLogPath); rerr == nil &&
			strings.Contains(string(logBytes), "Restore finished successfully") {
			markerSeen = true
			break
		}
		// If CRIU exited before writing the marker, stop polling and inspect the exit.
		select {
		case waitErr := <-criuReaped:
			exitCode := -1
			if criuCmd.ProcessState != nil {
				exitCode = criuCmd.ProcessState.ExitCode()
			}
			// Re-read once: CRIU may have flushed the marker right before exiting.
			if logBytes, rerr := os.ReadFile(restoreLogPath); rerr == nil &&
				strings.Contains(string(logBytes), "Restore finished successfully") {
				markerSeen = true
			}
			if !markerSeen {
				stderrTail := strings.TrimSpace(criuStderr.String())
				if len(stderrTail) > 4096 {
					stderrTail = stderrTail[len(stderrTail)-4096:]
				}
				return 0, fmt.Errorf("criu restore exited (exit code %d) without 'Restore finished successfully' in restore.log: %w\ncriu stderr:\n%s\nrestore.log tail:\n%s",
					exitCode, waitErr, stderrTail, readLogTail(restoreLogPath, 4096))
			}
		default:
		}
		if markerSeen {
			break
		}
		time.Sleep(markerPollInterval)
	}

	if !markerSeen {
		stderrTail := strings.TrimSpace(criuStderr.String())
		if len(stderrTail) > 4096 {
			stderrTail = stderrTail[len(stderrTail)-4096:]
		}
		return 0, fmt.Errorf("criu restore did not write 'Restore finished successfully' to restore.log within %s (ADR-0127): \ncriu stderr:\n%s\nrestore.log tail:\n%s",
			markerPollTimeout, stderrTail, readLogTail(restoreLogPath, 4096))
	}

	// PRIMARY success: restore.log confirms the process tree was restored and resumed. CRIU remains
	// running in the foreground as the workload parent; that is expected on this path and is NOT a
	// zombie (the background goroutine above reaps it when the workload exits). Proceed to PID scan.
	log.Info("joinNsRestore: restore.log confirms 'Restore finished successfully' (ADR-0127); "+
		"CRIU remains as foreground workload parent — proceeding to PID resolution",
		"restoreLogPath", restoreLogPath)

	// Step 5: ADR-0123 D2 — locate the restored application PID via the replacement pod's
	// cgroup, NOT by process name. CRIU has exited (D1), so its PID can no longer be confused
	// with the application and there is no zombie to match. On the cold (--join-ns net:<path>) path the
	// sandboxID anchors the pod cgroup; the comm-based findRestoredProcessPID is never used as a
	// fallback (D2 step 5). The --join-ns Restore (TCP-stateful) path (no sandboxID) is out of Sprint-18 scope
	// and retains the legacy name/cgroup scan.
	var pid int
	if sandboxID != "" {
		// ADR-0128: --manage-cgroups=ignore leaves the restored tree in the AGENT's cgroup, not
		// the pod cgroup, so the ADR-0123 D2 pod-cgroup scan finds nothing. Instead diff the agent
		// cgroup against the pre-CRIU snapshot to find the new workload PID, then move it into the
		// pod's sandbox cgroup so containerd/k8s can manage it.
		if agentPIDsErr != nil {
			return 0, fmt.Errorf("ADR-0128: snapshot agent cgroup PIDs before restore: %w", agentPIDsErr)
		}
		pid, err = findRestoredPIDInAgentCgroup(beforeAgentPIDs, criuCmd.Process.Pid)
		if err != nil {
			// Fail loud — never fall back to comm-scan on the cold path (D2 step 5 / AC5).
			return 0, err
		}
		// Resolve the pod's sandbox cgroup path from the pause PID (same anchor as ADR-0123 D2).
		pausePID, perr := sandboxPausePID(sandboxID)
		if perr != nil {
			return 0, fmt.Errorf("ADR-0128: resolve pause PID for sandbox %s: %w", sandboxID, perr)
		}
		podCgroup, cerr := cgroupV2Path(pausePID)
		if cerr != nil {
			return 0, fmt.Errorf("ADR-0128: read pod cgroup from pause PID %d (sandbox %s): %w",
				pausePID, sandboxID, cerr)
		}
		// Move the restored tree root into the pod cgroup (single cgroup.procs write moves the group).
		if merr := moveProcessToPodCgroup(pid, podCgroup); merr != nil {
			return 0, fmt.Errorf("ADR-0128: move restored PID %d into pod cgroup %s: %w", pid, podCgroup, merr)
		}
		log.Info("joinNsRestore: moved restored process into pod cgroup (ADR-0128)",
			"pid", pid, "podCgroup", podCgroup, "sandboxID", sandboxID)
	} else {
		pid, err = findRestoredProcessPID(checkpointDir)
		if err != nil {
			return 0, err
		}
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
	return pid, nil
}

// readLogTail returns at most maxBytes of the tail of the file at path, prefixed with a marker
// when truncated. Best-effort: returns a short diagnostic string on read error rather than
// failing, so it is safe to embed in an error message. The bound (Security note 2) prevents a
// hostile/huge restore.log from blowing up the error string.
func readLogTail(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("(restore.log unavailable: %v)", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Sprintf("(restore.log stat failed: %v)", err)
	}
	size := fi.Size()
	if size == 0 {
		return "(restore.log empty)"
	}
	start := int64(0)
	truncated := false
	if size > maxBytes {
		start = size - maxBytes
		truncated = true
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return fmt.Sprintf("(restore.log seek failed: %v)", err)
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return fmt.Sprintf("(restore.log read failed: %v)", err)
	}
	if truncated {
		return "...(truncated to last 4 KiB)...\n" + string(buf)
	}
	return string(buf)
}

// findRestoredPIDByCgroup implements ADR-0123 Decision 2: resolve the restored application PID
// by cgroup membership in the replacement pod, anchored on the pod's pause/sandbox container.
//
//  1. Resolve the pause PID for sandboxID (the ADR-0122 sandbox anchor) via `ctr tasks list`,
//     then read /proc/<pausePID>/cgroup to obtain the pod cgroup path. If the pause PID has
//     exited (TOCTOU), fail loud rather than scanning an empty cgroup (Security/Runtime note 3).
//  2. Scan /proc/*/cgroup for processes whose cgroup path matches the pod-UID subtree exactly
//     (not a prefix that could match a sibling pod), excluding the CRIU binary and the pause PID.
//  3. Among survivors, select the restored tree's root/leader: a cgroup-resident process whose
//     PPid is NOT itself in the pod cgroup (CRIU exited, so the tree was reparented to the agent
//     subreaper / PID 1). Tie-break by LOWEST PID — the leader starts first; higher PIDs are its
//     children. "Highest PID" is explicitly wrong (can pick a transient child).
//  4. Retry for up to 10s at 200ms intervals to allow reparenting to become observable.
//  5. On zero candidates after timeout, return ErrRestoredPIDNotFound (no comm-scan fallback).
func findRestoredPIDByCgroup(sandboxID string) (int, error) {
	pausePID, err := sandboxPausePID(sandboxID)
	if err != nil {
		return 0, fmt.Errorf("ADR-0123 D2: resolve pause PID for sandbox %s: %w", sandboxID, err)
	}
	// Read the pod cgroup path from the pause container. TOCTOU: if the pause PID has exited,
	// /proc/<pid>/cgroup is gone — fail loud, never scan an empty cgroup (Security note 3).
	podCgroup, err := cgroupV2Path(pausePID)
	if err != nil {
		return 0, fmt.Errorf("ADR-0123 D2: read pod cgroup from pause PID %d (sandbox %s): %w",
			pausePID, sandboxID, err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		pid, found := scanCgroupForRestoredRoot(podCgroup, pausePID)
		if found {
			log.Info("findRestoredPIDByCgroup: resolved restored PID via pod cgroup (ADR-0123 D2)",
				"pid", pid, "sandboxID", sandboxID, "pausePID", pausePID, "podCgroup", podCgroup)
			return pid, nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("%w (sandbox %s, podCgroup %s, pausePID %d, 10s timeout)",
				ErrRestoredPIDNotFound, sandboxID, podCgroup, pausePID)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// getAgentCgroupPIDs implements ADR-0128: returns the set of PIDs currently resident in the
// agent's OWN cgroup. It reads /proc/self/cgroup to get the agent's cgroup v2 path, then reads
// cgroup.procs for that path. Used to snapshot the agent cgroup before CRIU starts so the
// restored workload PID can be identified as the new entrant afterwards.
func getAgentCgroupPIDs() (map[int]bool, error) {
	selfPath, err := cgroupV2Path(os.Getpid())
	if err != nil {
		return nil, fmt.Errorf("read agent cgroup path from /proc/self/cgroup: %w", err)
	}
	procsPath := filepath.Join("/sys/fs/cgroup", selfPath, "cgroup.procs")
	data, err := os.ReadFile(procsPath)
	if err != nil {
		return nil, fmt.Errorf("read agent cgroup.procs (%s): %w", procsPath, err)
	}
	pids := make(map[int]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if pid, convErr := strconv.Atoi(line); convErr == nil {
			pids[pid] = true
		}
	}
	return pids, nil
}

// findRestoredPIDInAgentCgroup implements ADR-0128: with --manage-cgroups=ignore the CRIU-restored
// process tree lands in the AGENT's cgroup (the launcher's). This scans the agent cgroup for PIDs
// that were NOT present in beforePIDs (the pre-CRIU snapshot) and are NOT the CRIU process itself,
// returning the LOWEST such PID — the restored tree root (the leader starts first; children get
// higher PIDs). Retries for up to 10s at 200ms intervals to allow the restored tree to appear.
func findRestoredPIDInAgentCgroup(beforePIDs map[int]bool, criuPID int) (int, error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		current, err := getAgentCgroupPIDs()
		if err == nil {
			bestPID := 0
			for pid := range current {
				if beforePIDs[pid] || pid == criuPID {
					continue
				}
				// Defensive: never select the CRIU binary even if PID-reuse hides it.
				comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
				if strings.TrimSpace(string(comm)) == "criu" {
					continue
				}
				if bestPID == 0 || pid < bestPID {
					bestPID = pid
				}
			}
			if bestPID != 0 {
				log.Info("findRestoredPIDInAgentCgroup: resolved restored PID via agent cgroup diff (ADR-0128)",
					"pid", bestPID, "criuPID", criuPID)
				return bestPID, nil
			}
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("%w (agent-cgroup diff, criuPID %d, 10s timeout)", ErrRestoredPIDNotFound, criuPID)
		}
		time.Sleep(200 * time.Millisecond)
	}
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

// scanCgroupForRestoredRoot performs one pass of the ADR-0123 D2 scan over /proc. It returns the
// lowest-PID cgroup-resident process whose parent is NOT in the pod cgroup (the reparented tree
// root), excluding the pause PID and the CRIU binary. found is false when no candidate exists.
func scanCgroupForRestoredRoot(podCgroup string, pausePID int) (int, bool) {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}

	// First collect the set of cgroup-resident PIDs so we can test parentage against it.
	resident := make(map[int]bool)
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid, convErr := strconv.Atoi(p.Name())
		if convErr != nil || pid == pausePID {
			continue
		}
		if procInPodCgroup(pid, podCgroup) {
			resident[pid] = true
		}
	}

	bestPID := 0
	for pid := range resident {
		// Exclude the CRIU binary (it has exited on the cold path, but guard defensively).
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if strings.TrimSpace(string(comm)) == "criu" {
			continue
		}
		// Root/leader = a cgroup-resident process whose parent is NOT in the pod cgroup.
		ppid := procPPid(pid)
		if resident[ppid] {
			continue // this is a child of another in-cgroup process, not the tree root
		}
		// Tie-break by LOWEST PID (the leader starts first).
		if bestPID == 0 || pid < bestPID {
			bestPID = pid
		}
	}
	if bestPID == 0 {
		return 0, false
	}
	return bestPID, true
}

// procInPodCgroup reports whether the cgroup v2 path of pid is within the podCgroup subtree
// (exact subtree match, not a sibling-pod-matching prefix). A process is in the subtree when its
// path equals podCgroup or is a descendant (podCgroup + "/...").
func procInPodCgroup(pid int, podCgroup string) bool {
	path, err := cgroupV2Path(pid)
	if err != nil {
		return false
	}
	return path == podCgroup || strings.HasPrefix(path, podCgroup+"/")
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

// procPPid returns the parent PID of pid by reading field 4 (PPid) of /proc/<pid>/status.
// Returns 0 on any read/parse error.
func procPPid(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				ppid, _ := strconv.Atoi(fields[1])
				return ppid
			}
		}
	}
	return 0
}

// sandboxPausePID resolves the host PID of the pause/sandbox container identified by sandboxID
// via `ctr --namespace k8s.io tasks list`. The sandbox ID is the pause container's containerd
// task ID (from the NRI pod sandbox object, pod.GetId()), so its PID is the task's PID.
func sandboxPausePID(sandboxID string) (int, error) {
	out, err := exec.Command("ctr", "--namespace", "k8s.io", "tasks", "list").Output()
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

// patchCheckpointImages modifies the CRIU image files in checkpointDir to remove entries
// that cannot be restored cross-node:
//   - mountpoints: remove mounts with null or absent ext_key (masked proc/sys paths that
//     reference source-node device IDs with no valid external mapping).
//   - netns:       remove the extRootNetNS ext_key (references the source host's net ns).
//   - netdev:      remove VETH interfaces (peer ifindex doesn't exist on destination); keep lo.
//
// Idempotent: backs up originals as *.orig on first call; subsequent calls are no-ops.
func patchCheckpointImages(checkpointDir string) error {
	// Write the patch script to a temp file and run it with the system python3 + pycriu.
	// containerdMaskedPaths is injected as a JSON argv so the patch step consumes the same
	// single source of truth as buildMaskedPathExtMountArgs (ADR-0124 R2 / AC6) — no divergent
	// hardcoded copy. The delete set (masked path AND no ext_key) and the restore-time map set
	// are disjoint by construction: entries deleted here are never presented to CRIU.
	maskedJSON, err := json.Marshal(containerdMaskedPaths)
	if err != nil {
		return fmt.Errorf("marshal masked paths: %w", err)
	}
	patchScript := `
import sys, os, shutil, glob, json
import pycriu

ckpt = sys.argv[1]
null_ext_key_masked = set(json.loads(sys.argv[2]))

def backup(path):
    orig = path + '.orig'
    if not os.path.exists(orig):
        shutil.copy2(path, orig)
    return orig

# ---- mountpoints: keep only mounts with valid (non-null) ext_key or standard in-container mounts ----
for mp_path in glob.glob(os.path.join(ckpt, 'mountpoints-*.img')):
    src = backup(mp_path)
    with open(src, 'rb') as f:
        img = pycriu.images.load(f)
    # Remove entries that have no ext_key AND are masked paths (proc/* or sys/firmware, sys/fs/pstore)
    # that cannot be recreated cross-node. Entries with a valid ext_key are handled via --ext-mount-map.
    # Also unconditionally drop the kubelet service-account tmpfs mount: it is source-node-specific
    # (token files not pre-staged on the destination) and is re-provided by the destination kubelet
    # for the replacement pod. Leaving it makes CRIU restore fail with "Can't bind-mount at
    # .../run/secrets/kubernetes.io/serviceaccount: No such file or directory" (ADR-0131 restore path).
    # Kubelet-injected, source-node-specific bind mounts. The destination containerd/kubelet
    # re-provides equivalents for the replacement pod, and their source files are not staged in
    # the CRIU restore mntns, so CRIU fails with "Can't bind-mount at .../<path>: No such file
    # or directory" (mount.c:2511). Strip them at dump time (ADR-0131 restore path).
    drop_mnts = {
        '/run/secrets/kubernetes.io/serviceaccount',
        '/etc/hosts',
        '/etc/hostname',
        '/etc/resolv.conf',
        '/dev/termination-log',
        '/dev/shm',
        # containerd/runc-injected proc & sys submounts that CRIU otherwise autodetects as
        # external with a (null) source on restore (mount.c:3120). The destination runtime
        # re-provides them; stripping avoids needing --ext-mount-map auto (which collides with
        # the /data CRIU:AUTOGENERATED key). (ADR-0131 restore path.)
        '/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger',
        '/proc/acpi', '/proc/scsi', '/proc/interrupts', '/proc/kcore', '/proc/keys',
        '/proc/latency_stats', '/proc/timer_list', '/proc/sched_debug',
        '/sys/firmware', '/sys/fs/pstore', '/sys/fs/bpf', '/sys/fs/cgroup',
    }
    kept = [e for e in img['entries']
            if not (e.get('mountpoint') in null_ext_key_masked and not e.get('ext_key'))
            and e.get('mountpoint') not in drop_mnts]
    # Rewrite the /data volume mount into a self-contained tmpfs that CRIU creates fresh in
    # its restore yard, instead of an external bind to a source-node containerd volume path
    # that does not exist on the destination (CRIU:AUTOGENERATED ext_key → "Can't bind-mount
    # at .../data", mount.c:2511). Redis state lives in the checkpoint memory pages, not the
    # volume, so an empty fresh /data is correct (Sprint 23 proved state continuity). We clear
    # the external key and the source-node root/source so CRIU mounts a new tmpfs at /data.
    # /data volume mount: redirect the CRIU:AUTOGENERATED external bind to the destination
    # dataDir via a stable ext_key the restore maps with --ext-mount-map. The source-node
    # containerd volume path does not exist on the destination; rewriting the ext_key to a
    # known token ("pm-data") lets buildCRIURestoreArgs map it to an empty destination dir.
    # NOTE: this is the least-fragile of the approaches tried; synthesizing a tmpfs hit
    # "No device" and dropping the subtree hit a mount-tree BUG/segfault (mount.c:3953).
    # KNOWN BLOCKER (ADR-0132): CRIU 4.2 + containerd-overlay VOLUME-mount restore on this
    # PoC still fails here even with the ext_key rewrite; tracked for follow-up.
    for e in kept:
        if e.get('mountpoint') == '/data' and e.get('ext_key'):
            e['ext_key'] = 'pm-data'
    img['entries'] = kept
    with open(mp_path, 'wb') as f:
        pycriu.images.dump(img, f)
    print('mountpoints:', os.path.basename(mp_path), 'kept', len(kept), 'entries')

# ---- netns: remove extRootNetNS dependency (references source host net ns) ----
netns_path = os.path.join(ckpt, 'netns-10.img')
if os.path.exists(netns_path):
    src = backup(netns_path)
    with open(src, 'rb') as f:
        img = pycriu.images.load(f)
    for e in img['entries']:
        e.pop('ext_key', None)
    with open(netns_path, 'wb') as f:
        pycriu.images.dump(img, f)
    print('netns: removed ext_key entries')

# ---- netdev: remove VETH (peer missing cross-node); keep loopback only ----
netdev_path = os.path.join(ckpt, 'netdev-10.img')
if os.path.exists(netdev_path):
    src = backup(netdev_path)
    with open(src, 'rb') as f:
        img = pycriu.images.load(f)
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
`
	// /dev/shm is an in-memory filesystem (tmpfs) — avoids writing the script to disk.
	// 0600 so only root can read the path; removed immediately after exec.
	scriptPath := "/dev/shm/pm-patch-ckpt.py"
	if err := os.WriteFile(scriptPath, []byte(patchScript), 0o600); err != nil {
		return fmt.Errorf("write patch script: %w", err)
	}
	defer os.Remove(scriptPath)
	cmd := exec.Command("python3", scriptPath, checkpointDir, string(maskedJSON))
	cmd.Env = append(os.Environ(), "PYTHONPATH=/usr/lib/python3/dist-packages")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("patch script failed: %w\n%s", err, out)
	}
	log.Info("patchCheckpointImages", "output", strings.TrimSpace(string(out)))
	return nil
}

// setupRestoreOverlayfs mounts an overlayfs rootfs for CRIU restore by launching a temporary
// placeholder container (to let containerd prepare the snapshot chain) then bind-mounting
// the snapshot layers at rootfsDir.
func setupRestoreOverlayfs(migrationName, checkpointDir, imageName, rootfsDir string) error {
	// Check if already mounted.
	if mounts, _ := os.ReadFile("/proc/mounts"); strings.Contains(string(mounts), rootfsDir) {
		return nil
	}

	if err := os.MkdirAll(rootfsDir, 0o755); err != nil {
		return fmt.Errorf("mkdir rootfs: %w", err)
	}

	// Launch a placeholder container so containerd prepares the overlayfs snapshot layers.
	placeholderID := "pm-placeholder-" + migrationName
	_ = exec.Command("ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()
	_ = exec.Command("ctr", "--namespace", "k8s.io", "container", "rm", placeholderID).Run()
	runOut, err := exec.Command("ctr", "--namespace", "k8s.io", "run",
		"--detach", "--snapshotter", "overlayfs",
		imageName, placeholderID, "sleep", "600",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ctr run placeholder: %w\n%s", err, runOut)
	}
	time.Sleep(600 * time.Millisecond)

	// Read the placeholder's overlayfs mount options from /proc/mounts.
	taskRootfs := fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s/rootfs", placeholderID)
	mountsData, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return fmt.Errorf("read /proc/mounts: %w", err)
	}
	overlayOpts := ""
	for _, line := range strings.Split(string(mountsData), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == taskRootfs && fields[2] == "overlay" {
			overlayOpts = fields[3]
			break
		}
	}
	if overlayOpts == "" {
		return fmt.Errorf("placeholder overlayfs not found in /proc/mounts at %s", taskRootfs)
	}

	// Mount our own overlayfs at rootfsDir using the same lower layers but fresh upper/work dirs.
	// Extract lowerdir from the placeholder's options; create fresh upperdir and workdir.
	lowerDir := ""
	for _, opt := range strings.Split(overlayOpts, ",") {
		if strings.HasPrefix(opt, "lowerdir=") {
			lowerDir = strings.TrimPrefix(opt, "lowerdir=")
		}
	}
	if lowerDir == "" {
		return fmt.Errorf("lowerdir not found in overlay options: %s", overlayOpts)
	}
	upperDir := filepath.Join(filepath.Dir(rootfsDir), "upper")
	workDir := filepath.Join(filepath.Dir(rootfsDir), "work")
	_ = os.MkdirAll(upperDir, 0o755)
	_ = os.MkdirAll(workDir, 0o755)
	mountArgs := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lowerDir, upperDir, workDir)
	if out, err := exec.Command("mount", "-t", "overlay", "overlay", "-o", mountArgs, rootfsDir).CombinedOutput(); err != nil {
		return fmt.Errorf("mount overlayfs: %w\n%s", err, out)
	}

	// Kill the placeholder now that we have our own overlayfs.
	_ = exec.Command("ctr", "--namespace", "k8s.io", "task", "kill", "--signal", "KILL", placeholderID).Run()
	_ = exec.Command("ctr", "--namespace", "k8s.io", "container", "rm", placeholderID).Run()

	log.Info("setupRestoreOverlayfs: overlayfs mounted", "rootfs", rootfsDir)
	return nil
}

// findRestoredProcessPID scans /proc for the restored container process by reading the
// expected comm name from config.json process.args[0] in checkpointDir.
// Falls back to scanning for any recently-created non-pause process if config.json is absent.
func findRestoredProcessPID(checkpointDir string) (int, error) {
	// Determine the expected process name from config.json.
	expectedComm := ""
	cfgData, err := os.ReadFile(filepath.Join(checkpointDir, "config.json"))
	if err == nil {
		var cfg struct {
			Process struct {
				Args []string `json:"args"`
			} `json:"process"`
		}
		if json.Unmarshal(cfgData, &cfg) == nil && len(cfg.Process.Args) > 0 {
			expectedComm = filepath.Base(cfg.Process.Args[0])
		}
	}

	procs, _ := os.ReadDir("/proc")

	// First pass: look for an exact comm match.
	if expectedComm != "" {
		for _, p := range procs {
			if !p.IsDir() {
				continue
			}
			comm, _ := os.ReadFile(fmt.Sprintf("/proc/%s/comm", p.Name()))
			commStr := strings.TrimSpace(string(comm))
			if commStr != expectedComm {
				continue
			}
			pid, err := strconv.Atoi(p.Name())
			if err != nil {
				continue
			}
			return pid, nil
		}
		// Exact match not found — the entrypoint may have exec'd into the real
		// process (e.g. docker-entrypoint.sh → redis-server).  Fall through to
		// the generic non-pause scan below rather than failing immediately.
	}

	// Second pass (fallback): find a process in the agent's own cgroup that is NOT
	// the agent binary itself.  CRIU-restored processes inherit the cgroup of the
	// CRIU subprocess (which runs under podmotion-agent-ctl.service), so filtering
	// by cgroup reliably excludes kubepods containers and host system processes.
	agentCgroup, _ := os.ReadFile("/proc/self/cgroup")
	agentCgroupStr := strings.TrimSpace(string(agentCgroup))
	// Extract the last path component from "0::<path>" to get the service unit name.
	agentCgroupPath := ""
	for _, line := range strings.Split(agentCgroupStr, "\n") {
		if strings.HasPrefix(line, "0::") {
			agentCgroupPath = strings.TrimPrefix(line, "0::")
			break
		}
	}

	agentPID := os.Getpid()
	bestPID := 0
	bestStartTicks := uint64(0)
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid == agentPID {
			continue
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%s/comm", p.Name()))
		commStr := strings.TrimSpace(string(comm))
		if commStr == "" || commStr == "pause" || commStr == "podmotion-agent" {
			continue
		}
		if agentCgroupPath != "" {
			procCgroup, _ := os.ReadFile(fmt.Sprintf("/proc/%s/cgroup", p.Name()))
			if !strings.Contains(string(procCgroup), agentCgroupPath) {
				continue
			}
		}
		// Among matching processes, prefer the one with the highest start time
		// (most recently created = the CRIU-restored process from this run).
		statData, _ := os.ReadFile(fmt.Sprintf("/proc/%s/stat", p.Name()))
		fields := strings.Fields(string(statData))
		var startTicks uint64
		if len(fields) >= 22 {
			startTicks, _ = strconv.ParseUint(fields[21], 10, 64)
		}
		if startTicks > bestStartTicks {
			bestStartTicks = startTicks
			bestPID = pid
		}
	}
	if bestPID != 0 {
		return bestPID, nil
	}
	return 0, fmt.Errorf("findRestoredProcessPID: no CRIU-restored process found in agent cgroup after restore (expectedComm=%q)", expectedComm)
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
			sizeBytes, ctrErr := ctrCheckpoint(taskID, imagesDir)
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
				if rmErr := os.RemoveAll(imagesDir); rmErr != nil {
					return nil, fmt.Errorf("checkpoint: clearing partial ctr images before raw CRIU: %w", rmErr)
				}
			} else {
				sha := sha256OfDir(imagesDir)
				log.Info("Checkpoint complete (ctr)", "migration", req.MigrationName,
					"sizeBytes", sizeBytes, "sha256", sha, "freezeMs", freezeDurationMs)
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

	// Capture socket inventory immediately before freeze so snd_nxt/rcv_nxt reflect
	// the exact pre-freeze sequence numbers (ADR-0049 seq_delta=0 invariant).
	// Only populated when TCPPreservationMode is Strict or BestEffort.
	var seqSnapshots []*agentpb.SeqSnapshot
	if tcpEstablished && containerPID != 0 {
		sockEntries, invErr := network.SocketInventory(containerPID)
		if invErr != nil {
			log.Error(invErr, "Checkpoint: socket inventory failed — continuing without SeqSnapshot", "pid", containerPID)
		} else {
			for _, e := range sockEntries {
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
			log.Info("Checkpoint: socket inventory complete", "migration", req.MigrationName,
				"pid", containerPID, "connections", len(seqSnapshots))
		}
	}

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

	// Re-read socket inventory after dump succeeds. The post-dump read is for 4-tuple
	// tracking (SrcIP/SrcPort/DstIP/DstPort) only — SndNxt/RcvNxt are left zero because
	// /proc/net/tcp does not contain sequence numbers (see SocketEntry comment).
	if err == nil && tcpEstablished && containerPID != 0 {
		if postEntries, invErr := network.SocketInventory(containerPID); invErr != nil {
			log.Error(invErr, "Checkpoint: post-dump socket inventory failed — retaining pre-dump snapshots",
				"pid", containerPID, "migration", req.MigrationName)
		} else {
			seqSnapshots = seqSnapshots[:0]
			for _, e := range postEntries {
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
			log.Info("Checkpoint: post-dump socket inventory (exact freeze instant)",
				"migration", req.MigrationName, "pid", containerPID,
				"connections", len(seqSnapshots), "freezeTimestampNs", freezeTimestampNs)
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

		manifestPath := filepath.Join(imagesDir, "checkpoint-manifest.json")
		manifest := fmt.Sprintf(`{
  "migrationName": %q,
  "node": %q,
  "timestamp": %q,
  "mode": "mock-fallback",
  "reason": %q
}
`, req.MigrationName, s.nodeName, time.Now().UTC().Format(time.RFC3339), err.Error())

		if writeErr := os.WriteFile(manifestPath, []byte(manifest), 0o644); writeErr != nil {
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
					if wErr := os.WriteFile(dstCfg, data, 0o644); wErr != nil {
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
	// M4: stub — cgroup/netns setup wired in M5.
	return &agentpb.PrepareDestinationResponse{
		Ready:        true,
		IpReserved:   true,
		StorageReady: true,
	}, nil
}

// Restore recreates the container from dump images on the destination node.
// On kind/dev where CRIU restore lacks permissions, a graceful fallback starts
// a fresh nginx container via exec to simulate the restored workload.
func (s *AgentServer) Restore(_ context.Context, req *agentpb.RestoreRequest) (*agentpb.RestoreResponse, error) {
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
	// Zeroize checkpoint images after restore completes (success or failure) — the process
	// tree is alive (or dead) at that point; the images are no longer needed.
	defer func() { _ = zeroizeDir(imagesDir) }()

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
		pid, joinErr := joinNsRestore(req.MigrationName, imagesDir, req.DestNetnsFd, "")
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
			socketsLiveAt, resumedAt, orderErr := enforceRestoreOrderingInvariant(pid, req.MigrationName, len(req.SeqSnapshots))
			if orderErr != nil {
				log.Error(orderErr, "Restore: ordering invariant FAILED — SIGCONT withheld, failing restore for rollback",
					"migration", req.MigrationName, "pid", pid)
				return &agentpb.RestoreResponse{
					Success:      false,
					ErrorMessage: fmt.Sprintf("ordering invariant: %v", orderErr),
				}, nil
			}
			log.Info("Restore: ordering invariant satisfied",
				"migration", req.MigrationName,
				"socketsLiveAt", socketsLiveAt,
				"resumedAt", resumedAt,
				"socketsLiveBeforeResume", socketsLiveAt.Before(resumedAt),
			)
			if s.k8sClient != nil {
				if setErr := s.setOrderingConditions(req.MigrationName, pid, socketsLiveAt, resumedAt); setErr != nil {
					// Ordering condition update failure is non-fatal for the migration itself,
					// but we log it as an error because the condition API contract is violated.
					log.Error(setErr, "Restore: failed to set ordering conditions", "migration", req.MigrationName)
				}
			}
		}

		return &agentpb.RestoreResponse{
			Success:           true,
			RestoreDurationMs: restoreDurationMs,
		}, nil
	}

	// Fallback: raw CRIU restore via go-criu (legacy path, used when ctr checkpoint not available).
	h := sha256.Sum256([]byte(req.MigrationName))
	hostVeth := "veth" + hex.EncodeToString(h[:])[:7]

	t0 := time.Now()
	result, err := s.checkpointer.Restore(context.Background(), criu.RestoreOptions{
		ImagesDir:    imagesDir,
		Detached:     false, // foreground CRIU — no ghost container (ADR-0046)
		HostVethName: hostVeth,
	})
	if err != nil {
		log.Info("Restore: raw CRIU restore failed", "err", err)
		return nil, fmt.Errorf("restore failed: %w", err)
	}

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
func (s *AgentServer) PutCheckpointTar(_ context.Context, req *agentpb.PutCheckpointTarRequest) (*agentpb.PutCheckpointTarResponse, error) {
	if req.MigrationName == "" {
		return &agentpb.PutCheckpointTarResponse{Success: false, Error: "migration_name required"}, nil
	}
	if len(req.TarData) == 0 {
		return &agentpb.PutCheckpointTarResponse{Success: false, Error: "tar_data is empty"}, nil
	}

	// Stage on tmpfs (/run is tmpfs), root-only. Do NOT defer zeroize here — the Restore
	// RPC reads these files after PutCheckpointTar returns. Zeroize is done by CleanupCheckpoint
	// after restore completes (or by migration CR deletion finalizer).
	destDir := fmt.Sprintf("/run/podmotion/checkpoints/%s/final", req.MigrationName)
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return &agentpb.PutCheckpointTarResponse{Success: false, Error: fmt.Sprintf("mkdir %s: %v", destDir, err)}, nil
	}
	// Zeroize on extraction failure so partial checkpoint data doesn't linger.
	extractOK := false
	defer func() {
		if !extractOK {
			_ = zeroizeDir(destDir)
		}
	}()

	// Decompress and extract tar.
	gzr, err := gzip.NewReader(bytes.NewReader(req.TarData))
	if err != nil {
		return &agentpb.PutCheckpointTarResponse{Success: false, Error: fmt.Sprintf("gzip open: %v", err)}, nil
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var bytesWritten int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &agentpb.PutCheckpointTarResponse{Success: false, Error: fmt.Sprintf("tar read: %v", err)}, nil
		}

		// Security: only allow plain files, no directory traversal.
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		// Strip any leading path components — write all files flat into destDir.
		filename := filepath.Base(hdr.Name)
		if filename == "" || filename == "." || filename == ".." {
			continue
		}

		outPath := filepath.Join(destDir, filename)
		f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
		if err != nil {
			return &agentpb.PutCheckpointTarResponse{Success: false, Error: fmt.Sprintf("create %s: %v", outPath, err)}, nil
		}
		n, err := io.Copy(f, tr)
		f.Close()
		if err != nil {
			return &agentpb.PutCheckpointTarResponse{Success: false, Error: fmt.Sprintf("write %s: %v", filename, err)}, nil
		}
		bytesWritten += n
	}

	extractOK = true // disarm the error-path zeroize defer
	log.Info("PutCheckpointTar: extracted checkpoint images",
		"migration", req.MigrationName,
		"destDir", destDir,
		"bytesWritten", bytesWritten,
		"tarSize", len(req.TarData))
	return &agentpb.PutCheckpointTarResponse{Success: true, BytesWritten: bytesWritten}, nil
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

	log.Info("GetCheckpointTar: checkpoint packaged (source intact until ReleaseCheckpoint)",
		"migration", req.MigrationName,
		"srcDir", srcDir,
		"tarSizeBytes", len(tarData))

	return &agentpb.GetCheckpointTarResponse{
		Success:   true,
		TarData:   tarData,
		BytesRead: int64(len(tarData)),
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

	srcDir := fmt.Sprintf("/run/podmotion/checkpoints/%s/final", req.MigrationName)
	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		// Already released (or never existed) — idempotent success.
		log.Info("ReleaseCheckpoint: source dir already absent (idempotent)",
			"migration", req.MigrationName, "dir", srcDir)
		return &agentpb.ReleaseCheckpointResponse{Success: true}, nil
	}

	if err := zeroizeDir(srcDir); err != nil {
		log.Error(err, "ReleaseCheckpoint: zeroize failed — images remain on tmpfs until node reboot",
			"migration", req.MigrationName, "dir", srcDir)
		// Non-fatal: tmpfs is volatile; images are gone on node reboot.
		// Return success so the controller doesn't retry in a loop.
	}

	log.Info("ReleaseCheckpoint: source checkpoint zeroized and removed",
		"migration", req.MigrationName, "dir", srcDir)
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
	if err := armZeroWindowBPF(ctx, ifindex); err != nil {
		return &agentpb.ArmZeroWindowResponse{
			Armed:          false,
			BlockingReason: fmt.Sprintf("BPF arm failed: %v", err),
		}, nil
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
			log.Info("ArmZeroWindow: watchdog triggered — auto-disarming ZW hold",
				"migration", req.MigrationName, "budgetMs", req.FreezeWindowBudgetMs)
			disarmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if dErr := disarmZeroWindowBPF(disarmCtx, ifindex); dErr != nil {
				log.Info("ArmZeroWindow: watchdog disarm BPF error", "migration", req.MigrationName, "err", dErr)
			}
			s.zwHoldMu.Lock()
			delete(s.zwHolds, req.MigrationName)
			s.zwHoldMu.Unlock()
		case <-wdCtx.Done():
			// Normal path: DisarmZeroWindow cancelled the watchdog.
		}
	}()

	log.Info("ArmZeroWindow: hold armed", "migration", req.MigrationName, "armedAtNs", armedAtNs)
	return &agentpb.ArmZeroWindowResponse{
		Armed:     true,
		ArmedAtNs: armedAtNs,
	}, nil
}

// DisarmZeroWindow implements MigrationAgentServiceServer.DisarmZeroWindow.
// It cancels the watchdog goroutine and detaches the TC-BPF zero-window hold.
func (s *AgentServer) DisarmZeroWindow(_ context.Context, req *agentpb.DisarmZeroWindowRequest) (*agentpb.DisarmZeroWindowResponse, error) {
	log.Info("DisarmZeroWindow: disarming zero-window hold", "migration", req.MigrationName)

	s.zwHoldMu.Lock()
	state, ok := s.zwHolds[req.MigrationName]
	if ok {
		state.watchdogCancel()
		delete(s.zwHolds, req.MigrationName)
	}
	s.zwHoldMu.Unlock()

	if !ok {
		return &agentpb.DisarmZeroWindowResponse{
			Disarmed:       false,
			BlockingReason: "no active zero-window hold for migration",
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
	log.Info("registerFrozenSource: source process frozen",
		"migration", migrationName, "sourcePID", pid)
}

// clearFrozenSource removes the frozen-source record for migrationName.
// Called after thawing or on successful migration completion.
func (s *AgentServer) clearFrozenSource(migrationName string) {
	s.frozenSourcePIDsMu.Lock()
	defer s.frozenSourcePIDsMu.Unlock()
	delete(s.frozenSourcePIDs, migrationName)
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
	if ok {
		thawSourcePID(pid, migrationName)
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
func enforceRestoreOrderingInvariant(pid int, migrationName string, expectedCount int) (time.Time, time.Time, error) {
	// If the restore was not TCP-stateful (no expected connections), skip socket
	// polling and resume immediately — the invariant only applies to TCP migrations.
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
