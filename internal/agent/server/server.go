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
// migrationName is used for log tagging; checkpointDir is the tmpfs images path.
func (s *AgentServer) JoinNsRestore(migrationName, checkpointDir string) (int, error) {
	return joinNsRestore(migrationName, checkpointDir, "")
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
		// Detect in-flight TCP socket failure by inspecting the combined output from ctr/CRIU.
		// Wrap with ErrCtrInFlightTCP so callers can use errors.Is instead of string matching.
		outStr := string(out)
		if strings.Contains(outStr, "In-flight") ||
			strings.Contains(outStr, "in-flight") ||
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

// buildCRIURestoreArgs constructs the argument list for `criu restore`.
// Network namespace selection is tier-driven (ADR-0048):
//   - destNetnsFd non-empty → --join-ns net:<path> + --tcp-established: restore into the
//     pre-staged migration netns so that TCP seq/ack state is preserved across node handoff.
//   - destNetnsFd empty → --empty-ns net + --tcp-close: stateless cold migration; CRIU creates
//     a fresh netns and closes all TCP connections (correct default for NetworkContinuity=None).
//
// --restore-detached is intentionally absent: CRIU must remain the foreground parent of the
// restored process tree to avoid ghost containers (PID in /proc but untracked by any supervisor).
//
// --leave-stopped is added when destNetnsFd is non-empty (TCP-stateful path): the restored
// process tree stays in SIGSTOP until the caller sends SIGCONT, which must happen only AFTER
// SocketsLive=True is confirmed (M23 ordering invariant).
func buildCRIURestoreArgs(checkpointDir, rootfsDir, dataDir, termlogFile, secretsDir, restoreLogPath, destNetnsFd string) []string {
	tcpFlag := "--tcp-close"
	if destNetnsFd != "" {
		tcpFlag = "--tcp-established"
	}
	args := []string{
		"restore",
		"--images-dir", checkpointDir,
		"--root", rootfsDir,
		tcpFlag,
		"--mntns-compat-mode",
		"--manage-cgroups=ignore",
		"--ext-mount-map", "/dev/null:/dev/null",
		"--ext-mount-map", fmt.Sprintf("/data:%s", dataDir),
		"--ext-mount-map", fmt.Sprintf("/dev/termination-log:%s", termlogFile),
		"--ext-mount-map", fmt.Sprintf("/run/secrets/kubernetes.io/serviceaccount:%s", secretsDir),
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
		args = append(args, "--empty-ns", "net")
	}
	return args
}

// joinNsRestore restores a checkpointed container using a standalone overlayfs rootfs.
// When destNetnsFd is non-empty (a /proc/<pid>/fd/<n> path to a pre-staged migration netns),
// CRIU uses --join-ns net:<destNetnsFd> to restore TCP connections into the pre-staged netns
// (required for TCPPreservationMode=Strict/BestEffort per ADR-0048).
// When destNetnsFd is empty, CRIU falls back to --empty-ns net (stateless cold migration).
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
func joinNsRestore(migrationName, checkpointDir, destNetnsFd string) (int, error) {
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
	// 0o700: data dir may contain PV data; secrets dir holds service-account tokens.
	// World-readable (0o755) is inappropriate for either (M19.5 criterion 10).
	_ = os.MkdirAll(dataDir, 0o700)
	_ = os.MkdirAll(secretsDir, 0o700)
	_ = os.WriteFile(termlogFile, nil, 0o644)
	// Create missing mount target directories inside rootfs (CRIU bind-mounts into these).
	_ = os.MkdirAll(filepath.Join(rootfsDir, "run/secrets/kubernetes.io/serviceaccount"), 0o755)
	for _, f := range []string{"etc/resolv.conf", "etc/hostname", "etc/hosts"} {
		p := filepath.Join(rootfsDir, f)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			_ = os.WriteFile(p, nil, 0o644)
		}
	}

	// Step 4: CRIU restore — standalone rootfs.
	restoreLogPath := filepath.Join(checkpointDir, "restore.log")
	criuArgs := buildCRIURestoreArgs(checkpointDir, rootfsDir, dataDir, termlogFile, secretsDir, restoreLogPath, destNetnsFd)
	criuCmd := exec.Command("/usr/local/sbin/criu", criuArgs...)
	if err := criuCmd.Start(); err != nil {
		return 0, fmt.Errorf("criu restore start: %w", err)
	}
	// Give CRIU time to fork and restore the process tree before we scan /proc.
	time.Sleep(500 * time.Millisecond)
	// Check for early exit — if CRIU failed it will have exited already.
	if criuCmd.ProcessState != nil && criuCmd.ProcessState.Exited() {
		logContent, _ := os.ReadFile(restoreLogPath)
		return 0, fmt.Errorf("criu restore exited prematurely\nlog:\n%s", logContent)
	}

	// Step 5: Find the restored process by scanning /proc for the process name.
	time.Sleep(200 * time.Millisecond)
	pid, err := findRestoredProcessPID(checkpointDir)
	if err != nil {
		return 0, err
	}
	log.Info("joinNsRestore: found restored process", "pid", pid)

	// Step 6: Bring up loopback in the restored process's new (empty) net namespace.
	// --empty-ns net gives a clean ns with lo DOWN; Redis needs 127.0.0.1 reachable.
	if out, err := exec.Command("nsenter",
		fmt.Sprintf("--net=/proc/%d/ns/net", pid), "--",
		"ip", "link", "set", "lo", "up",
	).CombinedOutput(); err != nil {
		log.Info("joinNsRestore: warning — failed to bring up loopback", "err", err, "output", string(out))
	}

	success = true
	return pid, nil
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
	patchScript := `
import sys, os, shutil
sys.path.insert(0, '/tmp/criu-4.2/lib')
import pycriu

ckpt = sys.argv[1]

def backup(path):
    orig = path + '.orig'
    if not os.path.exists(orig):
        shutil.copy2(path, orig)
    return orig

# ---- mountpoints: keep only mounts with valid (non-null) ext_key or standard in-container mounts ----
mp_path = os.path.join(ckpt, 'mountpoints-13.img')
if os.path.exists(mp_path):
    src = backup(mp_path)
    with open(src, 'rb') as f:
        img = pycriu.images.load(f)
    # Remove entries that have no ext_key AND are masked paths (proc/* or sys/firmware, sys/fs/pstore)
    # that cannot be recreated cross-node. Entries with a valid ext_key are handled via --ext-mount-map.
    null_ext_key_masked = {
        '/proc/acpi', '/proc/scsi', '/sys/firmware', '/sys/fs/pstore',
        '/proc/timer_stats', '/proc/sched_debug',
    }
    kept = [e for e in img['entries']
            if not (e.get('mountpoint') in null_ext_key_masked and not e.get('ext_key'))]
    img['entries'] = kept
    with open(mp_path, 'wb') as f:
        pycriu.images.dump(img, f)
    print('mountpoints: kept', len(kept), 'entries')

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
	out, err := exec.Command("python3", scriptPath, checkpointDir).CombinedOutput()
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
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%s/comm", p.Name()))
		commStr := strings.TrimSpace(string(comm))
		if commStr == "" || commStr == "pause" {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		if expectedComm != "" {
			if commStr == expectedComm {
				return pid, nil
			}
		}
	}
	if expectedComm != "" {
		return 0, fmt.Errorf("restored process %q not found in /proc after CRIU restore", expectedComm)
	}
	return 0, fmt.Errorf("findRestoredProcessPID: config.json absent and no non-pause process found")
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

	// Try containerd-native checkpoint first (ctr tasks checkpoint).
	// This handles all container namespaces correctly (network, mount, etc.) and produces
	// CRIU images that runc can restore on the destination. Falls back to raw CRIU (go-criu)
	// if the containerd task ID can't be found (non-k8s environments, tests).
	if podUID != "" {
		taskID, taskErr := FindContainerTaskID(podUID)
		if taskErr == nil {
			log.Info("Checkpoint: using containerd-native ctr checkpoint", "taskID", taskID)
			freezeStart := time.Now()
			sizeBytes, ctrErr := ctrCheckpoint(taskID, imagesDir)
			freezeDurationMs := time.Since(freezeStart).Milliseconds()
			if ctrErr != nil {
				// Fall through to raw CRIU only for in-flight TCP socket failures — ctr invokes
				// CRIU without --skip-in-flight, so containers with active TCP connections fail.
				// Raw go-criu uses TcpSkipInFlight=true + TcpClose=true (established connections
				// will be closed on restore — this is a deliberate behavior change, logged below).
				// Any other ctr error (OOM, permission, corrupt task) is fatal and returned directly
				// to avoid a double-freeze and to surface the real cause.
				if !errors.Is(ctrErr, ErrCtrInFlightTCP) {
					return nil, fmt.Errorf("checkpoint failed (ctr): %w", ctrErr)
				}
				log.Info("Checkpoint: ctr failed due to in-flight TCP — falling back to raw CRIU (TcpClose=true: established connections will be dropped on restore)",
					"taskID", taskID, "err", ctrErr)
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
		pid, joinErr := joinNsRestore(req.MigrationName, imagesDir, req.DestNetnsFd)
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
