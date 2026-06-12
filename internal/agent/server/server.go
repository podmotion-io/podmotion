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

// AgentServer implements agentpb.MigrationAgentServiceServer.
// One instance runs per node agent process.
type AgentServer struct {
	agentpb.UnimplementedMigrationAgentServiceServer
	checkpointer criu.Checkpointer
	nodeName     string
	k8sClient    client.Client // may be nil in pure-stub mode

	// migrationPodUID stores pod UID keyed by migration name, populated by PrepareSource.
	// Used by Checkpoint to resolve the container root PID via /proc cgroup scan.
	migrationPodUIDMu sync.RWMutex
	migrationPodUID   map[string]string
}

// New constructs an AgentServer with the given Checkpointer implementation.
// k8sClient may be nil; when set the Checkpoint handler will update MigrationCheckpoint CRs.
func New(nodeName string, cp criu.Checkpointer, k8sClient client.Client) *AgentServer {
	return &AgentServer{
		checkpointer:    cp,
		nodeName:        nodeName,
		k8sClient:       k8sClient,
		migrationPodUID: make(map[string]string),
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
	// Network namespace selection:
	//   destNetnsFd non-empty → --join-ns net:<path>: restore into the pre-staged migration
	//     netns so TCP connections survive across the overlay handoff (ADR-0048).
	//   empty → --empty-ns net: create a fresh netns (stateless cold migration).
	restoreLogPath := filepath.Join(checkpointDir, "restore.log")
	// TCP flag is tier-driven: when restoring into a pre-staged migration netns (join-ns path,
	// TCPPreservationMode=Strict/BestEffort) we MUST pass --tcp-established so CRIU restores
	// the socket state table and TCP seq numbers. --tcp-close (the default) sends RST on every
	// established connection, directly defeating the join-ns TCP-preservation purpose (ADR-0048).
	// For the stateless cold path (destNetnsFd=="") --tcp-close is the correct/safe default.
	tcpFlag := "--tcp-close"
	if destNetnsFd != "" {
		tcpFlag = "--tcp-established"
	}
	criuArgs := []string{
		"restore",
		"--images-dir", checkpointDir,
		"--root", rootfsDir,
		tcpFlag,
		"--mntns-compat-mode",
		"--manage-cgroups=ignore",
		// /dev/null is the ext_key for all Kubernetes masked-path tmpfs bind-mounts.
		"--ext-mount-map", "/dev/null:/dev/null",
		// Kubernetes emptyDir / persistent volume mounted at /data.
		"--ext-mount-map", fmt.Sprintf("/data:%s", dataDir),
		// Container-terminated log file.
		"--ext-mount-map", fmt.Sprintf("/dev/termination-log:%s", termlogFile),
		// Service account token (not needed by Redis but present in the dump).
		"--ext-mount-map", fmt.Sprintf("/run/secrets/kubernetes.io/serviceaccount:%s", secretsDir),
		// Standard CRI bind-mounts that reference sandbox-specific host paths.
		"--ext-mount-map", "/dev/shm:/dev/shm",
		"--ext-mount-map", "/etc/resolv.conf:/etc/resolv.conf",
		"--ext-mount-map", "/etc/hostname:/etc/hostname",
		"--ext-mount-map", "/etc/hosts:/etc/hosts",
		// No --restore-detached: CRIU runs foreground as the restored process's init/parent.
		// --restore-detached would cause CRIU to exit-0 and orphan the process (ghost
		// container — PID visible in /proc but not tracked by any supervisor).
		"-v4",
		"-o", restoreLogPath,
	}
	if destNetnsFd != "" {
		criuArgs = append(criuArgs, "--join-ns", "net:"+destNetnsFd)
	} else {
		criuArgs = append(criuArgs, "--empty-ns", "net")
	}
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

	// Resolve the container root PID from the pod UID stored during PrepareSource.
	s.migrationPodUIDMu.RLock()
	podUID := s.migrationPodUID[req.MigrationName]
	s.migrationPodUIDMu.RUnlock()

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
				return &agentpb.CheckpointResponse{
					FreezeDurationMs:    freezeDurationMs,
					CheckpointSha256:    sha,
					CheckpointSizeBytes: sizeBytes,
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

	// Resolve TCPPreservationMode from the PodMigration CR so TcpEstablished is tier-driven.
	// The CR lives in the WORKLOAD namespace (not the operator namespace). The caller MUST
	// populate req.WorkloadNamespace; if it is empty and the k8s client is available we
	// fail the checkpoint rather than silently degrading to stateless (ADR-0047 §safety).
	tcpEstablished := false
	if s.k8sClient != nil {
		// WorkloadNamespace is the namespace of the migrating pod's PodMigration CR.
		// It is set by the controller in CheckpointRequest.WorkloadNamespace.
		// Falling back to POD_NAMESPACE (operator namespace) is WRONG for cross-namespace pods
		// and is the source of the silent-stateless-downgrade bug fixed here.
		workloadNs := req.WorkloadNamespace
		if workloadNs == "" {
			// WorkloadNamespace not provided: fail closed — we cannot determine the mode.
			// Return an error rather than silently dumping stateless for an unknown mode.
			return nil, fmt.Errorf("checkpoint: WorkloadNamespace is empty in CheckpointRequest; cannot resolve TCPPreservationMode — refusing to dump to avoid silent stateless downgrade")
		}
		pm := &pmv1.PodMigration{}
		lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer lookupCancel()
		if lookupErr := s.k8sClient.Get(lookupCtx, types.NamespacedName{
			Name:      req.MigrationName,
			Namespace: workloadNs,
		}, pm); lookupErr != nil {
			// Lookup failed: for a migration in Strict/BestEffort mode we must not silently
			// downgrade to stateless — fail the checkpoint so the controller can retry or rollback.
			return nil, fmt.Errorf("checkpoint: failed to look up PodMigration CR %s/%s: %w — cannot determine TCPPreservationMode; refusing to dump to avoid silent stateless downgrade",
				workloadNs, req.MigrationName, lookupErr)
		} else {
			mode := pm.Spec.TCPPreservationMode
			tcpEstablished = mode == pmv1.TCPPreservationModeStrict || mode == pmv1.TCPPreservationModeBestEffort
		}
	}

	freezeStart := time.Now()
	result, err := s.checkpointer.Dump(context.Background(), criu.DumpOptions{
		ImagesDir:      imagesDir,
		Pid:            containerPID,
		TcpEstablished: tcpEstablished,
	})

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

func (s *AgentServer) Abort(_ context.Context, req *agentpb.AbortRequest) (*agentpb.AbortResponse, error) {
	log.Info("Abort called", "migration", req.MigrationName, "reason", req.Reason)
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
