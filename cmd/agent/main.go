/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package main is the PodMotion node agent binary.
// Runs as a DaemonSet on every node. Responsibilities:
//   - On startup: run compatibility probe, create/update NodeMigrationCapacity CR
//   - Periodic heartbeat: update NMC status.lastHeartbeat and status.ready
//   - gRPC server: MigrationAgentService on :9090 (mTLS via cert-manager in production)
//   - NRI plugin: hook into containerd Stopping events for pre-dump trigger (M5)
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
	"github.com/podmotion-io/podmotion/internal/agent/nmcregistrar"
	"github.com/podmotion-io/podmotion/internal/agent/nri"
	"github.com/podmotion-io/podmotion/internal/agent/seccomp"
	"github.com/podmotion-io/podmotion/internal/agent/server"
	agenttls "github.com/podmotion-io/podmotion/internal/agent/tls"
	"github.com/podmotion-io/podmotion/internal/buildinfo"
)

const tmpfsMagic = 0x01021994

// defaultRouteIface returns the name of the network interface associated with
// the default (0.0.0.0/0) route, parsed from /proc/net/route.  This is the
// interface to which the XDP bridge program should be attached (ADR-0155 D1).
func defaultRouteIface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		// Destination 00000000 = 0.0.0.0 (default route).
		if fields[1] == "00000000" {
			return fields[0], nil
		}
	}
	// Fallback: first non-loopback interface.
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0", nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name, nil
		}
	}
	return "eth0", nil
}

func mustEnsureCheckpointTmpfs(log logr.Logger, path string) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		log.Error(err, "failed to create checkpoint root", "path", path)
		os.Exit(1)
	}
	// The agent runs in its own mount namespace (container overlayfs), so statfs on
	// the in-container path returns the overlayfs fstype. We verify via the host
	// mount namespace by reading through /proc/1/root (hostPID=true + privileged).
	hostPath := "/proc/1/root" + path
	var st syscall.Statfs_t
	if err := syscall.Statfs(hostPath, &st); err != nil {
		log.Error(err, "failed to statfs checkpoint root via host ns", "hostPath", hostPath)
		os.Exit(1)
	}
	if st.Type != tmpfsMagic {
		log.Error(fmt.Errorf("got fstype 0x%x, want 0x%x (tmpfs)", st.Type, tmpfsMagic),
			"ADR-0146 §5 violation: checkpoint dir is not tmpfs — aborting", "path", path)
		os.Exit(1)
	}
	log.Info("checkpoint tmpfs verified", "path", path, "mode", "0700")
}

var scheme = k8sruntime.NewScheme()

func init() {
	utilruntime.Must(pmv1.AddToScheme(scheme))
	// ADR-0195: register corev1 so the agent k8sClient can Create/Get
	// corev1.Event objects (emitCRIUImageInconsistencyEvent, emitExternalMountDroppedEvent,
	// emitExternalMountUnresolvedEvent at server.go:5735/5786/5836).
	// Without this registration, client.Create(&corev1.Event{}) fails with
	// "no kind is registered for the type v1.Event in scheme".
	utilruntime.Must(corev1.AddToScheme(scheme))
}

// brokerHostNSProcess adapts the netns-broker async exec ops (ExecPoll/ExecSignal —
// ADR-0234) to criu.HostNSProcess, so CRIUCheckpointer can poll a detached host-mount-ns
// CRIU child to completion and SIGKILL it on abort. pid is the broker-returned host PID
// of the criu-wrapper child.
type brokerHostNSProcess struct {
	pid int
}

// Poll reports whether the wrapper/criu child has exited, surfacing its exit code and
// captured stderr (the broker's async capture) on exit.
func (p *brokerHostNSProcess) Poll(ctx context.Context) (exited bool, exitCode int, output []byte, err error) {
	pr, perr := netnsbroker.NewClient().ExecPoll(ctx, p.pid)
	if perr != nil {
		return false, 0, nil, perr
	}
	if pr.Running {
		return false, 0, nil, nil
	}
	return true, pr.ExitCode, pr.Stderr, nil
}

// Signal delivers sig to the child via the broker (SIGKILL on abort).
func (p *brokerHostNSProcess) Signal(ctx context.Context, sig int) error {
	return netnsbroker.NewClient().ExecSignal(ctx, p.pid, sig)
}

// inetnsProbe exit codes — MUST match server.inetnsProbeExit* (ADR-0200 D1 (i)).
const (
	inetnsProbeExitSuccess  = 0
	inetnsProbeExitRefused  = 64
	inetnsProbeExitTimeout  = 65
	inetnsProbeExitOtherErr = 66
)

// runInetnsProbe is the ADR-0200 __inetns_probe helper subcommand. It is invoked by
// AgentServer.probeOldIPInPodNetns via `nsenter --net=/proc/<replPID>/ns/net <self>
// __inetns_probe <oldIP> <port>` so the TCP dial executes INSIDE the replacement pod
// netns (where the OLD IP is owned per ADR-0138 M7) instead of the agent's host netns.
// It performs the exact same net.DialTimeout the host-netns probe used (ADR-0192 R2) and
// classifies the result with the same ECONNREFUSED=success semantics (ADR-0200 D3),
// reporting the classification through the process exit code. Port :7 unchanged.
func runInetnsProbe(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "ADR-0200 __inetns_probe: usage: __inetns_probe <ip> <port>")
		os.Exit(inetnsProbeExitOtherErr)
	}
	probeAddr := net.JoinHostPort(args[0], args[1])
	conn, perr := net.DialTimeout("tcp", probeAddr, 2*time.Second)
	if conn != nil {
		conn.Close()
	}
	if perr == nil {
		os.Exit(inetnsProbeExitSuccess) // SYN-ACK — listener answered, IP live
	}
	// ECONNREFUSED = RST = the kernel in this (pod) netns answered: IP is live (success).
	var opErr *net.OpError
	if errors.As(perr, &opErr) && errors.Is(opErr.Err, syscall.ECONNREFUSED) {
		fmt.Fprint(os.Stderr, perr.Error())
		os.Exit(inetnsProbeExitRefused)
	}
	fmt.Fprint(os.Stderr, perr.Error())
	if ne, ok := perr.(net.Error); ok && ne.Timeout() {
		os.Exit(inetnsProbeExitTimeout) // i/o timeout — no owner on the path, failure
	}
	os.Exit(inetnsProbeExitOtherErr)
}

// runInetnsEcho is the ADR-0210 __inetns_echo helper subcommand. It is invoked by
// AgentServer.StartReachabilityEcho on the DESTINATION node via
// `nsenter --net=/proc/<replPID>/ns/net <self> __inetns_echo <listenIP> <port> <nonce> <ttlSeconds>`
// so the listener binds the preserved pod IP INSIDE the replacement pod netns (where the
// IP is owned). It accepts ONE connection, writes the nonce, closes, and exits. The
// cross-node SOURCE-agent probe (ProbeDataplaneReachability) connects to this listener and
// must read back the nonce — proving the SYN traversed the real overlay datapath, not a
// netns-local lo/32 alias. This is the destination half of the ADR-0210 nonce round-trip.
func runInetnsEcho(args []string) {
	if len(args) < 4 {
		fmt.Fprintln(os.Stderr, "ADR-0210 __inetns_echo: usage: __inetns_echo <ip> <port> <nonce> <ttlSeconds>")
		os.Exit(2)
	}
	listenAddr := net.JoinHostPort(args[0], args[1])
	nonce := args[2]
	ttlSecs, _ := strconv.Atoi(args[3])
	if ttlSecs <= 0 {
		ttlSecs = 15
	}
	ln, lerr := net.Listen("tcp", listenAddr)
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "ADR-0210 __inetns_echo: listen %s failed: %v", listenAddr, lerr)
		os.Exit(1)
	}
	defer ln.Close()
	deadline := time.Now().Add(time.Duration(ttlSecs) * time.Second)
	if tl, ok := ln.(*net.TCPListener); ok {
		_ = tl.SetDeadline(deadline)
	}
	// Serve connections until the TTL elapses (probe may retry); echo nonce on each.
	for time.Now().Before(deadline) {
		conn, aerr := ln.Accept()
		if aerr != nil {
			break // deadline reached
		}
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte(nonce))
		_ = conn.Close()
	}
	os.Exit(0)
}

func main() {
	// ADR-0200: in-netns probe helper subcommand dispatch. MUST run before any logging,
	// k8s client, or NRI setup — this process is a short-lived re-exec inside a pod netns
	// (entered via nsenter by the parent agent), does the dial, and exits with a coded status.
	if len(os.Args) > 1 && os.Args[1] == "__inetns_probe" {
		runInetnsProbe(os.Args[2:])
		return
	}
	// ADR-0210: in-netns nonce-echo helper subcommand dispatch (destination half of the
	// cross-node reachability round-trip). Same early-dispatch discipline as __inetns_probe.
	if len(os.Args) > 1 && os.Args[1] == "__inetns_echo" {
		runInetnsEcho(os.Args[2:])
		return
	}

	// SD-1-NETNS-BROKER (ADR-0148 Amendment): netns-broker subcommand dispatch.
	// When the agent image is invoked as `/agent netns-broker` (the privileged
	// sidecar container's args), serve the netns-broker socket and nothing else —
	// no gRPC, no NMC, no NRI, no k8s client. Same binary/image as the main agent
	// (no version skew), distinct narrow-surface entrypoint. MUST dispatch before
	// any agent setup runs.
	if len(os.Args) > 1 && os.Args[1] == "netns-broker" {
		blog := zap.New().WithName("netns-broker")
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		if err := netnsbroker.Run(ctx, blog); err != nil {
			blog.Error(err, "netns-broker exited with error")
			os.Exit(1)
		}
		return
	}

	log := zap.New().WithName("podmotion-agent")
	// Wire the controller-runtime global logger so packages that use ctrl.Log / logf.Log
	// (e.g. internal/agent/server, internal/agent/nri) produce structured output instead
	// of panicking with "log.SetLogger(...) was never called".
	ctrl.SetLogger(log)

	// ADR-0148 / ADR-0039: lift the RLIMIT_MEMLOCK ceiling before any BPF object is
	// loaded. BPF map creation charges locked memory against RLIMIT_MEMLOCK on kernels
	// < 5.11 (which lack memcg-based BPF memory accounting); the process inherits the
	// low default (often 64KB) and map create() fails EPERM ("operation not permitted /
	// MEMLOCK may be too low"). This is independent of CAP_BPF — the capability lets the
	// bpf() syscall run, but the rlimit still caps the locked pages. RemoveMemlock raises
	// it to RLIM_INFINITY (and is a harmless no-op on >= 5.11). MUST run before
	// server.New → EnsureXDPBridgeLoaded (PM_BRIDGE_MAP) and any ArmZeroWindowHold
	// (PM_ACTIVE_HOLDS) load. The netns-broker subcommand dispatched above does not load
	// XDP/zero_window BPF, so this placement covers every in-process BPF load site.
	if err := rlimit.RemoveMemlock(); err != nil {
		// Non-fatal: on kernels >= 5.11 BPF uses memcg accounting and the rlimit is
		// irrelevant; on older kernels a failure here will surface as the original
		// EPERM at map-create with an actionable error. Log and continue.
		log.Error(err, "rlimit.RemoveMemlock failed — BPF map creation may EPERM on kernels < 5.11")
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Error(nil, "NODE_NAME env var not set")
		os.Exit(1)
	}

	mustEnsureCheckpointTmpfs(log, "/run/podmotion/checkpoints")

	// Try in-cluster config first (DaemonSet pod), fall back to kubeconfig file
	// (bare binary on VM for PoC sprints).
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = "/etc/rancher/k3s/k3s.yaml" // k3s default
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Error(err, "Failed to build kubeconfig (tried in-cluster and file)")
			os.Exit(1)
		}
		log.Info("Using kubeconfig file", "path", kubeconfig)
	}

	registrar, regErr := nmcregistrar.New(cfg, nodeName)
	if regErr != nil {
		log.Error(regErr, "Failed to build NMC registrar — NMC registration will be skipped")
		registrar = nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	log.Info("PodMotion agent starting", "node", nodeName)

	// Surface the authoritative build identity so a live-migration proof run can be
	// bound to the exact source tree this binary was built from, instead of inferring
	// artifact/source correspondence structurally after the fact. A dirty build is
	// flagged explicitly: its identity is not pinned to a commit.
	prov := buildinfo.Read()
	log.Info("build provenance", prov.LogValues()...)
	if prov.Dirty {
		log.Info("WARNING: agent built from a working tree with uncommitted changes — build identity is NOT pinned to a commit; a proof artifact must record this and be rebuilt from a committed tree to establish artifact/source correspondence")
	}

	// Load mTLS config from cert-manager-provisioned secret mount.
	// Falls back to insecure if certs are not present (dev/kind environment).
	tlsCfg, err := agenttls.LoadServerConfig(
		agenttls.DefaultCertFile,
		agenttls.DefaultKeyFile,
		agenttls.DefaultCAFile,
	)
	if err != nil {
		log.Error(err, "Failed to load TLS config")
		os.Exit(1)
	}

	// Select the checkpointer based on OS.
	// On Linux (kind nodes / production), use the real CRIUCheckpointer.
	// On macOS (developer machines), fall back to StubCheckpointer with a warning.
	var checkpointer criu.Checkpointer
	if runtime.GOOS == "linux" {
		log.Info("Using CRIUCheckpointer (real CRIU subprocess via go-criu/v7)")
		cp := criu.NewCRIUCheckpointer("/usr/sbin/criu")
		// SD-1 (ADR-0231/0234): the de-privileged agent cannot itself setns(CLONE_NEWNS)
		// into the host mount namespace, and the HOST criu binary at /usr/sbin/criu is
		// dynamically linked against the host glibc (2.39) — running it directly in the
		// debian:12-slim agent container (glibc ~2.36) fails with "GLIBC_2.38 not found".
		// Route the dump/pre-dump CLI through the privileged netns-broker sidecar, which
		// nsenters the host mount namespace and execve's podmotion-criu-wrapper → criu
		// (same allowlisted host-ns launch primitive the restore path uses). The wrapper
		// is invoked with no --cgroup-fd args, so it is a pure "exec criu in host mnt ns"
		// shim. On kind/dev this runner is still installed but the broker runs criu in the
		// host mount namespace exactly the same way (the node/container glibc match there
		// made the old direct exec work only by coincidence).
		// Route dump/pre-dump through the broker's ASYNC exec ops (ExecStart/ExecPoll/
		// ExecSignal — ADR-0234), the same primitive the live Restore uses. The async path
		// lets an aborted dump SIGKILL the broker-side CRIU child (via ExecSignal) so it
		// cannot keep writing checkpoint images after the caller returns "aborted" and the
		// zeroize path runs (invariant 7). The broker pins the async binary to the criu
		// wrapper, which is exactly argv[0] here.
		cp.SetHostNSRunner(func(_ context.Context, argv ...string) (criu.HostNSProcess, error) {
			startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			pid, err := netnsbroker.NewClient().ExecStart(startCtx, argv...)
			if err != nil {
				return nil, err
			}
			return &brokerHostNSProcess{pid: pid}, nil
		})
		checkpointer = cp
	} else {
		log.Info("CRIU not available on this OS — using StubCheckpointer (dev mode)",
			"os", runtime.GOOS)
		checkpointer = &criu.StubCheckpointer{
			SimulatedDirtyMB:          128,
			SimulatedFreezeDurationMs: 150,
		}
	}

	// Build a controller-runtime cluster so the agent has a cached, informer-backed k8s client.
	// The cache is required for the ADR-0118 podUID-from-CR fallback: Checkpoint reads the
	// PodMigration CR, and a cold (un-synced) cache would return spurious not-found errors.
	var k8sClient client.Client
	var seccompRecorder record.EventRecorder
	cl, clErr := cluster.New(cfg, func(o *cluster.Options) { o.Scheme = scheme })
	if clErr != nil {
		log.Error(clErr, "Failed to build k8s cluster client — MigrationCheckpoint CR updates will be skipped")
		k8sClient = nil
	} else {
		k8sClient = cl.GetClient()
		// ADR-0009 §3/§4: the seccomp manager emits SeccompWeakened/SeccompRestored events
		// against the migrated Pod. Source the recorder from the cluster's event provider.
		seccompRecorder = cl.GetEventRecorderFor("podmotion-seccomp")
		// Run the cluster (starts the informer cache) for the agent's lifetime.
		go func() {
			if err := cl.Start(ctx); err != nil {
				log.Error(err, "cluster cache runtime exited with error")
			}
		}()
	}

	agentSrv := server.New(nodeName, checkpointer, k8sClient)

	// SD-3 (ADR-0009 §2): crash-recovery for the seccomp Unconfined window. If a prior agent
	// instance died inside the checkpoint window after SwapToUnconfined but before
	// RestoreSeccomp, the container is still Unconfined and a real-profile record is on disk
	// at /run/podmotion/seccomp-restore/. Restore each one at startup (Kill+Create mutation is
	// the partial M13 seam) and emit a SeccompRestoreAfterRestart event per recovered container.
	seccompMgr := &seccomp.ContainerdSeccompManager{KubeClient: k8sClient, Recorder: seccompRecorder}
	if n, recErr := seccompMgr.RecoverOrphanedProfiles(ctx); recErr != nil {
		log.Error(recErr, "seccomp crash-recovery scan failed (ADR-0009 §2)")
	} else if n > 0 {
		log.Info("seccomp crash-recovery (SD-3, ADR-0009 §2): restored orphaned Unconfined container(s) at startup",
			"restoredCount", n)
	}

	// SD-4 (ADR-0039, ADR-0148): start the ptrace-window stale sweeper. The CRIU dump/restore
	// handlers open a window marker around each CRIU invocation and close it (deferred + explicit)
	// when CRIU returns; this sweeper is the third line of defense — it closes any window left
	// stuck open by an agent that crashed inside the CRIU window before its deferred close fired,
	// so ptrace is never treated as in-window indefinitely (the in-window hint for the future SD-5
	// seccomp-BPF ptrace arg-filter). Bound = 2x freeze budget; runs until ctx is cancelled.
	seccomp.StartStaleWindowSweeper(ctx.Done(), 0)

	// ADR-0216: thaw any source workload left in SIGSTOP by a prior agent instance.
	// LeaveStopped=true (Strict TCP-stateful) dumps leave the source in State T until
	// the matching SIGCONT (Abort/rollback/InjectIPHandoff). If THIS agent's predecessor
	// died after the freeze but before that SIGCONT, the in-memory thaw registry was lost
	// and the source would stay frozen forever. The durable on-disk registry lets us thaw
	// those orphans at startup (PID+start-time guarded, never signals a reused PID).
	// Gate-12 origin: gate-redis-s35 was left in State T, listening but never PONGing.
	if n := server.ReconcileOrphanedFrozenSources(); n > 0 {
		log.Info("ReconcileOrphanedFrozenSources (ADR-0216): thawed orphaned frozen source process(es) at startup",
			"thawedCount", n)
	}

	// Start gRPC server on :9090.
	go func() {
		// ADR-0118 Blocking Item 1: do not accept Checkpoint RPCs until the informer cache
		// has completed its initial sync, otherwise CR lookups race against cache warm-up.
		if cl != nil {
			if ok := cl.GetCache().WaitForCacheSync(ctx); !ok {
				log.Error(nil, "informer cache failed to sync — refusing to start gRPC server")
				os.Exit(1)
			}
		}
		if err := agentSrv.ListenAndServe(ctx, ":9090", tlsCfg); err != nil {
			log.Error(err, "gRPC server exited with error")
		}
	}()

	// Start NRI plugin. OnStartContainer triggers CRIU restore when a replacement pod
	// bearing podmotion.io/checkpoint-ref starts on this node (live restore path #2).
	nriPlugin := nri.New(
		nil, // OnStopping: pre-dump trigger wired in M5
		func(ctx context.Context, event nri.ContainerEvent, checkpointRef string) error {
			// checkpointRef is already validated by HandleStartContainer regex before
			// this callback is invoked, so concatenation is safe here.
			checkpointDir := "/run/podmotion/checkpoints/" + checkpointRef + "/final"
			log.Info("NRI StartContainer: invoking CRIU restore",
				"container", event.ID,
				"pod", event.Pod,
				"checkpointRef", checkpointRef,
				"checkpointDir", checkpointDir,
			)
			// ADR-0144 Decision Point 1 / NB-3: fetch tcpPreservationMode from the
			// PodMigration CR BEFORE invoking CRIU so that --leave-stopped is emitted
			// correctly. CR fetch failure defaults to Strict (fail-closed, NB-4): if the
			// mode is unknown it is safer to hold the restored tree than to risk a write
			// into an unwired datapath, which breaks seq_delta=0.
			migrationNamespace := event.Annotations["podmotion.io/migration-namespace"]
			if migrationNamespace == "" {
				migrationNamespace = event.Namespace
			}
			tcpPreservationMode := string(pmv1.TCPPreservationModeStrict) // fail-closed default
			if k8sClient != nil {
				fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 10*time.Second)
				pmCR := &pmv1.PodMigration{}
				if fetchErr := k8sClient.Get(fetchCtx, types.NamespacedName{Namespace: migrationNamespace, Name: checkpointRef}, pmCR); fetchErr != nil {
					log.Error(fetchErr, "NRI StartContainer: could not fetch PodMigration CR for tcpPreservationMode — defaulting to Strict (fail-closed, ADR-0144 NB-4)",
						"migration", checkpointRef, "namespace", migrationNamespace)
				} else {
					tcpPreservationMode = string(pmCR.Spec.TCPPreservationMode)
					log.Info("NRI StartContainer: fetched tcpPreservationMode from CR (ADR-0144)",
						"migration", checkpointRef, "mode", tcpPreservationMode)
				}
				fetchCancel()
			}
			// ADR-0122: pass the replacement pod's containerd sandbox ID (pod.GetId()) so
			// JoinNsRestore can resolve its netns via the containerd sandbox API. Also pass
			// tcpPreservationMode so JoinNsRestore can gate --leave-stopped on the Strict path.
			// E1 Condition 1: JoinNsRestore now returns (pid, mac, error). The MAC is populated
			// by the shared finalizeRestore primitive inside JoinNsRestore — this closure must
			// NOT call ReadReplVethMAC independently (path-independent contract, ADR-0133 D3).
			// E1 Condition 2: SingleHomeRestoredPod is called inside finalizeRestore; do not
			// call it independently here.
			// ADR-0353 R4/D6: ReportRestoreConfirmed is now called INSIDE JoinNsRestore itself
			// (server-side critical section), not here — the deferred releaseRestore inside
			// JoinNsRestore must fire AFTER the terminal confirm, never before, so the
			// single-owner claim release never straddles the server<->main package boundary.
			// This closure passes migrationNamespace (already resolved above) into JoinNsRestore
			// and no longer calls ReportRestoreConfirmed independently.
			// ADR-0351 D1.2: pass the NRI-carried cgroup fields straight through as parameters —
			// no query, no poll, no side-map. event.ContainerCgroupsPath/PodCgroupParent were
			// populated directly off the NRI hook payload in buildContainerEvent (plugin.go).
			pid, replVethMAC, err := agentSrv.JoinNsRestore(checkpointRef, migrationNamespace, checkpointDir, event.ImageName, event.ID, event.SandboxID, event.ContainerCgroupsPath, event.PodCgroupParent, tcpPreservationMode)
			if err != nil {
				log.Error(err, "NRI CRIU restore failed", "container", event.ID)
				return err
			}
			log.Info("NRI CRIU restore complete (ReportRestoreConfirmed reported server-side, ADR-0353 R4)",
				"container", event.ID, "restoredPID", pid, "replVethMAC", replVethMAC)
			return nil
		},
	).WithK8sVerification(k8sClient, nodeName)
	go func() {
		if err := nriPlugin.Run(ctx); err != nil {
			log.Error(err, "NRI plugin exited with error")
		}
	}()

	// Register NodeMigrationCapacity for this node.
	// Non-fatal: agent still serves gRPC even if NMC registration fails temporarily.
	if registrar != nil {
		if err := registrar.Register(ctx); err != nil {
			log.Error(err, "NMC registration failed — will retry via heartbeat")
		} else {
			log.Info("NodeMigrationCapacity registered", "node", nodeName)
		}
	}

	// EnsureXDPBridgeLoaded: load and pin the xdp_bridge BPF program on the host
	// network interface at agent startup (ADR-0155 Decision 1).  Read XDPBridgeCapable
	// from the NMC CR; fall back to true on Linux if the NMC is not yet readable.
	{
		xdpBridgeCapable := false
		hostIfname := "eth0" // default for kind/VM; overridden by default route lookup below
		if defaultIface, err := defaultRouteIface(); err == nil && defaultIface != "" {
			hostIfname = defaultIface
		}
		if k8sClient != nil {
			nmc := &pmv1.NodeMigrationCapacity{}
			fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := k8sClient.Get(fetchCtx, types.NamespacedName{Name: nodeName}, nmc); err != nil {
				log.Error(err, "EnsureXDPBridgeLoaded: could not read NMC — XDPBridgeCapable=false (no-op)")
			} else {
				xdpBridgeCapable = nmc.Spec.NetworkCapability.XDPBridgeCapable
			}
			fetchCancel()
		}
		xdpCtx, xdpCancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := agentSrv.EnsureXDPBridgeLoaded(xdpCtx, hostIfname, xdpBridgeCapable); err != nil {
			log.Error(err, "EnsureXDPBridgeLoaded failed (non-fatal — XDP bridge will be inactive)",
				"hostIfname", hostIfname, "xdpBridgeCapable", xdpBridgeCapable)
		}
		xdpCancel()
	}

	// TODO(podmotion-io/podmotion#<issue>, M1): start metrics server on :9091 (Prometheus /metrics endpoint for agent DaemonSet scraping).

	// Heartbeat loop — updates NMC status.lastHeartbeat every 30s.
	// Sets status.ready=false on shutdown so the scheduler stops sending migrations here.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info("Shutting down — marking node not ready for migration")
				if registrar != nil {
					if err := registrar.Deregister(context.Background()); err != nil {
						log.Error(err, "Failed to deregister NMC on shutdown")
					}
				}
				return
			case <-ticker.C:
				if registrar != nil {
					if err := registrar.Heartbeat(ctx); err != nil {
						log.Error(err, "NMC heartbeat failed")
					}
				}
			}
		}
	}()

	<-ctx.Done()
	log.Info("Agent exiting")
}
