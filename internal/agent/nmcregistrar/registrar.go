/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package nmcregistrar creates and maintains the NodeMigrationCapacity CR for this node.
package nmcregistrar

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
	"github.com/podmotion-io/podmotion/internal/agent/network"
)

// defaultAgentPort is the port the agent gRPC server listens on.
const defaultAgentPort = "9090"

// hostExecFunc runs argv to completion in the HOST mount namespace via the netns-broker's
// synchronous "exec" op and returns the result (ADR-0366). nil ⇒ detectCRIU falls back to a
// direct in-container exec (kind/dev/tests where node and container glibc match, and unit
// tests) — the exact fallback convention criu.CRIUCheckpointer.hostNSRun already established.
type hostExecFunc func(ctx context.Context, opTimeout time.Duration, argv ...string) netnsbroker.ExecResult

// Registrar creates and updates the NodeMigrationCapacity CR for the local node.
type Registrar struct {
	client    client.Client
	nodeName  string
	agentPort string       // gRPC listen port; defaults to defaultAgentPort
	hostExec  hostExecFunc // nil ⇒ direct in-container exec fallback (ADR-0366)
}

// SetHostExecFunc installs the host-mount-namespace exec primitive used by detectCRIU
// (ADR-0366). Must be called before Register/Heartbeat for the host-ns routing to take
// effect; nil (the zero value) preserves today's direct in-container exec behavior.
func (r *Registrar) SetHostExecFunc(f hostExecFunc) { r.hostExec = f }

// New builds a controller-runtime client with the pmv1 scheme registered.
func New(cfg *rest.Config, nodeName string) (*Registrar, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(pmv1.AddToScheme(scheme))

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("building controller-runtime client: %w", err)
	}
	return &Registrar{client: c, nodeName: nodeName, agentPort: defaultAgentPort}, nil
}

// resolveNodeInternalIP looks up the Node object and returns its first InternalIP address.
func (r *Registrar) resolveNodeInternalIP(ctx context.Context) (string, error) {
	node := &corev1.Node{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: r.nodeName}, node); err != nil {
		return "", fmt.Errorf("getting Node %q to resolve InternalIP: %w", r.nodeName, err)
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP && addr.Address != "" {
			return addr.Address, nil
		}
	}
	return "", fmt.Errorf("no InternalIP found for node %q", r.nodeName)
}

// criuBinaryPath is the path to the CRIU binary, mounted from the host node via hostPath volume.
const criuBinaryPath = "/usr/sbin/criu"

// criuBinaryPathFallback is a second candidate, mounted from the host-usr-local-sbin hostPath
// volume (daemonset.yaml). On some hosts (observed on k3s-provisioned nodes) /usr/sbin/criu is
// a symlink to /usr/local/sbin/criu rather than a real binary; the agent only ever mounted
// /usr/sbin, so the symlink target was missing inside the container and os.Stat on the symlink
// itself (which does not follow it to check the target) silently failed, leaving
// spec.criuVersion empty even though CRIU was genuinely installed on the host.
const criuBinaryPathFallback = "/usr/local/sbin/criu"

// hostCRIUWrapperPath is the host-node install location of podmotion-criu-wrapper
// (ADR-0181/0183: the install-criu-wrapper init container copies it here), already a
// member of the netns-broker's synchronous "exec" op allowlist (ADR-0347,
// internal/agent/netnsbroker/broker.go execAllowlist) for the restore path. ADR-0366
// reuses this exact host-exec surface for CRIU-version detection instead of exec'ing
// the dynamically-linked host CRIU binary directly in the older-glibc agent container
// (the same glibc-mismatch fix internal/agent/criu/criu_checkpointer.go already applies
// one layer up, for dump/pre-dump — see hostCRIUWrapperPath there).
const hostCRIUWrapperPath = "/opt/podmotion/bin/podmotion-criu-wrapper"

// criuDetectionError classifies why detectCRIU failed, so callers can attach the right
// NMC status Condition reason (ADR-0366 Condition 2) without re-parsing a message string.
type criuDetectionError struct {
	reason string // pmv1.ReasonCRIUBrokerUnreachable or pmv1.ReasonCRIUExecFailed
	err    error
}

func (e *criuDetectionError) Error() string { return e.err.Error() }
func (e *criuDetectionError) Unwrap() error { return e.err }

// criuBrokerMaxAttempts/RetryBackoff/AttemptTimeout bound the broker-unreachable retry
// (ADR-0366 §3): a genuine startup race (broker sidecar still binding its socket) is
// worth a few quick retries; a broker that never comes up must still give up promptly
// and surface loudly rather than retry forever (zero-tech-debt: no fail-open fallback).
const (
	criuBrokerMaxAttempts    = 3
	criuBrokerRetryBackoff   = 500 * time.Millisecond
	criuBrokerAttemptTimeout = 5 * time.Second
)

// resolveCRIUBinaryPathForDirectExec finds the CRIU binary for the direct in-container
// exec path (kind/dev/tests). Tries the canonical path, then the /usr/local/sbin
// fallback, then finally searches PATH. Unchanged path-resolution logic (ADR-0366).
func resolveCRIUBinaryPathForDirectExec() string {
	bin := criuBinaryPath
	if _, err := os.Stat(bin); err != nil {
		if _, err2 := os.Stat(criuBinaryPathFallback); err2 == nil {
			bin = criuBinaryPathFallback
		} else {
			// Fallback: search PATH (useful in dev/test environments)
			bin = "criu"
		}
	}
	return bin
}

// parseCRIUVersion extracts the version string from `criu --version` output, e.g.
// "Version: 4.2\n" or "CRIU version 4.2". Unchanged parsing logic (ADR-0366), now
// shared between the direct-exec and broker-exec paths (applied to ExecResult's
// captured output instead of a local exec.Command's output on the broker path).
func parseCRIUVersion(out string) string {
	line := strings.TrimSpace(out)
	for _, part := range strings.Fields(line) {
		// First field that looks like a version number
		if len(part) > 0 && part[0] >= '0' && part[0] <= '9' {
			return part
		}
	}
	// Try colon-split form "Version: 4.2"
	if idx := strings.Index(line, ":"); idx != -1 {
		return strings.TrimSpace(line[idx+1:])
	}
	return line
}

// detectCRIU resolves the installed CRIU version and returns (version, error). version
// is "" on any failure; error is non-nil on any failure and nil on success — never both
// zero (ADR-0366: replaces the old bare `return ""` silent-swallow with a genuinely
// surfaced, classified error the caller uses to log AND set the CRIUDetected condition).
func (r *Registrar) detectCRIU(ctx context.Context) (string, error) {
	log := logf.FromContext(ctx).WithName("nmcregistrar")
	bin := resolveCRIUBinaryPathForDirectExec()

	if r.hostExec == nil {
		// kind/dev/tests: node and container glibc match (or StubCheckpointer path) —
		// same direct-exec behavior as today, minus the silent swallow.
		return execDirectAndParse(bin, log)
	}

	// Production (KVM/RKE2): route through the host mount namespace via the SAME
	// podmotion-criu-wrapper + broker exec surface criu_checkpointer.go uses for
	// dump/pre-dump (ADR-0234), through the broker's synchronous Exec op.
	return r.detectCRIUViaBroker(ctx, log)
}

// execDirectAndParse execs `bin --version` directly in the agent container (kind/dev/
// tests). WARN-logs and returns a classified error on any failure — never a bare "".
func execDirectAndParse(bin string, log logr.Logger) (string, error) {
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		log.Info("WARNING: CRIU version detection failed (direct in-container exec)",
			"binary", bin, "error", err)
		return "", &criuDetectionError{
			reason: pmv1.ReasonCRIUExecFailed,
			err:    fmt.Errorf("direct exec of %q --version: %w", bin, err),
		}
	}
	return parseCRIUVersion(string(out)), nil
}

// detectCRIUViaBroker issues `argv = [hostCRIUWrapperPath, "--", criuBinaryPath,
// "--version"]` through the broker's synchronous Exec op (ADR-0366 §1). It distinguishes
// ExecResult.SpawnErr (broker unreachable — a startup race, retried bounded: 3 attempts,
// 500ms backoff, 5s per-attempt timeout) from ExitCode != 0 (a genuine CRIU failure —
// logged immediately, never retried: retrying a deterministic failure only delays an
// equally-real WARN, and unbounded/infinite retry of either case would be exactly the
// fail-open fallback the zero-tech-debt pillar forbids).
func (r *Registrar) detectCRIUViaBroker(ctx context.Context, log logr.Logger) (string, error) {
	argv := []string{hostCRIUWrapperPath, "--", criuBinaryPath, "--version"}

	var lastSpawnErr error
retryLoop:
	for attempt := 1; attempt <= criuBrokerMaxAttempts; attempt++ {
		res := r.hostExec(ctx, criuBrokerAttemptTimeout, argv...)

		if res.SpawnErr == nil {
			if res.ExitCode != 0 {
				// Broker reached, wrapper/criu ran and failed for real — deterministic,
				// not a startup race. No retry: log immediately.
				log.Info("WARNING: CRIU version detection failed — host CRIU exec via broker exited nonzero",
					"wrapper", hostCRIUWrapperPath, "criuBinary", criuBinaryPath,
					"exitCode", res.ExitCode, "stderr", string(res.Stderr))
				return "", &criuDetectionError{
					reason: pmv1.ReasonCRIUExecFailed,
					err: fmt.Errorf("broker exec of %v exited %d: %s",
						argv, res.ExitCode, strings.TrimSpace(string(res.Stderr))),
				}
			}
			out := res.Combined
			if len(out) == 0 {
				out = res.Stdout
			}
			return parseCRIUVersion(string(out)), nil
		}

		// broker unreachable this attempt — bounded retry.
		lastSpawnErr = res.SpawnErr
		if attempt == criuBrokerMaxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			lastSpawnErr = ctx.Err()
			break retryLoop
		case <-time.After(criuBrokerRetryBackoff):
		}
	}

	// Only the FINAL failed attempt logs here.
	log.Info("WARNING: CRIU version detection failed — could not reach netns-broker",
		"wrapper", hostCRIUWrapperPath, "criuBinary", criuBinaryPath,
		"error", lastSpawnErr, "attempts", criuBrokerMaxAttempts)
	return "", &criuDetectionError{
		reason: pmv1.ReasonCRIUBrokerUnreachable,
		err: fmt.Errorf("netns-broker unreachable after %d attempts: %w",
			criuBrokerMaxAttempts, lastSpawnErr),
	}
}

// criuDetectedCondition builds the ADR-0366 Condition-2 observability signal: a real NMC
// status Condition (not just a log line) reflecting whether CRIU detection has a value.
// version != "" is treated as success regardless of err (err is only consulted on
// failure, to classify Reason); this mirrors the caller contract established by
// detectCRIU/detectCRIUViaBroker (version and err are never both meaningfully set).
func criuDetectedCondition(version string, err error) metav1.Condition {
	if version != "" {
		return metav1.Condition{
			Type:    pmv1.ConditionCRIUDetected,
			Status:  metav1.ConditionTrue,
			Reason:  pmv1.ReasonCRIUVersionDetected,
			Message: fmt.Sprintf("CRIU version %q detected.", version),
		}
	}
	reason := pmv1.ReasonCRIUExecFailed
	msg := "CRIU version detection failed."
	var de *criuDetectionError
	switch {
	case errors.As(err, &de):
		reason = de.reason
		msg = de.Error()
	case err != nil:
		msg = err.Error()
	}
	return metav1.Condition{
		Type:    pmv1.ConditionCRIUDetected,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: msg,
	}
}

// detectKernelFeatures probes /proc and /boot for kernel config flags.
// Falls back to true on kind nodes (Linux 6.x) if config is not readable.
func detectKernelFeatures() pmv1.KernelFeatures {
	kf := pmv1.KernelFeatures{
		CheckpointRestore: true,
		MemSoftDirty:      true,
		Userfaultfd:       true,
		BPFEnabled:        true,
		XDPSupported:      true,
	}

	// Read kernel version
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kf.KernelVersion = strings.TrimSpace(string(b))
	} else {
		kf.KernelVersion = "unknown"
	}

	// Try to read kernel config from /proc/config.gz first
	cfg := readKernelConfig()
	if cfg == "" {
		// TCClsactSupported: always active-probe regardless of config readability (ADR-0169).
		kf.TCClsactSupported = probeTCClsact()
		return kf
	}

	kf.CheckpointRestore = configEnabled(cfg, "CONFIG_CHECKPOINT_RESTORE")
	kf.MemSoftDirty = configEnabled(cfg, "CONFIG_MEM_SOFT_DIRTY")
	kf.Userfaultfd = configEnabled(cfg, "CONFIG_USERFAULTFD")
	kf.BPFEnabled = configEnabled(cfg, "CONFIG_BPF_SYSCALL")
	kf.XDPSupported = configEnabled(cfg, "CONFIG_XDP_SOCKETS")
	// TCClsactSupported: active runtime probe — BPFEnabled is NOT a reliable proxy
	// for clsact-on-veth support on all substrates (ADR-0169). Probe error/failure → false.
	kf.TCClsactSupported = probeTCClsact()
	return kf
}

func readKernelConfig() string {
	// Try /proc/config.gz
	if f, err := os.Open("/proc/config.gz"); err == nil {
		defer f.Close()
		r, err := gzip.NewReader(f)
		if err == nil {
			defer r.Close()
			b, err := io.ReadAll(r)
			if err == nil {
				return string(b)
			}
		}
	}
	// Try /boot/config-<uname-r>
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kver := strings.TrimSpace(string(b))
		path := "/boot/config-" + kver
		if b2, err2 := os.ReadFile(path); err2 == nil {
			return string(b2)
		}
	}
	return ""
}

func configEnabled(cfg, key string) bool {
	target := key + "=y"
	return strings.Contains(cfg, target)
}

// detectBPF gives a best-effort BPF hint from perf_event_paranoid.
func detectBPF() bool {
	b, err := os.ReadFile("/proc/sys/kernel/perf_event_paranoid")
	if err != nil {
		return true // assume yes on kind
	}
	val := strings.TrimSpace(string(b))
	return val != "4" // 4 = very restricted, unlikely on kind
}

// detectLonghorn checks if the longhorn.io CRD group is available.
func detectLonghorn(ctx context.Context, c client.Client) bool {
	// We attempt to list an NMC with a fake name to detect if CRD group routes work.
	// A simpler approach: check if the longhorn-system namespace or engine CRD exists.
	// We use the REST mapper to check if longhorn volumes resource is known.
	mapper := c.RESTMapper()
	_, err := mapper.ResourcesFor(longHornVolumeGVR())
	return err == nil
}

func longHornVolumeGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "longhorn.io",
		Version:  "v1beta2",
		Resource: "volumes",
	}
}

// ensure metav1 is used
var _ = metav1.Now

// knownPycriuImageTypes is the set of CRIU image types covered by the vendored pycriu magic
// table (pycriu/images/magic.py). If CRIU produces an image type not in this set, pycriu.images.load
// will raise MagicException. Add entries here whenever magic.py is updated (N1, CNCF portability).
var knownPycriuImageTypes = map[string]bool{
	"CRTOOLS_IMAGES_V1_1": true,
	"IMG_COMMON":          true,
	"IMG_SERVICE":         true,
	"INVENTORY":           true,
	"PSTREE":              true,
	"FDINFO":              true,
	"PAGEMAP":             true,
	"CORE":                true,
	"IDS":                 true,
	"VMAS":                true,
	"PIPES":               true,
	"PIPES_DATA":          true,
	"FIFO":                true,
	"FIFO_DATA":           true,
	"SIGACT":              true,
	"UNIXSK":              true,
	"INETSK":              true,
	"PACKETSK":            true,
	"ITIMERS":             true,
	"POSIX_TIMERS":        true,
	"SK_QUEUES":           true,
	"UTSNS":               true,
	"CREDS":               true,
	"IPC_VAR":             true,
	"IPCNS_SHM":           true,
	"IPCNS_MSG":           true,
	"IPCNS_SEM":           true,
	"REG_FILES":           true,
	"EXT_FILES":           true,
	"FS":                  true,
	"MM":                  true,
	"REMAP_FPATH":         true,
	"GHOST_FILE":          true,
	"TCP_STREAM":          true,
	"EVENTFD_FILE":        true,
	"EVENTPOLL_FILE":      true,
	"EVENTPOLL_TFD":       true,
	"SIGNALFD":            true,
	"INOTIFY_FILE":        true,
	"INOTIFY_WD":          true,
	"MNTS":                true,
	"NETDEV":              true,
	"NETNS":               true,
	"TTY_FILES":           true,
	"TTY_INFO":            true,
	"TTY_DATA":            true,
	"FILE_LOCKS":          true,
	"RLIMIT":              true,
	"FANOTIFY_FILE":       true,
	"FANOTIFY_MARK":       true,
	"SIGNAL":              true,
	"NETLINK_SK":          true,
	"NS_FILES":            true,
	"TUNFILE":             true,
	"CGROUP":              true,
	"TIMERFD":             true,
	"CPUINFO":             true,
	"USERNS":              true,
	"SECCOMP":             true,
	"BINFMT_MISC":         true,
	"AUTOFS":              true,
	"FILES":               true,
	"MEMFD_INODE":         true,
	"TIMENS":              true,
	"PIDNS":               true,
	"BPFMAP_FILE":         true,
	"BPFMAP_DATA":         true,
	"APPARMOR":            true,
	"PIDFD":               true,
	"STATS":               true,
	"IRMAP_CACHE":         true,
	"KDAT":                true,
	"IFADDR":              true, // added Q1: CRIU 4.2
}

// criuImageTypesForVersion returns the set of image type names expected from a given CRIU version.
// This is a best-effort heuristic; extend when new CRIU image types are discovered at runtime.
// Currently all known types are assumed present for any CRIU >= 3.x.
func criuImageTypesForVersion(_ string) []string {
	types := make([]string, 0, len(knownPycriuImageTypes))
	for t := range knownPycriuImageTypes {
		types = append(types, t)
	}
	return types
}

// assertMagicTableCoverage checks that the vendored pycriu magic table covers all image types
// the installed CRIU version is known to produce. Logs warnings for any gaps (N1).
// This is a non-fatal preflight assertion: gaps are surfaced for observability but do not
// block NMC registration (a fatal block would prevent the agent from starting on any node
// whose CRIU differs slightly from the pinned version — the skip-on-unknown (S1) is the
// runtime safety net for strip-only images; mountpoints will already fail loud).
func assertMagicTableCoverage(criuVersion string) {
	expected := criuImageTypesForVersion(criuVersion)
	var missing []string
	for _, t := range expected {
		if !knownPycriuImageTypes[t] {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		// Log as a warning; the monitoring layer should alert on this condition.
		fmt.Printf("WARNING: pycriu magic table missing %d image type(s) for CRIU %s: %v — "+
			"pycriu.images.load will raise MagicException on these types; "+
			"update pycriu/images/magic.py and knownPycriuImageTypes\n",
			len(missing), criuVersion, missing)
	}
}

// Register creates or updates the NodeMigrationCapacity CR for this node.
func (r *Registrar) Register(ctx context.Context) error {
	criuVersion, criuErr := r.detectCRIU(ctx)
	// N1: assert vendored pycriu magic table covers all expected CRIU image types.
	assertMagicTableCoverage(criuVersion)
	kernelFeatures := detectKernelFeatures()
	longhornAvailable := detectLonghorn(ctx, r.client)
	cni := detectCNI() // ADR-0313: single call, reused for CNIPlugin, IPMobilitySupported, CNICompatible
	// ADR-0367: single computation reused for both IPMobilitySupported and
	// LiveMigrationEligible — the two fields describe the same underlying fact and must
	// never be independently derived (that is the exact drift shape ADR-0367 fixes).
	mobile := ipMobilitySupported(cni, kernelFeatures)

	// Resolve the node's InternalIP so the operator can reach this agent even when
	// it runs as a systemd service (no pod IP discoverable via label selector).
	agentEndpoint := ""
	if nodeIP, err := r.resolveNodeInternalIP(ctx); err == nil {
		port := r.agentPort
		if port == "" {
			port = defaultAgentPort
		}
		agentEndpoint = fmt.Sprintf("%s:%s", nodeIP, port)
	}

	nmc := &pmv1.NodeMigrationCapacity{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "migration.podmotion.io/v1alpha1",
			Kind:       "NodeMigrationCapacity",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: r.nodeName,
		},
		Spec: pmv1.NodeMigrationCapacitySpec{
			NodeName:       r.nodeName,
			CRIUVersion:    criuVersion,
			NRIEnabled:     false, // set by NRI probe in M5
			AgentEndpoint:  agentEndpoint,
			KernelFeatures: kernelFeatures,
			StorageCapability: pmv1.StorageCapability{
				LonghornAvailable: longhornAvailable,
				CephRBDAvailable:  false,
				LocalPVMigratable: true,
			},
			NetworkCapability: pmv1.NetworkCapability{
				CNIPlugin:             cni,
				IPMobilitySupported:   mobile,
				LiveMigrationEligible: mobile,
				XDPBridgeCapable:      kernelFeatures.XDPSupported && kernelFeatures.BPFEnabled,
			},
			MaxConcurrentMigrationsSource:      2,
			MaxConcurrentMigrationsDestination: 2,
		},
	}

	// Server-side apply with force=true
	data, err := client.MergeFrom(nmc).Data(nmc)
	if err != nil {
		// Fall back to raw patch data built manually via Apply
		_ = data
	}

	if err := r.client.Patch(ctx, nmc, client.Apply, client.ForceOwnership, client.FieldOwner("podmotion-agent")); err != nil {
		return fmt.Errorf("applying NodeMigrationCapacity: %w", err)
	}

	// Update status — include M25 network encryption probes (ADR-0081, ADR-0102).
	now := metav1.Now()
	nmc.Status.Ready = true
	nmc.Status.LastHeartbeat = &now
	nmc.Status.ClusterIPFamily = detectIPFamilySupport()
	// WireGuard and IPSec detection uses the network package (Linux-only; no-op stub on other OS).
	// Pod CIDR is read from the node spec; fall back to nil (detection skips CIDR-scoped checks).
	var podCIDR *net.IPNet
	nodeObj := &corev1.Node{}
	if r.client.Get(ctx, client.ObjectKey{Name: r.nodeName}, nodeObj) == nil {
		for _, cidr := range nodeObj.Spec.PodCIDRs {
			if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
				podCIDR = ipnet
				break
			}
		}
	}
	if wgIface, err := detectWireGuardInterface(podCIDR); err == nil {
		nmc.Spec.NetworkCapability.WireGuardInterface = wgIface
	}
	if ipsec, err := detectIPSecModeCNI(podCIDR); err == nil {
		nmc.Status.IPSecEncryption = ipsec
	}

	// ADR-0318: CNICompatible condition. Cilium now has a real ipcache/CiliumEndpoint
	// IP-mobility handoff path (ADR-0318 Decision §2) and is reported compatible like
	// the other supported CNIs; ipMobilitySupported below is flipped to match.
	meta.SetStatusCondition(&nmc.Status.Conditions, metav1.Condition{
		Type:    pmv1.ConditionCNICompatible,
		Status:  metav1.ConditionTrue,
		Reason:  pmv1.ReasonCNISupported,
		Message: fmt.Sprintf("CNI plugin %q is supported by PodMotion's live-migration datapath.", cni),
	})

	// ADR-0366 Condition 2: real observability for a CRIU-detection failure — not just
	// the WARN log line already emitted inside detectCRIU — so this state is visible via
	// `kubectl get nmc -o wide`/status without needing to go read agent pod logs.
	meta.SetStatusCondition(&nmc.Status.Conditions, criuDetectedCondition(criuVersion, criuErr))

	if err := r.client.Status().Update(ctx, nmc); err != nil {
		return fmt.Errorf("updating NodeMigrationCapacity status: %w", err)
	}
	return nil
}

// detectIPFamilySupport inspects the node's non-loopback, non-link-local addresses
// to determine IP family support (ADR-0081).
func detectIPFamilySupport() pmv1.IPFamilySupport {
	ifaces, err := net.Interfaces()
	if err != nil {
		return pmv1.IPFamilySupportUnknown
	}
	var hasV4, hasV6 bool
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip.To4() != nil {
				hasV4 = true
			} else {
				hasV6 = true
			}
		}
	}
	switch {
	case hasV4 && hasV6:
		return pmv1.IPFamilySupportDualStack
	case hasV4:
		return pmv1.IPFamilySupportIPv4Only
	case hasV6:
		return pmv1.IPFamilySupportIPv6Only
	default:
		return pmv1.IPFamilySupportUnknown
	}
}

// detectCNI tries to identify the CNI plugin from known directories.
// If PODMOTION_CNI_OVERRIDE is set, its value is returned directly without scanning.
// Detection order: filename match → "type" field inside conflist/conf JSON.
func detectCNI() string {
	// Env override wins — useful for kind clusters where /etc/cni/net.d may not be
	// mounted into the agent container or may contain ambiguous filenames.
	if override, ok := os.LookupEnv("PODMOTION_CNI_OVERRIDE"); ok && override != "" {
		return strings.ToLower(strings.TrimSpace(override))
	}

	cniConfDirs := []string{"/etc/cni/net.d"}
	// Some distros do not populate the canonical /etc/cni/net.d: k3s writes its embedded-
	// Flannel conflist to /var/lib/rancher/k3s/agent/etc/cni/net.d instead. The chart mounts
	// that host path (or any other distro-specific path) into the container and tells us
	// where via PODMOTION_CNI_EXTRA_CONF_DIR when agent.cni.extraConfDir is set (see
	// values.yaml / daemonset.yaml host-cni-conf-extra).
	if extra, ok := os.LookupEnv("PODMOTION_CNI_EXTRA_CONF_DIR"); ok && extra != "" {
		cniConfDirs = append(cniConfDirs, extra)
	}
	for _, dir := range cniConfDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := strings.ToLower(e.Name())
			// Fast path: CNI name in filename (most common case).
			switch {
			case strings.Contains(name, "kindnet"):
				return "kindnet"
			case strings.Contains(name, "flannel"):
				return "flannel"
			case strings.Contains(name, "calico"):
				return "calico"
			case strings.Contains(name, "cilium"):
				return "cilium"
			case strings.Contains(name, "ovn"):
				return "ovn-kubernetes"
			}
		}
		// Fallback: scan "type" field inside conflist/conf JSON files.
		for _, e := range entries {
			fname := e.Name()
			if !strings.HasSuffix(fname, ".conflist") && !strings.HasSuffix(fname, ".conf") {
				continue
			}
			data, err := os.ReadFile(dir + "/" + fname)
			if err != nil {
				continue
			}
			content := strings.ToLower(string(data))
			switch {
			case strings.Contains(content, `"type":"kindnet"`) ||
				strings.Contains(content, `"type": "kindnet"`):
				return "kindnet"
			case strings.Contains(content, `"type":"flannel"`) ||
				strings.Contains(content, `"type": "flannel"`):
				return "flannel"
			case strings.Contains(content, `"type":"calico"`) ||
				strings.Contains(content, `"type": "calico"`):
				return "calico"
			case strings.Contains(content, `"type":"cilium"`) ||
				strings.Contains(content, `"type": "cilium"`):
				return "cilium"
			case strings.Contains(content, "ovn-kubernetes"):
				return "ovn-kubernetes"
			}
		}
	}
	return "unknown"
}

// requiredBinaryForCNI maps a detected CNI plugin to the external binary its
// IPHandoffStrategy implementation depends on being present on PATH. Only CNIs with
// such a dependency have an entry; a CNI absent from this map has no startup binary
// check (its handoff strategy has no such dependency today).
//
// calico -> calicoctl: CalicoHandoff.WaitForWorkloadEndpointReady (internal/agent/iphandoff/
// calico.go) is documented as a stopgap that shells out via calicoctl until a direct CRD
// client lands (M9); this check makes a missing calicoctl fail loud and immediate at agent
// startup instead of surfacing as a confusing exec error mid-migration on the reconcile hot
// path (tryEstablishDataplaneReachability in podmigration_controller.go).
var requiredBinaryForCNI = map[string]string{
	"calico": "calicoctl",
}

// PreflightRequiredCNIBinaries detects this node's CNI plugin (the same detectCNI used by
// Register, honoring PODMOTION_CNI_OVERRIDE) and, if that CNI's IPHandoffStrategy depends on
// an external binary being present on PATH, verifies it resolves via exec.LookPath.
//
// Fail-closed by design — mirrors the netnsbroker ADR-0347 A1 startup-pin pattern used for
// nsenter/ip (internal/agent/netnsbroker/server.go Serve(): resolve required binaries once at
// startup, from the trusted startup PATH, and fail loud before serving any request rather than
// discovering the gap mid-operation. A missing required binary here must be a loud, immediate
// agent startup failure, not a silent skip.
func PreflightRequiredCNIBinaries() error {
	cni := detectCNI()
	bin, required := requiredBinaryForCNI[cni]
	if !required {
		return nil
	}
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("PreflightRequiredCNIBinaries: detected CNI %q requires %q on PATH but it was not found (fail-closed — see internal/agent/iphandoff/calico.go WaitForWorkloadEndpointReady): %w",
			cni, bin, err)
	}
	return nil
}

// ipMobilitySupported reports whether PodMotion's overlay FDB/VTEP handoff
// (ADR-0048 eBPF XDP VTEP + ADR-0133 neighbor injection) can preserve pod IPs
// on this CNI. A CNI match is a necessary condition but not sufficient: the overlay
// FDB/VTEP device must actually exist on this node (ADR-0192 Site B, B2 fix).
// The device is probed via DiscoverFdbInterface (link-type VXLAN discrimination —
// no "flannel.1" literal). On kind/kindnet DiscoverFdbInterface returns "" because
// kindnet is host-routed with no VXLAN overlay; this returns false.
// Env override PODMOTION_FORCE_IP_MOBILITY ("true"/"false") wins for gate/bring-up.
func ipMobilitySupported(cni string, kf pmv1.KernelFeatures) bool {
	if v, ok := os.LookupEnv("PODMOTION_FORCE_IP_MOBILITY"); ok {
		return strings.EqualFold(v, "true")
	}
	if !(kf.XDPSupported && kf.BPFEnabled) {
		return false
	}
	switch cni {
	case "flannel": // VXLAN overlay — FDB/VTEP handoff implemented (ADR-0048, ADR-0133)
		// Probe whether the VXLAN FDB device actually exists on this node (ADR-0192 B2).
		// DiscoverFdbInterface uses link-type VXLAN discrimination — no "flannel.1" literal.
		fdbIf, probeErr := network.DiscoverFdbInterface()
		if probeErr != nil || fdbIf == "" {
			return false
		}
		return true
	case "kindnet":
		// kindnet is host-routed (no VXLAN overlay); no FDB device exists.
		// DiscoverFdbInterface would return "" — return false directly (ADR-0192 B2).
		return false
	case "calico", "ovn-kubernetes": // BGP/native routing or native eBPF datapath
		return true
	case "cilium": // ADR-0318: real ipcache/CiliumEndpoint IP-mobility handoff implemented.
		return true
	default:
		return false
	}
}

// Heartbeat patches status.lastHeartbeat and ready=true. ADR-0366 §3 self-heal: it also
// re-attempts detectCRIU (and re-PATCHes Spec.CRIUVersion) whenever the currently-stored
// value is empty — making the pre-existing "NMC registration failed — will retry via
// heartbeat" comment (cmd/agent/main.go) actually true for this field. detectCRIU is
// deliberately NOT re-run when CRIUVersion is already populated (no needless host-ns
// exec calls once detection has already succeeded).
func (r *Registrar) Heartbeat(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("nmcregistrar")
	nmc := &pmv1.NodeMigrationCapacity{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: r.nodeName}, nmc); err != nil {
		return fmt.Errorf("getting NodeMigrationCapacity for heartbeat: %w", err)
	}

	var detectErr error
	if nmc.Spec.CRIUVersion == "" {
		var version string
		version, detectErr = r.detectCRIU(ctx)
		if version != "" {
			nmc.Spec.CRIUVersion = version
			if err := r.client.Update(ctx, nmc); err != nil {
				return fmt.Errorf("updating NodeMigrationCapacity spec.criuVersion (heartbeat self-heal): %w", err)
			}
			log.Info("CRIU version detected on heartbeat self-heal retry", "criuVersion", version)
			detectErr = nil
		}
	}

	now := metav1.Now()
	nmc.Status.Ready = true
	nmc.Status.LastHeartbeat = &now
	// ADR-0366 Condition 2: keep the CRIUDetected condition current on every heartbeat,
	// whether or not a re-attempt ran this cycle (reflects the currently-stored field).
	meta.SetStatusCondition(&nmc.Status.Conditions, criuDetectedCondition(nmc.Spec.CRIUVersion, detectErr))
	if err := r.client.Status().Update(ctx, nmc); err != nil {
		return fmt.Errorf("updating NodeMigrationCapacity heartbeat: %w", err)
	}
	return nil
}

// Deregister patches status.ready=false to signal the node is going offline.
func (r *Registrar) Deregister(ctx context.Context) error {
	nmc := &pmv1.NodeMigrationCapacity{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: r.nodeName}, nmc); err != nil {
		return fmt.Errorf("getting NodeMigrationCapacity for deregister: %w", err)
	}
	nmc.Status.Ready = false
	if err := r.client.Status().Update(ctx, nmc); err != nil {
		return fmt.Errorf("deregistering NodeMigrationCapacity: %w", err)
	}
	return nil
}
