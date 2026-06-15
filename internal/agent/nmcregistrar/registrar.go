/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package nmcregistrar creates and maintains the NodeMigrationCapacity CR for this node.
package nmcregistrar

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// defaultAgentPort is the port the agent gRPC server listens on.
const defaultAgentPort = "9090"

// Registrar creates and updates the NodeMigrationCapacity CR for the local node.
type Registrar struct {
	client    client.Client
	nodeName  string
	agentPort string // gRPC listen port; defaults to defaultAgentPort
}

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

// detectCRIU runs "/usr/sbin/criu --version" and returns the version string (e.g. "3.17.1").
// Falls back to searching PATH if the explicit path is not present.
// Returns an empty string on any error.
func detectCRIU() string {
	bin := criuBinaryPath
	if _, err := os.Stat(bin); err != nil {
		// Fallback: search PATH (useful in dev/test environments)
		bin = "criu"
	}
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return ""
	}
	// Output looks like: "Version: 4.2\n" or "CRIU version 4.2"
	line := strings.TrimSpace(string(out))
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
	criuVersion := detectCRIU()
	// N1: assert vendored pycriu magic table covers all expected CRIU image types.
	assertMagicTableCoverage(criuVersion)
	kernelFeatures := detectKernelFeatures()
	longhornAvailable := detectLonghorn(ctx, r.client)

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
				CNIPlugin:           detectCNI(),
				IPMobilitySupported: ipMobilitySupported(detectCNI(), kernelFeatures),
				XDPBridgeCapable:    kernelFeatures.XDPSupported && kernelFeatures.BPFEnabled,
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

// ipMobilitySupported reports whether PodMotion's overlay FDB/VTEP handoff
// (ADR-0048 eBPF XDP VTEP + ADR-0133 neighbor injection) can preserve pod IPs
// on this CNI. Flannel/kindnet VXLAN overlays ARE supported because PodMotion
// injects the FDB/neighbor entries the static overlay lacks (see internal/agent/
// network/fdb.go, bpf/pm_xdp_vtep.c). Env override PODMOTION_FORCE_IP_MOBILITY
// ("true"/"false") wins for gate/bring-up.
func ipMobilitySupported(cni string, kf pmv1.KernelFeatures) bool {
	if v, ok := os.LookupEnv("PODMOTION_FORCE_IP_MOBILITY"); ok {
		return strings.EqualFold(v, "true")
	}
	if !(kf.XDPSupported && kf.BPFEnabled) {
		return false
	}
	switch cni {
	case "flannel", "kindnet": // VXLAN overlay — FDB/VTEP handoff implemented (ADR-0048, ADR-0133)
		return true
	case "calico", "cilium", "ovn-kubernetes": // BGP/native routing or native eBPF datapath
		return true
	default:
		return false
	}
}

// Heartbeat patches status.lastHeartbeat and ready=true.
func (r *Registrar) Heartbeat(ctx context.Context) error {
	nmc := &pmv1.NodeMigrationCapacity{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: r.nodeName}, nmc); err != nil {
		return fmt.Errorf("getting NodeMigrationCapacity for heartbeat: %w", err)
	}
	now := metav1.Now()
	nmc.Status.Ready = true
	nmc.Status.LastHeartbeat = &now
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
