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

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// Registrar creates and updates the NodeMigrationCapacity CR for the local node.
type Registrar struct {
	client   client.Client
	nodeName string
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
	return &Registrar{client: c, nodeName: nodeName}, nil
}

// detectCRIU runs "criu --version" and returns the version string (e.g. "4.2").
// Returns an empty string on any error.
func detectCRIU() string {
	out, err := exec.Command("criu", "--version").Output()
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
		return kf // use defaults
	}

	kf.CheckpointRestore = configEnabled(cfg, "CONFIG_CHECKPOINT_RESTORE")
	kf.MemSoftDirty = configEnabled(cfg, "CONFIG_MEM_SOFT_DIRTY")
	kf.Userfaultfd = configEnabled(cfg, "CONFIG_USERFAULTFD")
	kf.BPFEnabled = configEnabled(cfg, "CONFIG_BPF_SYSCALL")
	kf.XDPSupported = configEnabled(cfg, "CONFIG_XDP_SOCKETS")
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

// Register creates or updates the NodeMigrationCapacity CR for this node.
func (r *Registrar) Register(ctx context.Context) error {
	criuVersion := detectCRIU()
	kernelFeatures := detectKernelFeatures()
	longhornAvailable := detectLonghorn(ctx, r.client)

	nmc := &pmv1.NodeMigrationCapacity{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "migration.podmotion.io/v1alpha1",
			Kind:       "NodeMigrationCapacity",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: r.nodeName,
		},
		Spec: pmv1.NodeMigrationCapacitySpec{
			NodeName:    r.nodeName,
			CRIUVersion: criuVersion,
			NRIEnabled:  false, // set by NRI probe in M5
			KernelFeatures: kernelFeatures,
			StorageCapability: pmv1.StorageCapability{
				LonghornAvailable:  longhornAvailable,
				CephRBDAvailable:   false,
				LocalPVMigratable:  true,
			},
			NetworkCapability: pmv1.NetworkCapability{
				CNIPlugin:           detectCNI(),
				IPMobilitySupported: false,
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

	// Update status
	now := metav1.Now()
	nmc.Status.Ready = true
	nmc.Status.LastHeartbeat = &now
	if err := r.client.Status().Update(ctx, nmc); err != nil {
		return fmt.Errorf("updating NodeMigrationCapacity status: %w", err)
	}
	return nil
}

// detectCNI tries to identify the CNI plugin from known directories.
func detectCNI() string {
	cniConfDirs := []string{"/etc/cni/net.d"}
	for _, dir := range cniConfDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := strings.ToLower(e.Name())
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
	}
	return "unknown"
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
