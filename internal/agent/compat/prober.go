// Package compat probes node capabilities at agent startup and periodically.
// Results populate NodeMigrationCapacity.spec fields so the scheduler plugin
// and admission webhook can read them without node-local API calls.
package compat

import (
	"context"
	"os/exec"
	"strings"

	migrationv1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// ProbeResult contains all capability data for a single probe run.
type ProbeResult struct {
	Spec   migrationv1alpha1.NodeMigrationCapacitySpec
	Errors []string // non-fatal probe warnings
}

// Prober runs capability checks and returns a ProbeResult.
type Prober struct {
	NodeName string
}

// Run executes all capability probes. Non-fatal errors are collected in result.Errors.
// Fatal errors (e.g. CRIU absent, NRI not enabled) set result.Spec fields accordingly
// and do NOT return an error — the spec fields carry the failure information.
func (p *Prober) Run(ctx context.Context) (ProbeResult, error) {
	result := ProbeResult{}
	result.Spec.NodeName = p.NodeName

	// TODO(M1): probe CRIU version
	result.Spec.CRIUVersion = probeCRIUVersion()

	// TODO(M1): probe kernel features from /proc/config.gz or /boot/config-$(uname -r)
	// TODO(M1): probe NRI socket at /var/run/nri/nri.sock
	// TODO(M1): probe runc version
	// TODO(M1): probe CNI plugin from /etc/cni/net.d/
	// TODO(M1): probe XDP capability from kernel version
	// TODO(M1): probe storage capabilities (Longhorn API, Ceph RBD, pv-migrate)
	// TODO(M1): probe GPU (nvidia-smi, cuda-checkpoint binary)
	// TODO(M1): probe AWS IMDS for VPC/subnet/instance type

	result.Spec.NRIEnabled = probeNRIEnabled()

	return result, nil
}

func probeCRIUVersion() string {
	out, err := exec.Command("criu", "--version").Output()
	if err != nil {
		return ""
	}
	// Output: "Version: 4.2"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	return ""
}

func probeNRIEnabled() bool {
	// NRI socket presence indicates containerd has NRI enabled
	out, err := exec.Command("test", "-S", "/var/run/nri/nri.sock").Output()
	_ = out
	return err == nil
}
