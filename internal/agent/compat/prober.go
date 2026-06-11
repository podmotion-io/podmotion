// Package compat probes node capabilities at agent startup and periodically.
// Results populate NodeMigrationCapacity.spec fields so the scheduler plugin
// and admission webhook can read them without node-local API calls.
package compat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	migrationv1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// GPUProbeResult holds the result of the GPU capability probe.
type GPUProbeResult struct {
	// Available is true when nvidia-smi is on PATH.
	Available bool
	// DriverVersion is the NVIDIA driver version string (e.g. "530.30.02").
	DriverVersion string
	// SupportedCheckpoint is true when the driver version meets the CUDA checkpoint minimum (525+).
	SupportedCheckpoint bool
}

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

	result.Spec.CRIUVersion = probeCRIUVersion()
	result.Spec.NRIEnabled = probeNRIEnabled()

	cniPlugin, ipMobility, ipMobilityMode := ProbeNetworkCapability()
	result.Spec.NetworkCapability.CNIPlugin = cniPlugin
	result.Spec.NetworkCapability.IPMobilitySupported = ipMobility
	result.Spec.NetworkCapability.IPMobilityMode = ipMobilityMode

	gpu := ProbeGPU()
	result.Spec.GPUMigrationSupported = gpu.SupportedCheckpoint
	result.Spec.GPUDriverVersion = gpu.DriverVersion

	if srcDstOk, err := ProbeAWSSourceDestCheck(ctx); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("AWS src/dst check probe: %v", err))
	} else if !srcDstOk {
		result.Errors = append(result.Errors, "AWS source/destination check is ENABLED — IP mobility requires it to be disabled")
	}

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

// ProbeGPU detects NVIDIA GPU availability and driver version via nvidia-smi.
// Returns a zero-value result (Available=false) when no GPU hardware is present —
// this is not an error, just an absent capability.
func ProbeGPU() GPUProbeResult {
	const minMajor = 525

	out, err := exec.Command("nvidia-smi",
		"--query-gpu=driver_version",
		"--format=csv,noheader",
	).Output()
	if err != nil {
		return GPUProbeResult{}
	}
	dv := strings.TrimSpace(string(out))
	if dv == "" {
		return GPUProbeResult{Available: true}
	}

	parts := strings.SplitN(dv, ".", 2)
	var major int
	if _, err := fmt.Sscanf(parts[0], "%d", &major); err != nil {
		return GPUProbeResult{Available: true, DriverVersion: dv}
	}

	return GPUProbeResult{
		Available:           true,
		DriverVersion:       dv,
		SupportedCheckpoint: major >= minMajor,
	}
}

func probeNRIEnabled() bool {
	info, err := os.Stat("/var/run/nri/nri.sock")
	return err == nil && (info.Mode()&os.ModeSocket != 0)
}

// NRIPreflightResult holds the outcome of the NRI readiness check.
type NRIPreflightResult struct {
	// SocketPresent is true when /var/run/nri/nri.sock exists and is a socket.
	SocketPresent bool
	// ContainerdVersion is the detected containerd version string (e.g. "2.0.1").
	ContainerdVersion string
	// ContainerdMeetsMinimum is true when containerd >= 2.0 (NRI plugin API stable).
	ContainerdMeetsMinimum bool
	// Ready is true when both SocketPresent and ContainerdMeetsMinimum are true.
	Ready bool
	// Reason is populated when Ready=false.
	Reason string
}

// ProbeNRIPreflight checks whether the NRI plugin API is available and usable.
// The NRI StartContainer hook (which CRIU restore uses) requires containerd >= 2.0.
// Nodes running older containerd cannot use NRI-based restore; they must use the
// legacy joinNsRestore path.
func ProbeNRIPreflight() NRIPreflightResult {
	result := NRIPreflightResult{}

	result.SocketPresent = probeNRIEnabled()
	if !result.SocketPresent {
		result.Reason = "NRI socket /var/run/nri/nri.sock not found — containerd NRI not enabled"
		return result
	}

	// Probe containerd version via `containerd --version`.
	out, err := exec.Command("containerd", "--version").Output()
	if err != nil {
		result.Reason = fmt.Sprintf("containerd --version failed: %v", err)
		return result
	}
	// Output: "containerd containerd.io 2.0.1 ..."
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) >= 3 {
		result.ContainerdVersion = fields[2]
	} else if len(fields) >= 2 {
		result.ContainerdVersion = fields[1]
	}

	// Check major version >= 2.
	major := 0
	if result.ContainerdVersion != "" {
		fmt.Sscanf(strings.SplitN(result.ContainerdVersion, ".", 2)[0], "%d", &major)
	}
	result.ContainerdMeetsMinimum = major >= 2
	if !result.ContainerdMeetsMinimum {
		result.Reason = fmt.Sprintf("containerd %s < 2.0 — NRI plugin API requires containerd >= 2.0 (StartContainer hook unavailable)", result.ContainerdVersion)
		return result
	}

	result.Ready = true
	return result
}

// ProbeNetworkCapability detects the primary CNI plugin from /etc/cni/net.d/*.conf
// or *.conflist. Returns (cniPlugin, ipMobilitySupported, ipMobilityMode).
//
// The CNI conf directory is the canonical source of truth for which plugin is active.
// We read only the first lexically-sorted file (active CNI convention).
func ProbeNetworkCapability() (cniPlugin string, ipMobilitySupported bool, ipMobilityMode string) {
	const cniDir = "/etc/cni/net.d"
	matches, err := filepath.Glob(filepath.Join(cniDir, "*.conf"))
	if err == nil && len(matches) == 0 {
		// Also check conflist format
		matches2, _ := filepath.Glob(filepath.Join(cniDir, "*.conflist"))
		matches = append(matches, matches2...)
	}
	if len(matches) == 0 {
		return "", false, ""
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		return "", false, ""
	}

	var conf struct {
		Type    string `json:"type"`
		Plugins []struct {
			Type string `json:"type"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		return "", false, ""
	}

	// Prefer top-level "type"; fall back to first plugin entry (conflist format).
	detected := conf.Type
	if detected == "" && len(conf.Plugins) > 0 {
		detected = conf.Plugins[0].Type
	}

	lower := strings.ToLower(detected)
	switch {
	case strings.Contains(lower, "ovn"):
		return detected, true, "IPAMClaim"
	case strings.Contains(lower, "calico"):
		return detected, true, "IPAMAnnotation"
	case strings.Contains(lower, "cilium"):
		return detected, true, "IPAMAnnotation"
	case strings.Contains(lower, "flannel"):
		// Flannel has no IP mobility support — cold migration (NetworkContinuity=false) only.
		return detected, false, "ColdOnly"
	default:
		return detected, false, ""
	}
}

// imdsClient is a package-level HTTP client for IMDS calls.
// Timeout of 2s avoids blocking the probe loop on non-AWS nodes.
var imdsClient = &http.Client{Timeout: 2 * time.Second}

// ProbeAWSSourceDestCheck queries IMDSv2 to determine whether the EC2 instance's
// source/destination check is disabled. IP mobility requires it to be disabled so
// the instance can forward packets destined for the migrated pod IP.
//
// Returns (true, nil) if src/dst check is disabled (OK for IP mobility).
// Returns (false, nil) if enabled (migration will fail).
// Returns (false, err) if IMDS is unreachable (non-AWS node).
func ProbeAWSSourceDestCheck(ctx context.Context) (bool, error) {
	token, err := imdsToken(ctx)
	if err != nil {
		// Not an AWS instance or IMDS unreachable — not an error for non-AWS clusters.
		return true, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/latest/meta-data/network/interfaces/macs/", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)

	resp, err := imdsClient.Do(req)
	if err != nil {
		return true, nil // non-AWS: skip
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	macs := strings.Fields(strings.TrimSpace(string(body)))
	if len(macs) == 0 {
		return true, nil
	}
	// Check the first MAC's source/destination check field.
	mac := strings.TrimSuffix(macs[0], "/")
	url := fmt.Sprintf("http://169.254.169.254/latest/meta-data/network/interfaces/macs/%s/source-dest-check", mac)
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req2.Header.Set("X-aws-ec2-metadata-token", token)
	resp2, err := imdsClient.Do(req2)
	if err != nil {
		return false, err
	}
	defer resp2.Body.Close()
	val, _ := io.ReadAll(resp2.Body)
	// IMDS returns "true" or "false" as a plain string.
	disabled := strings.TrimSpace(string(val)) == "false"
	return disabled, nil
}

// imdsToken fetches an IMDSv2 session token using a PUT request.
func imdsToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		"http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := imdsClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	tok, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(tok)), nil
}
