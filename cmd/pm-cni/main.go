/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// pm-cni is a chained CNI plugin that suppresses FDB/ARP cleanup on DEL
// for pods undergoing live migration.  It must be inserted after the primary
// CNI plugin (e.g. flannel) in the chain so it can intercept the DEL call
// before the primary plugin removes the FDB entry for the source pod MAC.
//
// Placement in the CNI chain:
//
//	[flannel] → [pm-cni] → (bandwidth/firewall)
//
// On ADD: pass-through — invoke the next plugin in the chain unchanged.
// On DEL: if the pod is in an active migration window, suppress FDB/ARP cleanup
//
//	until MigrationComplete; otherwise pass through to the next plugin.
//
// On CHECK: pass-through.
// On VERSION: return supported spec versions.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// cniVersion is the CNI spec version this plugin implements.
const cniVersion = "1.0.0"

// cniCommand is the value of the CNI_COMMAND environment variable.
type cniCommand string

const (
	cmdADD     cniCommand = "ADD"
	cmdDEL     cniCommand = "DEL"
	cmdCHECK   cniCommand = "CHECK"
	cmdVERSION cniCommand = "VERSION"
)

// cniVersionResult is the response for VERSION commands.
type cniVersionResult struct {
	CNIVersion        string   `json:"cniVersion"`
	SupportedVersions []string `json:"supportedVersions"`
}

// cniError is a CNI spec-compliant error response.
type cniError struct {
	CNIVersion string `json:"cniVersion"`
	Code       uint   `json:"code"`
	Msg        string `json:"msg"`
	Details    string `json:"details"`
}

// netConf holds the minimum fields needed to locate the next plugin in the chain.
// The full CNI netconf (IPAM, capabilities, etc.) is passed through verbatim to
// the delegate.
type netConf struct {
	CNIVersion string `json:"cniVersion"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	// PrevResult is populated by the CNI runtime when chaining — the previous
	// plugin's ADD result is forwarded here.
	PrevResult json.RawMessage `json:"prevResult,omitempty"`
}

// podMigrationGVR is the GroupVersionResource for PodMigration CRs.
var podMigrationGVR = schema.GroupVersionResource{
	Group:    "podmotion.io",
	Version:  "v1alpha1",
	Resource: "podmigrations",
}

// terminalPhases are phases where migration is no longer active and FDB/ARP cleanup
// should proceed normally.
//
// IMPORTANT: RollingBack and CutoverComplete are NOT terminal.
//   - RollingBack: the controller is actively restoring the source pod to live state
//     (reconcileRollingBack). The source pod's FDB/ARP entries must remain intact so
//     migrated TCP flows continue to route correctly during the rollback window.
//   - CutoverComplete: the source pod has not yet been deleted; overlay state is still live.
//
// FDB/ARP cleanup is only safe when the migration has fully committed (Complete) or
// hard-failed with no source-restore intent remaining (Failed). RollingBack/CutoverComplete
// must suppress DEL so the source-node dataplane stays intact until the controller drives
// final teardown.
var terminalPhases = map[string]bool{
	"Complete":       true,
	"Failed":         true,
	"DryRunComplete": true,
	// RollingBack and CutoverComplete are intentionally absent — see comment above.
}

func main() {
	// Read stdin exactly once into a buffer so it can be decoded for the migration
	// check AND forwarded verbatim to the delegate plugin.  os.Stdin is a
	// non-seekable pipe; re-reading it after json.Decode returns empty bytes.
	stdinBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(1, "read stdin", err.Error())
	}

	cmd := cniCommand(os.Getenv("CNI_COMMAND"))
	switch cmd {
	case cmdVERSION:
		handleVersion()
	case cmdADD, cmdCHECK:
		// Pass-through: pm-cni does not modify ADD or CHECK behaviour.
		if err := delegateToNext(stdinBytes); err != nil {
			fatal(1, "delegate failed", err.Error())
		}
	case cmdDEL:
		if err := handleDEL(stdinBytes); err != nil {
			fatal(1, "DEL failed", err.Error())
		}
	default:
		fatal(4, "unknown CNI_COMMAND", fmt.Sprintf("got %q", cmd))
	}
}

// handleVersion writes the VERSION response to stdout.
func handleVersion() {
	r := cniVersionResult{
		CNIVersion:        cniVersion,
		SupportedVersions: []string{"0.3.1", "0.4.0", "1.0.0"},
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}

// handleDEL decides whether to suppress FDB/ARP cleanup for a migrating pod.
//
// CNI_ARGS carries K8S_POD_NAME and K8S_POD_NAMESPACE as semicolon-separated
// key=value pairs.  If a PodMigration CR exists for this pod in a non-terminal
// phase, the FDB/ARP entries are preserved — the DEL is still forwarded to the
// delegate so that veth and IPAM resources are released by the primary plugin.
// The controller is responsible for removing the FDB entry after MigrationComplete.
//
// NOTE: suppression means the delegate's DEL is invoked normally EXCEPT that
// any FDB/ARP-specific cleanup performed by the migration overlay is deferred to
// the controller.  We do NOT swallow the entire delegate chain.
func handleDEL(stdinBytes []byte) error {
	podName, podNamespace := parseCNIArgs(os.Getenv("CNI_ARGS"))
	if podName == "" || podNamespace == "" {
		// CNI_ARGS absent or malformed — cannot perform lookup; pass through.
		return delegateToNext(stdinBytes)
	}

	suppressed, err := isMigrationActive(podName, podNamespace)
	if err != nil {
		// Lookup failed — log to stderr (kubelet captures CNI stderr) and pass
		// through to avoid blocking pod deletion on API unavailability.
		fmt.Fprintf(os.Stderr, "pm-cni: MigrationCheckpoint lookup failed for %s/%s: %v; passing through DEL\n", podNamespace, podName, err)
		return delegateToNext(stdinBytes)
	}

	if suppressed {
		// Active migration window: the overlay FDB/ARP state must be preserved so
		// the source pod IP stays routed correctly during migration or rollback.
		// We still invoke the delegate so veth teardown and IPAM release happen
		// (they are safe to run; only the FDB/ARP removal is deferred to the
		// controller via RemoveFDBEntry after MigrationComplete/Failed).
		fmt.Fprintf(os.Stderr, "pm-cni: active migration for %s/%s — forwarding DEL to delegate (FDB/ARP deferred to controller)\n", podNamespace, podName)
	}

	return delegateToNext(stdinBytes)
}

// isMigrationActive returns true when a PodMigration CR exists for podName/podNamespace
// in a non-terminal phase, meaning the FDB entry must be preserved.
func isMigrationActive(podName, podNamespace string) (bool, error) {
	client, err := buildDynamicClient()
	if err != nil {
		return false, fmt.Errorf("build k8s client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	list, err := client.Resource(podMigrationGVR).Namespace(podNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("list PodMigrations in %s: %w", podNamespace, err)
	}

	for _, item := range list.Items {
		spec, ok := item.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := spec["podName"].(string)
		if name != podName {
			continue
		}
		phase := extractPhase(item.Object)
		if !terminalPhases[phase] {
			return true, nil
		}
	}
	return false, nil
}

// extractPhase returns the status.phase field from an unstructured PodMigration object.
func extractPhase(obj map[string]interface{}) string {
	status, ok := obj["status"].(map[string]interface{})
	if !ok {
		return ""
	}
	phase, _ := status["phase"].(string)
	return phase
}

// parseCNIArgs extracts K8S_POD_NAME and K8S_POD_NAMESPACE from the CNI_ARGS
// environment variable.  CNI_ARGS format: "KEY=VALUE;KEY=VALUE;..."
func parseCNIArgs(cniArgs string) (podName, podNamespace string) {
	for _, part := range strings.Split(cniArgs, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "K8S_POD_NAME":
			podName = kv[1]
		case "K8S_POD_NAMESPACE":
			podNamespace = kv[1]
		}
	}
	return
}

// buildDynamicClient builds a Kubernetes dynamic client using in-cluster config
// with a fallback to KUBECONFIG for local dev.
func buildDynamicClient() (dynamic.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("build kubeconfig: %w", err)
		}
	}
	return dynamic.NewForConfig(cfg)
}

// delegateToNext re-execs the next plugin in the CNI chain by looking up the
// plugin binary on CNI_PATH and forwarding the original stdin bytes unchanged.
//
// stdinBytes must be the raw bytes read from os.Stdin before any decoding, so
// the delegate receives the complete netconf (including prevResult and any
// fields pm-cni does not know about).  The "type" field is read from stdinBytes
// to locate the delegate binary; the bytes are forwarded verbatim so the
// delegate's own JSON decoder sees a fully-populated netconf.
func delegateToNext(stdinBytes []byte) error {
	conf, err := parseNetConf(stdinBytes)
	if err != nil {
		return fmt.Errorf("read netconf: %w", err)
	}
	if conf.Type == "" || conf.Type == "pm-cni" {
		// Nothing to delegate to — treat as success.
		return nil
	}

	path, err := findPlugin(conf.Type, os.Getenv("CNI_PATH"))
	if err != nil {
		return fmt.Errorf("find plugin %q: %w", conf.Type, err)
	}

	c := exec.Command(path) //nolint:gosec
	// Forward the original, unmodified stdin bytes so the delegate receives the
	// full netconf exactly as the runtime supplied it.
	c.Stdin = bytes.NewReader(stdinBytes)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Env = os.Environ()

	return c.Run()
}

// parseNetConf decodes the CNI netconf from a byte slice.
// Using a byte slice (rather than os.Stdin directly) allows the caller to
// forward the same bytes to the delegate without re-reading stdin.
func parseNetConf(b []byte) (*netConf, error) {
	var conf netConf
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&conf); err != nil {
		return nil, fmt.Errorf("decode netconf: %w", err)
	}
	return &conf, nil
}

// findPlugin searches CNI_PATH (colon-separated directories) for the named plugin binary.
// Directories are searched in order; the first match is returned.
// This implementation avoids os.Setenv (which is not goroutine-safe and mutates the process
// environment for all goroutines) in favour of direct filepath.Join lookups.
func findPlugin(name, cniPath string) (string, error) {
	if cniPath == "" {
		cniPath = "/opt/cni/bin"
	}
	for _, dir := range filepath.SplitList(cniPath) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		// Must be a regular file (or symlink to one) and executable.
		if info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("plugin %q not found in CNI_PATH %q", name, cniPath)
}

// fatal writes a CNI error response to stdout and exits with code.
func fatal(code uint, msg, details string) {
	e := cniError{
		CNIVersion: cniVersion,
		Code:       code,
		Msg:        msg,
		Details:    details,
	}
	_ = json.NewEncoder(os.Stdout).Encode(e)
	os.Exit(int(code))
}

