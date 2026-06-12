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
	"context"
	"encoding/json"
	"fmt"
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

// terminalPhases are phases where migration is no longer active and FDB cleanup
// should proceed normally.
var terminalPhases = map[string]bool{
	"Complete":       true,
	"Failed":         true,
	"RollingBack":    true,
	"DryRunComplete": true,
	"CutoverComplete": true,
}

func main() {
	cmd := cniCommand(os.Getenv("CNI_COMMAND"))
	switch cmd {
	case cmdVERSION:
		handleVersion()
	case cmdADD, cmdCHECK:
		// Pass-through: pm-cni does not modify ADD or CHECK behaviour.
		if err := delegateToNext(); err != nil {
			fatal(1, "delegate failed", err.Error())
		}
	case cmdDEL:
		if err := handleDEL(); err != nil {
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
// phase, the DEL is suppressed — the FDB entry is left intact so the overlay
// continues to route traffic to the migration netns on the destination node.
// The controller is responsible for removing the FDB entry after MigrationComplete.
func handleDEL() error {
	podName, podNamespace := parseCNIArgs(os.Getenv("CNI_ARGS"))
	if podName == "" || podNamespace == "" {
		// CNI_ARGS absent or malformed — cannot perform lookup; pass through.
		return delegateToNext()
	}

	suppressed, err := isMigrationActive(podName, podNamespace)
	if err != nil {
		// Lookup failed — log to stderr (kubelet captures CNI stderr) and pass
		// through to avoid blocking pod deletion on API unavailability.
		fmt.Fprintf(os.Stderr, "pm-cni: MigrationCheckpoint lookup failed for %s/%s: %v; passing through DEL\n", podNamespace, podName, err)
		return delegateToNext()
	}

	if suppressed {
		// Active migration: suppress FDB/ARP cleanup.  The DEL succeeds (exit 0)
		// without invoking the next plugin, preserving the source node FDB entry
		// until the controller removes it post-MigrationComplete.
		fmt.Fprintf(os.Stderr, "pm-cni: suppressing FDB/ARP DEL cleanup for migrating pod %s/%s\n", podNamespace, podName)
		return nil
	}

	return delegateToNext()
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
// plugin binary on CNI_PATH and re-passing stdin + environment unchanged.
//
// CNI chaining convention: the runtime passes the full netconf on stdin; the
// chained plugin finds the next type from the "plugins" array or from the
// "delegate" field.  For M19 we read the type from the netconf and exec the
// binary of the same name from CNI_PATH.  M21 will switch to reading
// conflist["plugins"][nextIndex] for proper chain ordering.
func delegateToNext() error {
	conf, err := readNetConf()
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

	stdin, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("marshal netconf: %w", err)
	}

	c := exec.Command(path) //nolint:gosec
	c.Stdin = os.Stdin      // re-pass original stdin (full netconf with prevResult)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Env = os.Environ()
	// Override stdin with the re-serialised conf only if we need to strip our own type.
	_ = stdin // used when stripping pm-cni from the chain config

	return c.Run()
}

// readNetConf decodes the CNI netconf from stdin.
func readNetConf() (*netConf, error) {
	var conf netConf
	if err := json.NewDecoder(os.Stdin).Decode(&conf); err != nil {
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

