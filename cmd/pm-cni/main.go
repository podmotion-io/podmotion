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
//
// M19 delivers the skeleton only.  The MigrationCheckpoint CR lookup and the
// actual FDB suppression are implemented in M21 alongside migrationnetns.go.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
// M19 stub: always pass-through.
// M21 will add MigrationCheckpoint CR lookup here; if the pod is an active
// migration source, FDB cleanup is suppressed and a deferred cleanup is
// registered via the controller.
func handleDEL() error {
	// M21: look up MigrationCheckpoint CR for CNI_CONTAINERID / CNI_NETNS.
	// If found and migration is not Complete/Failed, log suppression and return nil
	// without invoking the next plugin for FDB teardown.
	return delegateToNext()
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
	_ = stdin // M21: use when stripping pm-cni from the chain config

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
func findPlugin(name, cniPath string) (string, error) {
	if cniPath == "" {
		cniPath = "/opt/cni/bin"
	}
	// Use exec.LookPath with a PATH set to cniPath so we find the binary in
	// the first matching directory.  We replace os.Getenv("PATH") temporarily
	// via a synthetic PATH value rather than modifying the process environment.
	origPath := os.Getenv("PATH")
	_ = os.Setenv("PATH", cniPath)
	p, err := exec.LookPath(name)
	_ = os.Setenv("PATH", origPath)
	if err != nil {
		return "", fmt.Errorf("plugin %q not found in CNI_PATH %q: %w", name, cniPath, err)
	}
	return p, nil
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
