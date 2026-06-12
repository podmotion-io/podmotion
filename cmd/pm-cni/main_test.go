/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"testing"
)

func TestParseCNIArgs(t *testing.T) {
	tests := []struct {
		name              string
		cniArgs           string
		wantPodName       string
		wantPodNamespace  string
	}{
		{
			name:             "standard k8s args",
			cniArgs:          "K8S_POD_NAMESPACE=default;K8S_POD_NAME=my-pod;K8S_POD_INFRA_CONTAINER_ID=abc123",
			wantPodName:      "my-pod",
			wantPodNamespace: "default",
		},
		{
			name:             "args with spaces around semicolons",
			cniArgs:          "K8S_POD_NAMESPACE=kube-system ; K8S_POD_NAME=coredns-abc",
			wantPodName:      "coredns-abc",
			wantPodNamespace: "kube-system",
		},
		{
			name:             "empty args",
			cniArgs:          "",
			wantPodName:      "",
			wantPodNamespace: "",
		},
		{
			name:             "missing pod name",
			cniArgs:          "K8S_POD_NAMESPACE=default",
			wantPodName:      "",
			wantPodNamespace: "default",
		},
		{
			name:             "value contains equals sign",
			cniArgs:          "K8S_POD_NAME=pod=with=equals;K8S_POD_NAMESPACE=ns",
			wantPodName:      "pod=with=equals",
			wantPodNamespace: "ns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotNS := parseCNIArgs(tt.cniArgs)
			if gotName != tt.wantPodName {
				t.Errorf("podName = %q, want %q", gotName, tt.wantPodName)
			}
			if gotNS != tt.wantPodNamespace {
				t.Errorf("podNamespace = %q, want %q", gotNS, tt.wantPodNamespace)
			}
		})
	}
}

func TestExtractPhase(t *testing.T) {
	tests := []struct {
		name      string
		obj       map[string]interface{}
		wantPhase string
	}{
		{
			name: "active migration",
			obj: map[string]interface{}{
				"status": map[string]interface{}{
					"phase": "ZeroWindowArm",
				},
			},
			wantPhase: "ZeroWindowArm",
		},
		{
			name: "complete migration",
			obj: map[string]interface{}{
				"status": map[string]interface{}{
					"phase": "Complete",
				},
			},
			wantPhase: "Complete",
		},
		{
			name:      "missing status",
			obj:       map[string]interface{}{},
			wantPhase: "",
		},
		{
			name: "missing phase",
			obj: map[string]interface{}{
				"status": map[string]interface{}{},
			},
			wantPhase: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPhase(tt.obj)
			if got != tt.wantPhase {
				t.Errorf("phase = %q, want %q", got, tt.wantPhase)
			}
		})
	}
}

func TestTerminalPhases(t *testing.T) {
	terminal := []string{"Complete", "Failed", "RollingBack", "DryRunComplete", "CutoverComplete"}
	active := []string{"Pending", "SocketInventory", "Validating", "DestinationPrewarm",
		"PreCopyMemory", "ZeroWindowArm", "FinalFreezeStateCapture",
		"OverlayHandoff", "RestoreSocketReattach", "DisengageHold",
		"TCPVerifying", "ServiceVerifying"}

	for _, phase := range terminal {
		if !terminalPhases[phase] {
			t.Errorf("phase %q should be terminal but is not in terminalPhases map", phase)
		}
	}

	for _, phase := range active {
		if terminalPhases[phase] {
			t.Errorf("phase %q is active but was incorrectly classified as terminal", phase)
		}
	}
}
