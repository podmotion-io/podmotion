/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package nmcregistrar

import (
	"os"
	"testing"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestIPMobilitySupported_CiliumTrue verifies ADR-0318: Cilium now advertises real
// IP-mobility support via the ipcache/CiliumEndpoint handoff mechanism, regardless of
// PODMOTION_FORCE_IP_MOBILITY (that env var is no longer required to force this path).
func TestIPMobilitySupported_CiliumTrue(t *testing.T) {
	if _, ok := os.LookupEnv("PODMOTION_FORCE_IP_MOBILITY"); ok {
		t.Setenv("PODMOTION_FORCE_IP_MOBILITY", "")
		os.Unsetenv("PODMOTION_FORCE_IP_MOBILITY")
	}

	got := ipMobilitySupported("cilium", pmv1.KernelFeatures{XDPSupported: true, BPFEnabled: true})
	if got != true {
		t.Fatalf("ipMobilitySupported(\"cilium\", full kernel features) = %v, want true (ADR-0318)", got)
	}
}

// TestIPMobilitySupported_CiliumTrue_EvenWithAllFeatures re-asserts the same
// invariant with every kernel feature flag set, to guard against a future
// regression that removes "cilium" from the supported-CNI case list.
func TestIPMobilitySupported_CiliumTrue_EvenWithAllFeatures(t *testing.T) {
	os.Unsetenv("PODMOTION_FORCE_IP_MOBILITY")
	kf := pmv1.KernelFeatures{
		CheckpointRestore: true,
		MemSoftDirty:      true,
		Userfaultfd:       true,
		BPFEnabled:        true,
		XDPSupported:      true,
		TCClsactSupported: true,
	}
	if !ipMobilitySupported("cilium", kf) {
		t.Fatalf("ipMobilitySupported(\"cilium\", all kernel features) = false, want true (ADR-0318)")
	}
}

// TestCNICompatibleCondition_Cilium verifies the CNICompatible=True/CNISupported
// condition shape emitted when detectCNI()=="cilium" (ADR-0318: real ipcache/
// CiliumEndpoint IP-mobility handoff implemented), using the same
// meta.SetStatusCondition idiom as the registrar's real write path.
func TestCNICompatibleCondition_Cilium(t *testing.T) {
	var conditions []metav1.Condition
	meta.SetStatusCondition(&conditions, metav1.Condition{
		Type:    pmv1.ConditionCNICompatible,
		Status:  metav1.ConditionTrue,
		Reason:  pmv1.ReasonCNISupported,
		Message: "CNI plugin \"cilium\" is supported by PodMotion's live-migration datapath.",
	})

	cond := meta.FindStatusCondition(conditions, pmv1.ConditionCNICompatible)
	if cond == nil {
		t.Fatal("CNICompatible condition not found")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("Status = %v, want True", cond.Status)
	}
	if cond.Reason != pmv1.ReasonCNISupported {
		t.Errorf("Reason = %q, want %q", cond.Reason, pmv1.ReasonCNISupported)
	}
}

// TestCNICompatibleCondition_NonCilium verifies the True/CNISupported shape for a
// supported CNI, exercising the else-branch of the registrar's condition write.
func TestCNICompatibleCondition_NonCilium(t *testing.T) {
	var conditions []metav1.Condition
	meta.SetStatusCondition(&conditions, metav1.Condition{
		Type:    pmv1.ConditionCNICompatible,
		Status:  metav1.ConditionTrue,
		Reason:  pmv1.ReasonCNISupported,
		Message: "CNI plugin \"calico\" is supported by PodMotion's live-migration datapath.",
	})

	cond := meta.FindStatusCondition(conditions, pmv1.ConditionCNICompatible)
	if cond == nil {
		t.Fatal("CNICompatible condition not found")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("Status = %v, want True", cond.Status)
	}
	if cond.Reason != pmv1.ReasonCNISupported {
		t.Errorf("Reason = %q, want %q", cond.Reason, pmv1.ReasonCNISupported)
	}
}
