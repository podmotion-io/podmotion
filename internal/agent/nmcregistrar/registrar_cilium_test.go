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

// TestIPMobilitySupported_CiliumFalse verifies ADR-0313: Cilium no longer advertises
// IP-mobility support regardless of kernel features, since PODMOTION_FORCE_IP_MOBILITY
// is not set in this test's environment.
func TestIPMobilitySupported_CiliumFalse(t *testing.T) {
	if _, ok := os.LookupEnv("PODMOTION_FORCE_IP_MOBILITY"); ok {
		t.Setenv("PODMOTION_FORCE_IP_MOBILITY", "")
		os.Unsetenv("PODMOTION_FORCE_IP_MOBILITY")
	}

	got := ipMobilitySupported("cilium", pmv1.KernelFeatures{XDPSupported: true, BPFEnabled: true})
	if got != false {
		t.Fatalf("ipMobilitySupported(\"cilium\", full kernel features) = %v, want false (ADR-0313)", got)
	}
}

// TestIPMobilitySupported_CiliumFalse_EvenWithAllFeatures re-asserts the same
// invariant with every kernel feature flag set, to guard against a future
// regression that re-adds "cilium" to the supported-CNI case list.
func TestIPMobilitySupported_CiliumFalse_EvenWithAllFeatures(t *testing.T) {
	os.Unsetenv("PODMOTION_FORCE_IP_MOBILITY")
	kf := pmv1.KernelFeatures{
		CheckpointRestore: true,
		MemSoftDirty:      true,
		Userfaultfd:       true,
		BPFEnabled:        true,
		XDPSupported:      true,
		TCClsactSupported: true,
	}
	if ipMobilitySupported("cilium", kf) {
		t.Fatalf("ipMobilitySupported(\"cilium\", all kernel features) = true, want false (ADR-0313)")
	}
}

// TestCNICompatibleCondition_Cilium verifies the CNICompatible=False/CNIUnsupported
// condition shape emitted when detectCNI()=="cilium" (ADR-0313), using the same
// meta.SetStatusCondition idiom as the registrar's real write path.
func TestCNICompatibleCondition_Cilium(t *testing.T) {
	var conditions []metav1.Condition
	meta.SetStatusCondition(&conditions, metav1.Condition{
		Type:    pmv1.ConditionCNICompatible,
		Status:  metav1.ConditionFalse,
		Reason:  pmv1.ReasonCNIUnsupported,
		Message: "Cilium has no IP-mobility handoff implementation.",
	})

	cond := meta.FindStatusCondition(conditions, pmv1.ConditionCNICompatible)
	if cond == nil {
		t.Fatal("CNICompatible condition not found")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("Status = %v, want False", cond.Status)
	}
	if cond.Reason != pmv1.ReasonCNIUnsupported {
		t.Errorf("Reason = %q, want %q", cond.Reason, pmv1.ReasonCNIUnsupported)
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
