/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package nmcregistrar

import (
	"context"
	"os"
	"testing"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ADR-0367: NMC.Spec.NetworkCapability.LiveMigrationEligible must be populated from the
// exact same computed boolean as IPMobilitySupported, at the single existing write site
// (nmcregistrar.Register()) — never a second, independently-derived detection path, and
// never left at Go's false zero-value regardless of CNI.

// registerAndFetch runs a full Register() against a fake client (exercising the real SSA
// write path, not just the ipMobilitySupported helper in isolation) and returns the
// resulting NMC's NetworkCapability, driving detectCNI() via PODMOTION_CNI_OVERRIDE so the
// test does not depend on whatever CNI conf files happen to exist on the machine running
// the test.
func registerAndFetch(t *testing.T, cniOverride string) pmv1.NetworkCapability {
	t.Helper()

	// Full kernel-feature set so the CNI branch inside ipMobilitySupported is what's under
	// test, not the XDP/BPF short-circuit.
	prevXDP, hadXDP := os.LookupEnv("PODMOTION_FORCE_IP_MOBILITY")
	os.Unsetenv("PODMOTION_FORCE_IP_MOBILITY") // must be genuinely absent, not "" (empty still short-circuits ipMobilitySupported)
	t.Cleanup(func() {
		if hadXDP {
			os.Setenv("PODMOTION_FORCE_IP_MOBILITY", prevXDP)
		} else {
			os.Unsetenv("PODMOTION_FORCE_IP_MOBILITY")
		}
	})

	t.Setenv("PODMOTION_CNI_OVERRIDE", cniOverride)

	s := newTestScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&pmv1.NodeMigrationCapacity{}).
		Build()

	r := &Registrar{client: c, nodeName: "test-node-" + cniOverride, agentPort: "9090"}
	if err := r.Register(context.Background()); err != nil {
		t.Fatalf("Register(%q) returned error: %v", cniOverride, err)
	}

	got := &pmv1.NodeMigrationCapacity{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: r.nodeName}, got); err != nil {
		t.Fatalf("fetching NMC after Register(%q): %v", cniOverride, err)
	}
	return got.Spec.NetworkCapability
}

// TestRegister_LiveMigrationEligible_MirrorsIPMobilitySupported is the structural,
// drift-proof assertion Decision 1 exists to guarantee: for every CNI, the two fields
// must always agree, because after this ADR they are written from the same local
// variable in the same struct literal.
func TestRegister_LiveMigrationEligible_MirrorsIPMobilitySupported(t *testing.T) {
	for _, cni := range []string{"cilium", "flannel", "calico", "ovn-kubernetes", "kindnet", "some-unknown-cni"} {
		t.Run(cni, func(t *testing.T) {
			nc := registerAndFetch(t, cni)
			if nc.LiveMigrationEligible != nc.IPMobilitySupported {
				t.Fatalf("CNI %q: LiveMigrationEligible=%v, IPMobilitySupported=%v — must match (ADR-0367 single-source-of-truth)",
					cni, nc.LiveMigrationEligible, nc.IPMobilitySupported)
			}
		})
	}
}

// TestRegister_LiveMigrationEligible_CiliumTrue: Cilium's real ipcache/CiliumEndpoint
// handoff (ADR-0318) means Cilium nodes must advertise eligible=true — the exact bug
// this ADR fixes (previously always false regardless of CNI).
func TestRegister_LiveMigrationEligible_CiliumTrue(t *testing.T) {
	nc := registerAndFetch(t, "cilium")
	if !nc.LiveMigrationEligible {
		t.Fatalf("cilium: LiveMigrationEligible = false, want true (ADR-0318 real ipcache handoff)")
	}
	if !nc.IPMobilitySupported {
		t.Fatalf("cilium: IPMobilitySupported = false, want true")
	}
}

// TestRegister_LiveMigrationEligible_FlannelFalse: on a test host with no live VXLAN FDB
// device, DiscoverFdbInterface() finds nothing, so ipMobilitySupported's Flannel case
// correctly returns false (cold-migration-only) — the safe, conservative default per
// Chad's zero-tech-debt pillar (ambiguous/no-probe-hit CNI state must never default to
// true).
func TestRegister_LiveMigrationEligible_FlannelFalse(t *testing.T) {
	nc := registerAndFetch(t, "flannel")
	if nc.LiveMigrationEligible {
		t.Fatalf("flannel (no FDB device on test host): LiveMigrationEligible = true, want false")
	}
	if nc.IPMobilitySupported {
		t.Fatalf("flannel (no FDB device on test host): IPMobilitySupported = true, want false")
	}
}

// TestRegister_LiveMigrationEligible_CalicoTrue: Calico has a real, wired IPHandoffStrategy
// (ADR Finding 3: BGP/native routing, IPAM-pin pattern) even though its dataplane-readiness
// verification is weaker than Cilium's — per ADR-0367 Finding 1/3 this field describes
// node-level IP-mobility capability, not gate-wiring completeness, so eligible=true is
// correct here.
func TestRegister_LiveMigrationEligible_CalicoTrue(t *testing.T) {
	nc := registerAndFetch(t, "calico")
	if !nc.LiveMigrationEligible {
		t.Fatalf("calico: LiveMigrationEligible = false, want true")
	}
}

// TestRegister_LiveMigrationEligible_OVNKubernetesTrue: OVN-Kubernetes has a real
// IPAMClaim reserve/release mechanism (ADR Finding 3) even though it is not yet wired to
// the stronger authoritative dataplane-reachability gate Cilium/Calico received — same
// node-level-capability reasoning as Calico above.
func TestRegister_LiveMigrationEligible_OVNKubernetesTrue(t *testing.T) {
	nc := registerAndFetch(t, "ovn-kubernetes")
	if !nc.LiveMigrationEligible {
		t.Fatalf("ovn-kubernetes: LiveMigrationEligible = false, want true")
	}
}

// TestRegister_LiveMigrationEligible_UnknownCNIDefaultsFalse: an unrecognized/ambiguous
// CNI (the ARPHandoff/"default" case in ipMobilitySupported) must default to false, never
// true — the standing zero-tech-debt/no-fail-open rule: genuine ambiguity is conservative,
// not optimistic.
func TestRegister_LiveMigrationEligible_UnknownCNIDefaultsFalse(t *testing.T) {
	nc := registerAndFetch(t, "some-unknown-cni")
	if nc.LiveMigrationEligible {
		t.Fatalf("unknown CNI: LiveMigrationEligible = true, want false (safe default on ambiguous CNI)")
	}
	if nc.IPMobilitySupported {
		t.Fatalf("unknown CNI: IPMobilitySupported = true, want false (safe default on ambiguous CNI)")
	}
}

// TestRegister_LiveMigrationEligible_KindnetFalse: kindnet is host-routed with no VXLAN
// overlay (ADR-0192 B2) — no IP-mobility mechanism exists, so eligible must be false.
func TestRegister_LiveMigrationEligible_KindnetFalse(t *testing.T) {
	nc := registerAndFetch(t, "kindnet")
	if nc.LiveMigrationEligible {
		t.Fatalf("kindnet: LiveMigrationEligible = true, want false")
	}
}
