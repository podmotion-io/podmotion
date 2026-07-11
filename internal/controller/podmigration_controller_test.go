/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	migrationv1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/traffic"
)

var _ = Describe("PodMigration Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		podmigration := &migrationv1alpha1.PodMigration{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind PodMigration")
			err := k8sClient.Get(ctx, typeNamespacedName, podmigration)
			if err != nil && errors.IsNotFound(err) {
				resource := &migrationv1alpha1.PodMigration{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					// TODO(user): Specify other spec details if needed.
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &migrationv1alpha1.PodMigration{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance PodMigration")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &PodMigrationReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})
})

// countingProbeVerifier is a traffic.Verifier that always succeeds (mirroring a wired,
// healthy service-path verifier in the live deployment) so the None reconcile path settles
// TrafficVerified=True cleanly. It records nothing about the cross-node ADR-0210 probe — that
// probe (StartReachabilityEcho / ProbeDataplaneReachability) is an AgentPool RPC, reachable
// ONLY from inside injectIPHandoff -> verifyDataplaneReachability. Under TCPPreservationMode=None
// injectIPHandoff is never called (podmigration_controller.go:3808), so the probe is
// structurally unreachable. The test proves that structurally by leaving AgentPool nil: any
// path that reached the probe would first hit injectIPHandoff's `AgentPool == nil` requeue
// (podmigration_controller.go:3513) and would NOT set IPHandoffInjected=True/reason=Skipped.
type countingProbeVerifier struct{ calls int }

func (v *countingProbeVerifier) Verify(_ context.Context, _ traffic.VerifyRequest) error {
	v.calls++
	return nil
}

// TestReconcileVerifying_NoneMode_SkipsCrossNodeProbe pins that TCPPreservationMode=None
// STRUCTURALLY bypasses the ADR-0210 cross-node preserved-IP reachability probe (the real live
// 2026-07-10 CrossNodeUnreachable stall), rather than passing a broken probe. It mirrors the
// exact live CR (SourcePodIP=10.244.1.78, src=pm-w1, dest=pm-w2). A future edit that re-gated
// None on injectIPHandoff / the cross-node probe would break this test: with AgentPool nil that
// path requeues at 3513 and never sets IPHandoffInjected=True/reason=Skipped.
func TestReconcileVerifying_NoneMode_SkipsCrossNodeProbe(t *testing.T) {
	scheme := adr0210Scheme(t)

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: "none-skip-crossnode", Namespace: "default"},
		Spec: pmv1.PodMigrationSpec{
			PodName:             "postgres-src",
			PodNamespace:        "default",
			SourcePodIP:         "10.244.1.78",
			TargetNodeName:      "pm-w2",
			TCPPreservationMode: pmv1.TCPPreservationModeNone,
		},
		Status: pmv1.PodMigrationStatus{
			Phase:               pmv1.MigrationPhaseVerifying,
			SourceNodeName:      "pm-w1",
			DestinationNodeName: "pm-w2",
			ReplacementPodName:  "postgres-src-m-abc",
			Conditions: []metav1.Condition{
				{Type: conditionRestored, Status: metav1.ConditionTrue, Reason: "Restored", LastTransitionTime: metav1.Now()},
				{Type: conditionDestinationVolumeReady, Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()

	verifier := &countingProbeVerifier{}
	// AgentPool is deliberately nil: the ADR-0210 echo/probe RPCs (StartReachabilityEcho /
	// ProbeDataplaneReachability) are AgentPool calls; a None path that never touches AgentPool
	// proves the probe is structurally unreachable, not merely passed-while-broken.
	r := &PodMigrationReconciler{Client: fakeClient, Scheme: scheme, TrafficVerifier: verifier}
	ctx := context.Background()

	if _, err := r.reconcileVerifying(ctx, pm); err != nil {
		t.Fatalf("reconcileVerifying under None returned error (must not requeue on the reachability path): %v", err)
	}

	// Re-read from the fake client so we assert on persisted status, not the in-memory copy.
	got := &pmv1.PodMigration{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name}, got); err != nil {
		t.Fatalf("get PodMigration: %v", err)
	}

	// (a) IPHandoffInjected=True with reason=Skipped — set ONLY by the None branch at
	// podmigration_controller.go:3808. If a future edit removed that branch, the reconcile would
	// fall into injectIPHandoff, hit the nil-AgentPool requeue at 3513, and leave this unset.
	ipCond := meta.FindStatusCondition(got.Status.Conditions, conditionIPHandoffInjected)
	if ipCond == nil || ipCond.Status != metav1.ConditionTrue {
		t.Fatalf("IPHandoffInjected must be True under None (proves injectIPHandoff/probe were structurally skipped); got %+v", ipCond)
	}
	if ipCond.Reason != "Skipped" {
		t.Fatalf("IPHandoffInjected reason must be Skipped under None; got %q", ipCond.Reason)
	}

	// (b) TrafficVerified=True — under None it is set without a faked cross-node self-probe
	// (ADR-0012 safety: source held until TrafficVerified=True; here it is the completed local
	// restore + service-path verifier, not the cross-node nonce round-trip).
	if !meta.IsStatusConditionTrue(got.Status.Conditions, conditionTrafficVerified) {
		t.Fatalf("TrafficVerified must be True under None; conditions=%+v", got.Status.Conditions)
	}

	// (c) The authoritative cross-node gate is NEVER set under None — it is declined, not asserted.
	if meta.FindStatusCondition(got.Status.Conditions, conditionDataplaneReachabilityVerified) != nil {
		t.Fatalf("DataplaneReachabilityVerified must NOT be set under None (probe declined, not run); it was set")
	}
}
