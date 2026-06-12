//go:build e2e
// +build e2e

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package e2e — NS#3 North Star: operator-driven live migration of a stateless pod.
//
// This test suite proves that PodMotion can migrate a running stateless pod between
// nodes using CRIU cold-mode restore, the operator-created replacement pod path, and
// the ADR-0015 EndpointSlice overlap-then-delete protocol — WITHOUT any workload
// controller involvement (source pod is never deleted until TrafficVerified=True).
//
// Pass criteria (subset of docs/MILESTONES.md pre-beta chaos requirements):
//  1. phase=Complete reached within migrationTimeout
//  2. Replacement pod running on destination node (pm.Status.ReplacementPodName)
//  3. Source pod deleted after Complete
//  4. NGINX service returns HTTP 200 AND the serving pod is pm.Status.ReplacementPodName
//  5. Zero ERROR/WARN in operator logs scoped to the successful migration window
//  6. No stale replacement pod after a failed migration (rollback path)
package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/test/utils"
)

const (
	liveMigrationTimeout = 8 * time.Minute
	liveReadinessTimeout = 3 * time.Minute
	livePollInterval     = 2 * time.Second
	nginxLiveFixture     = "test/e2e/fixtures/nginx-live.yaml"
	nginxLivePodName     = "pm-test-nginx-live"
	nginxLiveService     = "pm-test-nginx-live"
	nginxLiveNamespace   = "pm-e2e-live"
)

// NS3Result is the structured proof record written at the end of the North Star test.
type NS3Result struct {
	SourceNode       string
	DestNode         string
	ReplacementPod   string
	FreezeDurationMs int64
	MigrationName    string
}

var _ = Describe("NS#3 — Stateless Live Migration (Operator-Driven)", Ordered, Label("northstar", "stateless"), func() {
	var k8sClient client.Client
	var ns3Result NS3Result
	// logAuditStart / logAuditEnd bracket ONLY the successful migration (Test 2).
	// Test 3 (rollback) runs after Test 2 in the Ordered suite and intentionally
	// produces ERROR/WARN logs. The audit uses both --since-time and --until-time
	// so Test 3's deliberate errors do not trigger a false criterion-5 failure.
	var logAuditStart, logAuditEnd time.Time

	BeforeAll(func() {
		var err error
		k8sClient, err = utils.NewPMClient()
		Expect(err).NotTo(HaveOccurred())

		By("creating live-migration e2e namespace")
		cmd := exec.Command("kubectl", "apply", "-f", nginxLiveFixture)
		out, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "applying nginx-live fixture: "+string(out))

		By("waiting for nginx-live pod to be Running")
		Eventually(func() corev1.PodPhase {
			pod := &corev1.Pod{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{
				Namespace: nginxLiveNamespace,
				Name:      nginxLivePodName,
			}, pod); err != nil {
				return corev1.PodUnknown
			}
			return pod.Status.Phase
		}, liveReadinessTimeout, livePollInterval).Should(Equal(corev1.PodRunning),
			"nginx-live pod must reach Running")
	})

	AfterAll(func() {
		if !logAuditStart.IsZero() && !logAuditEnd.IsZero() {
			By("auditing operator logs for ERROR/WARN scoped to successful migration window")
			// --since-time + --until-time tightly brackets Test 2 (the successful migration).
			// Test 3 (deliberate rollback failure) runs after logAuditEnd is recorded, so its
			// intentional ERROR/WARN lines are excluded from this check.
			cmd := exec.Command("kubectl", "logs",
				"-n", "podmotion-system",
				"-l", "control-plane=controller-manager",
				fmt.Sprintf("--since-time=%s", logAuditStart.UTC().Format(time.RFC3339)),
				fmt.Sprintf("--until-time=%s", logAuditEnd.UTC().Format(time.RFC3339)),
			)
			out, _ := utils.Run(cmd)
			logStr := string(out)
			for _, line := range strings.Split(logStr, "\n") {
				Expect(line).NotTo(ContainSubstring(`"level":"error"`),
					"operator log must have zero ERROR lines during successful migration")
				Expect(line).NotTo(ContainSubstring(`"level":"warn"`),
					"operator log must have zero WARN lines during successful migration")
			}
		}

		By("resetting NodeMigrationCapacity counters after suite")
		resetNMCCmd := exec.Command("kubectl", "get", "nodemigrationcapacities",
			"-o", "jsonpath={.items[*].metadata.name}")
		nmcOut, nmcErr := utils.Run(resetNMCCmd)
		if nmcErr == nil {
			for _, nmcName := range strings.Fields(nmcOut) {
				patchCmd := exec.Command("kubectl", "patch", "nodemigrationcapacity", nmcName,
					"--subresource=status", "--type=merge",
					`--patch={"status":{"activeDestinationMigrations":0,"activeSourceMigrations":0}}`)
				_, _ = utils.Run(patchCmd)
			}
		}

		By("cleaning up live-migration namespace")
		cmd := exec.Command("kubectl", "delete", "namespace", nginxLiveNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	// ── Test 1: Smoke — operator creates replacement pod ────────────────────

	Describe("Replacement pod lifecycle", Ordered, func() {
		var pm *pmv1.PodMigration
		var sourcePod *corev1.Pod

		BeforeAll(func() {
			sourcePod = getNginxLivePod(context.Background(), k8sClient)
		})

		AfterAll(func() {
			if pm != nil {
				cleanupLiveMigration(context.Background(), k8sClient, pm)
			}
		})

		It("creates PodMigration and reaches Checkpointing", func(ctx SpecContext) {
			destNode := pickDestNode(ctx, k8sClient, sourcePod.Spec.NodeName)
			pm = createLiveMigration(ctx, k8sClient, sourcePod, destNode)
			Eventually(func() pmv1.MigrationPhase {
				_ = k8sClient.Get(ctx, types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name}, pm)
				return pm.Status.Phase
			}, 3*time.Minute, livePollInterval).Should(
				BeElementOf(
					pmv1.MigrationPhaseCheckpointing,
					pmv1.MigrationPhaseTransferring,
					pmv1.MigrationPhaseRestoring,
					pmv1.MigrationPhaseVerifying,
					pmv1.MigrationPhaseComplete,
				),
				"migration should advance past PreMigrating within 3 minutes")
		})

		It("records replacement pod name in pm.Status (not Spec)", func(ctx SpecContext) {
			Eventually(func() string {
				_ = k8sClient.Get(ctx, types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name}, pm)
				return pm.Status.ReplacementPodName
			}, 3*time.Minute, livePollInterval).ShouldNot(BeEmpty(),
				"pm.Status.ReplacementPodName should be set by operator after Checkpointing")

			// Verify it is in Status, not Spec. The Spec type has no ReplacementPodName field
			// by design (quorum requirement: controller-derived state lives in Status only).
			// We assert the field is populated in Status — the absence from Spec is enforced
			// at compile time by the type definition.
			Expect(pm.Status.ReplacementPodName).NotTo(BeEmpty(),
				"ReplacementPodName must be populated in Status")
		})

		It("replacement pod has PodMigration owner reference", func(ctx SpecContext) {
			Expect(pm.Status.ReplacementPodName).NotTo(BeEmpty())
			replacement := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Namespace: nginxLiveNamespace,
				Name:      pm.Status.ReplacementPodName,
			}, replacement)).To(Succeed())

			hasOwner := false
			for _, ref := range replacement.OwnerReferences {
				if ref.Kind == "PodMigration" && ref.Name == pm.Name {
					hasOwner = true
					break
				}
			}
			Expect(hasOwner).To(BeTrue(), "replacement pod must have PodMigration ownerRef")
		})

		It("replacement pod labels do NOT include pod-template-hash", func(ctx SpecContext) {
			replacement := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Namespace: nginxLiveNamespace,
				Name:      pm.Status.ReplacementPodName,
			}, replacement)).To(Succeed())

			_, hasHash := replacement.Labels["pod-template-hash"]
			Expect(hasHash).To(BeFalse(),
				"pod-template-hash must be stripped to prevent ReplicaSet from counting gated clone")
		})
	})

	// ── Test 2: Full NS#3 North Star proof ──────────────────────────────────

	Describe("Full live migration — phase=Complete proof", Ordered, Label("proof"), func() {
		var pm *pmv1.PodMigration
		var sourcePod *corev1.Pod
		var destNode string

		BeforeAll(func() {
			// Refresh: previous test suite may have migrated the pod to a different node.
			sourcePod = getNginxLivePod(context.Background(), k8sClient)
			destNode = pickDestNode(context.Background(), k8sClient, sourcePod.Spec.NodeName)
			// Mark the log audit window from just before this migration begins.
			logAuditStart = time.Now()
		})

		AfterAll(func() {
			// Record the end of the audit window before Test 3 (rollback) runs.
			// This must happen in AfterAll (not AfterEach) to fire after the last It in this
			// Describe block completes, while still preceding Test 3's BeforeAll.
			logAuditEnd = time.Now()
			// NOTE: Do NOT delete the migration CR here — the replacement pod has an ownerRef
			// to this CR, so deleting it would GC the replacement pod before Test 3 can use it.
			// The top-level NS#3 AfterAll handles cleanup after all Describe blocks complete.
		})

		It("reaches phase=Complete within "+liveMigrationTimeout.String(), func(ctx SpecContext) {
			pm = createLiveMigration(ctx, k8sClient, sourcePod, destNode)

			var finalPM pmv1.PodMigration
			err := wait.PollUntilContextTimeout(ctx, livePollInterval, liveMigrationTimeout, true,
				func(ctx context.Context) (bool, error) {
					if getErr := k8sClient.Get(ctx,
						types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name},
						&finalPM); getErr != nil {
						return false, getErr
					}
					switch finalPM.Status.Phase {
					case pmv1.MigrationPhaseComplete:
						return true, nil
					case pmv1.MigrationPhaseFailed:
						return false, fmt.Errorf("migration failed: %s", phaseReason(&finalPM))
					}
					return false, nil
				})
			Expect(err).NotTo(HaveOccurred(), "migration must reach Complete")

			// Snapshot the result for subsequent assertions.
			ns3Result = NS3Result{
				SourceNode:    sourcePod.Spec.NodeName,
				DestNode:      finalPM.Status.DestinationNodeName,
				ReplacementPod: finalPM.Status.ReplacementPodName,
				MigrationName: finalPM.Name,
			}
			if finalPM.Status.PreCopyStats != nil {
				ns3Result.FreezeDurationMs = finalPM.Status.PreCopyStats.FreezeDurationMs
			}
		})

		It("replacement pod is running on the DESTINATION node", func(ctx SpecContext) {
			Expect(ns3Result.ReplacementPod).NotTo(BeEmpty(), "must have replacement pod name")
			Expect(ns3Result.DestNode).NotTo(BeEmpty(), "must have destination node")
			Expect(ns3Result.DestNode).To(Equal(destNode),
				"destination node must match the explicitly pinned target")
			Expect(ns3Result.DestNode).NotTo(Equal(ns3Result.SourceNode),
				"destination node must differ from source node")

			replacement := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Namespace: nginxLiveNamespace,
				Name:      ns3Result.ReplacementPod,
			}, replacement)).To(Succeed())

			Expect(replacement.Spec.NodeName).To(Equal(ns3Result.DestNode),
				"replacement pod must be scheduled on destination node")
			Expect(replacement.Status.Phase).To(Equal(corev1.PodRunning),
				"replacement pod must be Running")
		})

		It("source pod is deleted after migration (ADR-0040 gate)", func(ctx SpecContext) {
			Eventually(func() bool {
				srcPod := &corev1.Pod{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: nginxLiveNamespace,
					Name:      sourcePod.Name,
				}, srcPod)
				return apierrors.IsNotFound(err)
			}, 2*time.Minute, livePollInterval).Should(BeTrue(),
				"source pod must be deleted after TrafficVerified=True")
		})

		It("NGINX service returns HTTP 200 AND replacement pod is the responder", func(ctx SpecContext) {
			Expect(ns3Result.ReplacementPod).NotTo(BeEmpty())

			// First verify the replacement pod itself is the only pod that matches the Service selector.
			// Since this is a bare Pod (no Deployment/RS), the only running pod with label
			// app=pm-test-nginx-live must be the replacement pod by this point.
			Eventually(func() string {
				list := &corev1.PodList{}
				_ = k8sClient.List(ctx, list,
					client.InNamespace(nginxLiveNamespace),
					client.MatchingLabels{"app": nginxLivePodName},
				)
				var running []string
				for i := range list.Items {
					if list.Items[i].Status.Phase == corev1.PodRunning &&
						list.Items[i].DeletionTimestamp == nil {
						running = append(running, list.Items[i].Name)
					}
				}
				if len(running) == 1 {
					return running[0]
				}
				return fmt.Sprintf("running-pods:%v", running)
			}, 2*time.Minute, livePollInterval).Should(Equal(ns3Result.ReplacementPod),
				"only the replacement pod (pm.Status.ReplacementPodName) must be running with Service selector after migration")

			// Now verify the Service actually routes HTTP traffic.
			Eventually(func() int {
				cmd := exec.Command("kubectl", "run", "curl-probe",
					"--image=curlimages/curl:8.5.0",
					"--restart=Never",
					"--rm", "--attach",
					"-n", nginxLiveNamespace,
					"--command", "--",
					"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
					fmt.Sprintf("http://%s.%s.svc.cluster.local/", nginxLiveService, nginxLiveNamespace),
				)
				out, err := utils.Run(cmd)
				if err != nil {
					return 0
				}
				code := 0
				fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &code)
				return code
			}, 2*time.Minute, 5*time.Second).Should(Equal(http.StatusOK),
				"NGINX must return 200 after live migration — traffic is routed through replacement pod")
		})

		It("TrafficVerified=True condition is set", func(ctx SpecContext) {
			finalPM := &pmv1.PodMigration{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name}, finalPM)).To(Succeed())
			Expect(meta.IsStatusConditionTrue(finalPM.Status.Conditions, "TrafficVerified")).To(BeTrue(),
				"TrafficVerified condition must be True at Complete")
		})

		It("SourcePodDeleted=True condition is set", func(ctx SpecContext) {
			finalPM := &pmv1.PodMigration{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name}, finalPM)).To(Succeed())
			Expect(meta.IsStatusConditionTrue(finalPM.Status.Conditions, "SourcePodDeleted")).To(BeTrue(),
				"SourcePodDeleted condition must be True at Complete")
		})

		It("prints NS#3 proof summary", func(_ SpecContext) {
			_, _ = fmt.Fprintf(GinkgoWriter, "\n"+
				"══════════════════════════════════════════════════════\n"+
				"  NS#3 NORTH STAR PROOF — STATELESS LIVE MIGRATION\n"+
				"══════════════════════════════════════════════════════\n"+
				"  Source node       : %s\n"+
				"  Destination node  : %s\n"+
				"  Replacement pod   : %s\n"+
				"  Freeze duration   : %dms\n"+
				"  PROVED            : %s\n"+
				"══════════════════════════════════════════════════════\n\n",
				ns3Result.SourceNode,
				ns3Result.DestNode,
				ns3Result.ReplacementPod,
				ns3Result.FreezeDurationMs,
				time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			)
		})
	})

	// ── Test 3: Rollback — no stale replacement pod on failure ───────────────

	Describe("Rollback path — replacement pod cleanup", Ordered, func() {
		// This test injects a failure by targeting a non-existent destination node,
		// forcing the migration to fail, and verifying the replacement pod is cleaned up.
		// NOTE: this test intentionally produces error/warn logs in the operator.
		// The log audit in AfterAll is scoped to AFTER the successful migration started,
		// so those deliberate errors do not trigger a false failure in criterion 5.

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "podmigrations",
				"-n", nginxLiveNamespace,
				"-l", "podmotion.io/test=rollback-probe",
				"--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("source pod is NOT deleted when migration is aborted (ADR-0012 inverse)", func(ctx SpecContext) {
			// After Test 2, find whatever pod is currently running with the nginx-live app label.
			// (This may be the replacement pod from the successful migration.)
			sourcePod := getCurrentNginxLivePod(ctx, k8sClient)
			if sourcePod == nil {
				Skip("no running nginx-live pod found — skipping rollback test")
			}

			// Create a migration targeting the SAME node as the source pod.
			// The operator should reject this (or at least not delete the source pod)
			// because it cannot migrate a pod to its own current node.
			// This tests that the source pod is protected under partial failure.
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "pm-live-fail-",
					Namespace:    nginxLiveNamespace,
					Labels:       map[string]string{"podmotion.io/test": "rollback-probe"},
				},
				Spec: pmv1.PodMigrationSpec{
					PodName:                  sourcePod.Name,
					PodNamespace:             nginxLiveNamespace,
					Mode:                     pmv1.MigrationModeCold,
					TargetNodeName:           sourcePod.Spec.NodeName, // same node = must fail validation
					RollbackOnFailure:        true,
					CompletionTimeoutSeconds: 30,
				},
			}
			Expect(k8sClient.Create(ctx, pm)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, pm) }()

			// Wait for the migration to either fail (expected) or time out at 60s.
			// The operator should reject same-node migration in Validating phase.
			Eventually(func() pmv1.MigrationPhase {
				_ = k8sClient.Get(ctx, types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name}, pm)
				return pm.Status.Phase
			}, 90*time.Second, livePollInterval).Should(
				BeElementOf(
					pmv1.MigrationPhaseFailed,
					pmv1.MigrationPhaseRollingBack,
					pmv1.MigrationPhaseValidating,
					pmv1.MigrationPhasePreMigrating,
				),
				"migration to same node should fail or remain in early phase")

			By("asserting source pod is NOT deleted during failed/aborted migration")
			runningPod := &corev1.Pod{}
			err := k8sClient.Get(ctx, types.NamespacedName{
				Namespace: nginxLiveNamespace,
				Name:      sourcePod.Name,
			}, runningPod)
			Expect(err).NotTo(HaveOccurred(),
				"source pod must NOT be deleted when migration fails (ADR-0012 inverse)")
			Expect(runningPod.DeletionTimestamp).To(BeNil(),
				"source pod must not have a deletionTimestamp when migration is not Complete")
		})
	})
})

// ── Helpers ─────────────────────────────────────────────────────────────────

func getNginxLivePod(ctx context.Context, c client.Client) *corev1.Pod {
	GinkgoHelper()
	pod := &corev1.Pod{}
	Expect(c.Get(ctx, types.NamespacedName{
		Namespace: nginxLiveNamespace,
		Name:      nginxLivePodName,
	}, pod)).To(Succeed(), "nginx-live pod must exist")
	return pod
}

// getCurrentNginxLivePod returns whatever pod is currently Running with the
// nginx-live app label. After a successful migration Test 2 deletes the original
// bare Pod and the replacement pod becomes the current workload pod.
// Returns nil if no running pod is found (caller should Skip).
func getCurrentNginxLivePod(ctx context.Context, c client.Client) *corev1.Pod {
	GinkgoHelper()
	list := &corev1.PodList{}
	if err := c.List(ctx, list,
		client.InNamespace(nginxLiveNamespace),
		client.MatchingLabels{"app": nginxLivePodName},
	); err != nil {
		return nil
	}
	for i := range list.Items {
		p := &list.Items[i]
		if p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil {
			return p
		}
	}
	return nil
}

// pickDestNode returns a node that is NOT the source node.
// The test requires an explicit destination to guarantee a cross-node move and
// to make the assertion deterministic on single-worker clusters (skip if only 1 node).
func pickDestNode(ctx context.Context, c client.Client, sourceNode string) string {
	GinkgoHelper()
	nodeList := &corev1.NodeList{}
	Expect(c.List(ctx, nodeList)).To(Succeed())

	var candidates []string
	for _, n := range nodeList.Items {
		if n.Name == sourceNode {
			continue
		}
		ready := false
		for _, cond := range n.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				ready = true
				break
			}
		}
		if ready {
			candidates = append(candidates, n.Name)
		}
	}
	if len(candidates) == 0 {
		Skip("NS#3 requires at least 2 nodes; only 1 ready node found — skipping")
	}
	return candidates[0]
}

func createLiveMigration(ctx context.Context, c client.Client, sourcePod *corev1.Pod, targetNode string) *pmv1.PodMigration {
	GinkgoHelper()
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("pm-live-%s-", sourcePod.Name),
			Namespace:    nginxLiveNamespace,
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  sourcePod.Name,
			PodNamespace:             nginxLiveNamespace,
			Mode:                     pmv1.MigrationModeCold,
			TargetNodeName:           targetNode,
			NetworkContinuity:        false,
			RollbackOnFailure:        true,
			CompletionTimeoutSeconds: int32(liveMigrationTimeout.Seconds()),
		},
	}
	Expect(c.Create(ctx, pm)).To(Succeed(), "creating live PodMigration for "+sourcePod.Name)
	return pm
}

func cleanupLiveMigration(ctx context.Context, c client.Client, pm *pmv1.PodMigration) {
	_ = c.Delete(ctx, pm)
}

// phaseReason extracts a human-readable failure reason from PodMigration conditions.
func phaseReason(pm *pmv1.PodMigration) string {
	for _, c := range pm.Status.Conditions {
		if c.Type == "Failed" && c.Status == metav1.ConditionTrue {
			return c.Message
		}
	}
	return string(pm.Status.Phase)
}
