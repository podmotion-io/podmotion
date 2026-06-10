//go:build e2e
// +build e2e

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/test/utils"
)

// preCopyTimeout allows enough time for up to 5 pre-dump rounds plus the freeze.
const preCopyTimeout = 8 * time.Minute

var _ = Describe("PreCopy Migration", Ordered, func() {
	var k8sClient client.Client

	BeforeAll(func() {
		var err error
		k8sClient, err = utils.NewPMClient()
		Expect(err).NotTo(HaveOccurred())

		By("ensuring e2e namespace exists")
		cmd := exec.Command("kubectl", "create", "namespace", e2eNamespace, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	})

	Describe("Redis under redis-benchmark pre-copy migration", Ordered, func() {
		const workload = "pm-test-redis-precopy"

		BeforeAll(func() {
			By("deploying redis fixture for pre-copy test")
			cmd := exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/redis.yaml",
				"-n", e2eNamespace,
				"--set", fmt.Sprintf("name=%s", workload))
			// Tolerate apply flag syntax differences; fall back to raw apply.
			if _, err := utils.Run(cmd); err != nil {
				cmd = exec.Command("kubectl", "run", workload,
					"-n", e2eNamespace,
					"--image=redis:7-alpine",
					"--restart=Always",
					"--labels=app="+workload,
					"--port=6379")
				_, err = utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
			}
			waitForPodReady(workload, e2eNamespace, readinessTimeout)
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "pod", workload,
				"-n", e2eNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("pre-copy migration completes within MaxRounds and FinalDirtyMB is within bounds", func(ctx SpecContext) {
			By("starting redis-benchmark to create dirty page pressure during migration")
			benchCtx, cancelBench := context.WithCancel(ctx)
			defer cancelBench()
			go func() {
				cmd := exec.CommandContext(benchCtx, "kubectl", "exec",
					"-n", e2eNamespace, workload, "--",
					"redis-benchmark", "-q", "-n", "10000000", "-c", "4", "--no-auth-warning")
				// Ignore error — command will be cancelled when migration completes.
				_, _ = utils.Run(cmd)
			}()

			pm := createPreCopyMigration(ctx, k8sClient, workload, e2eNamespace)
			defer cleanupMigration(ctx, k8sClient, pm)

			By("waiting for migration to reach Complete or Failed")
			Eventually(func() pmv1.MigrationPhase {
				_ = k8sClient.Get(ctx, namespacedName(pm), pm)
				return pm.Status.Phase
			}, preCopyTimeout, pollInterval).Should(
				BeElementOf(pmv1.MigrationPhaseComplete, pmv1.MigrationPhaseFailed),
				"migration should terminate (complete or fail) within timeout")

			cancelBench()

			By("asserting migration completed successfully")
			Expect(pm.Status.Phase).To(Equal(pmv1.MigrationPhaseComplete),
				"pre-copy migration should complete, not fail")

			By("asserting PreCopyStats are present")
			Expect(pm.Status.PreCopyStats).NotTo(BeNil(),
				"PreCopyStats must be populated after a PreCopy migration")

			stats := pm.Status.PreCopyStats

			By("asserting convergence constraint: FinalDirtyMB < 100 OR RoundsCompleted == MaxRounds")
			maxRounds := pm.Spec.PreCopyMaxRounds
			if maxRounds <= 0 {
				maxRounds = 5
			}
			Expect(stats.FinalDirtyPagesMB < 100 || stats.RoundsCompleted == maxRounds).To(BeTrue(),
				fmt.Sprintf("FinalDirtyPagesMB=%d RoundsCompleted=%d MaxRounds=%d",
					stats.FinalDirtyPagesMB, stats.RoundsCompleted, maxRounds))

			By("asserting at least one pre-dump round ran")
			Expect(stats.RoundsCompleted).To(BeNumerically(">=", 1),
				"at least one pre-dump round must complete")

			By("asserting MemorySynced condition is True")
			condSet := false
			for _, c := range pm.Status.Conditions {
				if c.Type == "MemorySynced" && c.Status == "True" {
					condSet = true
					break
				}
			}
			Expect(condSet).To(BeTrue(), "MemorySynced=True condition must be set on completion")
		}, SpecTimeout(preCopyTimeout+time.Minute))
	})
})

// createPreCopyMigration creates a PodMigration in PreCopy mode with tight parameters
// suitable for E2E testing: 5 max rounds, 64MB threshold.
func createPreCopyMigration(ctx context.Context, c client.Client, podName, ns string) *pmv1.PodMigration {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("pm-precopy-%s-", podName),
			Namespace:    ns,
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  podName,
			PodNamespace:             ns,
			Mode:                     pmv1.MigrationModePreCopy,
			PreCopyMaxRounds:         5,
			PreCopyDirtyThresholdMB:  64,
			RollbackOnFailure:        true,
			CompletionTimeoutSeconds: 480,
		},
	}
	Expect(c.Create(ctx, pm)).To(Succeed(), "creating pre-copy PodMigration")
	return pm
}
