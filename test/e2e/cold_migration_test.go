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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/test/utils"
)

const (
	e2eNamespace      = "pm-e2e"
	migrationTimeout  = 5 * time.Minute
	readinessTimeout  = 2 * time.Minute
	pollInterval      = 3 * time.Second
)

var _ = Describe("Cold Migration", Ordered, func() {
	var k8sClient client.Client

	BeforeAll(func() {
		var err error
		k8sClient, err = utils.NewPMClient()
		Expect(err).NotTo(HaveOccurred())

		By("creating e2e namespace")
		cmd := exec.Command("kubectl", "create", "namespace", e2eNamespace, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	})

	AfterAll(func() {
		By("cleaning up e2e namespace")
		cmd := exec.Command("kubectl", "delete", "namespace", e2eNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	// ── Tier 1: Core workloads ─────────────────────────────────────────────

	Describe("nginx cold migration", Ordered, func() {
		const workload = "pm-test-nginx"

		BeforeAll(func() {
			By("deploying nginx fixture")
			cmd := exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/nginx.yaml")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for nginx to be ready")
			waitForPodReady(workload, e2eNamespace, readinessTimeout)
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "-f", "test/e2e/fixtures/nginx.yaml", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("dry-run estimate completes and marks Migratable=true", func(ctx SpecContext) {
			pm := createDryRunMigration(ctx, k8sClient, workload, e2eNamespace)
			defer cleanupMigration(ctx, k8sClient, pm)

			Eventually(func() pmv1.MigrationPhase {
				_ = k8sClient.Get(ctx, namespacedName(pm), pm)
				return pm.Status.Phase
			}, 2*time.Minute, pollInterval).Should(Equal(pmv1.MigrationPhaseDryRunComplete),
				"dry-run should reach DryRunComplete")

			Expect(pm.Status.DryRunEstimate).NotTo(BeNil())
			Expect(pm.Status.DryRunEstimate.Migratable).To(BeTrue(),
				"nginx (stateless) should be Migratable=true")
			Expect(pm.Status.DryRunEstimate.StorageTier).To(BeEquivalentTo(0),
				"nginx has no PVC, should be Tier 0")
		})

		It("cold migration completes with pod on destination node", func(ctx SpecContext) {
			// Get source node before migration.
			sourcePod := getPodByDeployment(ctx, k8sClient, workload, e2eNamespace)
			sourceNode := sourcePod.Spec.NodeName

			pm := createColdMigration(ctx, k8sClient, workload, e2eNamespace, "")
			defer cleanupMigration(ctx, k8sClient, pm)

			By("waiting for migration to reach Complete")
			Eventually(func() pmv1.MigrationPhase {
				_ = k8sClient.Get(ctx, namespacedName(pm), pm)
				return pm.Status.Phase
			}, migrationTimeout, pollInterval).Should(Equal(pmv1.MigrationPhaseComplete))

			By("verifying pod is on a different node")
			Expect(pm.Status.DestinationNodeName).NotTo(Equal(sourceNode),
				"pod should have moved to a different node")

			By("verifying nginx responds after migration")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "exec", "-n", e2eNamespace,
					"-l", "app="+workload, "--", "wget", "-qO-", "localhost")
				_, err := utils.Run(cmd)
				return err
			}, 30*time.Second, 3*time.Second).Should(Succeed(),
				"nginx should respond to HTTP after migration")
		}, SpecTimeout(migrationTimeout+time.Minute))
	})

	Describe("Redis cold migration", Ordered, func() {
		const workload = "pm-test-redis"

		BeforeAll(func() {
			By("deploying redis fixture")
			cmd := exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/redis.yaml")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			waitForPodReady(workload, e2eNamespace, readinessTimeout)
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "-f", "test/e2e/fixtures/redis.yaml", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("Redis is reachable and retains keys after cold migration", func(ctx SpecContext) {
			By("seeding a test key before migration")
			Expect(redisSet(e2eNamespace, workload, "pm-test-key", "pm-test-value")).To(Succeed())

			pm := createColdMigration(ctx, k8sClient, workload, e2eNamespace, "")
			defer cleanupMigration(ctx, k8sClient, pm)

			Eventually(func() pmv1.MigrationPhase {
				_ = k8sClient.Get(ctx, namespacedName(pm), pm)
				return pm.Status.Phase
			}, migrationTimeout, pollInterval).Should(Equal(pmv1.MigrationPhaseComplete))

			By("verifying key survives migration")
			val, err := redisGet(e2eNamespace, workload, "pm-test-key")
			Expect(err).NotTo(HaveOccurred())
			Expect(val).To(Equal("pm-test-value"),
				"in-memory Redis key should survive cold migration checkpoint")
		}, SpecTimeout(migrationTimeout+time.Minute))
	})

	Describe("PostgreSQL cold migration", Ordered, func() {
		const workload = "pm-test-postgres"

		BeforeAll(func() {
			By("deploying postgres fixture")
			cmd := exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/postgres.yaml")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			waitForPodReady(workload, e2eNamespace, readinessTimeout)
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "-f", "test/e2e/fixtures/postgres.yaml", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("PostgreSQL data is consistent after cold migration", func(ctx SpecContext) {
			By("creating a test table and inserting a row before migration")
			Expect(pgExec(e2eNamespace, workload,
				"CREATE TABLE IF NOT EXISTS pm_test (id SERIAL PRIMARY KEY, val TEXT);")).To(Succeed())
			Expect(pgExec(e2eNamespace, workload,
				"INSERT INTO pm_test (val) VALUES ('migration-test-row');")).To(Succeed())

			pm := createColdMigration(ctx, k8sClient, workload, e2eNamespace, "")
			defer cleanupMigration(ctx, k8sClient, pm)

			Eventually(func() pmv1.MigrationPhase {
				_ = k8sClient.Get(ctx, namespacedName(pm), pm)
				return pm.Status.Phase
			}, migrationTimeout, pollInterval).Should(Equal(pmv1.MigrationPhaseComplete))

			By("verifying data integrity after migration")
			count, err := pgQuery(e2eNamespace, workload,
				"SELECT COUNT(*) FROM pm_test WHERE val='migration-test-row';")
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal("1"), "test row should exist post-migration")

			By("verifying PostgreSQL accepts new writes after migration")
			Expect(pgExec(e2eNamespace, workload,
				"INSERT INTO pm_test (val) VALUES ('post-migration-row');")).To(Succeed())
		}, SpecTimeout(migrationTimeout+time.Minute))
	})

	// ── Admission control tests ────────────────────────────────────────────

	Describe("Webhook admission rules", func() {
		It("rejects migration for a non-existent pod", func(ctx SpecContext) {
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "pm-reject-test-",
					Namespace:    e2eNamespace,
				},
				Spec: pmv1.PodMigrationSpec{
					PodName:      "does-not-exist",
					PodNamespace: e2eNamespace,
					Mode:         pmv1.MigrationModeCold,
				},
			}
			err := k8sClient.Create(ctx, pm)
			Expect(err).To(HaveOccurred(), "webhook should reject migration for non-existent pod")
		})

		It("rejects migration for a pod with a hostPath volume", func(ctx SpecContext) {
			By("creating a pod with hostPath volume")
			cmd := exec.Command("kubectl", "run", "hostpath-pod", "-n", e2eNamespace,
				"--image=nginx:alpine", "--restart=Never",
				"--overrides={\"spec\":{\"volumes\":[{\"name\":\"hp\",\"hostPath\":{\"path\":\"/tmp\"}}],\"containers\":[{\"name\":\"nginx\",\"image\":\"nginx:alpine\",\"volumeMounts\":[{\"name\":\"hp\",\"mountPath\":\"/hp\"}]}]}}")
			_, _ = utils.Run(cmd)
			defer func() {
				_ = exec.Command("kubectl", "delete", "pod", "hostpath-pod", "-n", e2eNamespace, "--ignore-not-found").Run()
			}()

			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "pm-hostpath-test-",
					Namespace:    e2eNamespace,
				},
				Spec: pmv1.PodMigrationSpec{
					PodName:      "hostpath-pod",
					PodNamespace: e2eNamespace,
					Mode:         pmv1.MigrationModeCold,
				},
			}
			err := k8sClient.Create(ctx, pm)
			Expect(err).To(HaveOccurred(), "webhook should reject Tier 4 hostPath volume")
		})
	})
})

// ── Test helpers ──────────────────────────────────────────────────────────

func createDryRunMigration(ctx context.Context, c client.Client, podName, ns string) *pmv1.PodMigration {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("pm-dryrun-%s-", podName),
			Namespace:    ns,
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:      podName,
			PodNamespace: ns,
			Mode:         pmv1.MigrationModeCold,
			DryRun:       true,
		},
	}
	Expect(c.Create(ctx, pm)).To(Succeed(), "creating dry-run PodMigration")
	return pm
}

func createColdMigration(ctx context.Context, c client.Client, podName, ns, targetNode string) *pmv1.PodMigration {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("pm-cold-%s-", podName),
			Namespace:    ns,
		},
		Spec: pmv1.PodMigrationSpec{
			PodName:                  podName,
			PodNamespace:             ns,
			Mode:                     pmv1.MigrationModeCold,
			TargetNodeName:           targetNode,
			RollbackOnFailure:        true,
			CompletionTimeoutSeconds: 300,
		},
	}
	Expect(c.Create(ctx, pm)).To(Succeed(), "creating cold PodMigration")
	return pm
}

func cleanupMigration(ctx context.Context, c client.Client, pm *pmv1.PodMigration) {
	_ = c.Delete(ctx, pm)
}

func namespacedName(pm *pmv1.PodMigration) types.NamespacedName {
	return types.NamespacedName{Namespace: pm.Namespace, Name: pm.Name}
}

func waitForPodReady(deployment, ns string, timeout time.Duration) {
	GinkgoHelper()
	cmd := exec.Command("kubectl", "rollout", "status",
		fmt.Sprintf("deployment/%s", deployment), "-n", ns,
		fmt.Sprintf("--timeout=%s", timeout))
	out, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "waiting for deployment ready: "+string(out))
}

func getPodByDeployment(ctx context.Context, c client.Client, deployment, ns string) *corev1.Pod {
	GinkgoHelper()
	// This is a simplification — in real tests, query by label selector.
	// Kept simple for M3.
	list := &corev1.PodList{}
	Expect(c.List(ctx, list, client.InNamespace(ns),
		client.MatchingLabels{"app": deployment})).To(Succeed())
	Expect(list.Items).NotTo(BeEmpty(), "expected at least one pod for "+deployment)
	return &list.Items[0]
}

func redisSet(ns, svc, key, val string) error {
	cmd := exec.Command("kubectl", "exec", "-n", ns,
		fmt.Sprintf("svc/%s", svc), "--", "redis-cli", "set", key, val)
	_, err := utils.Run(cmd)
	return err
}

func redisGet(ns, svc, key string) (string, error) {
	cmd := exec.Command("kubectl", "exec", "-n", ns,
		fmt.Sprintf("svc/%s", svc), "--", "redis-cli", "get", key)
	out, err := utils.Run(cmd)
	return strings.TrimSpace(string(out)), err
}

func pgExec(ns, svc, sql string) error {
	cmd := exec.Command("kubectl", "exec", "-n", ns,
		fmt.Sprintf("svc/%s", svc), "--",
		"psql", "-U", "pmtest", "-d", "pmtest", "-c", sql)
	_, err := utils.Run(cmd)
	return err
}

func pgQuery(ns, svc, sql string) (string, error) {
	cmd := exec.Command("kubectl", "exec", "-n", ns,
		fmt.Sprintf("svc/%s", svc), "--",
		"psql", "-U", "pmtest", "-d", "pmtest", "-tAc", sql)
	out, err := utils.Run(cmd)
	return strings.TrimSpace(string(out)), err
}

// Ensure wait is referenced.
var _ = wait.PollUntilContextTimeout
