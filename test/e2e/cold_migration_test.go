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

	// ── Tier 2: Data-integrity assertions (Sprint 3 Phase 3) ──────────────

	Describe("nginx data integrity after cold migration", Ordered, func() {
		const workload = "pm-test-nginx"

		BeforeAll(func() {
			By("deploying nginx fixture for data-integrity test")
			cmd := exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/nginx.yaml")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			waitForPodReady(workload, e2eNamespace, readinessTimeout)
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "-f", "test/e2e/fixtures/nginx.yaml", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("nginx serves HTTP 200 with 'Welcome to nginx' before and after migration", func(ctx SpecContext) {
			By("confirming nginx serves HTTP 200 before migration")
			Eventually(func() (string, error) {
				cmd := exec.Command("kubectl", "exec", "-n", e2eNamespace,
					"-l", "app="+workload, "--", "wget", "-qO-", "http://localhost")
				out, err := utils.Run(cmd)
				return out, err
			}, 30*time.Second, 3*time.Second).Should(ContainSubstring("Welcome to nginx"),
				"nginx should return 'Welcome to nginx' before migration")

			sourcePod := getPodByDeployment(ctx, k8sClient, workload, e2eNamespace)
			sourcePodName := sourcePod.Name
			targetNode, err := otherWorkerNode(ctx, k8sClient, sourcePod.Spec.NodeName)
			Expect(err).NotTo(HaveOccurred())

			pm := createColdMigration(ctx, k8sClient, workload, e2eNamespace, targetNode)
			defer cleanupMigration(ctx, k8sClient, pm)

			By("waiting for migration to complete")
			Expect(waitForMigrationPhase(ctx, k8sClient, pm.Namespace, pm.Name,
				string(pmv1.MigrationPhaseComplete), migrationTimeout)).To(Succeed())

			By("confirming source pod is gone within 30s (ADR-0040)")
			Expect(waitForSourcePodGone(e2eNamespace, sourcePodName, 30*time.Second)).To(Succeed())

			By("confirming nginx serves HTTP 200 with correct body after migration")
			Eventually(func() (string, error) {
				cmd := exec.Command("kubectl", "exec", "-n", e2eNamespace,
					"-l", "app="+workload, "--", "wget", "-qO-", "http://localhost")
				out, err := utils.Run(cmd)
				return out, err
			}, 30*time.Second, 3*time.Second).Should(ContainSubstring("Welcome to nginx"),
				"nginx should return 'Welcome to nginx' after migration")
		}, SpecTimeout(migrationTimeout+time.Minute))
	})

	Describe("Redis key persistence after cold migration", Ordered, func() {
		const workload = "pm-test-redis"

		BeforeAll(func() {
			By("deploying redis fixture for key-persistence test")
			cmd := exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/redis.yaml")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			waitForPodReady(workload, e2eNamespace, readinessTimeout)
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "-f", "test/e2e/fixtures/redis.yaml", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("Redis keys survive cold migration and source pod is gone within 30s", func(ctx SpecContext) {
			By("seeding migration_test_key before migration")
			Expect(redisSet(e2eNamespace, workload, "migration_test_key", "hello_podmotion")).To(Succeed())
			By("seeding counter before migration")
			Expect(redisSet(e2eNamespace, workload, "counter", "42")).To(Succeed())

			sourcePod := getPodByDeployment(ctx, k8sClient, workload, e2eNamespace)
			sourcePodName := sourcePod.Name
			targetNode, err := otherWorkerNode(ctx, k8sClient, sourcePod.Spec.NodeName)
			Expect(err).NotTo(HaveOccurred())

			pm := createColdMigration(ctx, k8sClient, workload, e2eNamespace, targetNode)
			defer cleanupMigration(ctx, k8sClient, pm)

			By("waiting for migration to complete")
			Expect(waitForMigrationPhase(ctx, k8sClient, pm.Namespace, pm.Name,
				string(pmv1.MigrationPhaseComplete), migrationTimeout)).To(Succeed())

			By("verifying migration_test_key value after migration")
			val, err := redisGet(e2eNamespace, workload, "migration_test_key")
			Expect(err).NotTo(HaveOccurred())
			Expect(val).To(Equal("hello_podmotion"), "migration_test_key should survive cold migration")

			By("verifying counter value after migration")
			counter, err := redisGet(e2eNamespace, workload, "counter")
			Expect(err).NotTo(HaveOccurred())
			Expect(counter).To(Equal("42"), "counter should survive cold migration")

			By("confirming source pod is gone within 30s (ADR-0040)")
			Expect(waitForSourcePodGone(e2eNamespace, sourcePodName, 30*time.Second)).To(Succeed())
		}, SpecTimeout(migrationTimeout+time.Minute))
	})

	Describe("Postgres row integrity after cold migration", Ordered, func() {
		const workload = "pm-test-postgres"

		BeforeAll(func() {
			By("deploying postgres fixture for row-integrity test")
			cmd := exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/postgres.yaml")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			waitForPodReady(workload, e2eNamespace, readinessTimeout)
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "-f", "test/e2e/fixtures/postgres.yaml", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("Postgres rows survive cold migration and new writes succeed after migration", func(ctx SpecContext) {
			By("creating migration_test table and inserting pre-migration row")
			Expect(pgExec(e2eNamespace, workload,
				"CREATE TABLE IF NOT EXISTS migration_test (id SERIAL PRIMARY KEY, value TEXT);")).To(Succeed())
			Expect(pgExec(e2eNamespace, workload,
				"INSERT INTO migration_test (value) VALUES ('sprint3-pre-migration');")).To(Succeed())

			By("recording pre-migration row count")
			preCount, err := pgQuery(e2eNamespace, workload,
				"SELECT COUNT(*) FROM migration_test;")
			Expect(err).NotTo(HaveOccurred())

			sourcePod := getPodByDeployment(ctx, k8sClient, workload, e2eNamespace)
			sourcePodName := sourcePod.Name
			targetNode, err := otherWorkerNode(ctx, k8sClient, sourcePod.Spec.NodeName)
			Expect(err).NotTo(HaveOccurred())

			pm := createColdMigration(ctx, k8sClient, workload, e2eNamespace, targetNode)
			defer cleanupMigration(ctx, k8sClient, pm)

			By("waiting for migration to complete")
			Expect(waitForMigrationPhase(ctx, k8sClient, pm.Namespace, pm.Name,
				string(pmv1.MigrationPhaseComplete), migrationTimeout)).To(Succeed())

			By("verifying row count matches pre-migration count")
			postCount, err := pgQuery(e2eNamespace, workload,
				"SELECT COUNT(*) FROM migration_test;")
			Expect(err).NotTo(HaveOccurred())
			Expect(postCount).To(Equal(preCount), "row count should match pre-migration count")

			By("verifying sprint3-pre-migration row is present after migration")
			rowVal, err := pgQuery(e2eNamespace, workload,
				"SELECT value FROM migration_test WHERE value='sprint3-pre-migration' LIMIT 1;")
			Expect(err).NotTo(HaveOccurred())
			Expect(rowVal).To(Equal("sprint3-pre-migration"),
				"pre-migration row should be present after migration")

			By("verifying new writes succeed after migration")
			Expect(pgExec(e2eNamespace, workload,
				"INSERT INTO migration_test (value) VALUES ('sprint3-post-migration');")).To(Succeed())

			By("confirming source pod is gone within 30s (ADR-0040)")
			Expect(waitForSourcePodGone(e2eNamespace, sourcePodName, 30*time.Second)).To(Succeed())
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

// waitForSourcePodGone polls kubectl until the named pod is NotFound or timeout is exceeded.
func waitForSourcePodGone(namespace, podName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := exec.Command("kubectl", "get", "pod", podName, "-n", namespace)
		out, err := utils.Run(cmd)
		if err != nil && strings.Contains(out, "NotFound") {
			return nil
		}
		if err != nil && strings.Contains(strings.ToLower(out), "not found") {
			return nil
		}
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("pod %s/%s still present after %s", namespace, podName, timeout)
}

// waitForMigrationPhase polls the PodMigration CR until it reaches the desired phase or timeout.
func waitForMigrationPhase(ctx context.Context, c client.Client, namespace, migrationName, phase string, timeout time.Duration) error {
	pm := &pmv1.PodMigration{}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: migrationName}, pm); err != nil {
			return fmt.Errorf("getting PodMigration %s/%s: %w", namespace, migrationName, err)
		}
		if string(pm.Status.Phase) == phase {
			return nil
		}
		if pm.Status.Phase == pmv1.MigrationPhaseFailed {
			return fmt.Errorf("PodMigration %s/%s reached Failed phase (wanted %s)", namespace, migrationName, phase)
		}
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("PodMigration %s/%s did not reach phase %s within %s (last: %s)",
		namespace, migrationName, phase, timeout, pm.Status.Phase)
}

// otherWorkerNode returns a worker node that is different from the given node.
// It is used to pin migrations to the opposite worker so source/destination differ.
func otherWorkerNode(ctx context.Context, c client.Client, currentNode string) (string, error) {
	nodeList := &corev1.NodeList{}
	if err := c.List(ctx, nodeList); err != nil {
		return "", fmt.Errorf("listing nodes: %w", err)
	}
	for _, node := range nodeList.Items {
		// Skip control-plane nodes.
		if _, isCP := node.Labels["node-role.kubernetes.io/control-plane"]; isCP {
			continue
		}
		if node.Name != currentNode {
			return node.Name, nil
		}
	}
	return "", fmt.Errorf("no other worker node found (current: %s)", currentNode)
}

// Ensure wait is referenced.
var _ = wait.PollUntilContextTimeout
