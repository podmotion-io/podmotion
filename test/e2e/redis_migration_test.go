//go:build e2e

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package e2e — live Redis migration under active load.
//
// Structural twin of db_migration_test.go (Label("live-db")). Proves a Redis pod
// migrates LIVE from pm-w1 to pm-w2 while a client runs a continuous
// `INCR gate:counter` write loop against it. Key assertions:
//
//  1. Migration reaches Complete with at least one pre-copy round recorded
//     (proves this was a live pre-copy migration, not a cold checkpoint/restore).
//  2. Replacement pod is Running on the target node (pm-w2) and its name is
//     recorded in Status.ReplacementPodName; only it carries the Service selector.
//  3. `GET gate:counter` on the restored pod is >= the value snapshotted before
//     migration — CRIU preserved the in-memory counter, no increments lost.
//  4. Redis on the restored pod answers `redis-cli ping`.
//  5. A fresh `INCR` succeeds against the restored pod post-migration.
//  6. Strict TCP preservation: zero client RSTs/errors across the freeze window.
package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
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
	redisTestNS      = "pm-redis-test"
	redisSrcPod      = "redis-src"
	redisLoadGenPod  = "redis-load-gen"
	redisSourceNode  = "pm-w1"
	redisTargetNode  = "pm-w2"
	redisTestTimeout = 12 * time.Minute
	redisTestPoll    = 5 * time.Second
	redisLiveFixture = "test/e2e/fixtures/redis-live.yaml"
	redisLoadFixture = "test/e2e/fixtures/redis-loadgen.yaml"
)

var _ = Describe("Live Redis migration under load", Label("live-redis"), Ordered, func() {
	var (
		ctx      = context.Background()
		pmClient client.Client
	)

	BeforeAll(func() {
		var err error
		pmClient, err = utils.NewPMClient()
		Expect(err).NotTo(HaveOccurred())

		By("deploying Redis source pod and load generator")
		for _, f := range []string{redisLiveFixture, redisLoadFixture} {
			out, err := exec.Command("kubectl", "apply", "-f", f).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "kubectl apply %s: %s", f, string(out))
		}

		By("waiting for redis-src to be Ready on " + redisSourceNode + " (up to 2 min)")
		Expect(utils.WaitForPodReadyOnNode(ctx, pmClient, redisSrcPod, redisTestNS, redisSourceNode,
			2*time.Minute, 3*time.Second)).To(Succeed())

		By("warming up INCR write load for 15s")
		time.Sleep(15 * time.Second)
	})

	AfterAll(func() {
		exec.Command("kubectl", "delete", "namespace", redisTestNS, "--ignore-not-found").Run() //nolint:errcheck
	})

	It("load generator is incrementing without errors before migration", Label("redis-baseline"), func() {
		out, err := exec.Command("kubectl", "logs", redisLoadGenPod, "-n", redisTestNS, "--tail=20").Output()
		Expect(err).NotTo(HaveOccurred())
		GinkgoWriter.Printf("Load gen pre-migration tail:\n%s\n", string(out))
		Expect(strings.Contains(string(out), "WRITE_ERROR")).To(BeFalse(),
			"no write errors expected before migration starts")
	})

	It("completes live Redis migration preserving the in-memory counter", Label("live-redis-precopy"), func() {
		By("snapshotting GET gate:counter before migration")
		counterBefore := readRedisCounter(ctx, redisSrcPod)
		GinkgoWriter.Printf("gate:counter before: %d\n", counterBefore)
		Expect(counterBefore).To(BeNumerically(">", 0), "load gen must have made at least one INCR")

		By("creating PodMigration CR in PreCopy mode with Strict TCP preservation")
		pm := &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "redis-live-migration",
				Namespace: redisTestNS,
			},
			Spec: pmv1.PodMigrationSpec{
				PodName:                  redisSrcPod,
				PodNamespace:             redisTestNS,
				TargetNodeName:           redisTargetNode,
				Mode:                     pmv1.MigrationModePreCopy,
				TCPPreservationMode:      pmv1.TCPPreservationModeStrict,
				PreCopyMaxRounds:         5,
				PreCopyDirtyThresholdMB:  16,
				CompletionTimeoutSeconds: 720,
			},
		}
		Expect(pmClient.Create(ctx, pm)).To(Succeed())

		By("waiting for migration to Complete")
		var finalPM pmv1.PodMigration
		err := wait.PollUntilContextTimeout(ctx, redisTestPoll, redisTestTimeout, true,
			func(ctx context.Context) (bool, error) {
				if err := pmClient.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, &finalPM); err != nil {
					return false, nil
				}
				GinkgoWriter.Printf("  phase=%s\n", finalPM.Status.Phase)
				switch finalPM.Status.Phase {
				case pmv1.MigrationPhaseComplete:
					return true, nil
				case pmv1.MigrationPhaseFailed:
					return false, fmt.Errorf("migration reached Failed")
				}
				return false, nil
			})
		Expect(err).NotTo(HaveOccurred(), "migration must reach Complete")

		if finalPM.Status.PreCopyStats != nil {
			GinkgoWriter.Printf("PreCopy: rounds=%d finalDirtyMB=%d freezeMs=%d\n",
				finalPM.Status.PreCopyStats.RoundsCompleted,
				finalPM.Status.PreCopyStats.FinalDirtyPagesMB,
				finalPM.Status.PreCopyStats.FreezeDurationMs)
		}

		By("(b) asserting pre-copy ran at least one round (proves live, not cold)")
		Expect(finalPM.Status.PreCopyStats).NotTo(BeNil())
		Expect(finalPM.Status.PreCopyStats.RoundsCompleted).To(BeNumerically(">", 0),
			"PreCopyRounds must be > 0 — a cold migration would record zero rounds")

		By("(a) asserting replacement pod is Running on " + redisTargetNode)
		Expect(finalPM.Status.ReplacementPodName).NotTo(BeEmpty(), "Status.ReplacementPodName must be set")
		var replacement corev1.Pod
		Expect(pmClient.Get(ctx, types.NamespacedName{
			Name: finalPM.Status.ReplacementPodName, Namespace: redisTestNS,
		}, &replacement)).To(Succeed())
		Expect(replacement.Spec.NodeName).To(Equal(redisTargetNode),
			"replacement pod must be scheduled on the target node")
		Expect(replacement.Status.Phase).To(Equal(corev1.PodRunning))

		By("asserting only the replacement pod carries the redis-src Service selector")
		Eventually(func() string {
			list := &corev1.PodList{}
			_ = pmClient.List(ctx, list,
				client.InNamespace(redisTestNS),
				client.MatchingLabels{"app": redisSrcPod},
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
		}, 2*time.Minute, redisTestPoll).Should(Equal(finalPM.Status.ReplacementPodName),
			"only the replacement pod must carry the Service selector after migration")

		By("(d) waiting for redis-cli ping to succeed on the restored pod (up to 2 min)")
		var lastPingErr error
		Eventually(func() bool {
			out, err := exec.Command("kubectl", "exec", replacement.Name, "-n", redisTestNS,
				"--", "redis-cli", "ping").Output()
			lastPingErr = err
			return err == nil && strings.Contains(strings.ToUpper(string(out)), "PONG")
		}, 2*time.Minute, 5*time.Second).Should(BeTrue(),
			fmt.Sprintf("redis on replacement must answer PING (last error: %v)", lastPingErr))

		By("(c) verifying GET gate:counter on restored pod >= value before migration")
		// Give the load gen a moment to reconnect through the Service to the new pod.
		time.Sleep(5 * time.Second)
		counterAfter := readRedisCounter(ctx, replacement.Name)
		GinkgoWriter.Printf("gate:counter after migration: %d (before=%d delta=%d)\n",
			counterAfter, counterBefore, counterAfter-counterBefore)
		Expect(counterAfter).To(BeNumerically(">=", counterBefore),
			"no increments must be lost: counter on restored pod must be >= counter before migration")

		By("(e) verifying a fresh INCR succeeds against the restored pod")
		out, err := exec.Command("kubectl", "exec", replacement.Name, "-n", redisTestNS,
			"--", "redis-cli", "INCR", "gate:counter").Output()
		Expect(err).NotTo(HaveOccurred(), "fresh INCR must succeed post-migration")
		incremented, perr := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		Expect(perr).NotTo(HaveOccurred(), "fresh INCR must return a numeric value: %q", string(out))
		Expect(incremented).To(BeNumerically(">", counterAfter),
			"fresh INCR must advance the counter past the post-migration snapshot")

		By("(f) Strict mode: asserting zero client errors across the freeze window")
		loadGenLogs := getRedisLoadGenLogs(ctx)
		errorLines := countErrorLines(loadGenLogs)
		freezeMs := int64(0)
		if finalPM.Status.PreCopyStats != nil {
			freezeMs = finalPM.Status.PreCopyStats.FreezeDurationMs
		}
		GinkgoWriter.Printf("Load gen errors: %d  freeze=%dms\n", errorLines, freezeMs)
		// Strict TCP preservation must hold the connection across the freeze: zero errors.
		Expect(errorLines).To(Equal(0),
			"Strict TCP preservation must produce zero client RSTs/errors across the freeze window")
	})

	It("load generator continues without errors after migration", Label("redis-post-routing"), func() {
		By("verifying the load generator keeps writing to the replacement pod without manual intervention")
		time.Sleep(5 * time.Second)
		out, err := exec.Command("kubectl", "logs", redisLoadGenPod, "-n", redisTestNS, "--tail=30").Output()
		Expect(err).NotTo(HaveOccurred())
		postMigrationErrors := countErrorLines(string(out))
		GinkgoWriter.Printf("Load gen errors in post-migration window: %d\n", postMigrationErrors)
		Expect(postMigrationErrors).To(Equal(0),
			"load generator must have zero errors in the post-migration window")
	})
})

// readRedisCounter returns the integer value of gate:counter from the named redis pod.
// Returns -1 on any error so callers can assert BeNumerically(">", 0) as a liveness gate.
func readRedisCounter(ctx context.Context, podName string) int64 {
	GinkgoHelper()
	out, err := exec.Command("kubectl", "exec", podName, "-n", redisTestNS,
		"--", "redis-cli", "--no-raw", "GET", "gate:counter").Output()
	if err != nil {
		GinkgoWriter.Printf("readRedisCounter(%s) error: %v\n", podName, err)
		return -1
	}
	// --no-raw wraps the value in quotes (e.g. "1234"); strip them before parsing.
	val := strings.Trim(strings.TrimSpace(string(out)), "\"")
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		GinkgoWriter.Printf("readRedisCounter(%s) parse error: %v (raw=%q)\n", podName, err, string(out))
		return -1
	}
	return n
}

func getRedisLoadGenLogs(ctx context.Context) string {
	out, _ := exec.Command("kubectl", "logs", redisLoadGenPod, "-n", redisTestNS).Output()
	return string(out)
}
