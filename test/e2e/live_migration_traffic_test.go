//go:build e2e

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package e2e — live migration traffic continuity tests.
//
// Deploys HAProxy in TCP mode in front of the migrating nginx service.
// Polls HAProxy stats CSV during the migration window to count TCP errors.
//
// Phase 1 (cold / pre-copy, no TCP_REPAIR): errors during the freeze window are
// recorded but do NOT fail the test. The count is logged as a baseline metric.
//
// Phase 2 (NS#5 — TCP_REPAIR): assert errsDuringMigration == 0.
package e2e

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
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
	liveTrafficNS      = "pm-live-test"
	liveTrafficTimeout = 10 * time.Minute
	liveTrafficPoll    = 5 * time.Second
)

var _ = Describe("Live migration traffic continuity", Label("live-traffic"), Ordered, func() {
	var (
		ctx      = context.Background()
		pmClient client.Client
	)

	BeforeAll(func() {
		var err error
		pmClient, err = utils.NewPMClient()
		Expect(err).NotTo(HaveOccurred())

		By("deploying nginx backend, HAProxy, and traffic generator")
		for _, f := range []string{
			"test/fixtures/traffic-test/nginx-backend.yaml",
			"test/fixtures/traffic-test/haproxy-tcp-proxy.yaml",
			"test/fixtures/traffic-test/haproxy-deploy.yaml",
			"test/fixtures/traffic-test/traffic-gen.yaml",
		} {
			out, err := exec.Command("kubectl", "apply", "-f", f).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "kubectl apply %s: %s", f, string(out))
		}

		By("waiting for nginx-live-src to be Ready")
		Eventually(func() bool {
			var pod corev1.Pod
			if err := pmClient.Get(ctx, types.NamespacedName{Name: "nginx-live-src", Namespace: liveTrafficNS}, &pod); err != nil {
				return false
			}
			for _, c := range pod.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					return true
				}
			}
			return false
		}, 2*time.Minute, 3*time.Second).Should(BeTrue(), "nginx-live-src must be Ready")

		By("waiting for HAProxy deployment to be ready")
		Eventually(func() bool {
			out, err := exec.Command("kubectl", "get", "deployment", "haproxy-tcp",
				"-n", liveTrafficNS, "-o", "jsonpath={.status.readyReplicas}").Output()
			return err == nil && strings.TrimSpace(string(out)) == "1"
		}, 2*time.Minute, 3*time.Second).Should(BeTrue(), "haproxy-tcp deployment must be Ready")

		By("warming up traffic for 10s")
		time.Sleep(10 * time.Second)
	})

	AfterAll(func() {
		exec.Command("kubectl", "delete", "namespace", liveTrafficNS, "--ignore-not-found").Run() //nolint:errcheck
	})

	It("has zero HAProxy errors before migration", Label("traffic-baseline"), func() {
		errs := haproxyErrors(ctx, pmClient)
		GinkgoWriter.Printf("HAProxy baseline errors: %d\n", errs)
		Expect(errs).To(BeNumerically(">=", 0), "stats endpoint must be reachable")
		Expect(errs).To(Equal(int64(0)), "no errors expected before migration")
	})

	It("completes PreCopy migration and records traffic errors", Label("live-precopy-traffic"), func() {
		By("snapshot pre-migration error counts (econ + dreq)")
		econBefore, dreqBefore := haproxyErrorSnapshot(ctx, pmClient)
		GinkgoWriter.Printf("HAProxy baseline: econ=%d dreq=%d\n", econBefore, dreqBefore)

		By("creating PodMigration CR in PreCopy mode")
		pm := &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-live-migration",
				Namespace: liveTrafficNS,
			},
			Spec: pmv1.PodMigrationSpec{
				PodName:                 "nginx-live-src",
				PodNamespace:            liveTrafficNS,
				TargetNodeName:          "pm-control",
				Mode:                    pmv1.MigrationModePreCopy,
				TCPPreservationMode:     pmv1.TCPPreservationModeNone,
				PreCopyMaxRounds:        5,
				PreCopyDirtyThresholdMB: 16,
				CompletionTimeoutSeconds: 600,
			},
		}
		Expect(pmClient.Create(ctx, pm)).To(Succeed())

		By("waiting for migration to reach Complete or Failed")
		var finalPM pmv1.PodMigration
		err := wait.PollUntilContextTimeout(ctx, liveTrafficPoll, liveTrafficTimeout, true,
			func(ctx context.Context) (bool, error) {
				if err := pmClient.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, &finalPM); err != nil {
					return false, nil
				}
				GinkgoWriter.Printf("  phase=%s\n", finalPM.Status.Phase)
				switch finalPM.Status.Phase {
				case pmv1.MigrationPhaseComplete:
					return true, nil
				case pmv1.MigrationPhaseFailed:
					return false, fmt.Errorf("migration reached Failed phase")
				}
				return false, nil
			})
		Expect(err).NotTo(HaveOccurred(), "migration must reach Complete")

		By("recording post-migration error counts (econ + dreq)")
		econAfter, dreqAfter := haproxyErrorSnapshot(ctx, pmClient)
		econDuring := econAfter - econBefore
		dreqDuring := dreqAfter - dreqBefore
		errsDuring := econDuring + dreqDuring
		GinkgoWriter.Printf("HAProxy during migration: econ_delta=%d dreq_delta=%d total=%d\n",
			econDuring, dreqDuring, errsDuring)

		By("cross-checking traffic-gen pod logs for client-side errors")
		genLogs, _ := exec.Command("kubectl", "logs", "traffic-gen", "-n", liveTrafficNS).Output()
		clientErrors := countErrorLines(string(genLogs))
		GinkgoWriter.Printf("Traffic-gen client errors: %d\n", clientErrors)
		// Combined signal: HAProxy sees the backend side, traffic-gen sees the client side.
		// Both must be zero for full connection continuity (NS#5 gate).
		totalSignal := errsDuring + int64(clientErrors)
		if totalSignal > 0 {
			GinkgoWriter.Printf("BASELINE: haproxy=%d client=%d total=%d (expected until NS#5 TCP_REPAIR)\n",
				errsDuring, clientErrors, totalSignal)
		} else {
			GinkgoWriter.Printf("EXCELLENT: zero errors on both HAProxy and client side\n")
		}

		if finalPM.Status.PreCopyStats != nil {
			GinkgoWriter.Printf("PreCopy rounds=%d finalDirtyMB=%d freezeMs=%d\n",
				finalPM.Status.PreCopyStats.RoundsCompleted,
				finalPM.Status.PreCopyStats.FinalDirtyPagesMB,
				finalPM.Status.PreCopyStats.FreezeDurationMs)
		}
		GinkgoWriter.Printf("HAProxy errors during migration: econ_delta=%d dreq_delta=%d total=%d\n",
			econDuring, dreqDuring, errsDuring)

		By("asserting replacement pod is Running on pm-control")
		var replacement corev1.Pod
		Expect(pmClient.Get(ctx, types.NamespacedName{
			Name: finalPM.Status.ReplacementPodName, Namespace: liveTrafficNS,
		}, &replacement)).To(Succeed())
		Expect(replacement.Spec.NodeName).To(Equal("pm-control"))
		Expect(replacement.Status.Phase).To(Equal(corev1.PodRunning))

		By("asserting pre-copy ran at least one round")
		Expect(finalPM.Status.PreCopyStats).NotTo(BeNil())
		Expect(finalPM.Status.PreCopyStats.RoundsCompleted).To(BeNumerically(">=", 1))

		By("asserting EndpointSliceCleanupVerified=True")
		var esCond *metav1.Condition
		for i := range finalPM.Status.Conditions {
			if finalPM.Status.Conditions[i].Type == "EndpointSliceCleanupVerified" {
				esCond = &finalPM.Status.Conditions[i]
				break
			}
		}
		Expect(esCond).NotTo(BeNil(), "EndpointSliceCleanupVerified condition must be set")
		Expect(esCond.Status).To(Equal(metav1.ConditionTrue))

		// Phase 1: record errors, don't gate on them (TCP_REPAIR not yet implemented — NS#5).
		// When NS#5 lands, change to: Expect(errsDuring).To(Equal(int64(0)))
		if errsDuring > 0 {
			GinkgoWriter.Printf("BASELINE: %d TCP error(s) during freeze window (expected until NS#5 TCP_REPAIR)\n", errsDuring)
		} else {
			GinkgoWriter.Printf("EXCELLENT: zero TCP errors — connection continuity maintained\n")
		}
	})

	It("routes traffic to replacement pod after migration", Label("live-post-routing"), func() {
		var pm pmv1.PodMigration
		Expect(pmClient.Get(ctx, types.NamespacedName{Name: "nginx-live-migration", Namespace: liveTrafficNS}, &pm)).To(Succeed())

		var replacement corev1.Pod
		Expect(pmClient.Get(ctx, types.NamespacedName{Name: pm.Status.ReplacementPodName, Namespace: liveTrafficNS}, &replacement)).To(Succeed())

		haproxyIP := getHAProxyIP(ctx, pmClient)
		successCount := 0
		for i := 0; i < 10; i++ {
			resp, err := http.Get(fmt.Sprintf("http://%s:8080/", haproxyIP))
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(body), replacement.Name) {
				successCount++
			}
		}
		GinkgoWriter.Printf("Replacement pod answered %d/10 requests\n", successCount)
		Expect(successCount).To(BeNumerically(">=", 8))
	})
})

func getHAProxyIP(ctx context.Context, c client.Client) string {
	GinkgoHelper()
	svc := &corev1.Service{}
	Expect(c.Get(ctx, types.NamespacedName{Name: "haproxy-tcp-svc", Namespace: liveTrafficNS}, svc)).To(Succeed())
	return svc.Spec.ClusterIP
}

// haproxyErrorSnapshot reads HAProxy CSV stats and returns (econ, dreq) totals.
// econ = backend connection errors (HAProxy→pod failed).
// dreq = requests denied because no backend was available (mid-flight reset window).
// Both must be zero for connection continuity to be proved; econ alone misses
// client-side resets that occur when the pod TCP stack is restored from checkpoint.
// Returns (-1, -1) if the stats endpoint is unreachable.
func haproxyErrorSnapshot(ctx context.Context, c client.Client) (int64, int64) {
	ip := getHAProxyIP(ctx, c)
	url := fmt.Sprintf("http://%s:9090/stats;csv", ip)

	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get(url)
	if err != nil {
		GinkgoWriter.Printf("HAProxy stats unreachable: %v\n", err)
		return -1, -1
	}
	defer resp.Body.Close()

	r := csv.NewReader(resp.Body)
	r.Comment = '#'
	records, err := r.ReadAll()
	if err != nil || len(records) < 2 {
		return -1, -1
	}

	econIdx, dreqIdx := -1, -1
	for i, h := range records[0] {
		switch strings.TrimSpace(h) {
		case "econ":
			econIdx = i
		case "dreq":
			dreqIdx = i
		}
	}
	if econIdx < 0 || dreqIdx < 0 {
		GinkgoWriter.Printf("HAProxy CSV missing econ or dreq column (headers: %v)\n", records[0])
		return -1, -1
	}

	var totalEcon, totalDreq int64
	for _, row := range records[1:] {
		if econIdx < len(row) {
			if n, err := strconv.ParseInt(strings.TrimSpace(row[econIdx]), 10, 64); err == nil {
				totalEcon += n
			}
		}
		if dreqIdx < len(row) {
			if n, err := strconv.ParseInt(strings.TrimSpace(row[dreqIdx]), 10, 64); err == nil {
				totalDreq += n
			}
		}
	}
	return totalEcon, totalDreq
}

// haproxyErrors is a convenience wrapper returning the combined econ+dreq total.
func haproxyErrors(ctx context.Context, c client.Client) int64 {
	econ, dreq := haproxyErrorSnapshot(ctx, c)
	if econ < 0 || dreq < 0 {
		return -1
	}
	return econ + dreq
}
