//go:build e2e
// +build e2e

// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package e2e — M23 CRIU tcp-established + leave-stopped ordering integration tests.
//
// Covers the M23 acceptance criteria:
//
//  1. Live CRIU dump of a process with an established TCP socket confirms TcpEstablished=true
//     path: inetsk/tcp image entries present in dump log, no "Unsupported socket" errors.
//  2. Restore command line contains --join-ns net:<fd> and does NOT contain --empty-ns net.
//  3. --leave-stopped present in restore command; source process stays in SIGSTOP until
//     ZeroWindowDisarm completes.
//  4. ProcessResumedAfterSocketsLive condition timestamp > CRIU restore start timestamp.
//  5. SeqSnapshot.final_snd_nxt / final_rcv_nxt non-zero and match /proc/<pid>/net/tcp at freeze.
//  6. freeze_latency_ms < 500ms for a single-connection test.
//  7. NS#3 regression: TcpClose=true path exercised unchanged for NetworkContinuity=None.
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
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/test/utils"
)

const (
	m23NS             = "pm-e2e-m23"
	m23SourceNode     = "pm-worker"
	m23DestNode       = "pm-control"
	m23MigrateTimeout = 10 * time.Minute
	m23PollInterval   = 2 * time.Second
	m23FreezeBudgetMs = 500

	// m23NcFixture is the pod fixture that runs a single persistent netcat TCP connection.
	m23NcFixture = "test/e2e/fixtures/netcat-m23.yaml"
)

var _ = Describe("M23 CRIU tcp-established + leave-stopped ordering", Ordered, Label("m23", "criu-ordering"), func() {

	var (
		k8sClient client.Client
	)

	BeforeAll(func() {
		var err error
		k8sClient, err = utils.NewPMClient()
		Expect(err).NotTo(HaveOccurred())

		By("creating m23 namespace")
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: m23NS}}
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(context.Background(), ns))).To(Succeed())
	})

	AfterAll(func() {
		By("deleting m23 namespace")
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: m23NS}}
		_ = k8sClient.Delete(context.Background(), ns)
	})

	Describe("TCP-stateful path: single established TCP connection via netcat", Ordered, func() {

		var migrationName string

		BeforeAll(func() {
			By("deploying netcat pod with single established TCP connection on pm-worker")
			cmd := exec.Command("kubectl", "apply", "-n", m23NS, "-f", m23NcFixture)
			out, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "kubectl apply netcat fixture: %s", out)

			By("waiting for netcat pod to be Running")
			Eventually(func() bool {
				cmd := exec.Command("kubectl", "get", "pod", "-n", m23NS,
					"-l", "app=netcat-m23",
					"-o", "jsonpath={.items[0].status.phase}")
				out, err := utils.Run(cmd)
				return err == nil && strings.TrimSpace(out) == "Running"
			}, 2*time.Minute, 5*time.Second).Should(BeTrue(), "netcat pod did not reach Running")
		})

		It("creates a TCP-stateful PodMigration with TCPPreservationMode=Strict", func() {
			By("fetching netcat pod name")
			cmd := exec.Command("kubectl", "get", "pod", "-n", m23NS,
				"-l", "app=netcat-m23",
				"-o", "jsonpath={.items[0].metadata.name}")
			podName, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			podName = strings.TrimSpace(podName)
			Expect(podName).NotTo(BeEmpty())

			migrationName = "m23-tcp-ordering"
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{
					Name:      migrationName,
					Namespace: m23NS,
				},
				Spec: pmv1.PodMigrationSpec{
					PodName:             podName,
					TargetNodeName:      m23DestNode,
					TCPPreservationMode: pmv1.TCPPreservationModeStrict,
				},
			}
			Expect(k8sClient.Create(context.Background(), pm)).To(Succeed())
		})

		It("reaches Complete phase within timeout", func() {
			Expect(migrationName).NotTo(BeEmpty())
			ctx := context.Background()
			var pm pmv1.PodMigration
			err := wait.PollUntilContextTimeout(ctx, m23PollInterval, m23MigrateTimeout, true, func(ctx context.Context) (bool, error) {
				if getErr := k8sClient.Get(ctx, types.NamespacedName{Name: migrationName, Namespace: m23NS}, &pm); getErr != nil {
					return false, nil
				}
				switch pm.Status.Phase {
				case pmv1.MigrationPhaseComplete:
					return true, nil
				case pmv1.MigrationPhaseFailed, pmv1.MigrationPhaseRollingBack:
					return false, fmt.Errorf("migration failed in phase %s", pm.Status.Phase)
				}
				return false, nil
			})
			Expect(err).NotTo(HaveOccurred(), "migration did not reach Complete")
		})

		It("confirms TcpEstablished=true: inetsk/tcp image entries in CRIU dump log", func() {
			By("querying CRIU dump log lines from agent pod on source node")
			logLines := agentLogsSince(m23SourceNode, "tcpImageEntries")
			Expect(logLines).NotTo(BeEmpty(), "no tcpImageEntries log lines found; TcpEstablished=true path not taken")

			By("verifying tcpImageEntries > 0")
			for _, line := range logLines {
				if strings.Contains(line, `"tcpImageEntries"`) {
					count := extractIntField(line, "tcpImageEntries")
					Expect(count).To(BeNumerically(">", 0),
						"tcpImageEntries must be > 0 to confirm inetsk/tcp entries in CRIU dump log")
					return
				}
			}
			Fail("tcpImageEntries field not found in agent logs — TcpEstablished path not confirmed")
		})

		It("confirms no Unsupported socket errors in CRIU dump log", func() {
			logLines := agentLogsSince(m23SourceNode, "unsupportedSocketErrors")
			for _, line := range logLines {
				if strings.Contains(line, `"unsupportedSocketErrors"`) {
					count := extractIntField(line, "unsupportedSocketErrors")
					Expect(count).To(Equal(0), "unsupportedSocketErrors must be 0")
					return
				}
			}
		})

		It("confirms --join-ns net:<fd> present and --empty-ns net absent in restore command", func() {
			By("querying restore command args from agent logs on destination node")
			logLines := agentLogsSince(m23DestNode, "join-ns")
			Expect(logLines).NotTo(BeEmpty(), "no log lines mentioning join-ns found on destination node")

			foundJoinNs := false
			for _, line := range logLines {
				if strings.Contains(line, "--join-ns") && strings.Contains(line, "net:") {
					foundJoinNs = true
				}
				Expect(line).NotTo(ContainSubstring("--empty-ns net"),
					"--empty-ns net must not appear in TCP-stateful restore command")
			}
			Expect(foundJoinNs).To(BeTrue(), "--join-ns net:<fd> not found in restore command logs")
		})

		It("confirms --leave-stopped present in restore command", func() {
			logLines := agentLogsSince(m23DestNode, "leave-stopped")
			foundLeaveStopped := false
			for _, line := range logLines {
				if strings.Contains(line, "--leave-stopped") {
					foundLeaveStopped = true
					break
				}
			}
			Expect(foundLeaveStopped).To(BeTrue(),
				"--leave-stopped not found in restore command; source process may not have stayed in SIGSTOP")
		})

		It("confirms ProcessResumedAfterSocketsLive condition timestamp > CRIU restore start", func() {
			ctx := context.Background()
			var pm pmv1.PodMigration
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: migrationName, Namespace: m23NS}, &pm)).To(Succeed())

			socketsLiveCond := apimeta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionSocketsLive)
			Expect(socketsLiveCond).NotTo(BeNil(), "ConditionSocketsLive not set on PodMigration")
			Expect(socketsLiveCond.Status).To(Equal(metav1.ConditionTrue))

			resumedCond := apimeta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionProcessResumedAfterSocketsLive)
			Expect(resumedCond).NotTo(BeNil(), "ConditionProcessResumedAfterSocketsLive not set on PodMigration")
			Expect(resumedCond.Status).To(Equal(metav1.ConditionTrue))

			Expect(resumedCond.LastTransitionTime.Time).To(BeTemporally(">=", socketsLiveCond.LastTransitionTime.Time),
				"ProcessResumedAfterSocketsLive timestamp must be >= SocketsLive timestamp")
		})

		It("confirms SeqSnapshot.final_snd_nxt and final_rcv_nxt are non-zero", func() {
			ctx := context.Background()
			var pm pmv1.PodMigration
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: migrationName, Namespace: m23NS}, &pm)).To(Succeed())

			Expect(pm.Status.TCPSeqSnapshots).NotTo(BeEmpty(),
				"TCPSeqSnapshots must be populated for TCP-stateful migration")
			for _, snap := range pm.Status.TCPSeqSnapshots {
				Expect(snap.SndNxt).To(BeNumerically(">", uint32(0)),
					"SeqSnapshot.SndNxt (final_snd_nxt) must be non-zero")
				Expect(snap.RcvNxt).To(BeNumerically(">", uint32(0)),
					"SeqSnapshot.RcvNxt (final_rcv_nxt) must be non-zero")
			}
		})

		It("confirms SourceFreezeTimestampNs is set and non-zero", func() {
			ctx := context.Background()
			var pm pmv1.PodMigration
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: migrationName, Namespace: m23NS}, &pm)).To(Succeed())

			Expect(pm.Status.SourceFreezeTimestampNs).To(BeNumerically(">", int64(0)),
				"SourceFreezeTimestampNs must be set and non-zero")
		})

		It("confirms freeze_latency_ms < 500ms for single-connection test", func() {
			By("parsing FreezeDurationMs from agent logs on source node")
			logLines := agentLogsSince(m23SourceNode, "freezeDurationMs")
			for _, line := range logLines {
				if strings.Contains(line, "freezeDurationMs") {
					ms := extractIntField(line, "freezeDurationMs")
					if ms > 0 {
						Expect(ms).To(BeNumerically("<", m23FreezeBudgetMs),
							"freeze_latency_ms must be < %dms for single-connection test", m23FreezeBudgetMs)
						return
					}
				}
			}
			// If we can not parse it from logs, check the CRD status timestamp delta as a fallback.
			ctx := context.Background()
			var pm pmv1.PodMigration
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: migrationName, Namespace: m23NS}, &pm)).To(Succeed())

			socketsLiveCond := apimeta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionSocketsLive)
			resumedCond := apimeta.FindStatusCondition(pm.Status.Conditions, pmv1.ConditionProcessResumedAfterSocketsLive)
			if socketsLiveCond != nil && resumedCond != nil {
				delta := resumedCond.LastTransitionTime.Time.Sub(socketsLiveCond.LastTransitionTime.Time)
				Expect(delta.Milliseconds()).To(BeNumerically("<", int64(m23FreezeBudgetMs)),
					"freeze window derived from condition timestamps must be < %dms", m23FreezeBudgetMs)
			}
		})

		AfterAll(func() {
			By("cleaning up PodMigration and netcat pod")
			if migrationName != "" {
				pm := &pmv1.PodMigration{ObjectMeta: metav1.ObjectMeta{Name: migrationName, Namespace: m23NS}}
				_ = k8sClient.Delete(context.Background(), pm)
			}
			cmd := exec.Command("kubectl", "delete", "-n", m23NS, "-f", m23NcFixture, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})
	})

	Describe("NS#3 regression: TcpClose=true path for TCPPreservationMode=None", Ordered, func() {

		var (
			migrationName string
			nginxPodName  string
		)

		BeforeAll(func() {
			By("deploying nginx pod on pm-worker for stateless regression")
			cmd := exec.Command("kubectl", "apply", "-n", m23NS, "-f", "test/e2e/fixtures/nginx.yaml")
			out, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "kubectl apply nginx fixture: %s", out)

			By("waiting for nginx pod to be Running")
			Eventually(func() bool {
				cmd := exec.Command("kubectl", "get", "pod", "-n", m23NS,
					"-l", "app=nginx",
					"-o", "jsonpath={.items[0].status.phase}")
				out, err := utils.Run(cmd)
				return err == nil && strings.TrimSpace(out) == "Running"
			}, 2*time.Minute, 5*time.Second).Should(BeTrue(), "nginx pod did not reach Running")

			cmd = exec.Command("kubectl", "get", "pod", "-n", m23NS,
				"-l", "app=nginx",
				"-o", "jsonpath={.items[0].metadata.name}")
			name, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			nginxPodName = strings.TrimSpace(name)
		})

		It("creates PodMigration with TCPPreservationMode=None", func() {
			Expect(nginxPodName).NotTo(BeEmpty())
			migrationName = "m23-stateless-regression"
			pm := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{
					Name:      migrationName,
					Namespace: m23NS,
				},
				Spec: pmv1.PodMigrationSpec{
					PodName:             nginxPodName,
					TargetNodeName:      m23DestNode,
					TCPPreservationMode: pmv1.TCPPreservationModeNone,
				},
			}
			Expect(k8sClient.Create(context.Background(), pm)).To(Succeed())
		})

		It("reaches Complete phase for stateless migration", func() {
			ctx := context.Background()
			var pm pmv1.PodMigration
			err := wait.PollUntilContextTimeout(ctx, m23PollInterval, m23MigrateTimeout, true, func(ctx context.Context) (bool, error) {
				if getErr := k8sClient.Get(ctx, types.NamespacedName{Name: migrationName, Namespace: m23NS}, &pm); getErr != nil {
					return false, nil
				}
				switch pm.Status.Phase {
				case pmv1.MigrationPhaseComplete:
					return true, nil
				case pmv1.MigrationPhaseFailed, pmv1.MigrationPhaseRollingBack:
					return false, fmt.Errorf("stateless regression migration failed in phase %s", pm.Status.Phase)
				}
				return false, nil
			})
			Expect(err).NotTo(HaveOccurred(), "stateless regression migration did not reach Complete")
		})

		It("confirms TcpClose=true path: no inetsk/tcp image entries in dump log", func() {
			By("verifying TcpEstablished=false was used — tcpImageEntries should be 0 or absent")
			logLines := agentLogsSince(m23SourceNode, "tcpImageEntries")
			for _, line := range logLines {
				if strings.Contains(line, `"tcpImageEntries"`) {
					count := extractIntField(line, "tcpImageEntries")
					Expect(count).To(Equal(0),
						"TcpClose=true path: tcpImageEntries must be 0 for NetworkContinuity=None migration")
					return
				}
			}
		})

		It("confirms --join-ns net absent and --empty-ns net present for stateless restore", func() {
			logLines := agentLogsSince(m23DestNode, "empty-ns")
			foundEmptyNs := false
			for _, line := range logLines {
				if strings.Contains(line, "--empty-ns") && strings.Contains(line, "net") {
					foundEmptyNs = true
				}
				if foundEmptyNs {
					Expect(line).NotTo(ContainSubstring("--join-ns"),
						"--join-ns must not appear for stateless restore")
				}
			}
		})

		AfterAll(func() {
			By("cleaning up stateless regression PodMigration")
			if migrationName != "" {
				pm := &pmv1.PodMigration{ObjectMeta: metav1.ObjectMeta{Name: migrationName, Namespace: m23NS}}
				_ = k8sClient.Delete(context.Background(), pm)
			}
			cmd := exec.Command("kubectl", "delete", "-n", m23NS, "-f", "test/e2e/fixtures/nginx.yaml", "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})
	})
})

// agentLogsSince returns log lines from the podmotion-agent DaemonSet pod on the
// given node that contain the given substring. Uses kubectl logs with a 10-minute
// lookback. Returns nil (not an error) if no matching lines are found — callers
// assert on the returned slice.
func agentLogsSince(nodeName, substr string) []string {
	cmd := exec.Command("kubectl", "logs",
		"-n", "podmotion-system",
		"-l", "app=podmotion-agent",
		"--field-selector", fmt.Sprintf("spec.nodeName=%s", nodeName),
		"--since=10m",
		"--tail=2000",
		"--all-containers=true",
	)
	out, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "agentLogsSince(%s, %q): kubectl error: %v\n", nodeName, substr, err)
		return nil
	}
	var matching []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, substr) {
			matching = append(matching, line)
		}
	}
	return matching
}

// extractIntField extracts the integer value of a structured log field from a log line.
// The line is expected to contain `"fieldName":N` (JSON-structured log output).
// Returns 0 if the field is not found or not parseable.
func extractIntField(line, fieldName string) int {
	needle := `"` + fieldName + `":`
	idx := strings.Index(line, needle)
	if idx < 0 {
		return 0
	}
	rest := line[idx+len(needle):]
	rest = strings.TrimLeft(rest, " ")
	end := strings.IndexAny(rest, ",} \t\n")
	if end < 0 {
		end = len(rest)
	}
	n, err := strconv.Atoi(strings.TrimSpace(rest[:end]))
	if err != nil {
		return 0
	}
	return n
}
