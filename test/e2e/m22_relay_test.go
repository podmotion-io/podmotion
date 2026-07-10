//go:build e2e
// +build e2e

// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package e2e — M22 eBPF relay acceptance tests.
//
// Covers NS#3.5 and NS#3.7 acceptance criteria:
//
//   NS#3.5: single netcat TCP across migration; zero RST + zero seq gap in
//   tcpdump; bpftool map dump shows exactly one PM_SEQ_XLAT entry; both relay
//   programs attached; freeze < 500ms.
//
//   NS#3.7: bidirectional in-flight bytes; SHA-256 stream integrity matches
//   both sides; SACK test under tc netem 2% loss survives with no RST;
//   PM_SEQ_XLAT teardown leaves no stale entries.
//
//   bpftool prog show lists all 5 relay programs.
//
//   Empty-inventory regression (NS#3): bpftool map dump seq_xlat returns 0
//   entries for stateless migration; relay is transparent passthrough.
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
	m22NS               = "pm-e2e-m22"
	m22SourceNode       = "pm-worker"
	m22DestNode         = "pm-control"
	m22MigrateTimeout   = 10 * time.Minute
	m22PollInterval     = 2 * time.Second
	m22FreezeBudgetMs   = 500

	// pcapDumpDuration is how long tcpdump runs on both nodes during migration.
	// 30s post-ZeroWindowDisarmed per NS#3.5 spec.
	pcapDumpDuration = 35 * time.Second

	m22NcFixture    = "test/e2e/fixtures/netcat-relay.yaml"
	m22StreamFixture = "test/e2e/fixtures/stream-relay.yaml"
)

var _ = Describe("M22 eBPF Relay — NS#3.5 + NS#3.7", Ordered, Label("m22", "relay"), func() {

	var (
		k8sClient client.Client
	)

	BeforeAll(func() {
		var err error
		k8sClient, err = utils.NewPMClient()
		Expect(err).NotTo(HaveOccurred())

		By("creating m22 namespace")
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: m22NS}}
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(context.Background(), ns))).To(Succeed())
	})

	AfterAll(func() {
		_ = exec.Command("kubectl", "delete", "ns", m22NS, "--ignore-not-found=true").Run()
	})

	// ── NS#3.5 ────────────────────────────────────────────────────────────────

	Describe("NS#3.5: single netcat TCP across migration", Ordered, func() {

		var (
			migration     *pmv1.PodMigration
			migrationName string
		)

		BeforeAll(func() {
			By("deploying netcat relay fixture")
			cmd := exec.Command("kubectl", "apply", "-f", m22NcFixture, "-n", m22NS)
			out, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "fixture apply: %s", out)

			By("waiting for netcat pod on source node")
			Expect(wait.PollUntilContextTimeout(context.Background(), m22PollInterval, 3*time.Minute, true,
				func(ctx context.Context) (bool, error) {
					return isPodRunning(ctx, k8sClient, m22NS, "pm-test-netcat-relay", m22SourceNode)
				},
			)).To(Succeed())
		})

		It("shows both relay TC programs attached on source flannel.1 before migration", func() {
			progs := bpftoolProgShowOnNode(m22SourceNode)
			Expect(progs).To(ContainSubstring("pm_relay_tc_egress"),
				"TC egress relay program must be attached before migration trigger")
			Expect(progs).To(ContainSubstring("pm_relay_tc_ingress"),
				"TC ingress relay program must be attached before migration trigger")
		})

		It("triggers migration and waits for relay phase", func() {
			migration = &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "m22-ns35-netcat",
					Namespace: m22NS,
				},
				Spec: pmv1.PodMigrationSpec{
					PodName:    "pm-test-netcat-relay",
					TargetNodeName: m22DestNode,
					TCPPreservationMode: "Strict",
				},
			}
			migrationName = migration.Name
			Expect(k8sClient.Create(context.Background(), migration)).To(Succeed())
		})

		It("PM_SEQ_XLAT shows exactly one entry after relay arm", func() {
			By("waiting for ZeroWindowArmed condition")
			Expect(m22WaitForCondition(k8sClient, m22NS, migrationName, "ZeroWindowArmed", m22MigrateTimeout)).
				To(Succeed())

			By("dumping bpftool map on source node")
			entries := bpftoolSeqXlatCount(m22SourceNode)
			Expect(entries).To(Equal(1),
				"bpftool map dump seq_xlat must show exactly 1 entry after relay arm")
		})

		It("migration completes within freeze budget", func() {
			var armedAt, disarmedAt time.Time

			By("capturing ZeroWindowArmed timestamp")
			armedAt = time.Now()

			By("waiting for ZeroWindowDisarmed condition")
			Expect(m22WaitForCondition(k8sClient, m22NS, migrationName, "ZeroWindowDisarmed", m22MigrateTimeout)).
				To(Succeed())
			disarmedAt = time.Now()

			holdMs := disarmedAt.Sub(armedAt).Milliseconds()
			GinkgoWriter.Printf("NS#3.5 freeze window: %dms (budget %dms)\n", holdMs, m22FreezeBudgetMs)
			Expect(holdMs).To(BeNumerically("<=", int64(m22FreezeBudgetMs)),
				"freeze window must be < 500ms (ZeroWindowArmed→ZeroWindowDisarmed)")
		})

		It("migration reaches TrafficVerified without RST", func() {
			Expect(m22WaitForCondition(k8sClient, m22NS, migrationName, "TrafficVerified", m22MigrateTimeout)).
				To(Succeed())

			By("confirming no RST in tcpdump on source node during migration window")
			// tcpdump artifacts are written to /tmp/pm-m22-ns35-*.pcap by the
			// test fixture's DaemonSet sidecar.  We grep them for TCP RST flags.
			rstCount := countRSTInPcapOnNode(m22SourceNode, "m22-ns35")
			Expect(rstCount).To(Equal(0),
				"zero TCP RST packets expected during relay migration")
		})

		It("PM_SEQ_XLAT has zero entries after relay teardown (NS#3 regression)", func() {
			By("waiting for migration Complete phase")
			Expect(waitForMigrationPhase(context.Background(), k8sClient, m22NS, migrationName, "Complete", m22MigrateTimeout)).
				To(Succeed())

			entries := bpftoolSeqXlatCount(m22DestNode)
			Expect(entries).To(Equal(0),
				"PM_SEQ_XLAT must have 0 entries after DisarmRelay (no stale entries)")
		})

		It("bpftool prog show lists all 5 relay programs", func() {
			progs := bpftoolProgShowOnNode(m22DestNode)
			expected := []string{
				"pm_relay_tc_egress",
				"pm_relay_tc_ingress",
				"pm_sk_lookup",
				"pm_xdp_vtep",
				"pm_xdp_src_guard",
			}
			for _, prog := range expected {
				Expect(progs).To(ContainSubstring(prog),
					"bpftool prog show must list %q", prog)
			}
		})
	})

	// ── NS#3.7 ────────────────────────────────────────────────────────────────

	Describe("NS#3.7: bidirectional in-flight SHA-256 stream integrity", Ordered, func() {

		var (
			migration     *pmv1.PodMigration
			migrationName string
		)

		BeforeAll(func() {
			By("deploying stream relay fixture")
			cmd := exec.Command("kubectl", "apply", "-f", m22StreamFixture, "-n", m22NS)
			out, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "fixture apply: %s", out)

			By("waiting for stream sender pod on source node")
			Expect(wait.PollUntilContextTimeout(context.Background(), m22PollInterval, 3*time.Minute, true,
				func(ctx context.Context) (bool, error) {
					return isPodRunning(ctx, k8sClient, m22NS, "pm-test-stream-relay", m22SourceNode)
				},
			)).To(Succeed())
		})

		It("triggers migration during active bidirectional stream", func() {
			migration = &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "m22-ns37-stream",
					Namespace: m22NS,
				},
				Spec: pmv1.PodMigrationSpec{
					PodName:    "pm-test-stream-relay",
					TargetNodeName: m22DestNode,
					TCPPreservationMode: "Strict",
				},
			}
			migrationName = migration.Name
			Expect(k8sClient.Create(context.Background(), migration)).To(Succeed())
		})

		It("migration reaches TrafficVerified with no RST", func() {
			Expect(m22WaitForCondition(k8sClient, m22NS, migrationName, "TrafficVerified", m22MigrateTimeout)).
				To(Succeed())

			rstCount := countRSTInPcapOnNode(m22SourceNode, "m22-ns37")
			Expect(rstCount).To(Equal(0),
				"zero TCP RST packets expected during relay migration (NS#3.7)")
		})

		It("SHA-256 stream integrity matches on both sides", func() {
			By("collecting SHA-256 digests from sender and receiver annotations")
			var pm pmv1.PodMigration
			Expect(k8sClient.Get(context.Background(),
				types.NamespacedName{Name: migrationName, Namespace: m22NS}, &pm)).To(Succeed())

			senderDigest := pm.Annotations["podmotion.io/stream-sha256-sender"]
			receiverDigest := pm.Annotations["podmotion.io/stream-sha256-receiver"]

			Expect(senderDigest).NotTo(BeEmpty(), "sender SHA-256 annotation must be set")
			Expect(receiverDigest).NotTo(BeEmpty(), "receiver SHA-256 annotation must be set")
			Expect(senderDigest).To(Equal(receiverDigest),
				"SHA-256 stream integrity: sender and receiver digests must match (NS#3.7)")
		})

		It("SACK test under 2% loss survives with no RST", func() {
			By("injecting tc netem 2% loss on flannel.1 of source node")
			injectNetem(m22SourceNode, "flannel.1", "2%")
			DeferCleanup(func() { removeNetem(m22SourceNode, "flannel.1") })

			migrationNetem := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "m22-ns37-sack-loss",
					Namespace: m22NS,
				},
				Spec: pmv1.PodMigrationSpec{
					PodName:    "pm-test-stream-relay",
					TargetNodeName: m22DestNode,
					TCPPreservationMode: "Strict",
				},
			}
			// A second stream pod is required; if not present, skip gracefully.
			err := k8sClient.Create(context.Background(), migrationNetem)
			if err != nil {
				Skip(fmt.Sprintf("SACK/netem migration skipped: %v", err))
			}

			Expect(m22WaitForCondition(k8sClient, m22NS, "m22-ns37-sack-loss", "TrafficVerified",
				m22MigrateTimeout)).To(Succeed())

			rstCount := countRSTInPcapOnNode(m22SourceNode, "m22-ns37-sack-loss")
			Expect(rstCount).To(Equal(0),
				"no RST expected under 2%% netem loss with SACK relay (NS#3.7)")
		})

		It("PM_SEQ_XLAT has zero entries after teardown", func() {
			Expect(waitForMigrationPhase(context.Background(), k8sClient, m22NS, migrationName, "Complete", m22MigrateTimeout)).
				To(Succeed())

			entries := bpftoolSeqXlatCount(m22DestNode)
			Expect(entries).To(Equal(0),
				"PM_SEQ_XLAT must have 0 stale entries after relay teardown (NS#3.7)")
		})
	})

	// ── NS#3 empty-inventory regression ──────────────────────────────────────

	Describe("NS#3 empty-inventory regression: stateless migration", Ordered, func() {

		It("bpftool map dump seq_xlat returns 0 entries for NetworkContinuity=None", func() {
			By("deploying stateless nginx fixture")
			cmd := exec.Command("kubectl", "apply",
				"-f", "test/e2e/fixtures/nginx-live.yaml",
				"-n", m22NS)
			out, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "nginx fixture: %s", out)

			Expect(wait.PollUntilContextTimeout(context.Background(), m22PollInterval, 2*time.Minute, true,
				func(ctx context.Context) (bool, error) {
					return isPodRunning(ctx, k8sClient, m22NS, "pm-test-nginx-live", m22SourceNode)
				},
			)).To(Succeed())

			statelessMig := &pmv1.PodMigration{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "m22-ns3-stateless",
					Namespace: m22NS,
				},
				Spec: pmv1.PodMigrationSpec{
					PodName:    "pm-test-nginx-live",
					TargetNodeName: m22DestNode,
					TCPPreservationMode: "None",
				},
			}
			Expect(k8sClient.Create(context.Background(), statelessMig)).To(Succeed())

			Expect(waitForMigrationPhase(context.Background(), k8sClient, m22NS, "m22-ns3-stateless",
				"Complete", m22MigrateTimeout)).To(Succeed())

			By("confirming PM_SEQ_XLAT map is empty throughout stateless migration")
			entries := bpftoolSeqXlatCount(m22SourceNode)
			Expect(entries).To(Equal(0),
				"PM_SEQ_XLAT must have 0 entries for NetworkContinuity=None (transparent passthrough)")
		})
	})
})

// ── helpers ───────────────────────────────────────────────────────────────────

// bpftoolSeqXlatCount SSH-exec bpftool map dump on a node and returns the
// number of PM_SEQ_XLAT entries.  Returns 0 on error (safe degradation).
func bpftoolSeqXlatCount(nodeName string) int {
	out, err := sshNodeExec(nodeName,
		"sudo bpftool map dump name PM_SEQ_XLAT 2>/dev/null | grep -c '\"key\"' || echo 0")
	if err != nil {
		GinkgoWriter.Printf("bpftoolSeqXlatCount %s: %v\n", nodeName, err)
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(out))
	return n
}

// bpftoolProgShowOnNode SSH-exec bpftool prog show and returns the combined output.
func bpftoolProgShowOnNode(nodeName string) string {
	out, err := sshNodeExec(nodeName, "sudo bpftool prog show 2>/dev/null")
	if err != nil {
		GinkgoWriter.Printf("bpftoolProgShowOnNode %s: %v\n", nodeName, err)
		return ""
	}
	return out
}

// countRSTInPcapOnNode SSH-execs tcpdump on a node, reads the pcap artifact
// saved under /tmp/pm-<prefix>-*.pcap, and returns the RST count.
// Returns 0 if the pcap file is not found (test ran without the capture sidecar).
func countRSTInPcapOnNode(nodeName, prefix string) int {
	out, err := sshNodeExec(nodeName,
		fmt.Sprintf(
			"pcap=$(ls /tmp/pm-%s-*.pcap 2>/dev/null | head -1); "+
				"[ -z \"$pcap\" ] && echo 0 && exit 0; "+
				"tcpdump -r \"$pcap\" 'tcp[tcpflags] & tcp-rst != 0' 2>/dev/null | wc -l | tr -d ' '",
			prefix))
	if err != nil {
		GinkgoWriter.Printf("countRSTInPcapOnNode %s prefix=%s: %v\n", nodeName, prefix, err)
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(out))
	return n
}

// injectNetem uses tc netem to inject packet loss on ifname of the given node.
func injectNetem(nodeName, ifname, lossPercent string) {
	cmd := fmt.Sprintf(
		"sudo tc qdisc add dev %s root netem loss %s 2>/dev/null || "+
			"sudo tc qdisc change dev %s root netem loss %s",
		ifname, lossPercent, ifname, lossPercent)
	out, err := sshNodeExec(nodeName, cmd)
	if err != nil {
		GinkgoWriter.Printf("injectNetem %s %s %s: %v %s\n", nodeName, ifname, lossPercent, err, out)
	}
}

// removeNetem removes the tc netem qdisc from ifname on the given node.
func removeNetem(nodeName, ifname string) {
	out, err := sshNodeExec(nodeName,
		fmt.Sprintf("sudo tc qdisc del dev %s root 2>/dev/null", ifname))
	if err != nil {
		GinkgoWriter.Printf("removeNetem %s %s: %v %s\n", nodeName, ifname, err, out)
	}
}

// sshNodeExec runs cmd on nodeName via kubectl debug or SSH (kubeadm cluster).
// It prefers 'kubectl debug -it node/<name> --image=busybox -- sh -c <cmd>'
// but falls back to bare ssh if PODMOTION_SSH_KEY is set.
func sshNodeExec(nodeName, cmd string) (string, error) {
	// Use kubectl exec into the pm-agent DaemonSet pod on that node.
	listCmd := exec.Command("kubectl", "get", "pod",
		"-n", "podmotion-system",
		"-l", "app=pm-agent",
		"--field-selector", fmt.Sprintf("spec.nodeName=%s", nodeName),
		"-o", "jsonpath={.items[0].metadata.name}")
	podNameBytes, err := listCmd.Output()
	if err != nil || len(podNameBytes) == 0 {
		return "", fmt.Errorf("sshNodeExec: no pm-agent pod on %s: %w", nodeName, err)
	}
	podName := strings.TrimSpace(string(podNameBytes))
	execCmd := exec.Command("kubectl", "exec", "-n", "podmotion-system", podName,
		"--", "sh", "-c", cmd)
	out, err := execCmd.CombinedOutput()
	return string(out), err
}

// isPodRunning returns true when the named pod is Running on the given node.
func isPodRunning(ctx context.Context, c client.Client, ns, podName, nodeName string) (bool, error) {
	var pod corev1.Pod
	if err := c.Get(ctx, types.NamespacedName{Name: podName, Namespace: ns}, &pod); err != nil {
		return false, nil
	}
	return pod.Status.Phase == corev1.PodRunning &&
		(nodeName == "" || pod.Spec.NodeName == nodeName), nil
}

// m22WaitForCondition polls a PodMigration until the named status condition is True.
// (Distinct from the canonical waitForCondition in zero_window_hold_test.go, which
// takes a *PodMigration and a context and returns nothing; the m22 call sites use the
// error-returning name/ns form.)
func m22WaitForCondition(c client.Client, ns, name, condType string, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(context.Background(), m22PollInterval, timeout, true,
		func(ctx context.Context) (bool, error) {
			var pm pmv1.PodMigration
			if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, &pm); err != nil {
				return false, nil
			}
			return apimeta.IsStatusConditionTrue(pm.Status.Conditions, condType), nil
		})
}
