/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// TestCrossNodeReachability is the empirical check named by ADR-0324's
// verification check C (inherited unchanged from ADR-0322): it confirms whether the
// ipam.cilium.io/ip pinning annotation actually forces Cilium CNI ADD to
// assign a caller-specified pod IP under the standing cluster's real
// ipam.mode=cluster-pool configuration, and specifically whether that
// pinning survives when the destination pod is scheduled on a *different*
// node than the one that originally owned the IP's /24 cluster-pool
// allocation (the live-migration case).
//
// Gated behind PODMOTION_CILIUM_LIVE_TEST=1 because it requires a live
// cluster reachable via KUBECONFIG (or the standing KVM kubeconfig at
// $HOME/podmotion-kvm/kubeconfig by default) and creates/deletes real
// pods on it. It is intentionally NOT part of the default `go test ./...`
// run.
package iphandoff

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const liveTestNamespace = "default"

func TestCrossNodeReachability(t *testing.T) {
	if os.Getenv("PODMOTION_CILIUM_LIVE_TEST") != "1" {
		t.Skip("set PODMOTION_CILIUM_LIVE_TEST=1 to run against the live standing cluster")
	}

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			t.Fatalf("resolving home directory for default kubeconfig: %v", herr)
		}
		kubeconfig = filepath.Join(home, "podmotion-kvm", "kubeconfig")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("building kubeconfig from %s: %v", kubeconfig, err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building clientset: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// 1. Schedule a "source" pod on pm-w1, let cluster-pool IPAM assign it a
	// normal, unpinned IP. This is the IP we will attempt to pin onto a
	// second pod on a DIFFERENT node — mirroring what happens during a
	// live migration's IP handoff.
	srcName := fmt.Sprintf("iphandoff-src-%d", time.Now().UnixNano())
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: srcName, Namespace: liveTestNamespace},
		Spec: corev1.PodSpec{
			NodeName:      "pm-w1",
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:    "sleep",
				Image:   "busybox:1.36",
				Command: []string{"sleep", "300"},
			}},
		},
	}
	if _, err := client.CoreV1().Pods(liveTestNamespace).Create(ctx, srcPod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating source pod on pm-w1: %v", err)
	}
	defer client.CoreV1().Pods(liveTestNamespace).Delete(context.Background(), srcName, metav1.DeleteOptions{})

	srcIP, err := waitForPodIP(ctx, client, srcName)
	if err != nil {
		t.Fatalf("source pod never got an IP: %v", err)
	}
	t.Logf("source pod %s on pm-w1 assigned IP %s by cluster-pool IPAM", srcName, srcIP)

	// 2. Delete the source pod so its cluster-pool IP is released, then
	// create a "destination" pod on pm-w2 (a DIFFERENT node) carrying the
	// ipam.cilium.io/ip pinning annotation for that exact IP. This is the
	// real mechanism CiliumHandoff.AnnotateDestPodIPAM applies.
	if err := client.CoreV1().Pods(liveTestNamespace).Delete(ctx, srcName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("deleting source pod to release its IP: %v", err)
	}
	if err := waitForPodGone(ctx, client, srcName); err != nil {
		t.Fatalf("source pod did not terminate/release IP in time: %v", err)
	}

	dstName := fmt.Sprintf("iphandoff-dst-%d", time.Now().UnixNano())
	dstPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dstName,
			Namespace: liveTestNamespace,
			Annotations: map[string]string{
				"ipam.cilium.io/ip": srcIP,
			},
		},
		Spec: corev1.PodSpec{
			NodeName:      "pm-w2",
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:    "sleep",
				Image:   "busybox:1.36",
				Command: []string{"sleep", "60"},
			}},
		},
	}
	if _, err := client.CoreV1().Pods(liveTestNamespace).Create(ctx, dstPod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating pinned destination pod on pm-w2: %v", err)
	}
	defer client.CoreV1().Pods(liveTestNamespace).Delete(context.Background(), dstName, metav1.DeleteOptions{})

	// 3. Observe the outcome. Under cluster-pool IPAM, /24 blocks are
	// allocated per-node, so pinning an IP owned by pm-w1's block onto a pod
	// scheduled on pm-w2 is expected to be REJECTED or to silently receive a
	// different IP — this is exactly the open empirical question verification check C
	// asks to be resolved rather than assumed. We assert on the actual
	// outcome and report it either way; we do not pre-suppose success.
	gotIP, podErr := waitForPodIPOrError(ctx, client, dstName)
	if podErr != nil {
		t.Logf("RESULT: destination pod on pm-w2 failed to start with pinned IP %s under cluster-pool IPAM: %v", srcIP, podErr)
		t.Logf("CONCLUSION: ipam.cilium.io/ip pinning is NOT honored across cluster-pool per-node blocks; " +
			"per ADR-0324 verification check C escalation path, the substrate IPAM mode must move to multi-pool/crd " +
			"before the live Cilium IP-handoff proof can be credited on IP-preservation grounds.")
		t.Fatalf("cross-node IP pinning under cluster-pool IPAM did not succeed (see log): %v", podErr)
	}

	if gotIP != srcIP {
		t.Logf("RESULT: destination pod on pm-w2 started but with IP %s, NOT the pinned %s", gotIP, srcIP)
		t.Fatalf("ipam.cilium.io/ip annotation was not honored: wanted %s, got %s", srcIP, gotIP)
	}

	t.Logf("RESULT: destination pod on pm-w2 was assigned the pinned IP %s across a node boundary", gotIP)
}

func waitForPodIP(ctx context.Context, client kubernetes.Interface, name string) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
		pod, err := client.CoreV1().Pods(liveTestNamespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		if pod.Status.PodIP != "" {
			return pod.Status.PodIP, nil
		}
	}
}

func waitForPodIPOrError(ctx context.Context, client kubernetes.Interface, name string) (string, error) {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
		pod, err := client.CoreV1().Pods(liveTestNamespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		if pod.Status.PodIP != "" {
			return pod.Status.PodIP, nil
		}
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Waiting != nil && (cs.State.Waiting.Reason == "CreateContainerError" ||
				cs.State.Waiting.Reason == "FailedCreatePodSandBox") {
				return "", fmt.Errorf("pod %s sandbox failed: %s: %s", name, cs.State.Waiting.Reason, cs.State.Waiting.Message)
			}
		}
		if pod.Status.Phase == corev1.PodFailed {
			return "", fmt.Errorf("pod %s failed: %s", name, pod.Status.Reason)
		}
	}
	return "", fmt.Errorf("timed out waiting for pod %s to get an IP or a definitive failure state", name)
}

func waitForPodGone(ctx context.Context, client kubernetes.Interface, name string) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_, err := client.CoreV1().Pods(liveTestNamespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil // NotFound == gone
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("pod %s did not terminate within timeout", name)
}
