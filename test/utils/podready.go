/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package utils

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// WaitForPodReady polls the named pod until its PodReady condition is True,
// or returns a diagnostic error once timeout elapses.
//
// This is a general, workload-agnostic substrate primitive for the e2e suite:
// every test that stages a pod (postgres, redis, nginx, pgbouncer, ...) needs
// the same thing — wait for Ready, and if it never happens, know *why*
// without a manual follow-up `kubectl describe pod` / `kubectl get pvc`
// session. Before this helper, each test file re-implemented the same
// Eventually(...).Should(BeTrue(), "<pod> must be Ready") poll-and-guess
// pattern (db_migration_test.go, live_migration_traffic_test.go,
// redis_migration_test.go, sprint31_cold_migration_amd64_test.go): on
// failure it reports only the boolean, never the pod phase, container
// waiting reason, or (critically for storage-tier fixtures) whether an
// unbound PVC is missing its StorageClass. That gap is exactly what turned
// the sprint49 Longhorn e2e run into a multi-step manual investigation
// instead of an immediate, actionable test failure.
func WaitForPodReady(ctx context.Context, c client.Client, name, namespace string, timeout, poll time.Duration) error {
	return WaitForPodReadyOnNode(ctx, c, name, namespace, "", timeout, poll)
}

// WaitForPodReadyOnNode is WaitForPodReady plus a scheduling assertion: the
// pod must also have landed on wantNode (pass "" to skip that check). Several
// e2e tests pin a source pod to a specific node before migrating it elsewhere
// and were re-implementing this exact "Ready AND on the right node" poll
// inline (live_migration_traffic_test.go, redis_migration_test.go) — same
// brittle-chain duplication as the plain Ready case, so it gets the same
// shared primitive rather than a second special-cased copy.
func WaitForPodReadyOnNode(
	ctx context.Context,
	c client.Client,
	name, namespace, wantNode string,
	timeout, poll time.Duration,
) error {
	deadline := time.Now().Add(timeout)
	var lastPod corev1.Pod
	var lastGetErr error

	for {
		var pod corev1.Pod
		getErr := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &pod)
		if getErr == nil {
			lastPod = pod
			lastGetErr = nil
			onWantedNode := wantNode == "" || pod.Spec.NodeName == wantNode
			if onWantedNode {
				for _, cond := range pod.Status.Conditions {
					if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
						return nil
					}
				}
			}
		} else {
			lastGetErr = getErr
		}

		if time.Now().After(deadline) {
			return diagnosePodNotReady(ctx, c, name, namespace, wantNode, lastPod, lastGetErr, timeout)
		}
		time.Sleep(poll)
	}
}

// diagnosePodNotReady builds an actionable error describing why a pod never
// became Ready: its phase, any waiting-container reasons, unmet conditions,
// and — for every PersistentVolumeClaim-backed volume — that PVC's phase and
// StorageClass. A PVC stuck Pending because its StorageClass does not exist
// (the sprint49 Longhorn case) surfaces here directly, for any fixture that
// happens to hit it, rather than only as an opaque "pod must be Ready"
// timeout that requires a manual kubectl session to explain.
func diagnosePodNotReady(
	ctx context.Context,
	c client.Client,
	name, namespace, wantNode string,
	pod corev1.Pod,
	getErr error,
	timeout time.Duration,
) error {
	var b strings.Builder
	fmt.Fprintf(&b, "pod %s/%s did not become Ready within %s", namespace, name, timeout)

	if getErr != nil {
		fmt.Fprintf(&b, ": failed to get pod: %v", getErr)
		return fmt.Errorf("%s", b.String())
	}

	fmt.Fprintf(&b, "\n  phase: %s", pod.Status.Phase)
	if wantNode != "" && pod.Spec.NodeName != wantNode {
		fmt.Fprintf(&b, "\n  scheduled on node %q, wanted %q", pod.Spec.NodeName, wantNode)
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil {
			fmt.Fprintf(&b, "\n  container %s: waiting (%s): %s",
				cs.Name, cs.State.Waiting.Reason, cs.State.Waiting.Message)
		}
	}
	for _, cond := range pod.Status.Conditions {
		if cond.Status != corev1.ConditionTrue {
			fmt.Fprintf(&b, "\n  condition %s=%s: %s", cond.Type, cond.Status, cond.Message)
		}
	}

	for _, vol := range pod.Spec.Volumes {
		if vol.PersistentVolumeClaim == nil {
			continue
		}
		claimName := vol.PersistentVolumeClaim.ClaimName
		var pvc corev1.PersistentVolumeClaim
		if pvcErr := c.Get(ctx, types.NamespacedName{Name: claimName, Namespace: namespace}, &pvc); pvcErr != nil {
			fmt.Fprintf(&b, "\n  volume %s: PVC %s: failed to get: %v", vol.Name, claimName, pvcErr)
			continue
		}
		fmt.Fprintf(&b, "\n  volume %s: PVC %s phase=%s", vol.Name, pvc.Name, pvc.Status.Phase)
		if pvc.Status.Phase != corev1.ClaimBound {
			sc := "<none>"
			if pvc.Spec.StorageClassName != nil && *pvc.Spec.StorageClassName != "" {
				sc = *pvc.Spec.StorageClassName
			}
			fmt.Fprintf(&b, " (storageClassName=%s — check it exists: `kubectl get sc %s`)", sc, sc)
		}
	}

	return fmt.Errorf("%s", b.String())
}
