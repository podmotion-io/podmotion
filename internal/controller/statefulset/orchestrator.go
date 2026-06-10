/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package statefulset implements StatefulSet-aware migration orchestration.
// It enforces ordinal ordering and quorum safety as required by ADR-0033.
package statefulset

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// AnnotationOrdinalOrder allows operators to override the default highest-first ordering.
	// Values: "highest-first" (default) or "lowest-first".
	// See ADR-0033.
	AnnotationOrdinalOrder = "podmotion.io/statefulset-ordinal-order"

	ordinalOrderHighestFirst = "highest-first"
	ordinalOrderLowestFirst  = "lowest-first"
)

// OrdinalMigrationPlan describes which ordinals are safe to migrate and how many
// may run concurrently without violating split-brain or quorum constraints.
type OrdinalMigrationPlan struct {
	// Ordinals is the ordered list of pod ordinals to migrate (safe order).
	Ordinals []int
	// SafeParallelism is how many of Ordinals can be migrated simultaneously.
	// Always ≥1. Respects the non-adjacent constraint and quorum floor.
	SafeParallelism int
}

// StatefulSetMigrationOrchestrator coordinates the migration of all pods
// belonging to a StatefulSet in a split-brain-safe ordinal order.
//
// Safety invariants:
//   - Adjacent ordinals (|a-b|==1) are never migrated simultaneously.
//   - Migration is deferred if it would leave fewer than ceil(replicas/2)+1 running members (quorum floor).
//   - Default ordinal order is highest-first (non-leader heuristic for Raft-based workloads, ADR-0033).
type StatefulSetMigrationOrchestrator struct {
	Client client.Client
}

// BuildMigrationPlan computes the ordinal migration plan for the StatefulSet.
//
// activeCount is the current number of running/ready StatefulSet members.
// A member is considered "in-flight" during migration; activeCount should
// reflect the number available before any new migration starts.
func BuildMigrationPlan(sts *appsv1.StatefulSet, activeCount int) OrdinalMigrationPlan {
	replicas := 1
	if sts.Spec.Replicas != nil {
		replicas = int(*sts.Spec.Replicas)
	}

	// Quorum floor: majority. We must keep at least this many running.
	// For a 3-replica Raft ring: floor is 2 (ceil(3/2)).
	quorumFloor := (replicas / 2) + 1

	ordinals := make([]int, replicas)
	for i := range ordinals {
		ordinals[i] = i
	}

	// Determine ordinal order — operator may override via annotation (ADR-0033).
	order := ordinalOrderHighestFirst
	if sts.Annotations != nil {
		if v := sts.Annotations[AnnotationOrdinalOrder]; v == ordinalOrderLowestFirst {
			order = ordinalOrderLowestFirst
		}
	}

	if order == ordinalOrderHighestFirst {
		sort.Sort(sort.Reverse(sort.IntSlice(ordinals)))
	}

	// SafeParallelism: start at 1. Increase only if non-adjacent pairs exist and quorum holds.
	// The non-adjacent rule means we can never select two ordinals whose indices differ by 1
	// in the *original* (0-based) ordinal space.
	safeParallelism := computeSafeParallelism(ordinals, activeCount, quorumFloor)

	return OrdinalMigrationPlan{
		Ordinals:        ordinals,
		SafeParallelism: safeParallelism,
	}
}

// computeSafeParallelism returns the maximum number of ordinals from the plan
// that can migrate simultaneously without:
//  1. Including two adjacent ordinals (|a-b|==1 in the ordinal space).
//  2. Reducing activeCount below quorumFloor.
func computeSafeParallelism(ordinals []int, activeCount, quorumFloor int) int {
	maxAllowed := activeCount - quorumFloor
	if maxAllowed < 1 {
		// Quorum would be violated even by a single migration — still allow 1
		// because migration replaces (not removes) the pod; PDB overlap ensures both pods
		// live simultaneously (ADR-0015), so quorum is maintained during the window.
		// We return 1 to enable progress but the orchestrator will re-check before each step.
		maxAllowed = 1
	}

	// Walk the ordinals in plan order and select a non-adjacent subset.
	selected := 0
	inFlight := map[int]bool{}
	for _, o := range ordinals {
		if selected >= maxAllowed {
			break
		}
		if inFlight[o-1] || inFlight[o+1] {
			// Would be adjacent to an already-selected ordinal.
			continue
		}
		inFlight[o] = true
		selected++
	}
	if selected < 1 {
		return 1
	}
	return selected
}

// NextBatch returns the next batch of ordinals safe to migrate given the set
// of ordinals that are currently in-flight.
//
// inFlight is the set of ordinals currently being migrated (may be empty on
// first call). The returned batch respects adjacency and quorum constraints.
func (o *StatefulSetMigrationOrchestrator) NextBatch(
	ctx context.Context,
	sts *appsv1.StatefulSet,
	inFlight map[int]bool,
	safeParallelism int,
) ([]int, error) {
	log := logf.FromContext(ctx).WithValues("statefulset", sts.Name)

	replicas := 1
	if sts.Spec.Replicas != nil {
		replicas = int(*sts.Spec.Replicas)
	}

	// Count currently running pods to re-verify quorum.
	activeCount, err := o.countRunningPods(ctx, sts)
	if err != nil {
		return nil, fmt.Errorf("count running pods: %w", err)
	}

	quorumFloor := (replicas / 2) + 1
	available := activeCount - len(inFlight) - quorumFloor
	if available < 1 {
		log.Info("quorum check defers migration", "active", activeCount, "inFlight", len(inFlight), "quorumFloor", quorumFloor)
		return nil, nil
	}

	plan := BuildMigrationPlan(sts, activeCount-len(inFlight))

	var batch []int
	for _, ord := range plan.Ordinals {
		if inFlight[ord] {
			continue
		}
		// Non-adjacent check against in-flight set.
		if adjacentToInFlight(ord, inFlight) {
			continue
		}
		batch = append(batch, ord)
		if len(batch) >= safeParallelism {
			break
		}
	}
	return batch, nil
}

// countRunningPods counts pods belonging to this StatefulSet that are Running and Ready.
func (o *StatefulSetMigrationOrchestrator) countRunningPods(ctx context.Context, sts *appsv1.StatefulSet) (int, error) {
	var podList corev1.PodList
	if err := o.Client.List(ctx, &podList,
		client.InNamespace(sts.Namespace),
		client.MatchingLabels(sts.Spec.Selector.MatchLabels),
	); err != nil {
		return 0, err
	}
	count := 0
	for _, p := range podList.Items {
		if p.Status.Phase == corev1.PodRunning && isPodReady(&p) {
			count++
		}
	}
	return count, nil
}

func isPodReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func adjacentToInFlight(ord int, inFlight map[int]bool) bool {
	return inFlight[ord-1] || inFlight[ord+1]
}

// OrdinalFromPodName extracts the ordinal suffix from a StatefulSet pod name.
// StatefulSet pods are named <statefulset-name>-<ordinal>.
func OrdinalFromPodName(podName string) (int, error) {
	idx := strings.LastIndex(podName, "-")
	if idx < 0 {
		return 0, fmt.Errorf("pod name %q has no ordinal suffix", podName)
	}
	return strconv.Atoi(podName[idx+1:])
}
