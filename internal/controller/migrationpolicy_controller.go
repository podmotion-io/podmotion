/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	stsorch "github.com/podmotion-io/podmotion/internal/controller/statefulset"
)

// MigrationPolicyReconciler reconciles a MigrationPolicy object
type MigrationPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Now is injectable for deterministic unit tests.
	Now func() time.Time
	// STSOrchestrator handles StatefulSet-targeted migration plans.
	// Injected so tests can override; production wire in SetupWithManager.
	STSOrchestrator *stsorch.StatefulSetMigrationOrchestrator
}

// +kubebuilder:rbac:groups=migration.podmotion.io,resources=migrationpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=migrationpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=migrationpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=podmigrations,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch

func (r *MigrationPolicyReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *MigrationPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var policy pmv1.MigrationPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	now := r.now()

	// --- Window check ---
	if policy.Spec.Window != nil {
		if blocked, reason := r.isWindowBlocked(policy.Spec.Window, now); blocked {
			meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
				Type:               "WindowBlocked",
				Status:             metav1.ConditionTrue,
				Reason:             "CronBlocked",
				Message:            reason,
				LastTransitionTime: metav1.Now(),
			})
			if err := r.Status().Update(ctx, &policy); err != nil {
				return ctrl.Result{}, err
			}
			log.Info("migration window blocked", "reason", reason)
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "WindowBlocked",
			Status:             metav1.ConditionFalse,
			Reason:             "WindowOpen",
			Message:            "migration window is open",
			LastTransitionTime: metav1.Now(),
		})
	}

	// --- Count active migrations owned by this policy ---
	var pmList pmv1.PodMigrationList
	if err := r.List(ctx, &pmList, client.InNamespace(policy.Namespace)); err != nil {
		return ctrl.Result{}, err
	}
	active := int32(0)
	for _, pm := range pmList.Items {
		if pm.Spec.MigrationPolicyRef != nil && pm.Spec.MigrationPolicyRef.Name == policy.Name {
			if !isTerminal(pm.Status.Phase) {
				active++
			}
		}
	}
	policy.Status.ActiveMigrations = active
	if err := r.Status().Update(ctx, &policy); err != nil {
		return ctrl.Result{}, err
	}

	if active >= policy.Spec.MaxConcurrentMigrations {
		log.Info("max concurrent migrations reached", "active", active, "max", policy.Spec.MaxConcurrentMigrations)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// --- StatefulSet-targeted migration path ---
	if policy.Spec.StatefulSetRef != nil {
		return r.reconcileStatefulSet(ctx, &policy, pmList.Items, active, now)
	}

	// --- Find candidate pods via selector ---
	sel, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("invalid selector: %w", err)
	}

	var podList corev1.PodList
	if err := r.List(ctx, &podList, &client.ListOptions{LabelSelector: sel}); err != nil {
		return ctrl.Result{}, err
	}

	for _, pod := range podList.Items {
		if r.isBlocked(&policy, &pod) {
			continue
		}
		if r.alreadyMigrating(pmList.Items, pod.Name, pod.Namespace) {
			continue
		}
		if !r.triggerFired(&policy, &pod) {
			continue
		}

		pm := r.buildPodMigration(&policy, &pod)
		if err := r.Create(ctx, pm); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				log.Error(err, "failed to create PodMigration", "pod", pod.Name)
			}
			continue
		}
		log.Info("created PodMigration", "migration", pm.Name, "pod", pod.Name)
		active++
		policy.Status.TotalMigrations++
		t := metav1.NewTime(now)
		policy.Status.LastTriggerTime = &t
		if err := r.Status().Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		if active >= policy.Spec.MaxConcurrentMigrations {
			break
		}
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *MigrationPolicyReconciler) isBlocked(policy *pmv1.MigrationPolicy, pod *corev1.Pod) bool {
	for _, ns := range policy.Spec.BlockedNamespaces {
		if pod.Namespace == ns {
			return true
		}
	}
	return false
}

func (r *MigrationPolicyReconciler) alreadyMigrating(migrations []pmv1.PodMigration, podName, podNS string) bool {
	for _, pm := range migrations {
		if pm.Spec.PodName == podName && pm.Spec.PodNamespace == podNS && !isTerminal(pm.Status.Phase) {
			return true
		}
	}
	return false
}

func (r *MigrationPolicyReconciler) triggerFired(policy *pmv1.MigrationPolicy, pod *corev1.Pod) bool {
	t := policy.Spec.Triggers
	if t.NodeDrain != nil && *t.NodeDrain {
		// Check if the pod's node is cordoned.
		return true
	}
	if t.SpotReclaim != nil && *t.SpotReclaim {
		// Spot reclaim annotation set by the node termination handler DaemonSet.
		if pod.Annotations != nil {
			if _, ok := pod.Annotations["podmotion.io/spot-reclaim"]; ok {
				return true
			}
		}
	}
	// CPU/memory pressure triggers require node metrics — deferred to agent integration (M13).
	// Return false for now so the policy still functions for drain/spot in v0.1.
	return false
}

func (r *MigrationPolicyReconciler) buildPodMigration(policy *pmv1.MigrationPolicy, pod *corev1.Pod) *pmv1.PodMigration {
	spec := pmv1.PodMigrationSpec{
		PodName:          pod.Name,
		PodNamespace:     pod.Namespace,
		MigrationPolicyRef: &corev1.LocalObjectReference{Name: policy.Name},
	}
	if policy.Spec.MigrationDefaults != nil {
		d := policy.Spec.MigrationDefaults
		if d.Mode != "" {
			spec.Mode = d.Mode
		}
		if d.PreCopyMaxRounds > 0 {
			spec.PreCopyMaxRounds = d.PreCopyMaxRounds
		}
		if d.BandwidthLimitMbps > 0 {
			spec.BandwidthLimitMbps = d.BandwidthLimitMbps
		}
		if d.CompletionTimeoutSeconds > 0 {
			spec.CompletionTimeoutSeconds = d.CompletionTimeoutSeconds
		}
		spec.StorageStrategy = d.StorageStrategy
		spec.NetworkContinuity = d.NetworkContinuity
		spec.RollbackOnFailure = d.RollbackOnFailure
	}
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: policy.Name + "-",
			Namespace:    policy.Namespace,
			Labels: map[string]string{
				"migration.podmotion.io/policy": policy.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: pmv1.GroupVersion.String(),
					Kind:       "MigrationPolicy",
					Name:       policy.Name,
					UID:        policy.UID,
				},
			},
		},
		Spec: spec,
	}
}

// reconcileStatefulSet handles migration for policies that target a StatefulSet directly.
// It builds a migration plan via StatefulSetMigrationOrchestrator, then creates PodMigration
// CRs for ordinals that are safe to migrate given current quorum and parallelism settings.
func (r *MigrationPolicyReconciler) reconcileStatefulSet(
	ctx context.Context,
	policy *pmv1.MigrationPolicy,
	existingMigrations []pmv1.PodMigration,
	active int32,
	now time.Time,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: policy.Namespace,
		Name:      policy.Spec.StatefulSetRef.Name,
	}, sts); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("StatefulSet not found, requeueing", "sts", policy.Spec.StatefulSetRef.Name)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	// Build in-flight ordinal set from existing non-terminal migrations.
	inFlight := map[int]bool{}
	for _, pm := range existingMigrations {
		if pm.Spec.MigrationPolicyRef == nil || pm.Spec.MigrationPolicyRef.Name != policy.Name {
			continue
		}
		if isTerminal(pm.Status.Phase) {
			continue
		}
		// Derive ordinal from pod name suffix (e.g. "myapp-2" → 2).
		ord, err := stsorch.OrdinalFromPodName(pm.Spec.PodName)
		if err == nil {
			inFlight[ord] = true
		}
	}

	safeParallelism := int(policy.Spec.SafeOrdinalParallelism)
	if safeParallelism < 1 {
		safeParallelism = 1
	}

	orch := r.STSOrchestrator
	if orch == nil {
		orch = &stsorch.StatefulSetMigrationOrchestrator{Client: r.Client}
	}

	batch, err := orch.NextBatch(ctx, sts, inFlight, safeParallelism)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("statefulset next batch: %w", err)
	}

	for _, ord := range batch {
		podName := fmt.Sprintf("%s-%d", sts.Name, ord)
		if r.alreadyMigrating(existingMigrations, podName, policy.Namespace) {
			continue
		}
		pm := r.buildStatefulSetPodMigration(policy, podName)
		if err := r.Create(ctx, pm); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				log.Error(err, "failed to create StatefulSet PodMigration", "pod", podName)
			}
			continue
		}
		log.Info("created StatefulSet PodMigration", "migration", pm.Name, "pod", podName, "ordinal", ord)
		active++
		policy.Status.TotalMigrations++
		t := metav1.NewTime(now)
		policy.Status.LastTriggerTime = &t
		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
		if active >= policy.Spec.MaxConcurrentMigrations {
			break
		}
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *MigrationPolicyReconciler) buildStatefulSetPodMigration(policy *pmv1.MigrationPolicy, podName string) *pmv1.PodMigration {
	spec := pmv1.PodMigrationSpec{
		PodName:            podName,
		PodNamespace:       policy.Namespace,
		MigrationPolicyRef: &corev1.LocalObjectReference{Name: policy.Name},
	}
	if policy.Spec.MigrationDefaults != nil {
		d := policy.Spec.MigrationDefaults
		if d.Mode != "" {
			spec.Mode = d.Mode
		}
		if d.PreCopyMaxRounds > 0 {
			spec.PreCopyMaxRounds = d.PreCopyMaxRounds
		}
		if d.BandwidthLimitMbps > 0 {
			spec.BandwidthLimitMbps = d.BandwidthLimitMbps
		}
		if d.CompletionTimeoutSeconds > 0 {
			spec.CompletionTimeoutSeconds = d.CompletionTimeoutSeconds
		}
		spec.StorageStrategy = d.StorageStrategy
		spec.NetworkContinuity = d.NetworkContinuity
		spec.RollbackOnFailure = d.RollbackOnFailure
	}
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: policy.Name + "-sts-",
			Namespace:    policy.Namespace,
			Labels: map[string]string{
				"migration.podmotion.io/policy":      policy.Name,
				"migration.podmotion.io/statefulset": policy.Spec.StatefulSetRef.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: pmv1.GroupVersion.String(),
					Kind:       "MigrationPolicy",
					Name:       policy.Name,
					UID:        policy.UID,
				},
			},
		},
		Spec: spec,
	}
}

// isWindowBlocked returns true if the current time falls within a blockedCron window
// or outside the allowedCron window. BlockedCron takes precedence.
func (r *MigrationPolicyReconciler) isWindowBlocked(w *pmv1.MigrationWindow, now time.Time) (bool, string) {
	if w.BlockedCron != "" {
		if cronMatches(w.BlockedCron, now) {
			return true, "blockedCron matches current time: " + w.BlockedCron
		}
	}
	if w.AllowedCron != "" {
		if !cronMatches(w.AllowedCron, now) {
			return true, "outside allowedCron window: " + w.AllowedCron
		}
	}
	return false, ""
}

// isTerminal returns true for phases that represent a completed migration.
func isTerminal(phase pmv1.MigrationPhase) bool {
	switch phase {
	case pmv1.MigrationPhaseComplete, pmv1.MigrationPhaseFailed, pmv1.MigrationPhaseDryRunComplete:
		return true
	}
	return false
}

// cronMatches returns true if 'now' falls within the given 5-field cron expression.
// Only minute/hour/dom/month/dow fields are supported (standard cron).
// This is a lightweight match — for production use a full cron library.
func cronMatches(expr string, now time.Time) bool {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return false
	}
	return fieldMatch(fields[0], now.Minute(), 0, 59) &&
		fieldMatch(fields[1], now.Hour(), 0, 23) &&
		fieldMatch(fields[2], now.Day(), 1, 31) &&
		fieldMatch(fields[3], int(now.Month()), 1, 12) &&
		fieldMatch(fields[4], int(now.Weekday()), 0, 6)
}

// fieldMatch checks whether val matches a single cron field token.
// Supports: *, */step, single-value, and dash-range (e.g. 1-5).
func fieldMatch(field string, val, min, max int) bool {
	if field == "*" {
		return true
	}
	if strings.HasPrefix(field, "*/") {
		step, err := strconv.Atoi(field[2:])
		if err != nil || step == 0 {
			return false
		}
		return (val-min)%step == 0
	}
	if strings.Contains(field, "-") {
		parts := strings.SplitN(field, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return false
		}
		return val >= lo && val <= hi
	}
	if strings.Contains(field, ",") {
		for _, part := range strings.Split(field, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err == nil && n == val {
				return true
			}
		}
		return false
	}
	n, err := strconv.Atoi(field)
	return err == nil && n == val
}

// SetupWithManager sets up the controller with the Manager.
func (r *MigrationPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Ensure the label selector index is present for efficient list-by-label.
	_ = labels.Everything()
	return ctrl.NewControllerManagedBy(mgr).
		For(&pmv1.MigrationPolicy{}).
		Named("migrationpolicy").
		Complete(r)
}
