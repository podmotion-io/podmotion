/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package spotreclaim implements SpotReclaimReconciler, which watches Nodes for
// the eks.amazonaws.com/spot-interrupt annotation set by the node agent's IMDS
// poller (ADR-0035) and creates PodMigration CRs for eligible pods within the
// 2-minute AWS spot termination window.
package spotreclaim

import (
	"context"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/spotimds"
	"github.com/podmotion-io/podmotion/internal/podlineage"
)

const (
	// defaultTimeoutSeconds is used when MigrationPolicy.spec.triggers.spotReclaimTimeoutSeconds
	// is zero. It is 2 min (AWS notice) minus 30 s buffer = 90 s.
	defaultTimeoutSeconds int32 = 90

	// processedAnnotation is set on the Node after we have already created migrations
	// for it, preventing duplicate creation on re-reconcile before the node is gone.
	processedAnnotation = "podmotion.io/spot-reclaim-processed"
)

// SpotReclaimReconciler reacts to spot interruption annotations on Nodes and
// creates PodMigration CRs for pods whose MigrationPolicy has SpotReclaim=true.
type SpotReclaimReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=migrationpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=migration.podmotion.io,resources=podmigrations,verbs=get;list;watch;create

func (r *SpotReclaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithName("spotreclaim")

	var node corev1.Node
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if node.Annotations == nil || node.Annotations[spotimds.SpotInterruptAnnotation] != "true" {
		return ctrl.Result{}, nil
	}

	// Idempotency guard — if we already processed this node's interrupt event, skip.
	if node.Annotations[processedAnnotation] == "true" {
		return ctrl.Result{}, nil
	}

	log.Info("Spot interruption detected on node", "node", node.Name)

	pods, err := r.podsOnNode(ctx, node.Name)
	if err != nil {
		return ctrl.Result{}, err
	}

	policies, err := r.spotReclaimPolicies(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}

	eligible := r.filterEligiblePods(pods, policies)

	// Migrate smallest-RSS first to maximise the number of successful migrations
	// within the 2-minute window (ADR-0035). RSS is read from resource requests as
	// a proxy; actual RSS would require metrics-server integration (M13).
	sortByRSSAscending(eligible)

	for _, ep := range eligible {
		timeout := ep.timeoutSeconds
		if timeout == 0 {
			timeout = defaultTimeoutSeconds
		}
		pm := buildPodMigration(ep.pod, ep.policy, timeout)
		if err := r.Create(ctx, pm); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				log.Error(err, "failed to create PodMigration for spot reclaim",
					"pod", ep.pod.Name, "namespace", ep.pod.Namespace)
			}
			continue
		}
		log.Info("created PodMigration for spot-reclaimed pod",
			"migration", pm.Name, "pod", ep.pod.Name, "timeout", timeout)
	}

	// Mark the node processed so re-reconcile does not duplicate migrations.
	patch := client.MergeFrom(node.DeepCopy())
	node.Annotations[processedAnnotation] = "true"
	if err := r.Patch(ctx, &node, patch); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

type eligiblePod struct {
	pod            corev1.Pod
	policy         *pmv1.MigrationPolicy
	timeoutSeconds int32
}

func (r *SpotReclaimReconciler) podsOnNode(ctx context.Context, nodeName string) ([]corev1.Pod, error) {
	var list corev1.PodList
	if err := r.List(ctx, &list, client.MatchingFields{"spec.nodeName": nodeName}); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (r *SpotReclaimReconciler) spotReclaimPolicies(ctx context.Context) ([]*pmv1.MigrationPolicy, error) {
	var list pmv1.MigrationPolicyList
	if err := r.List(ctx, &list); err != nil {
		return nil, err
	}
	var out []*pmv1.MigrationPolicy
	for i := range list.Items {
		p := &list.Items[i]
		if p.Spec.Triggers.SpotReclaim != nil && *p.Spec.Triggers.SpotReclaim {
			out = append(out, p)
		}
	}
	return out, nil
}

// filterEligiblePods matches pods to policies whose selector covers them.
// A pod matched by multiple policies uses the policy with the tightest timeout
// (smallest non-zero SpotReclaimTimeoutSeconds).
func (r *SpotReclaimReconciler) filterEligiblePods(pods []corev1.Pod, policies []*pmv1.MigrationPolicy) []eligiblePod {
	var out []eligiblePod
	for _, pod := range pods {
		// Skip non-running pods — there is nothing to migrate.
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		var best *pmv1.MigrationPolicy
		var bestTimeout int32
		for _, p := range policies {
			sel, err := metav1.LabelSelectorAsSelector(&p.Spec.Selector)
			if err != nil {
				continue
			}
			if !sel.Matches(labelsOf(pod)) {
				continue
			}
			t := p.Spec.Triggers.SpotReclaimTimeoutSeconds
			if t == 0 {
				t = defaultTimeoutSeconds
			}
			if best == nil || t < bestTimeout {
				best = p
				bestTimeout = t
			}
		}
		if best != nil {
			out = append(out, eligiblePod{pod: pod, policy: best, timeoutSeconds: bestTimeout})
		}
	}
	return out
}

func sortByRSSAscending(pods []eligiblePod) {
	sort.Slice(pods, func(i, j int) bool {
		return memRequestBytes(pods[i].pod) < memRequestBytes(pods[j].pod)
	})
}

// memRequestBytes returns the total memory request for the pod as a byte count.
// Used as an RSS proxy when actual RSS data is not available.
func memRequestBytes(pod corev1.Pod) int64 {
	var total int64
	for _, c := range pod.Spec.Containers {
		if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
			total += q.Value()
		}
	}
	return total
}

func labelsOf(pod corev1.Pod) labels.Labels {
	return labels.Set(pod.Labels)
}

func buildPodMigration(pod corev1.Pod, policy *pmv1.MigrationPolicy, timeoutSeconds int32) *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{
			// Derive the CR name prefix from the STABLE ROOT workload name, not the
			// (possibly already "-m-"/"-r-"-suffixed) current pod name, so reclaiming an
			// already-migrated pod does not carry an accreted suffix into the CR name.
			GenerateName: "spot-reclaim-" + podlineage.OriginalNameFromLabels(pod.Labels, pod.Name) + "-",
			Namespace:    pod.Namespace,
			Labels: map[string]string{
				"migration.podmotion.io/trigger": "spot-reclaim",
				"migration.podmotion.io/policy":  policy.Name,
			},
			Annotations: map[string]string{
				"podmotion.io/spot-reclaim-node": pod.Spec.NodeName,
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
		Spec: pmv1.PodMigrationSpec{
			PodName:                  pod.Name,
			PodNamespace:             pod.Namespace,
			CompletionTimeoutSeconds: timeoutSeconds,
			MigrationPolicyRef:       &corev1.LocalObjectReference{Name: policy.Name},
		},
	}
}

// spotInterruptPredicate filters node update events to only those that add the
// spot-interrupt annotation. This avoids reconciling every node heartbeat.
var spotInterruptPredicate = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		newAnnotations := e.ObjectNew.GetAnnotations()
		oldAnnotations := e.ObjectOld.GetAnnotations()
		newVal := newAnnotations[spotimds.SpotInterruptAnnotation]
		oldVal := oldAnnotations[spotimds.SpotInterruptAnnotation]
		// Only enqueue when the annotation transitions to "true".
		return newVal == "true" && oldVal != "true"
	},
	CreateFunc:  func(e event.CreateEvent) bool { return false },
	DeleteFunc:  func(e event.DeleteEvent) bool { return false },
	GenericFunc: func(e event.GenericEvent) bool { return false },
}

// SetupWithManager registers the controller. A field index on spec.nodeName is
// required for efficient pod listing by node; the caller must also register:
//
//	mgr.GetFieldIndexer().IndexField(ctx, &corev1.Pod{}, "spec.nodeName",
//	    func(o client.Object) []string { return []string{o.(*corev1.Pod).Spec.NodeName} })
func (r *SpotReclaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, builder.WithPredicates(spotInterruptPredicate)).
		Named("spotreclaim").
		// Single worker: spot reclaim is a burst event that creates many CRs;
		// serialising avoids duplicate creation races under rapid node churn.
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// Ensure SpotReclaimReconciler satisfies the reconciler interface at compile time.
var _ reconcile.Reconciler = &SpotReclaimReconciler{}

// spotReclaimTimeoutOrDefault returns the configured timeout or the default value.
// Exported so cmd/main.go and tests can use it without importing the full controller.
func spotReclaimTimeoutOrDefault(t int32) int32 {
	if t <= 0 {
		return defaultTimeoutSeconds
	}
	return t
}

// SpotReclaimTimeout is the 2-min-window-safe default exposed for tests.
const SpotReclaimTimeout = defaultTimeoutSeconds

// NodeFieldIndexName is the field index key used for spec.nodeName queries.
// Exported so cmd/main.go can register it once for all controllers that need it.
const NodeFieldIndexName = "spec.nodeName"

// PodNodeNameIndexer is the IndexerFunc value for the spec.nodeName field index.
func PodNodeNameIndexer(o client.Object) []string {
	pod, ok := o.(*corev1.Pod)
	if !ok {
		return nil
	}
	if pod.Spec.NodeName == "" {
		return nil
	}
	return []string{pod.Spec.NodeName}
}

// ensure time import is used (timeout calculation)
var _ = time.Second
