/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"fmt"
	"net/http"

	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// EvictionInterceptor is a MutatingAdmissionWebhook that intercepts pod evictions
// while a PodMigration for that pod is active (not yet Complete/Failed/DryRunComplete).
//
// Evicting a pod mid-migration would destroy the source container before the
// destination is ready, violating the TrafficVerified gate (ADR-0012) and the
// PDB overlap-then-delete model (ADR-0015).
//
// Behaviour:
//   - If an active PodMigration exists for the target pod: DENY the eviction with
//     a 429-like message asking the caller to retry after the migration completes.
//   - If no PodMigration is active: ALLOW the eviction unchanged.
//
// Registered at /mutate-core-v1-pod-eviction.
type EvictionInterceptor struct {
	client  client.Client
	decoder admission.Decoder
}

// SetupWithManager registers the eviction interception webhook.
func (e *EvictionInterceptor) SetupWithManager(mgr ctrl.Manager) error {
	e.client = mgr.GetClient()
	e.decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register(
		"/mutate-core-v1-pod-eviction",
		&admission.Webhook{Handler: e},
	)
	return nil
}

// Handle implements admission.Handler.
func (e *EvictionInterceptor) Handle(ctx context.Context, req admission.Request) admission.Response {
	eviction := &policyv1.Eviction{}
	if err := e.decoder.Decode(req, eviction); err != nil {
		// Decode failure on the eviction object — let it through rather than block all evictions.
		return admission.Allowed("decode error — allowing eviction passthrough")
	}

	// The pod being evicted has the same name/namespace as the eviction object.
	podName := eviction.Name
	podNamespace := eviction.Namespace
	if podNamespace == "" {
		podNamespace = req.Namespace
	}

	activeMigration, err := e.findActiveMigration(ctx, podNamespace, podName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return admission.Allowed("")
		}
		// API error — fail open (allow eviction) to avoid blocking cluster operations.
		webhookLog.Error(err, "eviction interceptor: API error looking up PodMigration — allowing eviction",
			"pod", fmt.Sprintf("%s/%s", podNamespace, podName))
		return admission.Allowed("API error — allowing eviction passthrough")
	}

	if activeMigration != nil {
		return admission.Denied(fmt.Sprintf(
			"pod %s/%s is currently being migrated (PodMigration %s/%s, phase %s); "+
				"retry eviction after migration completes or reaches Failed state",
			podNamespace, podName,
			activeMigration.Namespace, activeMigration.Name,
			activeMigration.Status.Phase,
		))
	}

	return admission.Allowed("")
}

// findActiveMigration returns the in-progress PodMigration targeting this pod, or nil.
func (e *EvictionInterceptor) findActiveMigration(ctx context.Context, namespace, podName string) (*pmv1.PodMigration, error) {
	pmList := &pmv1.PodMigrationList{}
	if err := e.client.List(ctx, pmList,
		client.InNamespace(namespace),
		client.MatchingLabelsSelector{Selector: labels.Everything()},
	); err != nil {
		return nil, err
	}

	for i := range pmList.Items {
		pm := &pmList.Items[i]
		if pm.Spec.PodName != podName || pm.Spec.PodNamespace != namespace {
			continue
		}
		if isActiveMigrationPhase(pm.Status.Phase) {
			return pm, nil
		}
	}
	return nil, nil
}

// isActiveMigrationPhase returns true if the migration is in-flight (not terminal).
func isActiveMigrationPhase(phase pmv1.MigrationPhase) bool {
	switch phase {
	case pmv1.MigrationPhaseComplete,
		pmv1.MigrationPhaseFailed,
		pmv1.MigrationPhaseDryRunComplete,
		"":
		return false
	}
	return true
}

// httpStatusFromResponse is kept for completeness — the webhook returns 403 Forbidden
// for denied evictions, which the kubelet/descheduler treats as a retry signal.
var _ = http.StatusForbidden
