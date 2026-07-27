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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/metrics"
)

// EvictionInterceptor is a MutatingAdmissionWebhook that intercepts pod evictions
// while a PodMigration for that pod is active (not yet Complete/Failed/DryRunComplete).
//
// Evicting a pod mid-migration would destroy the source container before the
// destination is ready, violating the TrafficVerified gate (ADR-0012) and the
// PDB overlap-then-delete model (ADR-0015).
//
// ADR-0401 — the webhook fails CLOSED on any unverifiable migration state:
//   - If an active PodMigration exists for the target pod: DENY (429, retriable).
//   - If the migration lookup ERRORS (apiserver timeout, control-plane pressure,
//     RBAC gap): DENY (429) — never allow. "Could not verify" is not "verified safe".
//   - If the eviction object cannot be decoded: DENY (429) — a malformed object on the
//     pods/eviction subresource is a malformed eviction, and blocking it is contained.
//   - ONLY if the lookup completed AND found no active migration: ALLOW.
//
// The migration lookup reads through an UNCACHED apiserver reader (mgr.GetAPIReader),
// NOT the informer cache: the cache is not read-after-write consistent with PodMigration
// creation, so a cached "empty" result at t=0 of a migration would fail open and let the
// source pod be evicted. An uncached read grounds the negative decision in authoritative
// state. It also removes any informer-sync/readiness coupling — a lookup error at operator
// cold-start is a genuine "could not verify" and correctly fails closed.
//
// Every denial carries HTTP 429 TooManyRequests (not 403): kubectl drain / the descheduler /
// cluster-autoscaler / PDB-driven eviction key "not yet, retry" on 429 and treat 403 as
// "never, abort the drain". Failing closed must make legitimate drains RETRY until the
// migration converges, not abort them.
//
// Registered at /mutate-core-v1-pod-eviction.
type EvictionInterceptor struct {
	// reader is an UNCACHED reader (mgr.GetAPIReader) — see the type doc for why the
	// negative decision must not be served from the informer cache.
	reader  client.Reader
	decoder admission.Decoder
}

// SetupWithManager registers the eviction interception webhook.
func (e *EvictionInterceptor) SetupWithManager(mgr ctrl.Manager) error {
	e.reader = mgr.GetAPIReader()
	e.decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register(
		"/mutate-core-v1-pod-eviction",
		&admission.Webhook{Handler: e},
	)
	return nil
}

// failClosed builds a fail-closed denial: a retriable 429 TooManyRequests carrying msg,
// increments the fail-closed counter for reason, and emits a greppable Error-level marker
// log. This is the §5.3a "could-not-verify is a HARD STOP, never a silent pass" branch —
// it is deliberately loud (metric + log + caller-visible retriable denial).
func failClosed(reason, msg string, err error, podNamespace, podName string) admission.Response {
	metrics.EvictionWebhookFailClosedTotal.WithLabelValues(reason).Inc()
	webhookLog.Error(err, "eviction webhook failing closed: could not verify migration state",
		"reason", reason,
		"pod", fmt.Sprintf("%s/%s", podNamespace, podName))
	return retriableDenied(msg)
}

// retriableDenied returns an admission denial with HTTP 429 TooManyRequests so eviction
// callers back off and retry rather than aborting the drain (see the type doc).
func retriableDenied(msg string) admission.Response {
	resp := admission.Denied(msg)
	resp.Result.Code = http.StatusTooManyRequests
	resp.Result.Reason = metav1.StatusReasonTooManyRequests
	return resp
}

// Handle implements admission.Handler.
func (e *EvictionInterceptor) Handle(ctx context.Context, req admission.Request) admission.Response {
	eviction := &policyv1.Eviction{}
	if err := e.decoder.Decode(req, eviction); err != nil {
		// Fail CLOSED: an undecodable object on the pods/eviction subresource is a malformed
		// eviction. We cannot verify migration state for it, so deny (retriable) rather than
		// wave it through.
		return failClosed("decode_error",
			"eviction blocked: PodMotion could not decode the eviction request to verify "+
				"whether a live migration is in progress; failing closed to protect a possible "+
				"in-flight migration — retry the eviction shortly",
			err, req.Namespace, req.Name)
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
			// Positive fact: no PodMigration exists for this pod. Safe to allow.
			return admission.Allowed("")
		}
		// Fail CLOSED: the migration-state lookup itself failed, so we could NOT determine
		// whether a migration is active. Deny (retriable) — never allow on could-not-verify.
		return failClosed("api_error",
			fmt.Sprintf("eviction of %s/%s blocked: PodMotion could not verify whether a "+
				"live migration is in progress for this pod (migration-state lookup failed: %v); "+
				"failing closed to protect a possible in-flight migration — retry the eviction shortly",
				podNamespace, podName, err),
			err, podNamespace, podName)
	}

	if activeMigration != nil {
		// Positive detection: an active migration targets this pod. Deny (retriable 429) so the
		// drain retries until the migration completes rather than aborting on a 403.
		return retriableDenied(fmt.Sprintf(
			"pod %s/%s is currently being migrated (PodMigration %s/%s, phase %s); "+
				"retry eviction after migration completes or reaches Failed state",
			podNamespace, podName,
			activeMigration.Namespace, activeMigration.Name,
			activeMigration.Status.Phase,
		))
	}

	// Positive fact: lookup completed and found no active migration. This is the ONLY path
	// to Allow — "I checked and it is safe", never "I could not check".
	return admission.Allowed("")
}

// findActiveMigration returns the in-progress PodMigration targeting this pod, or nil.
// It reads through the UNCACHED apiserver reader so the negative ("no active migration")
// decision is grounded in authoritative state, not a possibly-stale informer cache.
func (e *EvictionInterceptor) findActiveMigration(ctx context.Context, namespace, podName string) (*pmv1.PodMigration, error) {
	pmList := &pmv1.PodMigrationList{}
	if err := e.reader.List(ctx, pmList,
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
