/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package nri

// adr0351_antispoof_test.go pins ADR-0351 D4: the synchronous PodMigration-CR anti-spoof verify
// loop in HandleStartContainer MUST return well before containerd's real, GROUNDED
// nriPluginRequestTimeout (G0.3 — 2s on this substrate, docs/sprints/sprint46B7/
// g0-probe-adr0351-transcript.md) or containerd drops the plugin connection entirely, forcing
// every migration onto the raw-CRIU fallback where the D1 cgroup-anchor primitive never runs.

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// TestHandleStartContainer_AntiSpoofCtxCancel drives HandleStartContainer against a k8sClient
// whose PodMigration is permanently stuck in a REJECTED phase (Pending) — verifyPodMigration
// therefore returns the transient "phase is ..." error on EVERY call, so the anti-spoof loop
// keeps retrying for its entire budget, the worst case for D4.2's bound. A ctx bounded at the
// real (G0.3) nriPluginRequestTimeout stands in for containerd's own request deadline. The
// handler MUST return fail-closed (non-nil error) well before that deadline — proving the loop's
// own antiSpoofVerifyBudget is what ends it, not a containerd-side connection drop — and
// verifyPodMigration must remain the pre-entrypoint gate (called synchronously, inline, never
// relocated to the async PostStartContainer barrier).
func TestHandleStartContainer_AntiSpoofCtxCancel(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	const checkpointRef = "adr0351-antispoof-test"
	const namespace = "default"

	// A REJECTED phase (Pending, not in the accept-set) so verifyPodMigration ALWAYS returns the
	// transient "phase is Pending" error — the loop retries until its own budget is spent, never
	// resolving. This is the worst case: it forces every retry iteration to actually run.
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: checkpointRef, Namespace: namespace},
		Status:     pmv1.PodMigrationStatus{Phase: pmv1.MigrationPhasePending},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm).Build()

	p := New(nil, nil).WithK8sVerification(fakeClient, "this-node")

	event := ContainerEvent{
		ID:          "container-antispoof-test",
		Name:        "redis",
		Namespace:   namespace,
		Pod:         "redis-src-m-antispoof",
		Annotations: map[string]string{"podmotion.io/checkpoint-ref": checkpointRef},
	}

	// Stand-in for containerd's own synchronous request deadline, bounded at the GROUNDED real
	// value (G0.3) — NOT the previously-assumed 60s/30s.
	ctx, cancel := context.WithTimeout(context.Background(), nriPluginRequestTimeout)
	defer cancel()

	start := time.Now()
	err := p.HandleStartContainer(ctx, event)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("HandleStartContainer returned nil error against a PodMigration permanently stuck out of the accept-set — expected a fail-closed error")
	}
	if elapsed >= nriPluginRequestTimeout {
		t.Fatalf("HandleStartContainer took %s, >= nriPluginRequestTimeout (%s) — the anti-spoof loop OVERRAN containerd's real request budget (D4.2 regression); containerd would have already dropped the plugin connection, forcing the raw-CRIU fallback where the D1 primitive never runs",
			elapsed, nriPluginRequestTimeout)
	}
	// The loop's own budget (antiSpoofVerifyBudget, well under nriPluginRequestTimeout by design)
	// should be what actually ends it — assert elapsed is close to that budget, not to the full
	// ctx deadline, proving D4.2's bound (not ctx cancellation) is the effective limiter here.
	if elapsed > antiSpoofVerifyBudget+200*time.Millisecond {
		t.Fatalf("HandleStartContainer took %s — expected close to antiSpoofVerifyBudget (%s); the loop is not honoring its own D4.2 bound",
			elapsed, antiSpoofVerifyBudget)
	}
}
