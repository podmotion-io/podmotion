/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/metrics"
)

func newEvictionScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme corev1: %v", err)
	}
	if err := policyv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme policyv1: %v", err)
	}
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme pmv1: %v", err)
	}
	return scheme
}

// evictionReq builds a CREATE admission request on pods/eviction carrying the given Eviction
// object as req.Object.Raw (what the apiserver sends). If raw is non-nil it is used verbatim
// (to exercise the decode-error path with malformed bytes).
func evictionReq(t *testing.T, ev *policyv1.Eviction, raw []byte) admission.Request {
	t.Helper()
	if raw == nil {
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal eviction: %v", err)
		}
		raw = b
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Name:               ev.Name,
		Namespace:          ev.Namespace,
		Operation:          admissionv1.Create,
		SubResource:        "eviction",
		RequestSubResource: "eviction",
		Resource:           metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
		Object:             runtime.RawExtension{Raw: raw},
	}}
}

func migrationForPod(name, ns, podName, podNS string) *pmv1.PodMigration {
	return &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       pmv1.PodMigrationSpec{PodName: podName, PodNamespace: podNS},
	}
}

// readerWithMigration builds a fake reader holding a PodMigration whose Status.Phase is
// persisted (the fake client only honors spec on create, so status is seeded via
// Status().Update against a registered status subresource).
func readerWithMigration(t *testing.T, scheme *runtime.Scheme, pm *pmv1.PodMigration, phase pmv1.MigrationPhase) client.Reader {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pm).
		WithStatusSubresource(pm).
		Build()
	pm.Status.Phase = phase
	if err := c.Status().Update(context.Background(), pm); err != nil {
		t.Fatalf("seed migration status: %v", err)
	}
	return c
}

// TestEvictionInterceptor_FailClosed is the ADR-0401 core regression suite: every
// unverifiable-state path must DENY (retriable 429), never Allow, and only a positively
// verified "no active migration" may Allow.
func TestEvictionInterceptor_FailClosed(t *testing.T) {
	scheme := newEvictionScheme(t)
	decoder := admission.NewDecoder(scheme)

	ev := &policyv1.Eviction{
		TypeMeta:   metav1.TypeMeta{APIVersion: "policy/v1", Kind: "Eviction"},
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "team-a"},
	}

	t.Run("api_error_denies_429_not_allow", func(t *testing.T) {
		before := testutil.ToFloat64(metrics.EvictionWebhookFailClosedTotal.WithLabelValues("api_error"))
		// Reader whose List always errors with a non-NotFound error → could-not-verify.
		reader := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errors.New("apiserver timeout")
			},
		}).Build()
		e := &EvictionInterceptor{reader: reader, decoder: decoder}

		resp := e.Handle(context.Background(), evictionReq(t, ev, nil))
		if resp.Allowed {
			t.Fatalf("api_error must DENY (fail closed), got Allowed=true")
		}
		if got := resp.Result.Code; got != http.StatusTooManyRequests {
			t.Fatalf("api_error denial must be 429 TooManyRequests, got %d", got)
		}
		after := testutil.ToFloat64(metrics.EvictionWebhookFailClosedTotal.WithLabelValues("api_error"))
		if after != before+1 {
			t.Fatalf("api_error must increment failclosed_total{api_error}: before=%v after=%v", before, after)
		}
	})

	t.Run("decode_error_denies_429_not_allow", func(t *testing.T) {
		before := testutil.ToFloat64(metrics.EvictionWebhookFailClosedTotal.WithLabelValues("decode_error"))
		reader := fake.NewClientBuilder().WithScheme(scheme).Build()
		e := &EvictionInterceptor{reader: reader, decoder: decoder}

		// Malformed JSON body → decoder.Decode fails.
		resp := e.Handle(context.Background(), evictionReq(t, ev, []byte("{ not valid json")))
		if resp.Allowed {
			t.Fatalf("decode_error must DENY (fail closed), got Allowed=true")
		}
		if got := resp.Result.Code; got != http.StatusTooManyRequests {
			t.Fatalf("decode_error denial must be 429 TooManyRequests, got %d", got)
		}
		after := testutil.ToFloat64(metrics.EvictionWebhookFailClosedTotal.WithLabelValues("decode_error"))
		if after != before+1 {
			t.Fatalf("decode_error must increment failclosed_total{decode_error}: before=%v after=%v", before, after)
		}
	})

	t.Run("no_active_migration_allows", func(t *testing.T) {
		// A terminal-phase migration for this pod must be treated as inactive → Allow.
		done := migrationForPod("m-done", "team-a", "web-0", "team-a")
		reader := readerWithMigration(t, scheme, done, pmv1.MigrationPhaseComplete)
		e := &EvictionInterceptor{reader: reader, decoder: decoder}

		resp := e.Handle(context.Background(), evictionReq(t, ev, nil))
		if !resp.Allowed {
			t.Fatalf("no active migration must ALLOW, got denied: %v", resp.Result)
		}
	})

	t.Run("active_migration_denies_429", func(t *testing.T) {
		mig := migrationForPod("m-live", "team-a", "web-0", "team-a")
		reader := readerWithMigration(t, scheme, mig, pmv1.MigrationPhaseRestoring)
		e := &EvictionInterceptor{reader: reader, decoder: decoder}

		resp := e.Handle(context.Background(), evictionReq(t, ev, nil))
		if resp.Allowed {
			t.Fatalf("active migration must DENY, got Allowed=true")
		}
		if got := resp.Result.Code; got != http.StatusTooManyRequests {
			t.Fatalf("active-migration denial must be 429 (drain retries, not aborts), got %d", got)
		}
	})

	t.Run("notfound_list_error_allows", func(t *testing.T) {
		// A NotFound error from the read is the one error that means "no such object" → Allow,
		// per the existing IsNotFound carve-out.
		reader := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return apierrors.NewNotFound(schema.GroupResource{Group: "migration.podmotion.io", Resource: "podmigrations"}, "")
			},
		}).Build()
		e := &EvictionInterceptor{reader: reader, decoder: decoder}

		resp := e.Handle(context.Background(), evictionReq(t, ev, nil))
		if !resp.Allowed {
			t.Fatalf("IsNotFound read must ALLOW, got denied: %v", resp.Result)
		}
	})
}
