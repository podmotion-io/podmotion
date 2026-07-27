/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package nmcregistrar

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
)

// newTestScheme builds a scheme with both the client-go and pmv1 types registered,
// mirroring nmcregistrar.New's own scheme construction.
func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme (client-go): %v", err)
	}
	if err := pmv1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme (pmv1): %v", err)
	}
	return s
}

// --- SpawnErr vs ExitCode distinction driving retry/no-retry behavior -----------------

// TestDetectCRIUViaBroker_SpawnErr_RetriesBounded verifies ADR-0366 §3: a broker-
// unreachable SpawnErr is retried, bounded at exactly criuBrokerMaxAttempts (3) — not
// infinitely — with a fixed backoff between attempts, and the final error is classified
// ReasonCRIUBrokerUnreachable.
func TestDetectCRIUViaBroker_SpawnErr_RetriesBounded(t *testing.T) {
	var calls int32
	r := &Registrar{
		hostExec: func(_ context.Context, _ time.Duration, _ ...string) netnsbroker.ExecResult {
			atomic.AddInt32(&calls, 1)
			return netnsbroker.ExecResult{ExitCode: -1, SpawnErr: errors.New("dial unix /run/podmotion/netns-broker.sock: connect: connection refused")}
		},
	}

	start := time.Now()
	version, err := r.detectCRIU(context.Background())
	elapsed := time.Since(start)

	if version != "" {
		t.Errorf("version = %q, want empty on broker-unreachable failure", version)
	}
	if err == nil {
		t.Fatal("err = nil, want a non-nil classified error")
	}
	var de *criuDetectionError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v (%T), want *criuDetectionError", err, err)
	}
	if de.reason != pmv1.ReasonCRIUBrokerUnreachable {
		t.Errorf("reason = %q, want %q", de.reason, pmv1.ReasonCRIUBrokerUnreachable)
	}
	if got := atomic.LoadInt32(&calls); got != criuBrokerMaxAttempts {
		t.Errorf("hostExec called %d times, want exactly %d (bounded, not infinite)", got, criuBrokerMaxAttempts)
	}
	// 2 backoffs between 3 attempts, 500ms each => must have taken at least that long,
	// proving the retry actually waited rather than spinning, but must also have
	// terminated (this whole test function returning at all proves boundedness).
	minExpected := 2 * criuBrokerRetryBackoff
	if elapsed < minExpected {
		t.Errorf("elapsed = %v, want >= %v (expected backoff between bounded retries)", elapsed, minExpected)
	}
}

// TestDetectCRIUViaBroker_ExitCodeNonZero_NoRetry verifies ADR-0366 §3: a genuine CRIU
// failure (broker reached, ExitCode != 0) is logged and returned immediately — NOT
// retried, since retrying a deterministic failure only delays an equally-real WARN.
func TestDetectCRIUViaBroker_ExitCodeNonZero_NoRetry(t *testing.T) {
	var calls int32
	r := &Registrar{
		hostExec: func(_ context.Context, _ time.Duration, _ ...string) netnsbroker.ExecResult {
			atomic.AddInt32(&calls, 1)
			return netnsbroker.ExecResult{ExitCode: 1, Stderr: []byte("criu: GLIBC_2.38 not found")}
		},
	}

	version, err := r.detectCRIU(context.Background())

	if version != "" {
		t.Errorf("version = %q, want empty on exit-code failure", version)
	}
	var de *criuDetectionError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v (%T), want *criuDetectionError", err, err)
	}
	if de.reason != pmv1.ReasonCRIUExecFailed {
		t.Errorf("reason = %q, want %q", de.reason, pmv1.ReasonCRIUExecFailed)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("hostExec called %d times, want exactly 1 (no retry on a genuine ExitCode failure)", got)
	}
}

// TestDetectCRIUViaBroker_Success verifies the happy path parses the version out of
// ExecResult.Combined and calls hostExec exactly once.
func TestDetectCRIUViaBroker_Success(t *testing.T) {
	var calls int32
	r := &Registrar{
		hostExec: func(_ context.Context, _ time.Duration, argv ...string) netnsbroker.ExecResult {
			atomic.AddInt32(&calls, 1)
			if len(argv) < 3 || argv[0] != hostCRIUWrapperPath || argv[1] != "--" || argv[2] != criuBinaryPath {
				t.Errorf("argv = %v, want [%s -- %s ...]", argv, hostCRIUWrapperPath, criuBinaryPath)
			}
			return netnsbroker.ExecResult{ExitCode: 0, Combined: []byte("Version: 4.2\n")}
		},
	}

	version, err := r.detectCRIU(context.Background())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if version != "4.2" {
		t.Errorf("version = %q, want %q", version, "4.2")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("hostExec called %d times, want exactly 1", got)
	}
}

// TestDetectCRIU_DirectFallback_WhenHostExecNil verifies detectCRIU routes through the
// direct in-container exec fallback (never touching hostExec) when hostExec is nil, and
// still returns a classified, non-swallowed error on failure (no bare "" with no error).
func TestDetectCRIU_DirectFallback_WhenHostExecNil(t *testing.T) {
	r := &Registrar{} // hostExec is nil (zero value)

	version, err := r.detectCRIU(context.Background())
	// In this test environment there is no /usr/sbin/criu, /usr/local/sbin/criu, or a
	// "criu" on PATH, so this exercises the direct-exec failure branch.
	if version != "" {
		t.Skip("a real criu binary is on PATH in this environment; direct-exec-failure branch not exercised")
	}
	var de *criuDetectionError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v (%T), want *criuDetectionError (never a silently-swallowed empty error)", err, err)
	}
	if de.reason != pmv1.ReasonCRIUExecFailed {
		t.Errorf("reason = %q, want %q", de.reason, pmv1.ReasonCRIUExecFailed)
	}
}

// --- Heartbeat() self-heal ---------------------------------------------------------

func newTestRegistrar(t *testing.T, nmc *pmv1.NodeMigrationCapacity, hostExec hostExecFunc) *Registrar {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithStatusSubresource(&pmv1.NodeMigrationCapacity{}).
		WithObjects(nmc).
		Build()
	return &Registrar{client: c, nodeName: nmc.Name, hostExec: hostExec}
}

// TestHeartbeat_ReattemptsDetection_WhenCRIUVersionEmpty verifies ADR-0366 §3's
// required companion fix: Heartbeat() now genuinely re-attempts detectCRIU (and
// re-PATCHes Spec.CRIUVersion) when the stored value is empty.
func TestHeartbeat_ReattemptsDetection_WhenCRIUVersionEmpty(t *testing.T) {
	nmc := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       pmv1.NodeMigrationCapacitySpec{NodeName: "node-a", CRIUVersion: ""},
	}
	var calls int32
	r := newTestRegistrar(t, nmc, func(_ context.Context, _ time.Duration, _ ...string) netnsbroker.ExecResult {
		atomic.AddInt32(&calls, 1)
		return netnsbroker.ExecResult{ExitCode: 0, Combined: []byte("Version: 4.2\n")}
	})

	if err := r.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("hostExec called %d times, want exactly 1 (Heartbeat should re-attempt detection once)", got)
	}

	got := &pmv1.NodeMigrationCapacity{}
	if err := r.client.Get(context.Background(), types.NamespacedName{Name: "node-a"}, got); err != nil {
		t.Fatalf("Get after Heartbeat: %v", err)
	}
	if got.Spec.CRIUVersion != "4.2" {
		t.Errorf("Spec.CRIUVersion = %q, want %q (self-heal did not persist)", got.Spec.CRIUVersion, "4.2")
	}
	cond := findCondition(got.Status.Conditions, pmv1.ConditionCRIUDetected)
	if cond == nil {
		t.Fatal("CRIUDetected condition not set after successful self-heal")
	}
	if cond.Status != metav1.ConditionTrue || cond.Reason != pmv1.ReasonCRIUVersionDetected {
		t.Errorf("condition = %+v, want Status=True Reason=%q", cond, pmv1.ReasonCRIUVersionDetected)
	}
}

// TestHeartbeat_DoesNotReattempt_WhenCRIUVersionAlreadySet verifies Heartbeat() does
// NOT re-run detectCRIU (no needless host-ns exec call) once Spec.CRIUVersion is
// already populated — verification assertion 6 of ADR-0366.
func TestHeartbeat_DoesNotReattempt_WhenCRIUVersionAlreadySet(t *testing.T) {
	nmc := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "node-b"},
		Spec:       pmv1.NodeMigrationCapacitySpec{NodeName: "node-b", CRIUVersion: "4.2"},
	}
	var calls int32
	r := newTestRegistrar(t, nmc, func(_ context.Context, _ time.Duration, _ ...string) netnsbroker.ExecResult {
		atomic.AddInt32(&calls, 1)
		t.Error("hostExec should not be called when Spec.CRIUVersion is already populated")
		return netnsbroker.ExecResult{ExitCode: 0, Combined: []byte("Version: 4.2\n")}
	})

	if err := r.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("hostExec called %d times, want 0", got)
	}

	got := &pmv1.NodeMigrationCapacity{}
	if err := r.client.Get(context.Background(), types.NamespacedName{Name: "node-b"}, got); err != nil {
		t.Fatalf("Get after Heartbeat: %v", err)
	}
	if got.Spec.CRIUVersion != "4.2" {
		t.Errorf("Spec.CRIUVersion = %q, want unchanged %q", got.Spec.CRIUVersion, "4.2")
	}
	if !got.Status.Ready {
		t.Error("Status.Ready = false, want true (Heartbeat's existing behavior must be preserved)")
	}
	cond := findCondition(got.Status.Conditions, pmv1.ConditionCRIUDetected)
	if cond == nil {
		t.Fatal("CRIUDetected condition not set")
	}
	if cond.Status != metav1.ConditionTrue || cond.Reason != pmv1.ReasonCRIUVersionDetected {
		t.Errorf("condition = %+v, want Status=True Reason=%q (reflecting the already-known version)", cond, pmv1.ReasonCRIUVersionDetected)
	}
}

// TestHeartbeat_SelfHeal_StaysEmptyAndSurfacesCondition_WhenStillFailing verifies that
// when the self-heal re-attempt ALSO fails, Heartbeat does not fabricate success: the
// field stays empty and the CRIUDetected condition surfaces the failure (Condition 2 —
// genuine observability, not a silent no-op).
func TestHeartbeat_SelfHeal_StaysEmptyAndSurfacesCondition_WhenStillFailing(t *testing.T) {
	nmc := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "node-c"},
		Spec:       pmv1.NodeMigrationCapacitySpec{NodeName: "node-c", CRIUVersion: ""},
	}
	r := newTestRegistrar(t, nmc, func(_ context.Context, _ time.Duration, _ ...string) netnsbroker.ExecResult {
		return netnsbroker.ExecResult{ExitCode: 1, Stderr: []byte("criu: GLIBC_2.38 not found")}
	})

	if err := r.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	got := &pmv1.NodeMigrationCapacity{}
	if err := r.client.Get(context.Background(), types.NamespacedName{Name: "node-c"}, got); err != nil {
		t.Fatalf("Get after Heartbeat: %v", err)
	}
	if got.Spec.CRIUVersion != "" {
		t.Errorf("Spec.CRIUVersion = %q, want still empty (detection genuinely failed)", got.Spec.CRIUVersion)
	}
	cond := findCondition(got.Status.Conditions, pmv1.ConditionCRIUDetected)
	if cond == nil {
		t.Fatal("CRIUDetected condition not set on a still-failing self-heal attempt")
	}
	if cond.Status != metav1.ConditionFalse || cond.Reason != pmv1.ReasonCRIUExecFailed {
		t.Errorf("condition = %+v, want Status=False Reason=%q", cond, pmv1.ReasonCRIUExecFailed)
	}
}

// --- Observability signal (Condition 2) actually firing on Register() --------------

// TestRegister_SetsCRIUDetectedConditionFalse_OnRealDetectionFailure verifies the new
// observability signal required by ADR-0366 Condition 2: a real detection failure
// during Register() results in a CRIUDetected=False condition on the persisted NMC —
// not just a log line — with a reason an operator/dashboard can act on.
func TestRegister_SetsCRIUDetectedConditionFalse_OnRealDetectionFailure(t *testing.T) {
	nmc := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "node-d"},
	}
	r := newTestRegistrar(t, nmc, func(_ context.Context, _ time.Duration, _ ...string) netnsbroker.ExecResult {
		return netnsbroker.ExecResult{ExitCode: 1, Stderr: []byte("criu: GLIBC_2.38 not found")}
	})
	r.agentPort = defaultAgentPort

	if err := r.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := &pmv1.NodeMigrationCapacity{}
	if err := r.client.Get(context.Background(), types.NamespacedName{Name: "node-d"}, got); err != nil {
		t.Fatalf("Get after Register: %v", err)
	}
	if got.Spec.CRIUVersion != "" {
		t.Errorf("Spec.CRIUVersion = %q, want empty", got.Spec.CRIUVersion)
	}
	cond := findCondition(got.Status.Conditions, pmv1.ConditionCRIUDetected)
	if cond == nil {
		t.Fatal("CRIUDetected condition not set by Register() on a real detection failure")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("condition.Status = %v, want False", cond.Status)
	}
	if cond.Reason != pmv1.ReasonCRIUExecFailed {
		t.Errorf("condition.Reason = %q, want %q", cond.Reason, pmv1.ReasonCRIUExecFailed)
	}
	if cond.Message == "" {
		t.Error("condition.Message is empty, want the underlying failure detail")
	}
}

// TestRegister_SetsCRIUDetectedConditionTrue_OnSuccess is the success-path mirror of
// the above, guarding against a regression that reports False unconditionally.
func TestRegister_SetsCRIUDetectedConditionTrue_OnSuccess(t *testing.T) {
	nmc := &pmv1.NodeMigrationCapacity{
		ObjectMeta: metav1.ObjectMeta{Name: "node-e"},
	}
	r := newTestRegistrar(t, nmc, func(_ context.Context, _ time.Duration, _ ...string) netnsbroker.ExecResult {
		return netnsbroker.ExecResult{ExitCode: 0, Combined: []byte("Version: 4.2\n")}
	})
	r.agentPort = defaultAgentPort

	if err := r.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := &pmv1.NodeMigrationCapacity{}
	if err := r.client.Get(context.Background(), types.NamespacedName{Name: "node-e"}, got); err != nil {
		t.Fatalf("Get after Register: %v", err)
	}
	if got.Spec.CRIUVersion != "4.2" {
		t.Errorf("Spec.CRIUVersion = %q, want %q", got.Spec.CRIUVersion, "4.2")
	}
	cond := findCondition(got.Status.Conditions, pmv1.ConditionCRIUDetected)
	if cond == nil {
		t.Fatal("CRIUDetected condition not set by Register() on success")
	}
	if cond.Status != metav1.ConditionTrue || cond.Reason != pmv1.ReasonCRIUVersionDetected {
		t.Errorf("condition = %+v, want Status=True Reason=%q", cond, pmv1.ReasonCRIUVersionDetected)
	}
}

func findCondition(conds []metav1.Condition, condType string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == condType {
			return &conds[i]
		}
	}
	return nil
}
