/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package controller

// disarm_zero_window_retry_attempts_test.go — fail-closed phase-gate remediation (item 5) unit coverage.
//
// readDisarmZeroWindowRetryAttempts backs the bounded-retry gate that replaced
// reconcileDisengageHold's prior "fabricate ConditionZeroWindowDisarmed=True on ANY
// DisarmZeroWindow RPC error" behavior. This exercises the annotation round-trip the retry
// bound depends on: absent annotation → 0, a real recorded attempt count → that count, and a
// corrupt annotation value → 0 (fail safe, never a crash or a negative bound).

import (
	"testing"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

func TestReadDisarmZeroWindowRetryAttempts(t *testing.T) {
	t.Run("no annotations", func(t *testing.T) {
		pm := &pmv1.PodMigration{}
		if got := readDisarmZeroWindowRetryAttempts(pm); got != 0 {
			t.Errorf("expected 0, got %d", got)
		}
	})

	t.Run("recorded attempt count", func(t *testing.T) {
		pm := &pmv1.PodMigration{}
		pm.Annotations = map[string]string{disarmZeroWindowRetryAttemptsAnnotation: "2"}
		if got := readDisarmZeroWindowRetryAttempts(pm); got != 2 {
			t.Errorf("expected 2, got %d", got)
		}
	})

	t.Run("corrupt value fails safe to 0", func(t *testing.T) {
		pm := &pmv1.PodMigration{}
		pm.Annotations = map[string]string{disarmZeroWindowRetryAttemptsAnnotation: "not-a-number"}
		if got := readDisarmZeroWindowRetryAttempts(pm); got != 0 {
			t.Errorf("expected 0 on corrupt annotation value, got %d", got)
		}
	})
}
