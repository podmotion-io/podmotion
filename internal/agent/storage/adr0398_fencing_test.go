/*
Copyright 2026 The PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage_test

// adr0398_fencing_test.go — ADR-0398 D1 fencing: a terminal StorageReadyForFreeze write from a
// SUPERSEDED storage pre-stage dispatch (one whose single-dispatch claim was re-claimed by a later
// reconcile, so the live marker records a different ClaimToken) is refused. This is defense-in-depth
// atop the operator's exactly-once launch gate.

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
)

func TestADR0398_RunPreStage_SupersededTokenSkipsTerminalWrite(t *testing.T) {
	cases := []struct {
		name        string
		markerToken string // token recorded on the live marker
		runToken    string // token this RunPreStage was launched under
		wantWrite   bool   // whether the terminal BlockedVolume condition should be written
	}{
		{"matching-token-writes", "T1", "T1", true},
		{"empty-token-disables-fencing-writes", "T1", "", true},
		{"superseded-token-skips-write", "T2", "T1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newManagerScheme(t)
			pm := makeMigration("mig-fence", "default", "src-pod")
			pm.Status.StoragePreStageDispatch = &pmv1.StoragePreStageDispatch{
				Phase:      pmv1.StoragePreStageInFlight,
				ClaimToken: tc.markerToken,
				ClaimedAt:  metav1.Now(),
			}
			pod := makePodWithEmptyDir("default", "src-pod") // classifies TierBlocked → BlockedVolume

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pm, pod).
				WithStatusSubresource(pm).
				Build()

			mgr := storage.NewStorageMigrationManager(c)
			if err := mgr.RunPreStage(context.Background(), pm, false, tc.runToken); err != nil {
				t.Fatalf("RunPreStage returned error: %v", err)
			}

			cond := readStorageReady(t, c, pm)
			if tc.wantWrite {
				if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "BlockedVolume" {
					t.Fatalf("expected a terminal BlockedVolume write, got: %+v", cond)
				}
			} else {
				if cond != nil {
					t.Fatalf("superseded dispatch must NOT write a terminal verdict, got: %+v", cond)
				}
			}
		})
	}
}
