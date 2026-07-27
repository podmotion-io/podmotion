//go:build scheduler

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package podmigration_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/scheduler-plugins/pkg/podmigration"
)

// stubPMReader satisfies NMCReader by serving a static PodMigration keyed on
// namespace/name. It exercises the migration-label fast path of Filter/Score, which
// reads a PodMigration rather than a NodeMigrationCapacity.
type stubPMReader struct {
	pm *v1alpha1.PodMigration
}

func (s *stubPMReader) Get(_ context.Context, key types.NamespacedName, obj client.Object, _ ...client.GetOption) error {
	if s.pm == nil || key.Name != s.pm.Name || key.Namespace != s.pm.Namespace {
		return &notFoundError{name: key.Name}
	}
	target, ok := obj.(*v1alpha1.PodMigration)
	if !ok {
		return &notFoundError{name: key.Name}
	}
	*target = *s.pm
	return nil
}

// migrationPod returns a replacement pod carrying the podmotion.io/migration-name
// label, which routes Filter/Score onto the exclusive migration-label fast path.
func migrationPod(pmName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replacement",
			Namespace: "default",
			Labels:    map[string]string{"podmotion.io/migration-name": pmName},
		},
	}
}

func pmWith(name string, statusDestNodeName, specTargetNodeName, specDestinationNode string) *v1alpha1.PodMigration {
	return &v1alpha1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: v1alpha1.PodMigrationSpec{
			TargetNodeName:  specTargetNodeName,
			DestinationNode: specDestinationNode,
		},
		Status: v1alpha1.PodMigrationStatus{
			DestinationNodeName: statusDestNodeName,
		},
	}
}

func node(name string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// --- Filter: chain resolution order ---

func TestFilter_MigrationLabel_ResolvesFromStatusDestinationNodeName(t *testing.T) {
	// All three links set — Status.DestinationNodeName must win.
	pm := pmWith("pm1", "node-status", "node-spec-target", "node-spec-dest")
	f := podmigration.NewMigrationAwareFilter(&stubPMReader{pm: pm}, runtime.NewScheme())

	result := f.Filter(context.Background(), migrationPod("pm1"), node("node-status"))
	if !result.Allowed {
		t.Fatalf("expected node-status to be allowed (Status.DestinationNodeName should win), got reason: %s", result.Reason)
	}

	result = f.Filter(context.Background(), migrationPod("pm1"), node("node-spec-target"))
	if result.Allowed {
		t.Fatalf("expected node-spec-target to be rejected when Status.DestinationNodeName is set")
	}
}

func TestFilter_MigrationLabel_FallsBackToSpecTargetNodeName(t *testing.T) {
	// Only Spec.TargetNodeName set (no Status yet) — the normal pre-cache-write window.
	pm := pmWith("pm2", "", "node-spec-target", "node-spec-dest")
	f := podmigration.NewMigrationAwareFilter(&stubPMReader{pm: pm}, runtime.NewScheme())

	result := f.Filter(context.Background(), migrationPod("pm2"), node("node-spec-target"))
	if !result.Allowed {
		t.Fatalf("expected node-spec-target to be allowed when only Spec.TargetNodeName is set, got reason: %s", result.Reason)
	}

	result = f.Filter(context.Background(), migrationPod("pm2"), node("node-spec-dest"))
	if result.Allowed {
		t.Fatalf("expected node-spec-dest to be rejected when Spec.TargetNodeName resolves first")
	}
}

func TestFilter_MigrationLabel_FallsBackToSpecDestinationNode(t *testing.T) {
	// Only the last-resort Spec.DestinationNode link set.
	pm := pmWith("pm3", "", "", "node-spec-dest")
	f := podmigration.NewMigrationAwareFilter(&stubPMReader{pm: pm}, runtime.NewScheme())

	result := f.Filter(context.Background(), migrationPod("pm3"), node("node-spec-dest"))
	if !result.Allowed {
		t.Fatalf("expected node-spec-dest to be allowed as last-resort fallback, got reason: %s", result.Reason)
	}
}

func TestFilter_MigrationLabel_EmptyChainFailsClosed(t *testing.T) {
	// Nothing in the chain set — must reject every node (fail-closed), never guess.
	pm := pmWith("pm4", "", "", "")
	f := podmigration.NewMigrationAwareFilter(&stubPMReader{pm: pm}, runtime.NewScheme())

	for _, n := range []string{"node-a", "node-b", ""} {
		result := f.Filter(context.Background(), migrationPod("pm4"), node(n))
		if result.Allowed {
			t.Fatalf("expected node %q to be rejected when the destination chain is entirely empty (fail-closed), got allowed", n)
		}
	}
}

// --- Score: chain resolution order ---

func TestScore_MigrationLabel_ResolvesFromStatusDestinationNodeName(t *testing.T) {
	pm := pmWith("pm5", "node-status", "node-spec-target", "node-spec-dest")
	s := podmigration.NewMigrationAwareScore(&stubPMReader{pm: pm}, podmigration.DefaultWeights)

	score, err := s.Score(context.Background(), migrationPod("pm5"), node("node-status"))
	if err != nil {
		t.Fatalf("Score error: %v", err)
	}
	if score != 100 {
		t.Fatalf("expected maxScore for the Status-resolved destination, got %d", score)
	}

	score, err = s.Score(context.Background(), migrationPod("pm5"), node("node-spec-target"))
	if err != nil {
		t.Fatalf("Score error: %v", err)
	}
	if score != 0 {
		t.Fatalf("expected 0 for a non-destination node when Status.DestinationNodeName resolves first, got %d", score)
	}
}

func TestScore_MigrationLabel_FallsBackToSpecTargetNodeName(t *testing.T) {
	pm := pmWith("pm6", "", "node-spec-target", "node-spec-dest")
	s := podmigration.NewMigrationAwareScore(&stubPMReader{pm: pm}, podmigration.DefaultWeights)

	score, err := s.Score(context.Background(), migrationPod("pm6"), node("node-spec-target"))
	if err != nil {
		t.Fatalf("Score error: %v", err)
	}
	if score != 100 {
		t.Fatalf("expected maxScore when only Spec.TargetNodeName is set, got %d", score)
	}
}

func TestScore_MigrationLabel_EmptyChainScoresZero(t *testing.T) {
	// Fail-closed applies at Filter; Score must still never award a guessed node
	// maxScore when the chain is unresolved.
	pm := pmWith("pm7", "", "", "")
	s := podmigration.NewMigrationAwareScore(&stubPMReader{pm: pm}, podmigration.DefaultWeights)

	for _, n := range []string{"node-a", "node-b"} {
		score, err := s.Score(context.Background(), migrationPod("pm7"), node(n))
		if err != nil {
			t.Fatalf("Score error: %v", err)
		}
		if score != 0 {
			t.Fatalf("expected 0 for node %q when the destination chain is entirely empty, got %d", n, score)
		}
	}
}
