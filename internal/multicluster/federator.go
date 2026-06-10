/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package multicluster provides the control-plane scaffolding for cross-cluster
// pod migration (ADR-0022). In v0.x/v1.x all migrations are intra-cluster;
// this package activates at M14+ (post-v1.0).
package multicluster

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// RemoteCluster describes a peer cluster that can serve as a migration destination.
type RemoteCluster struct {
	// Name is the logical cluster identifier used in spec.destinationCluster.
	Name string
	// APIServerURL is the kube-apiserver endpoint of the remote cluster.
	APIServerURL string
	// KubeconfigSecret names the Secret (in the operator namespace) containing
	// a kubeconfig with sufficient permissions on the remote cluster.
	KubeconfigSecret string
}

// ClusterFederator manages connections to remote clusters and orchestrates the
// cross-cluster leg of a migration. The source-cluster controller retains
// ownership; the remote cluster runs an independent reconcile loop fed by a
// mirrored PodMigration CR created via CreateRemotePodMigration.
type ClusterFederator interface {
	// GetRemoteClient returns a controller-runtime client scoped to the named cluster.
	// Returns an error if the cluster is not registered or the kubeconfig is invalid.
	GetRemoteClient(clusterName string) (client.Client, error)

	// CreateRemotePodMigration creates a PodMigration CR on the destination cluster
	// that describes the restore-side of the migration. The source PodMigration is
	// used to propagate spec fields; the returned CR is the remote object.
	CreateRemotePodMigration(ctx context.Context, srcPM *pmv1.PodMigration, destCluster string) (*pmv1.PodMigration, error)

	// WatchRemoteMigration streams phase transitions from the remote PodMigration until
	// the migration reaches a terminal phase (Complete or Failed) or ctx is cancelled.
	WatchRemoteMigration(ctx context.Context, destCluster, migrationName, ns string) (<-chan pmv1.MigrationPhase, error)
}

// StubClusterFederator satisfies ClusterFederator during intra-cluster operation.
// Every method returns a descriptive error so callers that incorrectly invoke
// multi-cluster paths in v0.x/v1.x fail loudly rather than silently.
type StubClusterFederator struct{}

var _ ClusterFederator = (*StubClusterFederator)(nil)

func (s *StubClusterFederator) GetRemoteClient(clusterName string) (client.Client, error) {
	return nil, fmt.Errorf("multi-cluster requires remote cluster config: cluster %q is not registered (feature available post-v1.0)", clusterName)
}

func (s *StubClusterFederator) CreateRemotePodMigration(_ context.Context, _ *pmv1.PodMigration, destCluster string) (*pmv1.PodMigration, error) {
	return nil, fmt.Errorf("multi-cluster requires remote cluster config: cannot create remote PodMigration on cluster %q", destCluster)
}

func (s *StubClusterFederator) WatchRemoteMigration(_ context.Context, destCluster, migrationName, _ string) (<-chan pmv1.MigrationPhase, error) {
	return nil, fmt.Errorf("multi-cluster requires remote cluster config: cannot watch migration %q on cluster %q", migrationName, destCluster)
}
