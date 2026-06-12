package gitops

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FluxClient suspends and resumes Flux Kustomizations and HelmReleases.
type FluxClient struct{ Client client.Client }

// Suspend patches Kustomization.spec.suspend and/or HelmRelease.spec.suspend to true.
func (f *FluxClient) Suspend(ctx context.Context, gctx *GitOpsContext) error {
	// TODO(M19b-Sprint2): patch Kustomization.spec.suspend + HelmRelease.spec.suspend
	return nil
}

// Resume removes the suspend flag from the Flux resources.
func (f *FluxClient) Resume(ctx context.Context, gctx GitOpsContext) error {
	// TODO(M19b-Sprint2): unpatch
	return nil
}
