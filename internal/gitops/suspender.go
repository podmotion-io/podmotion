package gitops

import "context"

// GitOpsSuspender suspends and resumes a GitOps controller's reconciliation
// for the workload described by GitOpsContext.
//
// Suspend receives a pointer so it can record the pre-suspension state (e.g.
// ArgoCD automated-sync flags) into gctx. Resume reads those saved fields to
// restore the original state precisely — never enabling auto-sync if it was
// already disabled before the migration window.
type GitOpsSuspender interface {
	Suspend(ctx context.Context, gctx *GitOpsContext) error
	Resume(ctx context.Context, gctx GitOpsContext) error
}

// NoopSuspender is used when no GitOps controller is detected.
type NoopSuspender struct{}

func (n *NoopSuspender) Suspend(_ context.Context, _ *GitOpsContext) error { return nil }
func (n *NoopSuspender) Resume(_ context.Context, _ GitOpsContext) error   { return nil }
