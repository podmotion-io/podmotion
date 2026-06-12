package gitops

// GitOpsProvider identifies which GitOps tool manages a workload.
type GitOpsProvider string

const (
	GitOpsProviderNone   GitOpsProvider = "None"
	GitOpsProviderArgoCD GitOpsProvider = "ArgoCD"
	GitOpsProviderFlux   GitOpsProvider = "Flux"
)

// GitOpsContext carries the detected GitOps ownership for a migrating pod.
type GitOpsContext struct {
	Provider          GitOpsProvider
	AppName           string // ArgoCD Application name
	AppNamespace      string // ArgoCD Application namespace (usually argocd)
	KustomizationName string // Flux Kustomization name
	KustomizationNS   string
	HelmReleaseName   string // Flux HelmRelease name
	HelmReleaseNS     string

	// Saved automated-sync flags captured at Suspend time; used by Resume to
	// restore the original ArgoCD Application spec.syncPolicy.automated values.
	OriginalAutomatedPrune    bool
	OriginalAutomatedSelfHeal bool
	// WasAutomated is false if spec.syncPolicy.automated was already nil before Suspend.
	// In that case Resume is a no-op (we must not suddenly enable auto-sync).
	WasAutomated bool
}
