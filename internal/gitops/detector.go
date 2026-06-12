package gitops

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// argoAnnotations are the well-known labels/annotations ArgoCD injects on managed resources.
var argoAnnotations = []string{
	"argocd.argoproj.io/app-name",
	"app.kubernetes.io/instance", // ArgoCD sets this to the app name
}

// fluxAnnotations that Flux sets on managed resources.
var fluxKsAnnotation = "kustomize.toolkit.fluxcd.io/name"
var fluxHRAnnotation = "helm.toolkit.fluxcd.io/name"
var fluxKsNSAnnotation = "kustomize.toolkit.fluxcd.io/namespace"
var fluxHRNSAnnotation = "helm.toolkit.fluxcd.io/namespace"

// Detect walks a pod's ownerRef chain and returns the GitOpsContext for the workload.
// Returns GitOpsContext{Provider: None} if no GitOps controller is detected.
//
// Detection strategy (in order):
//  1. Check pod annotations / labels for ArgoCD or Flux markers.
//  2. Walk ownerRefs upward (Pod → ReplicaSet → Deployment → etc.) and accumulate
//     annotations from each level; stop when an ArgoCD Application or Flux object is found.
//  3. Fall back to None if neither provider is detected.
func Detect(ctx context.Context, c client.Client, pod *corev1.Pod) (GitOpsContext, error) {
	ns := pod.Namespace

	// Check pod-level annotations first (ArgoCD propagates its app-name annotation down).
	if gctx, ok := checkArgoAnnotations(pod.Annotations, pod.Labels); ok {
		return gctx, nil
	}
	if gctx, ok := checkFluxAnnotations(pod.Annotations); ok {
		return gctx, nil
	}

	// Walk the ownerRef chain up to 5 levels deep.
	current := &unstructured.Unstructured{}
	current.SetAnnotations(pod.Annotations)
	current.SetLabels(pod.Labels)
	current.SetOwnerReferences(pod.OwnerReferences)
	current.SetNamespace(ns)

	for depth := 0; depth < 5; depth++ {
		refs := current.GetOwnerReferences()
		if len(refs) == 0 {
			break
		}
		parent, err := resolveOwnerRef(ctx, c, ns, refs[0])
		if err != nil || parent == nil {
			break
		}
		if gctx, ok := checkArgoAnnotations(parent.GetAnnotations(), parent.GetLabels()); ok {
			return gctx, nil
		}
		if gctx, ok := checkFluxAnnotations(parent.GetAnnotations()); ok {
			return gctx, nil
		}
		current = parent
	}

	// Last resort: check for an ArgoCD Application in argocd namespace that lists
	// the pod's namespace as a destination. This covers cases where ArgoCD does NOT
	// propagate annotations (e.g. server-side apply with pruning enabled).
	if gctx, err := scanArgoCDApplications(ctx, c, ns); err == nil && gctx.Provider != GitOpsProviderNone {
		return gctx, nil
	}

	return GitOpsContext{Provider: GitOpsProviderNone}, nil
}

func checkArgoAnnotations(annotations, labels map[string]string) (GitOpsContext, bool) {
	// ArgoCD app name can be in annotation OR label depending on ArgoCD version.
	for _, key := range argoAnnotations {
		if appName, ok := annotations[key]; ok && appName != "" {
			appNS := annotations["argocd.argoproj.io/app-namespace"]
			if appNS == "" {
				appNS = "argocd"
			}
			return GitOpsContext{
				Provider:     GitOpsProviderArgoCD,
				AppName:      appName,
				AppNamespace: appNS,
			}, true
		}
		if labels != nil {
			if appName, ok := labels[key]; ok && appName != "" {
				return GitOpsContext{
					Provider:     GitOpsProviderArgoCD,
					AppName:      appName,
					AppNamespace: "argocd",
				}, true
			}
		}
	}
	return GitOpsContext{}, false
}

func checkFluxAnnotations(annotations map[string]string) (GitOpsContext, bool) {
	if ksName, ok := annotations[fluxKsAnnotation]; ok && ksName != "" {
		return GitOpsContext{
			Provider:          GitOpsProviderFlux,
			KustomizationName: ksName,
			KustomizationNS:   annotations[fluxKsNSAnnotation],
		}, true
	}
	if hrName, ok := annotations[fluxHRAnnotation]; ok && hrName != "" {
		return GitOpsContext{
			Provider:        GitOpsProviderFlux,
			HelmReleaseName: hrName,
			HelmReleaseNS:   annotations[fluxHRNSAnnotation],
		}, true
	}
	return GitOpsContext{}, false
}

func resolveOwnerRef(ctx context.Context, c client.Client, ns string, ref metav1.OwnerReference) (*unstructured.Unstructured, error) {
	gv, err := schema.ParseGroupVersion(ref.APIVersion)
	if err != nil {
		return nil, err
	}
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   gv.Group,
		Version: gv.Version,
		Kind:    ref.Kind,
	})
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// scanArgoCDApplications lists Applications in common ArgoCD namespaces and returns
// one that targets the given namespace. Used as a fallback when annotation propagation
// is disabled. Only reads — no writes.
func scanArgoCDApplications(ctx context.Context, c client.Client, targetNS string) (GitOpsContext, error) {
	appList := &unstructured.UnstructuredList{}
	appList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "argoproj.io",
		Version: "v1alpha1",
		Kind:    "ApplicationList",
	})
	// Try argocd namespace first; failure is non-fatal.
	for _, ns := range []string{"argocd", "gitops", "argo-cd"} {
		if err := c.List(ctx, appList, client.InNamespace(ns)); err != nil {
			continue
		}
		for _, app := range appList.Items {
			dest, _, _ := unstructured.NestedMap(app.Object, "spec", "destination")
			if destNS, ok := dest["namespace"].(string); ok && destNS == targetNS {
				return GitOpsContext{
					Provider:     GitOpsProviderArgoCD,
					AppName:      app.GetName(),
					AppNamespace: ns,
				}, nil
			}
		}
	}
	return GitOpsContext{Provider: GitOpsProviderNone}, nil
}
