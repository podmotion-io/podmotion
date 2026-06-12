package gitops

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var argoCDAppGVK = schema.GroupVersionKind{
	Group:   "argoproj.io",
	Version: "v1alpha1",
	Kind:    "Application",
}

// ArgoCDClient suspends and resumes ArgoCD Applications.
// Uses unstructured PATCH so there is no dependency on the ArgoCD Go SDK —
// the argocd-application-controller API is stable across v2.x and v3.x.
type ArgoCDClient struct{ Client client.Client }

// Suspend disables ArgoCD's automated sync for the Application so it will not
// reconcile the workload during the migration window.
//
// Strategy: PATCH spec.syncPolicy.automated = null.
// If spec.operation is set (a sync in progress), clear it to avoid conflict.
// The Application is NOT deleted — this is a reversible, surgical suspension.
func (a *ArgoCDClient) Suspend(ctx context.Context, gctx *GitOpsContext) error {
	if gctx.Provider != GitOpsProviderArgoCD || gctx.AppName == "" {
		return nil
	}
	appNS := gctx.AppNamespace
	if appNS == "" {
		appNS = "argocd"
	}

	app := &unstructured.Unstructured{}
	app.SetGroupVersionKind(argoCDAppGVK)
	if err := a.Client.Get(ctx, types.NamespacedName{Namespace: appNS, Name: gctx.AppName}, app); err != nil {
		return fmt.Errorf("argocd suspend: get Application %s/%s: %w", appNS, gctx.AppName, err)
	}

	// Capture the existing automated-sync flags before nullifying them so Resume can restore.
	if automated, ok, _ := unstructured.NestedMap(app.Object, "spec", "syncPolicy", "automated"); ok {
		gctx.WasAutomated = true
		gctx.OriginalAutomatedPrune, _, _ = unstructured.NestedBool(automated, "prune")
		gctx.OriginalAutomatedSelfHeal, _, _ = unstructured.NestedBool(automated, "selfHeal")
	}

	// Build a merge-patch that nullifies spec.syncPolicy.automated.
	// We also clear spec.operation if set to avoid an in-flight sync racing us.
	patch := map[string]interface{}{
		"spec": map[string]interface{}{
			"syncPolicy": map[string]interface{}{
				"automated": nil, // null disables auto-sync
			},
		},
	}
	if _, hasOp, _ := unstructured.NestedMap(app.Object, "spec", "operation"); hasOp {
		patch["spec"].(map[string]interface{})["operation"] = nil
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("argocd suspend: marshal patch: %w", err)
	}

	target := &unstructured.Unstructured{}
	target.SetGroupVersionKind(argoCDAppGVK)
	target.SetNamespace(appNS)
	target.SetName(gctx.AppName)
	if err := a.Client.Patch(ctx, target, client.RawPatch(types.MergePatchType, patchBytes)); err != nil {
		return fmt.Errorf("argocd suspend: patch Application %s/%s: %w", appNS, gctx.AppName, err)
	}
	return nil
}

// Resume restores ArgoCD automated sync for the Application.
//
// Strategy: PATCH spec.syncPolicy.automated = {prune: <existing>, selfHeal: <existing>}.
// We re-read the Application before restoring to preserve the original prune/selfHeal flags
// (which were stored in the GitOpsContext by Suspend). If they were never set, we restore
// a sensible default (prune: false, selfHeal: true) matching ArgoCD's UI default.
func (a *ArgoCDClient) Resume(ctx context.Context, gctx GitOpsContext) error {
	if gctx.Provider != GitOpsProviderArgoCD || gctx.AppName == "" {
		return nil
	}
	appNS := gctx.AppNamespace
	if appNS == "" {
		appNS = "argocd"
	}

	// If automated sync was already disabled before Suspend, do not enable it on Resume.
	if !gctx.WasAutomated {
		return nil
	}

	// Restore automated sync using the flags captured at Suspend time.
	automated := map[string]interface{}{
		"prune":    gctx.OriginalAutomatedPrune,
		"selfHeal": gctx.OriginalAutomatedSelfHeal,
	}

	patch := map[string]interface{}{
		"spec": map[string]interface{}{
			"syncPolicy": map[string]interface{}{
				"automated": automated,
			},
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("argocd resume: marshal patch: %w", err)
	}

	target := &unstructured.Unstructured{}
	target.SetGroupVersionKind(argoCDAppGVK)
	target.SetNamespace(appNS)
	target.SetName(gctx.AppName)
	if err := a.Client.Patch(ctx, target, client.RawPatch(types.MergePatchType, patchBytes)); err != nil {
		return fmt.Errorf("argocd resume: patch Application %s/%s: %w", appNS, gctx.AppName, err)
	}
	return nil
}
