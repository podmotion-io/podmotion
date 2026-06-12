/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package webhook implements admission webhooks for PodMotion CRDs.
//
// ValidatingAdmissionWebhook rules for PodMigration (applied in order):
//
//  1. Pod existence — reject if the named pod does not exist in spec.podNamespace.
//  2. UID match — if spec.sourcePodUID is set, reject if it doesn't match the live pod.
//  3. Mode enum — enforce valid MigrationMode (redundant with CRD enum but defence-in-depth).
//  4. PostCopy requires userfaultfd — reject PostCopy if NMC reports Userfaultfd=false on source.
//  5. targetNodeName NMC readiness — if set, reject if NMC for that node is not Ready.
//  6. targetNodeName CRIU — if set, reject if NMC reports criuVersion == "".
//  7. targetNodeName capacity — if set, reject if ActiveDestinationMigrations >= Max.
//  8. networkContinuity downgrade — warn (annotation) if networkContinuity=true but CNI doesn't
//     support IP mobility; the webhook downgrades to networkContinuity=false rather than rejecting.
//  9. Tier 4 storage block — reject if any pod volume matches a Tier-4 unsupported pattern AND
//     storageStrategy is not explicitly set to Skip (caller's explicit opt-out).
//  10. Range validations — preCopyMaxRounds [1,20], preCopyDirtyThresholdMB >=1,
//     completionTimeoutSeconds >=30.
package webhook

import (
	"context"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/featuregate"
	"github.com/podmotion-io/podmotion/internal/multicluster"
)

var webhookLog = logf.Log.WithName("podmigration-webhook")

// PodMigrationValidator implements the ValidatingAdmissionWebhook for PodMigration.
// It is registered via SetupWithManager and served at /validate-podmotion-io-v1alpha1-podmigration.
type PodMigrationValidator struct {
	client    client.Client
	decoder   admission.Decoder
	Federator multicluster.ClusterFederator
}

// SetupWithManager registers the webhook with the controller-runtime manager.
func (v *PodMigrationValidator) SetupWithManager(mgr ctrl.Manager) error {
	v.client = mgr.GetClient()
	v.decoder = admission.NewDecoder(mgr.GetScheme())
	if v.Federator == nil {
		v.Federator = &multicluster.StubClusterFederator{}
	}
	mgr.GetWebhookServer().Register(
		"/validate-podmotion-io-v1alpha1-podmigration",
		&admission.Webhook{Handler: v},
	)
	return nil
}

// Handle implements admission.Handler.
func (v *PodMigrationValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	pm := &pmv1.PodMigration{}
	if err := v.decoder.Decode(req, pm); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if errs := v.validate(ctx, pm); len(errs) > 0 {
		return admission.Denied(errs.ToAggregate().Error())
	}
	return admission.Allowed("")
}

// validate runs all admission rules and returns any field errors.
func (v *PodMigrationValidator) validate(ctx context.Context, pm *pmv1.PodMigration) field.ErrorList {
	var allErrs field.ErrorList
	spec := field.NewPath("spec")

	// Rule 1: pod must exist
	pod, err := v.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			allErrs = append(allErrs, field.Invalid(spec.Child("podName"), pm.Spec.PodName,
				fmt.Sprintf("pod %s/%s not found", pm.Spec.PodNamespace, pm.Spec.PodName)))
		} else {
			allErrs = append(allErrs, field.InternalError(spec.Child("podName"), err))
		}
		// Can't proceed without the pod — remaining rules need it.
		return allErrs
	}

	// Rule 2: UID match if specified
	if pm.Spec.SourcePodUID != "" && string(pod.UID) != pm.Spec.SourcePodUID {
		allErrs = append(allErrs, field.Invalid(spec.Child("sourcePodUID"), pm.Spec.SourcePodUID,
			fmt.Sprintf("pod UID mismatch: live pod has UID %s", pod.UID)))
	}

	// Rule 3: mode enum (defence-in-depth — CRD enum already enforces this)
	switch pm.Spec.Mode {
	case pmv1.MigrationModePreCopy, pmv1.MigrationModePostCopy, pmv1.MigrationModeCold, "":
		// valid
	default:
		allErrs = append(allErrs, field.NotSupported(spec.Child("mode"), pm.Spec.Mode,
			[]string{"PreCopy", "PostCopy", "Cold"}))
	}

	// Rule 4: PostCopy requires userfaultfd on the source node
	if pm.Spec.Mode == pmv1.MigrationModePostCopy {
		sourceNode := pod.Spec.NodeName
		if sourceNode != "" {
			nmc, nmcErr := v.getNMC(ctx, sourceNode)
			if nmcErr == nil && !nmc.Spec.KernelFeatures.Userfaultfd {
				allErrs = append(allErrs, field.Forbidden(spec.Child("mode"),
					fmt.Sprintf("PostCopy requires CONFIG_USERFAULTFD on source node %q; node reports userfaultfd=false", sourceNode)))
			}
		}
	}

	// Rules 5-8: targetNodeName checks (only when explicitly set)
	if pm.Spec.TargetNodeName != "" {
		nmc, nmcErr := v.getNMC(ctx, pm.Spec.TargetNodeName)
		if nmcErr != nil {
			if apierrors.IsNotFound(nmcErr) {
				allErrs = append(allErrs, field.Invalid(spec.Child("targetNodeName"), pm.Spec.TargetNodeName,
					"no NodeMigrationCapacity found for this node; podmotion-agent may not be running there"))
			} else {
				allErrs = append(allErrs, field.InternalError(spec.Child("targetNodeName"), nmcErr))
			}
		} else {
			// Rule 5: NMC readiness
			if !nmc.Status.Ready {
				allErrs = append(allErrs, field.Invalid(spec.Child("targetNodeName"), pm.Spec.TargetNodeName,
					"NodeMigrationCapacity.status.ready=false; agent is not healthy on destination node"))
			}

			// Rule 6: CRIU present on destination
			if nmc.Spec.CRIUVersion == "" {
				allErrs = append(allErrs, field.Forbidden(spec.Child("targetNodeName"),
					fmt.Sprintf("destination node %q has no CRIU version reported; CRIU must be installed", pm.Spec.TargetNodeName)))
			}

			// Rule 7: destination capacity
			if nmc.Status.ActiveDestinationMigrations >= nmc.Spec.MaxConcurrentMigrationsDestination {
				allErrs = append(allErrs, field.Forbidden(spec.Child("targetNodeName"),
					fmt.Sprintf("destination node %q is at maximum concurrent migration capacity (%d/%d)",
						pm.Spec.TargetNodeName,
						nmc.Status.ActiveDestinationMigrations,
						nmc.Spec.MaxConcurrentMigrationsDestination)))
			}

			// Rule 8: networkContinuity downgrade (warn via annotation, not reject)
			// Handled in MutatingWebhook — see PodMigrationDefaulter.
		}
	}

	// Rule 8b: hard nodeAffinity / nodeSelector pinning check
	// If the source pod is pinned to its current node via hard constraints AND the caller
	// has not opted out (affinityMode=patch|ignore), deny the migration.
	if conflict, nodeName := detectHardNodeAffinity(pod); conflict {
		switch pm.Spec.AffinityMode {
		case pmv1.AffinityModePatch, pmv1.AffinityModeIgnore:
			// Caller acknowledged the conflict — allow and let the controller handle it.
		default: // AffinityModeStrict or unset → block
			allErrs = append(allErrs, field.Forbidden(spec.Child("affinityMode"),
				fmt.Sprintf("source pod has hard nodeAffinity pinning it to node %s; clear the affinity or set spec.affinityMode=patch|ignore before migrating", nodeName)))
		}
	}

	// Rule 9: Tier 4 storage block
	// Reject if any volume uses a hostPath, emptyDir with memory medium, or projected token volume
	// when storageStrategy is not Skip (explicit user opt-out).
	if pm.Spec.StorageStrategy != pmv1.StorageStrategySkip {
		if tier4Reason := detectTier4Volume(pod); tier4Reason != "" {
			allErrs = append(allErrs, field.Forbidden(spec.Child("storageStrategy"),
				fmt.Sprintf("pod uses unsupported storage (%s); set storageStrategy=Skip to bypass at your own risk", tier4Reason)))
		}
	}

	// Rule 10a: GPU migration gate — deny early if pod has GPU resources but gate is off.
	// This prevents a migration from reaching the Checkpointing phase only to fail there.
	// See ADR-0032: GPUMigration gate is never enabled by default.
	if webhookPodHasGPU(pod) && !featuregate.IsEnabled(featuregate.GPUMigration) {
		allErrs = append(allErrs, field.Forbidden(spec,
			"GPU migration requires --feature-gates=GPUMigration=true"))
	}

	// Rule 11: destinationCluster cross-cluster checks (ADR-0022, ADR-0034)
	if pm.Spec.DestinationCluster != "" {
		// Verify remote cluster connectivity.
		if _, err := v.Federator.GetRemoteClient(pm.Spec.DestinationCluster); err != nil {
			allErrs = append(allErrs, field.Invalid(spec.Child("destinationCluster"), pm.Spec.DestinationCluster,
				fmt.Sprintf("cannot reach remote cluster: %v", err)))
		}
		// Warn via annotation: multi-cluster uses TIER_4 network (reconnect model).
		// We surface this as an informational deny-override via an annotation rather
		// than a rejection because the caller has explicitly opted in to cross-cluster.
		webhookLog.Info("multi-cluster migration uses TIER_4 network reconnect model — IP preservation is not available",
			"destinationCluster", pm.Spec.DestinationCluster, "migration", pm.Name)
	}

	// Rule 10: range validations
	if pm.Spec.PreCopyMaxRounds < 1 || pm.Spec.PreCopyMaxRounds > 20 {
		allErrs = append(allErrs, field.Invalid(spec.Child("preCopyMaxRounds"), pm.Spec.PreCopyMaxRounds,
			"must be between 1 and 20"))
	}
	if pm.Spec.PreCopyDirtyThresholdMB < 1 {
		allErrs = append(allErrs, field.Invalid(spec.Child("preCopyDirtyThresholdMB"), pm.Spec.PreCopyDirtyThresholdMB,
			"must be at least 1"))
	}
	if pm.Spec.CompletionTimeoutSeconds < 30 {
		allErrs = append(allErrs, field.Invalid(spec.Child("completionTimeoutSeconds"), pm.Spec.CompletionTimeoutSeconds,
			"must be at least 30 seconds"))
	}

	return allErrs
}

// detectTier4Volume returns a non-empty reason string if any pod volume is in the Tier 4 (blocked) category.
//
// Tier 4 volumes are those PodMotion cannot migrate because no standard copy path exists:
//   - hostPath volumes (tied to a specific node's filesystem)
//   - emptyDir with memory medium (ephemeral, can't be migrated meaningfully)
//   - projected ServiceAccountToken-only volumes are always re-created on restore — not blocked.
func detectTier4Volume(pod *corev1.Pod) string {
	for _, vol := range pod.Spec.Volumes {
		if vol.HostPath != nil {
			return fmt.Sprintf("hostPath volume %q (path: %s)", vol.Name, vol.HostPath.Path)
		}
		if vol.EmptyDir != nil && vol.EmptyDir.Medium == corev1.StorageMediumMemory {
			return fmt.Sprintf("emptyDir volume %q with memory medium (tmpfs data is not migratable)", vol.Name)
		}
	}
	return ""
}

// webhookPodHasGPU returns true if any container in the pod requests an nvidia.com/gpu resource.
func webhookPodHasGPU(pod *corev1.Pod) bool {
	const gpuResource = corev1.ResourceName("nvidia.com/gpu")
	for _, c := range pod.Spec.Containers {
		if q, ok := c.Resources.Limits[gpuResource]; ok && q.Value() > 0 {
			return true
		}
	}
	return false
}

// getPod fetches the live pod from the API server.
func (v *PodMigrationValidator) getPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	err := v.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pod)
	return pod, err
}

// getNMC fetches the NodeMigrationCapacity for a given node (cluster-scoped, named after the node).
func (v *PodMigrationValidator) getNMC(ctx context.Context, nodeName string) (*pmv1.NodeMigrationCapacity, error) {
	nmc := &pmv1.NodeMigrationCapacity{}
	err := v.client.Get(ctx, client.ObjectKey{Name: nodeName}, nmc)
	return nmc, err
}

// PodMigrationDefaulter implements a MutatingAdmissionWebhook for PodMigration.
// It sets defaults and handles the networkContinuity downgrade (Rule 8 from the validator).
type PodMigrationDefaulter struct {
	client  client.Client
	decoder admission.Decoder
}

// SetupWithManager registers the mutating webhook with the controller-runtime manager.
func (d *PodMigrationDefaulter) SetupWithManager(mgr ctrl.Manager) error {
	d.client = mgr.GetClient()
	d.decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register(
		"/mutate-podmotion-io-v1alpha1-podmigration",
		&admission.Webhook{Handler: d},
	)
	return nil
}

// Handle implements admission.Handler.
func (d *PodMigrationDefaulter) Handle(ctx context.Context, req admission.Request) admission.Response {
	pm := &pmv1.PodMigration{}
	if err := d.decoder.Decode(req, pm); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	original := pm.DeepCopy()
	d.applyDefaults(ctx, pm)

	return admission.PatchResponseFromRaw(
		mustMarshal(original),
		mustMarshal(pm),
	)
}

// applyDefaults sets missing spec fields, handles the networkContinuity downgrade,
// and annotates solo StatefulSet pod migrations that bypass the orchestrator.
func (d *PodMigrationDefaulter) applyDefaults(ctx context.Context, pm *pmv1.PodMigration) {
	if pm.Spec.Mode == "" {
		pm.Spec.Mode = pmv1.MigrationModePreCopy
	}
	if pm.Spec.PreCopyMaxRounds == 0 {
		pm.Spec.PreCopyMaxRounds = 5
	}
	if pm.Spec.PreCopyDirtyThresholdMB == 0 {
		pm.Spec.PreCopyDirtyThresholdMB = 64
	}
	if pm.Spec.CompletionTimeoutSeconds == 0 {
		pm.Spec.CompletionTimeoutSeconds = 600
	}
	if pm.Spec.StorageStrategy == "" {
		pm.Spec.StorageStrategy = pmv1.StorageStrategyAuto
	}

	// StatefulSet ordinal-safety warning: if the pod belongs to a StatefulSet but this
	// migration was not created by a MigrationPolicy with statefulSetRef (i.e., no
	// orchestrator is managing it), annotate with a warning. We check for the
	// migration.podmotion.io/statefulset label which the orchestrator sets.
	if pod, err := d.getPod(ctx, pm.Spec.PodNamespace, pm.Spec.PodName); err == nil {
		if ownerRef := statefulSetOwnerRef(pod); ownerRef != "" {
			if pm.Labels == nil || pm.Labels["migration.podmotion.io/statefulset"] == "" {
				if pm.Annotations == nil {
					pm.Annotations = make(map[string]string)
				}
				pm.Annotations["podmotion.io/statefulset-ordinal-safety-warning"] = fmt.Sprintf(
					"pod %q belongs to StatefulSet %q but no StatefulSet orchestrator is managing this migration; ordinal safety is not guaranteed",
					pm.Spec.PodName, ownerRef)
			}
		}
	}

	// Rule 8: networkContinuity downgrade — if requested but CNI doesn't support IP mobility,
	// downgrade silently and annotate. This is a warning, not a rejection.
	if pm.Spec.NetworkContinuity && pm.Spec.TargetNodeName != "" {
		nmc, err := d.getNMC(ctx, pm.Spec.TargetNodeName)
		if err == nil && !nmc.Spec.NetworkCapability.IPMobilitySupported {
			webhookLog.Info("downgrading networkContinuity to false: CNI does not support IP mobility",
				"migration", pm.Name, "targetNode", pm.Spec.TargetNodeName,
				"cni", nmc.Spec.NetworkCapability.CNIPlugin)
			pm.Spec.NetworkContinuity = false
			if pm.Annotations == nil {
				pm.Annotations = make(map[string]string)
			}
			pm.Annotations["podmotion.io/network-continuity-downgraded"] = fmt.Sprintf(
				"CNI plugin %q on node %q does not support IP mobility; downgraded to cold migration mode",
				nmc.Spec.NetworkCapability.CNIPlugin, pm.Spec.TargetNodeName)
		}
	}
}

func (d *PodMigrationDefaulter) getPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	err := d.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pod)
	return pod, err
}

func (d *PodMigrationDefaulter) getNMC(ctx context.Context, nodeName string) (*pmv1.NodeMigrationCapacity, error) {
	nmc := &pmv1.NodeMigrationCapacity{}
	err := d.client.Get(ctx, client.ObjectKey{Name: nodeName}, nmc)
	return nmc, err
}

// statefulSetOwnerRef returns the StatefulSet name if the pod is owned by one, else "".
func statefulSetOwnerRef(pod *corev1.Pod) string {
	for _, ref := range pod.OwnerReferences {
		if ref.Kind == "StatefulSet" {
			return ref.Name
		}
	}
	return ""
}

// detectHardNodeAffinity returns (true, nodeName) if the pod has hard scheduling
// constraints that pin it to a specific node:
//   - NodeSelector containing kubernetes.io/hostname or node.kubernetes.io/instance-type
//   - NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution with a MatchExpression
//     using operator In on key kubernetes.io/hostname
//
// nodeName is the value found in those constraints (spec.nodeName as fallback).
func detectHardNodeAffinity(pod *corev1.Pod) (conflict bool, nodeName string) {
	sourceNode := pod.Spec.NodeName

	// Check NodeSelector
	for key, val := range pod.Spec.NodeSelector {
		if key == "kubernetes.io/hostname" || key == "node.kubernetes.io/instance-type" {
			return true, val
		}
	}

	// Check NodeAffinity
	if pod.Spec.Affinity == nil || pod.Spec.Affinity.NodeAffinity == nil {
		return false, ""
	}
	required := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
	if required == nil {
		return false, ""
	}
	for _, term := range required.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if expr.Key == "kubernetes.io/hostname" && expr.Operator == corev1.NodeSelectorOpIn {
				for _, v := range expr.Values {
					if v == sourceNode {
						return true, sourceNode
					}
				}
				// Values exist but none match source node — still a pinning constraint.
				if len(expr.Values) > 0 {
					return true, expr.Values[0]
				}
			}
		}
	}
	return false, ""
}

// mustMarshal marshals obj to JSON using the runtime codec; panics on error (should never happen).
func mustMarshal(obj runtime.Object) []byte {
	data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		panic(fmt.Sprintf("mustMarshal: ToUnstructured: %v", err))
	}
	out, err := jsonMarshal(data)
	if err != nil {
		panic(fmt.Sprintf("mustMarshal: json.Marshal: %v", err))
	}
	return out
}
