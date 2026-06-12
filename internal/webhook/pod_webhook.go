/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

const (
	// LabelMigrationName is the pod label the operator injects on the replacement pod.
	// Its presence at admission triggers this webhook.
	LabelMigrationName = "podmotion.io/migration-name"

	// AnnotationCheckpointRef carries the images-dir path so the NRI plugin can locate
	// the checkpoint without a controller-runtime cache call at restore time.
	AnnotationCheckpointRef = "podmotion.io/checkpoint-ref"

	// SchedulingGateName is the gate injected to hold the replacement pod at scheduling
	// until images are staged, capacity reserved, and volume attached (ADR-0046).
	SchedulingGateName = "podmotion.io/awaiting-checkpoint"

	// CustomSchedulerName is the name of PodMotion's out-of-tree scheduler plugin.
	CustomSchedulerName = "podmotion-scheduler"
)

// PodMutatingWebhook injects scheduling gates, schedulerName, and IPAM annotations
// into replacement pods created by the PodMotion operator during live migration.
//
// +kubebuilder:webhook:path=/mutate-core-v1-pod,mutating=true,failurePolicy=fail,groups="",resources=pods,verbs=create,versions=v1,name=mpod.podmotion.io,admissionReviewVersions=v1,sideEffects=None
type PodMutatingWebhook struct {
	Client  client.Client
	decoder admission.Decoder
}

var podWebhookLog = logf.Log.WithName("pod-webhook")

// NewPodMutatingWebhook constructs the webhook and initialises the decoder for the given scheme.
func NewPodMutatingWebhook(c client.Client, scheme *runtime.Scheme) *PodMutatingWebhook {
	return &PodMutatingWebhook{
		Client:  c,
		decoder: admission.NewDecoder(scheme),
	}
}

// SetupWithManager registers the mutating webhook with the controller-runtime manager.
func (w *PodMutatingWebhook) SetupWithManager(mgr ctrl.Manager) error {
	w.Client = mgr.GetClient()
	w.decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register(
		"/mutate-core-v1-pod",
		&admission.Webhook{Handler: w},
	)
	return nil
}

// Handle is the admission handler. Only acts on pods carrying the migration-name label.
func (w *PodMutatingWebhook) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := w.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decode pod: %w", err))
	}

	pmName, ok := pod.Labels[LabelMigrationName]
	if !ok || pmName == "" {
		// Not a migration replacement pod — pass through unchanged.
		return admission.Allowed("not a migration replacement pod")
	}

	log := podWebhookLog.WithValues("migration", pmName, "pod", pod.Name, "ns", req.Namespace)

	// Fetch the PodMigration CR to get SourcePodIP and CNIProvider.
	pm := &pmv1.PodMigration{}
	if err := w.Client.Get(ctx, types.NamespacedName{
		Name:      pmName,
		Namespace: req.Namespace,
	}, pm); err != nil {
		log.Error(err, "failed to fetch PodMigration — allowing without mutation")
		return admission.Allowed("PodMigration not found; no mutation applied")
	}

	// Fix 1 — Fetch source pod and merge its labels; also copy service-mesh annotations (Fix 3).
	srcPod := &corev1.Pod{}
	if err := w.Client.Get(ctx, types.NamespacedName{
		Name:      pm.Spec.PodName,
		Namespace: req.Namespace,
	}, srcPod); err == nil {
		// Merge source labels first; podmotion.io/* labels will overlay below.
		if pod.Labels == nil {
			pod.Labels = make(map[string]string)
		}
		for k, v := range srcPod.Labels {
			if _, exists := pod.Labels[k]; !exists {
				pod.Labels[k] = v
			}
		}

		// Fix 3 — Copy service-mesh injection annotations from source pod.
		// If absent on the replacement pod, Istio/Linkerd will inject a new proxy
		// sidecar — its iptables rules intercept CRIU-restored TCP sockets, causing
		// TCP RST on all restored connections immediately post-restore.
		meshAnnotations := []string{
			"sidecar.istio.io/inject",
			"sidecar.istio.io/status",
			"traffic.sidecar.istio.io/excludeInboundPorts",
			"traffic.sidecar.istio.io/excludeOutboundPorts",
			"traffic.sidecar.istio.io/includeInboundPorts",
			"linkerd.io/inject",
			"linkerd.io/proxy-injector-webhook",
		}
		for _, ann := range meshAnnotations {
			if v, ok := srcPod.Annotations[ann]; ok {
				if pod.Annotations == nil {
					pod.Annotations = make(map[string]string)
				}
				if _, exists := pod.Annotations[ann]; !exists {
					pod.Annotations[ann] = v
				}
			}
		}
	}

	original := pod.DeepCopy()

	// 1. Inject schedulerName so MigrationAwareFilter/Score routes this pod.
	//    schedulerName is immutable after creation — must be set at admission.
	pod.Spec.SchedulerName = CustomSchedulerName

	// 2. Inject scheduling gate so the pod holds at PodSchedulingGated until the
	//    controller removes it post-checkpoint (images staged + capacity reserved).
	hasGate := false
	for _, g := range pod.Spec.SchedulingGates {
		if g.Name == SchedulingGateName {
			hasGate = true
			break
		}
	}
	if !hasGate {
		pod.Spec.SchedulingGates = append(pod.Spec.SchedulingGates,
			corev1.PodSchedulingGate{Name: SchedulingGateName})
	}

	// 3. Inject checkpoint-ref annotation and label so the NRI plugin can locate images.
	// Annotation: human-visible, used by the NRI plugin when containerd forwards pod
	// annotations into sandbox annotations (real NRI v2 gRPC path).
	// Label: also set so the NRI JSON stub path (event.Labels) and any label-selector
	// tooling can see it. Both must be kept in sync.
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	if pm.Status.CheckpointRef != nil && pm.Status.CheckpointRef.Name != "" {
		pod.Annotations[AnnotationCheckpointRef] = pm.Status.CheckpointRef.Name
		pod.Labels[AnnotationCheckpointRef] = pm.Status.CheckpointRef.Name
	}

	// 4. Inject CNI-specific IPAM annotation so the destination pod receives the
	//    source pod's IP before the sandbox starts (CNI ADD fires with pinned address).
	//    CRIU does NOT overwrite the IP — the CNI annotation is authoritative (ADR-0046).
	if pm.Spec.SourcePodIP != "" {
		injectIPAMAnnotation(pod, pm.Spec.SourcePodIP, pm.Status.CNIProvider)
	}

	// Fix 2 — Patch all DoNotSchedule topology spread constraints to ScheduleAnyway.
	// MigrationAwareFilter pins the destination node; the built-in topology spread
	// plugin must not override it and leave the replacement pod Pending after
	// source deletion.
	for i := range pod.Spec.TopologySpreadConstraints {
		if pod.Spec.TopologySpreadConstraints[i].WhenUnsatisfiable == corev1.DoNotSchedule {
			pod.Spec.TopologySpreadConstraints[i].WhenUnsatisfiable = corev1.ScheduleAnyway
		}
	}

	log.Info("injected migration annotations",
		"schedulerName", pod.Spec.SchedulerName,
		"gate", SchedulingGateName,
		"cniProvider", pm.Status.CNIProvider,
		"sourceIP", pm.Spec.SourcePodIP)

	return admission.PatchResponseFromRaw(
		podMustMarshal(original),
		podMustMarshal(pod),
	)
}

// injectIPAMAnnotation adds the CNI-specific annotation that pins the destination pod
// to the source pod's IP address. The annotation is interpreted by the CNI plugin during
// ADD (before runc builds the network namespace) so CRIU restores into an already-correct
// network namespace without needing to overwrite any IP state.
func injectIPAMAnnotation(pod *corev1.Pod, ip, cniProvider string) {
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	switch {
	case cniProvider == "calico" || cniProvider == "tigera-operator":
		// Calico IPAM: request specific IP from the IPAM pool.
		pod.Annotations["cni.projectcalico.org/ipAddrs"] = fmt.Sprintf(`["%s"]`, ip)
	case cniProvider == "cilium":
		// Cilium IPAM: requires multi-pool or CRD IPAM mode.
		pod.Annotations["ipam.cilium.io/ip"] = ip
	case cniProvider == "flannel":
		// Flannel does not support IP mobility — cold migration only.
		// NetworkContinuity=true is rejected upstream; no annotation needed.
	default:
		// Unknown CNI — no annotation; falls back to gARP/reconnect semantics (ADR-0017 TIER_4).
	}
}

func podMustMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("podMustMarshal: %v", err))
	}
	return b
}
