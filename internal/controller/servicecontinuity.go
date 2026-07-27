/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/iphandoff"
	"github.com/podmotion-io/podmotion/internal/agent/traffic"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

// errNoEndpointSliceServiceLabelYet is returned by resolveTargetService when no
// EndpointSlice carrying destPodIP has a discoveryv1.LabelServiceName label. This is the
// ONE resolveTargetService failure mode establishServiceContinuity treats specially
// (§P-MECHANISM, ADR-0390): every other resolveTargetService error (API list error,
// Service fetch error, ClusterIP not yet assigned) stays a plain transient requeue, but
// this specific one is ambiguous on its own — it is produced identically whether (a) a
// Service selects this pod and its EndpointSlice controller simply hasn't converged yet
// (transient), or (b) no Service anywhere has ever selected this pod, in which case no
// EndpointSlice for it will EVER carry the label (permanent). Wrapped with %w so
// errors.Is can distinguish it from resolveTargetService's other error returns.
var errNoEndpointSliceServiceLabelYet = errors.New("no EndpointSlice carries a Service label yet")

// markDestinationReadyIfConverged (ADR-0352 D0.1) wires traffic.EndpointSliceManager.
// MarkDestinationReady (endpoints.go:113) — dead code since introduction, ZERO writers
// (VERIFIED: only the definition, no call sites) — controller-side, gated on BOTH
// authoritative convergence signals:
//   - WorkloadLivenessVerified=True (ADR-0325 condition)
//   - pm.Status.CRIURestoreConfirmed present-and-true (*bool, agent-written by
//     AgentServer.ReportRestoreConfirmed, server.go:1254/:1269/:1276 — NOT a condition,
//     read differently from WorkloadLivenessVerified)
//
// MUST fire from the controller reconcile loop, never from the agent's
// ReportRestoreConfirmed (D0.1 executed-path / delegation-boundary, Architect B):
// firing on CRIURestoreConfirmed alone — before liveness is proven — would flip
// Ready=true on a restored-but-not-live pod (Stop-here safety #1 regression).
//
// Shared by BOTH reconcileServiceVerifying and the legacy reconcileVerifying (mirrors the
// ensureWorkloadLivenessVerified sharing pattern, podmigration_controller.go:1394-1399) so
// the write-back fires on whichever verification path a migration actually takes — wiring
// only one path would silently strand the other and reopen the exact untested Ready-poll
// wedge this ADR closes. Warn-only on failure: MarkDestinationReady is idempotent and the
// caller reconciles again.
func (r *PodMigrationReconciler) markDestinationReadyIfConverged(ctx context.Context, pm *pmv1.PodMigration, destPodIP string) {
	log := logf.FromContext(ctx)
	if destPodIP == "" {
		return
	}
	livenessNow := meta.IsStatusConditionTrue(pm.Status.Conditions, pmv1.ConditionWorkloadLivenessVerified)
	restoreConfirmed := pm.Status.CRIURestoreConfirmed != nil && *pm.Status.CRIURestoreConfirmed
	if !livenessNow || !restoreConfirmed {
		return
	}

	// ADR-0405 3A — fail-closed third precondition on the Ready flip. WorkloadLivenessVerified
	// proves the replacement answers on its OWN IP from the destination-node agent netns; it does
	// NOT prove the cluster load-balancer can route to that backend from an off-pod vantage. Flipping
	// EndpointSlice Ready — the exact bit Cilium consumes to select a backend for VIP DNAT — on that
	// own-IP liveness fact is a §5.3a fail-open: the replacement can be enrolled as a Ready Service
	// backend before the CNI has finished programming its dataplane, so probeServiceClusterIP DNATs
	// onto a not-yet-routable backend (EHOSTUNREACH) and the sustained-consecutive probe never
	// latches. Gate the flip on the CNI's OWN source-of-truth write-back that destPodIP — the exact
	// IP being enrolled as the Ready backend — is programmed and cluster-routable. Single-shot read;
	// on not-yet or error we simply do not flip Ready this reconcile and the caller
	// (establishServiceContinuity D1.1) requeues, bounded by the D4 completion-deadline backstop.
	// This deliberately drops the "was the ipam.cilium.io/ip pin honored" semantic of the pod-IP-pin
	// path (that read keyed on SourcePodIP): pod-IP-pin is out of roadmap scope, so we key on the
	// replacement's actually-assigned destPodIP, which the CiliumEndpoint DOES advertise — the reason
	// this converges where the ADR-0352-D3-retired SourcePodIP read wedged under cluster-pool IPAM.
	programmed, progErr := r.confirmEndpointReadyAdvertisesIP(ctx, pm, destPodIP)
	if progErr != nil {
		log.Error(progErr, "ADR-0405: CNI endpoint-programming read did not confirm destPodIP is cluster-routable — NOT flipping Ready this reconcile (fail-closed; will retry)",
			"migration", pm.Name, "destPodIP", destPodIP)
		return
	}
	if !programmed {
		log.Info("ADR-0405: destination CNI has not yet programmed the replacement endpoint for destPodIP — deferring Ready flip (fail-closed; will retry)",
			"migration", pm.Name, "destPodIP", destPodIP)
		return
	}

	esMgr := traffic.NewEndpointSliceManager(r.Client)
	if err := esMgr.MarkDestinationReady(ctx, pm.Spec.PodNamespace, destPodIP); err != nil {
		log.Error(err, "ADR-0352 D0.1: MarkDestinationReady failed — continuing, will retry next reconcile",
			"migration", pm.Name, "destPodIP", destPodIP)
	}
}

// confirmEndpointReadyAdvertisesIP (ADR-0405 3B) is the workload-agnostic, SINGLE-SHOT control-plane
// read of one class question: "has the destination node's CNI programmed the replacement endpoint's
// dataplane so wantIP is cluster-routable?" It dispatches by the destination node's CNI plugin
// (reusing the existing CNIMobilitySelector, so no new CNI-detection code) and returns exactly once
// — no blocking poll — so the caller composes it with its own reconcile requeue cadence rather than
// parking a controller worker goroutine. It reuses the CNIs' own source-of-truth reads
// (Cilium: CiliumEndpoint single-shot core EndpointReadyAdvertisesIP; Calico: WEP single-shot core
// WorkloadEndpointReady) instead of inferring routability with a probe (invariant #10 /
// SUBSTRATE-PRIMITIVE BIAS).
//
// Scope note (Architect-B condition 4): this does NOT rewire the dormant pod-IP-pin dataplane-
// reachability caller (establishCiliumDataplaneReachability). That path is untouched and still calls
// the blocking ConfirmEndpointOwnsPreservedIP wrapper. The shared code is only the single-shot core
// inside iphandoff, so both paths read the same source of truth without widening this change into
// dormant controller code.
//
// Returns (true, nil) when the CNI write-back confirms the endpoint owns wantIP; (false, nil) when
// not yet programmed (caller requeues) OR when the destination CNI has no authoritative
// endpoint-programming producer wired (Flannel / OVN-K / unknown) — on those substrates there is no
// source of truth to gate on, so the pre-ADR-0405 behavior is preserved rather than adding a gate we
// cannot honor; and (false, err) only on a real read error or a DECIDED negative (ready-but-wrong-IP)
// — fail-closed.
func (r *PodMigrationReconciler) confirmEndpointReadyAdvertisesIP(ctx context.Context, pm *pmv1.PodMigration, wantIP string) (bool, error) {
	destNode := pm.Status.DestinationNodeName
	replPod := pm.Status.ReplacementPodName
	if destNode == "" || replPod == "" || wantIP == "" {
		// Not enough state yet to read the endpoint — treat as not-yet-programmed (caller requeues).
		return false, nil
	}
	cniPlugin, err := r.resolveDestCNIPlugin(ctx, destNode)
	if err != nil {
		return false, fmt.Errorf("resolving destination CNI plugin for node %s: %w", destNode, err)
	}
	selector := &iphandoff.CNIMobilitySelector{KubeClient: r.KubeClient, DynamicClient: r.DynamicClient}
	switch h := selector.Select(ctx, cniPlugin).(type) {
	case *iphandoff.CiliumHandoff:
		_, ok, ceErr := h.EndpointReadyAdvertisesIP(ctx, pm.Spec.PodNamespace, replPod, wantIP)
		return ok, ceErr
	case *iphandoff.CalicoHandoff:
		return h.WorkloadEndpointReady(ctx, pm.Spec.PodNamespace, replPod)
	default:
		// No authoritative endpoint-programming producer wired for this CNI (Flannel/OVN-K/unknown):
		// there is no source-of-truth write-back to read, so do not add a gate we cannot honor —
		// preserve the pre-ADR-0405 flip-on-liveness behavior on these substrates.
		return true, nil
	}
}

// resolveTargetService (ADR-0352 D1.2) returns the Service (and whether it is headless)
// that owns the EndpointSlice containing destPodIP, resolved via the standard
// discoveryv1.LabelServiceName label (traffic.EndpointSliceManager.ServiceNameForIP) — the
// only Service-linkage mechanism this codebase has; PodMigrationSpec carries no
// ServiceName field (grep-verified against api/v1alpha1/podmigration_types.go).
func (r *PodMigrationReconciler) resolveTargetService(ctx context.Context, esMgr *traffic.EndpointSliceManager, namespace, destPodIP string) (svc *corev1.Service, headless bool, err error) {
	svcName, err := esMgr.ServiceNameForIP(ctx, namespace, destPodIP)
	if err != nil {
		return nil, false, fmt.Errorf("resolving owning Service for %s: %w", destPodIP, err)
	}
	if svcName == "" {
		return nil, false, fmt.Errorf("%w (destPodIP=%s)", errNoEndpointSliceServiceLabelYet, destPodIP)
	}
	svc = &corev1.Service{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: svcName}, svc); err != nil {
		return nil, false, fmt.Errorf("fetching Service %s: %w", svcName, err)
	}
	if svc.Spec.ClusterIP == "" {
		// Not yet assigned — treat as "not yet resolvable" (caller requeues), not headless.
		return nil, false, fmt.Errorf("Service %s has no ClusterIP assigned yet", svcName)
	}
	return svc, svc.Spec.ClusterIP == "None", nil
}

// anyServiceSelectsPod (ADR-0390) is the real primitive that resolves the ambiguity
// errNoEndpointSliceServiceLabelYet leaves open: it lists Services directly — the actual
// source of truth for "is any Service in front of this pod" — and label-selector-matches
// each non-empty Spec.Selector against podLabels, exactly the same match the built-in
// EndpointSlice controller performs. This is asked once, directly, instead of inferred by
// repeatedly polling EndpointSlice population (the brittle poll-and-guess-chain pattern this
// project's standing primitive-over-brittle-chain bias exists to replace): a Service either
// selects this pod's labels right now or it does
// not — that fact does not change while an EndpointSlice controller is still converging,
// so a single read here authoritatively distinguishes "transient" from "permanent."
//
// Selector-less Services (Spec.Selector nil/empty — ExternalName Services, or Services
// with manually-managed Endpoints/EndpointSlices) are deliberately skipped: an empty
// selector matches no pod by Kubernetes' own selector semantics, and treating "empty" as
// "matches everything" would be a false positive here, not a conservative default.
func (r *PodMigrationReconciler) anyServiceSelectsPod(ctx context.Context, namespace string, podLabels map[string]string) (bool, error) {
	svcList := &corev1.ServiceList{}
	if err := r.List(ctx, svcList, client.InNamespace(namespace)); err != nil {
		return false, fmt.Errorf("listing Services in %s: %w", namespace, err)
	}
	podLabelSet := labels.Set(podLabels)
	for i := range svcList.Items {
		sel := svcList.Items[i].Spec.Selector
		if len(sel) == 0 {
			continue
		}
		if labels.SelectorFromSet(sel).Matches(podLabelSet) {
			return true, nil
		}
	}
	return false, nil
}

// probeServiceClusterIP (ADR-0352 D1.2 — the load-bearing new dependency, OV-2 resolved)
// issues a real client round-trip to the Service ClusterIP, reusing the ADR-0325
// VerifyTCP(AppProbeOnly=true) primitive and runAppProbe's protocol-dial code (never a
// second dialer) — pointed at svc.Spec.ClusterIP instead of the destination pod IP.
//
// Not the tautological self-dial TestVerifying_DoesNotSetTrafficVerified_OnLoopbackOnlyProbe
// (adr0210_dataplane_gate_test.go:90) guards against: that test guards a dial FROM a pod's
// own netns TO its own IP. This dial originates from the DESTINATION AGENT's own process
// netns (server.go's runAppProbe, plain net.Dialer{}) to the Service ClusterIP — a distinct
// vantage that genuinely traverses kube-proxy/Cilium Service load-balancing.
func (r *PodMigrationReconciler) probeServiceClusterIP(ctx context.Context, pm *pmv1.PodMigration, svc *corev1.Service) (bool, error) {
	if r.AgentPool == nil {
		return false, fmt.Errorf("AgentPool not wired")
	}
	destAgent, agentErr := r.AgentPool.ForNode(ctx, pm.Status.DestinationNodeName)
	if agentErr != nil {
		return false, fmt.Errorf("resolving destination-node agent client: %w", agentErr)
	}

	probeProtocol := ""
	destPodName := pm.Status.ReplacementPodName
	if destPodName != "" {
		destPod := &corev1.Pod{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: destPodName}, destPod); err == nil {
			probeProtocol, _, _ = resolveProbeProtocol(pm.Spec.ApplicationProbe, destPod)
		}
	}
	if probeProtocol == "" {
		probeProtocol = "TCP"
	}

	var port int32
	switch probeProtocol {
	case "SQL":
		port = 5432
	case "Redis":
		port = 6379
	case "HTTP":
		port = 80
	}
	if pm.Spec.ApplicationProbe != nil && pm.Spec.ApplicationProbe.Port > 0 {
		port = pm.Spec.ApplicationProbe.Port
	}
	if port == 0 {
		for _, sp := range svc.Spec.Ports {
			port = sp.Port
			break
		}
	}
	if port == 0 {
		return false, fmt.Errorf("could not resolve a probe port for Service %s", svc.Name)
	}

	clusterIP := svc.Spec.ClusterIP
	vtcpReq := &agentpb.VerifyTCPRequest{
		MigrationName:     pm.Name,
		AppProbeOnly:      true,
		AppProbeProtocol:  probeProtocol,
		AppProbeAddress:   fmt.Sprintf("%s:%d", clusterIP, port),
		ExpectedClusterIp: clusterIP,
	}
	if pm.Spec.ApplicationProbe != nil {
		vtcpReq.AppProbeQuery = pm.Spec.ApplicationProbe.Query
		vtcpReq.AppProbeTimeoutS = pm.Spec.ApplicationProbe.TimeoutSeconds
	}
	vtcpResp, rpcErr := destAgent.VerifyTCP(ctx, vtcpReq)
	if rpcErr != nil || vtcpResp == nil || !vtcpResp.Verified {
		msg := "app probe RPC error"
		if rpcErr == nil && vtcpResp != nil {
			msg = vtcpResp.AppProbeError
		}
		return false, fmt.Errorf("ClusterIP round-trip to %s failed: %v / %s", vtcpReq.AppProbeAddress, rpcErr, msg)
	}
	return true, nil
}

// establishServiceContinuity (ADR-0352 D1) drives the two source-of-truth reads that
// produce ServiceContinuityVerified — D1.1 EndpointSlice-Ready enrollment (made real by
// the D0.1 write-back) and D1.2 a real ClusterIP round-trip — and sets the condition.
// Mirrors injectIPHandoff's (ctrl.Result, error, done bool) return shape so the Strict
// completion-deadline backstop (D4) needs no structural change beyond the condition
// identifier it waits on.
//
// done=true, err=nil: ServiceContinuityVerified was set (True or the D0.2 headless
// fail-closed False) — the caller may proceed. done=false: not yet converged; the caller
// should hold (bounded by its own completion-deadline backstop) — this function
// deliberately does NOT set the condition False on a transient non-convergence; only the
// caller's bounded backstop is authorized to flip it affirmatively False (ADR-0352 D1
// truth table: "False" is reserved for an affirmative, bounded-window judgment).
func (r *PodMigrationReconciler) establishServiceContinuity(ctx context.Context, pm *pmv1.PodMigration, destPodIP string) (ctrl.Result, error, bool) {
	log := logf.FromContext(ctx)

	if destPodIP == "" {
		log.Info("establishServiceContinuity: destination pod IP not yet known — requeuing", "migration", pm.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false
	}

	esMgr := traffic.NewEndpointSliceManager(r.Client)
	svc, headless, err := r.resolveTargetService(ctx, esMgr, pm.Spec.PodNamespace, destPodIP)
	if err != nil {
		if errors.Is(err, errNoEndpointSliceServiceLabelYet) {
			// ADR-0390: this specific error is ambiguous on its own (see the sentinel's doc
			// comment) — resolve the ambiguity against the real source of truth (Service
			// selectors vs. the destination pod's own labels) before deciding whether to
			// keep requeuing or to recognize this as permanent.
			destPodName := pm.Status.ReplacementPodName
			if destPodName == "" {
				destPodName = pm.Spec.PodName
			}
			destPod := &corev1.Pod{}
			if getErr := r.Get(ctx, types.NamespacedName{Namespace: pm.Spec.PodNamespace, Name: destPodName}, destPod); getErr != nil {
				log.Info("establishServiceContinuity: could not fetch destination pod to check Service selectors — requeuing",
					"migration", pm.Name, "destPod", destPodName, "err", getErr.Error())
				return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false
			}
			anySvc, svcErr := r.anyServiceSelectsPod(ctx, pm.Spec.PodNamespace, destPod.Labels)
			if svcErr != nil {
				log.Info("establishServiceContinuity: Service-selector check errored — requeuing",
					"migration", pm.Name, "err", svcErr.Error())
				return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false
			}
			if !anySvc {
				// Permanent, not transient: no Service in this namespace selects this pod's
				// labels at all, so no EndpointSlice for it will EVER carry a Service label —
				// the previous code requeued this indefinitely until the completion-deadline
				// backstop fired and rolled the migration back. THE BAR IS SERVICE-IP (CLAUDE.md,
				// Chad standing 2026-07-11/2026-07-20): the Strict Service-continuity guarantee
				// is a statement about traffic reaching the pod via a Service ClusterIP. A pod
				// no Service ever selects has no such traffic to preserve, so the guarantee is
				// vacuously satisfied over an empty set — the same "nothing to preserve is a
				// trivial pass, not a failure" disposition ADR-0388 already applies to the
				// zero-TCP-connection case, applied here to the zero-Service case.
				setCondition(pm, pmv1.ConditionServiceContinuityVerified, metav1.ConditionTrue, "NoServiceSelectsPod",
					fmt.Sprintf("ADR-0390: no Service in namespace %s selects destination pod %s's labels — Strict Service-continuity is structurally inapplicable (nothing routes to this pod via a Service) and is trivially satisfied", pm.Spec.PodNamespace, destPodName))
				return ctrl.Result{}, nil, true
			}
			// A Service does select this pod's labels — the EndpointSlice controller just
			// hasn't converged yet. Genuinely transient; keep the existing requeue behavior.
		}
		log.Info("establishServiceContinuity: target Service not yet resolvable — requeuing",
			"migration", pm.Name, "err", err.Error())
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false
	}
	if headless {
		// ADR-0352 D0.2 option (b): explicit fail-closed for headless Services (clusterIP:
		// None). There is no VIP to round-trip, so D1.2 is structurally inapplicable —
		// rather than leave an unwired Ready-poll (the exact untested wedge this ADR
		// forbids), Strict teardown is affirmatively blocked for headless Services.
		setCondition(pm, pmv1.ConditionServiceContinuityVerified, metav1.ConditionFalse, "HeadlessServiceUnsupported",
			fmt.Sprintf("ADR-0352 D0.2: Service %s is headless (clusterIP: None); ClusterIP round-trip is structurally inapplicable — Strict teardown fail-closed", svc.Name))
		return ctrl.Result{}, nil, true
	}

	// D1.1 — EndpointSlice-Ready enrollment (control-plane truth). Reads the Ready bit the
	// D0.1 write-back makes real; verify.go's existing Ready-gate, not a new poll.
	esVerifier := &traffic.EndpointSliceVerifierImpl{Manager: esMgr}
	readyErr := esVerifier.Verify(ctx, traffic.VerifyRequest{
		Namespace:           pm.Spec.PodNamespace,
		DestPodName:         pm.Status.ReplacementPodName,
		DestPodIP:           destPodIP,
		TimeoutSeconds:      2,
		PollIntervalSeconds: 1,
	})

	// D1.2 — ClusterIP round-trip (dataplane truth). Only attempted once D1.1 holds — no
	// point proving the VIP serves clients before the replacement is even enrolled.
	var d12ok bool
	var d12err error
	if readyErr == nil {
		d12ok, d12err = r.probeServiceClusterIP(ctx, pm, svc)
	}

	if readyErr == nil && d12ok {
		setCondition(pm, pmv1.ConditionServiceContinuityVerified, metav1.ConditionTrue, "ServiceContinuityConfirmed",
			fmt.Sprintf("ADR-0352: replacement is Ready-enrolled in Service %s and the ClusterIP round-trip succeeded", svc.Name))
		return ctrl.Result{}, nil, true
	}

	if readyErr != nil {
		log.Info("establishServiceContinuity: not yet Ready-enrolled — requeuing",
			"migration", pm.Name, "service", svc.Name, "err", readyErr.Error())
	} else {
		log.Info("establishServiceContinuity: ClusterIP round-trip not yet successful — requeuing",
			"migration", pm.Name, "service", svc.Name, "err", d12err.Error())
	}
	return ctrl.Result{RequeueAfter: 3 * time.Second}, nil, false
}
