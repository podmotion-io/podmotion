/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/traffic"
	agentpb "github.com/podmotion-io/podmotion/proto/gen"
)

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
	esMgr := traffic.NewEndpointSliceManager(r.Client)
	if err := esMgr.MarkDestinationReady(ctx, pm.Spec.PodNamespace, destPodIP); err != nil {
		log.Error(err, "ADR-0352 D0.1: MarkDestinationReady failed — continuing, will retry next reconcile",
			"migration", pm.Name, "destPodIP", destPodIP)
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
		return nil, false, fmt.Errorf("no EndpointSlice for %s carries a Service label yet", destPodIP)
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
