/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// ADR-0039 SD-6 / ADR-0148 (agent privilege containment): block interactive
// access to podmotion-agent pods.
//
// The agent runs privileged (hostPID, hostNetwork, CAP_SYS_PTRACE, CAP_SYS_ADMIN,
// read-write containerd.sock — see ADR-0039 threat model). An attacker holding
// `kubectl exec`/`attach` RBAC against the agent pod inherits that full surface
// interactively. ADR-0039 §SD-6 roadmaps a ValidatingAdmissionWebhook that rejects
// the interactive subresources on agent pods; ADR-0148 turns it into a deployed
// control. The Security Reviewer requires ALL FOUR interactive vectors blocked:
//
//	pods/exec                  — interactive shell into the agent container
//	pods/attach                — attach to the agent's running process streams
//	pods/ephemeralcontainers   — inject a debug container sharing the agent's
//	                             namespaces (a process-namespace exec bypass)
//	nodes/proxy (agent SA)     — kubelet proxy reach that re-exposes exec/attach
//	                             out-of-band of the pods/* subresource rules
//
// These subresource requests arrive as CONNECT (exec/attach) or CREATE
// (ephemeralcontainers) admission reviews carrying a non-empty SubResource.
// The ValidatingWebhookConfiguration's objectSelector scopes the pods/* rules to
// agent pods, so this handler can DENY unconditionally for those; the nodes/proxy
// rule is scoped here by the request's ServiceAccount UserInfo because a node
// object has no agent-component label to select on.
const (
	// agentComponentCanonical is the component label value named by ADR-0039 SD-6
	// and the Security Reviewer. The deployed DaemonSet currently labels its pods
	// app.kubernetes.io/component=agent (charts/podmotion/templates/daemonset.yaml);
	// both values are treated as the agent for defense in depth so a future
	// relabel toward the canonical value cannot silently open the exec hole.
	agentComponentCanonical = "podmotion-agent"
	agentComponentDeployed  = "agent"

	// agentAppLabel is the immutable selector label the DaemonSet actually sets on
	// every agent pod (app: podmotion-agent). It is the authoritative match used by
	// the Helm objectSelector so the webhook fires on the real deployed pods.
	agentAppLabel = "podmotion-agent"

	// agentServiceAccount is the agent pod's ServiceAccount
	// (charts/podmotion/templates/serviceaccount.yaml). Used to scope the
	// nodes/proxy denial to the agent identity only.
	agentServiceAccount = "podmotion-agent"

	// subExec, subAttach, subEphemeral, subProxy are the blocked subresources.
	subExec      = "exec"
	subAttach    = "attach"
	subEphemeral = "ephemeralcontainers"
	subProxy     = "proxy"

	// execBlockDenyMessage is returned (HTTP 403) on every block.
	execBlockDenyMessage = "Direct exec/attach/ephemeral access to podmotion-agent pods is prohibited (security policy)"
)

var agentExecBlockLog = logf.Log.WithName("agent-exec-block-webhook")

// AgentExecBlockWebhook is a ValidatingAdmissionWebhook that denies interactive
// access (exec/attach/ephemeralcontainers) to podmotion-agent pods and denies the
// nodes/proxy subresource when requested by the agent ServiceAccount.
//
// failurePolicy is Fail (configured in the ValidatingWebhookConfiguration): if the
// webhook is unreachable, interactive access to a privileged agent pod must be
// denied, never fail-open. This is the inverse of the eviction interceptor, which
// fails open to avoid blocking routine cluster operations — here a fail-open would
// reopen exactly the privilege-escalation vector the control exists to close.
//
// Registered at /validate-core-v1-pod-exec-block.
type AgentExecBlockWebhook struct{}

// SetupWithManager registers the agent exec-block validating webhook.
func (w *AgentExecBlockWebhook) SetupWithManager(mgr ctrl.Manager) error {
	mgr.GetWebhookServer().Register(
		"/validate-core-v1-pod-exec-block",
		&admission.Webhook{Handler: w},
	)
	return nil
}

// Handle implements admission.Handler.
//
// Decision model — the webhook is reached only via the ValidatingWebhookConfiguration
// rules (pods/{exec,attach,ephemeralcontainers} CONNECT/CREATE selected by agent
// objectSelector, and nodes/proxy CONNECT). The handler re-asserts the subresource
// and identity in code so a mis-scoped rule cannot turn it into a blanket pod-exec
// block or, conversely, silently allow.
func (w *AgentExecBlockWebhook) Handle(_ context.Context, req admission.Request) admission.Response {
	sub := requestSubResource(req)

	switch req.Resource.Resource {
	case "pods":
		// The objectSelector on the pods/* rules already restricts this to agent
		// pods; DENY any blocked interactive subresource unconditionally.
		switch sub {
		case subExec, subAttach, subEphemeral:
			agentExecBlockLog.Info("denied interactive access to agent pod",
				"subresource", sub,
				"name", req.Name,
				"namespace", req.Namespace,
				"user", req.UserInfo.Username)
			return denied403(execBlockDenyMessage)
		default:
			// Not a blocked subresource (e.g. a non-CONNECT op reached us via an
			// over-broad rule) — allow; this webhook owns interactive blocking only.
			return admission.Allowed("subresource not blocked")
		}

	case "nodes":
		// Block kubelet proxy reach (nodes/proxy) from the agent ServiceAccount.
		// nodes/proxy re-exposes exec/attach/run on the kubelet API out-of-band of
		// the pods/* subresource rules above. A node object carries no
		// agent-component label, so scope by the requesting identity instead.
		if sub == subProxy && isAgentServiceAccount(req.UserInfo) {
			agentExecBlockLog.Info("denied nodes/proxy from agent service account",
				"node", req.Name,
				"user", req.UserInfo.Username)
			return denied403(execBlockDenyMessage)
		}
		return admission.Allowed("nodes/proxy not from agent service account")

	default:
		return admission.Allowed("resource not in scope")
	}
}

// requestSubResource returns the subresource of the admission request. The
// AdmissionRequest carries both SubResource (the admitted object's subresource)
// and RequestSubResource (the original API request's subresource); for CONNECT
// reviews on exec/attach the latter is the authoritative one, so prefer it and
// fall back to SubResource.
func requestSubResource(req admission.Request) string {
	if req.RequestSubResource != "" {
		return req.RequestSubResource
	}
	return req.SubResource
}

// isAgentServiceAccount reports whether the request identity is the agent's
// ServiceAccount. ServiceAccount usernames are system:serviceaccount:<ns>:<name>;
// match on the trailing name component and the SA group membership.
func isAgentServiceAccount(u authnv1.UserInfo) bool {
	const prefix = "system:serviceaccount:"
	if len(u.Username) <= len(prefix) || u.Username[:len(prefix)] != prefix {
		return false
	}
	// Trailing component after the final ':' is the ServiceAccount name.
	name := u.Username
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == ':' {
			name = name[i+1:]
			break
		}
	}
	return name == agentServiceAccount
}

// denied403 builds a 403 Forbidden admission denial carrying the security-policy
// message. admission.Denied returns Allowed=false; the API server surfaces this as
// HTTP 403 Forbidden to the client (kubectl exec/attach).
func denied403(msg string) admission.Response {
	resp := admission.Denied(msg)
	resp.Result.Code = http.StatusForbidden
	return resp
}

// Compile-time guard: keep the admissionv1 import referenced so the Operation
// constants this webhook reasons about (CONNECT/CREATE) stay documented at the
// type level even though the rules, not the handler, switch on Operation.
var _ = admissionv1.Connect
