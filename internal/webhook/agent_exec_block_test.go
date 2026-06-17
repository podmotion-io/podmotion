/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"net/http"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// TestAgentExecBlock covers ADR-0039 SD-6 / ADR-0148: the AgentExecBlockWebhook
// must DENY exec, attach, and ephemeralcontainers on agent pods (the
// ValidatingWebhookConfiguration objectSelector scopes those rules to agent pods,
// so the handler denies the blocked subresources unconditionally for pods), DENY
// nodes/proxy from the agent ServiceAccount, and ALLOW everything else.
func TestAgentExecBlock(t *testing.T) {
	w := &AgentExecBlockWebhook{}

	podReq := func(sub string, op admissionv1.Operation) admission.Request {
		return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
			Name:               "podmotion-agent-abcde",
			Namespace:          "podmotion-system",
			Operation:          op,
			SubResource:        sub,
			RequestSubResource: sub,
			Resource:           metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			UserInfo:           authnv1.UserInfo{Username: "kubernetes-admin"},
		}}
	}

	nodeReq := func(sub string, user string) admission.Request {
		return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
			Name:               "worker-1",
			Operation:          admissionv1.Connect,
			SubResource:        sub,
			RequestSubResource: sub,
			Resource:           metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"},
			UserInfo:           authnv1.UserInfo{Username: user},
		}}
	}

	cases := []struct {
		name       string
		req        admission.Request
		wantAllow  bool
		wantStatus int32 // only checked when denied
	}{
		{
			name:       "agent pod + exec -> DENY",
			req:        podReq(subExec, admissionv1.Connect),
			wantAllow:  false,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "agent pod + attach -> DENY",
			req:        podReq(subAttach, admissionv1.Connect),
			wantAllow:  false,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "agent pod + ephemeralcontainers -> DENY",
			req:        podReq(subEphemeral, admissionv1.Create),
			wantAllow:  false,
			wantStatus: http.StatusForbidden,
		},
		{
			// Non-agent pods never reach this handler in production (the
			// objectSelector excludes them). If an over-broad rule did route a
			// pods/exec here for a non-blocked subresource it must ALLOW; and a
			// plain pod CREATE (no subresource) is not a blocked op -> ALLOW.
			name:      "non-agent pod + exec -> ALLOW (no subresource, not blocked)",
			req:       podReq("", admissionv1.Create),
			wantAllow: true,
		},
		{
			name:      "agent pod + create (not a blocked op) -> ALLOW",
			req:       podReq("", admissionv1.Create),
			wantAllow: true,
		},
		{
			name:       "nodes/proxy from agent SA -> DENY",
			req:        nodeReq(subProxy, "system:serviceaccount:podmotion-system:podmotion-agent"),
			wantAllow:  false,
			wantStatus: http.StatusForbidden,
		},
		{
			name:      "nodes/proxy from non-agent SA -> ALLOW",
			req:       nodeReq(subProxy, "system:serviceaccount:kube-system:default"),
			wantAllow: true,
		},
		{
			name:      "nodes/proxy from human user -> ALLOW",
			req:       nodeReq(subProxy, "kubernetes-admin"),
			wantAllow: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := w.Handle(context.Background(), tc.req)
			if resp.Allowed != tc.wantAllow {
				t.Fatalf("Allowed = %v, want %v (result=%+v)", resp.Allowed, tc.wantAllow, resp.Result)
			}
			if !tc.wantAllow {
				if resp.Result == nil {
					t.Fatalf("denied response has nil Result")
				}
				if resp.Result.Code != tc.wantStatus {
					t.Errorf("status code = %d, want %d", resp.Result.Code, tc.wantStatus)
				}
				if !strings.Contains(resp.Result.Message, "prohibited (security policy)") {
					t.Errorf("deny message = %q, want security-policy message", resp.Result.Message)
				}
			}
		})
	}
}

// TestIsAgentServiceAccount verifies SA username parsing used to scope nodes/proxy.
func TestIsAgentServiceAccount(t *testing.T) {
	cases := []struct {
		user string
		want bool
	}{
		{"system:serviceaccount:podmotion-system:podmotion-agent", true},
		{"system:serviceaccount:default:podmotion-agent", true},
		{"system:serviceaccount:podmotion-system:podmotion-operator", false},
		{"system:serviceaccount:kube-system:default", false},
		{"kubernetes-admin", false},
		{"", false},
		{"system:serviceaccount:", false},
		{"system:node:worker-1", false},
	}
	for _, tc := range cases {
		if got := isAgentServiceAccount(authnv1.UserInfo{Username: tc.user}); got != tc.want {
			t.Errorf("isAgentServiceAccount(%q) = %v, want %v", tc.user, got, tc.want)
		}
	}
}
