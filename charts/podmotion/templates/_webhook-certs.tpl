{{/*
ADR-0039 SD-6 / HOLD-B: self-signed serving cert for the operator webhook server on
substrates WITHOUT cert-manager (kind/dev). cert-manager injects the caBundle and provisions
the podmotion-webhook-tls secret in the certManager.enabled path; when it is absent the chart
must mint the serving cert itself so the SD-6 exec-block VWC has a real, reachable webhook
backing it (a failurePolicy:Fail VWC pointing at a non-serving operator would deny ALL exec).

genSelfSignedCert is non-deterministic per render, so it MUST be generated exactly ONCE and
the SAME triple reused by both the Secret and the VWC caBundle. This helper memoizes the
generated cert on the root scope ($.podmotionWebhookCert) so every include returns the same
cert/key/ca within a single `helm template`/`helm upgrade` render pass.
*/}}
{{/*
podmotion.execBlockEnabled — nil-safe accessor for webhook.agentExecBlock.enabled.
Defaults to true when the key is absent (e.g. helm upgrade --reuse-values from a release
installed before this value existed), so the SD-6 control is on by default and an old
reuse-values upgrade does NOT silently disable it. Returns "true" or "" (falsey).
*/}}
{{- define "podmotion.execBlockEnabled" -}}
{{- $w := .Values.webhook | default dict -}}
{{- $aeb := $w.agentExecBlock | default dict -}}
{{- if hasKey $aeb "enabled" -}}
{{- if $aeb.enabled }}true{{ end -}}
{{- else -}}
true
{{- end -}}
{{- end -}}

{{/*
podmotion.podMutationEnabled — nil-safe accessor for webhook.podMutation.enabled.
Defaults to true when the key is absent (e.g. helm upgrade --reuse-values from a release
installed before this value existed), so the pod-mutation webhook is on by default and an
old reuse-values upgrade does NOT silently disable it. Returns "true" or "" (falsey).
*/}}
{{- define "podmotion.podMutationEnabled" -}}
{{- $w := .Values.webhook | default dict -}}
{{- $pm := $w.podMutation | default dict -}}
{{- if hasKey $pm "enabled" -}}
{{- if $pm.enabled }}true{{ end -}}
{{- else -}}
true
{{- end -}}
{{- end -}}

{{/*
podmotion.evictionEnabled — nil-safe accessor for webhook.eviction.enabled (ADR-0401).
Defaults to true when the key is absent (e.g. helm upgrade --reuse-values from a release
installed before this value existed), so the fail-closed eviction guard is on by default and
an old reuse-values upgrade does NOT silently disable source-pod protection. Returns "true"
or "" (falsey).
*/}}
{{- define "podmotion.evictionEnabled" -}}
{{- $w := .Values.webhook | default dict -}}
{{- $ev := $w.eviction | default dict -}}
{{- if hasKey $ev "enabled" -}}
{{- if $ev.enabled }}true{{ end -}}
{{- else -}}
true
{{- end -}}
{{- end -}}

{{- define "podmotion.webhookSelfSignedCert" -}}
{{- if not (index $ "podmotionWebhookCert") -}}
  {{- $altNames := list (printf "podmotion-webhook-service.%s.svc" .Release.Namespace) (printf "podmotion-webhook-service.%s.svc.cluster.local" .Release.Namespace) -}}
  {{- $ca := genCA "podmotion-webhook-ca" 3650 -}}
  {{- $cert := genSignedCert (printf "podmotion-webhook-service.%s.svc" .Release.Namespace) nil $altNames 3650 $ca -}}
  {{- $_ := set $ "podmotionWebhookCert" (dict "Cert" $cert.Cert "Key" $cert.Key "CA" $ca.Cert) -}}
{{- end -}}
{{- end -}}
