{{/*
ADR-0360 Decision §4: chart-level coherence constraint between webhook.podMutation.enabled and
scheduler.enabled.

The pod-mutating webhook (when enabled) injects spec.schedulerName=podmotion-scheduler plus the
podmotion.io/awaiting-checkpoint PodSchedulingGate onto every replacement pod (ADR-0046/ADR-0359).
If the podmotion-scheduler custom scheduler is not enabled, nothing will ever honor that
schedulerName or lift the gate via a Filter/Score decision — the replacement pod is gated and
pointed at a scheduler that does not exist, and is stranded Pending forever. This is exactly the
"zero-binder" hazard ADR-0359 flagged and parked as "Substrate audit gap"; this guard closes it by
making the combination unrenderable rather than merely documented.

Fails at `helm template`/`helm lint`/`helm install`/`helm upgrade` render time — before any object
reaches the API server.

Defined here as a named template (not bare top-level content) because Helm never executes the
top-level content of an underscore-prefixed partial file — only its `define` blocks, invoked via
`include` from a template that IS actually rendered. See
`templates/podmotion-coherence-check.yaml`, the (empty-output) render-time trigger for this check.
*/}}
{{- define "podmotion.coherenceChecks" -}}
{{- if and (eq (include "podmotion.podMutationEnabled" .) "true") (not .Values.scheduler.enabled) -}}
{{ fail "webhook.podMutation.enabled=true with scheduler.enabled=false: the pod-mutating webhook binds replacement pods via schedulerName=podmotion-scheduler, but no scheduler is enabled to honor it. The replacement pod would be gated and pointed at a scheduler that does not exist, and would never be scheduled (ADR-0359 'Substrate audit gap'; ADR-0360). Set both true, or set webhook.podMutation.enabled=false to accept the documented full-degradation path (no scheduler pinning, no gate, no IP-preservation pins, no node binding)." -}}
{{- end -}}
{{- end -}}
