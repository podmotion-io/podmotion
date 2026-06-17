# Sprint 35 Phase C — Gate Attempt 18

- **Date:** 2026-06-17 (UTC)
- **Branch:** sprint35-phase-c @ 9df05f0
- **Cluster:** podmotion-s35-strict (kind, v1.32.0; control-plane + 1 worker)
- **KUBECONFIG:** /tmp/podmotion-s35-strict.kubeconfig
- **Gate class:** §14g R-iteration (1/3 after fix)
- **Fix under test:** ADR-0223 — WebhookConfiguration registration conditional on `webhook.certManager.enabled` (deploy-layer asymmetric dual of ADR-0222, §3h-SYM class)

## Verdict

**GATE_VERDICT: GATE_FAIL 0/8**

P-MECHANISM (Attempt 18) reproduced **identically**. ADR-0223 did not close the gap on the deployed release.

## Evidence chain

### P-SUBSTRATE — PASS
- Operator: 3/3 Running, restartCount=0 on all replicas (no crash-loop). Confirms ADR-0222 "no cert → no crash" holds.
  - podmotion-operator-69bb8785dc-{7vnkw,9x5w2,szfmc} READY=true RESTARTS=0
- Agents: podmotion-agent-{hbfmm,hfkm4} 1/1 Running.
- Liveness check (not crash-loop): PASS.

### Operator liveness / webhook wiring (ADR-0222) — CORRECT
Operator logs (replicas 7vnkw, 9x5w2):
```
setup  webhook server disabled (no --webhook-cert-path); admission webhooks not registered
setup  admission webhooks not registered (webhook server disabled)
```
- Deployed args: `--leader-elect --metrics-bind-address=:8080 --health-probe-bind-address=:8081 --feature-gates=TCPPreservation=true` (no `--webhook-cert-path`).
- Image: `podmotion-manager:sprint35-amd64`.
- Operator correctly does NOT serve TLS on 9443. ADR-0222 operator-side behavior verified.

### P-VERIFY-MULTI / deploy-layer asymmetry — FAIL (root cause)
The chart side did NOT honor the same toggle. With the operator webhook server disabled, the WebhookConfigurations must not be registered (ADR-0223 intent). Live state:

- `helm get values podmotion --all` -> `webhook.certManager.enabled: false`
- Yet LIVE (Helm-managed, release `podmotion`, created 02:48:51):
  - `mutatingwebhookconfiguration/podmotion-mutating-webhook` (webhook `mpodmigration.kb.io`, **failurePolicy=Fail**, caBundle length **0**)
  - `validatingwebhookconfiguration/podmotion-validating-webhook` (`vpodmigration.kb.io`, **failurePolicy=Fail**)
  - `svc/podmotion-webhook-service` ClusterIP **10.106.168.32** (== P-MECHANISM failure IP)
- cert-manager: ABSENT (no cert-manager pods, no Certificate-issued serving-cert secret in podmotion-system).

The configs/service should have been excluded by the `{{- if .Values.webhook.certManager.enabled }}` guards in `charts/podmotion/templates/webhook.yaml` (lines 1, 47, 76). They were not. The deployed release is asymmetric: operator honored `false`, chart artifacts behave as if `true`. §3h-SYM dual NOT effective on the deployed binaries/manifests.

### SUT PONG — NOT REACHED
No SUT workload deployable through the migration path; gate blocks at CR admission before any PONG baseline is meaningful.

### Gate CR apply — FAIL (P-MECHANISM reproduced)
```
$ kubectl apply -f gate-s35-strict-018.yaml   # tcpPreservationMode: Strict
Error from server (InternalError): error when creating "...": Internal error occurred:
failed calling webhook "mpodmigration.kb.io": failed to call webhook:
Post "https://podmotion-webhook-service.podmotion-system.svc:443/mutate-podmotion-io-v1alpha1-podmigration?timeout=10s":
dial tcp 10.106.168.32:443: connect: connection refused
```
- CR `gate-s35-strict-018` did **NOT persist** (`kubectl get podmigration -A` -> No resources found).
- Identical to Attempt 18 P-MECHANISM: same webhook, same IP 10.106.168.32, same `connection refused`, CR never persisted.

### 2s poll / 480s window — NOT REACHED (CR never created).
### TCP sequence-delta evidence — NOT REACHED.

## Root cause

Deploy-layer asymmetry persists. The live release was installed with `webhook.certManager.enabled=false`, the operator correctly disabled its webhook server (ADR-0222), but the WebhookConfigurations + Service remained REGISTERED with `failurePolicy=Fail` and an empty caBundle, pointing at a service whose backing operator is not serving TLS. Every PodMigration CREATE is blocked at admission. ADR-0223's conditional did not take effect on the deployed release — either the deploy used a chart predating the fix (release created 02:48, must be re-rendered/re-applied from 9df05f0), or the `{{- if }}` guard scoping in `webhook.yaml` does not actually exclude the WebhookConfiguration objects when `certManager.enabled=false`. Source-vs-deployed provenance mismatch is the blocking finding (P2 deployed-provenance assertion).

## Required before next attempt (for ADR/quorum — not prescribed here)
- Re-render and re-apply the chart from HEAD (9df05f0) and assert deployed WebhookConfiguration set == rendered set for `certManager.enabled=false` (must be empty).
- If still present, the §3h-SYM removal-symmetry audit must cover the WebhookConfiguration + Service objects, not only the operator wiring.

## Strike count
§14g R-iteration: 1/3 consumed. Fix ADR-0223 did not pass empirical gate.
