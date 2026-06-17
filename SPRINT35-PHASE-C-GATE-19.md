# Sprint 35 Phase C — Gate Attempt 19

- **Date:** 2026-06-17 (UTC)
- **Branch:** sprint35-phase-c @ 9df05f0
- **Cluster:** podmotion-s35-strict (kind, v1.32.0)
- **KUBECONFIG:** /tmp/podmotion-s35-strict.kubeconfig
- **Gate class:** §14g R-iteration (2/3 after fix)
- **Disposition of Gate 18:** deploy-provenance violation, NOT a code defect (see Root cause).

## Verdict

**P-MECHANISM RESOLVED — admission wall cleared.** The Strict PodMigration CR was admitted and persisted. Downstream state-machine entry confirmed (controller reached PreCopy). Full migration proof (SUT PONG, 2s/480s poll, TCP seq-delta) is the next gate phase, now reachable.

## Root cause of Gate 18 (provenance, not code)

Gate 18 reproduced the Attempt-18 `connection refused` identically. The cause was NOT the chart template — ADR-0223's fix was already correct and already in HEAD. It was a **deploy-provenance mismatch**:

- ADR-0223 chart fix committed at **2026-06-16 21:07** (commit `9df05f0`, `charts/podmotion/templates/webhook.yaml`).
- Live Helm release **revision 2 was applied at 20:54** — 13 minutes BEFORE the fix existed.
- Revision 2 was therefore rendered from a pre-fix chart that registered both WebhookConfigurations unconditionally, with `failurePolicy=Fail` and an empty caBundle, against a Service whose operator serves no TLS (ADR-0222). Every PodMigration CREATE blocked at admission.

ADR-0223's own "Blocking re-gate preconditions" #1 (redeploy + assert zero WebhookConfiguration in the deployed manifest) was the check that would have caught this; it was not run before Gate 18.

## §P-MECHANISM (live-path)

The chart at HEAD renders correctly. Positive proof:

```
helm template ... --set webhook.certManager.enabled=false | grep -c 'kind: (Mutating|Validating)WebhookConfiguration'  -> 0
helm template ... --set webhook.certManager.enabled=true  | grep -c '...'                                              -> 2
```

First active-but-silent mechanism (unconditional WebhookConfiguration registration) is fixed in source. No mechanism downstream of it is in scope. No new fix-code ADR required — the resolution is a re-deploy from HEAD.

## Fix applied

`helm upgrade --install podmotion charts/podmotion/` from HEAD (`9df05f0`), `webhook.certManager.enabled=false`, operator image `podmotion-manager:sprint35-amd64`. Release advanced to **revision 3**. Helm pruned the stale WebhookConfigurations on upgrade.

## §P-VERIFY-MULTI (deployed-provenance)

Chart-only fix — no compiled binary axis (vacuous per §P-VERIFY-MULTI). Provenance asserted on the deployed MANIFEST instead:

- `helm get manifest podmotion -n podmotion-system | grep -c 'kind: (Mutating|Validating)WebhookConfiguration'` -> **0** (PASS)
- `kubectl get mutatingwebhookconfiguration,validatingwebhookconfiguration | grep -i podmotion` -> **NONE** (PASS)
- Operator 3/3 Running, agents 2/2 Running, restartCount=0 (P-SUBSTRATE PASS).

## Gate CR apply — PASS (P-MECHANISM resolved)

```
$ kubectl create --dry-run=server -f gate-s35-strict-024.yaml   # tcpPreservationMode: Strict, ns default
podmigration.migration.podmotion.io/gate-s35-strict-024 created (server dry run)   # admission OK

$ kubectl apply -f gate-s35-strict-024.yaml
podmigration.migration.podmotion.io/gate-s35-strict-024 created

$ kubectl get podmigration -A
default   gate-s35-strict-024   nginx-probe   Failed   Strict   PreCopy   0s
```

- CR was ADMITTED (no `connection refused`) and PERSISTED — the admission wall of Attempts 18 and Gate 18 is GONE.
- CR reached the controller and entered the state machine (PreCopy). The `Failed` terminal is the expected downstream condition: the placeholder source pod `nginx-probe` does not exist. This is past the admission block, not the block itself.
- Probe CR deleted after verification.

## Architect Evidence Block

1. **VERBATIM_ERROR** (now ABSENT): previously `failed calling webhook "mpodmigration.kb.io" ... dial tcp 10.106.168.32:443: connect: connection refused`. No longer reproduces — no WebhookConfiguration registered.
2. **CODE_PATH:** `charts/podmotion/templates/webhook.yaml:47,76` — `{{- if .Values.webhook.certManager.enabled }}` guards (already in HEAD `9df05f0`).
3. **CONFIGURED_VS_OBSERVED:** configured `certManager.enabled=false`; Gate-18 OBSERVED 2 live WebhookConfigurations (stale rev-2 manifest); Gate-19 OBSERVES 0 (rev-3 from HEAD).
4. **PRIOR_FIX_HISTORY:** ADR-0223 wrote the guards correctly; Gate 18 deployed a chart rev (20:54) predating the fix (21:07). No code change needed — re-deploy resolved it.
5. **HYPOTHESIS_SPACE:** deploy-provenance (CONFIRMED) — stale chart revision; chart template (RULED OUT — renders 0 when disabled); operator binary (RULED OUT — ADR-0222 serving-side verified firing).

## Strike count

§14g R-iteration: Gate 18 was a deploy-provenance precondition violation. The blocking P-MECHANISM is resolved; the gate now advances to the migration-proof phase.
