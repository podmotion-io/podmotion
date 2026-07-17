# Workload-Liveness Probe (ADR-0325)

## What this is

ADR-0210 proved that the network path between the migrated pod and the rest of the cluster is
reachable (dataplane transport liveness). It did **not** prove that the process listening behind
the socket is actually alive and functioning. ADR-0325 closes that gap: before a `PodMigration`
is allowed to reach `phase=Complete`, the operator now issues a real application-layer probe
against the destination pod and records the result in the `WorkloadLivenessVerified` status
condition.

## What is probed, per protocol

| `spec.applicationProbe.protocol` | What "alive" means |
|---|---|
| `SQL` | A real PostgreSQL wire-protocol v3 handshake (StartupMessage, no password — the probe never authenticates). **Trust / no-auth server:** replies `AuthenticationOk`, and the probe then runs a query (default `SELECT 1`, overridable via `query`) requiring a genuine `RowDescription` + at least one `DataRow` + `CommandComplete` + `ReadyForQuery`. **Password-protected server:** replies with a genuine authentication *challenge* (`AuthenticationCleartextPassword`/`MD5Password`/`SASL`/…), which only a live postmaster past `canAcceptConnections` + a real protocol-v3 backend can frame — this is itself proof of liveness, so the probe PASSES there without authenticating. An `ErrorResponse` (`'E'`, including "the database system is starting up" `57P03`), a malformed auth message, or a continuation/unknown auth subtype as the first reply is a FAILURE. |
| `Redis` (dispatched internally as `REDIS`) | A RESP-encoded `PING`, requiring the literal `+PONG\r\n` reply. |
| `HTTP` | An HTTP GET (default path `/`, overridable via `query`) requiring a genuine `[200,300)` status. Redirects (3xx) are treated as failures — the client does not follow them. |
| `TCP` | A bare TCP connect/close, for protocols with no richer handshake defined yet. |

If `spec.applicationProbe` is left unset and no known port/protocol can be inferred from the
destination pod's container ports, the condition is explicitly set `True`/`NoKnownProtocol` —
this is a deliberate, auditable "transport-only verification applies" outcome, not a silent
fallback.

## Where this runs

- The probe is dispatched from `reconcileServiceVerifying` in
  `internal/controller/podmigration_controller.go`, which calls the destination node's agent
  over the existing `VerifyTCP` RPC with `AppProbeOnly=true`.
- The wire-protocol probe bodies live in `internal/agent/server/pgprobe.go` (Postgres, Redis) and
  inline in `runAppProbe` (`internal/agent/server/server.go`) for HTTP/TCP.
- `runAppProbe` is called for **every** `TCPPreservationMode`, including `None` — workload
  liveness is checked on cold/stateless migrations too, not only `Strict`/`BestEffort`.

## Safety guarantees

- **Probe failure never triggers rollback in non-Strict mode.** A failed or incomplete
  workload-liveness probe causes `reconcileServiceVerifying` to requeue
  (`ctrl.Result{RequeueAfter: ...}`) so the probe can be retried; it does **not** call
  `initiateRollback` or drive the migration into `RollingBack`/`Failed`. Converting a transient
  probe failure into a destructive rollback would itself be a regression of the
  source-pod-never-deleted-until-verified invariant (ADR-0012). This is covered by
  `TestReconcileServiceVerifying_WorkloadLivenessFailure_RequeuesNotRollback_NonStrict` in
  `internal/controller/podmigration_liveness_gate_test.go`.
- **`WorkloadLivenessVerified` is an additive predicate.** `sourcePodDeletionBlockReason` in
  `internal/controller/podmigration_controller.go` requires `WorkloadLivenessVerified=True` in
  addition to the existing mode-specific predicates (`DataplaneReachabilityVerified`/
  `TrafficVerified`, plus `TCPSequenceContinuityVerified` for `Strict`/`BestEffort`) — for *all
  three* `TCPPreservationMode` values, including `None`. It can only make source-pod deletion
  stricter, never looser.
- **Fail-closed SSRF containment.** `dialAllowed` (`internal/agent/server/server.go`) refuses to
  dial any address outside this node's pod-CIDR allowlist, derived from `Node.Spec.PodCIDRs`. An
  unpopulated or unparseable allowlist (e.g. no Kubernetes client wired) fails **closed** —
  every dial is refused, never permitted by default.
- **No credentials are ever sent.** The Postgres probe never sends a password. A trust/no-auth
  server (`AuthenticationOk`) is proven by the full `SELECT 1` query; a password-protected server
  is proven by its genuine authentication *challenge* (a wire-correct challenge can only come from
  a live postmaster + real backend, so it is affirmative liveness) — the probe stops at the
  challenge as a PASS without ever authenticating. It never answers the challenge and holds no
  credential material (`ApplicationProbeSpec` has no password field). No auth header is attached to
  the HTTP probe. _(sprint46B9 round-3 correction: the earlier "auth challenge = `AuthRequired`
  failure" disposition was a false negative on healthy password-protected Postgres and is
  superseded — see ADR-0325 Decision item 1 amendment.)_

## Diagnosing a stuck `Verifying` phase

If a `PodMigration` appears stuck in `Verifying`, check the `WorkloadLivenessVerified` condition's
`Reason`/`Message` on the `PodMigration` status:

```bash
kubectl get podmigration <name> -o jsonpath='{.status.conditions[?(@.type=="WorkloadLivenessVerified")]}'
```

Reason values currently emitted by `reconcileServiceVerifying`:

- `NoKnownProtocol` — no probe protocol could be resolved and none was declared; transport-only
  verification applies (this is a passing/`True` outcome, not a failure).
- `AmbiguousProbeDefault` — multiple container ports matched the heuristic; set
  `spec.applicationProbe` explicitly to disambiguate.
- `ExplicitProbeFailed` / `DefaultedProbeFailed` — the probe RPC completed but the protocol
  handshake/check failed (Postgres `ErrorResponse` / server still starting up `57P03`, non-2xx
  HTTP, wrong PING reply, etc.).
- `ExplicitProbePassed` / `DefaultedProbePassed` — the probe succeeded.

A stuck reconcile with no condition set at all (rather than a `False` condition) most often means
`AgentPool` is not wired on the operator, or the destination-node agent client could not be
resolved — check the operator log for `"ServiceVerifying: AgentPool not wired"` or
`"ServiceVerifying: could not resolve destination-node agent client"`.

## Known gaps (tracked, not yet closed)

- Probe-failure classes (timeout vs. protocol-mismatch vs. SSRF-blocked-dial) are not yet
  surfaced as distinct metrics/events for on-call triage beyond the condition `Reason` string —
  tracked as a follow-up for the Test/SignOff phase of ADR-0325.
