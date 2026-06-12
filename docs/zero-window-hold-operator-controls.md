# Zero-Window Hold: Operator Controls

**Scope**: M20 — zero-window hold production eBPF  
**Reference**: ADR-0049, `api/v1alpha1/podmigration_types.go`, `proto/migration_agent.proto`

This document describes how the zero-window hold works from an operator's perspective: which
`PodMigration` fields control it, what status conditions are emitted, how the hold duration is
measured, and what failure modes look like in `kubectl describe`.

---

## What the Zero-Window Hold Does

During a live TCP-stateful migration the operator must quiesce the source pod's outgoing TCP
connections before invoking CRIU. If CRIU dumps a socket with unacknowledged bytes in the send
buffer, the relay's sequence-number translation (`seq_delta`) will be wrong and all subsequent
packets on that connection will have corrupt sequence numbers.

The hold works by attaching a `BPF_PROG_TYPE_SCHED_CLS` program to the TC egress hook of the
source pod's veth interface. The program rewrites the TCP window field in outgoing ACK segments
to zero. The peer's TCP stack obeys the advertised window and stops sending — no RST, no
timeout, no visible application error. The hold is released (veth filter removed) after CRIU
restore is confirmed and the relay is armed on the destination.

This is the `ZeroWindowArm` phase of the 12-phase migration pipeline.

---

## Spec Fields

### `spec.tcpPreservationMode`

```yaml
spec:
  tcpPreservationMode: Strict   # or BestEffort or None
```

| Value | Behavior |
|-------|----------|
| `Strict` | Full TCP sequence continuity required. If `TCPSequenceContinuityVerified=False` after restore, the operator triggers hard rollback and the source pod is NOT deleted. See ADR-0019 Amendment A. |
| `BestEffort` | Attempts zero-window hold and sequence preservation; emits a warning condition instead of rolling back on failure. |
| `None` | Skips `ZeroWindowArm`, `SocketInventory`, and `TCPVerifying` phases entirely. Correct for stateless workloads. This is the default (`+kubebuilder:default=None`). |

The zero-window hold is only engaged when `tcpPreservationMode` is `Strict` or `BestEffort`.
Setting it to `None` on a pod with active TCP connections results in those connections being
broken at migration — which may be acceptable for workloads that reconnect automatically.

### `spec.freezeWindowBudgetMs`

```yaml
spec:
  freezeWindowBudgetMs: 500   # default; range 50–10000
```

The maximum allowed wall-clock milliseconds for the complete arm-to-disarm critical path. This
budget covers:

1. TC-BPF attach on source veth (arm)
2. Send buffer drain poll (`tcpi_unacked == 0` on all migrated sockets)
3. CRIU final freeze + dump (`FinalFreeze` phase)
4. CRIU restore on destination (`Restore+SocketReattach` phase)
5. Relay arm + FDB convergence + 6-predicate barrier satisfied
6. TC-BPF detach on source veth (disarm)

If the arm-to-disarm wall time exceeds `freezeWindowBudgetMs`, the operator:

- Sets `ZeroWindowDisarmed=False` with `Reason=BudgetExceeded` and the actual duration in the
  `message` field.
- Triggers rollback (both `Strict` and `BestEffort` modes).

The send buffer drain sub-step is bounded to `freezeWindowBudgetMs / 2`. If `tcpi_unacked` does
not reach zero within that half-budget, the migration is aborted before CRIU is invoked — the
source pod is not checkpointed with a non-empty send buffer.

**Guidance**:
- 500ms (default) covers single-hop intra-datacenter migrations on standard hardware.
- Increase to 1000–2000ms for cross-AZ migrations or pods with deep send buffers.
- Values below 100ms are rarely achievable in practice and will produce frequent aborts.

### `spec.applicationProbe`

```yaml
spec:
  applicationProbe:
    type: SQL
    query: "SELECT 1"
    timeoutSeconds: 5
```

An optional post-restore application-level health check. If set, the operator executes this
probe after `TCPVerifying` before declaring `phase=Complete`. Supported types: `SQL`, `HTTP`,
`gRPC`, `TCP`.

---

## Status Conditions

The zero-window hold lifecycle produces two status conditions.

### `ZeroWindowArmed`

Set in the `ZeroWindowArm` phase.

| Status | Reason | Meaning |
|--------|--------|---------|
| `True` | `ZeroWindowEngaged` | TC-BPF program attached; window-size=0 advertisements active on source veth. |
| `False` | `ZeroWindowFailed` | BPF load or TC attach failed; migration aborted; see `message` for kernel error. |
| `False` | `DrainTimeout` | Send buffer did not drain within `freezeWindowBudgetMs / 2`; CRIU not invoked; migration aborted. |
| `Unknown` | `ZeroWindowNotStarted` | Phase not yet reached. |

### `ZeroWindowDisarmed`

Set in the `DisengageHold` phase, after CRIU restore and relay arm.

| Status | Reason | Meaning |
|--------|--------|---------|
| `True` | `ZeroWindowReleased` | TC-BPF filter removed; peer send window restored; hold duration within budget. |
| `False` | `BudgetExceeded` | Arm-to-disarm wall time exceeded `freezeWindowBudgetMs`; rollback triggered. Message carries `hold_duration_ms=<N>`. |
| `False` | `DisarmFailed` | TC filter removal returned an error; migration in degraded state; see `message`. |
| `Unknown` | `DisarmNotStarted` | Phase not yet reached. |

The `message` field of `ZeroWindowDisarmed=True` always includes `hold_duration_ms=<N>` so
that operators can trend actual hold durations against the budget without parsing logs.

```
kubectl get podmigration <name> -o jsonpath='{.status.conditions[?(@.type=="ZeroWindowDisarmed")].message}'
```

Example output: `hold_duration_ms=312 budget_ms=500`

---

## Watchdog Auto-Disarm

The node agent runs a watchdog goroutine after `ArmZeroWindow` succeeds. If the operator does
not send a `DisarmZeroWindow` gRPC call within `FreezeWindowBudgetMs + 500ms`, the watchdog
fires and removes the TC filter automatically. This prevents a leaked hold from leaving the
source pod's veth permanently stalled if the operator crashes or loses connectivity.

When the watchdog fires:
- The TC-BPF filter is removed.
- The agent logs `event=watchdog_disarm migration_name=<name>` at `Info` level.
- If the operator subsequently calls `DisarmZeroWindow`, it receives `disarmed=true` and
  `blocking_reason=watchdog_already_disarmed` in the response. The operator treats this as a
  successful disarm and sets `ZeroWindowDisarmed=True`.

The watchdog is not a substitute for correct hold duration management. If the watchdog fires
frequently in production, reduce workload complexity or increase `freezeWindowBudgetMs`.

---

## Observing a Migration with `kubectl describe`

A healthy migration through the zero-window hold phases looks like this:

```
Status:
  Phase:  DisengageHold
  Conditions:
    Type:               ZeroWindowArmed
    Status:             True
    Reason:             ZeroWindowEngaged
    Last Transition:    2026-06-12T14:22:03Z
    Message:            TC-BPF zero-window program attached to veth3a2f1b

    Type:               ZeroWindowDisarmed
    Status:             True
    Reason:             ZeroWindowReleased
    Last Transition:    2026-06-12T14:22:03Z
    Message:            hold_duration_ms=287 budget_ms=500
```

A migration that aborts due to send buffer drain timeout:

```
Status:
  Phase:  Failed
  Conditions:
    Type:               ZeroWindowArmed
    Status:             False
    Reason:             DrainTimeout
    Last Transition:    2026-06-12T14:22:07Z
    Message:            send buffer did not drain within 250ms; tcpi_unacked=4 at timeout; source pod thawed
```

---

## CI Hold-Duration Tracking

The Testing discipline emits `[CI hold-duration]` lines to Ginkgo output during E2E runs.
`scripts/m20-hold-duration.sh` parses these for trend tracking. Operators can correlate CI
p50/p99 hold durations against `freezeWindowBudgetMs` to set appropriate production budgets.

---

## Relationship to Other Conditions

The zero-window hold is one step in a larger 6-predicate ARM barrier (ADR-0049). The full
barrier before `ZeroWindowDisarm` fires requires all of:

| Predicate | Condition |
|-----------|-----------|
| A. Send buffer drained | `tcpi_unacked == 0` (checked inline, no condition emitted) |
| B. PM_SEQ_XLAT populated | `RelayProgramsLoaded=True` |
| C+D. FDB injected both sides | `VXLANFDBUpdated=True` |
| E. Conntrack NOTRACK armed | checked inline by `ConfirmOverlayReady` RPC |
| F. CRIU restore confirmed | `phase=Restore+SocketReattach` completed |

`ZeroWindowDisarmed=True` is set only after all 6 predicates are satisfied. If any predicate
fails, the hold remains armed until the watchdog fires or the operator rolls back.

---

## API Conventions Reference

All condition Types and Reasons follow the K8s API conventions documented in
`docs/adr/conditions-vocabulary.md`:

- Type: upper-CamelCase noun phrase
- Reason: upper-CamelCase single word or compound word, no spaces
- Message: human-readable, may change between releases — do not parse programmatically

The Go constants are defined in `api/v1alpha1/podmigration_types.go`:

```go
ConditionZeroWindowArmed    = "ZeroWindowArmed"
ConditionZeroWindowDisarmed = "ZeroWindowDisarmed"
```
