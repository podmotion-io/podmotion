# Sprint 41 Plan — NR-BLOCK-2: IP-Reclaim Trigger Event

**Status:** DRAFT — untracked, pending Chad review (same convention as `docs/adr/DRAFT-*.md` and
`docs/SPRINT40-40A-PLAN.md`). Not committed until Chad reviews; committed as a plan doc per the
committed-scope instruction for this sprint.
**Written by:** Sprint Manager, following the Workstream-40A precedent (`docs/SPRINT40-40A-PLAN.md`)
and the standing task-framing convention (precondition/ADR work before implementation).
**Workstream:** Workstream-40A — Chaos Hardening Backlog Catch-Up (`docs/WORKSTREAM-40A-CHAOS-HARDENING-CATCHUP.md`).
**Predecessor:** ADR-0241 (Accepted r2, EffSO=15.0) resolved NR-BLOCK-1's cutover-complete scope
(`CleanupSourceIPHandoff`, 2 cni0 objects) and split out the 4 remaining objects
(dest tc filter/qdisc, dest FORWARD ACCEPT, dest NOTRACK, source `flannel.1` redirect, source
NOTRACK) into NR-BLOCK-2 — OPEN, target Sprint 41, per `docs/chaos/CHAOS-QUEUE.md`.

---

## Objective

**Resolve NR-BLOCK-2: define and implement the IP-reclaim trigger event, so that
`r.disarmTCRedirect` and the source `flannel.1`/NOTRACK teardown are actually invoked by a real
code path, and `VerifyCleanup(IP_RECLAIM, ...)` can be implemented (today it unconditionally
returns `codes.Unimplemented`, citing NR-BLOCK-2, at `internal/agent/server/server.go:1575-1578`).**

Today, per ADR-0241's own findings and `docs/proof/SPRINT40-FS038-048-051-GATE-PROOF.md`:
`disarmTCRedirect` (`internal/controller/podmigration_controller.go:2830`) has zero reconciler
call sites — it is dead code, referenced only by its own definition and by a comment (L3450)
explaining why it is deliberately NOT called at cutover-complete ("to keep the OLD IP reachable
... retired only when the OLD IP is reclaimed by IPAM"). No IPAM-reclaim event, controller, or
trigger exists anywhere in the codebase. The four dest-side objects and the two source-side
objects (`flannel.1` redirect + source NOTRACK) are installed once per migration and never
removed by any code path today. This sprint closes that gap — it does not touch the
cutover-complete scope ADR-0241 already resolved.

**Unblocks:** FS-048, FS-049, FS-050, FS-051 (all four currently BLOCKED in
`docs/chaos/CHAOS-QUEUE.md` on NR-BLOCK-2 — the four highest contamination-risk chaos scenarios
in the entire 64-scenario queue).

**Explicitly OUT of scope this sprint:** FS-038. It requires (a) a `RunFS038` chaos scenario
driver, which does not exist anywhere in `test/chaos`, and (b) a PodMotion-deployed, multi-node,
Flannel-CNI test cluster — the only cluster currently available
(`kind-sprint40b1-infra-prep`) has no PodMotion CRDs/operator/agent deployed and cannot exercise
this datapath at all (per the Sprint 40 gate-proof evidence). Building a live 2-node test harness
from scratch is a substantially larger effort than an ADR + trigger implementation and does not
fit this sprint's committed scope. **Flagged as a backlog item for Sprint 42+**: stand up a
PodMotion-deployed 2-node (or 3-node) Flannel-CNI cluster with a real chaos-driver harness in
`test/chaos`, then write `RunFS038` (and, opportunistically, `RunFS048`..`RunFS051` once
NR-BLOCK-2 lands) against it.

---

## Why an ADR is required before implementation

Per the explicit High-tier trigger ("affects the migration datapath"), any change wiring a new
call site for `disarmTCRedirect` or adding source-side `flannel.1`/NOTRACK teardown is squarely
migration-datapath work — the same classification ADR-0241 and Workstream-40A's NR-BLOCK-1/R4
ADRs received. This sprint follows the same shape: ADR authored, High Review, then implementation.

## Choice of trigger event (author's justification)

The chaos-queue description names three candidate mechanisms: IPAM lease expiry, pod-IP GC sweep,
or CR deletion + TTL. This sprint's ADR must pick one (or a composite) and justify it against the
existing code shape. Framing for the ADR author, informed by reading the code already in place:

- **IPAM lease expiry** would require an event/webhook from whatever IPAM component owns lease
  state — PodMotion does not currently own or watch any IPAM lease object, so this would be a new
  external dependency and a new watch/informer with no existing analog in the codebase.
- **Pod-IP GC sweep** (a periodic reconcile-loop sweep, agent- or controller-side, that scans for
  migrations whose OLD IP is no longer referenced by any live pod/endpoint and fires teardown) has
  a direct analog already in the codebase: `EndpointSliceManager.HasEndpointForIP` (referenced in
  ADR-0241, `podmigration_controller.go` ~L3373) is exactly this kind of "probe after mutate, in
  the same reconcile pass" check, already House Style per ADR-0241's own stated precedent. A GC
  sweep re-uses that existing primitive to decide "is the OLD IP still live," which is a strong
  argument for a periodic-sweep design over a net-new external lease-watch dependency.
- **CR deletion + TTL** (fire teardown N seconds/reconciles after the `PodMigration` CR itself is
  deleted or reaches a terminal `Complete` state old enough to be GC'd) is the simplest to wire
  (an existing CR already carries a natural lifecycle event) but needs a TTL value derived from
  something concrete (NMC heartbeat interval, or a fixed multiple of the CUTOVER_COMPLETE retry
  window) — an arbitrary constant would not survive Review.

**Recommended default direction for the ADR author (not binding — the author may justify a
different choice): a pod-IP GC sweep, keyed off CR terminal state + `HasEndpointForIP`
returning false, run on a periodic reconcile requeue** — this avoids inventing a new external
IPAM-lease dependency, reuses an already-Reviewed primitive, and gives a natural condition (no
live endpoint references the OLD IP) rather than an arbitrary TTL. The ADR author must still
justify the actual choice in writing; this is a recommendation to shorten authoring time, not a
pre-decision.

---

## Workstreams

### Workstream 1 — ADR authoring and Review (blocking, must complete before Workstream 2)

1. **Pre-ADR mechanism map (Opus, blocking).** Before the ADR is authored: map every mechanism already
   in place on the reclaim-teardown path — `disarmTCRedirect`'s existing (but uncalled) RPC path,
   `EndpointSliceManager.HasEndpointForIP`, the `VerifyCleanup(IP_RECLAIM, ...)` stub, and the
   source-side `flannel.1`/NOTRACK removal functions referenced in `server.go` comments (currently
   no removal function exists for `flannel.1` — only the install path, per
   `server.go:1505-1531`). Mark each *active*, *firing*, or *silent* with positive-log-line
   evidence per the standing pre-ADR mechanism-map rule (CLAUDE.md rule 3k). This is required before authoring per the
   standing rule — CRIU/kernel/mount-namespace/low-level failures are not the only class this
   applies to; the netfilter/tc/VXLAN datapath state here is the same "kernel-adjacent, low-level"
   category ADR-0241's own planning treated as requiring this.
2. **Author the NR-BLOCK-2 ADR** (Sonnet ADR author): define the trigger event (justified choice,
   see above), the new `disarmTCRedirect` call site(s), the new source-side `flannel.1`/NOTRACK
   teardown function(s) (net-new — nothing removes these today), and the `VerifyCleanup(IP_RECLAIM, ...)`
   implementation replacing the current `codes.Unimplemented` stub. Must include a Reversibility
   field (per standing ADR authoring rules). Must explicitly address: (a) what happens if teardown fires while a
   *second* migration of the same pod is in flight (does the GC sweep need a migration-in-progress
   guard?); (b) idempotency of the new teardown functions on repeated fire (crash/restart safety,
   same class as ADR-0118's stale-claim recovery); (c) whether the four dest-side objects and two
   source-side objects fire from one trigger event or two (dest-side already has a single RPC,
   `DisarmTCRedirect`, that bundles all four — source-side has no equivalent bundling RPC yet and
   this ADR must decide whether to add one).
3. **High Review** (14 reviewers, EffSO ≥ 11, Security Reviewer 2× weight) — same tier as
   ADR-0241 and the NR-BLOCK-1/R4 ADRs, on the same "affects the migration datapath" criterion.
   A `DECLINE` from Security Reviewer is a hard block (EffSO unreachable).

### Workstream 2 — Implementation (gated on Workstream 1's ADR reaching Accepted)

4. Wire the chosen trigger event (controller reconcile loop or agent-side sweep, per the Accepted
   ADR) to call `r.disarmTCRedirect` for the four dest-side objects.
5. Implement the new source-side `flannel.1` redirect + source NOTRACK teardown function(s) (net
   new code — today only install paths exist for these two objects).
6. Implement `VerifyCleanup(IP_RECLAIM, ...)` for real (replace the `codes.Unimplemented` stub at
   `server.go:1575-1578`) — probing presence/absence of all six original NR-BLOCK-1 objects is
   already split: two (cni0 neigh/route) are covered by `VerifyCleanup(CUTOVER_COMPLETE, ...)`
   from ADR-0241; this sprint's `IP_RECLAIM` scope covers the remaining four plus the two
   source-side objects this ADR adds teardown for.
7. Update `docs/chaos/CHAOS-QUEUE.md`: move NR-BLOCK-2 from `OPEN` to `RESOLVED`, citing the new
   ADR number; update FS-048/049/050/051 status from `BLOCKED` to `QUEUED` (or `CONDITIONAL` if
   the Review attaches any non-blocking condition) now that a real cleanup path exists to fault-
   inject against. FS-038 stays BLOCKED, untouched, with an explicit backlog note pointing to
   Sprint 42+ (test-driver + cluster gap, out of this sprint's scope).
8. **T-INFRA-WIPE (Step -1, mandatory, before any implementation or gate work begins).** Per
   CLAUDE.md standing rule 9: `kind get clusters` then delete any cluster not belonging to Sprint
   41 (in particular, `kind-sprint40b1-infra-prep` and any other Sprint-40-prefixed cluster);
   `virsh list --all --name` then destroy+undefine any prior-sprint KVM VM. Named task, not
   ad-hoc — run before Workstream 2 implementation/gate work, not before Workstream 1 (ADR
   authoring needs no cluster).
9. **Sprint-close chain (on gate PASS).** Working-tree clean assert (steps 1-4), secret scan
   (step 5), push-readiness verdict (step 6), proof file `docs/proof/sprint41-proof.md` (step 7),
   `docs/proof/RESUME-STATE.yaml` spine update to `phase_state: closed` with `next_sprint`,
   `last_proof`, `cadence_owed` all set (step 8), plain-English closure summary (step 9),
   boundary cadence dispatch if this sprint advances a Capability-target claim — it does not
   (this is chaos-hardening/datapath-cleanup work, not a `seq_delta`/`tcpPreservationMode` claim),
   so `cadence_owed: []` is expected unless Workstream 2 surfaces new datapath-invariant evidence
   (step 10).

---

## Gate Criteria (GC-1..GC-7)

- **GC-1:** A numbered ADR (e.g. `docs/adr/ADR-0XXX-nr-block-2-ip-reclaim-trigger.md`) exists
  with `Status: Accepted`, defining the IP-reclaim trigger event with an explicit justification
  for the chosen mechanism (IPAM lease expiry / pod-IP GC sweep / CR deletion+TTL / composite),
  and records a High Review EffSO ≥ 11.
- **GC-2:** The ADR contains a non-empty `Reversibility` field.
- **GC-3:** Security Reviewer's recorded vote is `SIGN_OFF` or `CONDITIONAL_SIGN_OFF` (a
  `DECLINE` is a hard block — EffSO becomes unreachable).
- **GC-4:** `r.disarmTCRedirect` has at least one real reconciler call site (grep confirms it is
  no longer referenced only in its own definition and a "why not called" comment).
- **GC-5:** New teardown code exists and is called for the source `flannel.1` redirect and source
  NOTRACK rule (currently no removal function exists for either — grep confirms only install-path
  code today).
- **GC-6:** `VerifyCleanup(IP_RECLAIM, ...)` no longer returns `codes.Unimplemented` — it performs
  a real presence/absence probe of the four dest-side plus two source-side objects, mirroring the
  `CUTOVER_COMPLETE` scope's existing pattern.
- **GC-7:** `docs/chaos/CHAOS-QUEUE.md` shows NR-BLOCK-2 `RESOLVED` (citing the new ADR number)
  and FS-048/049/050/051 moved off `BLOCKED` (to `QUEUED` or `CONDITIONAL`, per Review outcome);
  FS-038's row is untouched apart from an added backlog note pointing to Sprint 42+; no other
  queue rows are altered.

**Not a gate criterion this sprint:** FS-038 passing live, or a `RunFS038` driver existing — both
explicitly deferred to Sprint 42+ per the Objective section above.

---

## Backlog item recorded for Sprint 42+ (FS-038)

FS-038 (iptables flushed on source while zero-window hold active) needs, before it can gate:
1. A live, PodMotion-deployed, multi-node (2+ node), Flannel-CNI test cluster — none currently
   exists; `kind-sprint40b1-infra-prep` has no PodMotion operator/agent/CRDs installed.
2. A `RunFS038` chaos-scenario driver in `test/chaos` — does not exist today; only unit-level
   coverage exists (`TestZeroWindowFlushWatch_StartOrdering_ADR0240D2a` /
   `..._StopOrdering_ADR0240D2a`, both passing).
The underlying detection logic (ADR-0240, Accepted, R4 resolution) is implemented and unit-tested
— the gap is entirely test-infrastructure, not code-under-test. This is a materially larger scope
(stand up a cluster + write a driver framework, likely usable by FS-048..FS-051's own live gating
too) than this sprint's ADR-plus-trigger scope, so it is flagged here rather than attempted now.

---

## T-INFRA-WIPE

Named task per CLAUDE.md standing rule 9 — run before any Sprint 41 implementation/gate work
(Workstream 2, not Workstream 1's ADR authoring):

```bash
kind get clusters
# delete every cluster that does not match a sprint41 prefix
virsh list --all --name
# destroy + undefine every VM that does not belong to Sprint 41
```
