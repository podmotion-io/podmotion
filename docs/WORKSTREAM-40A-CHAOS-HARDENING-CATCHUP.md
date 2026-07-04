# Workstream-40A: Chaos Hardening Backlog Catch-Up (PROPOSAL — Chad sign-off required)

> Supporting detail for `docs/CURRENT-POSITION.md` — see that file for the human-readable "you are here" summary; this doc is the detailed work-ledger record for Workstream-40A.

**serves_milestone:** HARDENING-PRE-M22

**Status:** PROPOSED — not yet authorized. Workstream scope, sequencing, and closure are Chad-owned (OPERATING_FRAMEWORK.md §4, §12). This document is a starting point for that decision, not a final scope.
**Drafted:** 2026-07-03, in response to Chad's north-star framing: two parallel tracks, of which this document covers **Track A — "All Chaos Hardening done up until this point."**
**Companion track (NOT covered here):** Track B — the Sprint 40 R750 4-runtime-matrix Workstream (KVM/kind/Docker/containerd proof). See "Explicitly out of scope" below.
**Source material verified directly:** `docs/chaos/CHAOS-QUEUE.md` (180 lines, read in full), `docs/chaos/SPRINT40-CHAOS-ASSESSMENT.md` (419 lines, read in full), `docs/chaos/CHAOS-PLAN-REVIEW.md`, `docs/OPERATING_FRAMEWORK.md` §4 (Workstream table format), and the relevant Go source (`internal/agent/server/server.go`, `internal/controller/podmigration_controller.go`) for the two long-blocked items.

---

## Following the OPERATING_FRAMEWORK.md §4 Workstream table convention

| Workstream | Status | Definition of "provably true at close" |
|---|---|---|
| **Workstream-40A** | Confirmed (Chad, 2026-07-03) | `docs/chaos/CHAOS-QUEUE.md` contains **zero BLOCKED, zero CONDITIONAL, and zero QUEUED items** older than Sprint 40 — the FULL pre-Sprint-40 backlog (49 sprint-points across all 4 categories), each closure backed by a proof artifact (a chaos-test run doc or ADR + passing gate, same evidentiary bar as ADR-0101/CHAOS-VALIDATION-PLAN.md precedent). Additionally, the two long-open blocking-precondition ADRs (NR-BLOCK-1, R4) have each reached an accepted decision (not necessarily the drafts below verbatim — those are starting points for review panel). Chad ruled: "the sprints have been accumulating chaos work that needs to be done and now we want to run all of them" — confirming phase 4 (the QUEUED sweep) is IN the closure bar, not optional. |

---

## 1. What the backlog actually contains right now (verified 2026-07-03, not secondhand)

Read `docs/chaos/CHAOS-QUEUE.md` in full. As of 2026-07-03 the queue holds **64 scenarios total** (FS-025..FS-089, some numbers reused/re-scoped) plus **4 open blocking-precondition entries**. Breaking out what predates Sprint 40 vs. what Sprint 40 just added:

**Predates Sprint 40 (this Workstream's candidate scope):**

| Status | Count | Items | Sprint-points (sum of "Sprint est.") |
|---|---|---|---|
| Blocking preconditions (open) | 3 | NR-BLOCK-1, SRE-C1, R4 | — (decision work, not scenario work) |
| BLOCKED | 5 | FS-038, FS-048, FS-049, FS-050, FS-051 | 10 |
| CONDITIONAL | 8 | FS-046, FS-047, FS-053, FS-054, FS-057, FS-060, FS-061, FS-062 | 11 |
| QUEUED (HIGH) | 12 | FS-025, FS-026, FS-030, FS-031, FS-042, FS-045, FS-052, FS-055, FS-056, FS-058, FS-059, FS-065 | 14 |
| QUEUED (MEDIUM) | 14 | FS-027, FS-028, FS-029, FS-032, FS-033, FS-034, FS-035, FS-036, FS-037, FS-039, FS-040, FS-041, FS-043, FS-044 | 14 |
| amd64-ONLY (separate deferred Workstream already, per queue's own notes) | 22 | FS-063, FS-064, FS-066..FS-085 | — out of this Workstream; queue already defers these to "the amd64/kind Workstream" |

**New from Sprint 40 (explicitly OUT of this Workstream — see below):** KVM-BLOCK-1 (blocking precondition), FS-086, FS-087, FS-088, FS-089 (4 scenarios), plus a non-blocking re-scope note on FS-039/040/041/075/076 (budget re-validation for the shared-host topology — that re-validation work belongs to Track B since it only matters once the 4-runtime matrix is actually running).

## 2. NR-BLOCK-1 and R4 — verified against source, not just the queue's description

Both have been OPEN since 2026-06-13 (three sprints, zero owner movement) per SPRINT40-CHAOS-ASSESSMENT.md §6's own escalation note. I traced both into the actual code to confirm what they are waiting on and drafted a starting-point ADR for each (see below) — these are **drafts for a real review panel**, not decisions.

- **NR-BLOCK-1** — verified in `internal/agent/server/server.go` (`CleanupSourceIPHandoff` L1191, `DisarmTCRedirect` L1495) and `internal/controller/podmigration_controller.go` (~L3320, ~L2834): both cleanup RPCs are called **warn-only** — an RPC error or a `Cleaned=false`/`Disarmed` response is logged and swallowed; `reconcileCutoverComplete` always proceeds to `MigrationPhaseComplete` regardless of confirmed cleanup state. The codebase already has the right pattern one code block later in the same function (the EndpointSlice post-flight check, `esMgr.HasEndpointForIP`, ~L3373) — it actively re-queries state and sets a condition, rather than trusting the mutating call's own report. NR-BLOCK-1 is asking for that same pattern applied to the six datapath cleanup objects. Draft: `docs/adr/DRAFT-NR-BLOCK-1-resolution.md`.
- **R4** — verified in `CHAOS-PLAN-REVIEW.md`'s consolidated required actions and `internal/controller/podmigration_controller.go:843` (`reconcileDisengageHold`). The scenario (FS-038): an external flush of the FORWARD ACCEPT/NOTRACK iptables rules while the zero-window hold is still active, before the controller ever re-checks that state. CHAOS-PLAN-REVIEW.md names two candidate mechanisms and explicitly declines to pick one — that's the actual unresolved decision. Draft: `docs/adr/DRAFT-R4-resolution.md`.

Both drafts propose a concrete direction and flag the specific open questions (blocking-vs-warn-only for NR-BLOCK-1; polling interval/SLO and whether to share a verification-RPC design with NR-BLOCK-1, for R4) that a real Review/review panel needs to settle. Neither draft should be treated as accepted — they exist so the review panel has a starting document instead of a blank page, matching the "zero owner movement in 3 sprints" problem directly.

## 3. Proposed sprint breakdown (rough — Chad's call on final sequencing)

Raw sprint-point sum for BLOCKED + CONDITIONAL + QUEUED(HIGH) + QUEUED(MEDIUM) pre-Sprint-40 items = 10 + 11 + 14 + 14 = **49 sprint-points**, where a "sprint-point" is the queue's own per-scenario estimate if run in isolation. In practice, sprints bundle multiple independent scenarios (same pattern as the queue's own "Recommended Workstream 1 Order," which schedules 5 no-precondition items together), so 49 raw points does not mean 49 sprints.

Proposed phasing:

1. **Sprints 1–2 (parallel with everything else): ADR review panel.** Accept real (non-draft) decisions for NR-BLOCK-1, R4, and the much smaller SRE-C1 (a pass-criteria SLO-number spec, no ADR needed per the queue's own note). This is decision work, not chaos-test execution, and can run fully in parallel with phase 2.
2. **Sprints 2–4: unblock and clear BLOCKED.** Once NR-BLOCK-1/R4 decisions are accepted, execute FS-038 and FS-048/049/050/051 (10 sprint-points, the four highest contamination-risk items in the queue) plus the queue's own "Recommended Workstream 1 Order" (FS-056, FS-055, FS-047, FS-058, FS-045 — already no-precondition).
3. **Sprints 5–8: close remaining CONDITIONAL.** Requires the harness primitives the queue already names (`AssertPendingResumePIDsEmpty` for FS-057, a dead-PID probe for FS-060, `AssertAgentCleanupNotRunPostOOM` for FS-062, the SRE-C1 SLO spec for FS-046/047/054/062) — these are small, well-scoped additions, not new architecture.
4. **Sprints 9–12: sweep remaining QUEUED (HIGH then MEDIUM).** No blocking preconditions on any of these 26 items; this is straightforward execution against the existing arm64 k3s / amd64 kind harness.

**Rough total estimate: 10–12 sprints**, comfortably inside the Workstream's normal 5–15 sprint range (OPERATING_FRAMEWORK.md §1.1). This assumes normal parallelism (multiple scenarios per sprint, ADR review panel work overlapping scenario execution) rather than one-scenario-per-sprint sequential execution.

### Scope question for Chad

**RESOLVED 2026-07-03:** Chad confirmed phase 4 (the 26-item QUEUED sweep) is IN the Workstream-40A closure bar — "the sprints have been accumulating chaos work that needs to be done and now we want to run all of them." The closure bar above has been updated accordingly: zero BLOCKED, zero CONDITIONAL, AND zero QUEUED older than Sprint 40, all 4 phases (~10-12 sprints), not just phases 1-3.

## 4. Explicitly OUT of scope for Workstream-40A (belongs to Track B)

Per Chad's framing, the new Sprint-40-specific fault surface is a **different track** — new-runtime-surface investigation, not backlog catch-up — and is explicitly excluded from this Workstream's closure bar:

- **KVM-BLOCK-1** — no CRIU-in-QEMU code path exists at all; this needs an Opus architect + ADR scope decision (SPRINT40-CHAOS-ASSESSMENT.md C2) before any KVM chaos scenario can even be written with real pass/fail criteria. This is Track B's problem, not Workstream-40A's.
- **FS-086, FS-087, FS-088, FS-089** — the four new Sprint 40 scenarios (host-Docker-crash-kills-all-kind-nodes; per-runtime image-store desync; `SameNodeVacuous` SPOF under shared-host topology; raw-Docker-Engine namespace mismatch). All are new fault surface introduced by the R750 4-runtime-matrix Workstream itself, not pre-existing backlog.
- **The FS-039/040/041/075/076 re-scope note** — re-validating resource-exhaustion pass-criteria/timeouts for the shared-host (4-concurrent-runtime, 56-core/62Gi) topology only matters once that topology exists; it's Track B's precondition to satisfy before re-running those scenarios in the new environment, not a Workstream-40A deliverable. (Workstream-40A may still execute these five scenarios in their *original* single-runtime scoping as part of the QUEUED-MEDIUM sweep in phase 4 above — that's independent of the Track B re-validation question.)

## 5. Deliverables of this drafting pass

- `docs/adr/DRAFT-NR-BLOCK-1-resolution.md` — draft ADR proposal (not accepted).
- `docs/adr/DRAFT-R4-resolution.md` — draft ADR proposal (not accepted).
- `docs/WORKSTREAM-40A-CHAOS-HARDENING-CATCHUP.md` — this document.

All three are new, untracked files — nothing has been committed to git, and no existing file was modified.
