# PodMotion — Current Position

> **This is a derived human view, not a second source of truth.** It is generated from
> `docs/proof/RESUME-STATE.yaml` (the resumption spine — machine-enum-only, resume-critical)
> and `HANDOFF-LOG.md` (session history). When this file and the spine disagree, **the spine
> wins, full stop.** Update this file at every sprint close; it does not replace the spine
> and it does not replace the capability register (`docs/FELN_SPRINT_PLAN.md` /
> `docs/MILESTONES.md`) or the work ledger (the `Workstream-40*.md` docs).

## You are here

1. **North Star:** complete bilateral transparency for live pod migration — ALL containers
   unaware, ALL clients unaware, `seq_delta=0`. Not proven end-to-end yet.
2. **Current milestone target: M22** (multi-container consistent checkpoint + security
   baseline + scope matrix) — **NOT yet proven.** Its controller-wiring gate (G1) passed
   14/14 (commit `5e76312`), but its core capability gate (G6, multi-container consistent
   freeze) has no code yet and is not started.
3. **Active work is pre-M22 hardening, not M22 itself:** three parallel Vorns —
   Workstream-40A (chaos-backlog catch-up), Workstream-40B-1 (Docker/containerd runtime certification),
   Workstream-40B-2 (KVM certification, spike-gated) — each declares `serves_milestone` in its
   own header (see those docs). This hardens the substrate M22's future proof will run on;
   it does not itself close M22.
4. **Current global sprint: Sprint 40**, Step 2, closed `GATE_PASS` (commit `cfc1450`).
5. **Spine state:** `phase: C`, `phase_state: closed`, `next_action: RESUME`.
6. **Next action:** resume Sprint 40 Step 3 across the three active Vorns (Workstream-40A,
   Workstream-40B-1 in parallel; Workstream-40B-2 remains spike-gated pending its architecture spike).

## History (append one row per sprint close; newest at the bottom)

| Global Sprint | Milestone target | Workstream (work) | Workstream-local # | Status | Proof |
|---|---|---|---|---|---|
| S39 | — (IP protection / evidence engine, no Capability-target claim) | — | — | GATE_PASS | `docs/proof/sprint39-proof.md` (`a3edecb`) |
| S40 Step 1 | pre-M22 hardening | Workstream-40A / Workstream-40B-1 (decision-only: ADR-0240, ADR-0241, ADR-0242 accepted) | #1 | GATE_PASS (decision-only, no code) | `docs/proof/SPRINT40-S1-PROOF.md` (`bef2690`) |
| S40 Step 2 | pre-M22 hardening | Workstream-40A (NR-BLOCK-1 / R4 Go implementation) + Workstream-40B-1 (FS-086 chaos design note) | #2 | GATE_PASS | `docs/proof/SPRINT40-S2-PROOF.md` (`cfc1450`) |

## Notes on reading this table

- An empty "Milestone target" cell (as in S39) means the sprint served no milestone rung at
  all — evidence/IP work, not capability work.
- "pre-M22 hardening" in the Milestone target column means the sprint served
  `HARDENING-PRE-M22` (see `serves_milestone` in the active Workstream docs) — work that de-risks
  the road to M22 without being a rung on the capability ladder itself.
- Workstream-40B-2 (KVM) is `CONFIRMED` but has not yet opened its own Workstream-local sprint 1; it
  will get a row here once its architecture spike closes.
- For "is M22 done," don't read this table alone — see `docs/FELN_SPRINT_PLAN.md` M22 gate
  criteria and the scope-distinction note in `docs/SPRINT_PLAN.md` (G1 wiring vs. G6
  capability are different scopes, both true statements about different things).
