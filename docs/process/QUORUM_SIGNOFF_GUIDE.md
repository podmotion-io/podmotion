# Quorum Sign-off Guide

<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2024 The PodMotion Authors
-->

## Purpose

Sprint gate reviews exist to ensure that every increment of PodMotion code meets the bar for architectural correctness, dependency hygiene, and open-source quality before it reaches a broader audience of contributors and end users. PodMotion operates in a privileged Kubernetes context — it invokes CRIU as a subprocess, manipulates pod network namespaces via eBPF and netlink, and interacts with the Kubernetes API server with elevated RBAC permissions. A single structural error can silently corrupt live workloads or introduce a license incompatibility that poisons downstream consumers. The quorum sign-off process distributes review responsibility across specialized roles so that no single reviewer becomes a bottleneck and no domain — architecture, quality assurance, product intent, OSS compliance, or new-contributor experience — goes unexamined.

---

## Roles

| Role | Review Scope | Required |
|---|---|---|
| **Architecture Quorum** (×2, must be independent) | CRD shape, controller reconciliation logic, gRPC contracts, CRIU integration correctness, dependency graph, backward-compatibility commitments | Every gate |
| **QA** | CI matrix coverage, test case completeness, known flaky tests, integration test environment parity | Every gate |
| **Product Manager** | Acceptance criteria alignment, milestone scope creep, feature flag correctness, user-facing behavior | Every gate |
| **K8s OSS PM** | Upstream KEP alignment, API conventions (group/version/kind naming, status conditions), graduation criteria, community norms | Every gate |
| **CKAD New-Grad Reviewer** | Operator usability from a certified-but-new Kubernetes practitioner perspective; CRD schema clarity; runbook accessibility | M19.5 and later only |
| **K8s OSS Technical Writer** | Documentation completeness (CLAUDE.md, ADR statuses, runbooks, API reference), prose accuracy, onboarding path | M19.5 and later only |

Both Architecture Quorum seats must be filled by different individuals. If the same person holds both seats, the gate does not pass.

---

## Gate Initiation

The **sprint lead** (or, in their absence, the operator on-call) is responsible for triggering a gate review. Before opening a review the following artifacts must all be ready:

1. **Code merged to the sprint branch** — all feature commits rebased, no open draft PRs that are in scope for the gate.
2. **CI green** — every job in `.github/workflows/` passes on the sprint branch HEAD. A single red job blocks initiation unless the sprint lead documents the job as explicitly out-of-scope with a tracked issue.
3. **CLAUDE.md updated** — the milestone completion status, any new commands, and any changed CRD fields reflected.
4. **ADR statuses current** — every ADR in `docs/adr/` carries an up-to-date status header (`Accepted`, `Superseded`, `Deprecated`, or `Proposed`). No ADR may linger in `Proposed` if the decision has already been implemented.

To notify reviewers, the sprint lead opens a GitHub Discussion (or, for private forks, a Slack thread in `#podmotion-gates`) titled `[GATE] M<N> Sign-off Request — <YYYY-MM-DD>` and links:

- The sprint branch diff against `main`
- The CI run URL
- The draft `QUORUM_SIGNOFF_M<N>.md` record (see below)
- Any relevant ADRs or KEPs changed in this sprint

Each reviewer must acknowledge receipt within 24 hours or the sprint lead escalates per the Blocking and Escalation section.

---

## Review Process

Each reviewer evaluates their scope independently, without coordinating verdicts in advance. Independent evaluation is a hard requirement; reviewers must not wait for other verdicts before recording their own.

A reviewer records one of three statuses in the sign-off record:

| Status | Meaning |
|---|---|
| `APPROVED` | No issues. Gate may proceed once all required reviewers approve. |
| `APPROVED_WITH_CONDITIONS` | Minor issues that do not block the gate but must be addressed in the next sprint. Conditions must be specific and trackable (GitHub issue number or explicit description). |
| `BLOCKED` | Substantive defect that must be resolved before the gate passes. The blocking condition must be described precisely enough that the sprint lead can act on it without follow-up questions. |

Reviewers record their findings directly in the sign-off record file by opening a PR against the sprint branch that adds or updates their row in the Reviewers table. The PR description should include the rationale for any non-`APPROVED` status.

---

## Sign-off Record Format

### File naming

```
docs/QUORUM_SIGNOFF_M<N>.md
```

Where `<N>` is the milestone number, zero-padded to two digits for milestones below 10 (e.g., `QUORUM_SIGNOFF_M07.md`, `QUORUM_SIGNOFF_M19.md`).

### Required sections

```markdown
# Quorum Sign-off — Gate M<N>

## Gate

| Field | Value |
|---|---|
| Milestone | M<N> — <Milestone title> |
| Sprint branch | `sprint/m<n>` |
| CI run | <URL> |
| Initiated by | <GitHub handle> |

## Date

| Event | Timestamp (UTC) |
|---|---|
| Gate opened | YYYY-MM-DD HH:MM |
| Gate closed | YYYY-MM-DD HH:MM |

## Reviewers

| Role | Reviewer | Status | Conditions |
|---|---|---|---|
| Architecture Quorum (1) | @handle | APPROVED / BLOCKED / APPROVED_WITH_CONDITIONS | — or issue #N |
| Architecture Quorum (2) | @handle | | |
| QA | @handle | | |
| Product Manager | @handle | | |
| K8s OSS PM | @handle | | |
| CKAD New-Grad Reviewer | @handle or N/A (pre-M19.5) | | |
| K8s OSS Technical Writer | @handle or N/A (pre-M19.5) | | |

## Outcome

`PASSED` / `FAILED` / `IN PROGRESS`

State the final outcome in one sentence. If FAILED, list the blocking conditions that remain unresolved.

## Next Steps

Bulleted list of follow-on actions, assignees, and due dates.
```

### Canonical example

`docs/QUORUM_SIGNOFF_M19.md` is the canonical example for a fully completed record. Refer to it when uncertain about field formatting or the level of detail expected in conditions.

---

## Blocking and Escalation

**No partial passes.** The gate outcome is binary: `PASSED` (all required reviewers are `APPROVED` or `APPROVED_WITH_CONDITIONS`) or `FAILED` (any required reviewer is `BLOCKED` or has not responded).

**Resolving a block:** When a reviewer records `BLOCKED`, the sprint lead must:

1. Create or update a GitHub issue tracking the blocking condition, linked from the sign-off record.
2. Implement the fix on the sprint branch.
3. Re-request review from the blocking reviewer only, referencing the issue and the specific commit that addresses the condition.
4. The reviewer re-evaluates and updates their row to `APPROVED` or `APPROVED_WITH_CONDITIONS`.

Other reviewers do not need to re-review unless the fix materially changes the scope of their domain.

**Reviewer unavailability (>48 hours):** If a required reviewer has not acknowledged the gate request within 24 hours and has not responded to a direct mention within 48 hours, the sprint lead:

1. Posts a note in the sign-off record under a `## Delay Log` section documenting the reviewer, timestamp, and reason if known.
2. Notifies all other reviewers in the gate thread.
3. Escalates to the project maintainer group (`@podmotion-io/maintainers`) to designate a substitute reviewer.

The 48-hour clock resets when a substitute is confirmed. Substitutes are held to the same review standards as the original reviewer.

---

## Where Records Live

All `QUORUM_SIGNOFF_*.md` files are committed to `docs/` at the repository root level:

```
docs/
  QUORUM_SIGNOFF_M07.md
  QUORUM_SIGNOFF_M19.md
  QUORUM_SIGNOFF_M20.md
  ...
```

Do **not** nest sign-off records under `docs/sprints/` or any other subdirectory. The flat layout makes it possible to glob all records with `docs/QUORUM_SIGNOFF_*.md` and ensures they are indexed by documentation tooling without special configuration.

Sign-off records are considered permanent artifacts. Do not delete or force-push over them. If a gate is re-run after a failed outcome, create a new record with a suffix (e.g., `QUORUM_SIGNOFF_M19_R2.md`) rather than overwriting the original.
