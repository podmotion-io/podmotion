# PodMotion Governance

PodMotion is an open-source project on a CNCF-track trajectory. This document
describes how decisions are made and how the project is run. It is the
authoritative operational document for PodMotion governance.

---

## Mission

PodMotion enables live pod migration for Kubernetes — moving running containers
between nodes with zero downtime, preserving in-memory state, active TCP
connections, and persistent volumes. The project is vendor-neutral, Apache 2.0
licensed, and governed by its maintainer community.

---

## Roles

### Contributor

Anyone who submits an issue, pull request, review, or documentation improvement.
No formal status is required to contribute.

### Reviewer

A contributor promoted to Reviewer after meeting all of the following criteria:

- **≥ 5 non-trivial PRs merged** into any PodMotion repository.
- **Active for ≥ 60 calendar days** since first accepted contribution.
- Nominated by an existing maintainer via a `MaintainerNomination` issue.
- No veto from any maintainer within the **14-day** comment window.

Reviewers receive GitHub repository write access scoped to approving pull
requests (they do not have merge or release rights). They are listed in
`MAINTAINERS.md §Reviewers`.

### Maintainer

A Reviewer promoted to Maintainer after meeting all of the following criteria:

- **Holds Reviewer status for ≥ 90 calendar days.**
- **≥ 10 non-trivial PRs merged or substantively reviewed** during the Reviewer
  tenure.
- Demonstrated sound technical judgment, respectful collaboration, and
  adherence to project conventions.
- Nominated by an existing maintainer via a `MaintainerNomination` issue.
- Approved by **simple majority** of current maintainers (≥ 50 % + 1 vote).
- No veto from any maintainer within the **14-day** comment window.

Before accepting a nomination, the nominating maintainer must verify the
**Vendor Cap** rule (§Vendor-Cap below) is not violated.

Maintainers hold GitHub repository write access, merge PRs, cut releases,
steward the roadmap, and uphold this governance document. They are listed in
`MAINTAINERS.md §Maintainers` and are members of the `@podmotion-io/maintainers`
team.

---

## Maintainer Lifecycle

### Addition

1. Any existing maintainer opens a `MaintainerNomination` GitHub issue using the
   standard template, stating the nominee's name, GitHub handle, organization,
   proposed role (Reviewer or Maintainer), and evidence of criteria satisfaction.
2. The issue remains open for **14 calendar days**.
3. Maintainers vote by commenting `+1` (approve) or `-1` (veto with rationale).
   Silence after 14 days counts as `+1` (lazy consensus).
4. The nomination passes if no veto is received and ≥ 50 % + 1 of current
   maintainers have voted `+1`.
5. The nominating maintainer opens a PR updating `MAINTAINERS.md`; the PR
   references the nomination issue. The PR is merged after passing CI and
   receiving one additional maintainer approval (may be the nominating
   maintainer).

### Removal

Maintainers may be removed for:

- **Voluntary step-down:** the maintainer opens a PR removing their own entry
  from `MAINTAINERS.md §Maintainers` and moving it to `§Emeritus`.
- **Inactivity:** no review, comment, or commit for **6 consecutive calendar
  months** triggers an emeritus ping issue (labeled `maintainer-emeritus`).
  If the maintainer does not respond within **30 days**, any active maintainer
  may open a PR moving the inactive entry to `§Emeritus`.
- **Conduct:** a code-of-conduct violation per the CNCF CoC process. Removal
  requires a **simple majority vote** of remaining maintainers.

All removed maintainers are listed in `MAINTAINERS.md §Emeritus` with date of
transition.

### Tie-breaking

If a vote is deadlocked (equal `+1` and `-1` counts), a **30-day cooling-off
period** applies followed by a re-vote. Once a CNCF TOC liaison is assigned,
that liaison acts as a neutral tie-breaker on a deadlocked re-vote.

---

## Vendor Cap

No single company shall hold a permanent blocking majority (≥ 50 % of all
maintainer votes) on the PodMotion maintainer team once the project has **three
or more maintainers**.

Before admitting a new maintainer, the nominating maintainer must verify that
the nominee's organization's share of the maintainer team will remain below
50 %. If accepting the nomination would bring any one organization to ≥ 50 %,
the next maintainer admitted **must come from a different organization** before
the over-represented organization's nominee is admitted.

This rule is the authoritative operational constraint on maintainer-team
composition.

---

## Decision Making

Most decisions are made by **lazy consensus**: a proposal (issue, PR, or design
doc) is considered accepted if no maintainer objects within a **3-day comment
window**. Substantive proposals should be given the full window even if early
approvals arrive.

- **Lazy consensus** — silence is assent after 3 days.
- **Maintainer veto** — any maintainer may block a proposal with a clearly
  stated, good-faith technical reason. A veto must be resolved through
  discussion, not overruled unilaterally.
- **Formal vote** — for contested decisions, a **simple majority** of
  maintainers decides.

Significant technical decisions (architecture, security model, API compatibility
breaks, new subsystem adoption) are documented in the pull request that
introduces them, together with its design notes, and go through the standard
lazy-consensus window; acceptance requires no veto and ≥ 1 explicit maintainer
approval beyond the author.

---

## PR Merge Rules

- **Standard changes:** require **1 maintainer approval** and passing CI.
- **Security-sensitive paths** (`bpf/`, `internal/agent/`, `pkg/nri/`,
  `pkg/restore/`, `docs/legal/`): require **2 approvals**, at least one from a
  member of `@podmotion-io/security-reviewers`.
- Authors may not approve their own PRs.
- All required status checks must be green before merge.
- Each commit must carry a **Signed-off-by** trailer (`git commit -s`) per the
  project's Developer Certificate of Origin (DCO) policy.

---

## Release Cadence

- **Minor releases** roughly every 6–8 weeks, when meaningful features land.
- **Patch releases** as needed for bug and security fixes.
- Releases are cut from `main` by tagging `vX.Y.Z`, which triggers the release
  workflow automatically. The latest and previous minor lines receive security
  backports.

---

## Conflict Resolution

Disagreements are resolved through respectful discussion on the relevant issue
or PR. If consensus cannot be reached:

1. The maintainers discuss and seek compromise.
2. If still unresolved, a **simple majority vote** of maintainers decides.
3. Conduct-related concerns are handled per the CNCF Code of Conduct (§CoC
   below) and may be escalated to the CNCF.

---

## Code of Conduct

All participants are bound by the
[CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).
A standalone `CODE_OF_CONDUCT.md` at the repository root points to the same
document. Conduct concerns may be reported per the CNCF process described
in that document.

---

## Amendments

Changes to this governance document require:

1. A PR with the proposed change.
2. A **7-day** comment window (extended from the standard 3 days given the
   significance of governance changes).
3. Approval by **simple majority** of current maintainers with no veto.

---

## Current Maintainers

See `MAINTAINERS.md` for the canonical list of current maintainers, reviewers,
and emeritus members.

As of 2026-06-12, the project has **one maintainer** (single-organization,
single-committer status). A concrete diversity plan with named milestones and
outreach targets is maintained by the project. No CNCF sandbox application
will be filed until `MAINTAINERS.md` lists ≥ 2 maintainers from ≥ 2 distinct
organizations (M-GOV-3, target 2026-09-30).
