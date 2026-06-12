# PodMotion Governance

PodMotion is an open-source project on a CNCF-track trajectory. This document
describes how decisions are made and how the project is run. It is intentionally
lightweight and will evolve as the community grows.

## Roles

### Contributor
Anyone who submits an issue, pull request, review, or documentation improvement.
No formal status is required to contribute.

### Reviewer
A contributor with a track record of quality contributions who has been granted
review responsibility for one or more areas. Reviewers provide non-binding
approvals and help triage. Listed via `CODEOWNERS` where applicable.

### Maintainer
A reviewer trusted with write access and release responsibility. Maintainers
merge PRs, cut releases, steward the roadmap, and uphold this governance
document. Maintainers are members of the `@podmotion-io/maintainers` team.

## Decision Making

Most decisions are made by **lazy consensus**: a proposal (issue, PR, or design
doc) is considered accepted if no maintainer objects within a **3-day comment
window**. Substantive proposals should be given the full window even if early
approvals arrive.

- **Lazy consensus** — silence is assent after 3 days.
- **Maintainer veto** — any maintainer may block a proposal with a clearly
  stated, good-faith technical reason. A veto must be resolved through
  discussion, not overruled unilaterally.
- For contested decisions, a simple majority of maintainers decides.

## PR Merge Rules

- **Standard changes:** require **1 maintainer approval** and passing CI.
- **Security-sensitive paths** (`bpf/`, `internal/agent/`, `pkg/nri/`,
  `pkg/restore/`, `docs/legal/`): require **2 approvals**, at least one from a
  member of `@podmotion-io/security-reviewers`.
- Authors may not approve their own PRs.
- All required status checks must be green before merge.

## Release Cadence

- **Minor releases** roughly every 6–8 weeks, when meaningful features land.
- **Patch releases** as needed for bug and security fixes.
- Releases are cut from `main` by tagging `vX.Y.Z`, which triggers the release
  workflow automatically. The latest and previous minor lines receive security
  backports.

## Becoming a Maintainer

A reviewer may be nominated for maintainership by an existing maintainer after
demonstrating, over time:

- Sustained, high-quality contributions and reviews.
- Sound technical judgment and adherence to project conventions.
- Constructive, respectful collaboration.

Nomination is a PR adding the person to `@podmotion-io/maintainers`, approved by
lazy consensus of the existing maintainers (3-day window, no veto).

## Conflict Resolution

Disagreements are resolved through respectful discussion on the relevant issue
or PR. If consensus cannot be reached:

1. The maintainers discuss and seek compromise.
2. If still unresolved, a simple majority vote of maintainers decides.
3. Conduct-related concerns are handled per the project Code of Conduct and may
   be escalated to the CNCF.

## Code of Conduct

All participants are bound by the
[CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).
