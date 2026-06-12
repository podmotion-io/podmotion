# One-Time GitHub Repository Setup

Manual configuration a maintainer performs once for `github.com/podmotion-io/podmotion`.
The workflows in `.github/workflows/` depend on these settings.

## 1. Teams

Create two teams under the `podmotion-io` organization (**Org → Teams → New team**):

- **`maintainers`** — write access to the repo. Owns all paths via `CODEOWNERS`.
- **`security-reviewers`** — required reviewers for security-sensitive paths
  (`bpf/`, `internal/agent/`, `pkg/nri/`, `pkg/restore/`, `docs/legal/`).

Grant both teams at least **Write** access (**Repo → Settings → Collaborators and teams**).

## 2. Actions Permissions (packages: write)

The workflows push images and Helm charts to `ghcr.io/podmotion-io/`.

1. **Repo → Settings → Actions → General → Workflow permissions** — ensure workflows
   are allowed to request elevated scopes.
2. After the first image push, each package automatically appears under the org.
   **Package → Settings → Manage Actions access** → add the repository with **Write**
   role so `GITHUB_TOKEN` can push subsequent versions. Set package visibility to
   **Public**.

## 3. Branch Protection for `main`

**Repo → Settings → Branches → Add branch ruleset** (or classic branch protection):

- ☑ Require a pull request before merging
  - Require **1** approval (CODEOWNERS enforced; security paths require 2)
  - ☑ Require review from Code Owners
  - ☑ Dismiss stale approvals on new commits
- ☑ Require status checks to pass before merging
  - ☑ Require branches to be up to date
  - Required checks (from `ci.yaml`):
    - `Unit Tests (race)`
    - `golangci-lint`
    - `govulncheck`
    - `CRD / Codegen Drift Check`
    - `Helm Lint`
    - `Multi-Arch Build Validation` (all 8 matrix legs recommended)
- ☑ Require signed commits (recommended)
- ☑ Require linear history (recommended)
- ☑ Do not allow bypassing the above settings
- ☑ Restrict who can push to matching branches → `maintainers` only

## 4. Tag Protection

**Repo → Settings → Tags** (or a ruleset targeting `v*`): restrict tag creation to
`@podmotion-io/maintainers` so only maintainers can trigger the release workflow.

## 5. `production` Environment (release gate)

1. **Repo → Settings → Environments → New environment** → name it **`production`**.
2. ☑ **Required reviewers** → add `@podmotion-io/maintainers`.
3. Optionally restrict deployment branches/tags to pattern `v*.*.*`.
4. Add `environment: production` to the `build`, `helm`, and `github-release` jobs in
   `release.yaml` if you want a manual approval gate before each release. The committed
   workflow leaves this optional for fully automated releases.

## 6. Private Vulnerability Reporting

1. **Repo → Settings → Code security and analysis**
2. ☑ **Private vulnerability reporting**
3. ☑ **Dependabot alerts** and **Dependabot security updates**
4. ☑ **Dependency graph** (required for Dependabot and SBOM accuracy)

## 7. Cosign Keyless Signing

No secrets are required. Cosign keyless signing uses the workflow's GitHub OIDC token
(`id-token: write`, declared per job) and the public Fulcio/Rekor infrastructure.

Verify a signed image locally:

```bash
cosign verify \
  --certificate-identity-regexp \
    'https://github.com/podmotion-io/podmotion/.github/workflows/.*' \
  --certificate-oidc-issuer \
    https://token.actions.githubusercontent.com \
  ghcr.io/podmotion-io/operator:latest
```

## 8. GitHub Labels

Create these labels for the release notes categorizer (`.github/release.yml`) and
PR template:

| Label | Color | Description |
|-------|-------|-------------|
| `breaking` / `breaking-change` | `#B60205` | Breaking change |
| `enhancement` / `feature` | `#0075CA` | New feature |
| `bug` / `fix` | `#D73A4A` | Bug fix |
| `security` | `#E4E669` | Security fix |
| `dependencies` | `#0075CA` | Dependency update |
| `documentation` / `docs` | `#0075CA` | Docs |
| `infrastructure` / `ci` / `build` | `#E4E669` | CI/infra |
| `nightly-failure` | `#B60205` | Auto-created by nightly workflow |
| `ignore-for-release` | `#EDEDED` | Exclude from release notes |

## 9. Agent Build Trigger (programmatic)

Coding agents or external systems can trigger a build via the GitHub API:

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/podmotion-io/podmotion/dispatches \
  -d '{
    "event_type": "agent-build-request",
    "client_payload": {
      "image": "operator",
      "tag": "dev-feature-xyz",
      "reason": "Sprint M19 operator image for integration testing"
    }
  }'
```

Or via `workflow_dispatch` through the GitHub UI or API targeting
`.github/workflows/agent-build.yaml`.
