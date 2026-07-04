# Changelog

> **Note:** this changelog is not maintained past early PoC sprints. For current status see `HANDOFF-LOG.md` and `docs/proof/DREX-STATE.yaml`.

All notable changes to PodMotion are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [v0.1.0-alpha] — 2026-06-09

### Added — M18: Upstream Contributions Scaffolding

- **KEP draft** (`docs/kep/kep-XXXX-kubelet-restore-api.md`): Full KEP-format proposal for a
  kubelet Restore API companion to KEP-2008.  Covers the
  `POST /checkpoint/{ns}/{pod}/{ctr}/restore` endpoint, `restoreFrom` PodSpec field, security
  model, test plan, and Alpha → GA graduation criteria.

- **OperatorHub bundle** (`bundle/`): OLM-compatible operator bundle including
  `ClusterServiceVersion`, channel annotations, and bundle `Dockerfile`.  Lists all five
  PodMotion CRDs as owned resources and declares webhook definitions.  Targets the `stable` and
  `alpha` channels.

- **kubectl migrate proposal** (`docs/kubectl-migrate-proposal.md`): Upstream proposal for a
  first-class `kubectl migrate` command.  Describes the plugin-first path, SIG-CLI proposal
  process, and the upstream `PodMigration` work object needed for Phase 3.

- **Descheduler upstream PR guide**
  (`descheduler/pkg/plugins/migrationbalance/UPSTREAM_PR.md`): Documents the interface changes
  (`Migrator` interface), feature-gating requirements, file changes, and upstream testing
  criteria needed to land `MigrationBalance` in `kubernetes-sigs/descheduler`.

- **Helm chart templates** (`charts/podmotion/templates/`): Complete set of Helm templates:
  - `serviceaccount.yaml` — operator and agent ServiceAccounts
  - `clusterrole.yaml` — manager and agent ClusterRoles
  - `clusterrolebinding.yaml` — bindings for both roles
  - `deployment.yaml` — operator Deployment with all flags, liveness/readiness probes
  - `daemonset.yaml` — agent DaemonSet with nodeSelector, tolerations, hostPID, volume mounts
  - `webhook.yaml` — cert-manager Certificate/Issuer, webhook Service, Validating/Mutating configs
  - `networkpolicy.yaml` — optional NetworkPolicy (enabled via `networkPolicy.enabled=true`)
  - `crds.yaml` — optional CRD installation (enabled via `installCRDs=true`)

- **Makefile targets**:
  - `make bundle` — generates OLM bundle from kustomize config
  - `make bundle-build` — builds bundle OCI image
  - `make bundle-push` — pushes bundle OCI image
  - `make release-manifests` — generates `dist/install.yaml` single-file install manifest

- **FEATURES.md**: M18 upstream contribution items marked Done.

### Dependencies

- No new Go dependencies (documentation and packaging milestone).
- OLM bundle format: `registry+v1` (Operator SDK v1.35.0 compatible).
- Helm chart: compatible with Helm 3.12+.

---

## Previous Milestones

| Milestone | Summary |
|---|---|
| M1 | CRDs, node image, compat prober, webhooks |
| M2 | State machine, dry-run estimation, rollback pipeline, eviction webhook |
| M3 | Checkpoint controller GC, CRIU interface (StubCheckpointer), traffic EndpointSlice, kubectl plugin, E2E fixtures |
