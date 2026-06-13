# PodMotion Pre-Production Checklist

**Source**: PREPROD_GAP_ANALYSIS.md + CNCF quorum review 2026-06-12
**Owner**: OSS Product Manager + Architecture quorum
**Gate**: ALL items in every section must be PASSED before beta promotion (M28).

Legend: `[ ]` Not Started · `[~]` In Progress · `[x]` PASSED · `[!]` BLOCKED

---

## Gap 1 — Supported Scope Matrix and Admission Enforcement

**ADR**: ADR-0077 (REJECTED — requires revision and re-review)
**Target milestone**: M22
**Gap analysis exit criterion**: Admission webhook hard-rejects unsupported mode/CNI/arch
combinations at CR creation time. Published support matrix in docs.

### Pre-conditions (must pass before ADR-0077 can be re-reviewed)

- [ ] Renumber scope-matrix ADR from 0077 to next available (≥0095); update all
      cross-references · Owner: [TBD] · M22
- [ ] Define normative `UnderlayType` enum; add normalization/case-fold in
      `resolveNodeContext`; map agent-reported tokens (`VXLAN`→`vxlan`, `Direct`→
      `host-gw`/`L3`) · Owner: Network Agent · M22
- [ ] Fix `CINCilium` → `CNICilium` typo in all matrix rows · Owner: [TBD] · M22
- [ ] Inject `RELEASE_SERIES` ldflag in all shipped artifact paths (PoC systemd
      binary, docker-build); define loud-WARN behavior for untagged builds ·
      Owner: Build Agent · M22
- [ ] Fix `matchGlob` to match `v1.0.x` patch strings against `"v1.0"` row pattern
      (use `"v1.0.*"` or dot-prefix matching) · Owner: [TBD] · M22
- [ ] Add `StorageTier` dimension to `ScopeMatrixEntry`; add Tier-4 unsupported row
      consistent with ADR-0007, or formally document storage as deferred with a
      named follow-on ADR · Owner: Storage Agent · M22
- [ ] State that `ValidatingAdmissionWebhook` MUST be deployed with
      `failurePolicy: Fail`; cross-reference ADR-0079 · Owner: [TBD] · M22

### Admission gate checks (automated, block on failure)

- [ ] `make test` includes `TestSupportMatrixReasonsPresent` — every `Unsupported`
      row has non-empty `Reason` · Owner: Testing Agent · M22
- [ ] Unit test `TestLookupSupportLevel` covers: each Unsupported row, no-match
      fallback, dev permissive fallback, BestEffort row, ARM64+Cilium,
      PostCopy+Strict+unknown CNI · Owner: Testing Agent · M22
- [ ] `make manifests && git diff --exit-code` passes in CI (no hand-edited RBAC or
      webhook YAML) · Owner: [TBD] · M22
- [ ] E2E: submit `PodMigration` with Cold mode → verify webhook rejects ·
      Owner: Testing Agent · M22
- [ ] E2E: submit `PodMigration` with Flannel VXLAN + TCPPreservationMode=Strict →
      verify webhook rejects · Owner: Testing Agent · M22

**Status**: `[ ]` Not Started

---

## Gap 2 — Controller Test Coverage Gate

**ADR**: ADR-0078 (REJECTED — requires revision and re-review)
**Target milestone**: M23
**Gap analysis exit criterion**: `podmigration_controller_test.go` replaced with
behavior tests covering all 12 phases × Success/Failure; compile-time drift
detection for condition vocabulary; 80% function coverage floor enforced in CI.

### Pre-conditions (must pass before ADR-0078 can be re-reviewed)

- [ ] Define `Reason*` Go constants in `api/v1alpha1/podmigration_types.go` for all
      condition Reasons in `conditions-vocabulary.md` · Owner: Operator Agent · M23
- [ ] Add `MigrationPhaseValidating` to `0078-phase-registry.yaml`
      `pipeline_12phase` block · Owner: [TBD] · M23
- [ ] Reconcile `pipeline_8phase` entry count (currently 6 entries) with the "8-phase"
      label — rename to `pipeline_6phase` or add the 2 missing phases · Owner: [TBD] · M23
- [ ] Define `podmotion.io/gc-requested=true` annotation constant in
      `api/v1alpha1/migrationcheckpoint_types.go` and implement reconciler logic that
      sets it on rollback · Owner: Operator Agent · M23
- [ ] Register `MigrationPhaseDryRunComplete` in the phase registry ·
      Owner: [TBD] · M23
- [ ] Decide fate of `twelve_phase_test.go`: explicitly state it does NOT satisfy
      coverage slots and is not counted by gate runner · Owner: Testing Agent · M23

### Coverage gate checks (automated, block on failure)

- [ ] `make test-coverage-gate` passes: all 12 phases have `Phase_Success` and
      `Phase_Failure` `It()` blocks in `podmigration_phase_test.go` ·
      Owner: Testing Agent · M23
- [ ] `make test-coverage-gate` enforces 80% function coverage on
      `podmigration_controller.go` (awk guard fails if file absent from report) ·
      Owner: Testing Agent · M23
- [ ] No test in `podmigration_phase_test.go` uses raw string literals for `condType`
      or `reason` arguments to `testutil.AssertCondition` (enforced by linter or
      typed wrapper types) · Owner: Testing Agent · M23
- [ ] `hack/verify-phase-registry` CI step diffs YAML registry against Go phase
      constants; fails if diverged · Owner: Testing Agent · M23
- [ ] Rollback slot `Rollback_ZeroWindowDisarmed` added and passing (ADR-0049 safety
      invariant: zero-window hold removed on all exit paths) · Owner: Network Agent · M23

**Status**: `[ ]` Not Started

---

## Gap 3 — E2E CI Matrix and Flake Budget

**ADR**: ADR-0079 (ACCEPTED 2026-06-12)
**Target milestone**: M26
**Gap analysis exit criterion**: Stable CI matrix, ≤2% flake budget, 10 consecutive
green runs required per required-tier cell, North Star invariant (`errsDuringMigration
== 0` in Phase 2 TCP_REPAIR) is release-blocking.

### Implementation tasks (owner-assigned, block M26 gate)

- [ ] Create `ci/matrix.yaml` with `schema_version: 1`; required tier: 2 kernels × 2
      CNIs × 2 storage backends × 2 K8s versions (16 cells) · Owner: Testing Agent · M26
- [ ] Implement `internal/ci/gate.go` with `GateResult`, `GateViolation`,
      `IsReleaseBlocking()` (fix typo: `IsReleaseBlocking` not `IsReleasBlocking`),
      `RequiredConsecutiveGreenRuns = 10`, `ClearanceWindowSize = 30` ·
      Owner: Testing Agent · M26
- [ ] Implement `internal/ci/flakedb.go` with `RunResult`, `FlakeRate(windowSize int)`
      returning 0 when `< windowSize` runs (document bootstrap gap explicitly) ·
      Owner: Testing Agent · M26
- [ ] Define cold-start policy: cells with `< 10` runs are `data-pending`, not
      `passing`, and block `ReadyForPromotion` · Owner: Testing Agent · M26
- [ ] Implement `check-release-gate.sh` reading `green-streaks.yaml`; fail-closed
      when YAML is malformed or absent · Owner: Testing Agent · M26
- [ ] Define write-serialization strategy for `green-streaks.yaml` under parallel
      matrix execution (per-cell NDJSON only; single aggregation job updates shared
      YAML after all cells report) · Owner: Testing Agent · M26
- [ ] Add `NorthStarRecoveryRuns = 3` constant and `TCPREPAIR_RECOVERY_STREAK_INSUFFICIENT`
      `GateViolation` code for Phase 2 live-tcprepair-traffic single-failure policy ·
      Owner: Testing Agent · M26
- [ ] Add `scripts/check-kernel-config.sh` validating 5 required `CONFIG_*` options ·
      Owner: Node Image Agent · M26
- [ ] Define retention policy for `ci/flake-db/*.ndjson` (e.g., keep last 100 runs
      per cell) to prevent unbounded repo growth · Owner: [TBD] · M26
- [ ] Pin exact versions + sha256 digests for all CNI images in `ci/matrix.yaml`
      (especially Cilium — direct kernel access) · Owner: Security Agent · M26
- [ ] Set quarantine approval to require a second approver for any
      release-blocking test (including `live-tcprepair-traffic`) ·
      Owner: [TBD] · M26

### CI gate checks (automated, release-blocking)

- [ ] All 16 required-tier cells: `current_streak ≥ 10` in `green-streaks.yaml` ·
      Owner: Testing Agent · M26
- [ ] Flake rate ≤ 2% across all required-tier cells (30-run window) ·
      Owner: Testing Agent · M26
- [ ] Phase 2 `live-tcprepair-traffic` test: `errsDuringMigration == 0` (hard
      block — any single failure blocks promotion until 3 consecutive passes; this
      supersedes the flake budget for this test) · Owner: Testing Agent · M26
- [ ] `make test-e2e` passes on all required-tier cells with `errsDuringMigration == 0`
      in HAProxy Phase 2 baseline · Owner: Testing Agent · M26
- [ ] Safety gate conditions False on required-tier cells at migration completion:
      `StorageReadyForFreeze`, `NetworkBridgeArmed`, `TrafficVerified` must not be
      False for a successful Complete-phase migration · Owner: Testing Agent · M26
- [ ] Freeze window: migration P99 freeze duration ≤ 100ms (WARN at >100ms, BLOCK
      at >500ms) · Owner: CRIU Agent · M26
- [ ] Extended-tier regressions escalate to release-blocking after 14 days (CI
      checks `regressions.yaml` expiry dates) · Owner: [TBD] · M27

**Status**: `[~]` In Progress (ADR accepted; implementation begins M26)

---

## Gap 4 — Security Hardening Baseline

**ADR**: ADR-0080 (REJECTED — requires architectural revision and re-review)
**Target milestone**: M22
**Gap analysis exit criterion**: Threat-model-driven secure-default baseline; RBAC
least-privilege verified; cert rotation tested; SBOM/signing/vuln-scan gate in CI.

### Pre-conditions (must pass before ADR-0080 can be re-reviewed)

- [ ] Renumber `0080-security-hardening-baseline.md` (away from collision with
      `0080-pm-cni-chained-plugin`) · Owner: [TBD] · M22
- [ ] Redesign `SeccompGuard`: patch the *agent container's* seccomp profile or use
      a node-level mechanism — not the target pod's immutable `securityContext` ·
      Owner: Security Agent · M22
- [ ] Resolve `allowPrivilegeEscalation` contradiction with ADR-0078: one
      authoritative decision with kernel-level evidence for CRIU parasite/ptrace path ·
      Owner: Security Agent + Opus quorum · M22
- [ ] Fix `pivot_root` seccomp contradiction: JSON allows it, prose denies it — pick
      one and document the rationale · Owner: Security Agent · M22
- [ ] Rescope §3 RBAC to defer to ADR-0078; rescope §4 webhook topology to defer to
      ADR-0079; rescope §5 supply chain to defer to ADR-0077 (CycloneDX, not SPDX) ·
      Owner: [TBD] · M22
- [ ] Specify seccomp profile distribution mechanism (Localhost profile must reach
      kubelet seccomp dir on each host node — Helm chart alone does not do this) ·
      Owner: Security Agent + Node Image Agent · M22

### Security gate checks (automated, block on failure)

- [ ] `make security-scan` (grype + CycloneDX SBOM per ADR-0077): no HIGH/CRITICAL
      unresolved findings · Owner: Security Agent · M22
- [ ] `make sbom` produces CycloneDX JSON for all 4 images (operator, agent,
      scheduler, checkpoint-gc) · Owner: [TBD] · M22
- [ ] All containers: `privileged: false`, `allowPrivilegeEscalation: false` (except
      agent — per resolved decision above), correct capability set · Owner: Security Agent · M22
- [ ] Helm template conformance test (polaris/kube-score): no privilege escalation,
      no `runAsRoot` except documented exceptions · Owner: Testing Agent · M23
- [ ] E2E: cert rotation completes; no gRPC disconnect > 5s · Owner: Security Agent · M22
- [ ] Kyverno/OPA policies enforcing privilege constraints deployed and active ·
      Owner: Security Agent · M23

**Status**: `[ ]` Not Started

---

## Gap 5 — Rollback and Crash-Safety Under Fault Injection

**ADR**: ADR-0094 (REJECTED — requires phase model rework and re-review)
**Target milestone**: M27
**Gap analysis exit criterion**: 24-scenario fault matrix with deterministic outcome
definitions; chaos suite passing 3 consecutive runs; ADR-0014 rollback ordering and
ADR-0018 crash-safe resume empirically verified.

### Pre-conditions (must pass before ADR-0094 can be re-reviewed)

- [ ] Re-map all 24 `FaultScenario.Phase` values from legacy 8-phase to 12-phase
      TCP-first constants (`ZeroWindowArm`, `FinalFreezeStateCapture`,
      `OverlayHandoff`, `RestoreSocketReattach`, etc.) · Owner: Testing Agent · M27
- [ ] Correct FS-010: source pod remains frozen (CRIU `--leave-stopped` + zero-window
      hold) throughout Transferring; outcome must include explicit rollback unfreeze ·
      Owner: Testing Agent · M27
- [ ] Fix `InjectNodeFailure`: remove cordon+drain; use direct kubelet kill (no
      graceful evacuation) · Owner: Testing Agent · M27
- [ ] Split FS-019 into FS-019a (Tier 3 PanicSafe) and FS-019b (Tier 2
      HumanRequired / `ErrRollbackPointOfNoReturn`) per ADR-0086 ·
      Owner: Storage Agent + Testing Agent · M27
- [ ] Replace `dm-delay` with a mechanism functional in standard kind clusters
      (overlayfs; no block device exposed) — e.g., `tc netem` or loop device in node
      image · Owner: Node Image Agent + Testing Agent · M27
- [ ] Split FS-005 dual `RecoveryClass` into FS-005a (PanicSafe) and FS-005b
      (HumanRequired after retry exhaustion) — `RecoveryClass` is a single enum ·
      Owner: Testing Agent · M27
- [ ] Specify `ChaosSyncPoint` signal transport protocol (what delivers the external
      signal: HTTP endpoint, Unix socket, in-process channel, etc.) ·
      Owner: Testing Agent · M27
- [ ] Fix `InjectEBPFMapFailure` to target a single node's agent pod (not full
      DaemonSet) · Owner: Testing Agent · M27

### Chaos gate checks (automated, block on M28 beta gate)

- [ ] All 24 fault scenarios: `RecoveryClass` exactly one enum value, non-empty ·
      Owner: Testing Agent · M27
- [ ] `make test-chaos` passes 3 consecutive runs on freshly provisioned kind cluster ·
      Owner: Testing Agent · M27
- [ ] `AssertRollbackComplete` passes: rollback condition timestamps verify
      Network < Compute < Storage ordering (ADR-0014) using sequence counter, not
      wall-clock (1s `metav1.Time` resolution) · Owner: Testing Agent · M27
- [ ] `AssertNorthStarInvariant` passes: eBPF ring buffer shows zero RST events
      during Phase 2 traffic under all 24 fault scenarios · Owner: Network Agent · M27
- [ ] `ZeroWindowDisarmed` rollback invariant verified on rollback path
      (ADR-0049 safety: hold removed on all exit paths) · Owner: Network Agent · M27
- [ ] `make chaos-report` produces per-scenario PASS/FAIL report with observed vs.
      declared `DeterministicOutcome` on failure · Owner: Testing Agent · M27

**Status**: `[ ]` Not Started

---

## Gap 6 — Release Hygiene and Operator Lifecycle

**ADR**: ADR-0082 (REJECTED — requires renumbering and targeted fixes)
**Target milestone**: M26
**Gap analysis exit criterion**: Single canonical deploy path enforced; CRD additive-only
invariants checked in CI; versioned webhook upgrade test passing; signed artifact
promotion pipeline with 30-day staging burn-in for minor releases.

### Pre-conditions (must pass before ADR-0082 can be re-reviewed)

- [ ] Renumber `0082-release-hygiene-and-operator-lifecycle.md` to next available ·
      Owner: [TBD] · M26
- [ ] Fix all chaos gate cross-references from `ADR-0081` → `ADR-0094` ·
      Owner: [TBD] · M26
- [ ] Add `deploy-crds` to canonical Makefile target table (§1a) with
      "rollback-only internal helper" note; or rename it outside the deploy namespace ·
      Owner: [TBD] · M26
- [ ] Replace `envtest.Environment` with real kind cluster handle in
      `webhook_versioned_test.go` (same pattern as `test/e2e/`) ·
      Owner: Testing Agent · M26
- [ ] Align SBOM format to CycloneDX JSON (defer to ADR-0077; remove SPDX 2.3
      specification) · Owner: [TBD] · M26
- [ ] Document Helm 3 CRD upgrade limitation: `helm upgrade` does not update CRDs;
      `make deploy` must pre-apply CRDs via `kubectl apply` before Helm invocation ·
      Owner: [TBD] · M26

### Release gate checks (automated + manual, all block promotion)

- [ ] `make crd-upgrade-check` passes: no required field additions, no field removal
      from served versions, no removal of CEL rules · Owner: [TBD] · M26
- [ ] `webhook_versioned_test.go` passes on real kind cluster: N-1 binary admits
      objects valid under N schema; N-1 forward-compat verified by confirming ≥1 request
      routed to N-1 pod · Owner: Testing Agent · M26
- [ ] `rollback_test.go` passes: N-only fields pruned after rollback; N-1 storage-state
      fields intact; no admission enforcement gap during rollback window ·
      Owner: Testing Agent · M26
- [ ] `make sbom` covers all 4 images (operator, agent, scheduler, checkpoint-gc) ·
      Owner: [TBD] · M26
- [ ] Cosign keyless signatures present for all 4 images; `cosign verify` passes ·
      Owner: [TBD] · M26
- [ ] SLSA L2 provenance attestation present; `cosign verify-attestation --type
      slsaprovenance` passes · Owner: [TBD] · M26
- [ ] 30-day staging burn-in completed (minor release) or 72-hour burn-in (patch
      release with explicit quorum classification) **[manual gate]** ·
      Owner: Release Manager · Per-release
- [ ] `scripts/promote-staging.sh` and `release.yml` CODEOWNERS-protected (requires
      2 quorum approvers) · Owner: [TBD] · M26
- [ ] `docs/compatibility-matrix.md` updated; `MaxKubernetesMinor` Go constant and
      matrix K8s-max column are in sync · Owner: [TBD] · Per-release

**Status**: `[ ]` Not Started

---

## Beta Promotion Gate Summary (M28)

All of the following must be `[x]` PASSED before beta tag is applied:

| Gate | ADR | Status |
|------|-----|--------|
| Supported scope matrix live; webhook rejects unsupported combos | 0077 (revision) | `[ ]` |
| Phase behavior tests cover all 12 phases × Success/Failure | 0078 (revision) | `[ ]` |
| 10 consecutive green runs across all 16 required-tier CI cells | **0079 (Accepted)** | `[ ]` |
| ≤2% flake rate across required-tier cells | **0079 (Accepted)** | `[ ]` |
| Phase 2 `errsDuringMigration == 0` (TCP_REPAIR) — release-blocking | **0079 (Accepted)** | `[ ]` |
| Security baseline: SBOM, signed artifacts, no HIGH/CRITICAL CVEs | 0080 (revision) | `[ ]` |
| 24-scenario chaos gate: 3 consecutive passes | 0094 (revision) | `[ ]` |
| CRD upgrade invariants, rollback test, signed artifact promotion | 0082 (revision) | `[ ]` |
| 30-day staging burn-in (no P0/P1 issues) | 0082 (revision) | `[ ]` |

**All rejected ADRs must be revised, re-reviewed, and accepted before their gate
checks can be treated as passing.**
