# PodMotion Official Sprint Plan — Post-M22 Gate, Path to M28 AWS Beta Gate

**Sprint Name:** NS5-Beta / M27 — "Every Container, Every Client, on AWS"
**Effective:** 2026-06-12
**Authority:** Synthesized from QA Lead + K8s OSS PM plans post-M22 gate (commit 5e76312, 14/14 gate passed); requires 2-Opus sign-off before any implementation agent begins
**Supersedes:** NS5-Alpha sprint plan; any milestone-specific sprint notes in `docs/sprints/`

---

## 1. Sprint Name and North-Star-Progress Statement

**Sprint:** NS5-Beta / M27 — "Every Container, Every Client, on AWS"

**North Star Progress:** M22 controller wiring passed 14/14 at gate r2 (commit `5e76312`, 2026-06-12). ADRs 0107–0110, ADR-0099 are all Accepted. `RPCNotWired` strings remain in test commentary only (`internal/controller/twelve_phase_test.go` lines 365, 437) and are not in production paths — G1 is satisfied. The M18.5 NS#4 spike proved `seq_delta=0` for one TCP flow, one container, one client, on a clean overlay. This sprint removes the two remaining Tier-0 engineering risks that stand between that single-flow proof and the north star guarantee:

1. **Multi-container CRIU consistent freeze/dump/restore (M22 core, G6)** — multi-container pods with shared netns/IPC/PID namespaces must all freeze atomically; any partial-freeze produces a corrupted migration artifact. `internal/agent/criu/multi_container_freeze.go` does not yet exist.
2. **Conntrack/NAT state survival through Service paths (M23 core, G7)** — client transparency through ClusterIP/NodePort/LB paths requires that conntrack entries (4-tuple + state + timeout) survive the node transition. `conntrack_export.go` and `conntrack_import.go` do not yet exist.

After G6 and G7 both pass, the M28 scored 80-run AWS gate is de-risked and executable. Until then, any full gate run is INVALID per the north star definition.

---

## 2. Blocking Dependencies — Must Complete Before Gate Runs Are Valid

The following are hard gates. No E2E or AWS gate run is adjudicated valid until all items are at the stated status.

### 2.1 M22 Controller Wiring (COMPLETE — commit 5e76312)

| Check | Status |
|-------|--------|
| `PrepareDestinationNetns` RPC wired | PASSED |
| `AddFDBEntry` / `ConfirmOverlayReady` RPC wired | PASSED |
| PM_SEQ_XLAT relay load confirmed | PASSED |
| `grep -rc "RPCNotWired" internal/controller/*.go` | Returns 0 (production paths clean) |

### 2.2 ADR Quorum Gate — Blocking ADRs Requiring Resolution This Sprint

**Already Accepted (no action needed):**

| ADR | Topic |
|-----|-------|
| ADR-0107 | Multi-Container CRIU Consistent-Freeze Ordering Contract |
| ADR-0108 | Conntrack Export/Import Protocol and Kernel State Migration Boundary |
| ADR-0109 | AWS EKS Routing Convergence Window and Pod IP Handoff Guarantee |
| ADR-0110 | AWS Gate Run Topology and Pass/Fail Adjudication |
| ADR-0099 | (see existing plan) |
| ADR-0047 | TCP-first migration architecture |
| ADR-0048 | Overlay-native L3 IP identity |
| ADR-0049 | Zero-window hold, relay ARM/DISARM atomicity |
| ADR-0095 | Scope Matrix |

**Must reach Accepted before M22 freeze/security work merges:**

| ADR | Current Status | Action Required |
|-----|---------------|-----------------|
| ADR-0077 / ADR-0103 | Proposed (naming conflict) | Deduplicate canonical file (0077 vs 0103); run 2-Opus + 5-CNCF quorum; mark Accepted. Blocks SBOM/signing work. |
| ADR-0084 | Proposed | Drive filesystem quiescence semantics (crash-consistent vs app-consistent) to Accepted. Blocks M22 SeccompGuard/quiescence implementation. |

**Must reach Accepted before M23 conversion-webhook merges:**

| ADR | Current Status | Action Required |
|-----|---------------|-----------------|
| ADR-0075 rev3 | Accepted (rev3 quorum NOT yet run) | Full 2-Opus-arch + 5-CNCF quorum on rev3 before conversion-webhook impl merges. |

**Must reach Accepted before M27 chaos gate runs:**

| ADR | Current Status | Action Required |
|-----|---------------|-----------------|
| ADR-0097 | FILE MISSING (OLD-0081 rejected) | Draft from scratch: 12-phase enum mapping for all 24 FaultScenario.Phase constants, dm-delay removal, ChaosSyncPoint signal transport spec. Quorum. Hard blocker for G8. |

**Non-blocking for M27 gate but required for M29 CNCF sandbox (8-week lead — start now):**

| ADR | Current Status | Action Required |
|-----|---------------|-----------------|
| ADR-0090 | Proposed | DCO vs CLA quorum run. Start during M22 work to hit 8-week lead. |

### 2.3 2-Opus Sign-Off

Two Opus-architect agents must review and sign off on this sprint plan and the ADR quorum state before any implementation agent begins. Sign-off must be recorded in `docs/adr/QUORUM_SIGNOFF_NS5_BETA.md`.

---

## 3. New ADRs to Author This Sprint

### 3.1 New ADRs (must reach Accepted before their gating milestone)

| ADR Slot | Title | Blocks |
|----------|-------|--------|
| ADR-0097 | Chaos Gate Revised — 12-phase enum mapping, tc netem replacement, ChaosSyncPoint protocol | G8, G10 |
| ADR-0022 (MVP) | Cross-org multi-cluster governance consent mechanism (minimum viable for AWS gate runs) | G9 multi-cluster topology |

### 3.2 ADRs to Revise This Sprint

| ADR | Action | Reason |
|-----|--------|--------|
| ADR-0077 / ADR-0103 | Deduplicate + quorum | Naming collision; both Proposed; must resolve before SBOM/signing impl merges. |
| ADR-0084 | Drive to Accepted | Filesystem quiescence semantics unresolved; blocks M22 freeze implementation. |
| ADR-0075 rev3 | Full quorum run | Rev3 quorum not yet scheduled; required before M23 conversion-webhook merges. |
| ADR-0090 | Quorum run (parallel, non-gating M27) | DCO vs CLA; 8-week lead for M29 CNCF sandbox. |

---

## 4. Dev Agent Roster

### Agent 1 — Multi-Container CRIU Consistent-Freeze Agent

**Role:** Implement atomic multi-container freeze/dump/restore per ADR-0107. Tier-0 prerequisite 1 for any valid gate run. Unblocks G6.

**Files to read:**
- `internal/controller/podmigration_controller.go`
- `internal/controller/twelve_phase_test.go` (lines 365, 437 — existing test commentary context)
- `internal/agent/criu/` (all files)
- `docs/adr/0107-*.md`
- `docs/adr/0084-*.md` (filesystem quiescence — must be Accepted before storage-quiescence code merges)
- `internal/api/v1/podmigration_types.go` (12-phase enum + condition types)
- `docs/NORTH_STAR_SPRINT_PLAN.md` §M22

**Files to produce:**
- `internal/agent/criu/multi_container_freeze.go` — atomic consistent-freeze per ADR-0107; freeze order: sidecar containers before main, main last-but-one relative to init, init last
- `internal/agent/criu/multi_container_freeze_test.go` — table-driven unit tests: `TestConsistentFreeze_N2_SharedNetns`, `TestConsistentFreeze_N3_SharedNetnsIPC`, `TestConsistentFreeze_PartialFailureRollback`, `TestConsistentFreeze_OrderingContract`; each sub-case labeled with ADR-0107 section reference

**Gate exit criterion (G6):**
```
go test -count=3 ./internal/agent/criu/... -run "TestConsistentFreeze"
```
Must return zero failures across all 3 sequential runs. Zero flakes.

---

### Agent 2 — Conntrack/NAT State Migration Agent

**Role:** Implement conntrack export at freeze and import at restore per ADR-0108, covering iptables and IPVS kube-proxy paths. Tier-0 prerequisite 2. Unblocks G7. Must not begin merge until ADR-0075 rev3 quorum completes.

**Files to read:**
- `internal/agent/network/` (all files, especially `conntrack.go`)
- `docs/adr/0049-*.md` (zero-window / PAWS / NOTRACK timing)
- `docs/adr/0108-*.md`
- `internal/api/v1/podmigration_types.go`
- `docs/NORTH_STAR_SPRINT_PLAN.md` §M23

**Files to produce:**
- `internal/agent/network/conntrack_export.go` — `ExportConntrackEntries(ctx, podIP string) ([]ConntrackEntry, error)` via `NFNL_SUBSYS_CTNETLINK`; filters by podIP; handles both iptables and IPVS kube-proxy modes (detect via `KUBE-IPVS-IN` chain presence)
- `internal/agent/network/conntrack_import.go` — `ImportConntrackEntries(ctx context.Context, entries []ConntrackEntry) error` via `IPCTNL_MSG_CT_NEW | NLM_F_CREATE | NLM_F_EXCL`; replace-on-collision semantics per ADR-0108 §4
- `internal/agent/network/conntrack_roundtrip_test.go` — unit tests: `TestExportConntrackEntries_IptablesPath`, `TestExportConntrackEntries_IPVSPath`, `TestExportConntrackEntries_EmptyTable`, `TestImportConntrackEntries_ReplaceOnCollision`; integration tests (`//go:build integration`): `TestConntrackRoundTrip_IptablesPath`, `TestConntrackRoundTrip_IPVSPath`

**Gate exit criterion (G7):**
```
go test -count=3 ./internal/agent/network/... -run "TestExportConntrack|TestImportConntrack|TestConntrackRoundTrip"
go test -tags integration -count=1 ./internal/agent/network/... -run "TestConntrackRoundTrip"
```
Zero failures; zero leaked conntrack entries across test runs (verified by `conntrack -L | grep <podIP>` before/after count).

---

### Agent 3 — Chaos Gate Agent

**Role:** Create the chaos test harness from scratch (directory does not exist) per ADR-0097. Unblocks G8 and G10. ADR-0097 must reach Accepted before any file in `test/chaos/` merges.

**Files to read:**
- `internal/api/v1/podmigration_types.go` (12-phase enum — canonical source for FaultScenario.Phase mapping)
- `docs/adr/0097-*.md` (once drafted and Accepted)
- `docs/NORTH_STAR_SPRINT_PLAN.md` §M27

**Files to produce:**
- `test/chaos/fault_scenarios.go` — `FaultScenario` struct; all 24 scenarios FS-001 through FS-024 mapped to 12-phase enum; FS-005 split → FS-005a/FS-005b; FS-019 split → FS-019a/FS-019b; `TestFaultScenarios_AllPhasesValidEnum` build-time assertion
- `test/chaos/chaos_sync.go` — `ChaosSyncPoint` type; `WaitForSyncPoint(ctx, point ChaosSyncPoint) error` via informer watching PodMigration CR conditions; no `time.Sleep` as sync mechanism
- `test/chaos/delay_inject.go` — `InjectNetworkDelay(ctx, iface, latencyMs, jitterMs int) error` via `tc qdisc add dev <iface> root netem delay`; no dm-delay; `TestDelayInject_AddsQdisc`
- `test/chaos/node_failure.go` — `InjectNodeFailure(ctx, nodeName string) error` via `pkill kubelet` only; `TestNodeFailure_KillsKubeletOnly`
- `test/chaos/invariants.go` — `AssertNorthStarInvariant(t, ringBufPath string)` (zero RST in eBPF ring buffer); `AssertRollbackComplete(t, cr *v1.PodMigration)` (sequence counter, not wall-clock); `AssertZeroWindowDisarmed(t, podIP string)` (iptables rule absent)
- `test/chaos/chaos_runner_test.go` (`//go:build chaos`) — Ginkgo Ordered suite; iterates all 24 FaultScenario entries; one fresh kind cluster per scenario; calls `WaitForSyncPoint` then fault injector; asserts all three invariants

**Gate exit criterion (G8, G10):**
```
go test -tags chaos -count=3 ./test/chaos/...
go test -count=1 ./test/chaos/... -run "TestFaultScenarios_AllPhasesValidEnum"
```
3 consecutive invocations return zero failures; eBPF ring buffer shows zero RST across all 24 fault scenarios; no legacy phase value or dm-delay reference in any file.

---

### Agent 4 — Multi-Container Rollback E2E Agent

**Role:** Author multi-container rollback E2E tests covering partial-freeze and conntrack-failure rollback paths. Depends on Agent 1 (G6) and Agent 2 (G7) passing. Unblocks chaos gate coverage for G6 + G8.

**Files to read:**
- `test/e2e/stateless_live_migration_test.go`
- `test/e2e/m25_wireguard_test.go`
- `test/chaos/invariants.go` (once authored by Agent 3)
- `internal/api/v1/podmigration_types.go`
- `docs/adr/0014-*.md` (rollback ordering: Network → Compute → Storage)
- `docs/adr/0012-*.md` (source pod not deleted until TrafficVerified=True)

**Files to produce:**
- `test/e2e/multi_container_rollback_test.go` — Ginkgo Ordered, labels `"multi-container"` + `"rollback"`:
  - `It("rolls back all containers when container-2 of 3 fails to dump")` — deploy 3-container pod; inject CRIU dump failure on container 2 via seccomp EPERM on ptrace; assert `MigrationFailed` reason `PartialFreezeFailure`; assert all 3 containers running on source with original pod name; assert no checkpoint artifact
  - `It("rolls back network state when conntrack import fails mid-flight")` — freeze all containers; inject conntrack import failure (netlink socket error); assert rollback unwinds in Network → Compute → Storage order; assert `AssertZeroWindowDisarmed` passes; assert source pod running
  - `It("does not delete source pod until TrafficVerified=True after rollback")` — assert source pod never in Terminating state until `TrafficVerified=True`; ADR-0012 enforcement on N=3 container pod

**Gate exit criterion:**
```
go test -count=1 ./test/e2e/... -run "MultiContainerRollback" --label-filter="multi-container"
grep -c "RPCNotWired" internal/controller/*.go   # must return 0 after test run
```
All 3 tests pass on kind with N=3 container pod; zero RST in eBPF ring buffer during rollback.

---

### Agent 5 — AWS Gate Harness Agent

**Role:** Build the AWS gate harness for M27 (first randomized gate run) and scaffold for M28 scored gate. No AWS gate run before G6 and G7 both pass. Dry-run test must pass without AWS credentials.

**Files to read:**
- `docs/NORTH_STAR_SPRINT_PLAN.md` §M27
- `docs/VALIDATION_AND_CERTIFICATION_PLAN.md`
- `docs/AWS_COST_PLAN.md`
- `docs/adr/0110-*.md` (AWS gate topology and adjudication)
- `docs/adr/0109-*.md` (EKS routing convergence window)

**Files to produce:**
- `test/aws/workload_matrix.go` — `WorkloadType` enum + `WorkloadSpec` struct; all 8 types: stateless-web, SQL-DB (PostgreSQL), Redis/KV, message-broker (NATS), gRPC-streaming, WebSocket-server, mixed-multi-container (N=3), long-running-compute; each spec includes container image, port, health check path, client load generator command, `seq_delta` assertion value (must be 0 for all types)
- `test/aws/gate_harness.go` — `RunGateRun(ctx, cfg GateConfig) (*RunReport, error)`: randomizes over AZ (≥2 per run), instance family (m7g/c7g Graviton arm64 + m7i/c7i x86-64), K8s version (N/N-1/N-2); provisions EKS + self-managed EC2 topologies; runs all 8 workload types; asserts `seq_delta == 0` and zero RST per workload; emits `RunReport` per ADR-0110
- `test/aws/run_report.go` — `RunReport` struct + `WriteReport(r *RunReport, path string) error`; report fields: run ID (UUID), timestamp, cluster topology, per-workload pass/fail, RST counts, seq_delta values, flakiness log path, overall pass/fail verdict; M28 80-run pass criterion recorded as comment
- `test/aws/gate_harness_test.go` — `TestGateHarness_DryRun` (`//go:build awsgate_dry`): stubs AWS provisioning; exercises randomization logic, workload matrix iteration, report generation, pass/fail adjudication; passes in CI without AWS credentials

**Gate exit criterion (G9):**
```
go test -tags awsgate_dry -count=1 ./test/aws/... -run "TestGateHarness_DryRun"
```
Dry-run passes without AWS credentials. For M27 full gate: one clean randomized AWS gate run across all 8 workload types; run report committed to repo; flakiness log committed for M28 hardening.

---

### Agent 6 — ADR Testability Hardening Agent

**Role:** Close ADR-0048 and ADR-0049 testability gaps. Non-blocking for M28 gate adjudication but must complete before any M28 gate run is declared valid. Parallel to Agents 1–5.

**Files to read:**
- `test/e2e/m21_overlay_netns_test.go`
- `test/e2e/zero_window_hold_test.go`
- `test/chaos/chaos_sync.go` (once authored by Agent 3)
- `docs/adr/0048-*.md`
- `docs/adr/0049-*.md`

**Files to produce:**
- `test/e2e/m21_overlay_netns_test.go` — add `TestOverlayIPReachabilityPrecedesNotrackArm`: assert `DestinationNetnsReady=True` is set and destination IP is ping-reachable from source node before `ArmConntrackNotrack` is called (timing invariant, not functional)
- `test/e2e/zero_window_hold_test.go` — add `TestNotrackArmedAtConditionE`: using `ChaosSyncPoint` infrastructure, assert `ArmConntrackNotrack` is called within one controller reconcile loop of condition E being satisfied

**Gate exit criterion:**
Both new tests pass on kind; tests exercise the relevant ADR invariant paths.

---

### Agent 7 — ADR Quorum and Sign-Off Agent

**Role:** Drive all blocking ADRs through quorum. Prerequisite gatekeeper — no implementation agent may merge gate-relevant PRs until this agent reports all required ADRs at Accepted status.

**Files to read:**
- `docs/adr/README.md`
- `docs/adr/GOVERNANCE.md`
- `docs/adr/0077-*.md` and `docs/adr/0103-*.md` (deduplication target)
- `docs/adr/0084-*.md`
- `docs/adr/0090-*.md`
- `docs/adr/0075-*.md`
- All ADR files listed in Section 2.2 and 3.1 of this plan

**Files to produce:**
- `docs/adr/0097-chaos-gate-revised.md` — ADR-0097 draft: 12-phase enum mapping for all 24 FaultScenario.Phase constants; dm-delay removal; ChaosSyncPoint signal transport; quorum record
- `docs/adr/QUORUM_SIGNOFF_NS5_BETA.md` — records 2-Opus sign-off + Accepted status for all blocking ADRs and new ADRs in this plan; lists ADR-0077/0103 deduplication resolution

**Gate exit criterion:**
`docs/adr/QUORUM_SIGNOFF_NS5_BETA.md` exists and lists ADR-0077 (canonical), ADR-0084, ADR-0097, and ADR-0075 rev3 all at Accepted, with 2-Opus sign-off. ADR-0090 quorum run started.

---

## 5. Sprint Gate Criteria

All criteria must pass before this sprint is declared complete. Any single fail blocks the sprint.

| # | Criterion | Pass Command / Check | Fail Condition |
|---|-----------|----------------------|----------------|
| G1 | M22 controller wiring (COMPLETE) | `grep -rc "RPCNotWired" internal/controller/*.go` == 0 | Any non-zero count in production paths |
| G2 | ADR-0077/0103 deduplication + Accepted | `QUORUM_SIGNOFF_NS5_BETA.md` lists canonical ADR-0077 at Accepted | Not Accepted or naming conflict unresolved |
| G3 | ADR-0084 Accepted | `QUORUM_SIGNOFF_NS5_BETA.md` lists ADR-0084 Accepted | Proposed or absent |
| G4 | ADR-0097 Accepted | `docs/adr/0097-chaos-gate-revised.md` exists with Status: Accepted | File missing or Proposed |
| G5 | ADR-0075 rev3 quorum complete | `QUORUM_SIGNOFF_NS5_BETA.md` records rev3 quorum completion | Quorum not run |
| G6 | Multi-container freeze unit tests | `go test -count=3 ./internal/agent/criu/... -run "TestConsistentFreeze"` — zero failures | Any failure or flake across 3 runs |
| G7 | Conntrack round-trip tests | `go test -count=3 ./internal/agent/network/... -run "TestExportConntrack\|TestImportConntrack\|TestConntrackRoundTrip"` — zero failures; zero leaked entries | Any failure or leaked conntrack entry |
| G8 | Chaos gate — 3 consecutive passes | `go test -tags chaos -count=3 ./test/chaos/...` — zero failures; eBPF ring buffer shows zero RST across all 24 fault scenarios | Any RST, assertion failure, or run abort |
| G9 | AWS gate run — M27 | One clean randomized gate run across all 8 workload types; run report + flakiness log committed | Run incomplete or any workload shows RST / seq_delta != 0 |
| G10 | ADR-0097 implementation correctness | All 24 FaultScenario.Phase values map to 12-phase enum; no dm-delay reference; `go test -count=1 ./test/chaos/... -run "TestFaultScenarios_AllPhasesValidEnum"` passes | Any unknown phase value, dm-delay reference, or test failure |
| G11 | AWS gate dry-run (no AWS credentials) | `go test -tags awsgate_dry -count=1 ./test/aws/... -run "TestGateHarness_DryRun"` passes in CI | Test fails or requires AWS credentials |
| G12 | Multi-container rollback E2E | `go test -count=1 ./test/e2e/... -run "MultiContainerRollback" --label-filter="multi-container"` — all 3 tests pass; zero RST | Any failure |
| G13 | ADR testability (ADR-0048 + ADR-0049) | `TestOverlayIPReachabilityPrecedesNotrackArm` and `TestNotrackArmedAtConditionE` pass | Either test fails |
| G14 | 2-Opus sign-off | `QUORUM_SIGNOFF_NS5_BETA.md` contains sign-off from two Opus-architect agents | Sign-off absent or fewer than 2 Opus agents |

---

## 6. Dependency Ordering Summary (DAG)

```
ADR-0077/0103 Accepted ─┐
ADR-0084 Accepted ───────┼──► M22 freeze impl (Agent 1) ──► G6 ──────────────────────┐
ADR-0075 rev3 quorum ────┘    M23 conntrack impl (Agent 2) ──► G7 ─────────────────── ┼──► M27 AWS gate (G9) ──► M28 (80 runs)
ADR-0097 Accepted ────────────────────────────────────────────────► chaos gate (G8) ──┘

Agent 3 (chaos harness) ── depends on ADR-0097 Accepted; parallel with Agents 1+2 impl
Agent 4 (rollback E2E) ─── depends on G6 + G7
Agent 5 (AWS harness) ──── dry-run independent; full gate run requires G6 + G7 + G8
Agent 6 (ADR testability) ─ depends on Agent 3 (ChaosSyncPoint); parallel otherwise
Agent 7 (ADR quorum) ────── starts immediately; gates all other agent merges

ADR-0090 quorum (parallel, non-blocking M27) ──────────────────────────────────────► M29 CNCF sandbox

After G9 (M27 clean gate run):
  M24 (CNI matrix) ────────────────────────────────────────────────────────────────► M28
  M25 (WireGuard/IPv6) ────────────────────────────────────────────────────────────► M28
  M26 (observability/CI) ──────────────────────────────────────────────────────────► M28

M27 green ──► M28 scored 80 runs ──► v1 API freeze ──► M29 (security audit + CNCF sandbox) ──► M30
```

---

## 7. Top Risks to M27

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| ADR-0077/0103 naming collision never formally clears | Medium | M22 SBOM/signing blocked indefinitely | Deduplicate immediately; do not allow both files to coexist with Proposed status |
| ADR-0084 Proposed — quorum surfaces design split (crash-consistent vs app-consistent) | Medium | M22 freeze implementation forks; rework cost | Resolve before any freeze code merges; treat as P0 for Agent 7 |
| ADR-0097 missing file — chaos gate (G8) has no ADR to implement against | High (file confirmed missing) | Hard blocker for M27 | Agent 7 must draft ADR-0097 as first action; chaos harness must not start until Accepted |
| ADR-0075 rev3 quorum not yet scheduled | Medium | M23 conversion-webhook blocked late-stage | Schedule immediately; do not allow M23 to start full impl without it |
| External security audit procurement — 8–12 week lead | High (no action yet) | Audit unavailable at M29 | Start procurement now, independent of gate status; assign Owner immediately |
| `test/chaos/`, `conntrack_export.go`, `conntrack_import.go`, multi-container freeze all absent | Confirmed | G6/G7/G8/G10 all blocked | Agents 1–3 are Tier-0 parallel work; begin immediately after 2-Opus sign-off |

---

## 8. What This Sprint Unblocks Toward the North Star

| Unblocked Item | Depends On | Opens |
|----------------|------------|-------|
| M28 scored 80-run AWS gate | G6 + G7 + G8 + G9 | Beta gate — the final pre-north-star milestone |
| CNI matrix expansion (Calico VXLAN / Cilium eBPF / Flannel) | G1 + G6 + G7 | M24 |
| IPv6 + encrypted overlay transparency | G9 + G10 | M25 |
| Observability + Scheduler/Descheduler E2E + CI matrix | G8 + G9 | M26 |
| CNCF sandbox application | ADR-0090 Accepted + M28 green | M29 |
| North star "COMPLETE" declaration | M28 scored gate green | Post-M28 |

**Critical path to north star:** M22 wiring (DONE, G1) → ADR-0084/0077 Accepted → multi-container consistent checkpoint (G6) → conntrack migration (G7) → ADR-0097 Accepted → chaos gate (G8) → first randomized AWS gate run (G9) → scored M28 gate (80 runs, zero errors) → v1 API freeze → external security audit → north star COMPLETE.

Until G6 and G7 both pass, no gate run — on any infrastructure — can demonstrate the north star guarantee. A single-container, single-flow result on kind does not count.
