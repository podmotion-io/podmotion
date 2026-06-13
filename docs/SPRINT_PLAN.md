# PodMotion Official Sprint Plan — Post-M22 Path to North Star

**Sprint Name:** NS5-Alpha / M27 — "Every Container, Every Client, on AWS"
**Effective:** 2026-06-12
**Authority:** Synthesized from QA Lead + K8s OSS PM plans; requires 2-Opus sign-off before execution begins
**Supersedes:** any milestone-specific sprint notes in `docs/sprints/`

---

## 1. Sprint Name and North-Star-Progress Statement

**Sprint:** NS5-Alpha / M27 — "Every Container, Every Client, on AWS"

**North Star Progress:** The M18.5 NS#4 spike proved `seq_delta=0` for one TCP flow, one container, one client, on a clean overlay — removing physics risk. This sprint removes the two remaining Tier-0 engineering risks that stand between that single-flow proof and the north star guarantee:

1. **Multi-container CRIU consistent freeze/dump/restore (M22 core)** — multi-container pods with shared netns/IPC/PID namespaces must all freeze atomically; any partial-freeze produces a corrupted migration artifact.
2. **Conntrack/NAT state survival through Service paths under load (M23 core)** — client transparency through ClusterIP/NodePort/LB paths requires that conntrack entries (4-tuple + state + timeout) survive the node transition; without this, any Service-routed client gets a RST.

After this sprint, the M28 scored 80-run AWS gate is de-risked and executable. Until then, any full gate run is INVALID per the north star definition.

---

## 2. Blocking Dependencies — Must Complete Before Sprint Work Begins

The following are hard gates. No milestone implementation or E2E gate opens until all items are at the stated status.

### 2.1 M22 Controller Wiring

| Check | Pass Criterion |
|-------|----------------|
| `PrepareDestinationNetns` RPC wired | Line 289 of `podmigration_controller.go` calls the live RPC, not a stub. |
| `AddFDBEntry` / `ConfirmOverlayReady` RPC wired | Line 527 of `podmigration_controller.go` calls live RPCs. |
| PM_SEQ_XLAT relay load confirmed | Relay is loaded and measured, not a placeholder log line. |
| Verification command | `grep -c "RPCNotWired"` returns 0 across the controller package. |

### 2.2 ADR Quorum Gate — All 12 BLOCKING Amendments at Accepted Status

These must clear quorum before any gate run. No exceptions.

**M22 group (9 ADRs):**

| ADR | Topic |
|-----|-------|
| ADR-0043 | Replace HTTP 429 with 409 Conflict; rate-limit logic to reconciler |
| ADR-0046 | Admission webhook `failurePolicy: Fail`; `timeoutSeconds <= 5`; NRI explicit failure |
| ADR-0003 | Immutability/status-subresource fields; ObservedGeneration; status via subresource only |
| ADR-0009 | Seccomp profile API path; max Unconfined window; rollback on failure; K8s Warning event |
| ADR-0039 | Threat model for agent hostPID + CAP_SYS_PTRACE; mitigations; kubectl exec blocked in prod |
| ADR-0029 | Checkpoint encryption DEFAULT in v0.1; opt-out requires explicit annotation + webhook enforcement |
| ADR-0048 | CNI spec compliance (ADD/DEL/CHECK/GC); FDB privilege model; IPAM double-allocation; Calico/Cilium scope |
| ADR-0051 | Flannel reconcile race window bounded; FDB grace period defined; LACP/bonding behavior specified |
| ADR-0015 | Remove "dry-run PDB token"; replace with positive PDB budget check at admission |

**M23 group (3 ADRs):**

| ADR | Topic |
|-----|-------|
| ADR-0026 | Block Tier 2 at webhook when Ceph version is Reef 18.x (hard block, not warning) |
| ADR-0007 | Tier 0 NFS/CephFS concurrent-writer safety handoff; Tier 3 local PV semantics |
| ADR-0044 | rsync must complete with --fsync; checksum verification before StorageCutoverComplete; storage rollback path |

### 2.3 Additional Pre-Sprint ADR Gates

| ADR | Requirement |
|-----|-------------|
| ADR-0095 (Scope Matrix) | Token case mismatch (`vxlan` vs `VXLAN`) fixed; `matchGlob` bug fixed; admission webhook enforces `failurePolicy: Fail`. Must be Accepted before any E2E gate run. |
| ADR-0075 rev3 | Conversion webhook deployed; CEL validation live. Must be Accepted before M23 conntrack work starts (API stability required for gate artifact preservation). |

### 2.4 2-Opus Sign-Off

Two Opus-architect agents must review and sign off on this sprint plan and the ADR quorum state before any implementation agent begins. Sign-off must be recorded in `docs/adr/QUORUM_SIGNOFF_NS5.md`.

---

## 3. New ADRs to Author This Sprint

### 3.1 ADRs to Author (New)

| ADR Slot | Title | Scope | Primary Reviewer Type |
|----------|-------|-------|-----------------------|
| ADR-0107 | Multi-Container CRIU Consistent-Freeze Ordering Contract | Normative freeze/dump/restore ordering for pods with shared netns, IPC, and PID namespaces; per-container in-flight state invariants; replaces ad-hoc ordering in ADR-0052. Specifies what constitutes an atomic checkpoint across N containers. | OSS Architect (correctness contract) |
| ADR-0108 | Conntrack Export/Import Protocol and Kernel State Migration Boundary | Exactly which conntrack entries (by 4-tuple + state + timeout) are exported at freeze, transferred, and imported at restore; NOTRACK arm timing contract relative to ADR-0049 condition E; covers both iptables and IPVS kube-proxy paths. | K8s OSS PM (protocol + compatibility scope) |
| ADR-0109 | AWS EKS Routing Convergence Window and Pod IP Handoff Guarantee | CNI route-advertisement latency window (0.5–3s) on EKS when a pod IP moves nodes; source-node redirect rule + destination-side confirmation probe that closes the blackhole; extends ADR-0102 WireGuard routing section to apply to all EKS CNIs. | K8s OSS PM (cloud CNI behavior) |
| ADR-NEW-AWS-GATE | AWS Gate Run Topology and Pass/Fail Adjudication | EKS + self-managed EC2 gate topology; randomization axes (AZ, instance family, K8s version N/N-1/N-2); workload matrix (all 8 types); pass/fail criteria for M27 gate runs vs. the scored M28 gate. | QA Lead (gate adjudication) |

### 3.2 ADRs to Revise This Sprint

| ADR | Action | Reason |
|-----|--------|--------|
| ADR-0097 (supersedes OLD-0081) | Revise + requorum | Re-map all 24 FaultScenario.Phase values to the current 12-phase TCP-first enum; replace dm-delay with tc-netem; split ambiguous recovery classes; specify ChaosSyncPoint signal transport. |
| ADR-0022 | Early draft (minimum viable for multi-cluster gate runs) | Cross-org multi-cluster governance consent mechanism must exist at MVP level before any multi-cluster AWS gate run; full version deferred to M29. |

---

## 4. Dev Agent Roster

### Agent 1 — Multi-Container CRIU Consistent-Freeze Agent

**Role:** Implement atomic multi-container freeze/dump/restore per ADR-0107. This is Tier-0 prerequisite 1 for any valid gate run.

**Files to read:**
- `internal/controller/podmigration_controller.go` (lines 250–350, 500–560)
- `internal/agent/criu/` (all files)
- `docs/adr/0052-*.md` (existing ordering — will be superseded)
- `docs/NORTH_STAR_SPRINT_PLAN.md` §M22
- `internal/api/v1/podmigration_types.go` (phase enum + condition types)

**Files to produce:**
- `internal/agent/criu/multi_container_freeze.go` — atomic consistent-freeze implementation
- `internal/agent/criu/multi_container_freeze_test.go` — unit + table-driven tests
- `internal/controller/podmigration_controller.go` — wire `PrepareDestinationNetns` at line 289; wire `AddFDBEntry`/`ConfirmOverlayReady` at line 527
- `docs/adr/0107-multi-container-criu-consistent-freeze-ordering.md` — ADR-0107 draft

**Gate exit criterion:** `grep -c "RPCNotWired"` returns 0 in controller package; unit tests for N=2 and N=3 container freeze pass.

---

### Agent 2 — Conntrack/NAT State Migration Agent

**Role:** Implement conntrack export at freeze and import at restore per ADR-0108, covering iptables and IPVS kube-proxy paths. This is Tier-0 prerequisite 2.

**Files to read:**
- `internal/agent/network/` (all files)
- `docs/adr/0049-*.md` (BPF zero-window / PAWS / NOTRACK timing)
- `docs/adr/0083-*.md` (kube-proxy iptables/IPVS NOTRACK interaction — draft)
- `docs/NORTH_STAR_SPRINT_PLAN.md` §M23
- `internal/api/v1/podmigration_types.go`

**Files to produce:**
- `internal/agent/network/conntrack_export.go` — conntrack export (4-tuple + state + timeout) at freeze
- `internal/agent/network/conntrack_import.go` — conntrack import at restore; NOTRACK arm timing gate
- `internal/agent/network/conntrack_test.go` — unit tests covering iptables path, IPVS path, empty-table path
- `docs/adr/0108-conntrack-export-import-protocol.md` — ADR-0108 draft

**Gate exit criterion:** conntrack round-trip test passes for both iptables and IPVS kube-proxy modes on kind; no entries leaked across test runs.

---

### Agent 3 — Chaos Gate Agent

**Role:** Correct the chaos test harness per ADR-0097 and run 3 consecutive clean passes.

**Files to read:**
- `test/chaos/` (all files)
- `docs/adr/0081-*.md` (OLD — will be superseded by ADR-0097)
- `internal/api/v1/podmigration_types.go` (12-phase enum)
- `docs/NORTH_STAR_SPRINT_PLAN.md` §M27 chaos work items

**Files to produce:**
- `test/chaos/fault_scenarios.go` — re-map all 24 FaultScenario.Phase constants to 12-phase enum; split FS-019 → FS-019a/b; split FS-005 → FS-005a/b
- `test/chaos/node_failure.go` — fix InjectNodeFailure to direct kubelet kill only (no dm-delay)
- `test/chaos/chaos_sync.go` — ChaosSyncPoint signal protocol implementation
- `test/chaos/invariants.go` — AssertNorthStarInvariant (zero RST in eBPF ring buffer); AssertRollbackComplete using sequence counter (not wall-clock); ZeroWindowDisarmed rollback invariant
- `test/chaos/delay_inject.go` — replace dm-delay with tc netem or loop device
- `docs/adr/0097-chaos-gate-revised.md` — ADR-0097 draft

**Gate exit criterion:** 3 consecutive clean chaos passes on freshly provisioned kind clusters; zero assertion failures; eBPF ring buffer shows zero RST across all 24 fault scenarios.

---

### Agent 4 — AWS Gate Harness Agent

**Role:** Build and run the first randomized AWS gate run for M27. Produce a reproducible run report and harden the harness for the scored M28 gate.

**Files to read:**
- `test/chaos/cluster_matrix.go`
- `test/chaos/validator.go`
- `scripts/beta-log-audit.sh`
- `docs/VALIDATION_AND_CERTIFICATION_PLAN.md`
- `docs/AWS_COST_PLAN.md`
- `docs/NORTH_STAR_SPRINT_PLAN.md` §M27

**Files to produce:**
- `test/aws/gate_harness.go` — randomized AWS gate run: EKS + self-managed EC2; instance families m7g/c7g (Graviton arm64) + m7i/c7i (x86-64); K8s versions N/N-1/N-2; all 8 beta-gate workload types
- `test/aws/workload_matrix.go` — workload matrix definition (stateless web, SQL DB, Redis/KV, message broker, gRPC streaming, WebSocket server, mixed multi-container, long-running compute)
- `test/aws/run_report.go` — reproducible run report generator
- `docs/adr/XXXX-aws-gate-run-topology.md` — ADR-NEW-AWS-GATE draft
- `docs/adr/0109-aws-eks-routing-convergence-window.md` — ADR-0109 draft

**Gate exit criterion:** one clean randomized AWS gate run completes across all 8 workload types; run report artifact produced and committed; flakiness log committed for M28 hardening.

---

### Agent 5 — ADR Quorum and Sign-Off Agent

**Role:** Drive all 12 blocking amendments and 4 new ADRs through quorum. Record sign-off. This agent is a prerequisite gatekeeper — no implementation agent should merge PRs until this agent reports all required ADRs at Accepted status.

**Files to read:**
- `docs/adr/README.md`
- `docs/adr/GOVERNANCE.md`
- All ADR files listed in Section 2.2 and 3.1 of this plan
- `docs/NORTH_STAR_SPRINT_PLAN.md` §2

**Files to produce:**
- `docs/adr/QUORUM_SIGNOFF_NS5.md` — records 2-Opus sign-off + ADR Accepted status for all 12 blocking amendments and 4 new ADRs
- Updated ADR files for each amendment brought to Accepted

**Gate exit criterion:** `docs/adr/QUORUM_SIGNOFF_NS5.md` exists and lists all 16 required ADRs (12 amendments + 4 new) as Accepted, with 2-Opus sign-off signatures.

---

## 5. Sprint Gate Criteria

All criteria must be pass before this sprint is declared complete. Any single fail blocks the sprint.

| # | Criterion | Pass | Fail |
|---|-----------|------|------|
| G1 | M22 controller wiring | `grep -c "RPCNotWired"` == 0 in controller package | Any non-zero count |
| G2 | ADR quorum — 12 blocking amendments | All 12 at Accepted in `QUORUM_SIGNOFF_NS5.md` | Any ADR not at Accepted |
| G3 | ADR quorum — 4 new ADRs | ADR-0107, ADR-0108, ADR-0109, ADR-NEW-AWS-GATE all at Accepted | Any ADR not at Accepted |
| G4 | ADR-0095 Scope Matrix | Token case fixed; `matchGlob` bug fixed; webhook enforces `failurePolicy: Fail` | Any open defect |
| G5 | ADR-0075 rev3 | Conversion webhook deployed and passing E2E smoke | Webhook absent or failing |
| G6 | Multi-container freeze unit tests | N=2 and N=3 container freeze pass with zero flakes across 3 runs | Any failure or flake |
| G7 | Conntrack round-trip | Conntrack export/import tests pass for iptables + IPVS on kind; zero leaked entries | Any failure |
| G8 | Chaos gate — 3 consecutive passes | 3 clean runs; eBPF ring buffer shows zero RST across all 24 fault scenarios | Any RST, assertion failure, or run abort |
| G9 | AWS gate run — M27 | One clean randomized gate run completes across all 8 workload types; run report committed | Run incomplete or any workload type shows RST / seq_delta != 0 |
| G10 | ADR-0097 revised | All 24 FaultScenario.Phase values mapped to 12-phase enum; dm-delay replaced; ChaosSyncPoint implemented | Any legacy phase value or dm-delay reference remaining |
| G11 | 2-Opus sign-off | `QUORUM_SIGNOFF_NS5.md` contains sign-off from two Opus-architect agents | Sign-off absent or from fewer than 2 Opus agents |

---

## 6. What This Sprint Unblocks Toward the North Star

Completing this sprint clears the last two Tier-0 physics risks and puts the project in position for the final pre-beta and beta phases:

| Unblocked Item | Depends On | Sprint That Opens |
|----------------|------------|-------------------|
| M28 scored 80-run AWS gate | G6 (multi-container) + G7 (conntrack) + G9 (AWS gate run) | M28 — the beta gate |
| CNI matrix expansion (Calico VXLAN / Cilium eBPF / Flannel) | G1 + G6 + G7 | M24 |
| IPv6 + encrypted overlay transparency | G9 + G10 | M25 |
| Observability + Scheduler/Descheduler E2E + CI matrix | G8 + G9 | M26 |
| North star "COMPLETE" declaration | M28 scored gate green | Post-M28 |

**Critical path to north star:** M22 wiring (this sprint, G1) → multi-container consistent checkpoint (G6) → conntrack migration (G7) → first AWS gate run (G9) → scored M28 gate (80 runs, zero errors) → v1 API freeze → external security audit → north star COMPLETE.

Until G6 and G7 both pass, no gate run — on any infrastructure — can demonstrate the north star guarantee. A single-container, single-flow result on kind does not count.
