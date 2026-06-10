# PodMotion Milestone Reference

Definitive record of all milestones, their status, key deliverables, and dependencies.
Current version: **v0.1.0-alpha**

## Status legend

| Status | Meaning |
|--------|---------|
| ✅ Complete | All deliverables merged and testable |
| 🔨 In Progress | Active implementation underway |
| 🔲 Planned | Scoped but not started |

---

## M1 — CRDs, Node Image, Webhooks ✅ Complete

**Deliverables:**
- 5 CRDs: PodMigration, MigrationPolicy, NodeMigrationCapacity, MigrationCheckpoint, MigrationWebhookConfig
- kind node image with CRIU 4.2 + kernel 6.8 prerequisites
- AWS AMI scaffolding via image-builder Ansible role
- NFD NodeFeatureRule for `criu-capable` labeling
- ValidatingAdmissionWebhook (block unmigrateable pods)
- MutatingAdmissionWebhook (intercept evictions during migration)
- Compat prober stubs (cpu, memory, kernel feature checks)

**Dependencies:** None — bootstraps everything else.

---

## M2 — State Machine, Dry-Run, Rollback ✅ Complete

**Deliverables:**
- PodMigration 11-phase state machine (Pending → Complete / Failed → RollingBack)
- Dry-run estimation: dirty page sampling without pod impact
- Rollback pipeline: immutable order Network → Compute → Storage (ADR-0014)
- Eviction webhook interceptor (blocks eviction of actively-migrating pods)
- Leader election (3 replicas, coordination.k8s.io/v1 Lease)
- Completion timeout with auto-abort

**Dependencies:** M1 (CRDs must exist).

---

## M3 — Cold Migration Path, kubectl Plugin, E2E Fixtures ✅ Complete

**Deliverables:**
- Checkpoint controller with GC (MigrationCheckpoint CR lifecycle)
- CRIU interface + StubCheckpointer (go-criu RPC subprocess; ADR-0002)
- EndpointSlice traffic manager (add new endpoint before removing old; ADR-0012)
- TrafficVerified gate (source pod never deleted until verified; ADR-0012)
- kubectl podmotion plugin (migrate / status / cancel / describe / estimate)
- Ginkgo E2E test fixtures (kind cluster setup helpers)

**Dependencies:** M1, M2.

---

## M4 — gRPC Agent Server, mTLS, Phase Gate Wiring ✅ Complete

**Deliverables:**
- gRPC agent server on each node (ADR-0023)
- mTLS loader with cert-manager integration
- Client connection pool with per-node TLS certs
- NRI plugin stub (containerd Stopping hook → pre-dump trigger)
- Phase gate wiring: Node → Compute → Network → Storage cost-ordered evaluation (ADR-0016)
- Migration bandwidth throttling

**Dependencies:** M1, M2, M3.

---

## M5 — Iterative Pre-Copy Dirty-Page Sync ✅ Complete

**Deliverables:**
- Pre-copy loop: CRIU pre-dump rounds until dirty pages < threshold
- Convergence tracking: dirty page rate per round
- Abort-on-divergence policy for thrashing workloads (ADR-0024)
- Force-freeze after max rounds (bounded downtime guarantee)
- Destination pod pre-activation (warm, not yet live)
- MemorySynced gate signal to CutoverCoordinator
- NRI plugin integration (containerd Stopping hook)
- eBPF packet counter on new pod veth for traffic arrival detection

**Dependencies:** M3, M4.

---

## M6 — Storage Tier 0 + Tier 1, StorageReadyForFreeze Gate ✅ Complete

**Deliverables:**
- Tier 0: RWX volume re-attach (NFS, CephFS) — zero-copy path
- Tier 1: Longhorn dual-engine live migration
- StorageReadyForFreeze gate: storage reaches 95% sync before compute freeze (ADR-0011)
- PDB overlap-then-delete: both pods live simultaneously during migration (ADR-0015)

**Dependencies:** M4, M5.

---

## M7 — Storage Tier 2 + Tier 3, Node Fencing ✅ Complete

**Deliverables:**
- Tier 2: Ceph RBD live migration via `rbd migrate` (requires Squid 18.2+; ADR-0026)
- Tier 3: VolumeSnapshot → clone → rsync delta (for local PVs and AWS EBS)
- NodeFencingEmitter: stuck RWO volume event emission and recovery guidance

**Dependencies:** M6.

---

## M8 — Scheduler + Descheduler Plugins ✅ Complete

**Deliverables:**
- MigrationAwareFilter scheduler plugin (rejects nodes without CRIU capacity)
- MigrationAwareScore scheduler plugin (NUMA topology, thermal throttle scoring)
- Descheduler MigrationBalance plugin (emits PodMigration CRs instead of evictions; ADR-0025)

**Dependencies:** M1, M2.

---

## M9 — AWS ALB/NLB Integration, CNI IP Mobility ✅ Complete

**Deliverables:**
- CNI IP mobility: OVN-Kubernetes IPAMClaim / Whereabouts static IP preservation
- Gratuitous ARP + unsolicited NDP after restore
- BGP /32 host route withdrawal and re-advertisement
- AWS ALB target group registration + health check polling (ADR-0027)
- AWS NLB target group integration
- ALB connection draining before old target deregistration

**Dependencies:** M5, M6.

---

## M10 — eBPF Zero-Window Hold, XDP Bridge, TCP Repair ✅ Complete

**Deliverables:**
- eBPF TC egress zero-window hold (freeze TCP senders during cutover window; ADR-0028)
- XDP packet bridge via GENEVE tunnel (in-flight packets during IP handoff)
- TCP_REPAIR socket state export/import interfaces (full preservation v0.2; stubs v0.1; ADR-0017)
- TCP PAWS timestamp delta correction
- Envoy/Istio drain coordination
- NetworkBridgeArmed CR condition (gates cutover; ADR-0028)
- bpfman DaemonSet for eBPF program lifecycle management

**Dependencies:** M9.

---

## M11 — Security Hardening ✅ Complete

**Deliverables:**
- Seccomp profile swap: Unconfined scoped only to checkpoint window (ADR-0009)
- Checkpoint OCI image encryption (cosign/ECDH; opt-in per MigrationPolicy; ADR-0029)
- Node-scoped projected ServiceAccountToken (least-privilege agent identity)
- mTLS cert rotation automation

**Dependencies:** M4.

---

## M12 — Observability, MigrationPolicy Controller, Audit ✅ Complete

**Deliverables:**
- Prometheus metrics: histograms not summaries (ADR-0030); migration_duration_seconds, freeze_window_seconds, dirty_page_bytes, etc.
- Grafana dashboard (per-migration timeline, cluster health overview)
- MigrationPolicy controller: trigger evaluation (node pressure, custom PromQL)
- Migration window enforcement (allowedCron / blockedCron)
- Audit logger for full migration lifecycle events
- Prometheus metrics-based traffic verification (PromQL hook)
- Custom webhook verification hook (escape hatch)

**Dependencies:** M3, M5, M9.

---

## M13 — Post-Copy / Lazy-Pages Mode ✅ Complete

**Deliverables:**
- CRIU userfaultfd lazy-pages server integration (ADR-0031)
- Post-copy mode toggle in MigrationPolicy spec
- Lazy-pages server lifetime tied to restore phase (torn down on Complete/Failed)
- Convergence metrics for post-copy fault rates

**Dependencies:** M5, M10.

---

## M14 — Multi-Cluster Migration Foundation ✅ Complete

**Deliverables:**
- Cross-cluster PodMigration CRD extension (remote cluster ref fields)
- OCI registry as WAN transfer medium (ADR-0034)
- DirectP2P blocked cross-cluster (too many firewall assumptions)
- Remote cluster kubeconfig/credentials management
- Intra-cluster still primary path; multi-cluster as explicit opt-in (ADR-0022)

**Dependencies:** M4, M7, M12.

---

## M15 — GPU Workload Migration ✅ Complete

**Deliverables:**
- GPUMigration feature gate (permanently experimental; ADR-0032)
- NVIDIA CUDA context checkpoint/restore via CRIU CUDA plugin
- Driver version guard (>= 525 required)
- GPU device re-bind on destination node

**Dependencies:** M5, M11.

---

## M16 — StatefulSet-Aware Migration ✅ Complete

**Deliverables:**
- StatefulSet controller watches and creates PodMigration CRs in ordinal order
- Descending ordinal sequence (highest-index pod migrated first; ADR-0033)
- PVC follow-along: each pod's PVCs migrate with its pod
- Ordinal integrity preserved across rollback

**Dependencies:** M7, M8.

---

## M17 — Spot Instance Reclamation Automation ✅ Complete

**Deliverables:**
- IMDS poller: polls EC2 instance metadata for spot interruption notice (ADR-0035)
- SpotReclaimReconciler: 90-second lead time from notice to forced migration
- Automatic PodMigration CR creation for all migratable pods on reclaimed node
- Non-migratable pod warning events

**Dependencies:** M8, M12.

---

## M18 — Upstream Contributions + Release Scaffolding ✅ Complete

**Deliverables:**
- KEP draft: kubelet Restore API (companion to KEP-2008; WG Checkpoint/Restore)
- kubectl migrate upstream proposal (native subcommand fork)
- Upstream descheduler EvictPlugin PR guide
- OperatorHub / OLM bundle
- Helm chart release targets in Makefile
- Docusaurus versioned docs structure

**Dependencies:** M1–M17 (capstone milestone).

---

## Dependency Graph (summary)

```
M1 ──► M2 ──► M3 ──► M4 ──► M5 ──► M6 ──► M7 ──► M9 ──► M10 ──► M13
                │                    │       │
                └──► M8              └──► M11│
                                            └──► M12 ──► M14
                                                         M16 (M7+M8)
                                                         M17 (M8+M12)
                                                         M15 (M5+M11)
                                                         M18 (all)
```

---

## Version Roadmap

| Version | Milestones | Description |
|---------|-----------|-------------|
| v0.1.0-alpha | M1–M5, M8, M11 | Cold + iterative pre-copy; TIER_4 network (reconnect); no TCP preservation |
| v0.1.0 | M1–M12 | Full intra-cluster migration; eBPF network bridge; all storage tiers |
| v0.2.0 | M13, M15, M16, M17 | Post-copy, GPU, StatefulSet, spot automation; TCP_REPAIR preservation |
| v1.0.0 | M1–M18 | Production-ready; OperatorHub; upstream KEPs submitted |
| v1.x+ | Multi-cluster GA | M14 graduated from experimental |
