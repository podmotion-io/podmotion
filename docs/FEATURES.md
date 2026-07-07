# PodMotion Feature Catalogue

Living catalogue of all planned and implemented features. Updated as features are designed, built, and released.

## Status legend

| Status | Meaning |
|--------|---------|
| 🔲 Planned | Defined, not started |
| 🔨 In Progress | Active development |
| ✅ Done | Merged and testable |
| 🧪 Experimental | Available but not production-ready |
| ❌ Blocked | Waiting on dependency or upstream |
| 💀 Rejected | Considered and explicitly not doing |

---

## Core Migration Engine

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| Cold migration (checkpoint → OCI image → restore) | M3 | ✅ Done | — |
| Iterative pre-copy (multi-round dirty page convergence) | M5 | ✅ Done | ADR-0024 |
| Post-copy / lazy-pages mode | M13 | ✅ Done | ADR-0031 |
| Dry-run estimation (dirty page sampling, no pod impact) | M2 | ✅ Done | — |
| Rollback on failure (unfreeze source pod) | M2 | ✅ Done | ADR-0014 |
| Migration bandwidth throttling | M4 | ✅ Done | — |
| Completion timeout with auto-abort | M2 | ✅ Done | — |
| GPU workload migration (NVIDIA CUDA; requires `--feature-gates=GPUMigration=true`, driver >= 525) | M15 | 🧪 Experimental | ADR-0032 |

---

## Network Continuity

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| CNI IP mobility (OVN-K IPAMClaim / Whereabouts) | M9 | ✅ Done | — |
| Gratuitous ARP / unsolicited NDP after restore | M9 | ✅ Done | — |
| BGP /32 host route withdrawal + re-advertisement | M9 | ✅ Done | — |
| eBPF zero-window hold (TC egress, freeze TCP senders) | M10 | ✅ Done | ADR-0028 |
| XDP packet bridge (GENEVE tunnel during cutover window) | M10 | ✅ Done | ADR-0028 |
| TCP_REPAIR socket state export/import | M10 | ✅ Done | — |
| TCP PAWS timestamp delta correction | M10 | ✅ Done | — |
| Envoy/Istio drain coordination | M10 | ✅ Done | — |

---

## Storage Migration

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| Tier 0: RWX re-attach (NFS, CephFS) | M6 | ✅ Done | ADR-0007 |
| Tier 1: Longhorn dual-engine live migration | M6 | ✅ Done | ADR-0007 |
| Tier 2: Ceph RBD live migration (rbd migrate) | M7 | ✅ Done | ADR-0007, ADR-0026 |
| Tier 3: VolumeSnapshot → clone → rsync delta (local/EBS) | M7 | ✅ Done | ADR-0007 |
| Tier 4: Webhook block for unsupported volumes | M1 | ✅ Done | ADR-0007 |
| Node fencing event emission (stuck RWO) | M7 | ✅ Done | — |
| StatefulSet-aware ordinal PVC follow-along | M16 | ✅ Done | ADR-0033 |

---

## Orchestration and Policy

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| PodMigration CRD + state machine (11 phases) | M2 | ✅ Done | ADR-0003 |
| MigrationPolicy CRD + trigger evaluation | M2 | ✅ Done | ADR-0003 |
| NodeMigrationCapacity CRD (agent capability advertisement) | M1 | ✅ Done | ADR-0003 |
| MigrationCheckpoint CRD + GC | M3 | ✅ Done | ADR-0003 |
| ValidatingAdmissionWebhook (block unmigrateable pods) | M1 | ✅ Done | — |
| MutatingAdmissionWebhook (intercept evictions during migration) | M2 | ✅ Done | — |
| Leader election (3 replicas, coordination.k8s.io/v1 Lease) | M2 | ✅ Done | — |
| Migration window (allowedCron / blockedCron) | M12 | ✅ Done | — |
| Phase gate protocol (component ready signals via CR status) | M4 | ✅ Done | ADR-0008 |
| Multi-cluster migration | M14 | ✅ Done | ADR-0022, ADR-0034 |
| Spot instance reclamation automation | M17 | ✅ Done | ADR-0035 |
| StatefulSet-aware ordinal migration ordering | M16 | ✅ Done | ADR-0033 |

---

## Scheduler and Descheduler

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| MigrationAwareFilter scheduler plugin | M8 | ✅ Done | ADR-0025 |
| MigrationAwareScore scheduler plugin | M8 | ✅ Done | ADR-0025 |
| Descheduler Balance plugin (creates PodMigration vs eviction) | M8 | ✅ Done | ADR-0025 |
| NUMA topology scoring | M8 | ✅ Done | — |
| Thermal throttle scoring | M8 | ✅ Done | — |

---

## Node Image and Infrastructure

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| kind node image (local dev/E2E) | M1 | ✅ Done | ADR-0005 |
| AWS AMI via image-builder (live PoC) | M1 | ✅ Done | ADR-0005 |
| Kernel config verification script | M1 | ✅ Done | — |
| NFD NodeFeatureRule (criu-capable node labeling) | M1 | ✅ Done | — |
| bpfman DaemonSet (eBPF program lifecycle) | M10 | ✅ Done | — |
| NRI plugin (containerd Stopping hook → pre-dump) | M5 | ✅ Done | — |

---

## CLI

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| `kubectl podmotion migrate` | M3 | ✅ Done | — |
| `kubectl podmotion status` | M3 | ✅ Done | — |
| `kubectl podmotion cancel` | M3 | ✅ Done | — |
| `kubectl podmotion describe` | M3 | ✅ Done | — |
| `kubectl podmotion estimate` | M2 | ✅ Done | — |
| Native `kubectl migrate` (fork, upstream proposal) | M18 | ✅ Done | — |

---

## Security

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| Seccomp profile swap (Unconfined scoped to checkpoint window) | M11 | ✅ Done | ADR-0009 |
| Checkpoint OCI image encryption (cosign/ECDH) | M11 | ✅ Done | ADR-0009, ADR-0029 |
| mTLS between agents (cert-manager) | M4 | ✅ Done | ADR-0023 |
| Node-scoped projected ServiceAccountToken | M11 | ✅ Done | — |
| Audit logging for migration lifecycle events | M12 | ✅ Done | — |

---

## Observability

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| Prometheus metrics (migration_duration_seconds histogram, etc.) | M12 | ✅ Done | ADR-0030 |
| Grafana dashboard (per-migration timeline, cluster health) | M12 | ✅ Done | — |
| Pre-copy round dirty page metrics | M5 | ✅ Done | — |
| TCP connections preserved counter | M10 | ✅ Done | — |

---

## Upstream Contributions

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| KEP draft: kubelet Restore API (companion to KEP-2008) | M18 | ✅ Done | — |
| Upstream descheduler EvictPlugin PR | M18 | ✅ Done | — |
| OperatorHub bundle | M18 | ✅ Done | — |

---

## Live Replication Pipeline

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| Mirror stage: initial full pre-dump to destination | M5 | ✅ Done | — |
| Iterative sync: incremental dirty page rounds | M5 | ✅ Done | — |
| Convergence tracking: dirty page rate per round | M5 | ✅ Done | — |
| Abort-on-divergence: thrashing workload clean abort | M5 | ✅ Done | ADR-0024 |
| Destination pod pre-activation (warm, not yet live) | M5 | ✅ Done | — |
| MemorySynced handoff gate signal to CutoverCoordinator | M5 | ✅ Done | — |
| Force-freeze after max rounds (bounded downtime guarantee) | M5 | ✅ Done | — |

---

## Traffic Drain and Verification

| Feature | Milestone | Status | ADR |
|---------|-----------|--------|-----|
| EndpointSlice transition management (add new before removing old) | M3 | ✅ Done | ADR-0012 |
| TrafficVerified gate (blocks source pod deletion) | M3 | ✅ Done | ADR-0012 |
| eBPF packet counter on new pod veth (traffic arrival detection) | M5 | ✅ Done | ADR-0012 |
| AWS ALB target group registration + health check polling | M9 | ✅ Done | ADR-0012, ADR-0027 |
| AWS NLB target group integration | M9 | ✅ Done | ADR-0012 |
| ALB connection draining before old target deregistration | M9 | ✅ Done | ADR-0012 |
| Prometheus metrics-based traffic verification (PromQL hook) | M12 | ✅ Done | ADR-0012 |
| Custom webhook verification hook (escape hatch) | M12 | ✅ Done | ADR-0012 |
| Rollback-on-no-traffic (timeout → clean rollback, source never deleted) | M3 | ✅ Done | ADR-0012 |
| Old pod drain (stop new connections, let in-flight complete) | M3 | ✅ Done | ADR-0012 |
