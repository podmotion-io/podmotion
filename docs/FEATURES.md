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

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| Cold migration (checkpoint → OCI image → restore) | M3 | ✅ Done | — | 0A, 1, 7 |
| Iterative pre-copy (multi-round dirty page convergence) | M5 | ✅ Done | ADR-0024 | 1 |
| Post-copy / lazy-pages mode | M13 | ✅ Done | ADR-0031 | 1 |
| Dry-run estimation (dirty page sampling, no pod impact) | M2 | ✅ Done | — | 0A, 1 |
| Rollback on failure (unfreeze source pod) | M2 | ✅ Done | ADR-0014 | 0A, 4 |
| Migration bandwidth throttling | M4 | ✅ Done | — | 7 |
| Completion timeout with auto-abort | M2 | ✅ Done | — | 0A, 4 |
| GPU workload migration (NVIDIA CUDA) | M15 | 🧪 Experimental | ADR-0032 | 1 | Requires `--feature-gates=GPUMigration=true`; driver >= 525 |

---

## Network Continuity

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| CNI IP mobility (OVN-K IPAMClaim / Whereabouts) | M9 | ✅ Done | — | 2 |
| Gratuitous ARP / unsolicited NDP after restore | M9 | ✅ Done | — | 2 |
| BGP /32 host route withdrawal + re-advertisement | M9 | ✅ Done | — | 2 |
| eBPF zero-window hold (TC egress, freeze TCP senders) | M10 | ✅ Done | ADR-0028 | 2 |
| XDP packet bridge (GENEVE tunnel during cutover window) | M10 | ✅ Done | ADR-0028 | 2 |
| TCP_REPAIR socket state export/import | M10 | ✅ Done | — | 2 |
| TCP PAWS timestamp delta correction | M10 | ✅ Done | — | 2 |
| Envoy/Istio drain coordination | M10 | ✅ Done | — | 2 |

---

## Storage Migration

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| Tier 0: RWX re-attach (NFS, CephFS) | M6 | ✅ Done | ADR-0007 | 3 |
| Tier 1: Longhorn dual-engine live migration | M6 | ✅ Done | ADR-0007 | 3 |
| Tier 2: Ceph RBD live migration (rbd migrate) | M7 | ✅ Done | ADR-0007, ADR-0026 | 3 |
| Tier 3: VolumeSnapshot → clone → rsync delta (local/EBS) | M7 | ✅ Done | ADR-0007 | 3 |
| Tier 4: Webhook block for unsupported volumes | M1 | ✅ Done | ADR-0007 | 4 |
| Node fencing event emission (stuck RWO) | M7 | ✅ Done | — | 3 |
| StatefulSet-aware ordinal PVC follow-along | M16 | ✅ Done | ADR-0033 | 3 |

---

## Orchestration and Policy

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| PodMigration CRD + state machine (11 phases) | M2 | ✅ Done | ADR-0003 | 4 |
| MigrationPolicy CRD + trigger evaluation | M2 | ✅ Done | ADR-0003 | 4, 5 |
| NodeMigrationCapacity CRD (agent capability advertisement) | M1 | ✅ Done | ADR-0003 | 4, 6 |
| MigrationCheckpoint CRD + GC | M3 | ✅ Done | ADR-0003 | 4 |
| ValidatingAdmissionWebhook (block unmigrateable pods) | M1 | ✅ Done | — | 4 |
| MutatingAdmissionWebhook (intercept evictions during migration) | M2 | ✅ Done | — | 4 |
| Leader election (3 replicas, coordination.k8s.io/v1 Lease) | M2 | ✅ Done | — | 4 |
| Migration window (allowedCron / blockedCron) | M12 | ✅ Done | — | 4 |
| Phase gate protocol (inter-agent ready signals via CR status) | M4 | ✅ Done | ADR-0008 | 0A |
| Multi-cluster migration | M14 | ✅ Done | ADR-0022, ADR-0034 | 0A, 7 |
| Spot instance reclamation automation | M17 | ✅ Done | ADR-0035 | 0B, 4 |
| StatefulSet-aware ordinal migration ordering | M16 | ✅ Done | ADR-0033 | 0A, 3 |

---

## Scheduler and Descheduler

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| MigrationAwareFilter scheduler plugin | M8 | ✅ Done | ADR-0025 | 5 |
| MigrationAwareScore scheduler plugin | M8 | ✅ Done | ADR-0025 | 5 |
| Descheduler Balance plugin (creates PodMigration vs eviction) | M8 | ✅ Done | ADR-0025 | 5 |
| NUMA topology scoring | M8 | ✅ Done | — | 5 |
| Thermal throttle scoring | M8 | ✅ Done | — | 5 |

---

## Node Image and Infrastructure

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| kind node image (local dev/E2E) | M1 | ✅ Done | ADR-0005 | 6 |
| AWS AMI via image-builder (live PoC) | M1 | ✅ Done | ADR-0005 | 6 |
| Kernel config verification script | M1 | ✅ Done | — | 6 |
| NFD NodeFeatureRule (criu-capable node labeling) | M1 | ✅ Done | — | 6 |
| bpfman DaemonSet (eBPF program lifecycle) | M10 | ✅ Done | — | 6 |
| NRI plugin (containerd Stopping hook → pre-dump) | M5 | ✅ Done | — | 1, 6 |

---

## CLI

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| `kubectl podmotion migrate` | M3 | ✅ Done | — | 0A |
| `kubectl podmotion status` | M3 | ✅ Done | — | 0A |
| `kubectl podmotion cancel` | M3 | ✅ Done | — | 0A |
| `kubectl podmotion describe` | M3 | ✅ Done | — | 0A |
| `kubectl podmotion estimate` | M2 | ✅ Done | — | 0A, 1 |
| Native `kubectl migrate` (fork, upstream proposal) | M18 | ✅ Done | — | 0B |

---

## Security

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| Seccomp profile swap (Unconfined scoped to checkpoint window) | M11 | ✅ Done | ADR-0009 | 9, 1 |
| Checkpoint OCI image encryption (cosign/ECDH) | M11 | ✅ Done | ADR-0009, ADR-0029 | 9 |
| mTLS between agents (cert-manager) | M4 | ✅ Done | ADR-0023 | 7, 9 |
| Node-scoped projected ServiceAccountToken | M11 | ✅ Done | — | 9 |
| Audit logging for migration lifecycle events | M12 | ✅ Done | — | 9 |

---

## Observability

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| Prometheus metrics (migration_duration_seconds histogram, etc.) | M12 | ✅ Done | ADR-0030 | 0A |
| Grafana dashboard (per-migration timeline, cluster health) | M12 | ✅ Done | — | 10 |
| Pre-copy round dirty page metrics | M5 | ✅ Done | — | 1 |
| TCP connections preserved counter | M10 | ✅ Done | — | 2 |

---

## Upstream Contributions

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| KEP draft: kubelet Restore API (companion to KEP-2008) | M18 | ✅ Done | — | 0B, 10 |
| Upstream descheduler EvictPlugin PR | M18 | ✅ Done | — | 0B, 5 |
| OperatorHub bundle | M18 | ✅ Done | — | 10 |

---

## Live Replication Pipeline (Agent 11)

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| Mirror stage: initial full pre-dump to destination | M5 | ✅ Done | — | 11, 1 |
| Iterative sync: incremental dirty page rounds | M5 | ✅ Done | — | 11, 1 |
| Convergence tracking: dirty page rate per round | M5 | ✅ Done | — | 11 |
| Abort-on-divergence: thrashing workload clean abort | M5 | ✅ Done | ADR-0024 | 11 |
| Destination pod pre-activation (warm, not yet live) | M5 | ✅ Done | — | 11 |
| MemorySynced handoff gate signal to CutoverCoordinator | M5 | ✅ Done | — | 11, 0A |
| Force-freeze after max rounds (bounded downtime guarantee) | M5 | ✅ Done | — | 11 |

---

## Traffic Drain and Verification (Agent 12)

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| EndpointSlice transition management (add new before removing old) | M3 | ✅ Done | ADR-0012 | 12 |
| TrafficVerified gate (blocks source pod deletion) | M3 | ✅ Done | ADR-0012 | 12, 0A |
| eBPF packet counter on new pod veth (traffic arrival detection) | M5 | ✅ Done | ADR-0012 | 12 |
| AWS ALB target group registration + health check polling | M9 | ✅ Done | ADR-0012, ADR-0027 | 12 |
| AWS NLB target group integration | M9 | ✅ Done | ADR-0012 | 12 |
| ALB connection draining before old target deregistration | M9 | ✅ Done | ADR-0012 | 12 |
| Prometheus metrics-based traffic verification (PromQL hook) | M12 | ✅ Done | ADR-0012 | 12 |
| Custom webhook verification hook (escape hatch) | M12 | ✅ Done | ADR-0012 | 12 |
| Rollback-on-no-traffic (timeout → clean rollback, source never deleted) | M3 | ✅ Done | ADR-0012 | 12, 0A |
| Old pod drain (stop new connections, let in-flight complete) | M3 | ✅ Done | ADR-0012 | 12 |
