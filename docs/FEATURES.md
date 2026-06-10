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
| Cold migration (checkpoint → OCI image → restore) | M3 | 🔲 Planned | — | 0A, 1, 7 |
| Iterative pre-copy (multi-round dirty page convergence) | M5 | 🔲 Planned | — | 1 |
| Post-copy / lazy-pages mode | M13 | 🔲 Planned | — | 1 |
| Dry-run estimation (dirty page sampling, no pod impact) | M2 | 🔲 Planned | — | 0A, 1 |
| Rollback on failure (unfreeze source pod) | M2 | 🔲 Planned | — | 0A, 4 |
| Migration bandwidth throttling | M4 | 🔲 Planned | — | 7 |
| Completion timeout with auto-abort | M2 | 🔲 Planned | — | 0A, 4 |
| GPU workload migration (NVIDIA CUDA) | M15 | 🧪 Experimental | — | 1 |

---

## Network Continuity

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| CNI IP mobility (OVN-K IPAMClaim / Whereabouts) | M9 | 🔲 Planned | — | 2 |
| Gratuitous ARP / unsolicited NDP after restore | M9 | 🔲 Planned | — | 2 |
| BGP /32 host route withdrawal + re-advertisement | M9 | 🔲 Planned | — | 2 |
| eBPF zero-window hold (TC egress, freeze TCP senders) | M10 | 🔲 Planned | — | 2 |
| XDP packet bridge (GENEVE tunnel during cutover window) | M10 | 🔲 Planned | — | 2 |
| TCP_REPAIR socket state export/import | M10 | 🔲 Planned | — | 2 |
| TCP PAWS timestamp delta correction | M10 | 🔲 Planned | — | 2 |
| Envoy/Istio drain coordination | M10 | 🔲 Planned | — | 2 |

---

## Storage Migration

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| Tier 0: RWX re-attach (NFS, CephFS) | M6 | 🔲 Planned | ADR-0007 | 3 |
| Tier 1: Longhorn dual-engine live migration | M6 | 🔲 Planned | ADR-0007 | 3 |
| Tier 2: Ceph RBD live migration (rbd migrate) | M7 | 🔲 Planned | ADR-0007 | 3 |
| Tier 3: VolumeSnapshot → clone → rsync delta (local/EBS) | M7 | 🔲 Planned | ADR-0007 | 3 |
| Tier 4: Webhook block for unsupported volumes | M1 | 🔲 Planned | ADR-0007 | 4 |
| Node fencing event emission (stuck RWO) | M7 | 🔲 Planned | — | 3 |
| StatefulSet-aware ordinal PVC follow-along | M16 | 🔲 Planned | — | 3 |

---

## Orchestration and Policy

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| PodMigration CRD + state machine (11 phases) | M2 | 🔲 Planned | ADR-0003 | 4 |
| MigrationPolicy CRD + trigger evaluation | M2 | 🔲 Planned | ADR-0003 | 4, 5 |
| NodeMigrationCapacity CRD (agent capability advertisement) | M1 | 🔲 Planned | ADR-0003 | 4, 6 |
| MigrationCheckpoint CRD + GC | M3 | 🔲 Planned | ADR-0003 | 4 |
| ValidatingAdmissionWebhook (block unmigrateable pods) | M1 | 🔲 Planned | — | 4 |
| MutatingAdmissionWebhook (intercept evictions during migration) | M2 | 🔲 Planned | — | 4 |
| Leader election (3 replicas, coordination.k8s.io/v1 Lease) | M2 | 🔲 Planned | — | 4 |
| Migration window (allowedCron / blockedCron) | M12 | 🔲 Planned | — | 4 |
| Phase gate protocol (inter-agent ready signals via CR status) | M4 | 🔲 Planned | ADR-0008 | 0A |
| Multi-cluster migration | M14 | 🔲 Planned | — | 0A, 7 |
| Spot instance reclamation automation | M17 | 🔲 Planned | — | 0B, 4 |
| StatefulSet-aware ordinal migration ordering | M16 | 🔲 Planned | — | 0A, 3 |

---

## Scheduler and Descheduler

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| MigrationAwareFilter scheduler plugin | M8 | 🔲 Planned | — | 5 |
| MigrationAwareScore scheduler plugin | M8 | 🔲 Planned | — | 5 |
| Descheduler Balance plugin (creates PodMigration vs eviction) | M8 | 🔲 Planned | — | 5 |
| NUMA topology scoring | M8 | 🔲 Planned | — | 5 |
| Thermal throttle scoring | M8 | 🔲 Planned | — | 5 |

---

## Node Image and Infrastructure

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| kind node image (local dev/E2E) | M1 | 🔲 Planned | ADR-0005 | 6 |
| AWS AMI via image-builder (live PoC) | M1 | 🔲 Planned | ADR-0005 | 6 |
| Kernel config verification script | M1 | 🔲 Planned | — | 6 |
| NFD NodeFeatureRule (criu-capable node labeling) | M1 | 🔲 Planned | — | 6 |
| bpfman DaemonSet (eBPF program lifecycle) | M10 | 🔲 Planned | — | 6 |
| NRI plugin (containerd Stopping hook → pre-dump) | M5 | 🔲 Planned | — | 1, 6 |

---

## CLI

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| `kubectl podmotion migrate` | M3 | 🔲 Planned | — | 0A |
| `kubectl podmotion status` | M3 | 🔲 Planned | — | 0A |
| `kubectl podmotion cancel` | M3 | 🔲 Planned | — | 0A |
| `kubectl podmotion describe` | M3 | 🔲 Planned | — | 0A |
| `kubectl podmotion estimate` | M2 | 🔲 Planned | — | 0A, 1 |
| Native `kubectl migrate` (fork, upstream proposal) | M18 | 🔲 Planned | — | 0B |

---

## Security

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| Seccomp profile swap (Unconfined scoped to checkpoint window) | M11 | 🔲 Planned | ADR-0009 | 9, 1 |
| Checkpoint OCI image encryption (cosign/ECDH) | M11 | 🔲 Planned | ADR-0009 | 9 |
| mTLS between agents (cert-manager) | M4 | 🔲 Planned | — | 7, 9 |
| Node-scoped projected ServiceAccountToken | M11 | 🔲 Planned | — | 9 |
| Audit logging for migration lifecycle events | M12 | 🔲 Planned | — | 9 |

---

## Observability

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| Prometheus metrics (migration_duration_seconds histogram, etc.) | M12 | 🔲 Planned | — | 0A |
| Grafana dashboard (per-migration timeline, cluster health) | M12 | 🔲 Planned | — | 10 |
| Pre-copy round dirty page metrics | M5 | 🔲 Planned | — | 1 |
| TCP connections preserved counter | M10 | 🔲 Planned | — | 2 |

---

## Upstream Contributions

| Feature | Milestone | Status | ADR | Owning Agent |
|---------|-----------|--------|-----|--------------|
| KEP draft: kubelet Restore API (companion to KEP-2008) | M18 | 🔲 Planned | — | 0B, 10 |
| Upstream descheduler EvictPlugin PR | M18 | 🔲 Planned | — | 0B, 5 |
| OperatorHub bundle | M18 | 🔲 Planned | — | 10 |
