# PodMotion Architecture Overview

> **Start here.** This document is the narrative entry point for the 49+ ADR corpus,
> the 18-milestone roadmap, and the SIG/upstream engagement record. It does not replace
> individual ADRs — it tells you which ones to read first and how they fit together.
> Approved as a prerequisite for SIG credibility by the open-source readiness review (recommendation #7).

---

## What PodMotion Does

PodMotion is a Kubernetes operator that migrates a running pod from one node to another with
zero downtime — the container-native equivalent of live VM migration. It preserves in-memory
process state through CRIU 4.2 iterative pre-copy checkpoint/restore, maintains active TCP
connections through an eBPF sequence-translation relay (PM_SEQ_XLAT) combined with a
TCP zero-window hold that freezes senders across both endpoints during the critical handoff
window, and handles persistent volume cutover through a four-tier storage migration strategy
spanning RWX re-attach, Longhorn dual-engine live migration, Ceph RBD `rbd migrate`, and
snapshot-clone-rsync for local or block volumes — all orchestrated by a controller-runtime
operator, an out-of-tree scheduler plugin, and a privileged per-node gRPC agent DaemonSet
running on every cluster node.

---

## System Narrative

The following is a time-ordered walk through a single migration from CR creation to source
pod deletion.

| Step | Phase | What Happens |
|------|-------|--------------|
| 1 | `Pending` | A user, MigrationPolicy controller, or descheduler plugin submits a `PodMigration` CR targeting a specific pod. The operator picks it up and begins reconciliation. |
| 2 | `Scheduling` | The out-of-tree scheduler plugin evaluates `NodeMigrationCapacity` CRs, applies `MigrationPolicy` constraints, and annotates the CR with the selected destination node. |
| 3 | `PreCopyIterating` | The source node agent invokes CRIU pre-dump in a loop. Each round snapshots dirty pages to the `CheckpointCatalog` staging area. Iterations continue until dirty-page delta falls below the convergence threshold or the abort policy triggers (ADR-0024). The pod continues serving traffic throughout this phase. |
| 4 | `ZeroWindowArmed` | The eBPF TC egress program intercepts outbound TCP segments on both source and destination and injects zero-window advertisements, pausing new data from entering the TCP send buffer on all tracked connections (ADR-0049). The `NetworkBridgeArmed` condition is set (ADR-0028). |
| 5 | `Checkpointing` | With TCP senders paused, the source node agent performs the final CRIU full dump, capturing process memory, file descriptors, and TCP socket state (including sequence numbers via TCP_REPAIR). Freeze window target: < 100 ms. |
| 6 | `StorageMigrating` | The storage pipeline (running in parallel since `PreCopyIterating` per the two-pipeline model, ADR-0011) executes the tier-appropriate cutover: Tier 0 re-attach, Tier 1 Longhorn dual-engine, Tier 2 `rbd migrate`, or Tier 3 snapshot-clone-rsync. An explicit handoff gate ensures storage is ready before destination pod start. |
| 7 | `DestinationStarting` | The destination node agent restores the CRIU image via the out-of-kubelet containerd task API (ADR-0013). The container runtime re-creates the process tree with original PID mappings and re-attaches volumes. |
| 8 | `RelayBridging` | The eBPF PM_SEQ_XLAT relay on the source node intercepts in-flight TCP packets still arriving for the source pod's IP, rewrites sequence numbers, and forwards them through a GENEVE/VXLAN bridge to the destination pod's new socket. Connections that were mid-flight during the handoff window are transparently continued (ADR-0047). |
| 9 | `TrafficVerifying` | The relay monitors active connection count. When the count reaches parity (all connections have drained through the relay or completed), the zero-window hold is disarmed and the eBPF bridge is removed. The `TrafficVerified` condition is set (ADR-0012). |
| 10 | `CleaningUp` → `Succeeded` | Only after `TrafficVerified=True` is the source pod deleted (ADR-0040). The `CheckpointCatalog` CR is updated for GC. The `NodeMigrationCapacity` active-migration counter is decremented. The `PodMigration` CR enters `Succeeded`. If any step fails, the state machine enters `Failed` and the rollback sequence runs in immutable order: Network → Compute → Storage (ADR-0014). |

---

## Data Model

PodMotion's five CRDs represent every aspect of the migration lifecycle as first-class
Kubernetes objects, enabling auditable history, independent rollback, and GitOps compatibility.
See [ADR-0003](adr/0003-five-crd-data-model.md) for the full rationale.

| CRD | API Group | Scope | Role |
|-----|-----------|-------|------|
| `PodMigration` | `migration.podmotion.io` | Namespaced | Primary work object; drives the 12-phase state machine; one CR per migration operation |
| `MigrationPolicy` | `migration.podmotion.io` | Namespaced | Cluster-scoped trigger rules, scheduling constraints, and behavioral defaults for automated migration |
| `NodeMigrationCapacity` | `migration.podmotion.io` | Cluster | Per-node capability advertisement from the node agent; read by the scheduler plugin |
| `MigrationWebhookConfig` | `migration.podmotion.io` | Namespaced | Singleton operator configuration (registry endpoint, TLS settings, feature gate overrides) |
| `CheckpointCatalog` | `migration.podmotion.io` | Namespaced | CRIU image storage metadata and garbage-collection lifecycle tracking |

> **Note:** The fifth CRD is `CheckpointCatalog` (CRIU image metadata), not
> `MigrationCheckpoint` — the naming was finalized in the M19 CRD schema revision.

---

## 12-Phase State Machine

`PodMigration` traverses the following phases. Every transition writes a `metav1.Condition`
to the CR status before executing the transition action, making the state machine crash-safe
(ADR-0018). Rollback from any phase follows the immutable order Network → Compute → Storage
(ADR-0014).

| Phase | Description | Key Transition Condition |
|-------|-------------|--------------------------|
| `Pending` | CR created; operator has picked it up and queued reconciliation | Destination node annotation set by scheduler plugin |
| `Scheduling` | Scheduler plugin evaluates `NodeMigrationCapacity` and `MigrationPolicy`; selects destination node | `NodeMigrationCapacity.spec.availableSlots > 0` on chosen node |
| `PreCopyIterating` | CRIU pre-dump loop running; pod continues serving traffic; dirty-page delta tracked per round | Dirty-page delta < convergence threshold **or** abort-policy limit reached (ADR-0024) |
| `ZeroWindowArmed` | eBPF TC programs inject zero-window on source and destination sockets; new TCP data paused | `NetworkBridgeArmed` condition = True on both node agents (ADR-0028, ADR-0049) |
| `Checkpointing` | Final CRIU full dump with TCP_REPAIR socket export; target freeze ≤ 100 ms | CRIU dump exit code 0; checkpoint artifact written to `CheckpointCatalog` |
| `StorageMigrating` | Tier-appropriate storage cutover (ADR-0007, ADR-0011); runs in parallel since `PreCopyIterating` | Storage handoff gate condition = True; volume attached on destination node |
| `DestinationStarting` | Destination node agent restores CRIU image via containerd task API (ADR-0013); volumes re-attached | Container enter Running state; readiness probe passes |
| `RelayBridging` | eBPF PM_SEQ_XLAT relay bridges in-flight TCP connections through GENEVE/VXLAN tunnel (ADR-0047) | Active relayed connection count stabilizes (no new connections entering relay) |
| `TrafficVerifying` | Relay monitors connection parity; zero-window hold disarmed when count reaches equilibrium | `TrafficVerified` condition = True (ADR-0012) |
| `CleaningUp` | Source pod deleted; `CheckpointCatalog` updated for GC; `NodeMigrationCapacity` counter decremented | All cleanup finalizers removed |
| `Succeeded` | Terminal success state; `PodMigration` CR preserved for audit history | — |
| `Failed` | Terminal failure state; reached via `RollingBack` after any phase error; rollback order is immutable | Rollback complete: Network → Compute → Storage reversed (ADR-0014) |

---

## Three-Layer Agent Stack

PodMotion's runtime is structured as three concentric layers of responsibility:

### Layer 1 — Operator (Cluster Scope)

- **Runtime:** controller-runtime reconciler loop
- **Scope:** cluster-wide; watches all `PodMigration`, `MigrationPolicy`, `NodeMigrationCapacity`, `MigrationWebhookConfig`, and `CheckpointCatalog` CRs
- **Responsibilities:** phase state machine execution, inter-agent interface contract ownership (ADR-0008), gate runner orchestration (ADR-0016), ValidatingAdmissionWebhook and MutatingAdmissionWebhook enforcement, scheduler plugin CR annotation, PDB overlap-then-delete (ADR-0015)
- **Binaries:** `cmd/operator` (controller-manager + webhook server)

### Layer 2 — Node Agent (Per-Node DaemonSet)

- **Runtime:** privileged DaemonSet; one pod per node
- **Transport:** gRPC over mTLS (cert-manager-provisioned certificates; ADR-0023)
- **Responsibilities:** `NodeMigrationCapacity` CR advertisement, CRIU subprocess invocation via go-criu RPC, eBPF TC program lifecycle management (zero-window hold + PM_SEQ_XLAT relay), containerd task API restore, TCP_REPAIR socket export/import
- **Image:** distroless container; CRIU binary lives on the host node (ADR-0039) to avoid embedding GPLv2 in the container image
- **Binary:** `cmd/agent`

### Layer 3 — Sub-Agents (Goroutine-Level Specialists)

Goroutine packages called by the node agent, each owning a single concern:

| Sub-agent | Package | Concern |
|-----------|---------|---------|
| CRIU sub-agent | `internal/agent/criu` | go-criu subprocess wrapper; pre-dump loop; convergence accounting |
| Network/eBPF sub-agent | `internal/agent/network` | eBPF program load/unload; zero-window ARM/DISARM; PM_SEQ_XLAT relay map management |
| Storage sub-agent | `internal/agent/storage` | Tier detection; VolumeSnapshot trigger; rsync delta; Longhorn/Ceph API calls |

---

## ADR Map by Subsystem

| Subsystem | ADR Numbers | Summary |
|-----------|-------------|---------|
| Core data model | 0001, 0003, 0018 | Module path (github.com/podmotion-io); five-CRD model; crash-safe phase persistence via CR conditions |
| CRIU / checkpoint | 0002, 0006, 0013, 0024, 0031, 0042 | Subprocess firewall (GPLv2); dual transfer modes (P2P gRPC vs OCI registry); out-of-kubelet restore; convergence abort policy; post-copy lazy-pages server lifetime; CRIU opts for containerized workloads |
| Network / eBPF | 0011, 0012, 0014, 0017, 0021, 0028, 0036, 0041, 0047, 0048, 0049, **0093** | Two-pipeline model; TrafficVerified gate; immutable rollback order; TCP preservation deferred v0.2 (superseded by 0047); service mesh option; NetworkBridgeArmed condition; VPC CNI EKS gap; networkContinuity default false (superseded by 0047); TCP-first architecture; overlay-native L3 IP identity; zero-window hold ARM/DISARM atomicity; **M22 relay program architecture (PM_SEQ_XLAT, TC relay, SK_LOOKUP, VTEP programs)** |
| Storage | 0007, 0011, 0026, 0034, 0044 | Four-tier classification + webhook enforcement; two-pipeline handoff gate; Ceph RBD Squid requirement; OCI registry WAN medium for multi-cluster; cold migration beta scope / live storage migration v1.2 |
| Security | 0009, 0029 | Security agent veto power; checkpoint encryption opt-in |
| Scheduler | 0025 | Scheduler plugin creates `PodMigration` CR; operator never binds pods directly |
| GitOps | 0046 | GitOps-aware migration; operator detects and pauses reconciliation during active GitOps sync |
| OSS hygiene | 0004, 0020, 0038 | Own public repos over long-lived upstream branches; WG Checkpoint/Restore engagement + KEP-2008; ecosystem delta model |

ADRs marked **superseded**: 0017 (TCP deferred, replaced by 0047), 0041 (networkContinuity default false, replaced by 0047's TCP-first model).

---

## M22 Status Conditions — TCP Socket Preservation

M22 added four `metav1.Condition` entries to `PodMigration` status. These conditions track
the relay lifecycle and are evaluated by the `TCPVerifying` controller phase before the
source pod deletion gate fires.

| Condition | Type | Meaning when True |
|-----------|------|--------------------|
| `SocketInventoryComplete` | `metav1.Condition` | `SocketInventory()` parsed `/proc/<pid>/net/tcp[6]` for all ESTABLISHED connections in the container netns and populated `SeqSnapshots` on `CheckpointResponse`. Set immediately before `FinalFreeze`. Must be True before relay arm proceeds. |
| `RelayProgramsLoaded` | `metav1.Condition` | All six eBPF programs are attached: `PM_RELAY_TC_EGRESS`, `PM_RELAY_TC_INGRESS`, `PM_SK_LOOKUP`, `PM_XDP_VTEP`, `PM_XDP_SRC_GUARD`. Verified via `bpftool prog show` output and BPF map lookup. Set after `ArmRelay` + `ArmVTEP` return without error. |
| `ZeroWindowArmed` | `metav1.Condition` | The TC egress zero-window hold program is attached on the source veth. The peer's TCP send window is 0; no new data is entering the connection. This condition gates `FinalFreeze`: CRIU dump does not start until this is True (ADR-0049 §1). |
| `TCPSequenceContinuityVerified` | `metav1.Condition` | Post-restore `VerifyTCP` RPC confirmed that the destination socket's 4-tuple and seq/ack state match the source `SeqSnapshots` within ±MSS (1448 bytes) using 32-bit modular arithmetic. SQL/TCP application probes passed if configured. In `Strict` mode, False causes rollback. In `BestEffort` mode, False logs a warning and continues. |

**Source pod deletion gate** (ADR-0012 + ADR-0049):
The source pod is NOT deleted until BOTH of the following conditions are True:
- `TrafficVerified=True` (HTTP/endpoint readiness check)
- `TCPSequenceContinuityVerified=True` (for `Strict` and `BestEffort` modes)

For `NetworkContinuityMode=None`, TCP conditions are not required — the standard
`TrafficVerified` gate applies.

---

## Decision Audit Trail

- **Full ADR index** (all 50 ADRs, grouped and linked): [docs/adr/README.md](adr/README.md)
- **M19 architecture review** — reviewed and accepted, recorded in the ADR corpus.
- **Open-source readiness review** — readiness gate, recommendation #7 that required this document.

For the milestone delivery record and dependency chain, see [MILESTONES.md](MILESTONES.md).
