# PodMotion

**Live-migrate running pods. Move them across platforms entirely.** One
checkpoint/restore engine, two co-equal goals: live-migrate a running pod between
nodes with zero downtime — the container-native equivalent of live VM migration —
and move containers between hosting platforms and back, or restore from a full
backup.

Every container in the pod keeps running. Every client with an open TCP connection
stays connected: no RST, no reconnect, no retry. The application sees nothing. It
runs on stock Kubernetes and stock kernels, with no changes to the workload and no
changes to its clients.

---

## What it does

PodMotion is a Kubernetes operator built around a single checkpoint/restore engine
serving two goals:

1. **Live node-to-node migration (proven, the flagship capability).** A live pod
   moves between nodes while preserving in-memory process state and active network
   connections:
   - **Process state** is captured with CRIU 4.x iterative pre-copy checkpoint/restore,
     keeping the freeze window under ~100 ms.
   - **TCP connections** survive the move via TCP_REPAIR sequence-number preservation, an
     eBPF sequence-translation relay (PM_SEQ_XLAT), and a TCP zero-window hold that pauses
     senders on both endpoints across the critical handoff window.
   - **The whole pod** is checkpointed and restored atomically — every sidecar, init
     container, and service-mesh proxy — not just the primary container.

   Live TCP-connection survival is proven: a single held connection survived a
   migration byte-exact (seq_delta 0/0, Strict mode) at Sprint 46 on a real
   multi-node cluster. Broader multi-flow, multi-CNI coverage is not yet proven.

2. **Cross-platform portability and backup/restore (roadmap, not yet implemented).**
   The same checkpoint/restore foundation is architected to move containers between
   different hosting platforms and back — for example AWS ECS ↔ EC2/Docker, or
   EKS ↔ EC2 — and to take a full pod backup that's ready for restore. No code for
   this goal exists yet; it shares pillar 1's checkpoint/restore engine but has no
   implementation, migration path, or proof today.

Migration is driven as a first-class Kubernetes object with status conditions,
rollback, and observability, orchestrated by a controller-runtime operator, an
out-of-tree scheduler plugin, and a privileged per-node gRPC agent DaemonSet.

## Why it matters

Stateful workloads are the workload — databases, in-memory caches, message brokers,
long-running ML training jobs, transaction processors. "Redesign it to be stateless"
is not an answer when the application is PostgreSQL or a 68-hours-in training run.
At the VM layer, live migration made node maintenance, cost optimization, and failure
remediation routine. At the container layer the answer has been "drain the node and
accept the downtime." PodMotion closes that gap for node-to-node migration today, and
is architected to close the same gap across hosting platforms and for backup/restore
as that second pillar is built out.

See [`docs/why-podmotion.md`](docs/why-podmotion.md) for the full rationale.

## Architecture

A single migration walks a 12-phase state machine from `Pending` through
`PreCopyIterating`, `ZeroWindowArmed`, `Checkpointing`, `StorageMigrating`,
`DestinationStarting`, `RelayBridging`, and `TrafficVerifying` to `Succeeded`. The
source pod is deleted only after in-flight traffic has drained through the relay. Any
failure runs rollback in immutable order: Network → Compute → Storage.

The data model is five CRDs in the `migration.podmotion.io` API group: `PodMigration`
(the primary work object), `MigrationPolicy`, `NodeMigrationCapacity`,
`MigrationWebhookConfig`, and `CheckpointCatalog`.

For the full narrative, start with
[`docs/architecture-overview.md`](docs/architecture-overview.md).

## Documentation

| Document | Purpose |
|----------|---------|
| [`docs/why-podmotion.md`](docs/why-podmotion.md) | The case for live pod migration |
| [`docs/architecture-overview.md`](docs/architecture-overview.md) | Narrative entry point to the architecture and roadmap |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Milestone roadmap |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute |
| [`GOVERNANCE.md`](GOVERNANCE.md) | Project governance |
| [`SECURITY.md`](SECURITY.md) | Security policy and threat model |

## Status

PodMotion is under active development toward a beta release. Interfaces and CRD schemas
may still change. See [`docs/ROADMAP.md`](docs/ROADMAP.md) and
[`docs/FEATURES.md`](docs/FEATURES.md) for current capabilities.

## License

See [`LICENSE`](LICENSE). Third-party notices are in
[`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md) and [`NOTICE`](NOTICE).
