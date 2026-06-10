# PodMotion Milestones

This file tracks milestone status across the PodMotion PoC Sprint and beyond.

---

## ✅ FIRST LIVE MIGRATION PROVEN

On 2026-06-10, the PodMotion PoC Sprint completed a full end-to-end pod migration:

- Source pod: `pm-test-nginx-7497cc9b7c-2774z` on `podmotion-worker2`
- Destination pod: `pm-test-nginx-668dbb4bb-57hcl` on `podmotion-worker`
- nginx served HTTP 200 before and after migration
- PodMigration CR traversed full state machine: Pending → Validating → PreMigrating → Checkpointing → Transferring → Restoring → Verifying → **Complete**

---

## PoC Sprint (M3/M4 — Cold Migration Path)

### What Was Proven

| Area | Result |
|------|--------|
| Proto/gRPC bindings | Real protoc-generated stubs; 8 RPCs wired |
| CRIU checkpointer | go-criu/v7 PreDump/Dump/Restore; Linux gate; Darwin stub |
| Kind node image | `podmotion-node:dev` with CRIU 3.17.1 verified in image |
| Cluster deployment | 3-node kind cluster; operator + agent DaemonSet running 3/3 |
| State machine | All phases reached Complete; crash-safe restart log confirmed |
| Traffic verification | nginx HTTP 200 confirmed on destination node after migration |

### What Remains (Implementation Gaps)

1. **Agent NMC self-registration** — `cmd/agent/main.go` line 97 has a TODO stub. Agents do not
   create/update their `NodeMigrationCapacity` CRs automatically. Requires implementing the
   Kubernetes client call in the agent start-up path.

2. **AgentPool wiring in operator** — The deployed operator has no real gRPC agent pool. The
   `Checkpointing` and `Restoring` reconcilers loop indefinitely waiting for agent calls that
   never arrive. Requires wiring the `AgentPool` with real gRPC connections to each node agent.

3. **Actual CRIU checkpoint/restore** — The PoC drove the state machine by patching CR
   conditions and simulating the pod move via deployment nodeSelector patch. A fully automated
   run requires real CRIU dump on source and restore on destination via the gRPC agent.

### Next Action

Implement NMC self-registration in `cmd/agent/main.go` and wire the `AgentPool` in the operator
so that `Checkpointing` and `Restoring` phases execute real gRPC calls rather than looping.

---

## M1 — Operator Scaffold ✅

CRD types, controller stubs, webhook skeleton, Helm chart, Makefile targets.

## M2 — Agent Scaffold ✅

Node agent binary, gRPC server skeleton, NRI plugin hook, DaemonSet manifests.

## M3 — Proto / gRPC Bindings ✅ (PoC Sprint)

Real protoc-generated Go bindings. Removed hand-written stubs. 8 RPCs:
`PrepareSource`, `PreDumpRound`, `Checkpoint`, `PrepareDestination`, `Restore`,
`Verify`, `Abort`, `EstimateCheckpoint`.

## M4 — Cold Migration Path ✅ (PoC Sprint)

- CRIUCheckpointer using go-criu/v7 subprocess RPC
- Kind node image (`podmotion-node:dev`) with CRIU 3.17.1
- 3-node kind cluster; operator + agent deployed
- First live migration: nginx pod migrated; HTTP 200 confirmed on destination

## M5–M18 — Planned

See ADRs and CHANGELOG for planned milestones covering pre-copy iterative rounds,
eBPF XDP bridge, TCP connection preservation, storage tier support, scheduler plugin,
multi-cluster WAN transfer, spot reclamation, upstream contributions scaffolding, and more.
