# NS#4 Revolutionary Plan: Live Stateful TCP Migration
**Status**: Approved — pending architecture quorum sign-off before M19 code begins  
**Date**: 2026-06-12  
**Author**: PodMotion 25-agent expert panel (6 phases, 1.07M tokens)

---

## North Star

**NS#4**: Live migration of a pod with active TCP connections to a PostgreSQL database (pgbench hammering, 8 concurrent connections, sustained TPS), cross-node (pm-worker → pm-control), **zero dropped connections**, sub-500ms freeze window, on stock Ubuntu 24.04 kernel 6.8, inside flannel VXLAN overlay — no cloud API calls in hot path.

---

## Unanimous Expert Panel Verdict

All 6 expert panels (kernel networking, container runtime, eBPF/XDP, database migration, cloud networking, VM migration) returned the same verdict: **refactor required**. The current code has two architectural blockers that make NS#4 categorically impossible without fixes:

### Blocker 1 — `--empty-ns net` destroys L3 identity before L4 can operate
**Location**: `internal/agent/server/server.go` ~L547–557 (NRI restore call)  
CRIU restore is invoked with `--empty-ns net`, which creates a brand-new netns with no IP assignment. By the time TCP_REPAIR would try to reattach sockets, the source pod IP (e.g., 10.244.1.5) no longer exists on any interface. The kernel refuses to bind a socket to an IP that isn't assigned to an interface — TCP preservation is categorically impossible.  
**Fix**: `--join-ns net:<dest_netns_fd>` with a pre-staged destination netns that already carries the source pod IP as a secondary address on a veth wired into the flannel overlay.

### Blocker 2 — `TcpEstablished` hardcoded false
**Location**: `internal/agent/criu/criu_checkpointer.go` ~L177  
`CheckpointRequest.tcp_established` is dead code. The CRIU dump always runs with `TcpClose=true`, which RSTs every TCP connection at checkpoint time. No TCP state is ever preserved.  
**Fix**: Drive `TcpEstablished` from `CheckpointRequest` tier (Strict → true, BestEffort → true, None → false/close).

---

## Winning Architecture: Phantom-First, Repair-Backed Hybrid

**Default tier**: eBPF seq-translation relay (`PM_SEQ_XLAT`)  
**Fidelity tier** (opt-in, custom kernel): `NETLINK_SOCKET_MIGRATE` out-of-tree module  

### How the relay tier works (stock kernel, cloud-deployable)

1. **SocketInventory** — enumerate all TCP sockets in source pod, classify per-port
2. **ZeroWindowArm** — TC-BPF egress program on source veth stalls sender (zero window advertisement, no drops)
3. **FinalFreeze + StateCapture** — CRIU `--tcp-established --leave-stopped` dumps seq/ack/ts at frozen instant
4. **OverlayHandoff** — inject RTM_NEWNEIGH FDB entry on flannel.1: source_pod_IP → dest_vtep_MAC; pm-cni chained plugin suppresses source DEL cleanup
5. **Restore + SocketReattach** — CRIU restores into pre-staged destination netns (source pod IP assigned); relay eBPF opens fresh sockets to each peer, seeds `PM_SEQ_XLAT` map with seq/ack deltas, translates all subsequent packets transparently
6. **DisengageHold** — remove zero-window BPF program from source; relay takes over traffic
7. **TCPVerifying** — SQL/gRPC/TCP probes (not HTTP-as-liveness); Strict mode hard-fails and rolls back on probe failure

### What IS available in cloud SDN (EC2/Azure/GCP)
- Full TCP stack inside guest kernel — all TCP_REPAIR, TC-BPF, XDP operations work
- VXLAN FDB manipulation on `flannel.1` — overlay-internal, cloud SDN cannot see or interfere
- `RTM_NEWNEIGH`/`RTM_DELNEIGH` on flannel.1 — safe inside the VM
- **NOT available**: gratuitous ARP to physical gateway, BGP /32 host route injection, cloud IPAM API calls in hot path

### Pre-staged destination netns (solves Blocker 1)
Before freeze, the destination agent:
1. Creates a new netns (`pm-migration-<uuid>`)
2. Creates a veth pair: one end in host netns (wired to flannel bridge or cni0), one end in migration netns
3. Assigns source pod IP (e.g., 10.244.1.5) as secondary address inside migration netns
4. Exports `dest_netns_fd` to the source agent via gRPC `PrepareDestinationNetns` RPC
5. CRIU restore uses `--join-ns net:<dest_netns_fd>` instead of `--empty-ns net`

---

## Sprint Sequence

### M18.5 — Throwaway Spike: NS#3.5-bare (PM recommendation: DO THIS FIRST)
**Duration**: 1 week  
**Goal**: Prove the relay concept works on one TCP connection with **sustained bidirectional in-flight traffic at freeze time** — hardcoded everything, no CRD changes, no clean proto. Manual `nsenter`, hand-loaded TC-BPF with hardcoded seq_delta, manually staged netns. If this doesn't work, the architecture needs revisiting before touching M19.  
**Exit criteria (ALL required)**:
1. Connection with active bidirectional traffic (e.g., continuous `nc` stream or app-level keepalive, NOT idle netcat) survives manual freeze/restore of its pod, no RST received
2. `tcpdump` on BOTH source and destination nodes confirms seq continuity in BOTH directions (egress AND return path)
3. Peer's return traffic (ACKs, server replies) routes correctly to the destination node (not dropped at source)
4. Connection with non-empty send buffer at freeze time (achieved by not draining before dump) produces a visible seq corruption — confirming that send-buffer-drain-before-dump is required (this is the negative test that proves the ADR-0049 sequencing constraint)

**Artifacts**: shell script, not production code. Throw it away after proof.

### M19 — Architecture Foundation (2–4 weeks)
**ADRs to approve before any code**: ADR-0047 (TCP-first), ADR-0048 (overlay-native L3), ADR-0049 (zero-window hold)  
**Amend**: ADR-0019 (verify: hard-fail + rollback for Strict TCP mode)

CRD refactor:
- Add `TCPPreservationMode: Strict | BestEffort | None`
- Add per-port `ConnectionClass` (Established | ShortLived | Ignore)
- Add `FreezeWindowBudgetMs` (default 500)
- Add `ApplicationProbeSpec` (SQL | HTTP | gRPC | TCP)
- Add 14 new status conditions (SocketInventoryComplete, ZeroWindowArmed, FDBEntryInjected, DestinationNetnsReady, SeqSnapshotCaptured, RelayArmed, TCPVerified, etc.)

State machine: 12-phase pipeline replacing 8-phase  
`SocketInventory → Validating → DestinationPrewarm → PreCopyMemory → ZeroWindowArm → FinalFreeze+StateCapture → OverlayHandoff → Restore+SocketReattach → DisengageHold → TCPVerifying → ServiceVerifying → Cutover+Complete`

Proto changes:
- Add `SeqSnapshot` message (4-tuple + seq + ack + ts_val + ts_ecr + wscale + sack_blocks)  
- Add `PrepareDestinationNetns` / `ExportTCPSockets` / `ImportTCPSockets` RPCs (relay tier only — defer kernel module interface until NS#4 proven)
- Add `dest_netns_fd` + `source_freeze_timestamp_ns` to `RestoreRequest`

Fix `criu_checkpointer.go:177`: drive `TcpEstablished` from tier  
Fix `server.go:547–557`: `--join-ns net:<dest_netns_fd>` replacing `--empty-ns net`  
Wire real `cilium/ebpf` loader as default (kernel ≥ 5.9); demote stub to opt-in  
Split `Verifying` → `TCPVerifier` + `ServiceVerifier`; `ApplicationProbe` interface  
Remove HTTP-200-as-TCP-liveness  
Add `fdb.go` skeleton (vishvananda/netlink RTM_NEWNEIGH/DELNEIGH stubs)  
Add `pm-cni` chained plugin skeleton  
**Defer**: kernel module interface (ExportTCPSockets/ImportTCPSockets RPCs, TCPSocketSnapshot repeated field) until NS#4 proven

### M20 — Zero-Window Hold: Real eBPF (1–2 weeks)
Wire real `cilium/ebpf` load of `zero_window.c` on TC egress of source veth (clsact, BPF_F_ALLOW_OVERRIDE). Add `ZeroWindowArm` / `ZeroWindowDisarm` gRPC calls. Validate: sender stalls within 1 RTT, no RST, resumes within 50ms of disarm. Kernel floor: 5.15 for this attach point.

### M21 — IP Identity: VXLAN FDB Injection + Migration Netns (1–2 weeks)
Implement `PrepareDestinationNetns` RPC fully (veth + bridge wire-up + source IP assignment). Implement `fdb.go` RTM_NEWNEIGH injection on flannel.1. Wire pm-cni to suppress source DEL FDB/ARP cleanup until `MigrationComplete`. Validate: pings to source pod IP from third node work on both nodes simultaneously for the handoff window.

### M22 — TCP Socket Preservation: eBPF Relay (4–8 weeks)
Full implementation of `PM_SEQ_XLAT` BPF_MAP_TYPE_LRU_HASH, relay agent, seq/ack/ts delta seeding at restore. NS#3.5 proof (single idle TCP connection) → NS#3.7 proof (bidirectional in-flight bytes under freeze).

### M23 — CRIU tcp-established + leave-stopped ordering (1–2 weeks)
Drive `DumpOptions.TcpEstablished` from tier. Implement `--leave-stopped` so frozen process is NOT resumed at source on dump completion. Validate ordering: source frozen → FDB injected → destination restored → relay armed → ZW disarmed.

### M24 — NS#4 Proof (2–4 weeks)
pgbench 8 connections, sustained TPS, cross-node migration pm-worker → pm-control, relay default tier, zero dropped connections, freeze window < 500ms measured (p50 and p99). Full gate per QA definition below.

---

## QA Gate Definition (NS#4 is achieved IFF all hold)

Cluster: aarch64 pm-control/pm-worker flannel-VXLAN, NO custom kernel module loaded (relay default tier only)  
Workload: `pgbench -T 600 -c 8 -j 8 -P 1` against PostgreSQL on the other node, sustained non-idle load (TPS must be measurable during migration, not just before/after)  
Migration: `PodMigration` with `TCPPreservationMode: Strict`

Pass criteria:
1. pgbench `failed transactions: 0` across entire 600s run
2. pgbench reports no disconnections in progress log
3. Freeze window < 500ms, measured source-side (CRIU `--stats` dump_time)
4. FDB entry injected and verified (RTM_GETNEIGH confirms entry exists) before ZW disarmed
5. Relay eBPF map has entries for all 8 connections at relay-arm time
6. TCPVerified condition = True via SQL probe (real query, not HTTP-200)
7. Source pod not deleted until `TrafficVerified=True` (ADR-0012)
8. Freeze window measured as full wall-clock from `ZeroWindowArm` to `ZeroWindowDisarm` (not just CRIU dump_time)

QA red flags to guard against:
- **False positive**: NS#4 passes on low-TPS migration because freeze window fit inside peer RTO_MIN — mandate sustained load AT freeze instant + record peer RTO
- **False positive**: TCP connection "survived" because pgbench reconnected silently — assert `failed_transactions=0` AND no reconnect events in pgbench output, not just final state
- **False positive**: relay eBPF only handles the happy path — test asymmetric packet loss (tc netem 1% loss), GRO coalescing, TSO segmentation

NS#3 regression gate must be wired as hard CI blocker at every milestone.

---

## What to Retain (Expert Panel Consensus)

| Component | Verdict |
|---|---|
| Pre-copy memory loop (CRIU pre-dump rounds) | Retain |
| NMC capacity model | Retain |
| MigrationPolicy + descheduler integration | Retain |
| ADR-0002 CRIU-as-subprocess (GPLv2 firewall) | Retain |
| ADR-0012 source-pod-deletion gate | Retain |
| ADR-0045/0046 stability + no-workload-controller-mutation | Retain |
| retry.RetryOnConflict on all status writes | Retain |
| 5-CRD data model (PodMigration, MigrationPolicy, NMC, MCP, MWC) | Retain |
| Storage tier classification (RWX → Longhorn → Ceph → snapshot) | Retain |
| Scheduler plugin (MigrationAwareFilter/Score) | Retain |

## What to Refactor

| Component | Fix |
|---|---|
| `server.go:547` `--empty-ns net` | `--join-ns net:<dest_netns_fd>` |
| `criu_checkpointer.go:177` `TcpEstablished: false` | Drive from `CheckpointRequest` tier |
| eBPF stub/loader | Real cilium/ebpf as default; stub opt-in |
| Verifying phase (HTTP-as-TCP-liveness) | Split: TCPVerifier (SQL/gRPC/TCP probes) + ServiceVerifier |
| State machine (8-phase) | 12-phase with TCP-specific phases |
| CRD (missing TCP fields) | TCPPreservationMode, ConnectionClass, FreezeWindowBudgetMs, ApplicationProbeSpec |
| Proto (tcp_established bool, no SeqSnapshot) | SeqSnapshot, PrepareDestinationNetns, dest_netns_fd |

## What to Remove

| Component | Verdict |
|---|---|
| HTTP-200-as-TCP-liveness logic | Remove |
| `--restore-detached` (ghost container) | Already banned (ADR) — confirm absent |
| Persistent checkpoint disk path `/var/lib/...` | Already banned — confirm absent |

---

## PM Sequencing Notes

- Insert M18.5 spike BEFORE M19 redesign — if the relay concept fails on one idle netcat, the architecture needs revisiting before we sink 4 weeks into M19
- Defer kernel module fidelity tier (ExportTCPSockets/ImportTCPSockets RPCs, NETLINK_SOCKET_MIGRATE `.ko`) out of M19; design it after NS#4 proven on relay path
- The pgbench proof is rigorous but tell the story as: "a live PostgreSQL client migrated to a new node mid-query, zero failed queries" — SREs need to feel it, not just read the number

---

## Architecture Quorum Sign-off Required

Before any M19 code is written, 2 independent Opus agents must review this document and both SIGN OFF. See standing instruction in CLAUDE.md team process section.
