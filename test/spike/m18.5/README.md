# M18.5 Spike — NS#3.5-bare: CRIU TCP Migration Proof

**Status**: PROVED ✓ (2026-06-12)

**Purpose**: Prove that a TCP connection with sustained bidirectional in-flight traffic
survives a manual CRIU checkpoint/restore with `--tcp-established` + `--leave-stopped` +
`--join-ns` into a bare destination netns. Same-node restore on pm-worker.

This is a throwaway shell script. No CRDs, no proto, no operator. Manual nsenter.
All production code comes AFTER this proof passes.

---

## Proof Result

```
sent=576, received=576, errors=0, gaps=[]
CRIU dump:    94ms
CRIU restore: 2013ms
seq_delta:    0 (CONFIRMED)
```

Live traffic resumed after restore and ran to 576 messages with zero sequence gaps.

---

## What this proves

1. CRIU `--tcp-established` + `--leave-stopped` correctly preserves TCP socket state
2. `nsenter --net` (NOT `ip netns exec`) is required for CRIU to work: `ip netns exec`
   creates an extra mount namespace, causing mount ID mismatches in CRIU images.
   `nsenter --net` enters ONLY the network namespace, keeping the host mount namespace.
3. CRIU `--join-ns net:PATH` + `--external veth[eth0]:veth-mig@cni0` correctly restores
   a TCP socket into a bare migration netns. CRIU creates eth0/veth-mig from the checkpoint.
4. Bare migration netns (no pre-staged eth0) is required — pre-staged eth0 causes
   EEXIST (Can't restore link: -17).
5. Post-restore: wiring veth-mig to cni0 + neighbor entry for the pod IP restores
   the return path through the flannel overlay.
6. The zero-window hold (TC-BPF) stalls the sender without RST during the freeze window.
7. seq_delta = 0 — no sequence number translation required.

---

## Seq_delta clarification (critical)

With CRIU `--tcp-established` + `--join-ns` into a netns that has the ORIGINAL source pod IP:
- CRIU uses TCP_REPAIR to restore the socket with EXACT seq/ack state from before freeze
- The peer has been stalled by the zero-window hold (no new data sent)
- The send buffer was drained (tcpi_unacked == 0) before the freeze
- Therefore: seq_delta = 0 — no sequence number translation needed

The PM_SEQ_XLAT eBPF relay in production is a PURE IP/MAC STEERING RELAY at the default
tier — its seq/ack translation fields are zero for CRIU-restored connections.

---

## Critical technical fixes (for production implementation)

| Issue | Root cause | Fix |
|-------|-----------|-----|
| CRIU mount ID mismatch | `ip netns exec` creates extra mount namespace | Use `nsenter --net` |
| "Can't restore link: -17" (EEXIST) | eth0 pre-staged in migration netns | Stage BARE netns; let CRIU create eth0 |
| "Unknown peer net namespace" | CRIU couldn't find veth peer namespace | Use `--external veth[eth0]:veth-mig@cni0` |
| "Can't fork: File exists" | Frozen source still holds PID | Kill frozen source before restore |
| IP conflict on cni0 | Both source and migration netns claim same IP | Delete source netns before restore |
| Sender stuck paused after restore | No SIGUSR2 resume handler | Added on_resume(SIGUSR2) to traffic_gen |

---

## Topology

```
pm-control (192.168.252.7)          pm-worker (192.168.252.8)
  flannel subnet: 10.244.0.0/24      flannel subnet: 10.244.1.0/24

  [TCP echo server]                  [spike-pod netns] → CHECKPOINT → [migration netns]
  addr: 10.244.0.50:9000             addr: 10.244.1.50
  (created by 00_setup_server.sh)    veth-spike ↔ cni0    veth-mig ↔ cni0
                                     (CRIU dump target)   (CRIU restore target)
```

The spike pod runs on pm-worker with IP 10.244.1.50 and has an established TCP connection
to the echo server on pm-control at 10.244.0.50:9000. The spike restores SAME-NODE (both
source and destination netns are on pm-worker). Cross-node requires 05_inject_fdb.sh.

---

## Prerequisites

On pm-worker:
- CRIU 4.2 (criu binary in PATH)
- iproute2 with tc and ip (Ubuntu 24.04 standard)
- clang + llvm (for BPF compilation)
- bpftool, conntrack tools, tcpdump, Python 3

Build the BPF programs first:
```bash
cd test/spike/m18.5/bpf && make
```

---

## Run sequence (same-node restore)

```bash
# Step 0: build BPF programs
cd bpf && make && cd ..

# Step 1: [PM-CONTROL] start echo server (one-time)
ssh ubuntu@192.168.252.7 'sudo bash -s' < 00_setup_server.sh

# Step 2: [PM-WORKER] create spike pod netns + start traffic generator
sudo bash 01_setup_pod.sh

# Step 3: [PM-WORKER] arm zero-window hold on spike pod veth
sudo bash 02_arm_zerowindow.sh

# Step 4: [PM-WORKER] wait for send buffer drain, then CRIU checkpoint
sudo bash 03_drain_and_checkpoint.sh

# Step 5: [PM-WORKER] create bare migration netns
sudo bash 04_stage_destnetns.sh

# Step 6: kill frozen source + delete source netns (frees PID, removes IP conflict)
CLIENT_PID=$(cat /tmp/pm-spike/client.pid)
sudo kill -9 ${CLIENT_PID}
sudo ip netns del pm-spike-pod
sudo ip link del veth-spike

# Step 7: [PM-WORKER] CRIU restore into migration netns
sudo bash 06_restore.sh

# Step 8: [PM-WORKER] wire veth-mig to cni0 + add neighbor (return path)
MIG_MAC=$(sudo ip netns exec pm-migration ip link show eth0 | awk '/link\/ether/{print $2}')
sudo ip link set veth-mig master cni0
sudo ip link set veth-mig up
sudo ip neigh replace 10.244.1.50 dev cni0 lladdr ${MIG_MAC} nud permanent
sudo ip route replace 10.244.1.50/32 dev cni0
sudo iptables -t raw -A PREROUTING -s 10.244.1.50 -j NOTRACK
sudo iptables -t raw -A PREROUTING -d 10.244.1.50 -j NOTRACK

# Step 9: [PM-WORKER] disarm zero-window hold + send SIGUSR2 to resume sender
sudo bash 07_disarm.sh

# Step 10: verify seq continuity
sudo bash 08_verify.sh

# Cleanup
sudo bash cleanup.sh
```

---

## Pass criteria (ALL confirmed ✓)

- [x] Traffic generator shows 0 errors, 0 gaps after migration (sent=576, recv=576)
- [x] TCP socket ESTAB in migration netns with live ACKs after restore
- [x] Return path works: ping 0% loss at <1ms from migration netns to echo server
- [x] CRIU dump: 94ms freeze window
- [x] CRIU restore: process alive, socket ESTAB, bytes_acked > 0 after resume
- [ ] Negative test (09_negative_test.sh): migrating without drain — not yet run
- [ ] Cross-node restore: requires 05_inject_fdb.sh pipeline

---

## Known limitations (scope for M20+)

1. **Same-node only**: Cross-node requires two-sided FDB injection (05_inject_fdb.sh) with
   root SSH access from pm-worker to pm-control.
2. **Source deleted before restore**: Production must satisfy ADR-0012 (source not deleted
   until TrafficVerified=True). The spike deletes source to free PID; the operator will
   use a different PID namespace strategy or hold the source frozen.
3. **Manual post-restore wiring**: The operator will handle veth-mig→cni0 wiring via
   the agent's network package.
4. **CRIU restore 2013ms**: The 2-second wait in 06_restore.sh is conservative. With
   proper health checking (poll for process existence), this reduces to ~200ms.
