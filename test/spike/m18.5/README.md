# M18.5 Spike — NS#3.5-bare: Relay Concept Proof

**Purpose**: Prove that a TCP connection with sustained bidirectional in-flight traffic
survives a manual CRIU checkpoint/restore with --tcp-established + --leave-stopped +
--join-ns into a pre-staged destination netns carrying the original pod IP.

This is a throwaway shell script. No CRDs, no proto, no operator. Manual nsenter.
All production code comes AFTER this proof passes.

---

## What this proves

1. CRIU --tcp-established + --leave-stopped correctly preserves TCP socket state
2. A pre-staged migration netns with the source pod IP allows CRIU --join-ns to restore
   sockets with seq/ack continuity (seq_delta = 0 — TCP_REPAIR preserves state exactly)
3. Two-sided AF_BRIDGE + AF_INET FDB injection on both flannel.1 interfaces keeps the
   return path alive after migration
4. The zero-window hold (TC-BPF) stalls the sender without RST during the freeze window
5. Conntrack NOTRACK prevents invalid-state drops on relay-translated packets
6. **Negative test**: migrating WITHOUT draining the send buffer produces seq corruption,
   proving that the drain-before-dump sequencing in ADR-0049 is required

---

## Seq_delta clarification (critical)

With CRIU --tcp-established + --join-ns into a netns that has the ORIGINAL source pod IP:
- CRIU uses TCP_REPAIR to restore the socket with EXACT seq/ack state from before freeze
- The peer has been stalled by the zero-window hold (no new data sent)
- The send buffer was drained (tcpi_unacked == 0) before the freeze
- Therefore: seq_delta = 0 — no sequence number translation needed

The PM_SEQ_XLAT eBPF relay in production is a PURE IP/MAC STEERING RELAY at the default
tier — its seq/ack translation fields are zero for CRIU-restored connections. The translation
machinery exists for the fidelity tier (kernel module, fresh-socket path) only.

This spike confirms: if seq_delta = 0 and IP identity is preserved, a simple FDB
steering relay with no arithmetic translation is sufficient for the relay default tier.

---

## Topology

```
pm-control (192.168.252.7)          pm-worker (192.168.252.8)
  flannel subnet: 10.244.0.0/24      flannel subnet: 10.244.1.0/24

  [TCP echo server]                  [spike-pod netns]
  addr: 10.244.0.50:9000             addr: 10.244.1.50
  (created by setup_server.sh)       veth: veth-spike <-> veth-spike-br
                                     (created by setup_pod.sh)

  [migration netns]                  
  addr: 10.244.1.50 (secondary)
  (pre-staged by stage_destnetns.sh)
```

The spike pod runs on pm-worker with IP 10.244.1.50 and has an established TCP connection
to the echo server on pm-control at 10.244.0.50:9000. The migration moves the spike pod
from pm-worker to pm-control (into the pre-staged migration netns).

---

## Prerequisites

On both nodes:
- CRIU 4.2 installed (criu binary in PATH)
- iproute2 with tc and ip (standard Ubuntu 24.04)
- clang + llvm (for BPF compilation)
- bpftool
- conntrack tools (conntrack -D)
- tcpdump

Build the BPF programs first:
```bash
cd test/spike/m18.5/bpf && make
```

---

## Run sequence

Run each step on the indicated node. Source scripts are annotated with [PM-WORKER] or
[PM-CONTROL]. All scripts accept SOURCE_IP and DEST_IP env vars if defaults don't match.

```bash
# Step 0: build BPF programs
cd bpf && make && cd ..

# Step 1: [PM-CONTROL] start echo server
ssh ubuntu@192.168.252.7 'bash -s' < 00_setup_server.sh

# Step 2: [PM-WORKER] create spike pod netns + start traffic generator
sudo bash 01_setup_pod.sh

# Step 3: [PM-WORKER] arm zero-window hold on spike pod veth
sudo bash 02_arm_zerowindow.sh

# Step 4: [PM-WORKER] wait for send buffer drain, then CRIU checkpoint
sudo bash 03_drain_and_checkpoint.sh

# Step 5: [PM-CONTROL] pre-stage migration netns
ssh ubuntu@192.168.252.7 'sudo bash -s' < 04_stage_destnetns.sh

# Step 6: both nodes — two-sided FDB injection + conntrack NOTRACK
sudo bash 05_inject_fdb.sh        # runs remote commands via ssh internally

# Step 7: [PM-CONTROL] CRIU restore into migration netns
ssh ubuntu@192.168.252.7 'sudo bash -s' < 06_restore.sh

# Step 8: [PM-WORKER] disarm zero-window hold
sudo bash 07_disarm.sh

# Step 9: verify seq continuity on both nodes
sudo bash 08_verify.sh

# Step 10: negative test (no drain → seq corruption)
sudo bash 09_negative_test.sh

# Cleanup
sudo bash cleanup.sh
ssh ubuntu@192.168.252.7 'sudo bash -s' < cleanup_dest.sh
```

---

## Pass criteria (ALL required)

- [ ] Traffic generator shows 0 errors after migration
- [ ] tcpdump on BOTH nodes confirms seq continuity in BOTH directions
- [ ] Return path (server ACKs → client) routes correctly to pm-control (not dropped at pm-worker)
- [ ] Negative test: non-drained migration shows seq gap or RST in tcpdump output

---

## Architecture note on seq_delta = 0

This spike is the empirical proof of the seq_delta=0 invariant. If CRIU TCP_REPAIR does NOT
perfectly preserve seq state (e.g., due to buffered ACKs being part of the image vs network),
we will observe a seq discontinuity in tcpdump even with the same IP. That would mean the
production relay DOES need seq translation. This spike settles that question definitively.
