#!/usr/bin/env bash
# [PM-WORKER] Arm zero-window hold on the spike pod veth.
#
# Attaches the TC-BPF zero_window program to the EGRESS of veth-spike (the host
# side of the spike pod's veth pair). This causes all TCP ACKs leaving the spike
# pod to advertise window=0, stalling the echo server's sender.
#
# The hold stays in place until 07_disarm.sh removes it.
set -euo pipefail

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
BPF_DIR="${BPF_DIR:-${SPIKE_DIR}/bpf}"
VETH_NAME=$(cat "${LOG_DIR}/veth_name" 2>/dev/null || echo "veth-spike")

BPF_OBJ="${BPF_DIR}/zero_window.o"
if [[ ! -f "${BPF_OBJ}" ]]; then
    echo "[arm-zw] FATAL: BPF object not found: ${BPF_OBJ}"
    echo "[arm-zw] Build first: cd ${BPF_DIR} && make"
    exit 1
fi

echo "[arm-zw] arming zero-window hold on ${VETH_NAME} TC egress"

# Add clsact qdisc if not present (idempotent)
if ! tc qdisc show dev "${VETH_NAME}" 2>/dev/null | grep -q clsact; then
    tc qdisc add dev "${VETH_NAME}" clsact
fi

# Remove any existing zero_window filter on egress
tc filter del dev "${VETH_NAME}" egress 2>/dev/null || true

# Attach
tc filter add dev "${VETH_NAME}" egress \
    bpf direct-action obj "${BPF_OBJ}" sec tc

echo "[arm-zw] zero-window hold ARMED on ${VETH_NAME} egress"

# Verify attachment
echo "[arm-zw] TC filter list:"
tc filter show dev "${VETH_NAME}" egress

# Start tcpdump on the veth to capture pre-freeze baseline seq numbers
# This capture runs until 08_verify.sh processes it
echo "[arm-zw] starting tcpdump baseline capture on ${VETH_NAME}"
tcpdump -i "${VETH_NAME}" -w "${LOG_DIR}/capture_source.pcap" \
    -s 128 'tcp' &
echo $! > "${LOG_DIR}/tcpdump_source.pid"

echo "[arm-zw] tcpdump PID $(cat ${LOG_DIR}/tcpdump_source.pid)"
echo "[arm-zw] zero-window hold active — sender should stall within 1 RTT"
echo "[arm-zw] observe: watch -n1 'ip netns exec pm-spike-pod ss -tin | grep -A2 10.244.0.50'"
echo "[arm-zw] look for: rcvwnd=0 or peer window shrinking to 0"
