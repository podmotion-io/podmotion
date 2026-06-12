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

# Pause traffic generator BEFORE arming hold so the kernel send buffer drains
# naturally while ACKs can still flow. Correct production ordering:
#   (1) signal app to stop new writes
#   (2) wait for kernel buffer to drain (notsent == 0)
#   (3) arm zero-window hold to freeze the peer
TGEN_HOST_PID=$(cat "${LOG_DIR}/tgen_host_pid" 2>/dev/null || echo "")
if [[ -n "${TGEN_HOST_PID}" ]]; then
    echo "[arm-zw] pausing traffic generator (SIGUSR1) — draining kernel send buffer first"
    # kill may need sudo if the process runs as root (ip netns exec runs as root)
    kill -USR1 "${TGEN_HOST_PID}" 2>/dev/null || \
        ([ -x /usr/bin/sudo ] && /usr/bin/sudo kill -USR1 "${TGEN_HOST_PID}" 2>/dev/null) || true
    # Brief wait for kernel to transmit buffered data and receive ACKs (~2 RTTs)
    VETH_HOST=$(cat "${LOG_DIR}/veth_name" 2>/dev/null || echo "veth-spike")
    POD_NETNS="${POD_NETNS:-pm-spike-pod}"
    for i in $(seq 1 30); do
        NS=$(ip netns exec "${POD_NETNS}" ss -tin 2>/dev/null \
            | grep -A3 "10.244.0" | grep -oE 'notsent:[0-9]+' | cut -d: -f2 | head -1 || true)
        # notsent absent in ss output means it is 0 (field omitted when zero)
        if [[ -z "${NS}" ]] || [[ "${NS}" == "0" ]]; then
            echo "[arm-zw] kernel buffer drained (notsent=${NS:-0}) after ${i}x100ms"
            break
        fi
        echo "[arm-zw] waiting for kernel buffer drain: notsent=${NS}"
        sleep 0.1
    done
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
