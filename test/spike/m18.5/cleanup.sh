#!/usr/bin/env bash
# [PM-WORKER] Cleanup: remove spike pod netns, BPF programs, iptables rules.
# Safe to run multiple times (idempotent).
set -uo pipefail  # not -e, we want cleanup to continue on errors

LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
POD_NETNS="${POD_NETNS:-pm-spike-pod}"
POD_IP="${POD_IP:-10.244.1.50}"
VTEP_DEV="${VTEP_DEV:-flannel.1}"

echo "[cleanup] stopping traffic generator"
if [[ -f "${LOG_DIR}/client.pid" ]]; then
    kill "$(cat ${LOG_DIR}/client.pid)" 2>/dev/null || true
fi
if [[ -f "${LOG_DIR}/tgen_host_pid" ]]; then
    kill "$(cat ${LOG_DIR}/tgen_host_pid)" 2>/dev/null || true
fi

echo "[cleanup] stopping tcpdump"
if [[ -f "${LOG_DIR}/tcpdump_source.pid" ]]; then
    kill "$(cat ${LOG_DIR}/tcpdump_source.pid)" 2>/dev/null || true
fi

echo "[cleanup] removing TC-BPF filters"
VETH_NAME=$(cat "${LOG_DIR}/veth_name" 2>/dev/null || echo "veth-spike")
tc filter del dev "${VETH_NAME}" egress 2>/dev/null || true
tc qdisc del dev "${VETH_NAME}" clsact 2>/dev/null || true

echo "[cleanup] removing pod netns ${POD_NETNS}"
ip netns del "${POD_NETNS}" 2>/dev/null || true
ip link del veth-spike 2>/dev/null || true

echo "[cleanup] removing iptables NOTRACK rules for ${POD_IP}"
iptables -t raw -D PREROUTING -s "${POD_IP}" -j NOTRACK 2>/dev/null || true
iptables -t raw -D PREROUTING -d "${POD_IP}" -j NOTRACK 2>/dev/null || true
iptables -t raw -D OUTPUT -s "${POD_IP}" -j NOTRACK 2>/dev/null || true
iptables -t raw -D OUTPUT -d "${POD_IP}" -j NOTRACK 2>/dev/null || true

echo "[cleanup] removing FDB entries for ${POD_IP}"
ip neigh del "${POD_IP}" dev "${VTEP_DEV}" 2>/dev/null || true

echo "[cleanup] zeroizing checkpoint images"
if [[ -d "${LOG_DIR}/checkpoint" ]]; then
    find "${LOG_DIR}/checkpoint" -type f -exec shred -u {} \; 2>/dev/null || \
        rm -rf "${LOG_DIR}/checkpoint"
fi

echo "[cleanup] DONE"
