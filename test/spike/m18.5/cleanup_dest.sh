#!/usr/bin/env bash
# [PM-CONTROL] Cleanup: remove migration netns, server netns, BPF, FDB, NOTRACK.
set -uo pipefail

LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
MIGRATION_NETNS="${MIGRATION_NETNS:-pm-migration}"
SERVER_NETNS="${SERVER_NETNS:-pm-spike-server}"
POD_IP="${POD_IP:-10.244.1.50}"
VTEP_DEV="${VTEP_DEV:-flannel.1}"

echo "[cleanup-dest] killing server"
if [[ -f "${LOG_DIR}/server.pid" ]]; then
    kill "$(cat ${LOG_DIR}/server.pid)" 2>/dev/null || true
fi

echo "[cleanup-dest] removing migration netns ${MIGRATION_NETNS}"
ip netns del "${MIGRATION_NETNS}" 2>/dev/null || true
ip link del veth-mig 2>/dev/null || true

echo "[cleanup-dest] removing server netns ${SERVER_NETNS}"
ip netns del "${SERVER_NETNS}" 2>/dev/null || true
ip link del veth-srv 2>/dev/null || true

echo "[cleanup-dest] removing TC-BPF filters on veth-mig"
tc filter del dev veth-mig ingress 2>/dev/null || true
tc qdisc del dev veth-mig clsact 2>/dev/null || true

echo "[cleanup-dest] removing iptables NOTRACK rules for ${POD_IP}"
iptables -t raw -D PREROUTING -s "${POD_IP}" -j NOTRACK 2>/dev/null || true
iptables -t raw -D PREROUTING -d "${POD_IP}" -j NOTRACK 2>/dev/null || true
iptables -t raw -D OUTPUT -s "${POD_IP}" -j NOTRACK 2>/dev/null || true
iptables -t raw -D OUTPUT -d "${POD_IP}" -j NOTRACK 2>/dev/null || true

echo "[cleanup-dest] removing FDB/neighbor entries for ${POD_IP}"
bridge fdb del "$(cat ${LOG_DIR}/pod_veth_mac 2>/dev/null || echo 00:00:00:00:00:00)" \
    dev "${VTEP_DEV}" 2>/dev/null || true
ip neigh del "${POD_IP}" dev "${VTEP_DEV}" 2>/dev/null || true

echo "[cleanup-dest] zeroizing checkpoint images"
find "${LOG_DIR}/checkpoint" -type f -exec shred -u {} \; 2>/dev/null || true

echo "[cleanup-dest] DONE"
