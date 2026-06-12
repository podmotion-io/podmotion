#!/usr/bin/env bash
# [PM-CONTROL] Pre-stage the destination migration netns.
#
# Creates a migration netns on pm-control that:
#   1. Has a veth pair wired into the flannel bridge (cni0)
#   2. Carries the source pod IP (10.244.1.50) as a SECONDARY address
#   3. Exports the dest_netns_fd for CRIU --join-ns
#
# This solves Blocker 1: CRIU --join-ns net:<fd> instead of --empty-ns net.
# The restored process sees its original IP on its interface — TCP_REPAIR can
# restore socket bindings because the IP exists on a local interface.
#
# After this script: the migration netns is ready. CRIU restore will join it.
set -euo pipefail

LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
FLANNEL_BRIDGE="${FLANNEL_BRIDGE:-cni0}"
POD_IP="${POD_IP:-10.244.1.50}"
MIGRATION_NETNS="${MIGRATION_NETNS:-pm-migration}"
VTEP_DEV="${VTEP_DEV:-flannel.1}"

mkdir -p "${LOG_DIR}"

# Clean up any prior migration netns
if ip netns list 2>/dev/null | grep -q "^${MIGRATION_NETNS}"; then
    echo "[dest-netns] removing existing migration netns ${MIGRATION_NETNS}"
    ip netns del "${MIGRATION_NETNS}" || true
fi
ip link del veth-mig 2>/dev/null || true

echo "[dest-netns] creating migration netns ${MIGRATION_NETNS}"
ip netns add "${MIGRATION_NETNS}"

# Create veth pair: veth-mig (host) <-> eth0 (migration netns)
ip link add veth-mig type veth peer name eth0
ip link set eth0 netns "${MIGRATION_NETNS}"

# Host side: wire into flannel bridge
ip link set veth-mig master "${FLANNEL_BRIDGE}"
ip link set veth-mig up

# Migration netns: assign the SOURCE pod IP as primary address
# (it will be a "foreign" IP from the flannel perspective of pm-control,
#  but that's fine — the FDB injection will route traffic here)
ip netns exec "${MIGRATION_NETNS}" ip addr add "${POD_IP}/32" dev eth0
ip netns exec "${MIGRATION_NETNS}" ip link set eth0 up
ip netns exec "${MIGRATION_NETNS}" ip link set lo up

# Default route inside migration netns via flannel bridge gateway
FLANNEL_GW=$(ip -4 addr show "${FLANNEL_BRIDGE}" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
if [[ -n "${FLANNEL_GW}" ]]; then
    ip netns exec "${MIGRATION_NETNS}" ip route add default via "${FLANNEL_GW}"
fi

echo "[dest-netns] migration netns ready: pod IP ${POD_IP} assigned to eth0 in ${MIGRATION_NETNS}"

# Export the migration netns fd path (CRIU needs a file descriptor or path)
NETNS_PATH="/var/run/netns/${MIGRATION_NETNS}"
echo "${NETNS_PATH}" > "${LOG_DIR}/dest_netns_path"
echo "[dest-netns] netns path: ${NETNS_PATH}"

# Discover the destination VTEP MAC (for FDB injection in step 05)
# Method 1: flannel annotation (preferred)
DEST_NODE=$(hostname)
VTEP_MAC_ANNOTATION=$(kubectl get node "${DEST_NODE}" \
    -o jsonpath='{.metadata.annotations.flannel\.alpha\.coreos\.com/backend-data}' \
    2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('VtepMAC',''))" \
    2>/dev/null || echo "")

# Method 2: RTM_GETLINK fallback
VTEP_MAC_LINK=$(ip link show "${VTEP_DEV}" 2>/dev/null | awk '/link\/ether/{print $2}' | head -1)

DEST_VTEP_MAC="${VTEP_MAC_ANNOTATION:-${VTEP_MAC_LINK}}"
if [[ -z "${DEST_VTEP_MAC}" ]]; then
    echo "[dest-netns] FATAL: cannot determine destination VTEP MAC"
    echo "[dest-netns] tried: flannel annotation + ip link show ${VTEP_DEV}"
    exit 1
fi
echo "${DEST_VTEP_MAC}" > "${LOG_DIR}/dest_vtep_mac"
echo "[dest-netns] destination VTEP MAC: ${DEST_VTEP_MAC}"

# Discover destination VTEP IP (this node's flannel.1 IP)
DEST_VTEP_IP=$(ip -4 addr show "${VTEP_DEV}" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
echo "${DEST_VTEP_IP}" > "${LOG_DIR}/dest_vtep_ip"
echo "[dest-netns] destination VTEP IP: ${DEST_VTEP_IP}"

# Discover the migration netns veth MAC (the pod's apparent MAC in flannel)
MIG_VETH_MAC=$(ip netns exec "${MIGRATION_NETNS}" ip link show eth0 | awk '/link\/ether/{print $2}')
echo "${MIG_VETH_MAC}" > "${LOG_DIR}/pod_veth_mac"
echo "[dest-netns] migration netns veth MAC: ${MIG_VETH_MAC}"

# Attach seq_xlat_noop observer BPF to the host side of the migration veth
# This logs seq numbers for every TCP packet crossing the relay boundary
SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BPF_OBJ="${SPIKE_DIR}/bpf/seq_xlat_noop.o"
if [[ -f "${BPF_OBJ}" ]]; then
    tc qdisc add dev veth-mig clsact 2>/dev/null || true
    tc filter del dev veth-mig ingress 2>/dev/null || true
    tc filter add dev veth-mig ingress bpf direct-action obj "${BPF_OBJ}" sec tc
    echo "[dest-netns] seq observer BPF attached to veth-mig ingress"
    echo "[dest-netns] trace: cat /sys/kernel/debug/tracing/trace_pipe | grep pm-relay"
fi

echo ""
echo "[dest-netns] DESTINATION NETNS READY"
echo "[dest-netns] CRIU restore will use: --join-ns net:${NETNS_PATH}"
echo ""
echo "[dest-netns] Copy these values to pm-worker for FDB injection (05_inject_fdb.sh):"
echo "  DEST_VTEP_MAC=${DEST_VTEP_MAC}"
echo "  DEST_VTEP_IP=${DEST_VTEP_IP}"
echo "  POD_VETH_MAC=${MIG_VETH_MAC}"
echo ""
echo "[dest-netns] Start tcpdump on destination to capture return path:"
echo "  tcpdump -i ${VTEP_DEV} -w ${LOG_DIR}/capture_dest.pcap -s 128 'tcp'"
