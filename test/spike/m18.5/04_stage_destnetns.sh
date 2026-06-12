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

echo "[dest-netns] creating bare migration netns ${MIGRATION_NETNS} (no eth0)"
# No veth or IP is pre-staged here. CRIU will create eth0 inside this netns
# during restore using --external veth[eth0]:veth-mig@BRIDGE. CRIU restores
# the IP address and routes from the checkpoint images.
# Pre-staging eth0 caused EEXIST (Can't restore link: -17) because CRIU
# tried to create eth0 again inside --join-ns netns.
ip netns add "${MIGRATION_NETNS}"

echo "[dest-netns] bare migration netns ready: ${MIGRATION_NETNS}"

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

# Note: eth0 and veth-mig are created by CRIU during restore
# (--external veth[eth0]:veth-mig@BRIDGE). MAC is unknown until after restore.
echo "[dest-netns] eth0/veth-mig will be created by CRIU restore"

# BPF observer attached AFTER CRIU restore creates veth-mig
# (see post-restore step in 07_disarm.sh or verify script)
SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BPF_OBJ="${SPIKE_DIR}/bpf/seq_xlat_noop.o"
echo "[dest-netns] BPF observer will be attached to veth-mig after CRIU restore"

echo ""
echo "[dest-netns] DESTINATION NETNS READY"
echo "[dest-netns] CRIU restore will use: --join-ns net:${NETNS_PATH}"
echo ""
echo "[dest-netns] Copy these values to pm-worker for FDB injection (05_inject_fdb.sh):"
echo "  DEST_VTEP_MAC=${DEST_VTEP_MAC}"
echo "  DEST_VTEP_IP=${DEST_VTEP_IP}"
echo "  POD_VETH_MAC=(determined after CRIU restore creates veth-mig)"
echo ""
echo "[dest-netns] Start tcpdump on destination to capture return path:"
echo "  tcpdump -i ${VTEP_DEV} -w ${LOG_DIR}/capture_dest.pcap -s 128 'tcp'"
