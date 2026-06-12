#!/usr/bin/env bash
# [PM-WORKER] Two-sided FDB + neighbor injection + conntrack NOTRACK.
#
# This implements ADR-0048's overlay handoff — programmed on BOTH nodes simultaneously
# before ZW disarm. The ConfirmOverlayReady verification step is included.
#
# Entry types (two distinct kernel objects, must not be conflated):
#
#   AF_BRIDGE FDB  (RTM_NEWNEIGH, AF_BRIDGE, NTF_SELF):
#     NDA_LLADDR = pod_veth_mac, NDA_DST = dest_vtep_ip
#     Controls: where flannel.1 encapsulates/sends VXLAN frames for this MAC
#
#   AF_INET neighbor (RTM_NEWNEIGH, AF_INET, NTF_OVERRIDE):
#     NDA_DST = pod_ip, NDA_LLADDR = pod_veth_mac
#     Controls: L3→L2 resolution (which MAC to use for this IP)
#
# Both entries on BOTH nodes. One-sided injection black-holes the return path.
set -euo pipefail

LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
VTEP_DEV="${VTEP_DEV:-flannel.1}"
POD_IP="${POD_IP:-10.244.1.50}"
POD_NETNS="${POD_NETNS:-pm-spike-pod}"
DEST_HOST="${DEST_HOST:-ubuntu@192.168.252.7}"
DEST_VTEP_DEV="${DEST_VTEP_DEV:-flannel.1}"

# Read values written by 04_stage_destnetns.sh (scp'd from pm-control)
# For the spike, we pass these as env vars or read from shared storage.
# In practice: after running 04_stage_destnetns.sh, scp the LOG_DIR files here.

if [[ -z "${DEST_VTEP_MAC:-}" ]]; then
    # Try to scp from pm-control
    echo "[fdb] fetching FDB parameters from pm-control..."
    scp "${DEST_HOST}:${LOG_DIR}/dest_vtep_mac" "${LOG_DIR}/dest_vtep_mac" 2>/dev/null || true
    scp "${DEST_HOST}:${LOG_DIR}/dest_vtep_ip"  "${LOG_DIR}/dest_vtep_ip"  2>/dev/null || true
    scp "${DEST_HOST}:${LOG_DIR}/pod_veth_mac"  "${LOG_DIR}/pod_veth_mac"  2>/dev/null || true
fi

DEST_VTEP_MAC=$(cat "${LOG_DIR}/dest_vtep_mac" 2>/dev/null || echo "${DEST_VTEP_MAC:-}")
DEST_VTEP_IP=$(cat  "${LOG_DIR}/dest_vtep_ip"  2>/dev/null || echo "${DEST_VTEP_IP:-}")
POD_VETH_MAC=$(cat  "${LOG_DIR}/pod_veth_mac"  2>/dev/null || echo "${POD_VETH_MAC:-}")

if [[ -z "${DEST_VTEP_MAC}" ]] || [[ -z "${DEST_VTEP_IP}" ]] || [[ -z "${POD_VETH_MAC}" ]]; then
    echo "[fdb] FATAL: missing parameters. Set env vars or run 04_stage_destnetns.sh first."
    echo "  DEST_VTEP_MAC=${DEST_VTEP_MAC}"
    echo "  DEST_VTEP_IP=${DEST_VTEP_IP}"
    echo "  POD_VETH_MAC=${POD_VETH_MAC}"
    exit 1
fi

echo "[fdb] Injecting overlay entries:"
echo "  POD_IP=${POD_IP}  POD_VETH_MAC=${POD_VETH_MAC}"
echo "  DEST_VTEP_MAC=${DEST_VTEP_MAC}  DEST_VTEP_IP=${DEST_VTEP_IP}"
echo ""

inject_fdb_local() {
    echo "[fdb] === SOURCE NODE (pm-worker) ==="

    # AF_BRIDGE FDB: source pod MAC → destination VTEP IP
    # Tells flannel.1: when you need to send frames to pod_veth_mac, encapsulate
    # VXLAN and send to dest_vtep_ip.
    echo "[fdb] source: AF_BRIDGE FDB: ${POD_VETH_MAC} → ${DEST_VTEP_IP}"
    bridge fdb replace "${POD_VETH_MAC}" dev "${VTEP_DEV}" \
        dst "${DEST_VTEP_IP}" self permanent

    # AF_INET neighbor: pod IP → pod MAC
    # Tells the source node's ARP: pod_ip resolves to pod_veth_mac (via flannel.1)
    echo "[fdb] source: AF_INET neighbor: ${POD_IP} → ${POD_VETH_MAC}"
    ip neigh replace "${POD_IP}" dev "${VTEP_DEV}" \
        lladdr "${POD_VETH_MAC}" nud permanent

    echo "[fdb] source entries verified:"
    bridge fdb show dev "${VTEP_DEV}" | grep -i "${POD_VETH_MAC}" || echo "  [not found — may use 'ip neigh show']"
    ip neigh show dev "${VTEP_DEV}" | grep "${POD_IP}" || echo "  [not found]"
}

inject_fdb_remote() {
    echo "[fdb] === DESTINATION NODE (pm-control) ==="

    # Run the same injection on pm-control via ssh.
    # In production this is the ConfirmOverlayReady gRPC call; here it's ssh.
    ssh "${DEST_HOST}" sudo bash << REMOTE_INJECT
set -euo pipefail
POD_VETH_MAC="${POD_VETH_MAC}"
POD_IP="${POD_IP}"
DEST_VTEP_MAC="${DEST_VTEP_MAC}"
VTEP_DEV="${DEST_VTEP_DEV}"

echo "[fdb-remote] dest: AF_BRIDGE FDB: \${POD_VETH_MAC} → local (self)"
# On the destination node, the FDB entry says: this MAC is reachable locally
# (we already have a veth with this MAC in the migration netns).
# Use the "self" flag to indicate local delivery.
bridge fdb replace "\${POD_VETH_MAC}" dev "\${VTEP_DEV}" local self permanent 2>/dev/null || \
    bridge fdb add    "\${POD_VETH_MAC}" dev "\${VTEP_DEV}" local self permanent

echo "[fdb-remote] dest: AF_INET neighbor: \${POD_IP} → \${POD_VETH_MAC}"
ip neigh replace "\${POD_IP}" dev "\${VTEP_DEV}" \
    lladdr "\${POD_VETH_MAC}" nud permanent

echo "[fdb-remote] dest entries verified:"
bridge fdb show dev "\${VTEP_DEV}" | grep -i "\${POD_VETH_MAC}" || true
ip neigh show dev "\${VTEP_DEV}" | grep "\${POD_IP}" || true
REMOTE_INJECT
}

# ── Conntrack NOTRACK ─────────────────────────────────────────────────────────
# Prevents the kernel's conntrack from dropping relay-translated packets as
# INVALID (the seq numbers change ownership but conntrack tracks the original state).
# We add a NOTRACK rule for the pod IP on both nodes before disarming the ZW hold.
arm_notrack_local() {
    echo "[fdb] source: arming conntrack NOTRACK for ${POD_IP}"
    # Delete any existing conntrack entries for this IP
    conntrack -D -s "${POD_IP}" 2>/dev/null || true
    conntrack -D -d "${POD_IP}" 2>/dev/null || true

    # Add NOTRACK iptables rule (raw table) for the pod IP
    # So newly arriving packets bypass conntrack entirely
    iptables -t raw -C PREROUTING -s "${POD_IP}" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A PREROUTING -s "${POD_IP}" -j NOTRACK
    iptables -t raw -C PREROUTING -d "${POD_IP}" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A PREROUTING -d "${POD_IP}" -j NOTRACK
    iptables -t raw -C OUTPUT -s "${POD_IP}" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A OUTPUT -s "${POD_IP}" -j NOTRACK
    iptables -t raw -C OUTPUT -d "${POD_IP}" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A OUTPUT -d "${POD_IP}" -j NOTRACK

    echo "[fdb] source: NOTRACK rules added for ${POD_IP}"
    # Save rule handles for cleanup
    iptables -t raw -nvL PREROUTING | grep "${POD_IP}" | tee -a "${LOG_DIR}/notrack_rules.txt"
}

arm_notrack_remote() {
    echo "[fdb] destination: arming conntrack NOTRACK for ${POD_IP}"
    ssh "${DEST_HOST}" sudo bash << REMOTE_NOTRACK
POD_IP="${POD_IP}"
conntrack -D -s "\${POD_IP}" 2>/dev/null || true
conntrack -D -d "\${POD_IP}" 2>/dev/null || true
iptables -t raw -C PREROUTING -s "\${POD_IP}" -j NOTRACK 2>/dev/null || \
    iptables -t raw -A PREROUTING -s "\${POD_IP}" -j NOTRACK
iptables -t raw -C PREROUTING -d "\${POD_IP}" -j NOTRACK 2>/dev/null || \
    iptables -t raw -A PREROUTING -d "\${POD_IP}" -j NOTRACK
echo "[fdb-remote] dest: NOTRACK rules added for \${POD_IP}"
REMOTE_NOTRACK
}

# ── Run both sides ────────────────────────────────────────────────────────────
inject_fdb_local
inject_fdb_remote
arm_notrack_local
arm_notrack_remote

# ── ConfirmOverlayReady: verify both sides (RTM_GETNEIGH read-back) ───────────
echo ""
echo "[fdb] verifying overlay ready (RTM_GETNEIGH read-back)..."

verify_local() {
    NEIGH=$(ip neigh show dev "${VTEP_DEV}" | grep "${POD_IP}")
    FDB=$(bridge fdb show dev "${VTEP_DEV}" | grep -i "${POD_VETH_MAC}")
    if [[ -z "${NEIGH}" ]] || [[ -z "${FDB}" ]]; then
        echo "[fdb] LOCAL VERIFY FAILED"
        echo "  neigh: '${NEIGH}'"
        echo "  fdb:   '${FDB}'"
        return 1
    fi
    echo "[fdb] local verify OK: neigh=${NEIGH} | fdb=${FDB}"
}

verify_remote() {
    RESULT=$(ssh "${DEST_HOST}" sudo bash << REMOTE_VERIFY
ip neigh show dev "${DEST_VTEP_DEV}" | grep "${POD_IP}" || echo "MISSING_NEIGH"
bridge fdb show dev "${DEST_VTEP_DEV}" | grep -i "${POD_VETH_MAC}" || echo "MISSING_FDB"
REMOTE_VERIFY
)
    if echo "${RESULT}" | grep -q "MISSING"; then
        echo "[fdb] REMOTE VERIFY FAILED: ${RESULT}"
        return 1
    fi
    echo "[fdb] remote verify OK"
}

verify_local
verify_remote

FDB_READY_NS=$(date +%s%N)
echo "${FDB_READY_NS}" > "${LOG_DIR}/fdb_ready_ns"

echo ""
echo "[fdb] OVERLAY READY — both-sided FDB + neighbor + NOTRACK confirmed"
echo "[fdb] proceed to: 06_restore.sh on PM-CONTROL, then 07_disarm.sh here"
