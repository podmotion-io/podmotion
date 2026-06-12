#!/usr/bin/env bash
# NEGATIVE TEST: Prove that migrating WITHOUT draining the send buffer produces
# seq corruption or a stale-segment retransmit storm.
#
# This test is NOT a migration proof — it is the proof that ADR-0049's
# drain-before-dump requirement is load-bearing, not cargo-cult.
#
# Approach:
#   1. Fresh pod setup (IP 10.244.1.51, netns pm-spike-pod-neg)
#   2. Add tc netem delay 50ms to veth — inflates RTT so ~1 message is always
#      in-flight (50ms RTT / 50ms send interval). NO ZW hold, NO SIGUSR1 pause.
#   3. CRIU dump immediately while tcpi_unacked > 0 (no drain step)
#   4. Kill frozen source, delete source netns
#   5. Restore into bare migration netns (same-node, no SSH)
#   6. Wire veth-mig-neg to cni0 + neighbor entry
#   7. Disarm netem, send SIGUSR2 to resume sender
#   8. Observe: if gaps=0, ADR-0049 drain requirement is conservative (CRIU TCP_REPAIR
#      handles retransmits transparently). If gaps>0, requirement is validated.
#
# Key fix vs prior run: 02_arm_zerowindow.sh sends SIGUSR1 + waits for drain BEFORE
# arming ZW, so unacked was always 0 by the time we checked. This version skips ZW
# entirely and uses netem delay to keep data in-flight at dump time.
set -euo pipefail

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
NEGATIVE_LOG_DIR="${LOG_DIR}/negative_test"
POD_NETNS="${POD_NETNS:-pm-spike-pod-neg}"
POD_IP="${POD_IP:-10.244.1.51}"
SERVER_IP="${SERVER_IP:-10.244.0.50}"
SERVER_PORT="${SERVER_PORT:-9000}"
FLANNEL_BRIDGE="${FLANNEL_BRIDGE:-cni0}"
MIGRATION_NETNS="pm-migration-neg"
NETEM_DELAY_MS="${NETEM_DELAY_MS:-50}"

mkdir -p "${NEGATIVE_LOG_DIR}"
chmod 0700 "${NEGATIVE_LOG_DIR}"

echo "========================================================"
echo " NEGATIVE TEST: No-drain migration"
echo " Proving ADR-0049 drain-before-dump is required"
echo "========================================================"
echo ""

# ── 1. Fresh pod setup ────────────────────────────────────────────────────────
echo "[neg] setting up negative-test pod netns (IP ${POD_IP})"
POD_NETNS="${POD_NETNS}" POD_IP="${POD_IP}" LOG_DIR="${NEGATIVE_LOG_DIR}" \
    bash "${SPIKE_DIR}/01_setup_pod.sh"

# veth-spike is always the host-side veth name written by 01_setup_pod.sh
VETH_NAME=$(cat "${NEGATIVE_LOG_DIR}/veth_name" 2>/dev/null || echo "veth-spike")

# Let traffic generator establish connection and send a few messages
sleep 1

# ── 2. Inflate RTT with tc netem delay (NO ZW hold, NO pause) ────────────────
# This keeps ~1 message in-flight at all times (RTT=100ms at 50ms send rate).
# We do NOT pause the sender (no SIGUSR1) so new sends keep flowing.
echo "[neg] adding tc netem delay ${NETEM_DELAY_MS}ms on ${VETH_NAME} to inflate RTT"
tc qdisc add dev "${VETH_NAME}" root netem delay "${NETEM_DELAY_MS}ms" 2>/dev/null || \
    tc qdisc replace dev "${VETH_NAME}" root netem delay "${NETEM_DELAY_MS}ms"

sleep 0.2  # let a few messages get in-flight with the new RTT

# ── 3. Check unacked and dump IMMEDIATELY (no drain) ─────────────────────────
CLIENT_PID=$(cat "${NEGATIVE_LOG_DIR}/client.pid")
POD_NETNS_PATH="/var/run/netns/${POD_NETNS}"

UNACKED=$(nsenter --net="${POD_NETNS_PATH}" ss -tin 2>/dev/null \
    | grep -A3 "${SERVER_IP}" \
    | grep -oE 'unacked:[0-9]+' | cut -d: -f2 | head -1 || echo "0")
echo "[neg] unacked at dump time (no drain): ${UNACKED}"
echo "${UNACKED}" > "${NEGATIVE_LOG_DIR}/unacked_at_dump"

if [[ "${UNACKED}" == "0" ]]; then
    echo "[neg] WARNING: unacked=0 — RTT inflation may not have taken effect yet"
    echo "[neg] Proceeding anyway — CRIU will checkpoint with empty send queue"
    echo "[neg] This tests a different failure mode: no atomicity guarantee without ZW hold"
fi

CHECKPOINT_DIR="${NEGATIVE_LOG_DIR}/checkpoint"
rm -rf "${CHECKPOINT_DIR}"
mkdir -p "${CHECKPOINT_DIR}"
chmod 0700 "${CHECKPOINT_DIR}"

DUMP_START_NS=$(date +%s%N)
echo "[neg] DUMPING WITHOUT DRAIN (unacked=${UNACKED})"

# Use nsenter --net (not ip netns exec) — critical: ip netns exec creates extra
# mount namespace causing CRIU mount ID mismatches (same fix as positive test).
nsenter --net="${POD_NETNS_PATH}" -- \
    criu dump \
        --tree "${CLIENT_PID}" \
        --images-dir "${CHECKPOINT_DIR}" \
        --log-file "${NEGATIVE_LOG_DIR}/criu_dump.log" \
        --verbosity=4 \
        --tcp-established \
        --leave-stopped \
        --shell-job \
        --file-locks \
        2>&1 | tee "${NEGATIVE_LOG_DIR}/criu_dump_stdout.log"

DUMP_EXIT=$?
DUMP_END_NS=$(date +%s%N)
DUMP_MS=$(( (DUMP_END_NS - DUMP_START_NS) / 1000000 ))
echo "[neg] CRIU dump exit: ${DUMP_EXIT} elapsed: ${DUMP_MS}ms"

if [[ "${DUMP_EXIT}" -ne 0 ]]; then
    echo "[neg] FATAL: CRIU dump failed — check ${NEGATIVE_LOG_DIR}/criu_dump.log"
    exit 1
fi

# ── 4. Kill frozen source, remove source netns (frees PID + IP conflict) ─────
echo "[neg] killing frozen source PID ${CLIENT_PID} and removing source netns"
kill -9 "${CLIENT_PID}" 2>/dev/null || true
tc qdisc del dev "${VETH_NAME}" root 2>/dev/null || true
ip netns del "${POD_NETNS}" 2>/dev/null || true
ip link del "${VETH_NAME}" 2>/dev/null || true

# ── 5. Stage bare destination netns (same-node) ──────────────────────────────
echo "[neg] staging bare migration netns ${MIGRATION_NETNS}"
ip netns del "${MIGRATION_NETNS}" 2>/dev/null || true
ip link del veth-mig-neg 2>/dev/null || true
ip netns add "${MIGRATION_NETNS}"
# NO eth0 pre-staged — CRIU creates eth0 from checkpoint via --external veth[eth0]

MIGRATION_NETNS_PATH="/var/run/netns/${MIGRATION_NETNS}"
echo "[neg] bare migration netns ready: ${MIGRATION_NETNS_PATH}"

# ── 6. CRIU restore into bare migration netns ─────────────────────────────────
RESTORE_START_NS=$(date +%s%N)
echo "[neg] restoring (without drain, unacked was ${UNACKED})"

nsenter --net="${MIGRATION_NETNS_PATH}" -- \
    criu restore \
        --images-dir "${CHECKPOINT_DIR}" \
        --log-file "${NEGATIVE_LOG_DIR}/criu_restore.log" \
        --verbosity=4 \
        --tcp-established \
        --shell-job \
        --file-locks \
        --join-ns "net:${MIGRATION_NETNS_PATH}" \
        --external "veth[eth0]:veth-mig-neg@${FLANNEL_BRIDGE}" \
        2>&1 | tee "${NEGATIVE_LOG_DIR}/criu_restore_stdout.log" &

CRIU_RESTORE_PID=$!

# Poll for process existence (up to 10s)
RESTORED_PID=""
for i in $(seq 1 100); do
    sleep 0.1
    if [[ -f "${NEGATIVE_LOG_DIR}/client.pid" ]]; then
        CANDIDATE=$(cat "${NEGATIVE_LOG_DIR}/client.pid")
        if kill -0 "${CANDIDATE}" 2>/dev/null; then
            RESTORED_PID="${CANDIDATE}"
            break
        fi
    fi
    # Also check if CRIU restore process exited prematurely
    if ! kill -0 "${CRIU_RESTORE_PID}" 2>/dev/null; then
        break
    fi
done

wait "${CRIU_RESTORE_PID}" || true
RESTORE_END_NS=$(date +%s%N)
RESTORE_MS=$(( (RESTORE_END_NS - RESTORE_START_NS) / 1000000 ))
echo "[neg] CRIU restore elapsed: ${RESTORE_MS}ms"

if [[ -z "${RESTORED_PID}" ]]; then
    echo "[neg] ERROR: could not confirm restored process — check criu_restore.log"
    cat "${NEGATIVE_LOG_DIR}/criu_restore.log" 2>/dev/null | tail -20
fi

# ── 7. Wire veth-mig-neg to cni0 (return path) ───────────────────────────────
echo "[neg] wiring veth-mig-neg to ${FLANNEL_BRIDGE}"
MIG_MAC=$(ip netns exec "${MIGRATION_NETNS}" ip link show eth0 2>/dev/null \
    | awk '/link\/ether/{print $2}' || echo "")

if [[ -n "${MIG_MAC}" ]]; then
    ip link set veth-mig-neg master "${FLANNEL_BRIDGE}" 2>/dev/null || true
    ip link set veth-mig-neg up 2>/dev/null || true
    ip neigh replace "${POD_IP}" dev "${FLANNEL_BRIDGE}" lladdr "${MIG_MAC}" nud permanent
    ip route replace "${POD_IP}/32" dev "${FLANNEL_BRIDGE}"
    iptables -t raw -A PREROUTING -s "${POD_IP}" -j NOTRACK 2>/dev/null || true
    iptables -t raw -A PREROUTING -d "${POD_IP}" -j NOTRACK 2>/dev/null || true
    echo "[neg] return path wired: ${POD_IP} via ${FLANNEL_BRIDGE} lladdr ${MIG_MAC}"
else
    echo "[neg] WARNING: could not get eth0 MAC — CRIU may not have created veth-mig-neg yet"
    echo "[neg] Check: ip netns exec ${MIGRATION_NETNS} ip link show"
fi

# ── 8. Resume restored sender ─────────────────────────────────────────────────
RESUME_PID="${RESTORED_PID:-${CLIENT_PID}}"
if [[ -n "${RESUME_PID}" ]]; then
    kill -SIGUSR2 "${RESUME_PID}" 2>/dev/null && \
        echo "[neg] SIGUSR2 sent to ${RESUME_PID} — sender resuming" || true
fi

sleep 3  # observe traffic for 3s

# ── 9. Final stats and analysis ───────────────────────────────────────────────
# Kill restored process to flush final stats
[[ -n "${RESUME_PID}" ]] && kill -TERM "${RESUME_PID}" 2>/dev/null || true
sleep 0.5

echo ""
echo "[neg] === NEGATIVE TEST RESULT ==="
echo "[neg] unacked at dump time: ${UNACKED}"
echo "[neg] CRIU dump: ${DUMP_MS}ms  restore: ${RESTORE_MS}ms"
echo ""

FINAL="${NEGATIVE_LOG_DIR}/final_stats.json"
if [[ -f "${FINAL}" ]]; then
    python3 - << PYEOF
import json
with open("${FINAL}") as f:
    s = json.load(f)
errors = s.get('errors', 0)
gaps = s.get('gaps', [])
sent = s.get('sent', 0)
recv = s.get('received', 0)
print(f"  sent={sent}  received={recv}  errors={errors}  gaps={len(gaps)}")
if gaps:
    print("  [neg] GAPS DETECTED — ADR-0049 drain requirement VALIDATED:")
    for g in gaps[:10]:
        print(f"    {g}")
else:
    print("  [neg] NO GAPS — CRIU TCP_REPAIR handles retransmits transparently")
    print("  [neg] Finding: ADR-0049 drain requirement may be conservative")
    print("  [neg] Document this result; do NOT relax drain requirement without")
    print("  [neg] testing with higher unacked counts and real workloads.")
PYEOF
else
    echo "[neg] no final_stats.json — restored process may have exited early"
    echo "[neg] check: ${NEGATIVE_LOG_DIR}/client.log"
    tail -20 "${NEGATIVE_LOG_DIR}/client.log" 2>/dev/null || true
fi

echo ""
echo "[neg] socket state in migration netns:"
nsenter --net="${MIGRATION_NETNS_PATH}" ss -tin 2>/dev/null \
    | grep -A3 "${SERVER_IP}" || echo "  (no socket or netns gone)"

echo ""
echo "[neg] CRIU dump log tail:"
tail -5 "${NEGATIVE_LOG_DIR}/criu_dump.log" 2>/dev/null || true

echo ""
echo "[neg] CRIU restore log tail:"
tail -5 "${NEGATIVE_LOG_DIR}/criu_restore.log" 2>/dev/null || true

# ── Cleanup ───────────────────────────────────────────────────────────────────
[[ -n "${RESUME_PID}" ]] && kill -9 "${RESUME_PID}" 2>/dev/null || true
ip netns del "${MIGRATION_NETNS}" 2>/dev/null || true
ip link del veth-mig-neg 2>/dev/null || true
ip neigh del "${POD_IP}" dev "${FLANNEL_BRIDGE}" 2>/dev/null || true
ip route del "${POD_IP}/32" dev "${FLANNEL_BRIDGE}" 2>/dev/null || true
iptables -t raw -D PREROUTING -s "${POD_IP}" -j NOTRACK 2>/dev/null || true
iptables -t raw -D PREROUTING -d "${POD_IP}" -j NOTRACK 2>/dev/null || true

# Zeroize checkpoint images on exit
find "${CHECKPOINT_DIR}" -type f -exec shred -u {} \; 2>/dev/null || \
    rm -rf "${CHECKPOINT_DIR}"

echo "[neg] negative test complete"
