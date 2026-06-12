#!/usr/bin/env bash
# [PM-WORKER] Disarm the zero-window hold.
#
# Removes the TC-BPF zero_window filter from the source veth egress.
# The peer's TCP sender immediately resumes (it has been in window-probe state).
# Traffic now flows toward the destination (pm-control migration netns) via FDB.
#
# This is the last step before ZW disarm — all of A–F from ADR-0049 must be
# confirmed before calling this script.
set -euo pipefail

LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
VETH_NAME=$(cat "${LOG_DIR}/veth_name" 2>/dev/null || echo "veth-spike")

FREEZE_START_NS=$(cat "${LOG_DIR}/freeze_start_ns" 2>/dev/null || echo "0")

echo "[disarm] removing zero-window hold from ${VETH_NAME} TC egress"
tc filter del dev "${VETH_NAME}" egress 2>/dev/null || true
tc qdisc del dev "${VETH_NAME}" clsact 2>/dev/null || true

DISARM_NS=$(date +%s%N)
echo "${DISARM_NS}" > "${LOG_DIR}/disarm_ns"

if [[ "${FREEZE_START_NS}" != "0" ]]; then
    FULL_FREEZE_MS=$(( (DISARM_NS - FREEZE_START_NS) / 1000000 ))
    echo "[disarm] FULL FREEZE WINDOW (ZW-arm to ZW-disarm): ${FULL_FREEZE_MS}ms"
    echo "${FULL_FREEZE_MS}" > "${LOG_DIR}/full_freeze_ms"

    # Component breakdown
    CRIU_DUMP_MS=$(cat "${LOG_DIR}/criu_dump_ms" 2>/dev/null || echo "?")
    CRIU_RESTORE_MS=$(cat "${LOG_DIR}/criu_restore_ms" 2>/dev/null || echo "?")
    echo "[disarm] breakdown: criu_dump=${CRIU_DUMP_MS}ms criu_restore=${CRIU_RESTORE_MS}ms"
    echo "[disarm] overhead (FDB+NOTRACK+RTT): $(( FULL_FREEZE_MS - ${CRIU_DUMP_MS:-0} - ${CRIU_RESTORE_MS:-0} ))ms"
fi

echo "[disarm] zero-window hold DISARMED — peer sender will resume within 1 RTT"

# Resume the (possibly paused) restored process sender thread via SIGUSR2
RESTORED_PID=$(cat "${LOG_DIR}/restored_pid" 2>/dev/null || echo "")
CLIENT_PID=$(cat "${LOG_DIR}/client.pid" 2>/dev/null || echo "")
RESUME_PID="${RESTORED_PID:-${CLIENT_PID}}"
if [[ -n "${RESUME_PID}" ]]; then
    kill -SIGUSR2 "${RESUME_PID}" 2>/dev/null && echo "[disarm] SIGUSR2 sent to ${RESUME_PID} — sender resuming" || true
fi

echo ""
echo "[disarm] proceed to: 08_verify.sh to check seq continuity"
