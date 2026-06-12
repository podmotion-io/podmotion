#!/usr/bin/env bash
# [PM-CONTROL] CRIU restore into the pre-staged migration netns.
#
# Uses --join-ns net:<netns_path> so the restored process inherits the
# migration netns (which has the source pod IP as primary address).
# This is the critical fix for Blocker 1 (--empty-ns net → --join-ns).
#
# The checkpoint image directory must have been scp'd from pm-worker first.
set -euo pipefail

LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
CHECKPOINT_DIR="${LOG_DIR}/checkpoint"
MIGRATION_NETNS="${MIGRATION_NETNS:-pm-migration}"
SOURCE_HOST="${SOURCE_HOST:-ubuntu@192.168.252.8}"

# Ensure checkpoint images are present
if [[ ! -d "${CHECKPOINT_DIR}" ]] || [[ -z "$(ls -A ${CHECKPOINT_DIR} 2>/dev/null)" ]]; then
    echo "[restore] FATAL: checkpoint dir empty — copying from pm-worker"
    mkdir -p "${CHECKPOINT_DIR}"
    chmod 0700 "${CHECKPOINT_DIR}"
    scp -r "${SOURCE_HOST}:${CHECKPOINT_DIR}/" "${LOG_DIR}/"
fi

NETNS_PATH="/var/run/netns/${MIGRATION_NETNS}"
if [[ ! -e "${NETNS_PATH}" ]]; then
    echo "[restore] FATAL: migration netns not found: ${NETNS_PATH}"
    echo "[restore] Run 04_stage_destnetns.sh first"
    exit 1
fi

echo "[restore] restoring into migration netns: ${NETNS_PATH}"
echo "[restore] checkpoint dir: ${CHECKPOINT_DIR}"

RESTORE_START_NS=$(date +%s%N)

# CRIU restore with --join-ns net:<netns_fd>
# The restored process will live in the migration netns with its original IP.
# --restore-detached: NOT used (ADR: causes ghost container)
# --tcp-established: required to restore the TCP sockets in repair mode
criu restore \
    --images-dir "${CHECKPOINT_DIR}" \
    --log-file "${LOG_DIR}/criu_restore.log" \
    --log-level 4 \
    --tcp-established \
    --shell-job \
    --file-locks \
    --join-ns "net:${NETNS_PATH}" \
    --detach \
    2>&1 | tee "${LOG_DIR}/criu_restore_stdout.log"

CRIU_EXIT=$?
RESTORE_END_NS=$(date +%s%N)
RESTORE_ELAPSED_MS=$(( (RESTORE_END_NS - RESTORE_START_NS) / 1000000 ))

if [[ ${CRIU_EXIT} -ne 0 ]]; then
    echo "[restore] FATAL: CRIU restore failed (exit ${CRIU_EXIT})"
    echo "[restore] CRIU restore log:"
    tail -50 "${LOG_DIR}/criu_restore.log"
    exit 1
fi

echo "[restore] CRIU restore complete in ${RESTORE_ELAPSED_MS}ms"
echo "${RESTORE_ELAPSED_MS}" > "${LOG_DIR}/criu_restore_ms"

# Find the restored process PID
sleep 0.2  # give criu a moment to write stats
RESTORED_PID=$(ip netns exec "${MIGRATION_NETNS}" \
    ss -tp 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1 || echo "")

if [[ -n "${RESTORED_PID}" ]]; then
    echo "[restore] restored process PID: ${RESTORED_PID}"
    echo "${RESTORED_PID}" > "${LOG_DIR}/restored_pid"
else
    # Try ps in the netns
    RESTORED_PID=$(ps aux | grep traffic_gen | grep -v grep | awk '{print $2}' | head -1 || echo "")
    echo "[restore] restored PID (from ps): ${RESTORED_PID}"
fi

# Verify the socket exists in the migration netns with the correct address
echo "[restore] verifying restored socket in migration netns:"
ip netns exec "${MIGRATION_NETNS}" ss -tin 2>/dev/null | grep -E "(State|10\.244)" || \
    echo "[restore] WARNING: no TCP sockets found in migration netns"

# Verify the pod IP is assigned in the migration netns
echo "[restore] verifying pod IP in migration netns:"
ip netns exec "${MIGRATION_NETNS}" ip addr show eth0 2>/dev/null | grep inet || \
    echo "[restore] WARNING: pod IP not found"

# Scp restore ms back to pm-worker for total freeze window calculation
echo "${RESTORE_ELAPSED_MS}" > "${LOG_DIR}/criu_restore_ms"

echo ""
echo "[restore] RESTORE COMPLETE"
echo "[restore] next: run 07_disarm.sh on PM-WORKER to release zero-window hold"
echo "[restore] IMPORTANT: do this as fast as possible to minimize freeze window"
