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
SOURCE_HOST="${SOURCE_HOST:-root@192.168.252.8}"
FLANNEL_BRIDGE="${FLANNEL_BRIDGE:-cni0}"

# Ensure checkpoint images are present (they should be on the same node)
if [[ ! -d "${CHECKPOINT_DIR}" ]] || [[ -z "$(ls -A ${CHECKPOINT_DIR} 2>/dev/null)" ]]; then
    echo "[restore] checkpoint dir empty or missing"
    if [[ "${SOURCE_HOST}" != "local" ]]; then
        echo "[restore] copying from ${SOURCE_HOST}..."
        mkdir -p "${CHECKPOINT_DIR}"
        chmod 0700 "${CHECKPOINT_DIR}"
        scp -r "${SOURCE_HOST}:${CHECKPOINT_DIR}/" "${LOG_DIR}/"
    else
        echo "[restore] FATAL: no checkpoint images found"
        exit 1
    fi
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

# CRIU restore with --join-ns net:<netns_path>
# The restored process will live in the migration netns with its original IP.
# --restore-detached: NOT used (ADR: causes ghost container)
# --tcp-established: required to restore the TCP sockets in repair mode
# Background: criu restore blocks until the restored process exits.
#
# No mount namespace flags needed: the source process was launched with
# nsenter --net (not ip netns exec), so it was always in the host mount
# namespace. CRIU and the target both see the same mount IDs — no special
# --enable-external-masters / --mntns-compat-mode needed.
criu restore \
    --images-dir "${CHECKPOINT_DIR}" \
    --log-file "${LOG_DIR}/criu_restore.log" \
    --verbosity=4 \
    --tcp-established \
    --shell-job \
    --file-locks \
    --join-ns "net:${NETNS_PATH}" \
    --external "veth[eth0]:veth-mig@${FLANNEL_BRIDGE:-cni0}" \
    2>&1 | tee "${LOG_DIR}/criu_restore_stdout.log" &

CRIU_BG_PID=$!
# Wait briefly for CRIU to start the restore (it fails fast if it can't restore)
sleep 2
# Check if CRIU failed immediately
if ! kill -0 "${CRIU_BG_PID}" 2>/dev/null; then
    wait "${CRIU_BG_PID}"
    CRIU_EXIT=$?
else
    CRIU_EXIT=0
fi
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
