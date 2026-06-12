#!/usr/bin/env bash
# [PM-WORKER] Wait for TCP send buffer to drain, then CRIU checkpoint.
#
# ADR-0049 requires: tcpi_unacked == 0 on ALL migrated sockets before CRIU dump.
# Reason: if the send buffer contains unACK'd bytes when CRIU dumps, the relay's
# seq_delta will be wrong (or, for the spike where seq_delta=0, the restored socket
# will try to retransmit bytes the peer has already received — silent corruption).
#
# CRIU flags:
#   --tcp-established   dump TCP sockets in repair mode (preserves seq/ack exactly)
#   --leave-stopped     leave source process in SIGSTOP after dump (do NOT resume)
#   --file-locks        preserve file descriptor state
#   --shell-job         allow checkpointing processes in a shell session
#
# After this script completes:
#   - Source process is FROZEN (SIGSTOP, not killed)
#   - Checkpoint image is in /tmp/pm-spike/checkpoint/
#   - Source pod IP is still on veth-spike on pm-worker
set -euo pipefail

LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
POD_NETNS="${POD_NETNS:-pm-spike-pod}"
CHECKPOINT_DIR="${LOG_DIR}/checkpoint"
DRAIN_TIMEOUT_MS="${DRAIN_TIMEOUT_MS:-5000}"   # 5s max drain wait (half of 10s budget)

mkdir -p "${CHECKPOINT_DIR}"
chmod 0700 "${CHECKPOINT_DIR}"

CLIENT_PID=$(cat "${LOG_DIR}/client.pid" 2>/dev/null)
if [[ -z "${CLIENT_PID}" ]]; then
    echo "[checkpoint] FATAL: client.pid not found — run 01_setup_pod.sh first"
    exit 1
fi

echo "[checkpoint] target PID: ${CLIENT_PID} in netns ${POD_NETNS}"

# ── Step 1: poll for send buffer drain ───────────────────────────────────────
# getsockopt(TCP_INFO) via ss --extended shows tcpi_unacked in 'bytes_acked' context.
# We use `ss -tin` and parse the 'unacked:' field directly.
echo "[checkpoint] waiting for send buffer to drain (tcpi_unacked == 0)..."
echo "[checkpoint] max wait: ${DRAIN_TIMEOUT_MS}ms"

DRAIN_START_NS=$(date +%s%N)
DRAIN_DEADLINE_NS=$(( DRAIN_START_NS + DRAIN_TIMEOUT_MS * 1000000 ))

DRAINED=false
while true; do
    NOW_NS=$(date +%s%N)
    if (( NOW_NS > DRAIN_DEADLINE_NS )); then
        echo "[checkpoint] FATAL: send buffer did not drain within ${DRAIN_TIMEOUT_MS}ms"
        echo "[checkpoint] ss output:"
        ip netns exec "${POD_NETNS}" ss -tin 2>/dev/null | grep -A5 "10.244.0.50" || true
        echo ""
        echo "[checkpoint] This means the zero-window hold is not stalling the SENDER."
        echo "[checkpoint] Check 02_arm_zerowindow.sh ran correctly."
        exit 1
    fi

    # Parse 'unacked:N' from ss output for our connection
    UNACKED=$(ip netns exec "${POD_NETNS}" ss -tin 2>/dev/null \
        | grep -A2 "10.244.0.50" \
        | grep -oE 'unacked:[0-9]+' | cut -d: -f2 | head -1)

    if [[ "${UNACKED}" == "0" ]] || [[ -z "${UNACKED}" ]]; then
        ELAPSED_MS=$(( ($(date +%s%N) - DRAIN_START_NS) / 1000000 ))
        echo "[checkpoint] send buffer drained in ${ELAPSED_MS}ms (unacked=0)"
        DRAINED=true
        break
    fi

    echo "[checkpoint] waiting... unacked=${UNACKED}"
    sleep 0.05
done

# Record the freeze timestamp (wall clock) — used to measure full freeze window duration
FREEZE_START_NS=$(date +%s%N)
echo "${FREEZE_START_NS}" > "${LOG_DIR}/freeze_start_ns"
echo "[checkpoint] freeze window start: ${FREEZE_START_NS} ns"

# ── Step 2: CRIU dump ─────────────────────────────────────────────────────────
echo "[checkpoint] starting CRIU dump of PID ${CLIENT_PID}"
echo "[checkpoint] checkpoint dir: ${CHECKPOINT_DIR}"

# Flush checkpoint dir
rm -f "${CHECKPOINT_DIR}"/*.img "${CHECKPOINT_DIR}"/*.json 2>/dev/null || true

# CRIU dump inside the pod's netns context.
# We use ip netns exec to run CRIU inside the pod's network namespace so that
# socket FDs resolve correctly.
ip netns exec "${POD_NETNS}" criu dump \
    --tree "${CLIENT_PID}" \
    --images-dir "${CHECKPOINT_DIR}" \
    --log-file "${LOG_DIR}/criu_dump.log" \
    --log-level 4 \
    --tcp-established \
    --leave-stopped \
    --shell-job \
    --file-locks \
    --track-mem \
    2>&1 | tee "${LOG_DIR}/criu_dump_stdout.log"

CRIU_EXIT=$?
if [[ ${CRIU_EXIT} -ne 0 ]]; then
    echo "[checkpoint] FATAL: CRIU dump failed (exit ${CRIU_EXIT})"
    echo "[checkpoint] CRIU log:"
    tail -40 "${LOG_DIR}/criu_dump.log"
    exit 1
fi

DUMP_END_NS=$(date +%s%N)
DUMP_ELAPSED_MS=$(( (DUMP_END_NS - FREEZE_START_NS) / 1000000 ))
echo "[checkpoint] CRIU dump complete in ${DUMP_ELAPSED_MS}ms"
echo "${DUMP_ELAPSED_MS}" > "${LOG_DIR}/criu_dump_ms"

# ── Step 3: extract seq/ack from CRIU images (verify TCP_REPAIR preserved state) ──
# CRIU image files are protobuf; use criu's own --output-format json if available,
# otherwise use the binary inspect tool.
echo "[checkpoint] extracting TCP socket state from CRIU image"
criu inspect \
    --images-dir "${CHECKPOINT_DIR}" \
    --show-dump 2>/dev/null \
    | grep -E "(tcp|sk_ino|src_port|dst_port|seq|ack)" \
    | tee "${LOG_DIR}/criu_tcp_state.txt" || true

# Alternatively, look for tcp*.img files
ls -la "${CHECKPOINT_DIR}"/tcp* 2>/dev/null || echo "[checkpoint] no tcp*.img files found (check CRIU version)"

echo ""
echo "[checkpoint] CHECKPOINT COMPLETE"
echo "[checkpoint] source process is FROZEN (SIGSTOP, not killed)"
echo "[checkpoint] verify: kill -0 ${CLIENT_PID} && echo 'process alive but frozen'"
kill -0 "${CLIENT_PID}" 2>/dev/null && echo "[checkpoint] confirmed: process ${CLIENT_PID} still exists (frozen)" || echo "[checkpoint] WARNING: process gone"

echo ""
echo "[checkpoint] next step: run 04_stage_destnetns.sh on PM-CONTROL"
echo "[checkpoint] CRIU dump elapsed: ${DUMP_ELAPSED_MS}ms"
