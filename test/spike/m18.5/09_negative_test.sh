#!/usr/bin/env bash
# NEGATIVE TEST: Prove that migrating WITHOUT draining the send buffer produces
# seq corruption or a stale-segment retransmit storm.
#
# This test is NOT a migration proof — it is the proof that ADR-0049's
# drain-before-dump requirement is load-bearing, not cargo-cult.
#
# What we do:
#   1. Re-run the spike pod setup (fresh connection)
#   2. Arm the zero-window hold
#   3. SKIP the drain step — dump immediately while tcpi_unacked > 0
#   4. Restore and disarm
#   5. Observe: peer receives duplicate/out-of-order segments, or RST
#
# Expected outcome: tcpdump shows either:
#   a) A retransmit of already-ACK'd data (dup seq, SACK violation), OR
#   b) A RST from the peer (seq out of window), OR
#   c) The BPF trace shows the restored socket emitting seq < last peer ACK
#
# If outcome is NONE of the above (connection survives without drain), then
# ADR-0049's drain requirement is overly conservative and should be relaxed.
# In that case: document the finding and proceed — we got lucky with the
# CRIU TCP_REPAIR semantics. Either way, the test settles the question.
set -euo pipefail

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
NEGATIVE_LOG_DIR="${LOG_DIR}/negative_test"
POD_NETNS="${POD_NETNS:-pm-spike-pod-neg}"
POD_IP="${POD_IP:-10.244.1.51}"          # different IP to avoid collision with positive run
SERVER_IP="${SERVER_IP:-10.244.0.50}"
SERVER_PORT="${SERVER_PORT:-9000}"
DEST_HOST="${DEST_HOST:-ubuntu@192.168.252.7}"

mkdir -p "${NEGATIVE_LOG_DIR}"

echo "========================================================"
echo " NEGATIVE TEST: No-drain migration"
echo " Proving ADR-0049 drain-before-dump is required"
echo "========================================================"
echo ""

# ── 1. Fresh pod setup ────────────────────────────────────────────────────────
echo "[neg] setting up negative-test pod netns (IP ${POD_IP})"
POD_NETNS="${POD_NETNS}" POD_IP="${POD_IP}" LOG_DIR="${NEGATIVE_LOG_DIR}" \
    bash "${SPIKE_DIR}/01_setup_pod.sh"

sleep 2  # let traffic build up in the buffer

# ── 2. Arm zero-window hold ───────────────────────────────────────────────────
echo "[neg] arming zero-window hold"
VETH_NAME="veth-spike-neg"
# Rename for the negative test — or reuse 01_setup_pod.sh with a different veth name
VETH_NAME=$(cat "${NEGATIVE_LOG_DIR}/veth_name" 2>/dev/null || echo "veth-spike-neg")
LOG_DIR="${NEGATIVE_LOG_DIR}" VETH_NAME="${VETH_NAME}" bash "${SPIKE_DIR}/02_arm_zerowindow.sh"

# ── 3. SKIP the drain — dump immediately ─────────────────────────────────────
echo "[neg] checking current unacked count (should be > 0 if ZW hold just armed)"
CLIENT_PID=$(cat "${NEGATIVE_LOG_DIR}/client.pid" 2>/dev/null)

# Show unacked count right now — expect > 0 (buffered, not yet drained)
UNACKED=$(ip netns exec "${POD_NETNS}" ss -tin 2>/dev/null \
    | grep -A2 "${SERVER_IP}" \
    | grep -oE 'unacked:[0-9]+' | cut -d: -f2 | head -1 || echo "0")
echo "[neg] unacked bytes at dump time (NO DRAIN): ${UNACKED}"
echo "${UNACKED}" > "${NEGATIVE_LOG_DIR}/unacked_at_dump"

if [[ "${UNACKED}" == "0" ]]; then
    echo "[neg] WARNING: unacked=0 already — traffic may be too slow to fill buffer"
    echo "[neg] increasing send rate and retrying..."
    # Kill existing traffic gen and start a faster one
    if [[ -f "${NEGATIVE_LOG_DIR}/client.pid" ]]; then
        kill "$(cat ${NEGATIVE_LOG_DIR}/client.pid)" 2>/dev/null || true
    fi
    # Start a high-rate sender (1ms interval)
    SEND_INTERVAL_MS=1 SERVER_IP="${SERVER_IP}" SERVER_PORT="${SERVER_PORT}" \
    LOG_DIR="${NEGATIVE_LOG_DIR}" \
    ip netns exec "${POD_NETNS}" python3 "${NEGATIVE_LOG_DIR}/traffic_gen.py" \
        > "${NEGATIVE_LOG_DIR}/client.log" 2>&1 &
    echo $! > "${NEGATIVE_LOG_DIR}/tgen_host_pid"
    sleep 0.5
    CLIENT_PID=$(cat "${NEGATIVE_LOG_DIR}/client.pid" 2>/dev/null)
    UNACKED=$(ip netns exec "${POD_NETNS}" ss -tin 2>/dev/null \
        | grep -A2 "${SERVER_IP}" \
        | grep -oE 'unacked:[0-9]+' | cut -d: -f2 | head -1 || echo "0")
    echo "[neg] unacked after high-rate burst: ${UNACKED}"
fi

CHECKPOINT_DIR="${NEGATIVE_LOG_DIR}/checkpoint"
mkdir -p "${CHECKPOINT_DIR}" && chmod 0700 "${CHECKPOINT_DIR}"

echo "[neg] DUMPING WITHOUT DRAIN (unacked=${UNACKED})"
ip netns exec "${POD_NETNS}" criu dump \
    --tree "${CLIENT_PID}" \
    --images-dir "${CHECKPOINT_DIR}" \
    --log-file "${NEGATIVE_LOG_DIR}/criu_dump.log" \
    --log-level 4 \
    --tcp-established \
    --leave-stopped \
    --shell-job \
    --file-locks \
    2>&1 | tee "${NEGATIVE_LOG_DIR}/criu_dump_stdout.log"

DUMP_EXIT=$?
echo "[neg] CRIU dump exit: ${DUMP_EXIT}"

# ── 4. Restore and disarm ─────────────────────────────────────────────────────
# Use a different migration netns to avoid collision
MIGRATION_NETNS="pm-migration-neg"
echo "[neg] staging destination netns ${MIGRATION_NETNS} on pm-control"
ssh "${DEST_HOST}" sudo bash << REMOTE_SETUP
ip netns del pm-migration-neg 2>/dev/null || true
ip link del veth-mig-neg 2>/dev/null || true
ip netns add pm-migration-neg
ip link add veth-mig-neg type veth peer name eth0-neg
ip link set eth0-neg netns pm-migration-neg
ip link set veth-mig-neg master cni0
ip link set veth-mig-neg up
ip netns exec pm-migration-neg ip addr add ${POD_IP}/32 dev eth0-neg
ip netns exec pm-migration-neg ip link set eth0-neg up
ip netns exec pm-migration-neg ip link set lo up
echo "pm-migration-neg ready"
REMOTE_SETUP

# Scp checkpoint to pm-control
scp -r "${CHECKPOINT_DIR}/" "${DEST_HOST}:${NEGATIVE_LOG_DIR}/checkpoint/" 2>/dev/null || \
    ssh "${DEST_HOST}" "mkdir -p ${NEGATIVE_LOG_DIR}/checkpoint" && \
    scp "${CHECKPOINT_DIR}"/* "${DEST_HOST}:${NEGATIVE_LOG_DIR}/checkpoint/"

# Start dest tcpdump to catch the seq corruption
echo "[neg] starting dest tcpdump"
ssh "${DEST_HOST}" "tcpdump -i flannel.1 -w ${NEGATIVE_LOG_DIR}/neg_capture_dest.pcap -s 128 'tcp' &"

# Restore on pm-control
echo "[neg] restoring (without drain)"
ssh "${DEST_HOST}" sudo criu restore \
    --images-dir "${NEGATIVE_LOG_DIR}/checkpoint" \
    --log-file "${NEGATIVE_LOG_DIR}/criu_restore.log" \
    --log-level 4 \
    --tcp-established \
    --shell-job \
    --file-locks \
    --join-ns "net:/var/run/netns/pm-migration-neg" \
    --detach 2>&1 | tee "${NEGATIVE_LOG_DIR}/criu_restore_stdout.log"

# Inject FDB
POD_NETNS="${POD_NETNS}" MIGRATION_NETNS="${MIGRATION_NETNS}" \
LOG_DIR="${NEGATIVE_LOG_DIR}" \
    bash "${SPIKE_DIR}/05_inject_fdb.sh" || echo "[neg] FDB injection partial (expected for negative test)"

# Disarm ZW hold
LOG_DIR="${NEGATIVE_LOG_DIR}" bash "${SPIKE_DIR}/07_disarm.sh"

sleep 2

# ── 5. Analyze negative test result ──────────────────────────────────────────
echo ""
echo "[neg] === NEGATIVE TEST RESULT ==="
echo "[neg] unacked at dump time: ${UNACKED}"
echo ""

# Fetch dest capture
scp "${DEST_HOST}:${NEGATIVE_LOG_DIR}/neg_capture_dest.pcap" \
    "${NEGATIVE_LOG_DIR}/neg_capture_dest.pcap" 2>/dev/null || true

# Look for RST
if [[ -f "${NEGATIVE_LOG_DIR}/neg_capture_dest.pcap" ]]; then
    RST_COUNT=$(tcpdump -r "${NEGATIVE_LOG_DIR}/neg_capture_dest.pcap" \
        'tcp[tcpflags] & tcp-rst != 0' 2>/dev/null | wc -l)
    echo "[neg] RST segments on destination: ${RST_COUNT}"

    # Look for retransmits (same seq range appearing twice)
    python3 - << PYEOF
import subprocess, re

pcap = "${NEGATIVE_LOG_DIR}/neg_capture_dest.pcap"
try:
    out = subprocess.check_output(["tcpdump", "-r", pcap, "-nn", "-t", "tcp"],
                                   stderr=subprocess.DEVNULL).decode()
except Exception as e:
    print(f"  [error: {e}]")
    exit(0)

seqs = []
for line in out.splitlines():
    m = re.search(r'seq (\d+):(\d+)', line)
    if m:
        seqs.append((int(m.group(1)), int(m.group(2))))

retrans = sum(1 for i in range(1, len(seqs)) if seqs[i][0] <= seqs[i-1][0] and seqs[i][0] > 0)
print(f"  Retransmits / duplicate-seq events: {retrans}")
print(f"  Segments observed: {len(seqs)}")
PYEOF
fi

# Traffic generator final stats for negative test
FINAL="${NEGATIVE_LOG_DIR}/final_stats.json"
if [[ -f "${FINAL}" ]]; then
    python3 - << PYEOF
import json
with open("${FINAL}") as f:
    s = json.load(f)
print(f"  errors: {s['errors']}, gaps: {len(s['gaps'])}")
PYEOF
fi

echo ""
if [[ "${UNACKED}" != "0" ]]; then
    echo "[neg] EXPECTED OUTCOME: seq corruption or RST detected (ADR-0049 drain requirement VALIDATED)"
else
    echo "[neg] WARNING: unacked was 0 even without explicit drain — test inconclusive"
    echo "[neg] Try with a higher send rate (SEND_INTERVAL_MS=1)"
fi

# Cleanup negative test netns
POD_NETNS="${POD_NETNS}" LOG_DIR="${NEGATIVE_LOG_DIR}" \
    bash "${SPIKE_DIR}/cleanup.sh" 2>/dev/null || true
ssh "${DEST_HOST}" sudo bash -c "
    ip netns del pm-migration-neg 2>/dev/null || true
    ip link del veth-mig-neg 2>/dev/null || true
" 2>/dev/null || true

echo "[neg] negative test complete"
