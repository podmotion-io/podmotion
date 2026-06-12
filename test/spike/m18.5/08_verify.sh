#!/usr/bin/env bash
# [PM-WORKER + PM-CONTROL] Verify seq continuity and return path survival.
#
# Analyzes the tcpdump captures from both nodes and the traffic generator logs.
# Reports:
#   1. Traffic generator: 0 errors / 0 seq gaps
#   2. Source node tcpdump: seq numbers before/after migration (looking for discontinuity)
#   3. Destination node tcpdump: seq numbers arriving at pm-control (return path proof)
#   4. BPF trace pipe: relay observer confirmed seq numbers in both directions
#
# Pass criteria (ALL required):
#   [ ] Traffic generator errors == 0
#   [ ] Traffic generator seq gaps == 0
#   [ ] Source tcpdump: no RST segments after ZW disarm
#   [ ] Destination tcpdump: TCP segments arriving with expected seq range
#   [ ] BPF trace: seq numbers are continuous (no gap between pre-freeze and post-restore)
set -euo pipefail

LOG_DIR="${LOG_DIR:-/tmp/pm-spike}"
DEST_HOST="${DEST_HOST:-ubuntu@192.168.252.7}"
POD_IP="${POD_IP:-10.244.1.50}"

echo "========================================================"
echo " M18.5 Spike Verification Report"
echo "========================================================"
echo ""

# ── Fetch captures from pm-control ───────────────────────────────────────────
echo "[verify] fetching destination captures from pm-control..."
scp "${DEST_HOST}:${LOG_DIR}/capture_dest.pcap" "${LOG_DIR}/capture_dest.pcap" 2>/dev/null || \
    echo "[verify] WARNING: could not fetch capture_dest.pcap — run tcpdump on pm-control first"

# ── Stop captures ─────────────────────────────────────────────────────────────
if [[ -f "${LOG_DIR}/tcpdump_source.pid" ]]; then
    kill "$(cat ${LOG_DIR}/tcpdump_source.pid)" 2>/dev/null || true
    echo "[verify] source tcpdump stopped"
fi

# ── Traffic generator result ──────────────────────────────────────────────────
echo ""
echo "── Traffic Generator ──────────────────────────────────"
FINAL_STATS="${LOG_DIR}/final_stats.json"
if [[ -f "${FINAL_STATS}" ]]; then
    python3 - << PYEOF
import json
with open("${FINAL_STATS}") as f:
    s = json.load(f)
print(f"  sent:          {s['sent']}")
print(f"  received:      {s['received']}")
print(f"  errors:        {s['errors']}")
print(f"  seq gaps:      {len(s['gaps'])}")
if s['gaps']:
    for g in s['gaps'][:10]:
        print(f"    GAP: {g}")
if s['errors'] == 0 and len(s['gaps']) == 0:
    print("")
    print("  RESULT: PASS — 0 errors, 0 seq gaps")
else:
    print("")
    print("  RESULT: FAIL — errors or seq gaps detected")
PYEOF
else
    echo "  [no final_stats.json — traffic generator may still be running]"
    echo "  live stats from client.log:"
    tail -10 "${LOG_DIR}/client.log" | grep "\[traffic\]" || echo "  (no output)"
fi

# ── TCP RST analysis (source node capture) ────────────────────────────────────
echo ""
echo "── Source Node tcpdump: RST Analysis ──────────────────"
if command -v tcpdump &>/dev/null && [[ -f "${LOG_DIR}/capture_source.pcap" ]]; then
    RST_COUNT=$(tcpdump -r "${LOG_DIR}/capture_source.pcap" 'tcp[tcpflags] & tcp-rst != 0' 2>/dev/null | wc -l)
    echo "  RST segments in source capture: ${RST_COUNT}"
    if [[ "${RST_COUNT}" -eq 0 ]]; then
        echo "  RESULT: PASS — no RSTs"
    else
        echo "  RESULT: FAIL — RST segments detected (connection was reset)"
        tcpdump -r "${LOG_DIR}/capture_source.pcap" 'tcp[tcpflags] & tcp-rst != 0' 2>/dev/null | head -10
    fi
else
    echo "  [no source pcap available]"
fi

# ── Seq continuity analysis ───────────────────────────────────────────────────
echo ""
echo "── Seq Continuity Analysis ─────────────────────────────"
if command -v tcpdump &>/dev/null && [[ -f "${LOG_DIR}/capture_source.pcap" ]]; then
    python3 - << PYEOF
import subprocess, re, sys

pcap = "${LOG_DIR}/capture_source.pcap"
pod_ip = "${POD_IP}"

# Extract seq/ack from source capture for the pod's connection
cmd = ["tcpdump", "-r", pcap, "-n", "-t", f"host {pod_ip}", "-A"]
try:
    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
except Exception as e:
    print(f"  [tcpdump error: {e}]")
    sys.exit(0)

seqs = []
for line in out.splitlines():
    m = re.search(r'seq (\d+):(\d+)', line)
    if m:
        seqs.append((int(m.group(1)), int(m.group(2))))

if not seqs:
    print("  [no seq data extracted — try: tcpdump -r capture_source.pcap -nn host ${POD_IP}]")
    sys.exit(0)

print(f"  TCP segments observed: {len(seqs)}")
print(f"  seq range: {seqs[0][0]} → {seqs[-1][1]}")

# Check for gaps
gaps = 0
for i in range(1, len(seqs)):
    if seqs[i][0] != seqs[i-1][1]:
        gap = seqs[i][0] - seqs[i-1][1]
        if abs(gap) > 0:
            gaps += 1
            print(f"  SEQ GAP at segment {i}: expected {seqs[i-1][1]} got {seqs[i][0]} (delta={gap})")

if gaps == 0:
    print("  RESULT: PASS — seq is continuous, no gaps")
else:
    print(f"  RESULT: FAIL — {gaps} seq gaps detected")
PYEOF
fi

# ── Return path verification (destination node capture) ───────────────────────
echo ""
echo "── Return Path: Destination Node tcpdump ───────────────"
if [[ -f "${LOG_DIR}/capture_dest.pcap" ]]; then
    python3 - << PYEOF
import subprocess, sys

pcap = "${LOG_DIR}/capture_dest.pcap"
pod_ip = "${POD_IP}"

cmd = ["tcpdump", "-r", pcap, "-n", "-t", f"host {pod_ip}", "--count"]
try:
    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
    count = int(out.strip()) if out.strip().isdigit() else -1
except:
    # Non-count version
    try:
        out = subprocess.check_output(["tcpdump", "-r", pcap, "-nn", f"host {pod_ip}"],
                                       stderr=subprocess.DEVNULL).decode()
        count = len([l for l in out.splitlines() if pod_ip in l])
    except Exception as e:
        print(f"  [error: {e}]")
        sys.exit(0)

if count > 0:
    print(f"  TCP segments to/from {pod_ip} seen on destination: {count}")
    print("  RESULT: PASS — return path confirmed, traffic reached pm-control")
else:
    print(f"  NO segments for {pod_ip} on destination")
    print("  RESULT: FAIL — return path black-holed (check FDB injection)")
PYEOF
else
    echo "  [no destination capture — start: tcpdump -i flannel.1 -w ${LOG_DIR}/capture_dest.pcap on pm-control]"
fi

# ── BPF relay observer ────────────────────────────────────────────────────────
echo ""
echo "── BPF Relay Observer (seq from trace_pipe) ────────────"
if [[ -f "${LOG_DIR}/bpf_trace.txt" ]]; then
    echo "  seq observations (first 10):"
    head -10 "${LOG_DIR}/bpf_trace.txt"
    echo "  total observations: $(wc -l < ${LOG_DIR}/bpf_trace.txt)"
else
    echo "  [no bpf_trace.txt — during restore, run on pm-control:]"
    echo "  cat /sys/kernel/debug/tracing/trace_pipe | grep pm-relay > ${LOG_DIR}/bpf_trace.txt &"
fi

# ── Freeze window summary ─────────────────────────────────────────────────────
echo ""
echo "── Freeze Window Summary ───────────────────────────────"
FULL_FREEZE_MS=$(cat "${LOG_DIR}/full_freeze_ms" 2>/dev/null || echo "?")
CRIU_DUMP_MS=$(cat "${LOG_DIR}/criu_dump_ms"       2>/dev/null || echo "?")
CRIU_RESTORE_MS=$(cat "${LOG_DIR}/criu_restore_ms" 2>/dev/null || echo "?")
echo "  Full freeze window (ZW-arm → ZW-disarm): ${FULL_FREEZE_MS}ms"
echo "  CRIU dump time:    ${CRIU_DUMP_MS}ms"
echo "  CRIU restore time: ${CRIU_RESTORE_MS}ms"
echo "  NS#4 target:       <500ms"
if [[ "${FULL_FREEZE_MS}" != "?" ]] && (( FULL_FREEZE_MS < 500 )); then
    echo "  RESULT: PASS (${FULL_FREEZE_MS}ms < 500ms)"
elif [[ "${FULL_FREEZE_MS}" != "?" ]]; then
    echo "  RESULT: FAIL (${FULL_FREEZE_MS}ms >= 500ms — budget exceeded)"
fi

echo ""
echo "========================================================"
echo " Summary"
echo "========================================================"
