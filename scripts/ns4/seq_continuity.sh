#!/usr/bin/env bash
# scripts/ns4/seq_continuity.sh
#
# Analyse peer-side seq/ack progression across the handoff timestamp to verify
# TCP sequence continuity for NS#4 PostgreSQL migrations.
#
# What it checks (per TCP flow on port 5432):
#   a) No sequence gap between the last pre-handoff segment and the first
#      post-handoff segment (within one MSS of tolerance — retransmits OK).
#   b) Zero RST segments on pgbench flows after ZW-disarm.
#   c) Illegal seq regressions (> MSS) that would indicate relay rewrite errors.
#
# Usage:
#   ZW_DISARM_TS="2026-06-11T10:00:01.345678901Z" \
#   PCAP=./captures/ns4/pm-control-flannel1.pcap \
#     ./scripts/ns4/seq_continuity.sh
#
#   # Restrict analysis to flows involving a specific pod IP:
#   POD_IP=10.244.1.50 ZW_DISARM_TS=... PCAP=... ./scripts/ns4/seq_continuity.sh
#
# Environment variables:
#   PCAP           Path to pcap file (required)
#   ZW_DISARM_TS   RFC3339Nano timestamp of ZeroWindowDisarmed event (required)
#   POD_IP         Source pod IP; when set only flows involving this IP are checked
#   MSS            Maximum Segment Size tolerance for gap detection (default: 1460)
#   PORT           TCP port to filter on (default: 5432)
#
# Dependencies: tshark, python3, awk
#
# Exit codes:
#   0  seq continuity confirmed — no gap, no RST, no illegal regression
#   1  one or more continuity violations found

set -euo pipefail

PCAP="${PCAP:-}"
ZW_DISARM_TS="${ZW_DISARM_TS:-}"
POD_IP="${POD_IP:-}"
MSS="${MSS:-1460}"
PORT="${PORT:-5432}"

error() { echo "[ERROR] $*" >&2; }
info()  { echo "[INFO]  $*"; }

if [[ -z "$PCAP" ]]; then
    error "PCAP must be set to the path of the peer-side pcap file"
    exit 1
fi

if [[ ! -f "$PCAP" ]]; then
    error "pcap file not found: $PCAP"
    exit 1
fi

if [[ -z "$ZW_DISARM_TS" ]]; then
    error "ZW_DISARM_TS must be set to the ZeroWindowDisarmed RFC3339Nano timestamp"
    exit 1
fi

require_cmd() {
    if ! command -v "$1" &>/dev/null; then
        error "required command not found: $1"
        exit 1
    fi
}

require_cmd tshark
require_cmd python3

# Convert ZW_DISARM_TS to Unix epoch (decimal seconds, nanosecond precision).
ZW_DISARM_EPOCH=$(python3 -c "
import sys, datetime
s = '${ZW_DISARM_TS}'.rstrip('Z')
if '.' in s:
    base, frac = s.split('.', 1)
    frac = (frac + '0' * 9)[:9]
    dt = datetime.datetime.strptime(base + '.' + frac[:6], '%Y-%m-%dT%H:%M:%S.%f')
    extra_ns = int(frac[6:]) if len(frac) > 6 else 0
else:
    dt = datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S')
    extra_ns = 0
epoch = datetime.datetime(1970, 1, 1)
total_ns = int((dt - epoch).total_seconds() * 1_000_000_000) + extra_ns
print(f'{total_ns / 1_000_000_000:.9f}')
")

info "ZW-disarm epoch: $ZW_DISARM_EPOCH"
info "pcap: $PCAP"
info "port: $PORT  pod_ip: ${POD_IP:-<any>}  MSS tolerance: $MSS"

# Build tshark display filter.
TSHARK_FILTER="tcp.port == ${PORT}"
if [[ -n "$POD_IP" ]]; then
    TSHARK_FILTER="${TSHARK_FILTER} && (ip.src == ${POD_IP} || ip.dst == ${POD_IP})"
fi

# Extract per-packet fields as CSV.
TSHARK_OUT=$(tshark -r "$PCAP" -Y "$TSHARK_FILTER" \
    -T fields \
    -e frame.time_epoch \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e tcp.seq \
    -e tcp.ack \
    -e tcp.flags.reset \
    -e tcp.len \
    -E separator=, 2>/dev/null)

if [[ -z "$TSHARK_OUT" ]]; then
    error "no packets matched filter '$TSHARK_FILTER' in $PCAP"
    exit 1
fi

PKTCOUNT=$(echo "$TSHARK_OUT" | wc -l | tr -d ' ')
info "extracted $PKTCOUNT packets matching filter"

# Run continuity analysis in Python for numeric precision and 32-bit seq wrap.
STATUS=0
python3 -c "
import sys, csv, io, collections

disarm_epoch = float('${ZW_DISARM_EPOCH}')
mss = int('${MSS}')
lines = '''${TSHARK_OUT}'''

class FlowData:
    def __init__(self):
        self.pre_seqs  = []
        self.post_seqs = []

flows = {}

for row in csv.reader(io.StringIO(lines)):
    if len(row) < 9:
        continue
    try:
        epoch    = float(row[0])
        src_ip   = row[1].strip()
        dst_ip   = row[2].strip()
        src_port = int(row[3].strip())
        dst_port = int(row[4].strip())
        seq      = int(row[5].strip())
        is_rst   = row[7].strip() == '1'
        pkt_len  = int(row[8].strip()) if row[8].strip() else 0
    except (ValueError, IndexError):
        continue

    key = (src_ip, dst_ip, src_port, dst_port)
    if key not in flows:
        flows[key] = FlowData()

    entry = (epoch, seq, pkt_len, is_rst)
    if epoch < disarm_epoch:
        flows[key].pre_seqs.append(entry)
    else:
        flows[key].post_seqs.append(entry)

total_pass = 0
total_fail = 0

for key, fd in flows.items():
    src_ip, dst_ip, src_port, dst_port = key
    label = f'{src_ip}:{src_port} -> {dst_ip}:{dst_port}'

    rst_post = [e for e in fd.post_seqs if e[3]]
    if rst_post:
        print(f'[FAIL]  {label}: {len(rst_post)} RST segment(s) after ZW-disarm')
        total_fail += 1
    else:
        print(f'[PASS]  {label}: zero RST after ZW-disarm')
        total_pass += 1

    if not fd.pre_seqs or not fd.post_seqs:
        side = 'pre' if fd.pre_seqs else 'post'
        print(f'[INFO]  {label}: only {side}-disarm packets; skip gap check')
        continue

    pre_sorted  = sorted(fd.pre_seqs,  key=lambda x: x[0])
    post_sorted = sorted(fd.post_seqs, key=lambda x: x[0])

    _, last_seq, last_len, _ = pre_sorted[-1]
    _, first_seq, _, _       = post_sorted[0]

    expected = (last_seq + last_len) & 0xFFFFFFFF
    diff = (first_seq - expected) & 0xFFFFFFFF
    if diff > 0x7FFFFFFF:
        diff -= 0x100000000

    if abs(diff) <= mss:
        print(f'[PASS]  {label}: seq continuity OK (last_seq={last_seq} len={last_len} first_post={first_seq} diff={diff:+d})')
        total_pass += 1
    else:
        print(f'[FAIL]  {label}: seq gap detected (expected~{expected} got={first_seq} diff={diff:+d} > MSS={mss})')
        total_fail += 1

print(f'')
print(f'Summary: PASS={total_pass}  FAIL={total_fail}')
sys.exit(0 if total_fail == 0 else 1)
" || STATUS=$?

if [[ $STATUS -eq 0 ]]; then
    info "seq continuity analysis: ALL PASS"
else
    error "seq continuity analysis: FAILURES detected"
fi

exit $STATUS
