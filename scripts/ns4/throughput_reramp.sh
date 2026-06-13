#!/usr/bin/env bash
# scripts/ns4/throughput_reramp.sh
#
# Document the time-to-full-throughput / cwnd re-ramp curve after NS#4 migration.
#
# Method:
#   - Parse pgbench progress output (-P 1 flag gives tps per second).
#   - Find the timestamp of the migration handoff (ZeroWindowDisarmed in logs).
#   - Compute tps in each 1-second window post-handoff until throughput recovers
#     to >= 95% of the pre-migration baseline.
#   - Emit a CI-parseable summary with ramp-to-95pct-sec and raw tps series.
#
# Usage:
#   ./scripts/ns4/throughput_reramp.sh --pgbench-log <logfile> --operator-log <logfile> \
#       [--migration-name <name>]
#
# Environment variables:
#   MIGRATION     Migration name to look up in operator log (default: all)
#   TPS_BASELINE  Known baseline tps (overrides auto-detection)
#   RECOVERY_PCT  Percentage of baseline to consider "recovered" (default: 95)

set -euo pipefail

PGBENCH_LOG=""
OPERATOR_LOG=""
MIGRATION="${MIGRATION:-}"
TPS_BASELINE="${TPS_BASELINE:-0}"
RECOVERY_PCT="${RECOVERY_PCT:-95}"

usage() {
    echo "Usage: $0 --pgbench-log <file> --operator-log <file> [--migration-name <name>]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pgbench-log)    PGBENCH_LOG="$2";  shift 2 ;;
        --operator-log)   OPERATOR_LOG="$2"; shift 2 ;;
        --migration-name) MIGRATION="$2";    shift 2 ;;
        *) usage ;;
    esac
done

if [[ -z "$PGBENCH_LOG" || -z "$OPERATOR_LOG" ]]; then
    usage
fi

require_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "[ERROR] required command not found: $1" >&2
        exit 1
    fi
}

require_cmd python3
require_cmd jq

python3 - "$PGBENCH_LOG" "$OPERATOR_LOG" "$MIGRATION" \
    "$TPS_BASELINE" "$RECOVERY_PCT" <<'PYEOF'
import sys
import re
import json
import datetime

pgbench_log  = sys.argv[1]
operator_log = sys.argv[2]
migration    = sys.argv[3]   # may be empty
tps_baseline = float(sys.argv[4])
recovery_pct = float(sys.argv[5])

# ── Parse pgbench -P 1 progress lines ──────────────────────────────────────
# Format: progress: <seconds>.0 s, <tps> tps, lat <n> ms stddev <n>
# or:     progress: <seconds>.0 s, <tps> tps, lat <n>/<n>/<n> ms (min/avg/max)
progress_re = re.compile(
    r"progress:\s+([\d.]+)\s+s,\s+([\d.]+)\s+tps"
)

tps_series = []  # list of (elapsed_sec, tps)
with open(pgbench_log) as f:
    for line in f:
        m = progress_re.search(line)
        if m:
            tps_series.append((float(m.group(1)), float(m.group(2))))

if not tps_series:
    print("[ERROR] no progress lines found in pgbench log", file=sys.stderr)
    sys.exit(1)

# ── Extract ZeroWindowDisarmed timestamp from operator log ──────────────────
disarm_epoch_sec = None
with open(operator_log) as f:
    for line in f:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("event") != "ZeroWindowDisarmed":
            continue
        if migration and obj.get("migration", "") != migration:
            continue
        ts = obj.get("ts", "")
        if not ts:
            continue
        ts = ts.rstrip("Z")
        if "." in ts:
            base, frac = ts.split(".", 1)
            frac = (frac + "0" * 6)[:6]
            dt = datetime.datetime.strptime(base + "." + frac, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        disarm_epoch_sec = dt.timestamp()
        break

if disarm_epoch_sec is None:
    print("[WARN] ZeroWindowDisarmed not found in operator log; using midpoint of tps series",
          file=sys.stderr)
    disarm_epoch_sec = None  # handled below

# ── Determine pgbench start time ─────────────────────────────────────────────
# pgbench progress timestamps are elapsed seconds from start.
# Without an absolute start timestamp we can't align with operator log time.
# Use the disarm offset relative to pgbench progress by finding the inflection.
# If we have the operator log timestamp, we need the pgbench start epoch.
# Look for a pgbench "starting vacuum" line with a date if present.
pgbench_start_epoch = None
start_re = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+starting vacuum")
with open(pgbench_log) as f:
    for line in f:
        m = start_re.match(line)
        if m:
            try:
                pgbench_start_epoch = datetime.datetime.strptime(
                    m.group(1)[:19], "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                pass
            break

# ── Find disarm point in pgbench elapsed series ──────────────────────────────
disarm_elapsed_sec = None
if disarm_epoch_sec is not None and pgbench_start_epoch is not None:
    disarm_elapsed_sec = disarm_epoch_sec - pgbench_start_epoch

# If we cannot align timestamps, use the tps inflection (first local minimum).
if disarm_elapsed_sec is None:
    # Find the first point where tps drops by > 20% from local max then recovers.
    local_max = max(t for _, t in tps_series[:max(1, len(tps_series)//2)])
    for i, (elapsed, tps) in enumerate(tps_series):
        if tps < local_max * 0.8:
            disarm_elapsed_sec = elapsed
            print(f"[WARN] using tps inflection point at {elapsed}s as handoff proxy",
                  file=sys.stderr)
            break
    if disarm_elapsed_sec is None:
        disarm_elapsed_sec = tps_series[len(tps_series) // 2][0]

# ── Pre-migration baseline ────────────────────────────────────────────────────
if tps_baseline <= 0:
    pre_samples = [t for el, t in tps_series if el < disarm_elapsed_sec]
    if pre_samples:
        tps_baseline = sum(pre_samples) / len(pre_samples)
    else:
        tps_baseline = tps_series[0][1]
    print(f"[INFO] auto-detected tps_baseline={tps_baseline:.1f}", file=sys.stderr)

# ── Post-handoff recovery curve ───────────────────────────────────────────────
recovery_threshold = tps_baseline * (recovery_pct / 100.0)
post_series = [(el - disarm_elapsed_sec, t)
               for el, t in tps_series if el >= disarm_elapsed_sec]

ramp_secs = None
for offset, tps in post_series:
    if tps >= recovery_threshold:
        ramp_secs = offset
        break

print()
print(f"Throughput re-ramp after migration handoff")
print(f"  tps_baseline:       {tps_baseline:.1f}")
print(f"  recovery_threshold: {recovery_threshold:.1f} ({recovery_pct:.0f}% of baseline)")
print(f"  handoff_elapsed:    {disarm_elapsed_sec:.1f}s into pgbench run")
print()
print(f"{'offset_sec':>12}  {'tps':>10}  {'vs_baseline':>14}")
for offset, tps in post_series[:30]:
    pct = (tps / tps_baseline * 100) if tps_baseline > 0 else 0
    marker = " <-- RECOVERED" if ramp_secs is not None and abs(offset - ramp_secs) < 0.5 else ""
    print(f"{offset:>12.1f}  {tps:>10.1f}  {pct:>13.1f}%{marker}")

if ramp_secs is not None:
    print(f"\n[CI throughput-reramp] tps_baseline={tps_baseline:.1f} "
          f"recovery_pct={recovery_pct:.0f} ramp_to_recovery_sec={ramp_secs:.1f}")
    print(f"\nTime to {recovery_pct:.0f}% throughput recovery: {ramp_secs:.1f}s")
else:
    print(f"\n[CI throughput-reramp] tps_baseline={tps_baseline:.1f} "
          f"recovery_pct={recovery_pct:.0f} ramp_to_recovery_sec=NOT_REACHED")
    print(f"\nThroughput did not reach {recovery_pct:.0f}% recovery in observed window")
PYEOF
