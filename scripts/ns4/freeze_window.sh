#!/usr/bin/env bash
# scripts/ns4/freeze_window.sh
#
# Extract the full zero-window freeze window duration (ZW-arm to ZW-disarm) from
# PodMotion controller logs for one or more migration runs.
#
# The controller emits structured log lines in the form:
#   {"event":"ZeroWindowArmed",   "ts":"<RFC3339Nano>", "migration":"<name>", ...}
#   {"event":"ZeroWindowDisarmed","ts":"<RFC3339Nano>", "migration":"<name>", ...}
#
# This script pairs those events by migration name and prints the elapsed
# milliseconds for each run.
#
# Usage:
#   # From a saved operator log file:
#   ./scripts/ns4/freeze_window.sh --file operator.log
#
#   # From live operator logs (requires kubectl access):
#   NAMESPACE=pm-ns4 ./scripts/ns4/freeze_window.sh --live
#
#   # Filter to a specific migration name:
#   MIGRATION=pm-pgbench-0 ./scripts/ns4/freeze_window.sh --file operator.log
#
# Environment variables:
#   NAMESPACE    Kubernetes namespace for live log mode (default: pm-ns4)
#   MIGRATION    Restrict output to this migration name (default: all)
#   BUDGET_MS    Expected freeze budget in ms; marks PASS/FAIL (default: 500)
#
# Output (one line per paired arm/disarm event):
#   migration                zwArmTs                         zwDisarmTs                      freezeMs  budget  result
#   pm-pgbench-0             2026-06-11T10:00:01.123456789Z  2026-06-11T10:00:01.345678901Z  222       500     PASS
#
# Exit codes:
#   0  all measured freeze windows are within budget (or no measurement taken)
#   1  one or more windows exceeded budget, or no arm/disarm pairs found

set -euo pipefail

MODE="file"
SOURCE=""
NAMESPACE="${NAMESPACE:-pm-ns4}"
MIGRATION="${MIGRATION:-}"
BUDGET_MS="${BUDGET_MS:-500}"

usage() {
    echo "Usage: $0 --file <operator.log> | --live"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --file) MODE="file"; SOURCE="$2"; shift 2 ;;
        --live) MODE="live"; shift ;;
        *) usage ;;
    esac
done

if [[ "$MODE" == "file" && -z "$SOURCE" ]]; then
    usage
fi

require_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "[ERROR] required command not found: $1" >&2
        exit 1
    fi
}

require_cmd jq
require_cmd python3

# Produce a stream of relevant log lines.
log_stream() {
    if [[ "$MODE" == "live" ]]; then
        require_cmd kubectl
        kubectl logs -n "$NAMESPACE" -l app=podmotion-operator --follow=false 2>/dev/null
    else
        cat "$SOURCE"
    fi
}

# Parse timestamps using Python's datetime (portable; no GNU date needed on macOS).
ts_to_ns() {
    # Accepts RFC3339Nano; returns nanoseconds-since-epoch as integer.
    python3 - "$1" <<'EOF'
import sys, datetime
s = sys.argv[1].rstrip("Z")
# Handle sub-second precision of arbitrary length by truncating to 9 digits.
if "." in s:
    base, frac = s.split(".", 1)
    frac = (frac + "0" * 9)[:9]
    s = base + "." + frac
    fmt = "%Y-%m-%dT%H:%M:%S.%f"
    # Python %f only handles 6 digits; use first 6 for microsecond, remainder for ns.
    dt = datetime.datetime.strptime(base + "." + frac[:6], fmt)
    extra_ns = int(frac[6:]) if len(frac) > 6 else 0
else:
    dt = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S")
    extra_ns = 0
epoch = datetime.datetime(1970, 1, 1)
total_ns = int((dt - epoch).total_seconds() * 1_000_000_000) + extra_ns
print(total_ns)
EOF
}

# Collect arm/disarm timestamps keyed by migration name.
declare -A ARM_TS
declare -A DISARM_TS

while IFS= read -r line; do
    # Skip lines that don't look like JSON.
    [[ "$line" != "{"* ]] && continue

    event=$(echo "$line" | jq -r '.event // empty' 2>/dev/null) || continue
    [[ -z "$event" ]] && continue
    [[ "$event" != "ZeroWindowArmed" && "$event" != "ZeroWindowDisarmed" ]] && continue

    mig=$(echo "$line" | jq -r '.migration // empty' 2>/dev/null) || continue
    [[ -z "$mig" ]] && continue
    [[ -n "$MIGRATION" && "$mig" != "$MIGRATION" ]] && continue

    ts=$(echo "$line" | jq -r '.ts // empty' 2>/dev/null) || continue
    [[ -z "$ts" ]] && continue

    if [[ "$event" == "ZeroWindowArmed" ]]; then
        ARM_TS["$mig"]="$ts"
    else
        DISARM_TS["$mig"]="$ts"
    fi
done < <(log_stream)

if [[ ${#ARM_TS[@]} -eq 0 ]]; then
    echo "[WARN] no ZeroWindowArmed events found" >&2
    exit 1
fi

PASS=0
FAIL=0
HEADER_PRINTED=0

for mig in "${!ARM_TS[@]}"; do
    arm_ts="${ARM_TS[$mig]}"
    disarm_ts="${DISARM_TS[$mig]:-}"

    if [[ -z "$disarm_ts" ]]; then
        echo "[WARN] no ZeroWindowDisarmed for migration $mig — window still open or log truncated" >&2
        continue
    fi

    arm_ns=$(ts_to_ns "$arm_ts")
    disarm_ns=$(ts_to_ns "$disarm_ts")
    freeze_ns=$(( disarm_ns - arm_ns ))
    freeze_ms=$(( freeze_ns / 1000000 ))

    if [[ $freeze_ms -le $BUDGET_MS ]]; then
        result="PASS"
        PASS=$(( PASS + 1 ))
    else
        result="FAIL"
        FAIL=$(( FAIL + 1 ))
    fi

    if [[ $HEADER_PRINTED -eq 0 ]]; then
        printf "%-30s  %-35s  %-35s  %9s  %6s  %s\n" \
            "migration" "zwArmTs" "zwDisarmTs" "freezeMs" "budget" "result"
        HEADER_PRINTED=1
    fi

    printf "%-30s  %-35s  %-35s  %9d  %6d  %s\n" \
        "$mig" "$arm_ts" "$disarm_ts" "$freeze_ms" "$BUDGET_MS" "$result"

    # Emit CI-parseable line for tooling consumption.
    echo "[CI freeze-window] migration=${mig} freezeMs=${freeze_ms} budgetMs=${BUDGET_MS} result=${result}"
done

echo ""
echo "Summary: PASS=$PASS  FAIL=$FAIL"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
