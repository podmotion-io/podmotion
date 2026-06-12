#!/usr/bin/env bash
# scripts/m20-hold-duration.sh
#
# Extracts zero-window hold-duration measurements from a Ginkgo e2e run log
# (or from live operator logs) and prints a summary table for CI reporting.
#
# Usage:
#   # From a saved ginkgo output file:
#   ./scripts/m20-hold-duration.sh --file ginkgo.log
#
#   # From live operator logs (requires kubectl access):
#   ./scripts/m20-hold-duration.sh --live
#
# Output format:
#   migration                holdMs  budgetMs  pass/fail
#   pm-zw-abc123             47      500       PASS
#   pm-zw-def456             312     500       PASS
#
# Exit code:
#   0 — all measured hold durations are within budget
#   1 — one or more hold durations exceeded budget (or no measurements found)
#
# The Ginkgo e2e test emits CI-parseable lines in the form:
#   [CI hold-duration] migration=<name> holdMs=<n> budgetMs=<n>
# This script greps for that prefix from the provided source.

set -euo pipefail

MODE="file"
SOURCE=""

usage() {
    echo "Usage: $0 --file <ginkgo.log> | --live"
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

# Collect raw lines containing the CI hold-duration marker.
if [[ "$MODE" == "live" ]]; then
    RAW=$(kubectl logs -n podmotion-system \
        -l control-plane=controller-manager \
        --tail=1000 2>/dev/null | grep '\[CI hold-duration\]' || true)
else
    if [[ ! -f "$SOURCE" ]]; then
        echo "ERROR: file not found: $SOURCE" >&2
        exit 1
    fi
    RAW=$(grep '\[CI hold-duration\]' "$SOURCE" || true)
fi

if [[ -z "$RAW" ]]; then
    echo "No [CI hold-duration] lines found. Run the e2e suite with -tags=e2e and Label('m20') to generate them." >&2
    exit 1
fi

PASS=0
FAIL=0
printf "%-40s %8s %9s %s\n" "migration" "holdMs" "budgetMs" "result"
printf "%-40s %8s %9s %s\n" "---------" "------" "--------" "------"

while IFS= read -r line; do
    # Parse key=value pairs.
    migration=$(echo "$line" | grep -oP 'migration=\K[^ ]+' || echo "unknown")
    holdMs=$(echo "$line"    | grep -oP 'holdMs=\K[0-9]+' || echo "-1")
    budgetMs=$(echo "$line"  | grep -oP 'budgetMs=\K[0-9]+' || echo "-1")

    if [[ "$holdMs" -le "$budgetMs" && "$holdMs" -ge 0 ]]; then
        result="PASS"
        PASS=$((PASS + 1))
    else
        result="FAIL"
        FAIL=$((FAIL + 1))
    fi

    printf "%-40s %8s %9s %s\n" "$migration" "$holdMs" "$budgetMs" "$result"
done <<< "$RAW"

echo ""
echo "Summary: $PASS PASS, $FAIL FAIL"

if [[ $FAIL -gt 0 ]]; then
    echo "FAIL: one or more hold durations exceeded FreezeWindowBudgetMs" >&2
    exit 1
fi

echo "PASS: all hold durations within budget"
exit 0
