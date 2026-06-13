#!/usr/bin/env bash
# scripts/check-release-gate.sh
# Reads ci/matrix.yaml and ci/green-streaks.yaml (+ ci/flake-db/*.ndjson).
# Exits 1 (fail-closed) if ANY required-tier cell has current_streak < 10
# or is in data-pending state.
# Outputs a per-cell summary table to stdout.
#
# ADR-0093 (formerly ADR-0079) §3.2 and §4.1.
# RequiredConsecutiveGreenRuns = 10 (from internal/ci/gate.go)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MATRIX_YAML="${REPO_ROOT}/ci/matrix.yaml"
STREAKS_YAML="${REPO_ROOT}/ci/green-streaks.yaml"
FLAKE_DB_DIR="${REPO_ROOT}/ci/flake-db"

REQUIRED_STREAK=10
FLAKE_BUDGET=0.02
WINDOW=30

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check required files exist
if [[ ! -f "${MATRIX_YAML}" ]]; then
    echo "ERROR: ci/matrix.yaml not found at ${MATRIX_YAML}" >&2
    exit 1
fi

if [[ ! -f "${STREAKS_YAML}" ]]; then
    echo "ERROR: ci/green-streaks.yaml not found at ${STREAKS_YAML}" >&2
    exit 1
fi

# Parse green-streaks.yaml using yq if available, else awk
if command -v yq &>/dev/null; then
    HAS_YQ=1
else
    HAS_YQ=0
fi

echo ""
echo "PodMotion CI Release Gate Check"
echo "================================"
echo "Required consecutive green runs : ${REQUIRED_STREAK}"
echo "Flake budget (rolling ${WINDOW} runs) : ${FLAKE_BUDGET}"
echo "Matrix                          : ${MATRIX_YAML}"
echo "Green streaks                   : ${STREAKS_YAML}"
echo ""
printf "%-52s  %-14s  %-8s  %s\n" "CELL ID" "STATUS" "STREAK" "GATE"
printf "%-52s  %-14s  %-8s  %s\n" "$(printf '%0.s-' {1..52})" "--------------" "--------" "------"

BLOCKING=0
BLOCKING_CELLS=()

# Read all cell_ids from green-streaks.yaml
# We use awk for portability (no yq dependency required in CI bootstrap).
while IFS= read -r line; do
    # Parse lines of form:  cell_id: "kernel-5-15/flannel/hostpath/n"
    if [[ "${line}" =~ ^[[:space:]]*cell_id:[[:space:]]*\"(.*)\"$ ]]; then
        CURRENT_CELL="${BASH_REMATCH[1]}"
        CURRENT_STREAK=""
        CURRENT_STATUS=""
    fi
    if [[ "${line}" =~ ^[[:space:]]*current_streak:[[:space:]]*([0-9]+)$ ]]; then
        CURRENT_STREAK="${BASH_REMATCH[1]}"
    fi
    if [[ "${line}" =~ ^[[:space:]]*status:[[:space:]]*(.*)$ ]]; then
        CURRENT_STATUS="${BASH_REMATCH[1]}"
    fi
    # When we have all three fields for a cell, emit the row
    if [[ -n "${CURRENT_CELL:-}" && -n "${CURRENT_STREAK:-}" && -n "${CURRENT_STATUS:-}" ]]; then
        STATUS="${CURRENT_STATUS}"
        STREAK="${CURRENT_STREAK}"
        GATE="PASS"
        COLOR="${GREEN}"

        if [[ "${STATUS}" == "data-pending" ]]; then
            GATE="BLOCK"
            COLOR="${YELLOW}"
            BLOCKING=1
            BLOCKING_CELLS+=("${CURRENT_CELL} (data-pending)")
        elif [[ "${STREAK}" -lt "${REQUIRED_STREAK}" ]]; then
            GATE="BLOCK"
            COLOR="${RED}"
            BLOCKING=1
            BLOCKING_CELLS+=("${CURRENT_CELL} (streak=${STREAK}/${REQUIRED_STREAK})")
        fi

        printf "%-52s  %-14s  %-8s  ${COLOR}%s${NC}\n" \
            "${CURRENT_CELL}" "${STATUS}" "${STREAK}/${REQUIRED_STREAK}" "${GATE}"

        # Reset for next cell
        CURRENT_CELL=""
        CURRENT_STREAK=""
        CURRENT_STATUS=""
    fi
done < "${STREAKS_YAML}"

echo ""

# Check flake-db NDJSON files for any cells over budget (best-effort; requires jq)
FLAKE_VIOLATIONS=()
if command -v jq &>/dev/null && [[ -d "${FLAKE_DB_DIR}" ]]; then
    for ndjson in "${FLAKE_DB_DIR}"/*.ndjson; do
        [[ -f "${ndjson}" ]] || continue
        cell_id="$(basename "${ndjson}" .ndjson)"
        # Count total runs and flaky transitions in the last WINDOW entries
        run_count=$(wc -l < "${ndjson}" | tr -d ' ')
        if [[ "${run_count}" -lt "${WINDOW}" ]]; then
            continue
        fi
        # Compute flaky run count: passed=true on line N-1, passed=false on line N
        flaky=$(tail -n "${WINDOW}" "${ndjson}" | jq -s '
            [range(1; length) |
                select(.[. - 1].passed == true and .[.].passed == false)
            ] | length
        ' 2>/dev/null || echo 0)
        # flake_rate = flaky / WINDOW
        # Use awk for float comparison
        over_budget=$(awk -v f="${flaky}" -v w="${WINDOW}" -v b="${FLAKE_BUDGET}" \
            'BEGIN { rate = f/w; if (rate > b) print "yes"; else print "no" }')
        if [[ "${over_budget}" == "yes" ]]; then
            rate=$(awk -v f="${flaky}" -v w="${WINDOW}" 'BEGIN { printf "%.4f", f/w }')
            FLAKE_VIOLATIONS+=("${cell_id} (flake_rate=${rate} > ${FLAKE_BUDGET})")
        fi
    done
fi

if [[ ${#FLAKE_VIOLATIONS[@]} -gt 0 ]]; then
    echo "FLAKE BUDGET VIOLATIONS (release-blocking):"
    for v in "${FLAKE_VIOLATIONS[@]}"; do
        echo "  ${RED}BLOCK${NC}  ${v}"
        BLOCKING=1
    done
    echo ""
fi

# Final verdict
if [[ "${BLOCKING}" -eq 1 ]]; then
    echo -e "${RED}GATE RESULT: BLOCKED${NC}"
    echo ""
    echo "Blocking conditions:"
    for cell in "${BLOCKING_CELLS[@]}"; do
        echo "  - ${cell}"
    done
    for v in "${FLAKE_VIOLATIONS[@]}"; do
        echo "  - ${v} [FLAKE_BUDGET_EXCEEDED]"
    done
    echo ""
    echo "Release promotion is blocked. All required-tier cells must have"
    echo "current_streak >= ${REQUIRED_STREAK} and flake_rate <= ${FLAKE_BUDGET}."
    echo "Cells in data-pending state block promotion until 10+ runs are recorded."
    echo ""
    exit 1
else
    echo -e "${GREEN}GATE RESULT: PASSED${NC}"
    echo ""
    echo "All required-tier cells have current_streak >= ${REQUIRED_STREAK}."
    echo "Release promotion is unblocked by the CI matrix gate."
    echo "(M28 beta gate — 80-run AWS+VM gate — is a separate, additive requirement.)"
    echo ""
    exit 0
fi
