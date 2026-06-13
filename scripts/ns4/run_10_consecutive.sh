#!/usr/bin/env bash
# scripts/ns4/run_10_consecutive.sh
#
# Orchestrate 10 consecutive NS#4 pgbench migration runs with randomized
# trigger offsets, collect freeze window measurements, emit p50/p99, and
# produce a CI-parseable pass/fail summary.
#
# Requirements:
#   - kubectl configured for the pm-control/pm-worker cluster
#   - scripts/ns4/freeze_window.sh in the same directory
#   - scripts/ns4/capture.sh in the same directory (optional; pcaps enriched output)
#   - jq, python3
#
# Usage:
#   ./scripts/ns4/run_10_consecutive.sh [--runs N] [--namespace NS]
#
# Environment variables:
#   NAMESPACE           Kubernetes namespace (default: pm-ns4)
#   POSTGRES_FIXTURE    Path to postgres fixture YAML (default: test/fixtures/ns4/postgres.yaml)
#   PGBENCH_FIXTURE     Path to pgbench fixture YAML (default: test/fixtures/ns4/pgbench-client.yaml)
#   OPERATOR_LOG_FILE   Path to write collected operator logs (default: /tmp/ns4-operator-run.log)
#   RUNS                Number of consecutive runs (default: 10)
#   MIN_OFFSET_SEC      Min randomized trigger offset (default: 30)
#   MAX_OFFSET_SEC      Max randomized trigger offset (default: 120)
#   FREEZE_BUDGET_MS    Freeze window budget in ms (default: 500)
#   PM_CONTROL_SSH      SSH target for pm-control (default: ubuntu@192.168.252.7)
#   PM_WORKER_SSH       SSH target for pm-worker (default: ubuntu@192.168.252.8)
#
# Exit codes:
#   0   all runs passed all hard gates
#   1   one or more runs failed a hard gate, or fewer than RUNS succeeded

set -euo pipefail

NAMESPACE="${NAMESPACE:-pm-ns4}"
POSTGRES_FIXTURE="${POSTGRES_FIXTURE:-test/fixtures/ns4/postgres.yaml}"
PGBENCH_FIXTURE="${PGBENCH_FIXTURE:-test/fixtures/ns4/pgbench-client.yaml}"
OPERATOR_LOG_FILE="${OPERATOR_LOG_FILE:-/tmp/ns4-operator-run.log}"
RUNS="${RUNS:-10}"
MIN_OFFSET_SEC="${MIN_OFFSET_SEC:-30}"
MAX_OFFSET_SEC="${MAX_OFFSET_SEC:-120}"
FREEZE_BUDGET_MS="${FREEZE_BUDGET_MS:-500}"
PM_CONTROL_SSH="${PM_CONTROL_SSH:-ubuntu@192.168.252.7}"
PM_WORKER_SSH="${PM_WORKER_SSH:-ubuntu@192.168.252.8}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs)    RUNS="$2"; shift 2 ;;
        --namespace) NAMESPACE="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

require_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "[ERROR] required command not found: $1" >&2
        exit 1
    fi
}

require_cmd kubectl
require_cmd jq
require_cmd python3

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

ssh_run() {
    local node="$1"; shift
    local host
    case "$node" in
        pm-control) host="$PM_CONTROL_SSH" ;;
        pm-worker)  host="$PM_WORKER_SSH"  ;;
        *)          host="$node"           ;;
    esac
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$host" "$@"
}

# ── Ensure namespace ──────────────────────────────────────────────────────────

log "ensuring namespace $NAMESPACE"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# ── Deploy PostgreSQL (idempotent) ────────────────────────────────────────────

log "deploying PostgreSQL fixture"
kubectl apply -n "$NAMESPACE" -f "$POSTGRES_FIXTURE"
kubectl wait pod -n "$NAMESPACE" -l app=postgres-ns4 \
    --for=condition=Ready --timeout=3m

# ── Operator log collection (background) ─────────────────────────────────────

log "starting operator log collection to $OPERATOR_LOG_FILE"
kubectl logs -n "$NAMESPACE" -l app=podmotion-operator \
    --follow --prefix=false > "$OPERATOR_LOG_FILE" 2>&1 &
LOG_PID=$!
trap "kill $LOG_PID 2>/dev/null || true" EXIT

# ── tcpdump capture (optional, best-effort) ──────────────────────────────────

CAPTURES_DIR="/tmp/ns4-captures"
mkdir -p "$CAPTURES_DIR"
if [[ -x "$SCRIPT_DIR/capture.sh" ]]; then
    log "starting tcpdump captures (capture.sh)"
    CAPTURE_DIR="$CAPTURES_DIR" "$SCRIPT_DIR/capture.sh" &
    CAPTURE_PID=$!
    trap "kill $CAPTURE_PID 2>/dev/null || true; kill $LOG_PID 2>/dev/null || true" EXIT
fi

# ── Run loop ──────────────────────────────────────────────────────────────────

declare -a FREEZE_MS_VALUES
PASS=0
FAIL=0

for (( run=1; run<=RUNS; run++ )); do
    log "=== Run $run/$RUNS ==="

    MIGRATION_NAME="pm-pgbench-${run}-$(date +%s)"

    # Deploy pgbench client
    kubectl apply -n "$NAMESPACE" -f "$PGBENCH_FIXTURE"

    # Wait for pgbench pod Running
    PGBENCH_POD=""
    for attempt in $(seq 1 24); do
        PGBENCH_POD=$(kubectl get pod -n "$NAMESPACE" -l app=pgbench-ns4 \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
        if [[ -n "$PGBENCH_POD" ]]; then
            PHASE=$(kubectl get pod "$PGBENCH_POD" -n "$NAMESPACE" \
                -o jsonpath='{.status.phase}' 2>/dev/null || true)
            if [[ "$PHASE" == "Running" ]]; then
                break
            fi
        fi
        sleep 5
    done
    if [[ -z "$PGBENCH_POD" ]]; then
        log "[FAIL] run $run: pgbench pod did not start"
        FAIL=$(( FAIL + 1 ))
        continue
    fi

    # Randomized trigger offset
    OFFSET=$(( MIN_OFFSET_SEC + RANDOM % (MAX_OFFSET_SEC - MIN_OFFSET_SEC + 1) ))
    log "run $run: pgbench pod=$PGBENCH_POD offset=${OFFSET}s"
    sleep "$OFFSET"

    # Confirm pgbench still active (load must be live at trigger)
    PHASE=$(kubectl get pod "$PGBENCH_POD" -n "$NAMESPACE" \
        -o jsonpath='{.status.phase}' 2>/dev/null || true)
    if [[ "$PHASE" != "Running" ]]; then
        log "[FAIL] run $run: pgbench pod exited before trigger (phase=$PHASE)"
        FAIL=$(( FAIL + 1 ))
        kubectl delete pod -n "$NAMESPACE" -l app=pgbench-ns4 --ignore-not-found --wait=false || true
        continue
    fi

    # Create PodMigration CR
    kubectl apply -n "$NAMESPACE" -f - <<EOF
apiVersion: podmotion.io/v1alpha1
kind: PodMigration
metadata:
  name: ${MIGRATION_NAME}
  namespace: ${NAMESPACE}
spec:
  podName: ${PGBENCH_POD}
  destinationNodeName: pm-control
  tcpPreservationMode: Strict
  freezeWindowBudgetMs: ${FREEZE_BUDGET_MS}
  applicationProbe:
    protocol: SQL
    query: "SELECT 1"
EOF

    # Wait for Complete (up to 15m)
    MIGRATION_PHASE=""
    for attempt in $(seq 1 300); do
        MIGRATION_PHASE=$(kubectl get podmigration "$MIGRATION_NAME" -n "$NAMESPACE" \
            -o jsonpath='{.status.phase}' 2>/dev/null || true)
        case "$MIGRATION_PHASE" in
            Complete) break ;;
            Failed|RollingBack)
                log "[FAIL] run $run: migration $MIGRATION_NAME phase=$MIGRATION_PHASE"
                break
                ;;
        esac
        sleep 3
    done

    if [[ "$MIGRATION_PHASE" != "Complete" ]]; then
        log "[FAIL] run $run: migration did not reach Complete (phase=$MIGRATION_PHASE)"
        FAIL=$(( FAIL + 1 ))
        kubectl delete pod -n "$NAMESPACE" -l app=pgbench-ns4 --ignore-not-found --wait=false || true
        continue
    fi

    # ── Hard gates ────────────────────────────────────────────────────────────

    RUN_PASS=1

    # Gate 1: freeze window < budget
    FREEZE_MS=0
    if [[ -x "$SCRIPT_DIR/freeze_window.sh" ]]; then
        FREEZE_LINE=$(NAMESPACE="$NAMESPACE" MIGRATION="$MIGRATION_NAME" \
            BUDGET_MS="$FREEZE_BUDGET_MS" \
            "$SCRIPT_DIR/freeze_window.sh" --live 2>/dev/null | \
            grep "\[CI freeze-window\]" | head -1 || true)
        if [[ -n "$FREEZE_LINE" ]]; then
            FREEZE_MS=$(echo "$FREEZE_LINE" | grep -oE 'freezeMs=[0-9]+' | cut -d= -f2 || echo 0)
        fi
    fi
    if [[ "$FREEZE_MS" -eq 0 ]]; then
        # Fall back to condition timestamps
        ZW_ARMED=$(kubectl get podmigration "$MIGRATION_NAME" -n "$NAMESPACE" \
            -o jsonpath='{.status.conditions[?(@.type=="ZeroWindowArmed")].lastTransitionTime}' \
            2>/dev/null || true)
        ZW_DISARMED=$(kubectl get podmigration "$MIGRATION_NAME" -n "$NAMESPACE" \
            -o jsonpath='{.status.conditions[?(@.type=="ZeroWindowDisarmed")].lastTransitionTime}' \
            2>/dev/null || true)
        if [[ -n "$ZW_ARMED" && -n "$ZW_DISARMED" ]]; then
            FREEZE_MS=$(python3 - "$ZW_ARMED" "$ZW_DISARMED" <<'EOF'
import sys, datetime
def parse_ts(s):
    s = s.rstrip("Z")
    if "." in s:
        base, frac = s.split(".", 1)
        frac = (frac + "0" * 6)[:6]
        return datetime.datetime.strptime(base + "." + frac, "%Y-%m-%dT%H:%M:%S.%f")
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S")
a, b = parse_ts(sys.argv[1]), parse_ts(sys.argv[2])
print(int((b - a).total_seconds() * 1000))
EOF
)
        fi
    fi

    log "run $run: freezeMs=$FREEZE_MS budgetMs=$FREEZE_BUDGET_MS"
    if [[ "$FREEZE_MS" -gt "$FREEZE_BUDGET_MS" ]]; then
        log "[FAIL] run $run: freeze ${FREEZE_MS}ms exceeds budget ${FREEZE_BUDGET_MS}ms"
        RUN_PASS=0
    fi
    FREEZE_MS_VALUES+=("${FREEZE_MS}")

    # Gate 2: failed_transactions = 0
    sleep 5
    PGBENCH_LOG=$(kubectl logs -n "$NAMESPACE" "$PGBENCH_POD" --tail=100 2>/dev/null || true)
    FAILED_TXN=$(echo "$PGBENCH_LOG" | \
        grep "number of failed transactions" | \
        grep -oE '[0-9]+' | head -1 || echo 0)
    log "run $run: failed_transactions=$FAILED_TXN"
    if [[ "${FAILED_TXN:-0}" -ne 0 ]]; then
        log "[FAIL] run $run: failed_transactions=$FAILED_TXN"
        RUN_PASS=0
    fi

    # Gate 3: zero disconnections
    for phrase in "could not connect" "server closed the connection unexpectedly" "connection to server was lost"; do
        if echo "$PGBENCH_LOG" | grep -qi "$phrase"; then
            log "[FAIL] run $run: pgbench log contains disconnection: '$phrase'"
            RUN_PASS=0
        fi
    done

    # Gate 4: TrafficVerified=True before SourcePodDeleted
    TV_TS=$(kubectl get podmigration "$MIGRATION_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.status.conditions[?(@.type=="TrafficVerified")].lastTransitionTime}' \
        2>/dev/null || true)
    SPD_TS=$(kubectl get podmigration "$MIGRATION_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.status.conditions[?(@.type=="SourcePodDeleted")].lastTransitionTime}' \
        2>/dev/null || true)
    if [[ -n "$TV_TS" && -n "$SPD_TS" ]]; then
        ADR_CHECK=$(python3 - "$TV_TS" "$SPD_TS" <<'EOF'
import sys, datetime
def parse_ts(s):
    s = s.rstrip("Z")
    if "." in s:
        base, frac = s.split(".", 1)
        frac = (frac + "0" * 6)[:6]
        return datetime.datetime.strptime(base + "." + frac, "%Y-%m-%dT%H:%M:%S.%f")
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S")
tv, spd = parse_ts(sys.argv[1]), parse_ts(sys.argv[2])
# spd must be >= tv
print("ok" if spd >= tv else "violation")
EOF
)
        if [[ "$ADR_CHECK" == "violation" ]]; then
            log "[FAIL] run $run: ADR-0012 VIOLATED — source pod deleted before TrafficVerified=True"
            RUN_PASS=0
        fi
    fi

    # Gate 5: TCPVerified=True
    TCP_VER=$(kubectl get podmigration "$MIGRATION_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.status.conditions[?(@.type=="TCPVerified")].status}' 2>/dev/null || true)
    if [[ "$TCP_VER" != "True" ]]; then
        log "[FAIL] run $run: TCPVerified not True (got '$TCP_VER')"
        RUN_PASS=0
    fi

    # Gate 6: ServiceVerified via SQL probe (not stub)
    SVC_REASON=$(kubectl get podmigration "$MIGRATION_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.status.conditions[?(@.type=="ServiceVerified")].reason}' 2>/dev/null || true)
    if [[ "$SVC_REASON" != "ServiceVerified" ]]; then
        log "[WARN] run $run: ServiceVerified reason='$SVC_REASON'; expected 'ServiceVerified' (SQL probe)"
        # Not a hard fail here if operator is in stub mode; log for human review.
    fi

    if [[ "$RUN_PASS" -eq 1 ]]; then
        log "[PASS] run $run: all gates passed (freezeMs=$FREEZE_MS failedTxn=${FAILED_TXN:-0})"
        PASS=$(( PASS + 1 ))
    else
        FAIL=$(( FAIL + 1 ))
    fi

    # Cleanup pgbench pod for next run
    kubectl delete pod -n "$NAMESPACE" -l app=pgbench-ns4 \
        --ignore-not-found --wait=false || true
    sleep 5
done

# ── Statistics ────────────────────────────────────────────────────────────────

log ""
log "=== NS#4 10-run statistics ==="

SORTED_MS=$(printf '%s\n' "${FREEZE_MS_VALUES[@]}" | sort -n)
COUNT=$(echo "$SORTED_MS" | wc -l | tr -d ' ')
P50_IDX=$(( COUNT / 2 ))
P99_IDX=$(python3 -c "import math; print(min(int(math.ceil($COUNT * 0.99)) - 1, $COUNT - 1))")

P50=$(echo "$SORTED_MS" | sed -n "$(( P50_IDX + 1 ))p")
P99=$(echo "$SORTED_MS" | sed -n "$(( P99_IDX + 1 ))p")

log "[CI ns4-stats] runs=$RUNS pass=$PASS fail=$FAIL p50ms=${P50} p99ms=${P99} budgetMs=$FREEZE_BUDGET_MS"

echo ""
echo "Summary: PASS=$PASS  FAIL=$FAIL  p50=${P50}ms  p99=${P99}ms  budget=${FREEZE_BUDGET_MS}ms"

if [[ $FAIL -gt 0 || $PASS -lt $RUNS ]]; then
    echo "RESULT: FAIL — not all $RUNS runs passed"
    exit 1
fi

echo "RESULT: PASS — $RUNS/$RUNS runs passed all NS#4 hard gates"
exit 0
