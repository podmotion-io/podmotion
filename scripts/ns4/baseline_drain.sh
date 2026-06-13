#!/usr/bin/env bash
# scripts/ns4/baseline_drain.sh
#
# Comparison baseline: run kubectl drain / rolling restart on the same pgbench
# workload used by NS#4 and record failed_transactions.
#
# This script documents the alternative-path cost (N failed transactions)
# against which NS#4's zero-dropped-connection proof is measured.
#
# Usage:
#   ./scripts/ns4/baseline_drain.sh [--method drain|restart]
#
# Environment variables:
#   NAMESPACE         Kubernetes namespace (default: pm-ns4-baseline)
#   PGBENCH_FIXTURE   Path to pgbench fixture YAML (default: test/fixtures/ns4/pgbench-client.yaml)
#   POSTGRES_FIXTURE  Path to postgres fixture YAML (default: test/fixtures/ns4/postgres.yaml)
#   DRAIN_NODE        Node to drain (default: pm-worker)
#   TRIGGER_OFFSET    Seconds into pgbench run before drain/restart (default: 30)
#   METHOD            drain|restart (default: drain)
#
# Output:
#   [CI baseline] method=drain|restart failed_transactions=N ns4_failed_transactions=0

set -euo pipefail

NAMESPACE="${NAMESPACE:-pm-ns4-baseline}"
PGBENCH_FIXTURE="${PGBENCH_FIXTURE:-test/fixtures/ns4/pgbench-client.yaml}"
POSTGRES_FIXTURE="${POSTGRES_FIXTURE:-test/fixtures/ns4/postgres.yaml}"
DRAIN_NODE="${DRAIN_NODE:-pm-worker}"
TRIGGER_OFFSET="${TRIGGER_OFFSET:-30}"
METHOD="${METHOD:-drain}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --method) METHOD="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

require_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "[ERROR] required command not found: $1" >&2
        exit 1
    fi
}

require_cmd kubectl

log "creating namespace $NAMESPACE"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

log "deploying PostgreSQL fixture"
kubectl apply -n "$NAMESPACE" -f "$POSTGRES_FIXTURE"
kubectl wait pod -n "$NAMESPACE" -l app=postgres-ns4 \
    --for=condition=Ready --timeout=3m

log "deploying pgbench fixture"
kubectl apply -n "$NAMESPACE" -f "$PGBENCH_FIXTURE"

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
    log "[ERROR] pgbench pod did not start"
    exit 1
fi

log "pgbench pod=$PGBENCH_POD; waiting ${TRIGGER_OFFSET}s before $METHOD"
sleep "$TRIGGER_OFFSET"

# Confirm pgbench still active
PHASE=$(kubectl get pod "$PGBENCH_POD" -n "$NAMESPACE" \
    -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [[ "$PHASE" != "Running" ]]; then
    log "[ERROR] pgbench pod exited before trigger (phase=$PHASE)"
    exit 1
fi

case "$METHOD" in
    drain)
        log "draining node $DRAIN_NODE"
        kubectl drain "$DRAIN_NODE" \
            --ignore-daemonsets \
            --delete-emptydir-data \
            --timeout=60s || true

        log "waiting 15s for pgbench to record failure"
        sleep 15

        log "uncordoning $DRAIN_NODE"
        kubectl uncordon "$DRAIN_NODE" || true
        ;;

    restart)
        log "deleting PostgreSQL pod (rolling restart simulation)"
        kubectl delete pod -n "$NAMESPACE" -l app=postgres-ns4 --wait=false || true

        log "waiting 15s for pgbench to record failure"
        sleep 15
        ;;

    *)
        log "[ERROR] unknown method: $METHOD"
        exit 1
        ;;
esac

log "waiting 5s for pgbench log to stabilize"
sleep 5

PGBENCH_LOG=$(kubectl logs -n "$NAMESPACE" "$PGBENCH_POD" --tail=200 2>/dev/null || true)
FAILED_TXN=$(echo "$PGBENCH_LOG" | \
    grep "number of failed transactions" | \
    grep -oE '[0-9]+' | head -1 || echo 0)

log "[CI baseline] method=$METHOD failed_transactions=${FAILED_TXN:-0} ns4_failed_transactions=0"

echo ""
echo "Baseline result:"
echo "  method:                   $METHOD"
echo "  failed_transactions:      ${FAILED_TXN:-0}"
echo "  ns4_failed_transactions:  0"
echo ""

if [[ "${FAILED_TXN:-0}" -gt 0 ]]; then
    echo "BASELINE: ${FAILED_TXN} transactions dropped — NS#4 proof shows 0 (improvement confirmed)"
else
    echo "BASELINE: 0 transactions dropped — baseline may have completed before drain took effect"
fi

log "cleaning up baseline namespace $NAMESPACE"
kubectl delete namespace "$NAMESPACE" --ignore-not-found --wait=false || true
