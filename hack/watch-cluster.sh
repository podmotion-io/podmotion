#!/usr/bin/env bash
# watch-cluster.sh — live dashboard for any PodMotion kind cluster
# Usage:
#   ./hack/watch-cluster.sh                  # auto-picks the newest kind cluster
#   ./hack/watch-cluster.sh podmotion-dev    # pick a specific context name
#   ./hack/watch-cluster.sh --list           # list available clusters

set -euo pipefail

if [[ "${1:-}" == "--list" ]]; then
  echo "=== kind clusters ==="
  kind get clusters 2>/dev/null | sed 's/^/  kind-/'
  echo ""
  echo "=== all kubectl contexts ==="
  kubectl config get-contexts --no-headers 2>/dev/null | awk '{print "  " $2}'
  exit 0
fi

# Resolve context
if [[ -n "${1:-}" ]]; then
  CTX="$1"
  # accept bare name or kind-prefixed
  if ! kubectl config get-contexts "$CTX" &>/dev/null; then
    CTX="kind-$1"
  fi
else
  # Auto-pick: prefer any context with "podmotion" in name; fall back to newest kind cluster
  CTX=$(kubectl config get-contexts --no-headers 2>/dev/null \
    | awk '{print $2}' \
    | grep -i podmotion | head -1 || true)
  if [[ -z "$CTX" ]]; then
    NEWEST_KIND=$(kind get clusters 2>/dev/null | tail -1)
    CTX="kind-${NEWEST_KIND}"
  fi
fi

if ! kubectl config get-contexts "$CTX" &>/dev/null; then
  echo "Context '$CTX' not found. Run: ./hack/watch-cluster.sh --list"
  exit 1
fi

echo "Watching cluster: $CTX"
echo "Press Ctrl-C to exit"
echo ""

# Switch context
kubectl config use-context "$CTX" >/dev/null

# Live watch — refreshes every 2 seconds
watch -n 2 "
echo '=== NODES ==='
kubectl get nodes -o wide --no-headers 2>/dev/null

echo ''
echo '=== PODMIGRATIONS ==='
kubectl get podmigration -A -o wide 2>/dev/null || echo '  (none yet)'

echo ''
echo '=== PODS (podmotion-system) ==='
kubectl get pods -n podmotion-system -o wide 2>/dev/null || echo '  (namespace not found)'

echo ''
echo '=== MIGRATION EVENTS (last 10) ==='
kubectl get events -A --sort-by=.lastTimestamp 2>/dev/null \
  | grep -i -E 'migration|criu|checkpoint|restore|rollback|transfer' \
  | tail -10 || echo '  (none)'

echo ''
echo '=== AGENT PODS ==='
kubectl get pods -A -o wide 2>/dev/null \
  | grep -E 'podmotion|pm-agent|migration' | head -20 || echo '  (none)'
"
