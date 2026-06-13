#!/usr/bin/env bash
# switch-cluster.sh — switch kubectl context and tail PodMigration events live
# Usage:
#   ./hack/switch-cluster.sh               # interactive picker
#   ./hack/switch-cluster.sh podmotion-dev # switch directly

set -euo pipefail

if [[ -n "${1:-}" ]]; then
  CTX="$1"
  if ! kubectl config get-contexts "$CTX" &>/dev/null; then
    CTX="kind-$1"
  fi
else
  # Interactive: list clusters and let user pick
  echo "Available clusters:"
  echo ""
  i=1
  declare -a CTXS=()
  while IFS= read -r ctx; do
    CTXS+=("$ctx")
    CURRENT=""
    [[ "$(kubectl config current-context 2>/dev/null)" == "$ctx" ]] && CURRENT=" ← current"
    echo "  $i) $ctx$CURRENT"
    ((i++))
  done < <(kubectl config get-contexts --no-headers 2>/dev/null | awk '{print $2}')

  echo ""
  read -rp "Pick a number (or Enter to cancel): " PICK
  [[ -z "$PICK" ]] && exit 0
  CTX="${CTXS[$((PICK-1))]}"
fi

kubectl config use-context "$CTX"
echo ""
echo "Switched to: $CTX"
echo ""
echo "Quick status:"
kubectl get nodes -o wide 2>/dev/null || echo "  (cluster not reachable)"
echo ""
echo "Run ./hack/watch-cluster.sh to open the live dashboard."
