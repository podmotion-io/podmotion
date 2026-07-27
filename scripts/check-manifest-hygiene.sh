#!/usr/bin/env bash
# scripts/check-manifest-hygiene.sh
#
# ADR-0402 finding-1 regression guard.
#
# charts/podmotion/ is the single authoritative deploy source (ADR-0078,
# reaffirmed by ADR-0402). ADR-0402 removed the orphaned, broader-privilege
# config/agent/daemonset.yaml (a dead bundle referenced by no deploy path). This
# guard fails CLOSED if that orphan reappears, or if any active deploy input
# (kustomization / build script / CI workflow) re-references it — the exact
# multi-source drift ADR-0402 closed.
#
# Scope note: this deliberately does NOT diff the marker-generated
# config/rbac/role.yaml against the chart RBAC *content* — that parity check is
# owned by ADR-0078 and is out of ADR-0402's scope (see ADR-0402 decision D3).
#
# Requires no kustomize and no cluster: pure file/grep checks, runnable anywhere.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

FAIL=0

echo ""
echo "PodMotion manifest-hygiene check (ADR-0402 F1 regression guard)"
echo "==============================================================="

# ---------------------------------------------------------------------------
# Check 1: the orphaned agent bundle must not exist.
# ---------------------------------------------------------------------------
if [[ -e "config/agent/daemonset.yaml" ]]; then
  echo "  [FAIL] config/agent/daemonset.yaml is present again."
  echo "         ADR-0402 removed this orphaned broader-privilege DaemonSet"
  echo "         (Unconfined seccomp + SETUID/SETGID/CHOWN/DAC_OVERRIDE). The"
  echo "         authoritative agent lives in charts/podmotion/templates/."
  FAIL=1
else
  echo "  [ OK ] config/agent/daemonset.yaml absent."
fi

if [[ -d "config/agent" ]]; then
  echo "  [FAIL] config/agent/ directory reintroduced (orphan bundle location)."
  FAIL=1
else
  echo "  [ OK ] config/agent/ directory absent."
fi

# ---------------------------------------------------------------------------
# Check 2: no ACTIVE deploy input may reference the orphan.
# Scope: kustomization files, build/CI scripts, the Makefile, GitHub workflows.
# (ADR .md history legitimately names the file and is intentionally excluded.)
# This script excludes itself.
# ---------------------------------------------------------------------------
declare -a SEARCH_FILES=()
while IFS= read -r f; do
  [[ "$(realpath "$f")" == "$(realpath "${BASH_SOURCE[0]}")" ]] && continue
  SEARCH_FILES+=("$f")
done < <(
  {
    find config .github hack scripts -type f \
      \( -name 'kustomization.yaml' -o -name 'kustomization.yml' \
         -o -name '*.sh' -o -name '*.yaml' -o -name '*.yml' \) 2>/dev/null
    [[ -f Makefile ]] && echo "Makefile"
  } | sort -u
)

REF_HITS=""
if [[ ${#SEARCH_FILES[@]} -gt 0 ]]; then
  # Match: config/agent, agent/daemonset, or a resources entry ../agent(/ or EOL).
  REF_HITS="$(grep -EnH 'config/agent|agent/daemonset|\.\./agent([/[:space:]]|$)' \
    "${SEARCH_FILES[@]}" 2>/dev/null || true)"
fi

if [[ -n "${REF_HITS}" ]]; then
  echo "  [FAIL] an active deploy input references the removed orphan bundle:"
  echo "${REF_HITS}" | sed 's/^/         /'
  echo "         No kustomization/script/CI may re-add config/agent — charts/"
  echo "         podmotion/ is the single authoritative deploy source (ADR-0402)."
  FAIL=1
else
  echo "  [ OK ] no kustomization/script/CI references config/agent or ../agent."
fi

echo ""
if [[ "${FAIL}" -ne 0 ]]; then
  echo "==> manifest-hygiene check FAILED (ADR-0402 F1 regression)."
  exit 1
fi
echo "==> manifest-hygiene check PASSED."
