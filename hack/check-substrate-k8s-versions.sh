#!/usr/bin/env bash
# check-substrate-k8s-versions.sh — cross-checks go.mod's k8s.io/kubernetes
# version requirement against what every deploy substrate actually serves.
#
# WHY THIS EXISTS (origin incident, 2026-09-03):
# go.mod's k8s.io/kubernetes was bumped to v1.35.0, which builds the
# scheduler against the DynamicResourceAllocation API — GA and locked-on
# (cannot be disabled) as of Kubernetes 1.35. images/kind/Dockerfile was
# still pinned to kindest/node:v1.32.0, which does not serve that API at
# all. The scheduler binary started, connected to the API server, and then
# silently never scheduled anything — no crash, no error, just a hang. That
# class of bug (go.mod's floor requirement silently outrunning a substrate's
# pinned/apt-installed Kubernetes version) has no other guard anywhere in
# this repo. This script is that guard. Run it any time go.mod's
# k8s.io/kubernetes entry changes, or any substrate's version pin changes.
#
# What it checks, one substrate config file each (see docs/ci-test-matrix.md
# §5 "Version Drift Tracking" for the companion OS-package drift table this
# extends):
#   - kind:          images/kind/Dockerfile               (ARG KIND_BASE=kindest/node:vX.Y.Z)
#   - KVM/RKE2:       hack/kvm-cluster.sh                   (header doc comment "Kubernetes vX.Y.x")
#   - kubeadm-EC2 AMI: images/capi/packer/kubeadm-ubuntu.pkrvars.hcl  (kubernetes_version = "X.Y")
#   - EKS:            terraform/eks-cluster/variables.tf    (variable "kubernetes_version" default)
#
# This is a FLOOR check: every substrate's Kubernetes minor version must be
# >= go.mod's k8s.io/kubernetes minor version. A substrate running a newer
# minor than go.mod requires is fine (not flagged). Only "substrate is
# behind go.mod's requirement" is an error — that's the exact shape of the
# kind-scheduler-hang incident.
#
# Usage:
#   bash hack/check-substrate-k8s-versions.sh
#
# Exit code: 0 if every substrate meets or exceeds the go.mod floor,
# 1 if any substrate is behind (or if a source file/pin could not be parsed).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GO_MOD="go.mod"
KIND_DOCKERFILE="images/kind/Dockerfile"
KVM_SCRIPT="hack/kvm-cluster.sh"
KUBEADM_EC2_PKRVARS="images/capi/packer/kubeadm-ubuntu.pkrvars.hcl"
EKS_VARIABLES="terraform/eks-cluster/variables.tf"

FAIL=0

# ── helpers ───────────────────────────────────────────────────────────────

# minor_ord "1.35" -> 1035 (comparable integer: major*1000+minor)
minor_ord() {
  local ver="$1" major minor
  major="${ver%%.*}"
  minor="${ver#*.}"
  minor="${minor%%.*}"
  echo $(( major * 1000 + minor ))
}

# Known feature-gate GA/lock milestones relevant to PodMotion's scheduler
# and node-agent paths. Informational only — the hard floor check below is
# the raw version comparison; this just explains WHY a given minor matters
# when it does, the same way the kind-scheduler-hang incident's root cause
# was a specific API's GA milestone, not just "some newer version."
declare -A KNOWN_MILESTONES=(
  ["1.35"]="DynamicResourceAllocation API GA'd and locked-on (cannot be disabled) — a substrate below this minor does not serve the API at all, and consumers (e.g. the scheduler) fail silently rather than erroring."
)

note_milestone() {
  local ver_minor="$1"
  local note="${KNOWN_MILESTONES[$ver_minor]:-}"
  if [[ -n "$note" ]]; then
    echo "      note (v${ver_minor} milestone): $note"
  fi
}

# ── 1. Parse the go.mod floor requirement ────────────────────────────────

if [[ ! -f "$GO_MOD" ]]; then
  echo "ERROR: $GO_MOD not found (run from repo root or check REPO_ROOT resolution)." >&2
  exit 1
fi

# Field-match rather than anchor on a literal tab/indent character (go.mod's
# require-block entries are tab-indented, but that byte is fragile to carry
# through nested shell invocations) — $1=="k8s.io/kubernetes" also correctly
# skips the "replace k8s.io/client-go => k8s.io/client-go vX.Y.Z" line,
# whose first field is "replace", not the module path.
REQUIRED_FULL="$(awk '$1=="k8s.io/kubernetes" { print $2; exit }' "$GO_MOD" | sed 's/^v//')"
if [[ -z "$REQUIRED_FULL" ]]; then
  echo "ERROR: could not parse a k8s.io/kubernetes version out of $GO_MOD." >&2
  echo "       Expected a require-block line: k8s.io/kubernetes v1.35.0" >&2
  exit 1
fi
REQUIRED_MINOR="$(echo "$REQUIRED_FULL" | cut -d. -f1,2)"
REQUIRED_ORD="$(minor_ord "$REQUIRED_MINOR")"

echo "=== PodMotion substrate Kubernetes version cross-check ==="
echo "go.mod requires: k8s.io/kubernetes v${REQUIRED_FULL} (floor minor: v${REQUIRED_MINOR})"
note_milestone "$REQUIRED_MINOR"
echo ""

# ── 2. Per-substrate checks ───────────────────────────────────────────────

# check_substrate <label> <file> <parsed-minor-or-empty> <raw-match-or-empty>
check_substrate() {
  local label="$1" file="$2" parsed="$3"

  if [[ -z "$parsed" ]]; then
    echo "[UNPARSEABLE] $label — could not extract a Kubernetes version from $file" >&2
    echo "              This substrate is UNVERIFIED against the go.mod floor (v${REQUIRED_MINOR})." >&2
    FAIL=1
    return
  fi

  local ord
  ord="$(minor_ord "$parsed")"
  if (( ord < REQUIRED_ORD )); then
    echo "[FAIL] $label: pinned at v${parsed} — BEHIND go.mod's v${REQUIRED_MINOR} floor by $(( REQUIRED_ORD - ord )) minor version(s)."
    echo "       source: $file"
    note_milestone "$REQUIRED_MINOR"
    FAIL=1
  else
    echo "[OK]   $label: pinned at v${parsed} — meets go.mod's v${REQUIRED_MINOR} floor."
  fi
}

# -- kind --
KIND_RAW="$(grep -E '^ARG KIND_BASE=kindest/node:v[0-9]+\.[0-9]+\.[0-9]+' "$KIND_DOCKERFILE" 2>/dev/null | head -1 || true)"
KIND_MINOR=""
if [[ -n "$KIND_RAW" ]]; then
  KIND_MINOR="$(echo "$KIND_RAW" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | sed 's/^v//' | cut -d. -f1,2)"
fi
check_substrate "kind (images/kind/Dockerfile ARG KIND_BASE)" "$KIND_DOCKERFILE" "$KIND_MINOR"

# -- KVM/RKE2 standing cluster --
# hack/kvm-cluster.sh has no static version *pin* for RKE2 (RKE2_VERSION
# defaults to empty = get.rke2.io's "current stable" channel — see the
# script's own RKE2_VERSION comment); the script's header block documents
# the standing cluster's actual running version instead ("Kubernetes
# v1.35.x"). That header line is this substrate's source of truth here.
KVM_RAW="$(grep -oE 'Kubernetes v[0-9]+\.[0-9]+\.x' "$KVM_SCRIPT" 2>/dev/null | head -1 || true)"
KVM_MINOR=""
if [[ -n "$KVM_RAW" ]]; then
  KVM_MINOR="$(echo "$KVM_RAW" | grep -oE '[0-9]+\.[0-9]+')"
fi
check_substrate "KVM/RKE2 standing cluster (hack/kvm-cluster.sh header)" "$KVM_SCRIPT" "$KVM_MINOR"

# -- kubeadm-EC2 AMI (apt-installed kubelet/kubeadm/kubectl) --
# The apt package version itself has no pin (k8s-prereqs role's
# kubernetes_package_version defaults to "" = latest patch in-channel); the
# real floor is the pkgs.k8s.io channel minor, set here and threaded through
# to the ansible role as kubernetes_minor_version.
KUBEADM_EC2_RAW="$(grep -E '^kubernetes_version[[:space:]]*=' "$KUBEADM_EC2_PKRVARS" 2>/dev/null | head -1 || true)"
KUBEADM_EC2_MINOR=""
if [[ -n "$KUBEADM_EC2_RAW" ]]; then
  KUBEADM_EC2_MINOR="$(echo "$KUBEADM_EC2_RAW" | grep -oE '"[0-9]+\.[0-9]+"' | tr -d '"')"
fi
check_substrate "kubeadm-EC2 AMI (images/capi/packer/kubeadm-ubuntu.pkrvars.hcl kubernetes_version)" "$KUBEADM_EC2_PKRVARS" "$KUBEADM_EC2_MINOR"

# -- EKS terraform default --
EKS_RAW="$(awk '/variable "kubernetes_version"/{f=1} f && /default/{print; exit}' "$EKS_VARIABLES" 2>/dev/null || true)"
EKS_MINOR=""
if [[ -n "$EKS_RAW" ]]; then
  EKS_MINOR="$(echo "$EKS_RAW" | grep -oE '"[0-9]+\.[0-9]+"' | tr -d '"')"
fi
check_substrate "EKS (terraform/eks-cluster/variables.tf kubernetes_version default)" "$EKS_VARIABLES" "$EKS_MINOR"

echo ""
if [[ "$FAIL" -ne 0 ]]; then
  echo "=== RESULT: FAIL — one or more substrates are behind go.mod's k8s.io/kubernetes floor (v${REQUIRED_MINOR}). ==="
  echo "Bump the failing substrate's pin (or, if go.mod's own bump was unintentional, revert it) before relying on that substrate for a gate run."
  exit 1
fi

echo "=== RESULT: PASS — every substrate meets go.mod's k8s.io/kubernetes floor (v${REQUIRED_MINOR}). ==="
exit 0
