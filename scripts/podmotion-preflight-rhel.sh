#!/usr/bin/env bash
# PodMotion preflight check for RHEL 8 / RHEL 9 / Rocky 9 / AlmaLinux 9 nodes.
#
# Usage:
#   bash scripts/podmotion-preflight-rhel.sh [--json]
#
# Exit codes:
#   0 — all required checks passed (warnings allowed)
#   1 — one or more required checks failed
#
# With --json: emits a JSON object suitable for direct population of
# NodeMigrationCapacitySpec fields (KernelFeatures, NetworkCapability,
# StorageCapability).  Wire this into agent startup with:
#   podmotion-agent --preflight-json <(scripts/podmotion-preflight-rhel.sh --json)
set -euo pipefail

JSON_MODE=false
[[ "${1:-}" == "--json" ]] && JSON_MODE=true

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS=0; WARN=0; FAIL=0
declare -A RESULTS  # name -> "pass|warn|fail"

KCONFIG="/boot/config-$(uname -r)"
[[ -f /proc/config.gz ]] && KCONFIG="/proc/config.gz"

log()  { $JSON_MODE || echo "$*"; }
info() { log "  $*"; }

check_kconfig() {
  local name=$1 level=$2  # level: required|optional
  local val=""
  if [[ "$KCONFIG" == *.gz ]]; then
    val=$(zcat "$KCONFIG" 2>/dev/null | grep "^${name}=" | cut -d= -f2 || true)
  else
    val=$(grep "^${name}=" "$KCONFIG" 2>/dev/null | cut -d= -f2 || true)
  fi
  if [[ "$val" == "y" || "$val" == "m" ]]; then
    info "PASS  ${name}=${val}"
    ((PASS++)); RESULTS["$name"]="pass"
  elif [[ "$level" == "required" ]]; then
    info "FAIL  ${name} MISSING — migration will not work"
    ((FAIL++)); RESULTS["$name"]="fail"
  else
    info "WARN  ${name} MISSING — some migration modes unavailable"
    ((WARN++)); RESULTS["$name"]="warn"
  fi
}

check_cmd() {
  local label=$1 cmd=$2 level=$3
  if eval "$cmd" &>/dev/null; then
    info "PASS  ${label}"
    ((PASS++)); RESULTS["$label"]="pass"
  elif [[ "$level" == "required" ]]; then
    info "FAIL  ${label}"
    ((FAIL++)); RESULTS["$label"]="fail"
  else
    info "WARN  ${label}"
    ((WARN++)); RESULTS["$label"]="warn"
  fi
}

check_sysctl() {
  local key=$1 expected=$2 level=$3
  local val
  val=$(sysctl -n "$key" 2>/dev/null || echo "")
  if [[ "$val" == "$expected" ]]; then
    info "PASS  sysctl ${key}=${val}"
    ((PASS++)); RESULTS["sysctl_${key}"]="pass"
  elif [[ "$level" == "required" ]]; then
    info "FAIL  sysctl ${key}=${val} (expected ${expected})"
    ((FAIL++)); RESULTS["sysctl_${key}"]="fail"
  else
    info "WARN  sysctl ${key}=${val} (expected ${expected})"
    ((WARN++)); RESULTS["sysctl_${key}"]="warn"
  fi
}

# ---------------------------------------------------------------------------
# Detect distro and version
# ---------------------------------------------------------------------------
DISTRO_ID=""
DISTRO_VERSION_ID=""
if [[ -f /etc/os-release ]]; then
  # shellcheck source=/dev/null
  source /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_VERSION_ID="${VERSION_ID:-unknown}"
fi
KERNEL_VERSION=$(uname -r)
ARCH=$(uname -m)

log "=== PodMotion RHEL Preflight Check ==="
log "Distro : ${DISTRO_ID} ${DISTRO_VERSION_ID}"
log "Kernel : ${KERNEL_VERSION}"
log "Arch   : ${ARCH}"
log ""

# ---------------------------------------------------------------------------
# RHEL 8 warning: cold-migration only
# ---------------------------------------------------------------------------
if [[ "$DISTRO_ID" == "rhel" && "$DISTRO_VERSION_ID" == 8* ]]; then
  log "WARNING: RHEL 8 ships kernel 4.18 with RHEL backports."
  log "  CONFIG_MEM_SOFT_DIRTY is NOT backported to RHEL 8's 4.18 kernel."
  log "  Iterative pre-copy migration is NOT supported on RHEL 8."
  log "  Only cold (stop-and-copy) migration is available on RHEL 8."
  log "  Upgrade to RHEL 9 for full PodMotion feature support."
  log ""
fi

# ---------------------------------------------------------------------------
# Section 1: Kernel config — mandatory for any migration
# ---------------------------------------------------------------------------
log "--- Kernel: mandatory for any migration ---"
check_kconfig CONFIG_CHECKPOINT_RESTORE required
check_kconfig CONFIG_NAMESPACES         required
check_kconfig CONFIG_UTS_NS             required
check_kconfig CONFIG_IPC_NS             required
check_kconfig CONFIG_PID_NS             required
check_kconfig CONFIG_NET_NS             required
check_kconfig CONFIG_UNIX_DIAG          required
check_kconfig CONFIG_INET_DIAG          required
check_kconfig CONFIG_FHANDLE            required
check_kconfig CONFIG_EVENTFD            required
log ""

# ---------------------------------------------------------------------------
# Section 2: Iterative pre-copy (RHEL 9 / Rocky 9 only — RHEL 8 will fail)
# ---------------------------------------------------------------------------
log "--- Kernel: iterative pre-copy (requires RHEL 9+ or kernel 4.18 with RHEL backport) ---"
if [[ "$DISTRO_ID" == "rhel" && "$DISTRO_VERSION_ID" == 8* ]]; then
  # RHEL 8: MEM_SOFT_DIRTY not backported — mark as expected failure
  info "SKIP  CONFIG_MEM_SOFT_DIRTY — not backported to RHEL 8 4.18 (cold migration only)"
  ((WARN++)); RESULTS["CONFIG_MEM_SOFT_DIRTY"]="warn"
else
  check_kconfig CONFIG_MEM_SOFT_DIRTY required
fi
log ""

# ---------------------------------------------------------------------------
# Section 3: Post-copy lazy pages (v0.2+)
# ---------------------------------------------------------------------------
log "--- Kernel: post-copy lazy pages (v0.2+) ---"
check_kconfig CONFIG_USERFAULTFD optional
log ""

# ---------------------------------------------------------------------------
# Section 4: eBPF packet bridge
# ---------------------------------------------------------------------------
log "--- Kernel: eBPF packet bridge ---"
check_kconfig CONFIG_BPF             optional
check_kconfig CONFIG_BPF_SYSCALL     optional
check_kconfig CONFIG_BPF_JIT         optional
check_kconfig CONFIG_XDP_SOCKETS     optional
check_kconfig CONFIG_NET_SCH_INGRESS optional
check_kconfig CONFIG_NET_CLS_BPF     optional
check_kconfig CONFIG_NETFILTER_XT_MATCH_CGROUP optional
check_kconfig CONFIG_TUN             optional
check_kconfig CONFIG_VETH            optional
log ""

# ---------------------------------------------------------------------------
# Section 5: cgroup v2 (mandatory)
# ---------------------------------------------------------------------------
log "--- cgroup v2 ---"
check_cmd "cgroup_v2_unified" \
  "[[ \$(stat -fc %T /sys/fs/cgroup/) == 'cgroup2fs' ]]" required
log ""

# ---------------------------------------------------------------------------
# Section 6: sysctl runtime values
# ---------------------------------------------------------------------------
log "--- sysctl runtime ---"
# userfaultfd unprivileged: RHEL 9 defaults to 0; agent requires 1 (or root)
check_sysctl vm.unprivileged_userfaultfd 1 optional
# BPF JIT: should be 1 (enabled) or 2 (enabled + hardened)
BPF_JIT_VAL=$(sysctl -n net.core.bpf_jit_enable 2>/dev/null || echo "0")
if [[ "$BPF_JIT_VAL" == "1" || "$BPF_JIT_VAL" == "2" ]]; then
  info "PASS  sysctl net.core.bpf_jit_enable=${BPF_JIT_VAL}"
  ((PASS++)); RESULTS["sysctl_bpf_jit"]="pass"
else
  info "WARN  sysctl net.core.bpf_jit_enable=${BPF_JIT_VAL} (expected 1 or 2)"
  ((WARN++)); RESULTS["sysctl_bpf_jit"]="warn"
fi
log ""

# ---------------------------------------------------------------------------
# Section 7: CRIU binary and version
# ---------------------------------------------------------------------------
log "--- CRIU ---"
CRIU_VERSION=""
if command -v criu &>/dev/null; then
  CRIU_VERSION=$(criu --version 2>&1 | head -1 | grep -oP '\d+\.\d+(\.\d+)?' || echo "unknown")
  # Minimum required: 3.15 for UFFD_FEATURE_THREAD_ID; 4.0 recommended
  CRIU_MAJOR=$(echo "$CRIU_VERSION" | cut -d. -f1)
  if [[ "$CRIU_MAJOR" -ge 4 ]]; then
    info "PASS  criu ${CRIU_VERSION} (>= 4.0 recommended)"
    ((PASS++)); RESULTS["criu_version"]="pass"
  elif [[ "$CRIU_MAJOR" -ge 3 ]]; then
    info "WARN  criu ${CRIU_VERSION} (3.x supported but 4.2 recommended; iterative pre-copy may be limited)"
    ((WARN++)); RESULTS["criu_version"]="warn"
  else
    info "FAIL  criu ${CRIU_VERSION} (too old — minimum 3.15)"
    ((FAIL++)); RESULTS["criu_version"]="fail"
  fi
else
  info "FAIL  criu binary not found — install via: dnf install criu (EPEL required on RHEL 8)"
  ((FAIL++)); RESULTS["criu_version"]="fail"
fi
log ""

# ---------------------------------------------------------------------------
# Section 8: containerd + NRI
# ---------------------------------------------------------------------------
log "--- containerd + NRI ---"
check_cmd "containerd_binary" "command -v containerd" required
check_cmd "containerd_nri_socket_dir" "[[ -d /var/run/nri ]]" optional
NRI_CONF="/etc/containerd/conf.d/nri.toml"
if [[ -f "$NRI_CONF" ]]; then
  if grep -q 'disable = false' "$NRI_CONF" 2>/dev/null; then
    info "PASS  containerd NRI enabled (${NRI_CONF})"
    ((PASS++)); RESULTS["containerd_nri"]="pass"
  else
    info "WARN  ${NRI_CONF} present but NRI may not be enabled"
    ((WARN++)); RESULTS["containerd_nri"]="warn"
  fi
else
  info "WARN  NRI config not found at ${NRI_CONF}"
  ((WARN++)); RESULTS["containerd_nri"]="warn"
fi
log ""

# ---------------------------------------------------------------------------
# Section 9: SELinux status
# ---------------------------------------------------------------------------
log "--- SELinux ---"
SELINUX_MODE=$(getenforce 2>/dev/null || echo "disabled")
case "$SELINUX_MODE" in
  Enforcing)
    # Check if podmotion module is loaded
    if semodule -l 2>/dev/null | grep -q podmotion; then
      info "PASS  SELinux enforcing + podmotion module loaded"
      ((PASS++)); RESULTS["selinux"]="pass"
    else
      info "FAIL  SELinux enforcing but podmotion.pp module NOT loaded"
      info "      Build and install: make selinux-policy && semodule -i selinux/podmotion.pp"
      ((FAIL++)); RESULTS["selinux"]="fail"
    fi
    ;;
  Permissive)
    info "WARN  SELinux permissive — acceptable for dev, NOT for production"
    ((WARN++)); RESULTS["selinux"]="warn"
    ;;
  *)
    info "WARN  SELinux disabled — acceptable for dev, NOT for production"
    ((WARN++)); RESULTS["selinux"]="warn"
    ;;
esac
log ""

# ---------------------------------------------------------------------------
# Section 10: bpffs mounted
# ---------------------------------------------------------------------------
log "--- bpffs ---"
check_cmd "bpffs_mounted" "mountpoint -q /sys/fs/bpf" optional
log ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log "=== Result: ${PASS} pass / ${WARN} warn / ${FAIL} fail ==="
log ""

# ---------------------------------------------------------------------------
# JSON output for NodeMigrationCapacitySpec population
# ---------------------------------------------------------------------------
if $JSON_MODE; then
  CRIU_OK="false"
  [[ "${RESULTS[criu_version]:-fail}" == "pass" || "${RESULTS[criu_version]:-fail}" == "warn" ]] && CRIU_OK="true"

  CHECKPOINT_RESTORE="false"
  [[ "${RESULTS[CONFIG_CHECKPOINT_RESTORE]:-fail}" == "pass" ]] && CHECKPOINT_RESTORE="true"

  MEM_SOFT_DIRTY="false"
  [[ "${RESULTS[CONFIG_MEM_SOFT_DIRTY]:-warn}" == "pass" ]] && MEM_SOFT_DIRTY="true"

  USERFAULTFD="false"
  [[ "${RESULTS[CONFIG_USERFAULTFD]:-warn}" == "pass" ]] && USERFAULTFD="true"

  BPF_SUPPORTED="false"
  [[ "${RESULTS[CONFIG_BPF_SYSCALL]:-warn}" == "pass" && "${RESULTS[CONFIG_XDP_SOCKETS]:-warn}" == "pass" ]] && BPF_SUPPORTED="true"

  CGROUP_V2="false"
  [[ "${RESULTS[cgroup_v2_unified]:-fail}" == "pass" ]] && CGROUP_V2="true"

  SELINUX_STATUS="${RESULTS[selinux]:-warn}"

  CONTAINERD_READY="false"
  [[ "${RESULTS[containerd_binary]:-fail}" == "pass" ]] && CONTAINERD_READY="true"

  cat <<EOF
{
  "distro": "${DISTRO_ID}",
  "distroVersion": "${DISTRO_VERSION_ID}",
  "kernelVersion": "${KERNEL_VERSION}",
  "arch": "${ARCH}",
  "criuVersion": "${CRIU_VERSION}",
  "kernelFeatures": {
    "checkpointRestore": ${CHECKPOINT_RESTORE},
    "memSoftDirty": ${MEM_SOFT_DIRTY},
    "userfaultfd": ${USERFAULTFD},
    "bpfSyscall": $([ "${RESULTS[CONFIG_BPF_SYSCALL]:-warn}" == "pass" ] && echo true || echo false),
    "xdpSockets": $([ "${RESULTS[CONFIG_XDP_SOCKETS]:-warn}" == "pass" ] && echo true || echo false),
    "cgroupV2": ${CGROUP_V2}
  },
  "networkCapability": {
    "bpfBridgeSupported": ${BPF_SUPPORTED},
    "xdpZeroWindowSupported": ${BPF_SUPPORTED}
  },
  "migrationModes": {
    "coldMigration": ${CHECKPOINT_RESTORE},
    "iterativePreCopy": ${MEM_SOFT_DIRTY},
    "postCopyLazyPages": ${USERFAULTFD}
  },
  "runtimeReady": {
    "criuBinaryPresent": ${CRIU_OK},
    "containerdPresent": ${CONTAINERD_READY},
    "selinuxStatus": "${SELINUX_STATUS}"
  },
  "preflight": {
    "pass": ${PASS},
    "warn": ${WARN},
    "fail": ${FAIL},
    "overallStatus": "$([ $FAIL -eq 0 ] && echo ok || echo fail)"
  }
}
EOF
fi

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
